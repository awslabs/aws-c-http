/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>
#include <aws/http/private/h1_connection.h>
#include <aws/http/private/proxy_impl.h>
#include <aws/http/proxy.h>
#include <aws/http/server.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/log_writer.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/common/uuid.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>
#include <aws/testing/io_testing_channel.h>

#include "proxy_test_helper.h"

enum {
    TESTER_TIMEOUT_SEC = 60, /* Give enough time for non-sudo users to enter password */
};

struct testing_channel_bootstrap_wrapper {
    struct testing_channel *channel;
    struct aws_http_client_bootstrap *bootstrap;
};

static struct testing_channel_bootstrap_wrapper *s_get_current_channel_bootstrap_wrapper(struct proxy_tester *tester) {
    struct testing_channel_bootstrap_wrapper *wrapper = NULL;

    size_t count = aws_array_list_length(&tester->testing_channels);
    aws_array_list_get_at_ptr(&tester->testing_channels, (void **)&wrapper, count - 1);

    return wrapper;
}

void proxy_tester_on_client_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {

    struct proxy_tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->client_connection_is_setup = true;

    if (error_code) {
        tester->client_connection = NULL;
        tester->wait_result = error_code;
        goto done;
    }

    tester->client_connection = connection;

done:
    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

void proxy_tester_on_client_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    (void)connection;
    (void)error_code;
    struct proxy_tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->client_connection_is_shutdown = true;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

int proxy_tester_wait(struct proxy_tester *tester, bool (*pred)(void *user_data)) {
    ASSERT_SUCCESS(aws_mutex_lock(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&tester->wait_cvar, &tester->wait_lock, pred, tester));
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->wait_lock));

    return AWS_OP_SUCCESS;
}

bool proxy_tester_connection_setup_pred(void *user_data) {
    struct proxy_tester *tester = user_data;
    return tester->wait_result || tester->client_connection;
}

bool proxy_tester_connection_complete_pred(void *user_data) {
    struct proxy_tester *tester = user_data;
    return tester->client_connection_is_setup;
}

bool proxy_tester_connection_shutdown_pred(void *user_data) {
    struct proxy_tester *tester = user_data;
    return tester->wait_result || tester->client_connection_is_shutdown;
}

bool proxy_tester_request_complete_pred_fn(void *user_data) {
    struct proxy_tester *tester = user_data;
    return tester->request_complete || tester->client_connection_is_shutdown;
}

int proxy_tester_init(struct proxy_tester *tester, const struct proxy_tester_options *options) {
    AWS_ZERO_STRUCT(*tester);

    tester->alloc = options->alloc;

    aws_http_library_init(options->alloc);

    ASSERT_SUCCESS(aws_array_list_init_dynamic(
        &tester->testing_channels, options->alloc, 1, sizeof(struct testing_channel_bootstrap_wrapper)));

    tester->host = options->host;
    tester->port = options->port;
    tester->proxy_options = *options->proxy_options;
    tester->test_mode = options->test_mode;
    tester->failure_type = options->failure_type;

    ASSERT_SUCCESS(aws_byte_buf_init(&tester->connection_host_name, tester->alloc, 128));

    ASSERT_SUCCESS(aws_mutex_init(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&tester->wait_cvar));

    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&tester->connect_requests, tester->alloc, 1, sizeof(struct aws_http_message *)));

    uint32_t connect_response_count = 1;
    if (options->desired_connect_response_count > connect_response_count) {
        connect_response_count = options->desired_connect_response_count;
    }
    ASSERT_SUCCESS(aws_array_list_init_dynamic(
        &tester->desired_connect_responses, tester->alloc, connect_response_count, sizeof(struct aws_string *)));

    for (size_t i = 0; i < options->desired_connect_response_count; ++i) {
        struct aws_byte_cursor response_cursor = options->desired_connect_responses[i];
        struct aws_string *response = aws_string_new_from_cursor(tester->alloc, &response_cursor);
        ASSERT_SUCCESS(aws_array_list_push_back(&tester->desired_connect_responses, &response));
    }

    tester->event_loop_group = aws_event_loop_group_new_default(tester->alloc, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = tester->event_loop_group,
        .max_entries = 8,
    };

    tester->host_resolver = aws_host_resolver_new_default(tester->alloc, &resolver_options);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = tester->event_loop_group,
        .host_resolver = tester->host_resolver,
    };
    tester->client_bootstrap = aws_client_bootstrap_new(tester->alloc, &bootstrap_options);
    ASSERT_NOT_NULL(tester->client_bootstrap);

    bool use_tls = options->test_mode == PTTM_HTTPS_TUNNEL;
    if (use_tls) {
        aws_tls_ctx_options_init_default_client(&tester->tls_ctx_options, tester->alloc);
        aws_tls_ctx_options_set_alpn_list(&tester->tls_ctx_options, "http/1.1");
        tester->tls_ctx_options.verify_peer = false;

        tester->tls_ctx = aws_tls_client_ctx_new(tester->alloc, &tester->tls_ctx_options);

        aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);
        aws_tls_connection_options_set_server_name(&tester->tls_connection_options, tester->alloc, &tester->host);
    }

    /* Connect */
    struct aws_http_client_connection_options client_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    client_options.allocator = tester->alloc;
    client_options.bootstrap = tester->client_bootstrap;
    client_options.host_name = tester->host;
    client_options.port = tester->port;
    client_options.socket_options = &socket_options;
    client_options.tls_options = use_tls ? &tester->tls_connection_options : NULL;
    client_options.user_data = tester;
    client_options.on_setup = proxy_tester_on_client_connection_setup;
    client_options.on_shutdown = proxy_tester_on_client_connection_shutdown;
    if (options->proxy_options) {
        client_options.proxy_options = options->proxy_options;
    }

    aws_http_client_connect(&client_options);

    /* Wait for server & client connections to finish setup */
    ASSERT_SUCCESS(proxy_tester_wait(tester, proxy_tester_connection_setup_pred));

    return AWS_OP_SUCCESS;
}

int proxy_tester_clean_up(struct proxy_tester *tester) {
    if (tester->client_connection) {
        aws_http_connection_release(tester->client_connection);
    }

    size_t channel_count = aws_array_list_length(&tester->testing_channels);
    for (size_t i = 0; i < channel_count; ++i) {
        struct testing_channel_bootstrap_wrapper wrapper;
        aws_array_list_get_at(&tester->testing_channels, &wrapper, i);
        struct testing_channel *channel = wrapper.channel;
        if (channel) {
            ASSERT_SUCCESS(testing_channel_clean_up(channel));
            while (!testing_channel_is_shutdown_completed(channel)) {
                aws_thread_current_sleep(1000000000);
            }

            aws_mem_release(tester->alloc, channel);
        }
    }

    ASSERT_SUCCESS(proxy_tester_wait(tester, proxy_tester_connection_shutdown_pred));

    for (size_t i = 0; i < channel_count; ++i) {
        struct testing_channel_bootstrap_wrapper wrapper;
        aws_array_list_get_at(&tester->testing_channels, &wrapper, i);
        if (wrapper.bootstrap != NULL) {
            if (channel_count == 0 && wrapper.bootstrap->user_data) {
                aws_http_proxy_user_data_destroy(wrapper.bootstrap->user_data);
            }
            if (i + 1 < channel_count) {
                wrapper.bootstrap->on_shutdown(tester->client_connection, 0, wrapper.bootstrap->user_data);
            }

            aws_http_client_bootstrap_destroy(wrapper.bootstrap);
        }
    }

    aws_array_list_clean_up(&tester->testing_channels);

    aws_client_bootstrap_release(tester->client_bootstrap);

    aws_host_resolver_release(tester->host_resolver);
    aws_event_loop_group_release(tester->event_loop_group);

    if (tester->tls_ctx) {
        aws_tls_connection_options_clean_up(&tester->tls_connection_options);
        aws_tls_ctx_release(tester->tls_ctx);
        aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    }

    size_t connect_request_count = aws_array_list_length(&tester->connect_requests);
    for (size_t i = 0; i < connect_request_count; ++i) {
        struct aws_http_message *request = NULL;

        aws_array_list_get_at(&tester->connect_requests, &request, i);
        aws_http_message_release(request);
    }
    aws_array_list_clean_up(&tester->connect_requests);

    size_t connect_response_count = aws_array_list_length(&tester->desired_connect_responses);
    for (size_t i = 0; i < connect_response_count; ++i) {
        struct aws_string *response = NULL;

        aws_array_list_get_at(&tester->desired_connect_responses, &response, i);
        aws_string_destroy(response);
    }
    aws_array_list_clean_up(&tester->desired_connect_responses);

    aws_http_library_clean_up();

    aws_byte_buf_clean_up(&tester->connection_host_name);

    return AWS_OP_SUCCESS;
}

static void s_testing_channel_shutdown_callback(int error_code, void *user_data) {
    struct proxy_tester *tester = user_data;

    if (tester->wait_result == AWS_ERROR_SUCCESS) {
        tester->wait_result = error_code;
    }

    struct testing_channel_bootstrap_wrapper *wrapper = s_get_current_channel_bootstrap_wrapper(tester);

    wrapper->bootstrap->on_shutdown(tester->client_connection, tester->wait_result, wrapper->bootstrap->user_data);
}

int proxy_tester_create_testing_channel_connection(
    struct proxy_tester *tester,
    struct aws_http_client_bootstrap *http_bootstrap) {

    struct testing_channel_bootstrap_wrapper *old_wrapper = s_get_current_channel_bootstrap_wrapper(tester);
    if (old_wrapper != NULL) {
        old_wrapper->channel->channel_shutdown = NULL;
    }

    struct testing_channel *testing_channel = aws_mem_calloc(tester->alloc, 1, sizeof(struct testing_channel));

    struct aws_testing_channel_options test_channel_options = {.clock_fn = aws_high_res_clock_get_ticks};
    ASSERT_SUCCESS(testing_channel_init(testing_channel, tester->alloc, &test_channel_options));
    testing_channel->channel_shutdown = s_testing_channel_shutdown_callback;
    testing_channel->channel_shutdown_user_data = tester;

    /* Use small window so that we can observe it opening in tests.
     * Channel may wait until the window is small before issuing the increment command. */
    struct aws_http1_connection_options http1_options;
    AWS_ZERO_STRUCT(http1_options);
    struct aws_http_connection *connection =
        aws_http_connection_new_http1_1_client(tester->alloc, true, 256, &http1_options);
    ASSERT_NOT_NULL(connection);

    connection->user_data = http_bootstrap->user_data;
    connection->client_data = &connection->client_or_server_data.client;
    connection->proxy_request_transform = http_bootstrap->proxy_request_transform;

    struct aws_channel_slot *slot = aws_channel_slot_new(testing_channel->channel);
    ASSERT_NOT_NULL(slot);
    ASSERT_SUCCESS(aws_channel_slot_insert_end(testing_channel->channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &connection->channel_handler));
    connection->vtable->on_channel_handler_installed(&connection->channel_handler, slot);
    testing_channel_drain_queued_tasks(testing_channel);

    tester->client_connection = connection;

    struct testing_channel_bootstrap_wrapper wrapper;
    wrapper.channel = testing_channel;
    wrapper.bootstrap = http_bootstrap;
    aws_array_list_push_back(&tester->testing_channels, &wrapper);

    return AWS_OP_SUCCESS;
}

bool s_line_feed_predicate(uint8_t value) {
    return value == '\r';
}

/*
 * A very crude, sloppy http request parser that does just enough to test what we want to test
 */
static int s_record_connect_request(struct aws_byte_buf *request_buffer, struct proxy_tester *tester) {
    struct aws_byte_cursor request_cursor = aws_byte_cursor_from_buf(request_buffer);

    struct aws_array_list lines;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&lines, tester->alloc, 10, sizeof(struct aws_byte_cursor)));
    aws_byte_cursor_split_on_char(&request_cursor, '\n', &lines);

    size_t line_count = aws_array_list_length(&lines);
    ASSERT_TRUE(line_count > 1);

    struct aws_http_message *message = aws_http_message_new_request(tester->alloc);

    struct aws_byte_cursor first_line_cursor;
    AWS_ZERO_STRUCT(first_line_cursor);
    aws_array_list_get_at(&lines, &first_line_cursor, 0);
    first_line_cursor = aws_byte_cursor_trim_pred(&first_line_cursor, s_line_feed_predicate);

    struct aws_byte_cursor method_cursor;
    AWS_ZERO_STRUCT(method_cursor);
    aws_byte_cursor_next_split(&first_line_cursor, ' ', &method_cursor);

    aws_http_message_set_request_method(message, method_cursor);

    aws_byte_cursor_advance(&first_line_cursor, method_cursor.len + 1);

    struct aws_byte_cursor uri_cursor;
    AWS_ZERO_STRUCT(uri_cursor);
    aws_byte_cursor_next_split(&first_line_cursor, ' ', &uri_cursor);

    aws_http_message_set_request_path(message, uri_cursor);

    for (size_t i = 1; i < line_count; ++i) {
        struct aws_byte_cursor line_cursor;
        AWS_ZERO_STRUCT(line_cursor);
        aws_array_list_get_at(&lines, &line_cursor, i);
        line_cursor = aws_byte_cursor_trim_pred(&line_cursor, s_line_feed_predicate);

        if (line_cursor.len == 0) {
            break;
        }

        struct aws_byte_cursor name_cursor;
        AWS_ZERO_STRUCT(name_cursor);
        aws_byte_cursor_next_split(&line_cursor, ':', &name_cursor);

        aws_byte_cursor_advance(&line_cursor, name_cursor.len + 1);
        line_cursor = aws_byte_cursor_trim_pred(&line_cursor, aws_isspace);

        struct aws_http_header header = {
            .name = name_cursor,
            .value = line_cursor,
        };

        aws_http_message_add_header(message, header);
    }

    /* we don't care about the body */

    aws_array_list_push_back(&tester->connect_requests, &message);

    aws_array_list_clean_up(&lines);

    return AWS_OP_SUCCESS;
}

int proxy_tester_verify_connect_request(struct proxy_tester *tester) {
    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, tester->alloc, 1024));

    struct testing_channel *testing_channel = proxy_tester_get_current_channel(tester);
    ASSERT_NOT_NULL(testing_channel);

    ASSERT_SUCCESS(testing_channel_drain_written_messages(testing_channel, &output));

    char connect_request_buffer[1024];
    snprintf(
        connect_request_buffer,
        AWS_ARRAY_SIZE(connect_request_buffer),
        "CONNECT " PRInSTR ":%d HTTP/1.1",
        AWS_BYTE_CURSOR_PRI(tester->host),
        (int)tester->port);

    struct aws_byte_cursor expected_connect_message_first_line_cursor =
        aws_byte_cursor_from_c_str(connect_request_buffer);
    ASSERT_TRUE(output.len >= expected_connect_message_first_line_cursor.len);

    struct aws_byte_cursor request_prefix = aws_byte_cursor_from_array(output.buffer, output.len);
    struct aws_byte_cursor first_line_cursor;
    AWS_ZERO_STRUCT(first_line_cursor);
    ASSERT_TRUE(aws_byte_cursor_next_split(&request_prefix, '\r', &first_line_cursor));

    ASSERT_TRUE(aws_byte_cursor_eq(&first_line_cursor, &expected_connect_message_first_line_cursor));

    ASSERT_SUCCESS(s_record_connect_request(&output, tester));

    aws_byte_buf_clean_up(&output);

    return AWS_OP_SUCCESS;
}

int proxy_tester_send_connect_response(struct proxy_tester *tester) {
    (void)tester;

    const char *response_string = NULL;

    size_t desired_response_count = aws_array_list_length(&tester->desired_connect_responses);
    if (desired_response_count > 0) {
        struct aws_string *response = NULL;
        aws_array_list_get_at(&tester->desired_connect_responses, &response, tester->current_response_index++);
        response_string = (const char *)response->bytes;

    } else if (tester->failure_type == PTFT_CONNECT_REQUEST) {
        response_string = "HTTP/1.0 407 Unauthorized\r\n\r\n";
    } else {
        /* adding close here because it's an edge case we need to exercise. The desired behavior is that it has
         * absolutely no effect. */
        response_string = "HTTP/1.0 200 Connection established\r\nconnection: close\r\n\r\n";
    }

    struct testing_channel *channel = proxy_tester_get_current_channel(tester);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(channel, response_string));

    testing_channel_drain_queued_tasks(channel);

    return AWS_OP_SUCCESS;
}

int proxy_tester_verify_connection_attempt_was_to_proxy(
    struct proxy_tester *tester,
    struct aws_byte_cursor expected_host,
    uint16_t expected_port) {
    ASSERT_BIN_ARRAYS_EQUALS(
        tester->connection_host_name.buffer,
        tester->connection_host_name.len,
        expected_host.ptr,
        expected_host.len,
        "Connection host should have been \"" PRInSTR "\", but was \"" PRInSTR "\".",
        AWS_BYTE_CURSOR_PRI(expected_host),
        AWS_BYTE_BUF_PRI(tester->connection_host_name));

    ASSERT_TRUE(tester->connection_port == expected_port);

    return AWS_OP_SUCCESS;
}

struct testing_channel *proxy_tester_get_current_channel(struct proxy_tester *tester) {
    struct testing_channel_bootstrap_wrapper *wrapper = s_get_current_channel_bootstrap_wrapper(tester);
    if (wrapper == NULL) {
        return NULL;
    }

    return wrapper->channel;
}
