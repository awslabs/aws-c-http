/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>
#include <aws/http/private/h1_connection.h>
#include <aws/http/private/proxy_impl.h>
#include <aws/http/server.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/log_writer.h>
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

void proxy_tester_on_client_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {

    struct proxy_tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

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

    tester->host = options->host;
    tester->port = options->port;
    tester->proxy_options = options->proxy_options;
    tester->test_mode = options->test_mode;
    tester->failure_type = options->failure_type;

    ASSERT_SUCCESS(aws_byte_buf_init(&tester->connection_host_name, tester->alloc, 128));

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    ASSERT_SUCCESS(aws_mutex_init(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&tester->wait_cvar));

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

    bool use_tls = options->test_mode == PTTM_HTTPS;
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
        if (tester->client_connection) {
            aws_http_connection_release(tester->client_connection);
        }
    }

    if (tester->testing_channel) {
        ASSERT_SUCCESS(testing_channel_clean_up(tester->testing_channel));
        while (!testing_channel_is_shutdown_completed(tester->testing_channel)) {
            aws_thread_current_sleep(1000000000);
        }

        aws_mem_release(tester->alloc, tester->testing_channel);
    }

    ASSERT_SUCCESS(proxy_tester_wait(tester, proxy_tester_connection_shutdown_pred));

    if (tester->http_bootstrap != NULL) {
        if (tester->testing_channel == NULL && tester->http_bootstrap->user_data) {
            aws_http_proxy_user_data_destroy(tester->http_bootstrap->user_data);
        }
        aws_mem_release(tester->alloc, tester->http_bootstrap);
    }

    aws_client_bootstrap_release(tester->client_bootstrap);

    aws_host_resolver_release(tester->host_resolver);
    aws_event_loop_group_release(tester->event_loop_group);
    ASSERT_SUCCESS(aws_global_thread_creator_shutdown_wait_for(10));

    if (tester->tls_ctx) {
        aws_tls_connection_options_clean_up(&tester->tls_connection_options);
        aws_tls_ctx_release(tester->tls_ctx);
        aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    }

    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);

    aws_byte_buf_clean_up(&tester->connection_host_name);

    return AWS_OP_SUCCESS;
}

static void s_testing_channel_shutdown_callback(int error_code, void *user_data) {
    struct proxy_tester *tester = user_data;

    if (tester->wait_result == AWS_ERROR_SUCCESS) {
        tester->wait_result = error_code;
    }

    tester->http_bootstrap->on_shutdown(
        tester->client_connection, tester->wait_result, tester->http_bootstrap->user_data);
}

int proxy_tester_create_testing_channel_connection(struct proxy_tester *tester) {
    tester->testing_channel = aws_mem_calloc(tester->alloc, 1, sizeof(struct testing_channel));

    struct aws_testing_channel_options test_channel_options = {.clock_fn = aws_high_res_clock_get_ticks};
    ASSERT_SUCCESS(testing_channel_init(tester->testing_channel, tester->alloc, &test_channel_options));
    tester->testing_channel->channel_shutdown = s_testing_channel_shutdown_callback;
    tester->testing_channel->channel_shutdown_user_data = tester;

    /* Use small window so that we can observe it opening in tests.
     * Channel may wait until the window is small before issuing the increment command. */
    struct aws_http1_connection_options http1_options = AWS_HTTP1_CONNECTION_OPTIONS_INIT;
    struct aws_http_connection *connection =
        aws_http_connection_new_http1_1_client(tester->alloc, true, 256, &http1_options);
    ASSERT_NOT_NULL(connection);

    connection->user_data = tester->http_bootstrap->user_data;
    connection->client_data = &connection->client_or_server_data.client;
    connection->proxy_request_transform = tester->http_bootstrap->proxy_request_transform;

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel->channel);
    ASSERT_NOT_NULL(slot);
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel->channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &connection->channel_handler));
    connection->vtable->on_channel_handler_installed(&connection->channel_handler, slot);
    testing_channel_drain_queued_tasks(tester->testing_channel);

    tester->client_connection = connection;

    return AWS_OP_SUCCESS;
}

int proxy_tester_verify_connect_request(struct proxy_tester *tester) {
    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, tester->alloc, 1024));
    ASSERT_SUCCESS(testing_channel_drain_written_messages(tester->testing_channel, &output));

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

    aws_byte_buf_clean_up(&output);

    return AWS_OP_SUCCESS;
}

int proxy_tester_send_connect_response(struct proxy_tester *tester) {
    (void)tester;

    const char *response_string = NULL;
    if (tester->failure_type == PTFT_CONNECT_REQUEST) {
        response_string = "HTTP/1.0 401 Unauthorized\r\n\r\n";
    } else {
        /* adding close here because it's an edge case we need to exercise. The desired behavior is that it has
         * absolutely no effect. */
        response_string = "HTTP/1.0 200 Connection established\r\nconnection: close\r\n\r\n";
    }

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(tester->testing_channel, response_string));

    testing_channel_drain_queued_tasks(tester->testing_channel);

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
