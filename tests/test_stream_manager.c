/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "h2_test_helper.h"
#include "stream_test_helper.h"

#include <aws/http/http2_stream_manager.h>

#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/private/connection_impl.h>
#include <aws/http/private/connection_manager_system_vtable.h>
#include <aws/http/private/h1_stream.h>
#include <aws/http/private/h2_connection.h>
#include <aws/http/private/http2_stream_manager_impl.h>
#include <aws/http/private/proxy_impl.h>
#include <aws/http/proxy.h>
#include <aws/http/statistics.h>

#include <aws/io/stream.h>
#include <aws/io/uri.h>

#include <aws/common/byte_buf.h>
#include <aws/common/condition_variable.h>
#include <aws/common/string.h>

#include <aws/testing/aws_test_harness.h>
#include <aws/testing/io_testing_channel.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

#define DEFINE_HEADER(NAME, VALUE)                                                                                     \
    { .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(NAME), .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(VALUE), }

struct sm_tester_options {
    struct aws_allocator *alloc;
    struct aws_http_connection_manager_system_vtable *mock_table;
    bool no_http2;
    size_t max_connections;
    size_t ideal_concurrent_streams_per_connection;
    size_t max_concurrent_streams_per_connection;

    const struct aws_http_connection_monitoring_options *monitor_opt;

    struct aws_byte_cursor *uri_cursor;
    const enum aws_log_level *log_level;
    bool prior_knowledge;
    bool close_connection_on_server_error;
    size_t connection_ping_period_ms;
    size_t connection_ping_timeout_ms;
};

static struct aws_logger s_logger;
struct sm_tester {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;

    struct aws_client_bootstrap *client_bootstrap;

    struct aws_http2_stream_manager *stream_manager;
    struct aws_http_connection_manager *connection_manager;

    struct aws_uri endpoint;
    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_http_proxy_options *verify_proxy_options;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_array_list streams;
    size_t wait_for_stream_acquire_count;
    size_t acquiring_stream_errors;
    int error_code;

    size_t wait_for_stream_completed_count;
    size_t stream_completed_count;
    struct aws_atomic_var stream_destroyed_count;
    size_t stream_complete_errors;
    size_t stream_200_count;
    size_t stream_status_not_200_count;
    int stream_completed_error_code;

    bool is_shutdown_complete;

    /* Fake HTTP/2 connection */
    size_t wait_for_fake_connection_count;

    size_t bad_connection_to_offer;
    size_t offer_bad_connection_count;

    /* Mock will wait for delay_finished to offer connections synced. Once flip async finished to true, you should offer
     * the count connections */
    size_t delay_offer_connection_count;
    bool delay_finished;

    struct aws_array_list fake_connections;
    bool release_sm_during_connection_acquiring;

    uint32_t max_con_stream_remote;

    /* To invoke the real on_setup */
    aws_http_on_client_connection_setup_fn *on_setup;

    size_t length_sent;
};

static struct sm_tester s_tester;

struct sm_fake_connection {
    struct testing_channel testing_channel;
    struct h2_fake_peer peer;
    struct aws_http_client_connection_options options;
    struct aws_http_connection *connection;
};

static void s_testing_channel_shutdown(int error_code, void *user_data) {
    struct sm_fake_connection *fake_connection = (struct sm_fake_connection *)user_data;
    if (!fake_connection->connection) {
        /* If there is no connection, which means the fake_connection is a bad connection and we should not invoke on
         * shutdown as setup failed for them */
        return;
    }
    if (fake_connection->options.on_shutdown) {
        /* In real world, this is trigger by the bootstrap */
        fake_connection->options.on_shutdown(
            fake_connection->connection, error_code, fake_connection->options.user_data);
    }
}

static struct sm_fake_connection *s_get_fake_connection(size_t i) {
    AWS_FATAL_ASSERT(aws_array_list_length(&s_tester.fake_connections) > i);
    struct sm_fake_connection *fake_connection = NULL;
    aws_array_list_get_at(&s_tester.fake_connections, &fake_connection, i);
    return fake_connection;
}

static struct sm_fake_connection *s_sm_fake_connection_new(void) {
    struct sm_fake_connection *fake_connection =
        aws_mem_calloc(s_tester.allocator, 1, sizeof(struct sm_fake_connection));

    struct aws_testing_channel_options options = {.clock_fn = aws_high_res_clock_get_ticks};

    AWS_FATAL_ASSERT(
        testing_channel_init(&fake_connection->testing_channel, s_tester.allocator, &options) == AWS_OP_SUCCESS);
    fake_connection->testing_channel.channel_shutdown_user_data = fake_connection;
    fake_connection->testing_channel.channel_shutdown = s_testing_channel_shutdown;
    struct h2_fake_peer_options peer_options = {
        .alloc = s_tester.allocator,
        .testing_channel = &fake_connection->testing_channel,
        .is_server = true,
    };
    AWS_FATAL_ASSERT(h2_fake_peer_init(&fake_connection->peer, &peer_options) == AWS_OP_SUCCESS);

    return fake_connection;
}

static void s_sm_fake_connection_destroy(struct sm_fake_connection *fake_connection) {

    AWS_FATAL_ASSERT(testing_channel_clean_up(&fake_connection->testing_channel) == AWS_OP_SUCCESS);
    aws_mem_release(s_tester.allocator, fake_connection);
}

static bool s_is_shutdown_complete(void *context) {
    (void)context;
    return s_tester.is_shutdown_complete;
}

static int s_wait_on_shutdown_complete(void) {
    ASSERT_SUCCESS(aws_mutex_lock(&s_tester.lock));

    int signal_error = aws_condition_variable_wait_pred(&s_tester.signal, &s_tester.lock, s_is_shutdown_complete, NULL);

    ASSERT_SUCCESS(aws_mutex_unlock(&s_tester.lock));
    return signal_error;
}

static void s_sm_tester_on_sm_shutdown_complete(void *user_data) {
    struct sm_tester *tester = user_data;
    AWS_FATAL_ASSERT(tester == &s_tester);

    aws_mutex_lock(&s_tester.lock);
    s_tester.is_shutdown_complete = true;
    aws_mutex_unlock(&s_tester.lock);
    aws_condition_variable_notify_one(&s_tester.signal);
}

static int s_tester_init(struct sm_tester_options *options) {
    struct aws_allocator *alloc = options->alloc;
    aws_http_library_init(alloc);

    s_tester.allocator = alloc;

    struct aws_logger_standard_options logger_options = {
        .level = options->log_level ? *options->log_level : AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    aws_logger_init_standard(&s_logger, alloc, &logger_options);
    aws_logger_set(&s_logger);

    ASSERT_SUCCESS(aws_mutex_init(&s_tester.lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&s_tester.signal));

    s_tester.event_loop_group = aws_event_loop_group_new_default(alloc, 0, NULL);

    ASSERT_SUCCESS(aws_array_list_init_dynamic(&s_tester.streams, alloc, 1, sizeof(struct aws_http_stream *)));
    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&s_tester.fake_connections, alloc, 3, sizeof(struct sm_fake_connection *)));

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = s_tester.event_loop_group,
        .max_entries = 8,
    };

    s_tester.host_resolver = aws_host_resolver_new_default(s_tester.allocator, &resolver_options);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = s_tester.event_loop_group,
        .host_resolver = s_tester.host_resolver,
    };
    s_tester.client_bootstrap = aws_client_bootstrap_new(s_tester.allocator, &bootstrap_options);
    ASSERT_NOT_NULL(s_tester.client_bootstrap);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms = (uint32_t)aws_timestamp_convert(10, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    if (options->uri_cursor) {
        ASSERT_SUCCESS(aws_uri_init_parse(&s_tester.endpoint, alloc, options->uri_cursor));
    } else {
        struct aws_byte_cursor default_host = aws_byte_cursor_from_c_str("https://www.amazon.com");
        ASSERT_SUCCESS(aws_uri_init_parse(&s_tester.endpoint, alloc, &default_host));
    }

    bool use_tls = true;
    uint32_t port = 443;
    if (!s_tester.endpoint.scheme.len && (s_tester.endpoint.port == 80 || s_tester.endpoint.port == 3280)) {
        use_tls = false;
    } else {
        if (aws_byte_cursor_eq_c_str_ignore_case(&s_tester.endpoint.scheme, "http")) {
            use_tls = false;
        }
    }
    if (s_tester.endpoint.port) {
        port = s_tester.endpoint.port;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(&s_tester.endpoint.scheme, "http")) {
        port = 80;
    }

    if (use_tls) {
        aws_tls_ctx_options_init_default_client(&s_tester.tls_ctx_options, alloc);
        if (!options->no_http2) {
            ASSERT_SUCCESS(aws_tls_ctx_options_set_alpn_list(&s_tester.tls_ctx_options, "h2"));
        }
        if (aws_byte_cursor_eq_c_str_ignore_case(&s_tester.endpoint.host_name, "localhost")) {
            /* Turn off peer verification as a localhost cert used */
            s_tester.tls_ctx_options.verify_peer = false;
        }
        s_tester.tls_ctx = aws_tls_client_ctx_new(alloc, &s_tester.tls_ctx_options);

        ASSERT_NOT_NULL(s_tester.tls_ctx);
        aws_tls_connection_options_init_from_ctx(&s_tester.tls_connection_options, s_tester.tls_ctx);
        aws_tls_connection_options_set_server_name(
            &s_tester.tls_connection_options, alloc, &s_tester.endpoint.host_name);
    }
    struct aws_http2_stream_manager_options sm_options = {
        .bootstrap = s_tester.client_bootstrap,
        .socket_options = &socket_options,
        .tls_connection_options = use_tls ? &s_tester.tls_connection_options : NULL,
        .host = s_tester.endpoint.host_name,
        .port = port,
        .ideal_concurrent_streams_per_connection = options->ideal_concurrent_streams_per_connection,
        .max_concurrent_streams_per_connection = options->max_concurrent_streams_per_connection,
        .max_connections = options->max_connections,
        .shutdown_complete_user_data = &s_tester,
        .shutdown_complete_callback = s_sm_tester_on_sm_shutdown_complete,
        .monitoring_options = options->monitor_opt,
        .close_connection_on_server_error = options->close_connection_on_server_error,
        .connection_ping_period_ms = options->connection_ping_period_ms,
        .connection_ping_timeout_ms = options->connection_ping_timeout_ms,
        .http2_prior_knowledge = options->prior_knowledge,
    };
    s_tester.stream_manager = aws_http2_stream_manager_new(alloc, &sm_options);

    s_tester.max_con_stream_remote = 100;
    aws_atomic_init_int(&s_tester.stream_destroyed_count, 0);

    return AWS_OP_SUCCESS;
}

static void s_release_all_streams(void) {

    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.lock) == AWS_OP_SUCCESS);
    size_t release_count = aws_array_list_length(&s_tester.streams);
    for (size_t i = 0; i < release_count; ++i) {
        struct aws_http_stream *stream = NULL;
        if (aws_array_list_back(&s_tester.streams, &stream)) {
            continue;
        }
        aws_http_stream_release(stream);
        aws_array_list_pop_back(&s_tester.streams);
    }
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);
}

static int s_fake_connection_get_stream_received(struct sm_fake_connection *fake_connection) {
    AWS_FATAL_ASSERT(h2_fake_peer_decode_messages_from_testing_channel(&fake_connection->peer) == AWS_OP_SUCCESS);
    size_t frames_count = h2_decode_tester_frame_count(&fake_connection->peer.decode);
    int streams_received = 0;
    for (size_t i = 0; i < frames_count; ++i) {
        struct h2_decoded_frame *frame = h2_decode_tester_get_frame(&fake_connection->peer.decode, i);
        if (frame->end_stream) {
            ++streams_received;
        }
    }
    return streams_received;
}

/* complete first num_streams_to_complete. If num_streams_to_complete is zero, complete all the streams. */
static void s_fake_connection_complete_streams(
    struct sm_fake_connection *fake_connection,
    int num_streams_to_complete) {
    if (!fake_connection->connection) {
        return;
    }

    testing_channel_drain_queued_tasks(&fake_connection->testing_channel);

    AWS_FATAL_ASSERT(h2_fake_peer_decode_messages_from_testing_channel(&fake_connection->peer) == AWS_OP_SUCCESS);
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };
    struct aws_http_headers *response_headers = aws_http_headers_new(s_tester.allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));
    size_t frames_count = h2_decode_tester_frame_count(&fake_connection->peer.decode);
    int streams_completed = 0;
    for (size_t i = 0; i < frames_count; ++i) {
        struct h2_decoded_frame *frame = h2_decode_tester_get_frame(&fake_connection->peer.decode, i);
        if (frame->end_stream) {
            struct aws_h2_frame *response_frame = aws_h2_frame_new_headers(
                s_tester.allocator, frame->stream_id, response_headers, true /*end_stream*/, 0, NULL);
            AWS_FATAL_ASSERT(h2_fake_peer_send_frame(&fake_connection->peer, response_frame) == AWS_OP_SUCCESS);
            if (num_streams_to_complete && ++streams_completed >= num_streams_to_complete) {
                break;
            }
        }
    }
    aws_http_headers_release(response_headers);
    testing_channel_drain_queued_tasks(&fake_connection->testing_channel);
}

static void s_clean_fake_connections(void) {

    size_t release_count = aws_array_list_length(&s_tester.fake_connections);
    for (size_t i = 0; i < release_count; ++i) {
        struct sm_fake_connection *fake_connection = NULL;
        if (aws_array_list_back(&s_tester.fake_connections, &fake_connection)) {
            continue;
        }
        aws_array_list_pop_back(&s_tester.fake_connections);
        s_sm_fake_connection_destroy(fake_connection);
    }
    aws_array_list_clean_up(&s_tester.fake_connections);
}

static void s_drain_all_fake_connection_testing_channel(void) {
    size_t count = aws_array_list_length(&s_tester.fake_connections);
    for (size_t i = 0; i < count; ++i) {
        struct sm_fake_connection *fake_connection = NULL;
        aws_array_list_get_at(&s_tester.fake_connections, &fake_connection, i);
        testing_channel_drain_queued_tasks(&fake_connection->testing_channel);
    }
}

static void s_release_fake_connections(void) {
    size_t count = aws_array_list_length(&s_tester.fake_connections);
    for (size_t i = 0; i < count; ++i) {
        struct sm_fake_connection *fake_connection = NULL;
        aws_array_list_get_at(&s_tester.fake_connections, &fake_connection, i);
        aws_http_connection_release(fake_connection->connection);
        h2_fake_peer_clean_up(&fake_connection->peer);
    }
    s_drain_all_fake_connection_testing_channel();
}

static int s_complete_all_fake_connection_streams(void) {
    size_t count = aws_array_list_length(&s_tester.fake_connections);
    for (size_t i = 0; i < count; ++i) {
        struct sm_fake_connection *fake_connection = NULL;
        ASSERT_SUCCESS(aws_array_list_get_at(&s_tester.fake_connections, &fake_connection, i));
        /* complete all the streams from the fake connection */
        s_fake_connection_complete_streams(fake_connection, 0 /*all streams*/);
        testing_channel_drain_queued_tasks(&fake_connection->testing_channel);
    }
    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
    s_release_all_streams();
    if (s_tester.stream_manager) {
        s_release_fake_connections();
        aws_http2_stream_manager_release(s_tester.stream_manager);
    }
    s_drain_all_fake_connection_testing_channel();
    s_wait_on_shutdown_complete();
    s_clean_fake_connections();
    aws_client_bootstrap_release(s_tester.client_bootstrap);

    aws_host_resolver_release(s_tester.host_resolver);
    aws_event_loop_group_release(s_tester.event_loop_group);

    aws_tls_ctx_options_clean_up(&s_tester.tls_ctx_options);
    aws_tls_connection_options_clean_up(&s_tester.tls_connection_options);
    aws_tls_ctx_release(s_tester.tls_ctx);

    aws_http_library_clean_up();

    aws_mutex_clean_up(&s_tester.lock);
    aws_condition_variable_clean_up(&s_tester.signal);
    aws_array_list_clean_up(&s_tester.streams);
    aws_uri_clean_up(&s_tester.endpoint);
    aws_logger_clean_up(&s_logger);

    return AWS_OP_SUCCESS;
}

static void s_sm_tester_on_stream_acquired(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)user_data;

    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.lock) == AWS_OP_SUCCESS);

    if (error_code) {
        ++s_tester.acquiring_stream_errors;
        ++s_tester.stream_completed_count; /* As the stream will never be completed through complete callback */
        s_tester.error_code = error_code;
    } else {
        aws_array_list_push_back(&s_tester.streams, &stream);
    }

    aws_condition_variable_notify_one(&s_tester.signal);

    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);
}

static bool s_is_stream_acquired_count_at_least(void *context) {
    (void)context;
    return s_tester.wait_for_stream_acquire_count <=
           aws_array_list_length(&s_tester.streams) + s_tester.acquiring_stream_errors;
}

static int s_wait_on_streams_acquired_count(size_t count) {
    ASSERT_SUCCESS(aws_mutex_lock(&s_tester.lock));

    s_tester.wait_for_stream_acquire_count = count;
    int signal_error =
        aws_condition_variable_wait_pred(&s_tester.signal, &s_tester.lock, s_is_stream_acquired_count_at_least, NULL);

    ASSERT_SUCCESS(aws_mutex_unlock(&s_tester.lock));
    return signal_error;
}

static bool s_is_stream_completed_count_at_least(void *context) {
    (void)context;
    return s_tester.wait_for_stream_completed_count <= s_tester.stream_completed_count;
}

static int s_wait_on_streams_completed_count(size_t count) {
    ASSERT_SUCCESS(aws_mutex_lock(&s_tester.lock));

    s_tester.wait_for_stream_completed_count = count;
    int signal_error =
        aws_condition_variable_wait_pred(&s_tester.signal, &s_tester.lock, s_is_stream_completed_count_at_least, NULL);

    ASSERT_SUCCESS(aws_mutex_unlock(&s_tester.lock));
    return signal_error;
}

static void s_sm_tester_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)user_data;
    (void)stream;
    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.lock) == AWS_OP_SUCCESS);
    if (error_code) {
        ++s_tester.stream_complete_errors;
        s_tester.stream_completed_error_code = error_code;
    } else {
        int status = 0;
        if (aws_http_stream_get_incoming_response_status(stream, &status)) {
            ++s_tester.stream_complete_errors;
            s_tester.stream_completed_error_code = aws_last_error();
        } else {
            if (status == 200) {
                ++s_tester.stream_200_count;
            } else {
                ++s_tester.stream_status_not_200_count;
            }
        }
    }
    ++s_tester.stream_completed_count;
    aws_condition_variable_notify_one(&s_tester.signal);
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);
}

static void s_sm_tester_on_stream_destroy(void *user_data) {
    (void)user_data;
    aws_atomic_fetch_add(&s_tester.stream_destroyed_count, 1);
}

static int s_sm_stream_acquiring_customize_request(
    int num_streams,
    struct aws_http_make_request_options *request_options) {
    struct aws_http2_stream_manager_acquire_stream_options acquire_stream_option = {
        .options = request_options,
        .callback = s_sm_tester_on_stream_acquired,
        .user_data = &s_tester,
    };
    for (int i = 0; i < num_streams; ++i) {
        /* TODO: Test the callback will always be fired asynced, as now the CM cannot ensure the callback happens
         * asynchronously, we cannot ensure it as well. */
        aws_http2_stream_manager_acquire_stream(s_tester.stream_manager, &acquire_stream_option);
    }
    return AWS_OP_SUCCESS;
}

static struct aws_byte_cursor s_default_empty_path = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/");

struct aws_byte_cursor s_normalize_path(struct aws_byte_cursor path) {
    return path.len == 0 ? s_default_empty_path : path;
}

static int s_sm_stream_acquiring(int num_streams) {
    struct aws_http_message *request = aws_http2_message_new_request(s_tester.allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        {
            .name = aws_byte_cursor_from_c_str(":scheme"),
            .value = *aws_uri_scheme(&s_tester.endpoint),
        },
        {
            .name = aws_byte_cursor_from_c_str(":path"),
            .value = s_normalize_path(*aws_uri_path(&s_tester.endpoint)),
        },
        {
            .name = aws_byte_cursor_from_c_str(":authority"),
            .value = *aws_uri_host_name(&s_tester.endpoint),
        },
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = &s_tester,
        .on_complete = s_sm_tester_on_stream_complete,
        .on_destroy = s_sm_tester_on_stream_destroy,
    };
    int return_code = s_sm_stream_acquiring_customize_request(num_streams, &request_options);
    aws_http_message_release(request);
    return return_code;
}

/* Test the common setup/teardown used by all tests in this file */
TEST_CASE(h2_sm_sanity_check) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    return s_tester_clean_up();
}

static bool s_is_fake_connection_count(void *context) {
    (void)context;
    return s_tester.wait_for_fake_connection_count <= aws_array_list_length(&s_tester.fake_connections);
}

static int s_wait_on_fake_connection_count(size_t count) {
    ASSERT_SUCCESS(aws_mutex_lock(&s_tester.lock));

    s_tester.wait_for_fake_connection_count = count;
    int signal_error =
        aws_condition_variable_wait_pred(&s_tester.signal, &s_tester.lock, s_is_fake_connection_count, NULL);

    ASSERT_SUCCESS(aws_mutex_unlock(&s_tester.lock));
    return signal_error;
}

static struct sm_fake_connection *s_sm_tester_fake_connection_new_from_options(
    const struct aws_http_client_connection_options *options) {
    struct sm_fake_connection *fake_connection = s_sm_fake_connection_new();
    fake_connection->options = *options;
    AWS_FATAL_ASSERT(aws_array_list_push_back(&s_tester.fake_connections, &fake_connection) == AWS_OP_SUCCESS);
    if (s_tester.offer_bad_connection_count < s_tester.bad_connection_to_offer) {
        /* Offer a bad connection */
        s_tester.offer_bad_connection_count++;
        return fake_connection;
    }

    struct aws_http_connection *connection = aws_http_connection_new_http2_client(
        options->allocator, options->manual_window_management /* manual window management */, options->http2_options);
    AWS_FATAL_ASSERT(connection);
    aws_http_connection_acquire(connection);

    {
        /* set connection user_data (handled by http-bootstrap in real world) */
        connection->user_data = options->user_data;
        /* re-enact marriage vows of http-connection and channel (handled by http-bootstrap in real world) */
        struct aws_channel_slot *slot = aws_channel_slot_new(fake_connection->testing_channel.channel);
        AWS_FATAL_ASSERT(slot);
        AWS_FATAL_ASSERT(aws_channel_slot_insert_end(fake_connection->testing_channel.channel, slot) == AWS_OP_SUCCESS);
        AWS_FATAL_ASSERT(aws_channel_slot_set_handler(slot, &connection->channel_handler) == AWS_OP_SUCCESS);
        connection->vtable->on_channel_handler_installed(&connection->channel_handler, slot);
    }
    fake_connection->connection = connection;
    return fake_connection;
}

static int s_sm_tester_finish_up_fake_connection_set_up(struct sm_fake_connection *fake_connection) {
    if (!fake_connection->connection) {
        fake_connection->options.on_setup(NULL, aws_last_error(), fake_connection->options.user_data);
        return AWS_OP_SUCCESS;
    }

    /* Invoke callback outside lock */
    fake_connection->options.on_setup(
        fake_connection->connection, AWS_ERROR_SUCCESS, fake_connection->options.user_data);
    testing_channel_drain_queued_tasks(&fake_connection->testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&fake_connection->peer));
    struct aws_http2_setting settings_array[] = {
        {
            .id = AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
            .value = s_tester.max_con_stream_remote,
        },
    };

    struct aws_h2_frame *settings_frame =
        aws_h2_frame_new_settings(s_tester.allocator, settings_array, AWS_ARRAY_SIZE(settings_array), false /*ack*/);
    ASSERT_NOT_NULL(settings_frame);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&fake_connection->peer, settings_frame));
    struct aws_h2_frame *settings_ack = aws_h2_frame_new_settings(s_tester.allocator, NULL, 0, true /*ack*/);
    ASSERT_NOT_NULL(settings_ack);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&fake_connection->peer, settings_ack));
    return AWS_OP_SUCCESS;
}

static int s_aws_http_connection_manager_create_connection_sync_mock(
    const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.lock) == AWS_OP_SUCCESS);
    struct sm_fake_connection *fake_connection = s_sm_tester_fake_connection_new_from_options(options);
    aws_condition_variable_notify_one(&s_tester.signal);
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);
    ASSERT_SUCCESS(s_sm_tester_finish_up_fake_connection_set_up(fake_connection));
    return AWS_OP_SUCCESS;
}

static int s_aws_http_connection_manager_create_connection_delay_mock(
    const struct aws_http_client_connection_options *options) {

    if (s_tester.delay_finished) {
        return s_aws_http_connection_manager_create_connection_sync_mock(options);
    }
    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.lock) == AWS_OP_SUCCESS);
    ++s_tester.delay_offer_connection_count;
    struct sm_fake_connection *fake_connection = s_sm_tester_fake_connection_new_from_options(options);
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);

    /* don't do anything as it's delivered delay */
    (void)fake_connection;
    return AWS_OP_SUCCESS;
}

static int s_sm_tester_offer_waiting_connections(void) {

    for (size_t i = 0; i < s_tester.delay_offer_connection_count; i++) {
        struct sm_fake_connection *fake_connection = s_get_fake_connection(i);
        ASSERT_SUCCESS(s_sm_tester_finish_up_fake_connection_set_up(fake_connection));
    }
    s_tester.delay_finished = true;
    /* We are not haveing any threads. so, not invoking anything */
    return AWS_OP_SUCCESS;
}

static struct aws_http_connection_manager_system_vtable s_mocks;

static void s_override_cm_connect_function(int (*fn)(const struct aws_http_client_connection_options *options)) {
    s_mocks = *g_aws_http_connection_manager_default_system_vtable_ptr;
    s_mocks.aws_http_client_connect = fn;
    s_tester.connection_manager = s_tester.stream_manager->connection_manager;
    aws_http_connection_manager_set_system_vtable(s_tester.connection_manager, &s_mocks);
}

TEST_CASE(h2_sm_mock_connection) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    int num_to_acquire = 5;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(num_to_acquire));
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());
    size_t destroyed = aws_atomic_load_int(&s_tester.stream_destroyed_count);
    ASSERT_INT_EQUALS(0, destroyed);
    s_release_all_streams();
    destroyed = aws_atomic_load_int(&s_tester.stream_destroyed_count);
    ASSERT_INT_EQUALS(num_to_acquire, destroyed);

    return s_tester_clean_up();
}

TEST_CASE(h2_sm_mock_multiple_connections) {
    (void)ctx;
    size_t max_concurrent_streams_per_connection = 3;
    int num_streams_to_acquire = 9;
    int num_expected_connection = num_streams_to_acquire / (int)max_concurrent_streams_per_connection;
    if (num_streams_to_acquire % max_concurrent_streams_per_connection) {
        ++num_expected_connection;
    }
    struct sm_tester_options options = {
        .max_connections = 5,
        .max_concurrent_streams_per_connection = max_concurrent_streams_per_connection,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_streams_to_acquire));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(num_expected_connection));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(num_streams_to_acquire));
    ASSERT_TRUE(aws_array_list_length(&s_tester.fake_connections) == (size_t)num_expected_connection);
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}

/* Test stream manager got an bad connection and fail the expected number of stream requests. */
TEST_CASE(h2_sm_mock_bad_connection_acquired) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .ideal_concurrent_streams_per_connection = 2,
        .max_concurrent_streams_per_connection = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_tester.bad_connection_to_offer = 2;
    size_t good_connections_num = options.max_connections - s_tester.bad_connection_to_offer;
    size_t streams_acquiring_num = 15;
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_delay_mock);
    ASSERT_SUCCESS(s_sm_stream_acquiring((int)streams_acquiring_num));
    /* The count should be max connection now */
    ASSERT_UINT_EQUALS(s_tester.delay_offer_connection_count, options.max_connections);
    /* Offer the connections waiting */
    ASSERT_SUCCESS(s_sm_tester_offer_waiting_connections());
    /* waiting for 3 fake connection made as the first two connection will fail */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(good_connections_num));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(streams_acquiring_num));
    /* We fail the number of streams cannot fit into the health connections based on the ideal. */
    ASSERT_INT_EQUALS(
        streams_acquiring_num - options.ideal_concurrent_streams_per_connection * good_connections_num,
        s_tester.acquiring_stream_errors);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_STREAM_MANAGER_CONNECTION_ACQUIRE_FAILURE, s_tester.error_code);
    ASSERT_TRUE(aws_array_list_length(&s_tester.streams) == 6);

    /* Acquire more streams, which should succeed as we don't close the connection */
    ASSERT_SUCCESS(s_sm_stream_acquiring(4));
    /* waiting for the new connection */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(options.max_connections + 2));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(streams_acquiring_num + 4));
    /* all the new streams succeed */
    ASSERT_TRUE(aws_array_list_length(&s_tester.streams) == 10);
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}

/* Test a connection offered, and before the stream was made, the connection dies. The stream should fail */
TEST_CASE(h2_sm_mock_connections_closed_before_request_made) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 1,
        .max_concurrent_streams_per_connection = 3,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    ASSERT_SUCCESS(s_sm_stream_acquiring(2));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(2));
    /* No error happens */
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    /* Now, we close the connection, the stream manager will fail the new stream, if the opening streams not completed.
     */
    struct sm_fake_connection *fake_connection = s_get_fake_connection(0);
    aws_http_connection_close(fake_connection->connection);
    ASSERT_SUCCESS(s_sm_stream_acquiring(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(3));
    /* ASSERT new one failed. */
    ASSERT_INT_EQUALS(1, s_tester.acquiring_stream_errors);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, s_tester.error_code);
    /* Reset errors */
    s_tester.acquiring_stream_errors = 0;
    s_tester.error_code = 0;
    s_drain_all_fake_connection_testing_channel();

    /* As long as the connection finishes shutting down, we can still make more requests from new connection. */
    ASSERT_SUCCESS(s_sm_stream_acquiring(2));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(2));
    s_drain_all_fake_connection_testing_channel();
    /* No error happens */
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    /* We made 4 streams successfully */
    ASSERT_INT_EQUALS(4, aws_array_list_length(&s_tester.streams));

    /* Finish all the opening streams */
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}

/* Test that the remote max concurrent streams setting hit */
TEST_CASE(h2_sm_mock_max_concurrent_streams_remote) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    /* Set the remote max to be 2 */
    s_tester.max_con_stream_remote = 2;
    /* Acquire a stream to trigger */
    ASSERT_SUCCESS(s_sm_stream_acquiring(1));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(1));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    ASSERT_INT_EQUALS(0, s_tester.stream_complete_errors);

    /* Fake peer send settings that only allow 2 concurrent streams */
    /* Acquire tow more streams */
    ASSERT_SUCCESS(s_sm_stream_acquiring(2));
    /* We created a new connection */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(2));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(1 + 2));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);

    ASSERT_INT_EQUALS(2, aws_array_list_length(&s_tester.fake_connections));
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}

/* Test that the remote max concurrent streams setting hit */
TEST_CASE(h2_sm_mock_fetch_metric) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    /* Set the remote max to be 2 */
    s_tester.max_con_stream_remote = 2;
    /* Acquire a stream to trigger */
    ASSERT_SUCCESS(s_sm_stream_acquiring(1));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(1));
    struct aws_http_manager_metrics out_metrics;
    AWS_ZERO_STRUCT(out_metrics);

    aws_http2_stream_manager_fetch_metrics(s_tester.stream_manager, &out_metrics);
    /* Acquired 1 stream, and we hold one connection, the max streams per connection is 2. */
    ASSERT_UINT_EQUALS(out_metrics.available_concurrency, 1);
    ASSERT_UINT_EQUALS(out_metrics.pending_concurrency_acquires, 0);
    ASSERT_UINT_EQUALS(out_metrics.leased_concurrency, 1);

    ASSERT_SUCCESS(s_sm_stream_acquiring(1));

    ASSERT_SUCCESS(s_wait_on_fake_connection_count(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(2));
    aws_http2_stream_manager_fetch_metrics(s_tester.stream_manager, &out_metrics);
    ASSERT_UINT_EQUALS(out_metrics.available_concurrency, 0);
    ASSERT_UINT_EQUALS(out_metrics.pending_concurrency_acquires, 0);
    ASSERT_UINT_EQUALS(out_metrics.leased_concurrency, 2);

    ASSERT_SUCCESS(s_sm_stream_acquiring(10));
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(5));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(10));
    aws_http2_stream_manager_fetch_metrics(s_tester.stream_manager, &out_metrics);
    ASSERT_UINT_EQUALS(out_metrics.available_concurrency, 0);
    ASSERT_UINT_EQUALS(out_metrics.pending_concurrency_acquires, 2);
    ASSERT_UINT_EQUALS(out_metrics.leased_concurrency, 10);

    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());
    /* Still have two more streams that have not been completed */
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}

/* Test that the stream completed will free the connection for more streams */
TEST_CASE(h2_sm_mock_complete_stream) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .ideal_concurrent_streams_per_connection = 2,
        .max_concurrent_streams_per_connection = 2,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    ASSERT_SUCCESS(s_sm_stream_acquiring(2));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(2));
    ASSERT_INT_EQUALS(1, aws_array_list_length(&s_tester.fake_connections));

    /* Fake peer send settings that only allow 2 concurrent streams */
    struct sm_fake_connection *fake_connection = s_get_fake_connection(0);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&fake_connection->peer));
    s_fake_connection_complete_streams(fake_connection, 1);

    /* Acquire a new streams */
    ASSERT_SUCCESS(s_sm_stream_acquiring(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(2 + 1));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    /* No error happens */
    ASSERT_INT_EQUALS(0, s_tester.stream_complete_errors);
    /* We have no extra connection made. */
    ASSERT_INT_EQUALS(1, aws_array_list_length(&s_tester.fake_connections));

    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}

/* Test the soft limit from user works as we want */
TEST_CASE(h2_sm_mock_ideal_num_streams) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .ideal_concurrent_streams_per_connection = 3,
        .max_concurrent_streams_per_connection = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    ASSERT_SUCCESS(s_sm_stream_acquiring(15));
    /* We will create 5 connections instead of 3 */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(5));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(15));
    ASSERT_INT_EQUALS(5, aws_array_list_length(&s_tester.fake_connections));

    s_drain_all_fake_connection_testing_channel();
    /* Check all the 5 fake connections received 3 streams each */
    for (size_t i = 0; i < aws_array_list_length(&s_tester.fake_connections); ++i) {
        struct sm_fake_connection *fake_connection = s_get_fake_connection(i);
        ASSERT_INT_EQUALS(
            s_fake_connection_get_stream_received(fake_connection), options.ideal_concurrent_streams_per_connection);
    }

    /* Acquire 15 more, we can only have 25 (5*5) in total */
    ASSERT_SUCCESS(s_sm_stream_acquiring(15));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(10));

    s_drain_all_fake_connection_testing_channel();
    /* Check all the 5 fake connections received 5 streams each */
    for (size_t i = 0; i < aws_array_list_length(&s_tester.fake_connections); ++i) {
        struct sm_fake_connection *fake_connection = s_get_fake_connection(i);
        ASSERT_INT_EQUALS(
            s_fake_connection_get_stream_received(fake_connection), options.max_concurrent_streams_per_connection);
    }

    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());
    s_drain_all_fake_connection_testing_channel();
    /* completed the remain streams */
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());
    return s_tester_clean_up();
}

TEST_CASE(h2_sm_mock_large_ideal_num_streams) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .ideal_concurrent_streams_per_connection = 3,
        .max_concurrent_streams_per_connection = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    /* Set the remote max to be 2 */
    s_tester.max_con_stream_remote = 2;
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    ASSERT_SUCCESS(s_sm_stream_acquiring(6));
    /* We will create 3 connections instead of 2 */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(3));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(6));
    ASSERT_INT_EQUALS(3, aws_array_list_length(&s_tester.fake_connections));

    s_drain_all_fake_connection_testing_channel();

    for (size_t i = 0; i < aws_array_list_length(&s_tester.fake_connections); ++i) {
        struct sm_fake_connection *fake_connection = s_get_fake_connection(i);
        ASSERT_INT_EQUALS(s_fake_connection_get_stream_received(fake_connection), s_tester.max_con_stream_remote);
    }

    /* Acquire 15 more, we can only have 10 (2*5) in total. 21 acquisitions made */
    ASSERT_SUCCESS(s_sm_stream_acquiring(15));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(10 - 6));

    s_drain_all_fake_connection_testing_channel();
    for (size_t i = 0; i < aws_array_list_length(&s_tester.fake_connections); ++i) {
        struct sm_fake_connection *fake_connection = s_get_fake_connection(i);
        ASSERT_INT_EQUALS(s_fake_connection_get_stream_received(fake_connection), s_tester.max_con_stream_remote);
    }
    ASSERT_UINT_EQUALS(10, aws_array_list_length(&s_tester.streams));
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());
    s_drain_all_fake_connection_testing_channel();
    /* Completed 10 streams, 10 more streams created */
    ASSERT_UINT_EQUALS(20, aws_array_list_length(&s_tester.streams));
    /* Completed remain 10 streams */
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());
    s_drain_all_fake_connection_testing_channel();
    /* Should have 1 more streams made now, which will have all 21 made */
    ASSERT_UINT_EQUALS(21, aws_array_list_length(&s_tester.streams));
    /* Completed all of them again, and we are good */
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());
    s_drain_all_fake_connection_testing_channel();

    return s_tester_clean_up();
}

/* Test that goaway received from peer, new connection will be made */
TEST_CASE(h2_sm_mock_goaway) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    ASSERT_SUCCESS(s_sm_stream_acquiring(5));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(5));
    ASSERT_INT_EQUALS(1, aws_array_list_length(&s_tester.fake_connections));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);

    /* Fake peer send goaway */
    struct sm_fake_connection *fake_connection = s_get_fake_connection(0);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&fake_connection->peer));
    struct aws_byte_cursor debug_info;
    AWS_ZERO_STRUCT(debug_info);
    struct aws_http_stream *stream = NULL;
    aws_array_list_front(&s_tester.streams, &stream);
    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_goaway(allocator, aws_http_stream_get_id(stream), AWS_HTTP2_ERR_NO_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&fake_connection->peer, peer_frame));
    testing_channel_drain_queued_tasks(&fake_connection->testing_channel);

    /* Should be the streams with id larger than the first stream all completed with error */
    ASSERT_INT_EQUALS(4, s_tester.stream_complete_errors);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_GOAWAY_RECEIVED, s_tester.stream_completed_error_code);

    /* When we create new streams, stream manager should create a new connection to use */
    ASSERT_SUCCESS(s_sm_stream_acquiring(5));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(2));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(5 + 5));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    /* No more stream completed with error */
    ASSERT_INT_EQUALS(4, s_tester.stream_complete_errors);
    /* Two connection made */
    ASSERT_INT_EQUALS(2, aws_array_list_length(&s_tester.fake_connections));
    fake_connection = s_get_fake_connection(1);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&fake_connection->peer));

    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}

/* Test that PING works as expected. */
TEST_CASE(h2_sm_connection_ping) {
    (void)ctx;
    size_t connection_ping_timeout_ms = AWS_TIMESTAMP_MILLIS; /* 1 sec */
    struct sm_tester_options options = {
        .max_connections = 3,
        .alloc = allocator,
        .max_concurrent_streams_per_connection = 2,
        .connection_ping_period_ms = 2 * AWS_TIMESTAMP_MILLIS,
        .connection_ping_timeout_ms = connection_ping_timeout_ms,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    ASSERT_SUCCESS(s_sm_stream_acquiring(6));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(3));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(6));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);

    aws_thread_current_sleep(2 * AWS_TIMESTAMP_NANOS); /* Sleep 2 sec */

    /* Check PING received for all the connections */
    struct sm_fake_connection *fake_connection_1 = s_get_fake_connection(0);
    struct sm_fake_connection *fake_connection_2 = s_get_fake_connection(1);
    struct sm_fake_connection *fake_connection_3 = s_get_fake_connection(2);
    testing_channel_drain_queued_tasks(&fake_connection_1->testing_channel);
    testing_channel_drain_queued_tasks(&fake_connection_2->testing_channel);
    testing_channel_drain_queued_tasks(&fake_connection_3->testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&fake_connection_1->peer));
    struct h2_decoded_frame *ping_frame =
        h2_decode_tester_find_frame(&fake_connection_1->peer.decode, AWS_H2_FRAME_T_PING, 0, NULL);
    ASSERT_NOT_NULL(ping_frame);

    /* Fake peer only send PINGACK to the first connection immediately */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&fake_connection_1->peer));
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_ping(allocator, true /*ACK*/, ping_frame->ping_opaque_data);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&fake_connection_1->peer, peer_frame));
    testing_channel_drain_queued_tasks(&fake_connection_1->testing_channel);
    s_fake_connection_complete_streams(
        fake_connection_1, 0 /*all streams*/); /* Make sure the streams completed successfully */

    /* Check fake connection 2 received PING */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&fake_connection_2->peer));
    ping_frame = h2_decode_tester_find_frame(&fake_connection_2->peer.decode, AWS_H2_FRAME_T_PING, 0, NULL);
    ASSERT_NOT_NULL(ping_frame);
    /* Check fake connection 3 received PING, but never send ping for connection 3 */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&fake_connection_3->peer));
    ping_frame = h2_decode_tester_find_frame(&fake_connection_3->peer.decode, AWS_H2_FRAME_T_PING, 0, NULL);
    ASSERT_NOT_NULL(ping_frame);

    aws_thread_current_sleep(AWS_TIMESTAMP_NANOS); /* Sleep 1 sec */
    testing_channel_drain_queued_tasks(&fake_connection_2->testing_channel);
    testing_channel_drain_queued_tasks(&fake_connection_3->testing_channel);

    /* Send PINGACK for connection 2 after timeout has happened */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&fake_connection_2->peer));
    peer_frame = aws_h2_frame_new_ping(allocator, true /*ACK*/, ping_frame->ping_opaque_data);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&fake_connection_2->peer, peer_frame));
    testing_channel_drain_queued_tasks(&fake_connection_2->testing_channel);

    /* The streams on second and third connection should failed to complete */
    ASSERT_INT_EQUALS(4, s_tester.stream_complete_errors);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, s_tester.stream_completed_error_code);

    return s_tester_clean_up();
}

/*******************************************************************************
 * Net test, that makes real HTTP/2 connection and requests
 ******************************************************************************/

/* Test that makes real streams */
TEST_CASE(h2_sm_acquire_stream) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    int num_to_acquire = 5;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(num_to_acquire));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    ASSERT_INT_EQUALS(num_to_acquire, s_tester.stream_200_count);

    return s_tester_clean_up();
}

/* Test that makes real streams and trigger multiple connections to be created */
TEST_CASE(h2_sm_acquire_stream_multiple_connections) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .alloc = allocator,
        .max_concurrent_streams_per_connection = 5,
    };
    ASSERT_SUCCESS(s_tester_init(&options));

    int num_to_acquire = 20;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(num_to_acquire));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    ASSERT_INT_EQUALS(num_to_acquire, s_tester.stream_200_count);

    return s_tester_clean_up();
}

/* Test that makes tons of real streams against real world */
TEST_CASE(h2_sm_close_connection_on_server_error) {
    (void)ctx;
    /* server that will return 500 status code all the time. */
    struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str("https://postman-echo.com/status/500");
    struct sm_tester_options options = {
        .max_connections = 1,
        .max_concurrent_streams_per_connection = 10,
        .alloc = allocator,
        .uri_cursor = &uri_cursor,
        .close_connection_on_server_error = true,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    int num_to_acquire = 50;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(num_to_acquire));
    ASSERT_TRUE((int)s_tester.acquiring_stream_errors == 0);
    ASSERT_TRUE((int)s_tester.stream_200_count == 0);

    return s_tester_clean_up();
}

static void s_sm_tester_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    if (s_tester.release_sm_during_connection_acquiring) {
        aws_http2_stream_manager_release(s_tester.stream_manager);
        s_tester.stream_manager = NULL;
    }
    s_tester.on_setup(connection, error_code, user_data);
}

static int s_aws_http_connection_manager_create_real_connection_sync(
    const struct aws_http_client_connection_options *options) {
    struct aws_http_client_connection_options local_options = *options;
    s_tester.on_setup = options->on_setup;
    local_options.on_setup = s_sm_tester_on_connection_setup;
    return aws_http_client_connect(&local_options);
}

/* Test that the stream manager closing before connection acquired, all the pending stream acquiring should fail */
TEST_CASE(h2_sm_closing_before_connection_acquired) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .max_concurrent_streams_per_connection = 2,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_tester.release_sm_during_connection_acquiring = true;
    s_override_cm_connect_function(s_aws_http_connection_manager_create_real_connection_sync);
    /* only acquire one as the connection create happens synced, the stream manager refcount will be released as the
     * first stream acquiring */
    ASSERT_SUCCESS(s_sm_stream_acquiring(1));
    ASSERT_SUCCESS(s_wait_on_streams_acquired_count(1));

    /* all acquiring stream failed */
    ASSERT_INT_EQUALS(1, s_tester.acquiring_stream_errors);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_STREAM_MANAGER_SHUTTING_DOWN, s_tester.error_code);
    return s_tester_clean_up();
}

/* Test our http2 stream manager works with prior knowledge */
TEST_CASE(localhost_integ_h2_sm_prior_knowledge) {
    (void)ctx;
    struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str("http://localhost:3280");
    struct sm_tester_options options = {
        .max_connections = 100,
        .max_concurrent_streams_per_connection = 100,
        .alloc = allocator,
        .uri_cursor = &uri_cursor,
        .prior_knowledge = true,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    int num_to_acquire = 2;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(num_to_acquire));
    ASSERT_TRUE((int)s_tester.acquiring_stream_errors == 0);
    ASSERT_TRUE((int)s_tester.stream_200_count == num_to_acquire);

    return s_tester_clean_up();
}

/* Test that makes tons of real streams against local host */
TEST_CASE(localhost_integ_h2_sm_acquire_stream_stress) {
    (void)ctx;
    struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str("https://localhost:3443/echo");
    struct aws_http_connection_monitoring_options monitor_opt = {
        .allowable_throughput_failure_interval_seconds = 2,
        .minimum_throughput_bytes_per_second = 1000,
    };
    enum aws_log_level log_level = AWS_LOG_LEVEL_DEBUG;
    struct sm_tester_options options = {
        .max_connections = 50,
        .max_concurrent_streams_per_connection = 100,
        .connection_ping_period_ms = 100 * AWS_TIMESTAMP_MILLIS,
        .alloc = allocator,
        .uri_cursor = &uri_cursor,
        .monitor_opt = &monitor_opt,
        .log_level = &log_level,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    size_t num_to_acquire = 500 * 100;
    ASSERT_SUCCESS(s_sm_stream_acquiring((int)num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(num_to_acquire));
    ASSERT_UINT_EQUALS(s_tester.acquiring_stream_errors, 0);
    ASSERT_UINT_EQUALS(s_tester.stream_200_count, num_to_acquire);

    return s_tester_clean_up();
}

static int s_tester_on_put_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)user_data;
    (void)stream;
    struct aws_string *content_length_header_str = aws_string_new_from_cursor(s_tester.allocator, data);
    size_t num_received = (uint32_t)atoi((const char *)content_length_header_str->bytes);
    AWS_FATAL_ASSERT(s_tester.length_sent == num_received);
    aws_string_destroy(content_length_header_str);

    return AWS_OP_SUCCESS;
}

static int s_sm_stream_acquiring_with_body(int num_streams) {
    char content_length_sprintf_buffer[128] = "";
    snprintf(content_length_sprintf_buffer, sizeof(content_length_sprintf_buffer), "%zu", s_tester.length_sent);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "PUT"),
        {
            .name = aws_byte_cursor_from_c_str(":scheme"),
            .value = *aws_uri_scheme(&s_tester.endpoint),
        },
        {
            .name = aws_byte_cursor_from_c_str(":path"),
            .value = s_normalize_path(*aws_uri_path(&s_tester.endpoint)),
        },
        {
            .name = aws_byte_cursor_from_c_str(":authority"),
            .value = *aws_uri_host_name(&s_tester.endpoint),
        },
        {
            .name = aws_byte_cursor_from_c_str("content_length"),
            .value = aws_byte_cursor_from_c_str(content_length_sprintf_buffer),
        },
    };
    for (int i = 0; i < num_streams; ++i) {
        /* TODO: Test the callback will always be fired asynced, as now the CM cannot ensure the callback happens
         * asynchronously, we cannot ensure it as well. */
        struct aws_http_message *request = aws_http2_message_new_request(s_tester.allocator);
        aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
        struct aws_input_stream *body_stream =
            aws_input_stream_tester_upload_new(s_tester.allocator, s_tester.length_sent);
        aws_http_message_set_body_stream(request, body_stream);
        aws_input_stream_release(body_stream);
        struct aws_http_make_request_options request_options = {
            .self_size = sizeof(request_options),
            .request = request,
            .on_response_body = s_tester_on_put_body,
            .on_complete = s_sm_tester_on_stream_complete,
        };

        struct aws_http2_stream_manager_acquire_stream_options acquire_stream_option = {
            .options = &request_options,
            .callback = s_sm_tester_on_stream_acquired,
            .user_data = &s_tester,
        };
        aws_http2_stream_manager_acquire_stream(s_tester.stream_manager, &acquire_stream_option);
        aws_http_message_release(request);
    }
    return AWS_OP_SUCCESS;
}

/* Test that makes tons of real streams with body against local host */
TEST_CASE(localhost_integ_h2_sm_acquire_stream_stress_with_body) {
    (void)ctx;
    struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str("https://localhost:3443/upload_test");
    enum aws_log_level log_level = AWS_LOG_LEVEL_DEBUG;
    struct sm_tester_options options = {
        .max_connections = 100,
        .max_concurrent_streams_per_connection = 100,
        .connection_ping_period_ms = 100 * AWS_TIMESTAMP_MILLIS,
        .alloc = allocator,
        .uri_cursor = &uri_cursor,
        .log_level = &log_level,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_tester.length_sent = 2000;
    int num_to_acquire = 500 * 100;

    ASSERT_SUCCESS(s_sm_stream_acquiring_with_body(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(num_to_acquire));
    ASSERT_UINT_EQUALS(s_tester.acquiring_stream_errors, 0);
    ASSERT_UINT_EQUALS(s_tester.stream_200_count, num_to_acquire);

    return s_tester_clean_up();
}

/* Test that connection monitor works properly with HTTP/2 stream manager */
TEST_CASE(localhost_integ_h2_sm_connection_monitor_kill_slow_connection) {
    (void)ctx;
    struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str("https://localhost:3443/slowConnTest");
    struct aws_http_connection_monitoring_options monitor_opt = {
        .allowable_throughput_failure_interval_seconds = 1,
        .minimum_throughput_bytes_per_second = 1000,
    };
    struct sm_tester_options options = {
        .max_connections = 100,
        .max_concurrent_streams_per_connection = 100,
        .alloc = allocator,
        .uri_cursor = &uri_cursor,
        .monitor_opt = &monitor_opt,
    };
    ASSERT_SUCCESS(s_tester_init(&options));

    ASSERT_SUCCESS(s_sm_stream_acquiring(1));
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(1));
    /* Check the connection closed by connection monitor and the stream should completed with corresponding error */
    ASSERT_UINT_EQUALS(s_tester.stream_completed_error_code, AWS_ERROR_HTTP_CONNECTION_CLOSED);

    return s_tester_clean_up();
}
