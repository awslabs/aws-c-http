/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "h2_test_helper.h"
#include "stream_test_helper.h"

#include <aws/http/http2_stream_manager.h>

#include <aws/http/private/connection_impl.h>
#include <aws/http/private/connection_manager_system_vtable.h>
#include <aws/http/private/h1_stream.h>
#include <aws/http/private/h2_connection.h>
#include <aws/http/private/http2_stream_manager_impl.h>
#include <aws/http/private/proxy_impl.h>
#include <aws/http/proxy.h>

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
};

struct sm_tester {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;

    struct aws_client_bootstrap *client_bootstrap;

    struct aws_http2_stream_manager *stream_manager;

    struct aws_string *host;
    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_http_proxy_options *verify_proxy_options;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_array_list streams;
    size_t acquiring_stream_errors;
    size_t stream_complete_errors;
    int error_code;
    int stream_completed_error_code;

    size_t wait_for_stream_count;
    bool is_shutdown_complete;

    bool real_connection;

    /* Fake HTTP/2 connection */
    size_t wait_for_fake_connection_count;
    size_t offer_closed_connection_count;
    struct aws_array_list fake_connections;
    bool release_sm_during_connection_acquiring;

    uint32_t max_con_stream_remote;

    /* Only for testing the acquiring callback will invoked async */
    struct aws_mutex async_acquiring_callback_lock;
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
    if (fake_connection->options.on_shutdown) {
        /* In real world, this is trigger by the bootstrp */
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
    h2_fake_peer_clean_up(&fake_connection->peer);
    testing_channel_clean_up(&fake_connection->testing_channel);
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

    ASSERT_SUCCESS(aws_mutex_init(&s_tester.lock));
    ASSERT_SUCCESS(aws_mutex_init(&s_tester.async_acquiring_callback_lock));
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

    aws_tls_ctx_options_init_default_client(&s_tester.tls_ctx_options, alloc);
    if (!options->no_http2) {
        ASSERT_SUCCESS(aws_tls_ctx_options_set_alpn_list(&s_tester.tls_ctx_options, "h2"));
    }
    s_tester.tls_ctx = aws_tls_client_ctx_new(alloc, &s_tester.tls_ctx_options);

    ASSERT_NOT_NULL(s_tester.tls_ctx);

    s_tester.host = aws_string_new_from_c_str(alloc, "www.google.com");
    struct aws_byte_cursor server_name = aws_byte_cursor_from_string(s_tester.host);
    aws_tls_connection_options_init_from_ctx(&s_tester.tls_connection_options, s_tester.tls_ctx);
    aws_tls_connection_options_set_server_name(&s_tester.tls_connection_options, alloc, &server_name);

    struct aws_http2_stream_manager_options sm_options = {
        .bootstrap = s_tester.client_bootstrap,
        .socket_options = &socket_options,
        .tls_connection_options = &s_tester.tls_connection_options,
        .host = server_name,
        .port = 443,
        .ideal_concurrent_streams_per_connection = options->ideal_concurrent_streams_per_connection,
        .max_concurrent_streams_per_connection = options->max_concurrent_streams_per_connection,
        .max_connections = options->max_connections,
        .shutdown_complete_user_data = &s_tester,
        .shutdown_complete_callback = s_sm_tester_on_sm_shutdown_complete,
    };
    s_tester.stream_manager = aws_http2_stream_manager_new(alloc, &sm_options);

    s_tester.max_con_stream_remote = 100;

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

/* complete first num_streams_to_complete. If num_streams_to_complete is zero, complete all the streams. */
static void s_fake_connection_complete_streams(
    struct sm_fake_connection *fake_connection,
    int num_streams_to_complete) {

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
    s_clean_fake_connections();
    aws_http2_stream_manager_release(s_tester.stream_manager);

    s_wait_on_shutdown_complete();
    aws_client_bootstrap_release(s_tester.client_bootstrap);

    aws_host_resolver_release(s_tester.host_resolver);
    aws_event_loop_group_release(s_tester.event_loop_group);

    aws_tls_ctx_options_clean_up(&s_tester.tls_ctx_options);
    aws_tls_connection_options_clean_up(&s_tester.tls_connection_options);
    aws_tls_ctx_release(s_tester.tls_ctx);

    aws_http_library_clean_up();

    aws_mutex_clean_up(&s_tester.lock);
    aws_mutex_clean_up(&s_tester.async_acquiring_callback_lock);
    aws_condition_variable_clean_up(&s_tester.signal);
    aws_array_list_clean_up(&s_tester.streams);
    aws_string_destroy(s_tester.host);

    return AWS_OP_SUCCESS;
}

static void s_sm_tester_on_stream_acquired(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)user_data;
    /* If the callback ever happens synced, it will be a dead lock */
    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.async_acquiring_callback_lock) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.async_acquiring_callback_lock) == AWS_OP_SUCCESS);

    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.lock) == AWS_OP_SUCCESS);

    if (error_code) {
        ++s_tester.acquiring_stream_errors;
        s_tester.error_code = error_code;
    } else {
        aws_array_list_push_back(&s_tester.streams, &stream);
    }

    aws_condition_variable_notify_one(&s_tester.signal);

    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);
}

static bool s_is_stream_reply_count_at_least(void *context) {
    (void)context;
    return s_tester.wait_for_stream_count <=
           aws_array_list_length(&s_tester.streams) + s_tester.acquiring_stream_errors;
}

static int s_wait_on_streams_reply_count(size_t count) {
    ASSERT_SUCCESS(aws_mutex_lock(&s_tester.lock));

    s_tester.wait_for_stream_count = count;
    int signal_error =
        aws_condition_variable_wait_pred(&s_tester.signal, &s_tester.lock, s_is_stream_reply_count_at_least, NULL);

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
    }
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);
}

static int s_sm_stream_acquiring(int num_streams) {
    struct aws_http_message *request = aws_http2_message_new_request(s_tester.allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
        DEFINE_HEADER(":authority", aws_string_c_str(s_tester.host)),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = &s_tester,
        .on_complete = s_sm_tester_on_stream_complete,
    };
    struct aws_http2_stream_manager_acquire_stream_options acquire_stream_option = {
        .options = &request_options,
        .callback = s_sm_tester_on_stream_acquired,
        .user_data = &s_tester,
    };
    for (int i = 0; i < num_streams; ++i) {
        /* TODO: Test the callback will always be fired asynced, as now the CM cannot ensure the callback happens
         * asynchronously, we cannot ensure it as well. */
        AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.async_acquiring_callback_lock) == AWS_OP_SUCCESS);
        aws_http2_stream_manager_acquire_stream(s_tester.stream_manager, &acquire_stream_option);
        AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.async_acquiring_callback_lock) == AWS_OP_SUCCESS);
    }
    aws_http_message_release(request);
    return AWS_OP_SUCCESS;
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

static int s_aws_http_connection_manager_create_connection_sync_mock(
    const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.lock) == AWS_OP_SUCCESS);
    if (s_tester.release_sm_during_connection_acquiring) {
        aws_http2_stream_manager_release(s_tester.stream_manager);
    }

    struct sm_fake_connection *fake_connection = s_sm_fake_connection_new();
    struct aws_http_connection *connection = aws_http_connection_new_http2_client(
        options->allocator, options->manual_window_management /* manual window management */, options->http2_options);
    ASSERT_NOT_NULL(connection);

    {
        /* set connection user_data (handled by http-bootstrap in real world) */
        connection->user_data = options->user_data;
        /* re-enact marriage vows of http-connection and channel (handled by http-bootstrap in real world) */
        struct aws_channel_slot *slot = aws_channel_slot_new(fake_connection->testing_channel.channel);
        ASSERT_NOT_NULL(slot);
        ASSERT_SUCCESS(aws_channel_slot_insert_end(fake_connection->testing_channel.channel, slot));
        ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &connection->channel_handler));
        connection->vtable->on_channel_handler_installed(&connection->channel_handler, slot);
    }
    fake_connection->connection = connection;
    fake_connection->options = *options;
    ASSERT_SUCCESS(aws_array_list_push_back(&s_tester.fake_connections, &fake_connection));

    aws_condition_variable_notify_one(&s_tester.signal);
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);
    /* Invoke callback outside lock */
    options->on_setup(connection, AWS_ERROR_SUCCESS, options->user_data);
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

static struct aws_http_connection_manager_system_vtable s_mocks;

static void s_override_cm_connect_function(aws_http_connection_manager_create_connection_fn *fn) {
    s_mocks = *g_aws_http_connection_manager_default_system_vtable_ptr;
    s_mocks.create_connection = fn;
    aws_http_connection_manager_set_system_vtable(s_tester.stream_manager->connection_manager, &s_mocks);
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
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_to_acquire));
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

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
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_streams_to_acquire));
    ASSERT_TRUE(aws_array_list_length(&s_tester.fake_connections) == (size_t)num_expected_connection);
    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}

// TEST_CASE(h2_sm_mock_close_connection) {
//     (void)ctx;
//     size_t max_concurrent_streams_per_connection = 3;
//     int num_streams_to_acquire = 3;
//     int num_expected_connection = num_streams_to_acquire / (int)max_concurrent_streams_per_connection;
//     if (num_streams_to_acquire % max_concurrent_streams_per_connection) {
//         ++num_expected_connection;
//     }
//     struct sm_tester_options options = {
//         .max_connections = 5,
//         .max_concurrent_streams_per_connection = max_concurrent_streams_per_connection,
//         .alloc = allocator,
//     };
//     ASSERT_SUCCESS(s_tester_init(&options));
//     s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
//     ASSERT_SUCCESS(s_sm_stream_acquiring(num_streams_to_acquire));
//     /* waiting for one fake connection made */
//     ASSERT_SUCCESS(s_wait_on_fake_connection_count(num_expected_connection));
//     s_drain_all_fake_connection_testing_channel();
//     ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_streams_to_acquire));
//     ASSERT_INT_EQUALS(num_streams_to_acquire, s_tester.acquiring_stream_errors);
//     ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, s_tester.error_code);
//     ASSERT_TRUE(aws_array_list_length(&s_tester.fake_connections) == (size_t)num_expected_connection);
//     /* Now close the connection */
//     struct sm_fake_connection *fake_connection = s_get_fake_connection(0);
//     aws_http_connection_close(fake_connection->connection);

//     /* Acquire more streams, which should succeed as we don't close the connection */
//     ASSERT_SUCCESS(s_sm_stream_acquiring(num_streams_to_acquire));
//     /* waiting for the new connection */
//     ASSERT_SUCCESS(s_wait_on_fake_connection_count(num_expected_connection + 1));
//     s_drain_all_fake_connection_testing_channel();
//     ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_streams_to_acquire + num_streams_to_acquire));
//     /* all the new streams succeed */
//     ASSERT_TRUE(aws_array_list_length(&s_tester.streams) == (size_t)num_streams_to_acquire);
//     ASSERT_SUCCESS(s_complete_all_fake_connection_streams(true /*Settings needed*/));

//     return s_tester_clean_up();
// }

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
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(1));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    ASSERT_INT_EQUALS(0, s_tester.stream_complete_errors);

    /* Fake peer send settings that only allow 2 concurrent streams */
    /* Acquire tow more streams */
    ASSERT_SUCCESS(s_sm_stream_acquiring(2));
    /* We created a new connection */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(2));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(1 + 2));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);

    ASSERT_INT_EQUALS(2, aws_array_list_length(&s_tester.fake_connections));
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
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(2));
    ASSERT_INT_EQUALS(1, aws_array_list_length(&s_tester.fake_connections));

    /* Fake peer send settings that only allow 2 concurrent streams */
    struct sm_fake_connection *fake_connection = s_get_fake_connection(0);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&fake_connection->peer));
    s_fake_connection_complete_streams(fake_connection, 1);

    /* Acquire a new streams */
    ASSERT_SUCCESS(s_sm_stream_acquiring(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(2 + 1));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
    /* No error happens */
    ASSERT_INT_EQUALS(0, s_tester.stream_complete_errors);
    /* We have no extra connection made. */
    ASSERT_INT_EQUALS(1, aws_array_list_length(&s_tester.fake_connections));

    ASSERT_SUCCESS(s_complete_all_fake_connection_streams());

    return s_tester_clean_up();
}
// /* Test the soft limit from user works as we want */
// TEST_CASE(h2_sm_mock_ideal_num_streams) {
//     (void)ctx;
//     struct sm_tester_options options = {
//         .max_connections = 5,
//         .ideal_concurrent_streams_per_connection = 3,
//         .max_concurrent_streams_per_connection = 5,
//         .alloc = allocator,
//     };
//     ASSERT_SUCCESS(s_tester_init(&options));
//     s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
//     ASSERT_SUCCESS(s_sm_stream_acquiring(15));
//     /* waiting for one fake connection made */
//     ASSERT_SUCCESS(s_wait_on_fake_connection_count(5));
//     s_drain_all_fake_connection_testing_channel();
//     ASSERT_SUCCESS(s_wait_on_streams_reply_count(5));
//     ASSERT_INT_EQUALS(2, aws_array_list_length(&s_tester.fake_connections));

//     /* Acquire a new streams */
//     ASSERT_SUCCESS(s_sm_stream_acquiring(1));
//     s_drain_all_fake_connection_testing_channel();
//     ASSERT_SUCCESS(s_wait_on_streams_reply_count(2 + 1));
//     ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);
//     /* No error happens */
//     ASSERT_INT_EQUALS(0, s_tester.stream_complete_errors);
//     /* We have no extra connection made. */
//     ASSERT_INT_EQUALS(1, aws_array_list_length(&s_tester.fake_connections));

//     ASSERT_SUCCESS(s_complete_all_fake_connection_streams(false /*Settings needed*/));

//     return s_tester_clean_up();
// }

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
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(5));
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
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(5 + 5));
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

/* Test that the stream manager closing before connection acquired, all the pending stream acquiring should fail */
TEST_CASE(h2_sm_mock_closing_before_connection_acquired) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .max_concurrent_streams_per_connection = 2,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_tester.release_sm_during_connection_acquiring = true;
    s_override_cm_connect_function(s_aws_http_connection_manager_create_connection_sync_mock);
    /* only acquire one as the connection create happens synced, the stream manager refcount will be released as the
     * first stream acquiring */
    ASSERT_SUCCESS(s_sm_stream_acquiring(1));
    /* waiting for one fake connection made */
    ASSERT_SUCCESS(s_wait_on_fake_connection_count(1));
    s_drain_all_fake_connection_testing_channel();
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(1));
    /* The stream manager will finish destroying before release called from clean up, set it to null to avoid use after
     * free */
    s_tester.stream_manager = NULL;

    /* all acquiring stream failed */
    ASSERT_INT_EQUALS(1, s_tester.acquiring_stream_errors);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_STREAM_MANAGER_SHUTTING_DOWN, s_tester.error_code);
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
    s_tester.real_connection = true;
    int num_to_acquire = 5;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_to_acquire));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);

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
    s_tester.real_connection = true;
    int num_to_acquire = 20;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_to_acquire));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);

    return s_tester_clean_up();
}

/* Test that makes tons of real streams */
TEST_CASE(h2_sm_acquire_stream_stress) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 100,
        .max_concurrent_streams_per_connection = 100,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    s_tester.real_connection = true;
    int num_to_acquire = 100 * 100 * 2;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_to_acquire));
    ASSERT_INT_EQUALS(0, s_tester.acquiring_stream_errors);

    return s_tester_clean_up();
}