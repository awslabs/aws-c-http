/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/http2_stream_manager.h>

#include <aws/http/private/connection_impl.h>
#include <aws/http/private/h1_stream.h>
#include <aws/http/private/http2_stream_manager_impl.h>
#include <aws/http/private/proxy_impl.h>
#include <aws/http/proxy.h>

#include <aws/io/uri.h>

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
    uint32_t max_concurrent_streams_per_connection;
};

struct sm_tester {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;

    struct aws_client_bootstrap *client_bootstrap;

    struct aws_http2_stream_manager *stream_manager;

    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_http_proxy_options *verify_proxy_options;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_array_list streams;
    size_t streams_errors;
    int error_code;

    size_t wait_for_stream_count;
    bool is_shutdown_complete;

    struct aws_http_connection_manager_system_vtable *mock_table;

    struct aws_atomic_var next_connection_id;
    struct aws_array_list mock_connections;
    aws_http_on_client_connection_shutdown_fn *release_connection_fn;

    struct aws_mutex mock_time_lock;
    uint64_t mock_time;

    struct proxy_env_var_settings proxy_ev_settings;
    bool proxy_request_complete;
    bool proxy_request_successful;
};

static struct sm_tester s_tester;

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
    ASSERT_SUCCESS(aws_condition_variable_init(&s_tester.signal));

    s_tester.event_loop_group = aws_event_loop_group_new_default(alloc, 0, NULL);

    ASSERT_SUCCESS(aws_array_list_init_dynamic(&s_tester.streams, alloc, 1, sizeof(struct aws_http_stream *)));

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

    struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str("www.amazon.com");
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
    return AWS_OP_SUCCESS;
}

static void s_release_all_streams(void) {
    size_t release_count = aws_array_list_length(&s_tester.streams);
    for (size_t i = 0; i < release_count; ++i) {
        struct aws_http_stream *stream = NULL;
        if (aws_array_list_back(&s_tester.streams, &stream)) {
            continue;
        }
        aws_http_stream_release(stream);
        aws_array_list_pop_back(&s_tester.streams);
    }
}

static int s_tester_clean_up(void) {
    s_release_all_streams();
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
    aws_condition_variable_clean_up(&s_tester.signal);
    aws_array_list_clean_up(&s_tester.streams);

    return AWS_OP_SUCCESS;
}

static void s_sm_tester_on_stream_acquired(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)user_data;

    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.lock) == AWS_OP_SUCCESS);

    if (error_code) {
        ++s_tester.streams_errors;
        s_tester.error_code = error_code;
    } else {
        aws_array_list_push_back(&s_tester.streams, &stream);
    }

    aws_condition_variable_notify_one(&s_tester.signal);

    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.lock) == AWS_OP_SUCCESS);
}

static bool s_is_stream_reply_count_at_least(void *context) {
    (void)context;
    return s_tester.wait_for_stream_count <= aws_array_list_length(&s_tester.streams) + s_tester.streams_errors;
}

static int s_wait_on_streams_reply_count(size_t count) {

    ASSERT_SUCCESS(aws_mutex_lock(&s_tester.lock));

    s_tester.wait_for_stream_count = count;
    int signal_error =
        aws_condition_variable_wait_pred(&s_tester.signal, &s_tester.lock, s_is_stream_reply_count_at_least, NULL);

    ASSERT_SUCCESS(aws_mutex_unlock(&s_tester.lock));
    return signal_error;
}

static int s_sm_stream_acquiring(int num_streams) {

    struct aws_http_message *request = aws_http2_message_new_request(s_tester.allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = &s_tester,
    };
    struct aws_http2_stream_manager_acquire_stream_options acquire_stream_option = {
        .options = &request_options,
        .callback = s_sm_tester_on_stream_acquired,
        .user_data = &s_tester,
    };
    for (int i = 0; i < num_streams; ++i) {
        aws_http2_stream_manager_acquire_stream(s_tester.stream_manager, &acquire_stream_option);
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

TEST_CASE(h2_sm_acquire_stream) {
    (void)ctx;
    struct sm_tester_options options = {
        .max_connections = 5,
        .alloc = allocator,
    };
    ASSERT_SUCCESS(s_tester_init(&options));
    int num_to_acquire = 5;
    ASSERT_SUCCESS(s_sm_stream_acquiring(num_to_acquire));
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_to_acquire));

    return s_tester_clean_up();
}

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
    ASSERT_SUCCESS(s_wait_on_streams_reply_count(num_to_acquire));

    return s_tester_clean_up();
}
