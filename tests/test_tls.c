/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>
#include <aws/http/request_response.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>
#include <aws/testing/aws_test_harness.h>

/* Singleton used by tests in this file */
struct test_ctx {
    struct aws_allocator *alloc;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;
    struct aws_tls_ctx *tls_ctx;
    struct aws_client_bootstrap *client_bootstrap;
    struct aws_http_connection *client_connection;
    struct aws_http_stream *stream;

    size_t body_size;
    bool stream_complete;
    bool client_connection_is_shutdown;

    struct aws_mutex wait_lock;
    struct aws_condition_variable wait_cvar;
    int wait_result;
};

static const uint32_t TEST_TIMEOUT_SEC = 4;

static void s_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct test_ctx *test = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&test->wait_lock) == AWS_OP_SUCCESS);

    test->client_connection = connection;
    test->wait_result = error_code;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&test->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&test->wait_cvar);
}

static void s_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)connection;
    struct test_ctx *test = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&test->wait_lock) == AWS_OP_SUCCESS);

    test->client_connection_is_shutdown = true;
    test->wait_result = error_code;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&test->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&test->wait_cvar);
}

static int s_test_wait(struct test_ctx *test, bool (*pred)(void *user_data)) {
    ASSERT_SUCCESS(aws_mutex_lock(&test->wait_lock));
    int wait_result = aws_condition_variable_wait_pred(&test->wait_cvar, &test->wait_lock, pred, test);
    ASSERT_SUCCESS(aws_mutex_unlock(&test->wait_lock));
    ASSERT_SUCCESS(wait_result);
    return AWS_OP_SUCCESS;
}

static bool s_test_connection_setup_pred(void *user_data) {
    struct test_ctx *test = user_data;
    return test->wait_result || test->client_connection;
}

static bool s_test_connection_shutdown_pred(void *user_data) {
    struct test_ctx *test = user_data;
    return test->wait_result || test->client_connection_is_shutdown;
}

static int s_on_stream_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;
    struct test_ctx *test = user_data;

    AWS_FATAL_ASSERT(aws_mutex_lock(&test->wait_lock) == AWS_OP_SUCCESS);
    test->body_size += data->len;
    AWS_FATAL_ASSERT(aws_mutex_unlock(&test->wait_lock) == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}

static void s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    struct test_ctx *test = user_data;

    AWS_FATAL_ASSERT(aws_mutex_lock(&test->wait_lock) == AWS_OP_SUCCESS);
    test->wait_result = error_code;
    test->stream_complete = true;
    AWS_FATAL_ASSERT(aws_mutex_unlock(&test->wait_lock) == AWS_OP_SUCCESS);

    aws_condition_variable_notify_one(&test->wait_cvar);
}

static bool s_stream_wait_pred(void *user_data) {
    struct test_ctx *test = user_data;
    return test->wait_result || test->stream_complete;
}

static int s_test_tls_download_medium_file_general(
    struct aws_allocator *allocator,
    struct aws_byte_cursor url,
    bool h2_required) {

    aws_http_library_init(allocator);
    struct aws_uri uri;
    aws_uri_init_parse(&uri, allocator, &url);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TEST_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    struct test_ctx test;
    AWS_ZERO_STRUCT(test);
    test.alloc = allocator;

    aws_mutex_init(&test.wait_lock);
    aws_condition_variable_init(&test.wait_cvar);

    test.event_loop_group = aws_event_loop_group_new_default(test.alloc, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = test.event_loop_group,
        .max_entries = 1,
    };

    test.host_resolver = aws_host_resolver_new_default(test.alloc, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = test.event_loop_group,
        .host_resolver = test.host_resolver,
    };
    ASSERT_NOT_NULL(test.client_bootstrap = aws_client_bootstrap_new(test.alloc, &bootstrap_options));
    struct aws_tls_ctx_options tls_ctx_options;
    aws_tls_ctx_options_init_default_client(&tls_ctx_options, allocator);
    char *apln = h2_required ? "h2" : "http/1.1";
    aws_tls_ctx_options_set_alpn_list(&tls_ctx_options, apln);
    ASSERT_NOT_NULL(test.tls_ctx = aws_tls_client_ctx_new(allocator, &tls_ctx_options));
    struct aws_tls_connection_options tls_connection_options;
    aws_tls_connection_options_init_from_ctx(&tls_connection_options, test.tls_ctx);
    aws_tls_connection_options_set_server_name(
        &tls_connection_options, allocator, (struct aws_byte_cursor *)aws_uri_host_name(&uri));
    struct aws_http_client_connection_options http_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    http_options.allocator = test.alloc;
    http_options.bootstrap = test.client_bootstrap;
    http_options.host_name = *aws_uri_host_name(&uri);
    http_options.port = 443;
    http_options.on_setup = s_on_connection_setup;
    http_options.on_shutdown = s_on_connection_shutdown;
    http_options.socket_options = &socket_options;
    http_options.tls_options = &tls_connection_options;
    http_options.user_data = &test;

    ASSERT_SUCCESS(aws_http_client_connect(&http_options));
    ASSERT_SUCCESS(s_test_wait(&test, s_test_connection_setup_pred));
    ASSERT_INT_EQUALS(0, test.wait_result);
    ASSERT_NOT_NULL(test.client_connection);
    if (h2_required) {
        ASSERT_INT_EQUALS(aws_http_connection_get_version(test.client_connection), AWS_HTTP_VERSION_2);
    } else {
        ASSERT_INT_EQUALS(aws_http_connection_get_version(test.client_connection), AWS_HTTP_VERSION_1_1);
    }

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_http_method_get));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, *aws_uri_path_and_query(&uri)));

    struct aws_http_header header_host = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
        .value = *aws_uri_host_name(&uri),
    };
    ASSERT_SUCCESS(aws_http_message_add_header(request, header_host));

    struct aws_http_make_request_options req_options = {
        .self_size = sizeof(req_options),
        .request = request,
        .on_response_body = s_on_stream_body,
        .on_complete = s_on_stream_complete,
        .user_data = &test,
    };

    ASSERT_NOT_NULL(test.stream = aws_http_connection_make_request(test.client_connection, &req_options));
    aws_http_stream_activate(test.stream);

    /* wait for the request to complete */
    s_test_wait(&test, s_stream_wait_pred);

    ASSERT_INT_EQUALS(14428801, test.body_size);

    aws_http_message_destroy(request);
    aws_http_stream_release(test.stream);
    test.stream = NULL;

    aws_http_connection_release(test.client_connection);
    ASSERT_SUCCESS(s_test_wait(&test, s_test_connection_shutdown_pred));

    aws_client_bootstrap_release(test.client_bootstrap);
    aws_host_resolver_release(test.host_resolver);
    aws_event_loop_group_release(test.event_loop_group);

    aws_tls_ctx_options_clean_up(&tls_ctx_options);
    aws_tls_connection_options_clean_up(&tls_connection_options);
    aws_tls_ctx_release(test.tls_ctx);

    aws_uri_clean_up(&uri);
    aws_http_library_clean_up();

    aws_mutex_clean_up(&test.wait_lock);
    aws_condition_variable_clean_up(&test.wait_cvar);

    return AWS_OP_SUCCESS;
}

static int s_test_tls_download_medium_file_h1(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_byte_cursor url =
        aws_byte_cursor_from_c_str("https://aws-crt-test-stuff.s3.amazonaws.com/http_test_doc.txt");
    ASSERT_SUCCESS(s_test_tls_download_medium_file_general(allocator, url, false /*h2_required*/));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(tls_download_medium_file_h1, s_test_tls_download_medium_file_h1);

static int s_tls_download_medium_file_h2(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* The cloudfront domain for aws-crt-test-stuff */
    struct aws_byte_cursor url = aws_byte_cursor_from_c_str("https://d1cz66xoahf9cl.cloudfront.net/http_test_doc.txt");
    ASSERT_SUCCESS(s_test_tls_download_medium_file_general(allocator, url, true /*h2_required*/));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(tls_download_medium_file_h2, s_tls_download_medium_file_h2);
