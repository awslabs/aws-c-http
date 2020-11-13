/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/http/server.h>

#include <aws/io/logging.h>

#include <aws/testing/aws_test_harness.h>

#include "proxy_test_helper.h"

static struct proxy_tester tester;
static int s_response_status_code = 0;

static int s_aws_http_on_incoming_headers_proxy_test(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)stream;
    (void)user_data;
    (void)header_block;

    for (size_t i = 0; i < num_headers; ++i) {
        const struct aws_byte_cursor *name = &header_array[i].name;
        const struct aws_byte_cursor *value = &header_array[i].value;
        AWS_LOGF_INFO(
            AWS_LS_HTTP_GENERAL, "< " PRInSTR " : " PRInSTR, AWS_BYTE_CURSOR_PRI(*name), AWS_BYTE_CURSOR_PRI(*value));
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_http_on_incoming_header_block_done_proxy_test(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    (void)header_block;

    struct proxy_tester *context = user_data;
    if (aws_http_stream_get_incoming_response_status(stream, &s_response_status_code) == AWS_OP_SUCCESS) {
        aws_mutex_lock(&context->wait_lock);
        context->request_successful = s_response_status_code == 200;
        aws_mutex_unlock(&context->wait_lock);
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_http_on_incoming_body_proxy_test(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {
    (void)stream;
    (void)user_data;

    AWS_LOGF_INFO(AWS_LS_HTTP_GENERAL, "< " PRInSTR, AWS_BYTE_CURSOR_PRI(*data));

    return AWS_OP_SUCCESS;
}

static void s_aws_http_on_stream_complete_proxy_test(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    (void)error_code;

    struct proxy_tester *context = user_data;

    aws_mutex_lock(&context->wait_lock);
    context->request_complete = true;
    aws_mutex_unlock(&context->wait_lock);
    aws_condition_variable_notify_one(&context->wait_cvar);
}

static int s_setup_proxy_test(
    struct aws_allocator *allocator,
    struct aws_byte_cursor host,
    enum proxy_tester_test_mode test_mode) {
    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .port = 3128,
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = host,
        .port = test_mode == PTTM_HTTP ? 80 : 443,
        .test_mode = test_mode,
        .failure_type = PTFT_NONE,
    };

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));
    ASSERT_SUCCESS(proxy_tester_wait(&tester, proxy_tester_connection_setup_pred));

    return AWS_OP_SUCCESS;
}

static int s_do_proxy_request_test(
    struct aws_allocator *allocator,
    struct aws_byte_cursor host,
    enum proxy_tester_test_mode test_mode,
    struct aws_byte_cursor method,
    struct aws_byte_cursor path) {
    ASSERT_SUCCESS(s_setup_proxy_test(allocator, host, test_mode));
    ASSERT_TRUE(tester.wait_result == AWS_ERROR_SUCCESS);

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    aws_http_message_set_request_method(request, method);
    aws_http_message_set_request_path(request, path);

    struct aws_http_header host_header = {
        .name = aws_byte_cursor_from_c_str("Host"),
        .value = host,
    };
    aws_http_message_add_header(request, host_header);

    struct aws_http_header accept_header = {
        .name = aws_byte_cursor_from_c_str("Accept"),
        .value = aws_byte_cursor_from_c_str("*/*"),
    };
    aws_http_message_add_header(request, accept_header);

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = &tester,
        .on_response_headers = s_aws_http_on_incoming_headers_proxy_test,
        .on_response_header_block_done = s_aws_http_on_incoming_header_block_done_proxy_test,
        .on_response_body = s_aws_http_on_incoming_body_proxy_test,
        .on_complete = s_aws_http_on_stream_complete_proxy_test,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.client_connection, &request_options);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    ASSERT_SUCCESS(proxy_tester_wait(&tester, proxy_tester_request_complete_pred_fn));
    ASSERT_TRUE(tester.wait_result == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(s_response_status_code == 200);

    aws_http_stream_release(stream);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    aws_http_message_destroy(request);

    return AWS_OP_SUCCESS;
}

static int s_test_http_proxy_connection_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_setup_proxy_test(allocator, aws_byte_cursor_from_c_str("example.org"), PTTM_HTTP));
    ASSERT_TRUE(tester.wait_result == AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_new_destroy, s_test_http_proxy_connection_new_destroy);

static int s_test_http_proxy_connection_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    return s_do_proxy_request_test(
        allocator,
        aws_byte_cursor_from_c_str("example.org"),
        PTTM_HTTP,
        aws_byte_cursor_from_c_str("GET"),
        aws_byte_cursor_from_c_str("/"));
}
AWS_TEST_CASE(test_http_proxy_connection_get, s_test_http_proxy_connection_get);

static int s_test_https_proxy_connection_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_setup_proxy_test(allocator, aws_byte_cursor_from_c_str("aws.amazon.com"), PTTM_HTTPS));
    ASSERT_TRUE(tester.wait_result == AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_https_proxy_connection_new_destroy, s_test_https_proxy_connection_new_destroy);

static int s_test_https_proxy_connection_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    return s_do_proxy_request_test(
        allocator,
        aws_byte_cursor_from_c_str("aws.amazon.com"),
        PTTM_HTTPS,
        aws_byte_cursor_from_c_str("GET"),
        aws_byte_cursor_from_c_str("/"));
}
AWS_TEST_CASE(test_https_proxy_connection_get, s_test_https_proxy_connection_get);

static int s_test_http_proxy_connection_options_star(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    return s_do_proxy_request_test(
        allocator,
        aws_byte_cursor_from_c_str("example.org"),
        PTTM_HTTP,
        aws_byte_cursor_from_c_str("OPTIONS"),
        aws_byte_cursor_from_c_str("*"));
}
AWS_TEST_CASE(test_http_proxy_connection_options_star, s_test_http_proxy_connection_options_star);
