/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/http/connection.h>
#include <aws/http/server.h>

#include <aws/io/logging.h>

#include <aws/testing/aws_test_harness.h>

#include "proxy_test_helper.h"

static int s_aws_http_on_incoming_headers_proxy_test(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)stream;
    (void)user_data;

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
    bool has_body,
    void *user_data) {
    (void)has_body;

    struct proxy_tester *context = user_data;
    int status = 0;
    if (aws_http_stream_get_incoming_response_status(stream, &status) == AWS_OP_SUCCESS) {
        aws_mutex_lock(&context->wait_lock);
        context->request_successful = status == 200;
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

static int s_do_proxy_get_test(struct aws_allocator *allocator, struct proxy_tester_options *options) {
    struct proxy_tester tester;
    ASSERT_SUCCESS(proxy_tester_init(&tester, options));
    ASSERT_TRUE(tester.wait_result == AWS_ERROR_SUCCESS);

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("GET"));
    aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/"));

    struct aws_http_header host = {
        .name = aws_byte_cursor_from_c_str("Host"),
        .value = aws_byte_cursor_from_c_str("aws.amazon.com"),
    };
    aws_http_message_add_header(request, host);

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.client_connection = tester.client_connection;
    request_options.request = request;
    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.user_data = &tester;
    request_options.on_response_headers = s_aws_http_on_incoming_headers_proxy_test;
    request_options.on_response_header_block_done = s_aws_http_on_incoming_header_block_done_proxy_test;
    request_options.on_response_body = s_aws_http_on_incoming_body_proxy_test;
    request_options.on_complete = s_aws_http_on_stream_complete_proxy_test;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);
    (void)stream;

    ASSERT_SUCCESS(proxy_tester_wait(&tester, proxy_tester_request_complete_pred_fn));
    ASSERT_TRUE(tester.wait_result == AWS_ERROR_SUCCESS);

    aws_http_stream_release(stream);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    aws_http_message_destroy(request);

    return AWS_OP_SUCCESS;
}

static int s_test_http_proxy_connection_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .port = 8080,
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str("aws.amazon.com"),
        .port = 80,
    };
    struct proxy_tester tester;
    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_new_destroy, s_test_http_proxy_connection_new_destroy);

static int s_test_http_proxy_connection_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .port = 8080,
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str("aws.amazon.com"),
        .port = 80,
    };

    return s_do_proxy_get_test(allocator, &options);
}
AWS_TEST_CASE(test_http_proxy_connection_get, s_test_http_proxy_connection_get);

static int s_test_http_proxy_connection_options_star(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .port = 8080,
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str("example.org"),
        .port = 80,
    };
    struct proxy_tester tester;
    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("OPTIONS"));
    aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("*"));

    struct aws_http_header host = {
        .name = aws_byte_cursor_from_c_str("Host"),
        .value = aws_byte_cursor_from_c_str("example.org"),
    };
    aws_http_message_add_header(request, host);

    struct aws_http_header accept = {
        .name = aws_byte_cursor_from_c_str("Accept"),
        .value = aws_byte_cursor_from_c_str("*/*"),
    };
    aws_http_message_add_header(request, accept);

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.client_connection = tester.client_connection;
    request_options.request = request;
    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.user_data = &tester;
    request_options.on_response_headers = s_aws_http_on_incoming_headers_proxy_test;
    request_options.on_response_header_block_done = s_aws_http_on_incoming_header_block_done_proxy_test;
    request_options.on_response_body = s_aws_http_on_incoming_body_proxy_test;
    request_options.on_complete = s_aws_http_on_stream_complete_proxy_test;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);
    (void)stream;

    ASSERT_SUCCESS(proxy_tester_wait(&tester, proxy_tester_request_complete_pred_fn));

    aws_http_stream_release(stream);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    aws_http_message_destroy(request);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_options_star, s_test_http_proxy_connection_options_star);

static int s_test_https_proxy_connection_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .port = 8080,
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str("aws.amazon.com"),
        .port = 443,
        .test_mode = PTTM_HTTPS,
        .failure_type = PTFT_NONE,
    };

    struct proxy_tester tester;
    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));
    ASSERT_TRUE(tester.wait_result == AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_https_proxy_connection_new_destroy, s_test_https_proxy_connection_new_destroy);

static int s_test_https_proxy_connection_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .port = 8080,
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str("aws.amazon.com"),
        .port = 443,
        .test_mode = PTTM_HTTPS,
        .failure_type = PTFT_NONE,
    };

    return s_do_proxy_get_test(allocator, &options);
}
AWS_TEST_CASE(test_https_proxy_connection_get, s_test_https_proxy_connection_get);