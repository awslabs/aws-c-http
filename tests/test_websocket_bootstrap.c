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

#include <aws/http/private/websocket_impl.h>

#include <aws/io/logging.h>
#include <aws/testing/aws_test_harness.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

static int s_mock_http_client_connect(const struct aws_http_client_connection_options *options);
static void s_mock_http_connection_release(struct aws_http_connection *connection);
static void s_mock_http_connection_close(struct aws_http_connection *connection);
static struct aws_channel *s_mock_http_connection_get_channel(struct aws_http_connection *connection);
static struct aws_http_stream *s_mock_http_stream_new_client_request(const struct aws_http_request_options *options);
static void s_mock_http_stream_release(struct aws_http_stream *stream);
static struct aws_http_connection *s_mock_http_stream_get_connection(const struct aws_http_stream *stream);
static int s_mock_http_stream_get_incoming_response_status(const struct aws_http_stream *stream, int *out_status);
static struct aws_websocket *s_mock_websocket_handler_new(const struct aws_websocket_handler_options *options);

static struct aws_websocket_client_bootstrap_function_table s_mock_function_table = {
    .aws_http_client_connect = s_mock_http_client_connect,
    .aws_http_connection_release = s_mock_http_connection_release,
    .aws_http_connection_close = s_mock_http_connection_close,
    .aws_http_connection_get_channel = s_mock_http_connection_get_channel,
    .aws_http_stream_new_client_request = s_mock_http_stream_new_client_request,
    .aws_http_stream_release = s_mock_http_stream_release,
    .aws_http_stream_get_connection = s_mock_http_stream_get_connection,
    .aws_http_stream_get_incoming_response_status = s_mock_http_stream_get_incoming_response_status,
    .aws_websocket_handler_new = s_mock_websocket_handler_new,
};

enum boot_step {
    BOOT_STEP_NONE,
    BOOT_STEP_HTTP_CONNECT,
    BOOT_STEP_HTTP_CONNECT_COMPLETE,
    BOOT_STEP_REQUEST_NEW,
    BOOT_STEP_REQUEST_COMPLETE,
    BOOT_STEP_WEBSOCKET_NEW,
    BOOT_STEP_HTTP_SHUTDOWN,
};

/* Needs to be a static singleton so that mock functions can access it */
static struct tester {
    /* Settings */
    struct aws_allocator *alloc;
    enum boot_step fail_at_step;

    /* State */
    struct aws_logger logger;
} s_tester;

static int s_tester_init(struct aws_allocator *alloc) {
    aws_load_error_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();
    aws_http_library_init(alloc);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&s_tester.logger, alloc, &logger_options));
    aws_logger_set(&s_tester.logger);

    s_tester.alloc = alloc;

    aws_websocket_client_bootstrap_set_function_table(&s_mock_function_table);

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
    aws_http_library_clean_up();
    aws_logger_clean_up(&s_tester.logger);
    return AWS_OP_SUCCESS;
}

/* Totally fake and not real objects created by the mocked functions */
static struct aws_http_connection *s_mock_http_connection = (void*)"http connection";
static struct aws_http_stream *s_mock_stream = (void*)"stream";
static struct aws_channel *s_mock_channel = (void *)"channel";
static struct aws_websocket *s_mock_websocket = (void *)"websocket";

static int s_mock_http_client_connect(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options);
    return AWS_OP_SUCCESS;
}

static void s_mock_http_connection_release(struct aws_http_connection *connection) {
    AWS_FATAL_ASSERT(connection == s_mock_http_connection);
}

static void s_mock_http_connection_close(struct aws_http_connection *connection) {
    AWS_FATAL_ASSERT(connection == s_mock_http_connection);
}

static struct aws_channel *s_mock_http_connection_get_channel(struct aws_http_connection *connection) {
    AWS_FATAL_ASSERT(connection == s_mock_http_connection);
    return s_mock_channel;
}

static struct aws_http_stream *s_mock_http_stream_new_client_request(const struct aws_http_request_options *options) {
    AWS_FATAL_ASSERT(options);
    return s_mock_stream;
}

static void s_mock_http_stream_release(struct aws_http_stream *stream) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
}

static struct aws_http_connection *s_mock_http_stream_get_connection(const struct aws_http_stream *stream) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    return s_mock_http_connection;
}

static int s_mock_http_stream_get_incoming_response_status(const struct aws_http_stream *stream, int *out_status) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    *out_status = 101;
    return AWS_OP_SUCCESS;
}

static struct aws_websocket *s_mock_websocket_handler_new(const struct aws_websocket_handler_options *options) {
    AWS_FATAL_ASSERT(options);
    return s_mock_websocket;
}

/* Test the infrastructure of this file */
TEST_CASE(websocket_boot_sanity_check) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));
    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Test that connection and shutdown proceed as expected if we don't make anything go wrong. */
TEST_CASE(websocket_boot_golden_path) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));
    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}
