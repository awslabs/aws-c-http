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

#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/io/logging.h>
#include <aws/io/uri.h>
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

    bool websocket_connect_called;

    bool http_connect_called;
    aws_http_on_client_connection_setup_fn *http_connect_setup_callback;
    aws_http_on_client_connection_shutdown_fn *http_connect_shutdown_callback;
    void *http_connect_user_data;

    bool http_connection_release_called;
    bool http_connection_close_called;

    bool http_stream_new_called;
    aws_http_on_incoming_headers_fn *http_stream_on_response_headers;
    aws_http_on_incoming_header_block_done_fn *http_stream_on_response_header_block_done;
    aws_http_on_stream_complete_fn *http_stream_on_complete;
    void *http_stream_user_data;

    bool websocket_new_called;

    bool http_stream_release_called;

    bool websocket_setup_complete;
    int websocket_setup_error_code;

    bool websocket_shutdown_complete;
    int websocket_shutdown_error_code;

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

    aws_websocket_client_bootstrap_set_function_table(&s_mock_function_table);

    s_tester.alloc = alloc;
    // ASSERT_SUCCESS(aws_mutex_init(&s_tester.mutex));
    // ASSERT_SUCCESS(aws_condition_variable_init(&s_tester.cvar));

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
    /* If connect called, then setup must fire. If setup successful then shutdown must fire. */
    if (s_tester.websocket_connect_called) {
        ASSERT_TRUE(s_tester.websocket_setup_complete);
        if (s_tester.websocket_setup_error_code == AWS_OP_SUCCESS) {
            ASSERT_TRUE(s_tester.websocket_shutdown_complete);
        } else {
            ASSERT_FALSE(s_tester.websocket_shutdown_complete);
        }
    }

    aws_http_library_clean_up();
    aws_logger_clean_up(&s_tester.logger);
    return AWS_OP_SUCCESS;
}

/* Totally fake and not real objects created by the mocked functions */
static struct aws_http_connection *s_mock_http_connection = (void *)"http connection";
static struct aws_http_stream *s_mock_stream = (void *)"stream";
static struct aws_channel *s_mock_channel = (void *)"channel";
static struct aws_websocket *s_mock_websocket = (void *)"websocket";

static int s_mock_http_client_connect(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options);
    AWS_FATAL_ASSERT(!s_tester.http_connect_called)
    s_tester.http_connect_called = true;
    s_tester.http_connect_setup_callback = options->on_setup;
    s_tester.http_connect_shutdown_callback = options->on_shutdown;
    s_tester.http_connect_user_data = options->user_data;
    return AWS_OP_SUCCESS;
}

static void s_mock_http_connection_release(struct aws_http_connection *connection) {
    AWS_FATAL_ASSERT(connection == s_mock_http_connection);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    s_tester.http_connection_release_called = true;
}

static void s_mock_http_connection_close(struct aws_http_connection *connection) {
    AWS_FATAL_ASSERT(connection == s_mock_http_connection);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    s_tester.http_connection_close_called = true;
}

static struct aws_channel *s_mock_http_connection_get_channel(struct aws_http_connection *connection) {
    AWS_FATAL_ASSERT(connection == s_mock_http_connection);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    return s_mock_channel;
}

static struct aws_http_stream *s_mock_http_stream_new_client_request(const struct aws_http_request_options *options) {
    AWS_FATAL_ASSERT(options);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_new_called); /* ensure we're only called once */
    s_tester.http_stream_new_called = true;
    s_tester.http_stream_on_response_headers = options->on_response_headers;
    s_tester.http_stream_on_response_header_block_done = options->on_response_header_block_done;
    s_tester.http_stream_on_complete = options->on_complete;
    s_tester.http_stream_user_data = options->user_data;
    return s_mock_stream;
}

static void s_mock_http_stream_release(struct aws_http_stream *stream) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_release_called);
    s_tester.http_stream_release_called = true;
}

static struct aws_http_connection *s_mock_http_stream_get_connection(const struct aws_http_stream *stream) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_release_called);
    return s_mock_http_connection;
}

static int s_mock_http_stream_get_incoming_response_status(const struct aws_http_stream *stream, int *out_status) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_release_called);
    *out_status = 101;
    return AWS_OP_SUCCESS;
}

static struct aws_websocket *s_mock_websocket_handler_new(const struct aws_websocket_handler_options *options) {
    AWS_FATAL_ASSERT(options);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.websocket_new_called); /* ensure we're only called once */
    s_tester.websocket_new_called = true;
    return s_mock_websocket;
}

static void s_on_websocket_setup(
    struct aws_websocket *websocket,
    int error_code,
    int handshake_response_status,
    const struct aws_http_header *handshake_response_header_array,
    size_t num_handhake_response_headers,
    void *user_data) {

    AWS_FATAL_ASSERT(websocket == s_mock_websocket);
    AWS_FATAL_ASSERT(user_data == &s_tester);

    s_tester.websocket_setup_complete = true;
    s_tester.websocket_setup_error_code = error_code;
}

static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {
    AWS_FATAL_ASSERT(websocket == s_mock_websocket);
    AWS_FATAL_ASSERT(user_data == &s_tester);

    s_tester.websocket_shutdown_complete = true;
    s_tester.websocket_shutdown_error_code = error_code;
}

static int s_drive_websocket_connect(void) {
    /* Call websocket_connect() */
    struct aws_byte_cursor uri_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("server.example.com");
    struct aws_uri uri;
    ASSERT_SUCCESS(aws_uri_init_parse(&uri, s_tester.alloc, &uri_cursor));

    struct aws_http_header request_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("server.example.com"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("websocket"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Connection"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Key"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("dGhlIHNhbXBsZSBub25jZQ=="),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Version"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("13"),
        },
    };

    struct aws_websocket_client_connection_options ws_options = {
        .allocator = s_tester.alloc,
        .bootstrap = (void *)"client channel bootstrap",
        .socket_options = (void *)"socket options",
        .uri = &uri,
        .handshake_header_array = request_headers,
        .num_handshake_headers = AWS_ARRAY_SIZE(request_headers),
        .user_data = &s_tester,
        .on_connection_setup = s_on_websocket_setup,
        .on_connection_shutdown = s_on_websocket_shutdown,
    };

    s_tester.websocket_connect_called = true;
    ASSERT_SUCCESS(aws_websocket_client_connect(&ws_options));
    aws_uri_clean_up(&uri);

    /* Bootstrap should have started HTTP connection */
    ASSERT_TRUE(s_tester.http_connect_called);

    /* Invoke HTTP setup callback */
    s_tester.http_connect_setup_callback(s_mock_http_connection, AWS_ERROR_SUCCESS, s_tester.http_connect_user_data);

    /* Bootstrap should have created new stream */
    ASSERT_TRUE(s_tester.http_stream_new_called);

    /* Invoke stream response callbacks */
    struct aws_http_header response_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("websocket"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Connection"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Accept"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        },
    };

    s_tester.http_stream_on_response_headers(
        s_mock_stream, response_headers, AWS_ARRAY_SIZE(response_headers), s_tester.http_stream_user_data);

    if (s_tester.http_stream_on_response_header_block_done) {
        s_tester.http_stream_on_response_header_block_done(s_mock_stream, false, s_tester.http_stream_user_data);
    }

    s_tester.http_stream_on_complete(s_mock_stream, AWS_ERROR_SUCCESS, s_tester.http_stream_user_data);

    /* Bootstrap should have created new websocket */
    ASSERT_TRUE(s_tester.websocket_new_called);

    /* Bootstrap should have notified that setup was successful */
    ASSERT_TRUE(s_tester.websocket_setup_complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.websocket_setup_error_code);

    /* Invoke HTTP shutdown callback */
    s_tester.http_connect_shutdown_callback(s_mock_http_connection, AWS_ERROR_SUCCESS, s_tester.http_connect_user_data);

    /* Bootstrap should have notified the shutdown had happend */
    ASSERT_TRUE(s_tester.websocket_shutdown_complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.websocket_shutdown_error_code);

    /* Check the bootstrap cleaned up any resources it had acquired. */
    ASSERT_TRUE(s_tester.http_stream_release_called);
    ASSERT_TRUE(s_tester.http_connection_release_called);

    return AWS_OP_SUCCESS;
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

    ASSERT_SUCCESS(s_drive_websocket_connect());

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}
