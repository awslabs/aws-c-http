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

/* If fail_at_step is set to one of these, that step will explicitly fail and raise its enum value as the error code */
enum boot_step {
    BOOT_STEP_HTTP_CONNECT = 0x4000000, /* Use values that don't overlap with another aws-c-xyz library */
    BOOT_STEP_HTTP_CONNECT_COMPLETE,
    BOOT_STEP_REQUEST_NEW,
    BOOT_STEP_REQUEST_COMPLETE,
    /* If the response validation steps fail, we expect a specific error */
    BOOT_STEP_VALIDATE_RESPONSE_STATUS = AWS_ERROR_HTTP_WEBSOCKET_UPGRADE_FAILURE,
    BOOT_STEP_WEBSOCKET_NEW = 0x50000000, /* Back to using made-up error-codes */
    BOOT_STEP_HTTP_SHUTDOWN,
};

/* Needs to be a static singleton so that mock functions can access it */
static struct tester {
    /* Settings */
    struct aws_allocator *alloc;
    enum boot_step fail_at_step;

    /* State */
    struct aws_logger logger;

    bool websocket_connect_called_successfully;

    bool http_connect_called_successfully;
    aws_http_on_client_connection_setup_fn *http_connect_setup_callback;
    aws_http_on_client_connection_shutdown_fn *http_connect_shutdown_callback;
    void *http_connect_user_data;

    bool http_connection_release_called;
    bool http_connection_close_called;

    bool http_stream_new_called_successfully;
    aws_http_on_incoming_headers_fn *http_stream_on_response_headers;
    aws_http_on_incoming_header_block_done_fn *http_stream_on_response_header_block_done;
    aws_http_on_stream_complete_fn *http_stream_on_complete;
    void *http_stream_user_data;

    bool websocket_new_called_successfully;

    bool http_stream_release_called;

    bool websocket_setup_invoked;
    int websocket_setup_error_code;

    bool websocket_shutdown_invoked;
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

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
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
    AWS_FATAL_ASSERT(!s_tester.http_connect_called_successfully)

    if (s_tester.fail_at_step == BOOT_STEP_HTTP_CONNECT) {
        return aws_raise_error(BOOT_STEP_HTTP_CONNECT);
    }

    s_tester.http_connect_called_successfully = true;
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
    AWS_FATAL_ASSERT(!s_tester.http_stream_new_called_successfully); /* ensure we're only called once */

    if (s_tester.fail_at_step == BOOT_STEP_REQUEST_NEW) {
        aws_raise_error(BOOT_STEP_REQUEST_NEW);
        return NULL;
    }

    s_tester.http_stream_new_called_successfully = true;
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

    if (s_tester.fail_at_step == BOOT_STEP_VALIDATE_RESPONSE_STATUS) {
        *out_status = 403;
    } else {
        *out_status = 101;
    }
    return AWS_OP_SUCCESS;
}

static struct aws_websocket *s_mock_websocket_handler_new(const struct aws_websocket_handler_options *options) {
    AWS_FATAL_ASSERT(options);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.websocket_new_called_successfully); /* ensure we're only called once */

    if (s_tester.fail_at_step == BOOT_STEP_WEBSOCKET_NEW) {
        aws_raise_error(BOOT_STEP_WEBSOCKET_NEW);
        return NULL;
    }

    s_tester.websocket_new_called_successfully = true;
    return s_mock_websocket;
}

static void s_on_websocket_setup(
    struct aws_websocket *websocket,
    int error_code,
    int handshake_response_status,
    const struct aws_http_header *handshake_response_header_array,
    size_t num_handhake_response_headers,
    void *user_data) {

    if (error_code) {
        AWS_FATAL_ASSERT(!websocket);
    } else {
        AWS_FATAL_ASSERT(websocket == s_mock_websocket);
    }

    AWS_FATAL_ASSERT(user_data == &s_tester);

    s_tester.websocket_setup_invoked = true;
    s_tester.websocket_setup_error_code = error_code;
}

static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {
    AWS_FATAL_ASSERT(websocket == s_mock_websocket);
    AWS_FATAL_ASSERT(user_data == &s_tester);

    s_tester.websocket_shutdown_invoked = true;
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

    int websocket_connect_err = aws_websocket_client_connect(&ws_options);
    aws_uri_clean_up(&uri);

    if (s_tester.fail_at_step == BOOT_STEP_HTTP_CONNECT) {
        ASSERT_ERROR(BOOT_STEP_HTTP_CONNECT, websocket_connect_err);
        ASSERT_FALSE(s_tester.websocket_setup_invoked);
        ASSERT_FALSE(s_tester.websocket_shutdown_invoked);
        return AWS_OP_SUCCESS;
    }

    ASSERT_SUCCESS(websocket_connect_err);
    s_tester.websocket_connect_called_successfully = true;

    /* Bootstrap should have started HTTP connection */
    ASSERT_TRUE(s_tester.http_connect_called_successfully);

    /* Invoke HTTP setup callback */
    if (s_tester.fail_at_step == BOOT_STEP_HTTP_CONNECT_COMPLETE) {
        s_tester.http_connect_setup_callback(NULL, BOOT_STEP_HTTP_CONNECT_COMPLETE, s_tester.http_connect_user_data);
        goto finishing_checks;
    }

    s_tester.http_connect_setup_callback(s_mock_http_connection, AWS_ERROR_SUCCESS, s_tester.http_connect_user_data);
    if (s_tester.http_connection_close_called) {
        s_tester.http_connect_shutdown_callback(
            s_mock_http_connection, AWS_OP_SUCCESS, s_tester.http_connect_user_data);
        goto finishing_checks;
    }

    /* Bootstrap should have created new stream */
    ASSERT_TRUE(s_tester.http_stream_new_called_successfully);

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

    if (s_tester.fail_at_step == BOOT_STEP_REQUEST_COMPLETE) {
        s_tester.http_stream_on_complete(s_mock_stream, BOOT_STEP_REQUEST_COMPLETE, s_tester.http_stream_user_data);
    } else {
        s_tester.http_stream_on_complete(s_mock_stream, AWS_ERROR_SUCCESS, s_tester.http_stream_user_data);
    }

    if (s_tester.http_connection_close_called) {
        s_tester.http_connect_shutdown_callback(
            s_mock_http_connection, AWS_OP_SUCCESS, s_tester.http_connect_user_data);
        goto finishing_checks;
    }

    /* Bootstrap should have created new websocket */
    ASSERT_TRUE(s_tester.websocket_new_called_successfully);

    /* Bootstrap should have notified that setup was successful */
    ASSERT_TRUE(s_tester.websocket_setup_invoked);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.websocket_setup_error_code);

    /* Invoke HTTP shutdown callback */
    if (s_tester.fail_at_step == BOOT_STEP_HTTP_SHUTDOWN) {
        s_tester.http_connect_shutdown_callback(
            s_mock_http_connection, BOOT_STEP_HTTP_SHUTDOWN, s_tester.http_connect_user_data);
        goto finishing_checks;
    }

    s_tester.http_connect_shutdown_callback(s_mock_http_connection, AWS_ERROR_SUCCESS, s_tester.http_connect_user_data);

    /* Bootstrap should have notified the shutdown had happend */
    ASSERT_TRUE(s_tester.websocket_shutdown_invoked);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.websocket_shutdown_error_code);

finishing_checks:

    /* If connection kicked off at all, setup callback must fire. */
    ASSERT_TRUE(s_tester.websocket_setup_invoked);
    if (s_tester.websocket_setup_error_code) {
        /* If setup callback reported failure, shutdown callback must never fire. */
        ASSERT_FALSE(s_tester.websocket_shutdown_invoked);

        /* Check that setup failure reports the expected error code (or 0 if we never failed) */
        ASSERT_INT_EQUALS(s_tester.fail_at_step, s_tester.websocket_setup_error_code);
    } else {
        /* If setup callback reports success, shutdown callback must fire. */
        ASSERT_TRUE(s_tester.websocket_shutdown_invoked);

        /* Check that shutdown reports the expected error code. */
        ASSERT_INT_EQUALS(s_tester.fail_at_step, s_tester.websocket_shutdown_error_code);
    }

    /* If request was created, it must be released eventually. */
    if (s_tester.http_stream_new_called_successfully) {
        ASSERT_TRUE(s_tester.http_stream_release_called);
    }

    /* If HTTP connection was established, it must be released eventually. */
    if (s_tester.fail_at_step > BOOT_STEP_HTTP_CONNECT_COMPLETE) {
        ASSERT_TRUE(s_tester.http_connection_release_called);
    }

    return AWS_OP_SUCCESS;
}

static int s_websocket_boot_fail_at_step_test(struct aws_allocator *alloc, void *ctx, enum boot_step fail_at_step) {
    (void)ctx;
    s_tester.fail_at_step = fail_at_step;
    ASSERT_SUCCESS(s_tester_init(alloc));
    ASSERT_SUCCESS(s_drive_websocket_connect());
    ASSERT_SUCCESS(s_tester_clean_up());
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

TEST_CASE(websocket_boot_fail_at_http_connect) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_HTTP_CONNECT);
}

TEST_CASE(websocket_boot_fail_at_http_connect_error) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_HTTP_CONNECT_COMPLETE);
}

TEST_CASE(websocket_boot_fail_at_new_request) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_REQUEST_NEW);
}

TEST_CASE(websocket_boot_fail_at_response_error) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_REQUEST_COMPLETE);
}

TEST_CASE(websocket_boot_fail_at_response_status) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_VALIDATE_RESPONSE_STATUS);
}

TEST_CASE(websocket_boot_fail_at_new_handler) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_WEBSOCKET_NEW);
}

TEST_CASE(websocket_boot_report_unexpected_http_shutdown) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_HTTP_SHUTDOWN);
}
