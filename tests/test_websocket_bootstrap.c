/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/websocket_impl.h>

#include <aws/common/atomics.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/io/logging.h>
#include <aws/io/uri.h>
#include <aws/testing/aws_test_allocators.h>

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
static struct aws_http_stream *s_mock_http_connection_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);
static int s_mock_http_stream_activate(struct aws_http_stream *stream);
static void s_mock_http_stream_release(struct aws_http_stream *stream);
static struct aws_http_connection *s_mock_http_stream_get_connection(const struct aws_http_stream *stream);
static int s_mock_http_stream_get_incoming_response_status(const struct aws_http_stream *stream, int *out_status);
static struct aws_websocket *s_mock_websocket_handler_new(const struct aws_websocket_handler_options *options);

static const struct aws_websocket_client_bootstrap_system_vtable s_mock_system_vtable = {
    .aws_http_client_connect = s_mock_http_client_connect,
    .aws_http_connection_release = s_mock_http_connection_release,
    .aws_http_connection_close = s_mock_http_connection_close,
    .aws_http_connection_get_channel = s_mock_http_connection_get_channel,
    .aws_http_connection_make_request = s_mock_http_connection_make_request,
    .aws_http_stream_activate = s_mock_http_stream_activate,
    .aws_http_stream_release = s_mock_http_stream_release,
    .aws_http_stream_get_connection = s_mock_http_stream_get_connection,
    .aws_http_stream_get_incoming_response_status = s_mock_http_stream_get_incoming_response_status,
    .aws_websocket_handler_new = s_mock_websocket_handler_new,
};

static const struct aws_http_header s_handshake_response_headers[] = {
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

/* If fail_at_step is set to one of these, that step will explicitly fail and raise its enum value as the error code */
enum boot_step {
    BOOT_STEP_HTTP_CONNECT = 0x4000000, /* Use values that don't overlap with another aws-c-xyz library */
    BOOT_STEP_HTTP_CONNECT_COMPLETE,
    BOOT_STEP_REQUEST_NEW,
    BOOT_STEP_HEADERS,
    BOOT_STEP_HEADERS_DONE,
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

    struct aws_http_message *handshake_request;
    const struct aws_http_header *handshake_response_headers;
    size_t num_handshake_response_headers;

    /* State */
    struct aws_logger logger;

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
    bool http_stream_activate_called;

    bool websocket_setup_invoked;
    int websocket_setup_error_code;

    bool websocket_shutdown_invoked;
    int websocket_shutdown_error_code;
} s_tester;

static int s_tester_init(struct aws_allocator *alloc) {
    aws_http_library_init(alloc);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&s_tester.logger, alloc, &logger_options));
    aws_logger_set(&s_tester.logger);

    aws_websocket_client_bootstrap_set_system_vtable(&s_mock_system_vtable);

    /* Set default settings for tester (unless the test already configured it) */
    if (!s_tester.alloc) {
        s_tester.alloc = alloc;
    }
    if (!s_tester.handshake_response_headers) {
        s_tester.handshake_response_headers = s_handshake_response_headers;
        s_tester.num_handshake_response_headers = AWS_ARRAY_SIZE(s_handshake_response_headers);
    }

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
    aws_http_library_clean_up();
    aws_logger_clean_up(&s_tester.logger);
    return AWS_OP_SUCCESS;
}

static bool s_headers_eq(
    const struct aws_http_header *headers_a,
    size_t num_headers_a,
    const struct aws_http_header *headers_b,
    size_t num_headers_b) {

    if (num_headers_a != num_headers_b) {
        return false;
    }

    for (size_t a_i = 0; a_i < num_headers_a; ++a_i) {
        struct aws_http_header a = headers_a[a_i];

        bool found_match = false;

        for (size_t b_i = 0; b_i < num_headers_b; ++b_i) {
            struct aws_http_header b = headers_b[b_i];

            if (aws_byte_cursor_eq_ignore_case(&a.name, &b.name) &&
                aws_byte_cursor_eq_ignore_case(&a.value, &b.value)) {

                found_match = true;
                break;
            }
        }

        if (!found_match) {
            printf(
                "Failed to find header '" PRInSTR ": " PRInSTR "'\n",
                AWS_BYTE_CURSOR_PRI(a.name),
                AWS_BYTE_CURSOR_PRI(a.value));
            return false;
        }
    }

    return true;
}

static bool s_request_eq(const struct aws_http_message *request_a, const struct aws_http_message *request_b) {

    const size_t num_headers_a = aws_http_message_get_header_count(request_a);
    const size_t num_headers_b = aws_http_message_get_header_count(request_b);

    if (num_headers_a != num_headers_b) {
        return false;
    }

    for (size_t a_i = 0; a_i < num_headers_a; ++a_i) {
        struct aws_http_header a;
        aws_http_message_get_header(request_a, &a, a_i);

        bool found_match = false;

        for (size_t b_i = 0; b_i < num_headers_b; ++b_i) {
            struct aws_http_header b;
            aws_http_message_get_header(request_b, &b, b_i);

            if (aws_byte_cursor_eq_ignore_case(&a.name, &b.name) &&
                aws_byte_cursor_eq_ignore_case(&a.value, &b.value)) {

                found_match = true;
                break;
            }
        }

        if (!found_match) {
            printf(
                "Failed to find header '" PRInSTR ": " PRInSTR "'\n",
                AWS_BYTE_CURSOR_PRI(a.name),
                AWS_BYTE_CURSOR_PRI(a.value));
            return false;
        }
    }

    return true;
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

static struct aws_http_stream *s_mock_http_connection_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {

    AWS_FATAL_ASSERT(client_connection);
    AWS_FATAL_ASSERT(options);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_new_called_successfully); /* ensure we're only called once */

    if (s_tester.fail_at_step == BOOT_STEP_REQUEST_NEW) {
        aws_raise_error(BOOT_STEP_REQUEST_NEW);
        return NULL;
    }

    /* Check that headers passed into websocket_connect() carry through. */
    AWS_FATAL_ASSERT(s_request_eq(s_tester.handshake_request, options->request));

    s_tester.http_stream_new_called_successfully = true;
    s_tester.http_stream_on_response_headers = options->on_response_headers;
    s_tester.http_stream_on_response_header_block_done = options->on_response_header_block_done;
    s_tester.http_stream_on_complete = options->on_complete;
    s_tester.http_stream_user_data = options->user_data;
    return s_mock_stream;
}

static int s_mock_http_stream_activate(struct aws_http_stream *stream) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_release_called);
    s_tester.http_stream_activate_called = true;

    return AWS_OP_SUCCESS;
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
    AWS_FATAL_ASSERT(out_status);

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
    size_t num_handshake_response_headers,
    void *user_data) {

    if (error_code) {
        AWS_FATAL_ASSERT(!websocket);
    } else {
        AWS_FATAL_ASSERT(websocket == s_mock_websocket);

        /* Check that headers passed by mock response carry through. */
        AWS_FATAL_ASSERT(s_headers_eq(
            s_tester.handshake_response_headers,
            s_tester.num_handshake_response_headers,
            handshake_response_header_array,
            num_handshake_response_headers));

        AWS_FATAL_ASSERT(handshake_response_status == 101);
    }

    AWS_FATAL_ASSERT(user_data == &s_tester);

    s_tester.websocket_setup_invoked = true;
    s_tester.websocket_setup_error_code = error_code;

    /* Don't need the request anymore */
    aws_http_message_destroy(s_tester.handshake_request);
    s_tester.handshake_request = NULL;
}

static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {
    AWS_FATAL_ASSERT(websocket == s_mock_websocket);
    AWS_FATAL_ASSERT(user_data == &s_tester);

    s_tester.websocket_shutdown_invoked = true;
    s_tester.websocket_shutdown_error_code = error_code;
}

static void s_complete_http_stream_and_connection(int error_code) {
    s_tester.http_stream_on_complete(s_mock_stream, error_code, s_tester.http_stream_user_data);
    s_tester.http_connect_shutdown_callback(s_mock_http_connection, error_code, s_tester.http_stream_user_data);
}

/* Calls aws_websocket_client_connect(), and drives the async call to its conclusions.
 * Reports the reason for the failure via `out_error_code`. */
static int s_drive_websocket_connect(int *out_error_code) {
    ASSERT_NOT_NULL(out_error_code);

    bool websocket_connect_called_successfully = false;
    bool http_connect_setup_reported_success = false;

    /* Call websocket_connect() */
    static struct aws_byte_cursor path = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/");
    static const struct aws_byte_cursor host = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("server.example.com");

    s_tester.handshake_request = aws_http_message_new_websocket_handshake_request(s_tester.alloc, path, host);
    if (!s_tester.handshake_request) {
        goto finishing_checks;
    }

    struct aws_websocket_client_connection_options ws_options = {
        .allocator = s_tester.alloc,
        .bootstrap = (void *)"client channel bootstrap",
        .socket_options = (void *)"socket options",
        .host = host,
        .handshake_request = s_tester.handshake_request,
        .user_data = &s_tester,
        .on_connection_setup = s_on_websocket_setup,
        .on_connection_shutdown = s_on_websocket_shutdown,
    };

    int err = aws_websocket_client_connect(&ws_options);

    if (err) {
        goto finishing_checks;
    }
    websocket_connect_called_successfully = true;

    /* Bootstrap should have started HTTP connection */
    ASSERT_TRUE(s_tester.http_connect_called_successfully);

    /* Invoke HTTP setup callback */
    if (s_tester.fail_at_step == BOOT_STEP_HTTP_CONNECT_COMPLETE) {
        s_tester.http_connect_setup_callback(NULL, BOOT_STEP_HTTP_CONNECT_COMPLETE, s_tester.http_connect_user_data);
        goto finishing_checks;
    }

    http_connect_setup_reported_success = true;
    s_tester.http_connect_setup_callback(s_mock_http_connection, AWS_ERROR_SUCCESS, s_tester.http_connect_user_data);

    /* Once websocket has valid HTTP connection, if anything goes wrong, the HTTP connection must be closed in order to
     * wrap things up. We manually check at every opportunity whether close has been called, and if so invoke the HTTP
     * shutdown callback */
    if (s_tester.http_connection_close_called) {
        s_tester.http_connect_shutdown_callback(
            s_mock_http_connection, AWS_OP_SUCCESS, s_tester.http_connect_user_data);
        goto finishing_checks;
    }

    /* Bootstrap should have created new stream */
    ASSERT_TRUE(s_tester.http_stream_new_called_successfully);

    /* HTTP connection could fail before any headers arrive */
    if (s_tester.fail_at_step == BOOT_STEP_HEADERS) {
        s_complete_http_stream_and_connection(BOOT_STEP_HEADERS);
        goto finishing_checks;
    }

    /* Headers arrive, HTTP connection ends if callback returns error */
    if (s_tester.http_stream_on_response_headers(
            s_mock_stream,
            AWS_HTTP_HEADER_BLOCK_MAIN,
            s_tester.handshake_response_headers,
            s_tester.num_handshake_response_headers,
            s_tester.http_stream_user_data)) {

        s_complete_http_stream_and_connection(aws_last_error());
        goto finishing_checks;
    }

    /* HTTP connection could fail before headers are done */
    if (s_tester.fail_at_step == BOOT_STEP_HEADERS_DONE) {
        s_complete_http_stream_and_connection(BOOT_STEP_HEADERS_DONE);
        goto finishing_checks;
    }

    /* Headers are done, HTTP connection ends if error returned */
    if (s_tester.http_stream_on_response_header_block_done(s_mock_stream, false, s_tester.http_stream_user_data)) {
        s_complete_http_stream_and_connection(aws_last_error());
        goto finishing_checks;
    }

    if (s_tester.http_connection_close_called) {
        s_complete_http_stream_and_connection(AWS_OP_SUCCESS);
        goto finishing_checks;
    }

    /* Bootstrap should have created new websocket */
    ASSERT_TRUE(s_tester.websocket_new_called_successfully);

    /* Bootstrap should have notified that setup was successful */
    ASSERT_TRUE(s_tester.websocket_setup_invoked);
    if (s_tester.websocket_setup_error_code) {
        goto finishing_checks;
    }

    /* Invoke HTTP shutdown callback */
    if (s_tester.fail_at_step == BOOT_STEP_HTTP_SHUTDOWN) {
        s_complete_http_stream_and_connection(BOOT_STEP_HTTP_SHUTDOWN);
        goto finishing_checks;
    }

    s_complete_http_stream_and_connection(AWS_OP_SUCCESS);

finishing_checks:

    /* Free the request */
    if (s_tester.handshake_request) {
        aws_http_message_destroy(s_tester.handshake_request);
        s_tester.handshake_request = NULL;
    }

    if (!websocket_connect_called_successfully) {
        /* If we didn't even kick off the async process, aws_last_error() has reason for failure */
        *out_error_code = aws_last_error();
        ASSERT_FALSE(s_tester.websocket_setup_invoked);
        ASSERT_FALSE(s_tester.websocket_shutdown_invoked);
    } else {
        /* If connection kicked off at all, setup callback must fire. */
        ASSERT_TRUE(s_tester.websocket_setup_invoked);
        if (s_tester.websocket_setup_error_code) {
            *out_error_code = s_tester.websocket_setup_error_code;

            /* If setup callback reported failure, shutdown callback must never fire. */
            ASSERT_FALSE(s_tester.websocket_shutdown_invoked);
        } else {
            *out_error_code = s_tester.websocket_shutdown_error_code;

            /* If setup callback reports success, shutdown callback must fire. */
            ASSERT_TRUE(s_tester.websocket_shutdown_invoked);
        }
    }

    /* If request was created, it must be released eventually. */
    if (s_tester.http_stream_new_called_successfully) {
        ASSERT_TRUE(s_tester.http_stream_activate_called);
        ASSERT_TRUE(s_tester.http_stream_release_called);
    }

    /* If HTTP connection was established, it must be released eventually. */
    if (http_connect_setup_reported_success) {
        ASSERT_TRUE(s_tester.http_connection_release_called);
    }

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

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, websocket_connect_error_code);

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Function to be reused by all the "fail at step X" tests. */
static int s_websocket_boot_fail_at_step_test(struct aws_allocator *alloc, void *ctx, enum boot_step fail_at_step) {
    (void)ctx;
    s_tester.fail_at_step = fail_at_step;
    ASSERT_SUCCESS(s_tester_init(alloc));

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));
    ASSERT_INT_EQUALS(fail_at_step, websocket_connect_error_code);

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

TEST_CASE(websocket_boot_fail_before_response_headers) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_HEADERS);
}

TEST_CASE(websocket_boot_fail_before_response_headers_done) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_HEADERS);
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

/* Run connection process with an allocator that fakes running out of memory after N allocations. */
TEST_CASE(websocket_boot_fail_because_oom) {
    (void)ctx;

    struct aws_allocator timebomb_alloc;
    ASSERT_SUCCESS(aws_timebomb_allocator_init(&timebomb_alloc, allocator, SIZE_MAX));

    /* Only use the timebomb allocator with actual the tester, not the logger or other systems. */
    s_tester.alloc = &timebomb_alloc;

    ASSERT_SUCCESS(s_tester_init(allocator));

    /* In a loop, keep trying to connect, allowing more and more allocations to succeed,
     * until the connection completes successfully */
    bool websocket_connect_eventually_succeeded = false;
    const int max_tries = 10000;
    int timer;
    for (timer = 0; timer < max_tries; ++timer) {
        aws_timebomb_allocator_reset_countdown(&timebomb_alloc, timer);

        int websocket_connect_error_code;
        ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));

        if (websocket_connect_error_code) {
            /* Assert that proper error code bubbled all the way out */
            ASSERT_TRUE(websocket_connect_error_code == AWS_ERROR_OOM);
        } else {
            /* Break out of loop once websocket_connect() succeeds. */
            websocket_connect_eventually_succeeded = true;
            break;
        }
    }

    ASSERT_TRUE(websocket_connect_eventually_succeeded);
    ASSERT_TRUE(timer >= 2); /* Assert that we actually did fail a few times */

    ASSERT_SUCCESS(s_tester_clean_up());
    aws_timebomb_allocator_clean_up(&timebomb_alloc);
    return AWS_OP_SUCCESS;
}

/* Check that AWS_WEBSOCKET_MAX_HANDSHAKE_KEY_LENGTH is sufficiently large */
TEST_CASE(websocket_handshake_key_max_length) {
    (void)allocator;
    (void)ctx;

    uint8_t small_buf_storage[AWS_WEBSOCKET_MAX_HANDSHAKE_KEY_LENGTH];
    for (size_t i = 0; i < 100; ++i) {
        struct aws_byte_buf small_buf = aws_byte_buf_from_empty_array(small_buf_storage, sizeof(small_buf_storage));
        ASSERT_SUCCESS(aws_websocket_random_handshake_key(&small_buf));
    }

    return AWS_OP_SUCCESS;
}

/* Ensure keys are random */
TEST_CASE(websocket_handshake_key_randomness) {
    (void)ctx;

    enum { count = 100 };
    struct aws_byte_buf keys[count];

    for (int i = 0; i < count; ++i) {
        struct aws_byte_buf *key = &keys[i];
        ASSERT_SUCCESS(aws_byte_buf_init(key, allocator, AWS_WEBSOCKET_MAX_HANDSHAKE_KEY_LENGTH));
        ASSERT_SUCCESS(aws_websocket_random_handshake_key(key));
        for (int existing_i = 0; existing_i < i; ++existing_i) {
            struct aws_byte_buf *existing = &keys[existing_i];
            ASSERT_FALSE(aws_byte_buf_eq(key, existing));
        }
    }

    for (int i = 0; i < count; ++i) {
        aws_byte_buf_clean_up(&keys[i]);
    }

    return AWS_OP_SUCCESS;
}
