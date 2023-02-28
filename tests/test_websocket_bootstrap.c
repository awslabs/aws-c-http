/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/websocket_impl.h>

#include <aws/common/atomics.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/io/uri.h>
#include <aws/testing/aws_test_harness.h>

#ifdef _MSC_VER
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
static void s_mock_http_stream_update_window(struct aws_http_stream *stream, size_t increment_size);
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
    .aws_http_stream_update_window = s_mock_http_stream_update_window,
    .aws_http_stream_get_incoming_response_status = s_mock_http_stream_get_incoming_response_status,
    .aws_websocket_handler_new = s_mock_websocket_handler_new,
};

/* Hardcoded value for "Sec-WebSocket-Key" header in handshake request. */
static const char *s_sec_websocket_key_value = "dGhlIHNhbXBsZSBub25jZQ==";

struct test_response {
    int status_code;
    struct aws_http_header headers[10];
    const char *body;
};

static const struct test_response s_accepted_response = {
    .status_code = 101,
    .headers =
        {
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
        },
};

static const struct test_response s_rejected_response = {
    .status_code = 403,
    .headers =
        {
            {
                .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
                .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("43"),
            },
        },
    .body = "your request is bad and you should feel bad",
};

/* If fail_at_step is set to one of these, that step will explicitly fail.
 * These represent the steps where an external system could fail. */
enum boot_step {
    BOOT_STEP_HTTP_CONNECT = 0x4000000, /* Use values that don't overlap with another aws-c-xyz library */
    BOOT_STEP_HTTP_CONNECT_COMPLETE,
    BOOT_STEP_REQUEST_NEW,
    BOOT_STEP_REQUEST_ACTIVATE,
    BOOT_STEP_BEFORE_HEADERS,
    BOOT_STEP_BEFORE_HEADERS_DONE,
    BOOT_STEP_BEFORE_REJECTION_BODY,
    BOOT_STEP_BEFORE_REJECTION_STREAM_COMPLETE,
    BOOT_STEP_WEBSOCKET_NEW,
    BOOT_STEP_HTTP_SHUTDOWN,
};

/* Needs to be a static singleton so that mock functions can access it */
static struct tester {
    /* Settings */
    struct aws_allocator *alloc;
    enum boot_step fail_at_step;

    struct aws_http_header *extra_handshake_request_header_array;
    size_t num_extra_handshake_request_headers;
    struct aws_http_message *handshake_request;

    const struct test_response *handshake_response;
    size_t num_handshake_response_headers;

    /* State */
    bool http_connect_called_successfully;

    aws_http_on_client_connection_setup_fn *http_connect_setup_callback;
    aws_http_on_client_connection_shutdown_fn *http_connect_shutdown_callback;
    void *http_connect_user_data;

    bool http_connection_release_called;
    bool http_connection_close_called;

    bool http_stream_new_called_successfully;
    aws_http_on_incoming_headers_fn *http_stream_on_response_headers;
    aws_http_on_incoming_header_block_done_fn *http_stream_on_response_header_block_done;
    aws_http_on_incoming_body_fn *http_stream_on_response_body;
    aws_http_on_stream_complete_fn *http_stream_on_complete;
    void *http_stream_user_data;

    bool http_stream_on_complete_invoked;

    bool websocket_new_called_successfully;

    bool http_stream_release_called;
    bool http_stream_activate_called_successfully;

    bool websocket_setup_invoked;
    int websocket_setup_error_code;
    bool websocket_setup_had_response_status;
    bool websocket_setup_had_response_headers;
    bool websocket_setup_had_response_body;

    bool websocket_shutdown_invoked;
    int websocket_shutdown_error_code;

    /* Track the sum of all calls to aws_http_stream_update_window() */
    size_t window_increment_total;
} s_tester;

static int s_tester_init(struct aws_allocator *alloc) {
    aws_http_library_init(alloc);

    aws_websocket_client_bootstrap_set_system_vtable(&s_mock_system_vtable);

    /* Set default settings for tester (unless the test already configured it) */
    s_tester.alloc = alloc;

    if (!s_tester.handshake_response) {
        s_tester.handshake_response = &s_accepted_response;
    }

    /* Count number of headers being sent */
    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_tester.handshake_response->headers); ++i) {
        if (s_tester.handshake_response->headers[i].name.len == 0) {
            break;
        }
        s_tester.num_handshake_response_headers = i + 1;
    }

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
    aws_http_library_clean_up();
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

    for (size_t i = 0; i < num_headers_a; ++i) {
        struct aws_http_header a = headers_a[i];
        struct aws_http_header b = headers_b[i];

        if (!aws_byte_cursor_eq_ignore_case(&a.name, &b.name) || !aws_byte_cursor_eq(&a.value, &b.value)) {
            printf(
                "Header did not match '" PRInSTR ": " PRInSTR "'\n",
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
    AWS_FATAL_ASSERT(!s_tester.http_connect_called_successfully);

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
    if (connection == NULL) {
        return;
    }
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
    s_tester.http_stream_on_response_body = options->on_response_body;
    s_tester.http_stream_on_complete = options->on_complete;
    s_tester.http_stream_user_data = options->user_data;
    return s_mock_stream;
}

static int s_mock_http_stream_activate(struct aws_http_stream *stream) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_release_called);

    if (s_tester.fail_at_step == BOOT_STEP_REQUEST_ACTIVATE) {
        return aws_raise_error(BOOT_STEP_REQUEST_ACTIVATE);
    }

    s_tester.http_stream_activate_called_successfully = true;
    return AWS_OP_SUCCESS;
}

static void s_mock_http_stream_release(struct aws_http_stream *stream) {
    if (stream == NULL) {
        return;
    }

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

static void s_mock_http_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_release_called);
    s_tester.window_increment_total += increment_size;
}

static int s_mock_http_stream_get_incoming_response_status(const struct aws_http_stream *stream, int *out_status) {
    AWS_FATAL_ASSERT(stream == s_mock_stream);
    AWS_FATAL_ASSERT(!s_tester.http_connection_release_called);
    AWS_FATAL_ASSERT(!s_tester.http_stream_release_called);
    AWS_FATAL_ASSERT(out_status);

    *out_status = s_tester.handshake_response->status_code;
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

static void s_on_websocket_setup(const struct aws_websocket_on_connection_setup_data *setup, void *user_data) {

    /* error-code is set XOR websocket is set. Must be one, but not both. */
    AWS_FATAL_ASSERT((setup->error_code != 0) ^ (setup->websocket != NULL));

    /* We may not get the full handshake response.
     * But any parts we do get should match what the mock sent us. */

    if (setup->handshake_response_status) {
        s_tester.websocket_setup_had_response_status = true;
        AWS_FATAL_ASSERT(*setup->handshake_response_status == s_tester.handshake_response->status_code);

        /* If we're reporting a status code, we should also be reporting the headers */
        AWS_FATAL_ASSERT(setup->handshake_response_header_array != NULL);
    }

    if (setup->handshake_response_header_array) {
        s_tester.websocket_setup_had_response_headers = true;
        AWS_FATAL_ASSERT(s_headers_eq(
            s_tester.handshake_response->headers,
            s_tester.num_handshake_response_headers,
            setup->handshake_response_header_array,
            setup->num_handshake_response_headers));

        /* If we're reporting headers, we should also be reporting the status code */
        AWS_FATAL_ASSERT(setup->handshake_response_status != NULL);
    }

    if (setup->handshake_response_body) {
        s_tester.websocket_setup_had_response_body = true;
        AWS_FATAL_ASSERT(aws_byte_cursor_eq_c_str(setup->handshake_response_body, s_tester.handshake_response->body));

        /* If we're reporting the body, we should also be reporting the headers and status code */
        AWS_FATAL_ASSERT(setup->handshake_response_status != NULL);
        AWS_FATAL_ASSERT(setup->handshake_response_header_array != NULL);
    }

    AWS_FATAL_ASSERT(user_data == &s_tester);

    s_tester.websocket_setup_invoked = true;
    s_tester.websocket_setup_error_code = setup->error_code;

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
    if (s_tester.http_stream_activate_called_successfully && !s_tester.http_stream_on_complete_invoked) {
        s_tester.http_stream_on_complete(s_mock_stream, error_code, s_tester.http_stream_user_data);
    }
    s_tester.http_connect_shutdown_callback(s_mock_http_connection, error_code, s_tester.http_stream_user_data);
}

/* Calls aws_websocket_client_connect(), and drives the async call to its conclusions.
 * Reports the reason for the failure via `out_error_code`. */
static int s_drive_websocket_connect(int *out_error_code) {
    ASSERT_NOT_NULL(out_error_code);

    bool websocket_connect_called_successfully = false;
    bool http_connect_setup_reported_success = false;

    /* Build handshake request */
    static struct aws_byte_cursor path = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/");
    static const struct aws_byte_cursor host = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("server.example.com");

    s_tester.handshake_request = aws_http_message_new_websocket_handshake_request(s_tester.alloc, path, host);
    if (!s_tester.handshake_request) {
        goto finishing_checks;
    }

    struct aws_http_headers *request_headers = aws_http_message_get_headers(s_tester.handshake_request);
    ASSERT_SUCCESS(aws_http_headers_set(
        request_headers,
        aws_byte_cursor_from_c_str("Sec-WebSocket-Key"),
        aws_byte_cursor_from_c_str(s_sec_websocket_key_value)));

    for (size_t i = 0; i < s_tester.num_extra_handshake_request_headers; ++i) {
        ASSERT_SUCCESS(aws_http_headers_add_header(request_headers, &s_tester.extra_handshake_request_header_array[i]));
    }

    /* Call websocket_connect() */
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
            s_mock_http_connection, AWS_ERROR_SUCCESS, s_tester.http_connect_user_data);
        goto finishing_checks;
    }

    /* Bootstrap should have created new stream */
    ASSERT_TRUE(s_tester.http_stream_new_called_successfully);
    ASSERT_TRUE(s_tester.http_stream_activate_called_successfully);

    /* HTTP connection could fail before any headers arrive */
    if (s_tester.fail_at_step == BOOT_STEP_BEFORE_HEADERS) {
        s_complete_http_stream_and_connection(BOOT_STEP_BEFORE_HEADERS);
        goto finishing_checks;
    }

    /* Headers arrive, HTTP connection ends if callback returns error */
    enum aws_http_header_block header_block = s_tester.handshake_response->status_code / 100 == 1
                                                  ? AWS_HTTP_HEADER_BLOCK_INFORMATIONAL
                                                  : AWS_HTTP_HEADER_BLOCK_MAIN;
    if (s_tester.http_stream_on_response_headers(
            s_mock_stream,
            header_block,
            s_tester.handshake_response->headers,
            s_tester.num_handshake_response_headers,
            s_tester.http_stream_user_data)) {

        s_complete_http_stream_and_connection(aws_last_error());
        goto finishing_checks;
    }

    /* HTTP connection could fail before headers are done */
    if (s_tester.fail_at_step == BOOT_STEP_BEFORE_HEADERS_DONE) {
        s_complete_http_stream_and_connection(BOOT_STEP_BEFORE_HEADERS_DONE);
        goto finishing_checks;
    }

    /* Headers are done, HTTP connection ends if error returned */
    if (s_tester.http_stream_on_response_header_block_done(
            s_mock_stream, header_block, s_tester.http_stream_user_data)) {
        s_complete_http_stream_and_connection(aws_last_error());
        goto finishing_checks;
    }

    if (s_tester.http_connection_close_called) {
        s_complete_http_stream_and_connection(AWS_ERROR_SUCCESS);
        goto finishing_checks;
    }

    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        /* If the response is a rejection, it will have a body */
        struct aws_byte_cursor body = aws_byte_cursor_from_c_str(s_tester.handshake_response->body);

        /* HTTP connection could fail before the body is delivered */
        if (s_tester.fail_at_step == BOOT_STEP_BEFORE_REJECTION_BODY) {
            s_complete_http_stream_and_connection(BOOT_STEP_BEFORE_REJECTION_BODY);
            goto finishing_checks;
        }

        /* Response body arrives, HTTP connection ends if error returned */
        if (body.len > 0) {

            /* If we're testing the stream dying before the whole body is delivered, then only deliver a bit of it */
            if (s_tester.fail_at_step == BOOT_STEP_BEFORE_REJECTION_STREAM_COMPLETE) {
                body.len = 1;
            }

            if (s_tester.http_stream_on_response_body(s_mock_stream, &body, s_tester.http_stream_user_data)) {
                s_complete_http_stream_and_connection(aws_last_error());
                goto finishing_checks;
            }

            if (s_tester.http_connection_close_called) {
                s_complete_http_stream_and_connection(AWS_ERROR_SUCCESS);
                goto finishing_checks;
            }
        }

        /* HTTP connection could fail before the stream completes on its own */
        if (s_tester.fail_at_step == BOOT_STEP_BEFORE_REJECTION_STREAM_COMPLETE) {
            s_complete_http_stream_and_connection(BOOT_STEP_BEFORE_REJECTION_STREAM_COMPLETE);
            goto finishing_checks;
        }

        /* HTTP stream completes on its own after delivering rejection */
        s_tester.http_stream_on_complete(s_mock_stream, AWS_ERROR_SUCCESS, s_tester.http_stream_user_data);
        s_tester.http_stream_on_complete_invoked = true;

        /* Bootstrap should have closed the connection after receiving the completed response */
        ASSERT_TRUE(s_tester.http_connection_close_called);
        s_tester.http_connect_shutdown_callback(
            s_mock_http_connection, AWS_ERROR_SUCCESS, s_tester.http_stream_user_data);
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

    s_complete_http_stream_and_connection(AWS_ERROR_SUCCESS);

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
    ASSERT_TRUE(s_tester.websocket_setup_had_response_status);
    ASSERT_TRUE(s_tester.websocket_setup_had_response_headers);
    ASSERT_FALSE(s_tester.websocket_setup_had_response_body);

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

TEST_CASE(websocket_boot_fail_at_activate_request) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_REQUEST_ACTIVATE);
}

TEST_CASE(websocket_boot_fail_before_response_headers) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_BEFORE_HEADERS);
}

TEST_CASE(websocket_boot_fail_before_response_headers_done) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_BEFORE_HEADERS_DONE);
}

TEST_CASE(websocket_boot_fail_at_new_handler) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_WEBSOCKET_NEW);
}

TEST_CASE(websocket_boot_report_unexpected_http_shutdown) {
    return s_websocket_boot_fail_at_step_test(allocator, ctx, BOOT_STEP_HTTP_SHUTDOWN);
}

/* Test receiving a 4xx rejection response from the server.
 * Note that this test doesn't use fail_at_step, because we're not modeling
 * an "unexpected" HTTP failure. */
TEST_CASE(websocket_boot_fail_from_handshake_rejection) {
    (void)ctx;
    s_tester.handshake_response = &s_rejected_response;
    ASSERT_SUCCESS(s_tester_init(allocator));

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_UPGRADE_FAILURE, websocket_connect_error_code);

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Test the connection dying early, while processing a 4xx rejection response.
 * Specifically, after the headers are received but before the body is received. */
TEST_CASE(websocket_boot_fail_before_handshake_rejection_body) {
    (void)ctx;
    s_tester.handshake_response = &s_rejected_response;
    s_tester.fail_at_step = BOOT_STEP_BEFORE_REJECTION_BODY;
    ASSERT_SUCCESS(s_tester_init(allocator));

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));

    /* It's ambiguous what the error-code should be here.
     * The connection died early, AND we know from the status code that it was an UPGRADE_FAILURE.
     * Currently, the bootstrap is programmed to report it as a normal UPGRADE_FAILURE,
     * but don't report a body, because we didn't receive any */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_UPGRADE_FAILURE, websocket_connect_error_code);
    ASSERT_TRUE(s_tester.websocket_setup_had_response_status);
    ASSERT_TRUE(s_tester.websocket_setup_had_response_headers);
    ASSERT_FALSE(s_tester.websocket_setup_had_response_body);

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Test the connection dying early, while processing a 4xx rejection response.
 * Specifically, after some of the body is received, but before the stream completes. */
TEST_CASE(websocket_boot_fail_before_handshake_rejection_stream_complete) {
    (void)ctx;
    s_tester.handshake_response = &s_rejected_response;
    s_tester.fail_at_step = BOOT_STEP_BEFORE_REJECTION_STREAM_COMPLETE;
    ASSERT_SUCCESS(s_tester_init(allocator));

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));

    /* It's ambiguous what the error-code should be here.
     * The connection died early, AND we know from the status code that it was an UPGRADE_FAILURE.
     * Currently, the bootstrap is programmed to report it as a normal UPGRADE_FAILURE,
     * but don't report a body, because we can't be 100% sure we got the whole thing.  */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_UPGRADE_FAILURE, websocket_connect_error_code);
    ASSERT_TRUE(s_tester.websocket_setup_had_response_status);
    ASSERT_TRUE(s_tester.websocket_setup_had_response_headers);
    ASSERT_FALSE(s_tester.websocket_setup_had_response_body);

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Function to be reused by all tests that pass a bad 101 response */
static int s_websocket_boot_fail_from_bad_101_response(
    struct aws_allocator *alloc,
    const struct test_response *bad_response) {

    ASSERT_INT_EQUALS(101, bad_response->status_code, "This helper function is only for bad 101 responses");

    s_tester.handshake_response = bad_response;
    ASSERT_SUCCESS(s_tester_init(alloc));

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_UPGRADE_FAILURE, websocket_connect_error_code);
    ASSERT_TRUE(s_tester.websocket_setup_had_response_status);
    ASSERT_TRUE(s_tester.websocket_setup_had_response_headers);
    ASSERT_FALSE(s_tester.websocket_setup_had_response_body);

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_boot_fail_from_invalid_upgrade_header) {
    (void)ctx;
    struct test_response bad_response = {
        .status_code = 101,
        .headers =
            {
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("HTTP/9000"), /* ought to be "websocket" */
                },
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Connection"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
                },
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Accept"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
                },
            },
    };
    return s_websocket_boot_fail_from_bad_101_response(allocator, &bad_response);
}

TEST_CASE(websocket_boot_fail_from_missing_upgrade_header) {
    (void)ctx;
    struct test_response bad_response = {
        .status_code = 101,
        .headers =
            {
                /* Commenting out required header
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("websocket"),
                },
                */
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Connection"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
                },
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Accept"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
                },
            },
    };
    return s_websocket_boot_fail_from_bad_101_response(allocator, &bad_response);
}

TEST_CASE(websocket_boot_fail_from_invalid_connection_header) {
    (void)ctx;
    struct test_response bad_response = {
        .status_code = 101,
        .headers =
            {
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("websocket"),
                },
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Connection"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("HeartToHeart"), /* ought to be "Upgrade" */
                },
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Accept"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
                },
            },
    };
    return s_websocket_boot_fail_from_bad_101_response(allocator, &bad_response);
}

TEST_CASE(websocket_boot_fail_from_invalid_sec_websocket_accept_header) {
    (void)ctx;
    struct test_response bad_response = {
        .status_code = 101,
        .headers =
            {
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
                    /* ought to be "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="*/
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("S3PPLMBITXAQ9KYGZZHZRBK+XOO="),
                },
            },
    };
    return s_websocket_boot_fail_from_bad_101_response(allocator, &bad_response);
}

TEST_CASE(websocket_boot_fail_from_unsupported_sec_websocket_extensions_in_request) {
    (void)ctx;
    struct aws_http_header extra_request_headers[] = {
        /* extensions are not currently supported */
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Extensions"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("permessage-deflate"),
        },
    };
    s_tester.extra_handshake_request_header_array = extra_request_headers;
    s_tester.num_extra_handshake_request_headers = AWS_ARRAY_SIZE(extra_request_headers);

    ASSERT_SUCCESS(s_tester_init(allocator));

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));
    ASSERT_INT_EQUALS(AWS_ERROR_INVALID_ARGUMENT, websocket_connect_error_code);
    ASSERT_FALSE(s_tester.websocket_setup_invoked);

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_boot_fail_from_unsupported_sec_websocket_extensions_in_response) {
    (void)ctx;
    struct test_response bad_response = {
        .status_code = 101,
        .headers =
            {
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
                {
                    /* extensions are not currently supported */
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Extensions"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("permessage-deflate"),
                },
            },
    };
    return s_websocket_boot_fail_from_bad_101_response(allocator, &bad_response);
}

/* If client requests a specific protocol, the server response must say it's being used */
TEST_CASE(websocket_boot_ok_with_sec_websocket_protocol_header) {
    (void)ctx;
    struct aws_http_header extra_request_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("mqtt"),
        },
    };
    s_tester.extra_handshake_request_header_array = extra_request_headers;
    s_tester.num_extra_handshake_request_headers = AWS_ARRAY_SIZE(extra_request_headers);

    struct test_response response = {
        .status_code = 101,
        .headers =
            {
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
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("mqtt"),
                },
            },
    };
    s_tester.handshake_response = &response;

    ASSERT_SUCCESS(s_tester_init(allocator));

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));
    ASSERT_INT_EQUALS(0, websocket_connect_error_code);

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* The client can request a list of acceptable protocols (may be split across headers), and server must pick one */
TEST_CASE(websocket_boot_ok_with_sec_websocket_protocol_split_across_headers) {
    (void)ctx;
    struct aws_http_header extra_request_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("http/1.1, http/2"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("mqtt, mqtt5, mqtt6"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("klingon, esperanto"),
        },
    };
    s_tester.extra_handshake_request_header_array = extra_request_headers;
    s_tester.num_extra_handshake_request_headers = AWS_ARRAY_SIZE(extra_request_headers);

    struct test_response response = {
        .status_code = 101,
        .headers =
            {
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
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("mqtt5"),
                },
            },
    };
    s_tester.handshake_response = &response;

    ASSERT_SUCCESS(s_tester_init(allocator));

    int websocket_connect_error_code;
    ASSERT_SUCCESS(s_drive_websocket_connect(&websocket_connect_error_code));
    ASSERT_INT_EQUALS(0, websocket_connect_error_code);

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_boot_fail_from_missing_sec_websocket_protocol_header) {
    (void)ctx;
    struct aws_http_header extra_request_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("mqtt, mqtt5"),
        },
    };
    s_tester.extra_handshake_request_header_array = extra_request_headers;
    s_tester.num_extra_handshake_request_headers = AWS_ARRAY_SIZE(extra_request_headers);

    struct test_response bad_response = {
        .status_code = 101,
        .headers =
            {
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
                /* commenting out required header
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("mqtt5"),
                },
                */
            },
    };
    return s_websocket_boot_fail_from_bad_101_response(allocator, &bad_response);
}

TEST_CASE(websocket_boot_fail_from_invalid_sec_websocket_protocol_header) {
    (void)ctx;
    struct aws_http_header extra_request_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("mqtt, mqtt5"),
        },
    };
    s_tester.extra_handshake_request_header_array = extra_request_headers;
    s_tester.num_extra_handshake_request_headers = AWS_ARRAY_SIZE(extra_request_headers);

    struct test_response bad_response = {
        .status_code = 101,
        .headers =
            {
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
                {
                    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
                    /* ought to be "mqtt" or "mqtt5" */
                    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("mqtt, mqtt5"),
                },
            },
    };
    return s_websocket_boot_fail_from_bad_101_response(allocator, &bad_response);
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
