/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>
#include <aws/http/private/h1_connection.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/http/request_response.h>
#include <aws/http/server.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/log_writer.h>
#include <aws/common/uuid.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

#include <aws/testing/io_testing_channel.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct tester_request {
    struct aws_http_stream *request_handler;

    /* All cursors in tester_request point into here */
    struct aws_byte_buf storage;

    struct aws_byte_cursor method;
    struct aws_byte_cursor uri;
    struct aws_http_header headers[100];
    size_t num_headers;

    bool header_done;
    size_t on_complete_cb_count;
    int on_complete_error_code;

    struct aws_byte_cursor body;

    struct aws_input_stream *response_body;
};

/* Singleton used by tests in this file */
static struct tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;

    struct aws_http_connection *server_connection;
    struct testing_channel testing_channel;

    struct tester_request requests[100];
    int request_num;

    bool server_connection_is_shutdown;

} s_tester;

static int s_tester_on_request_header(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)stream;
    (void)header_block;
    struct tester_request *request = user_data;
    struct aws_byte_buf *storage = &request->storage;
    const struct aws_http_header *in_header = header_array;
    struct aws_http_header *my_header = request->headers + request->num_headers;
    for (size_t i = 0; i < num_headers; ++i) {
        /* copy-by-value, then update cursors to point into permanent storage */
        *my_header = *in_header;

        my_header->name.ptr = storage->buffer + storage->len;
        AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_cursor(storage, in_header->name));

        my_header->value.ptr = storage->buffer + storage->len;
        AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_cursor(storage, in_header->value));

        in_header++;
        my_header++;
        request->num_headers++;
    }
    return AWS_OP_SUCCESS;
}

static int s_tester_on_request_header_block_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    (void)stream;
    (void)header_block;
    struct tester_request *request = user_data;
    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        AWS_FATAL_ASSERT(request->header_done == false);
        request->header_done = true;
    }
    struct aws_http_stream *r_handler = request->request_handler;
    AWS_FATAL_ASSERT(!aws_http_stream_get_incoming_request_method(r_handler, &request->method));
    AWS_FATAL_ASSERT(!aws_http_stream_get_incoming_request_uri(r_handler, &request->uri));
    return AWS_OP_SUCCESS;
}

static int s_tester_on_request_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;
    struct tester_request *request = user_data;

    AWS_FATAL_ASSERT(request->header_done == true);

    /* Copy data into storage, and point body cursor at that */
    AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_cursor(&request->storage, *data));
    request->body.len += data->len;
    if (!request->body.ptr) {
        request->body.ptr = request->storage.buffer + request->storage.len - request->body.len;
    }

    return AWS_OP_SUCCESS;
}

static void s_tester_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct tester_request *request = user_data;
    (void)stream;
    request->on_complete_cb_count++;
    request->on_complete_error_code = error_code;
}

/* Create a new request handler */
static struct aws_http_stream *s_tester_on_incoming_request(struct aws_http_connection *connection, void *user_data) {

    struct aws_http_request_handler_options options = AWS_HTTP_REQUEST_HANDLER_OPTIONS_INIT;
    struct tester *tester = user_data;

    int index = tester->request_num;
    /* initialize the new request */
    tester->requests[index].num_headers = 0;
    tester->requests[index].header_done = false;
    aws_byte_buf_init(&tester->requests[index].storage, tester->alloc, 1024 * 1024 * 1);

    options.user_data = &tester->requests[index];
    options.server_connection = connection;
    options.on_request_headers = s_tester_on_request_header;
    options.on_request_header_block_done = s_tester_on_request_header_block_done;
    options.on_request_body = s_tester_on_request_body;
    options.on_complete = s_tester_on_stream_complete;
    tester->requests[index].request_handler = aws_http_stream_new_server_request_handler(&options);

    tester->request_num++;
    return tester->requests[index].request_handler;
}

static int s_tester_init(struct aws_allocator *alloc) {

    aws_http_library_init(alloc);

    AWS_ZERO_STRUCT(s_tester);

    s_tester.alloc = alloc;

    s_tester.request_num = 0;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&s_tester.logger, s_tester.alloc, &logger_options));
    aws_logger_set(&s_tester.logger);

    struct aws_testing_channel_options test_channel_options = {.clock_fn = aws_high_res_clock_get_ticks};
    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, alloc, &test_channel_options));

    struct aws_http1_connection_options http1_options;
    AWS_ZERO_STRUCT(http1_options);
    s_tester.server_connection = aws_http_connection_new_http1_1_server(alloc, true, SIZE_MAX, &http1_options);
    ASSERT_NOT_NULL(s_tester.server_connection);
    struct aws_http_server_connection_options options = AWS_HTTP_SERVER_CONNECTION_OPTIONS_INIT;
    options.connection_user_data = &s_tester;
    options.on_incoming_request = s_tester_on_incoming_request;

    ASSERT_SUCCESS(aws_http_connection_configure_server(s_tester.server_connection, &options));

    struct aws_channel_slot *slot = aws_channel_slot_new(s_tester.testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    ASSERT_SUCCESS(aws_channel_slot_insert_end(s_tester.testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &s_tester.server_connection->channel_handler));
    s_tester.server_connection->vtable->on_channel_handler_installed(
        &s_tester.server_connection->channel_handler, slot);

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    return AWS_OP_SUCCESS;
}

static int s_server_request_clean_up(void) {
    for (int i = 0; i < s_tester.request_num; i++) {
        aws_http_stream_release(s_tester.requests[i].request_handler);
        aws_byte_buf_clean_up(&s_tester.requests[i].storage);
        aws_input_stream_release(s_tester.requests[i].response_body);
    }
    return AWS_OP_SUCCESS;
}

static int s_server_tester_clean_up(void) {
    s_server_request_clean_up();
    aws_http_connection_release(s_tester.server_connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&s_tester.testing_channel));
    aws_http_library_clean_up();
    aws_logger_clean_up(&s_tester.logger);

    return AWS_OP_SUCCESS;
}

/* For sending an aws_io_message into the channel, in the write or read direction */
static int s_send_message_cursor(struct aws_byte_cursor data) {

    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        s_tester.testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, data.len);
    ASSERT_NOT_NULL(msg);

    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&msg->message_data, data));

    ASSERT_SUCCESS(testing_channel_push_read_message(&s_tester.testing_channel, msg));

    return AWS_OP_SUCCESS;
}

static int s_send_message_c_str(const char *str) {
    return s_send_message_cursor(aws_byte_cursor_from_c_str(str));
}

/* Check that we can set and tear down the `tester` used by all other tests in this file */
TEST_CASE(h1_server_sanity_check) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_receive_1line_request) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&s_tester.requests[0].method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&s_tester.requests[0].uri, "/"));

    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

static int s_check_header(struct tester_request *request, size_t i, const char *name_str, const char *value) {

    ASSERT_TRUE(i < request->num_headers);
    struct aws_http_header *header = request->headers + i;
    ASSERT_TRUE(aws_byte_cursor_eq_c_str_ignore_case(&header->name, name_str));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str_ignore_case(&header->value, value));

    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_receive_headers) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "Accept: */*\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request request = s_tester.requests[0];
    ASSERT_TRUE(request.num_headers == 2);
    ASSERT_SUCCESS(s_check_header(&request, 0, "Host", "example.com"));
    ASSERT_SUCCESS(s_check_header(&request, 1, "Accept", "*/*"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.uri, "/"));
    ASSERT_TRUE(request.body.len == 0);

    /* clean up */
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_receive_body) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "PUT /plan.txt HTTP/1.1\r\n"
                                   "Content-Length: 16\r\n"
                                   "\r\n"
                                   "write more tests";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request request = s_tester.requests[0];
    ASSERT_TRUE(request.num_headers == 1);
    ASSERT_SUCCESS(s_check_header(&request, 0, "Content-Length", "16"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.method, "PUT"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.uri, "/plan.txt"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.body, "write more tests"));

    /* clean up */
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_receive_1_request_from_multiple_io_messages) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "PUT /plan.txt HTTP/1.1\r\n"
                                   "Content-Length: 16\r\n"
                                   "\r\n"
                                   "write more tests";
    size_t str_len = strlen(incoming_request);
    for (size_t i = 0; i < str_len; ++i) {
        s_send_message_cursor(aws_byte_cursor_from_array(incoming_request + i, 1));
    }
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request request = s_tester.requests[0];
    ASSERT_TRUE(request.num_headers == 1);
    ASSERT_SUCCESS(s_check_header(&request, 0, "Content-Length", "16"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.method, "PUT"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.uri, "/plan.txt"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.body, "write more tests"));

    /* clean up */
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_receive_multiple_requests_from_1_io_messages) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "PUT /plan.txt HTTP/1.1\r\n"
                                   "Content-Length: 16\r\n"
                                   "\r\n"
                                   "write more tests"
                                   "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 2);

    struct tester_request request = s_tester.requests[0];
    ASSERT_TRUE(request.num_headers == 1);
    ASSERT_SUCCESS(s_check_header(&request, 0, "Content-Length", "16"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.method, "PUT"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.uri, "/plan.txt"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.body, "write more tests"));

    request = s_tester.requests[1];
    ASSERT_TRUE(request.num_headers == 0);
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.uri, "/"));
    /* clean up */
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_receive_bad_request_shut_down_connection) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "Mmmm garbage data\r\n\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);
    struct tester_request request = s_tester.requests[0];
    ASSERT_TRUE(request.on_complete_cb_count == 1);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, request.on_complete_error_code);
    /* clean up */
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Response creation helper function */
static int s_create_response(
    struct aws_http_message **out_response,
    int status_code,
    const struct aws_http_header *header_array,
    size_t num_headers,
    struct aws_input_stream *body) {

    struct aws_http_message *response = aws_http_message_new_response(s_tester.alloc);
    ASSERT_NOT_NULL(response);
    ASSERT_SUCCESS(aws_http_message_set_response_status(response, status_code));
    if (num_headers) {
        ASSERT_SUCCESS(aws_http_message_add_header_array(response, header_array, num_headers));
    }
    aws_http_message_set_body_stream(response, body);
    *out_response = response;
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_1line_response) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request request = s_tester.requests[0];

    struct aws_http_message *response;
    ASSERT_SUCCESS(s_create_response(&response, 204, NULL, 0, NULL));
    ASSERT_SUCCESS(aws_http_stream_send_response(request.request_handler, response));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    const char *expected = "HTTP/1.1 204 No Content\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    aws_http_message_destroy(response);
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_response_headers) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request request = s_tester.requests[0];

    /* send response */
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Date"),
            .value = aws_byte_cursor_from_c_str("Fri, 01 Mar 2019 17:18:55 GMT"),
        },
        {
            .name = aws_byte_cursor_from_c_str("Location"),
            .value = aws_byte_cursor_from_c_str("/index.html"),
        },
    };
    struct aws_http_message *response;
    ASSERT_SUCCESS(s_create_response(&response, 308, headers, AWS_ARRAY_SIZE(headers), NULL));
    ASSERT_SUCCESS(aws_http_stream_send_response(request.request_handler, response));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    const char *expected = "HTTP/1.1 308 Permanent Redirect\r\n"
                           "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
                           "Location: /index.html\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    aws_http_message_destroy(response);
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_response_body) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request *request = s_tester.requests;

    /* send response */
    struct aws_byte_cursor body_src = aws_byte_cursor_from_c_str("write more tests");
    request->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request->response_body);
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Date"),
            .value = aws_byte_cursor_from_c_str("Fri, 01 Mar 2019 17:18:55 GMT"),
        },
        {
            .name = aws_byte_cursor_from_c_str("Location"),
            .value = aws_byte_cursor_from_c_str("/index.html"),
        },
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("16"),
        },
    };
    struct aws_http_message *response;
    ASSERT_SUCCESS(s_create_response(&response, 308, headers, AWS_ARRAY_SIZE(headers), request->response_body));

    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, response));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    const char *expected = "HTTP/1.1 308 Permanent Redirect\r\n"
                           "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
                           "Location: /index.html\r\n"
                           "Content-Length: 16\r\n"
                           "\r\n"
                           "write more tests";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    aws_http_message_destroy(response);
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

static int s_test_send_expected_no_body_response(int status_int, bool head_request) {
    const char *incoming_request;
    if (head_request) {
        incoming_request = "HEAD / HTTP/1.1\r\n"
                           "\r\n";
    } else {
        incoming_request = "GET / HTTP/1.1\r\n"
                           "\r\n";
    }

    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request *request = s_tester.requests;

    /* send response */

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Date"),
            .value = aws_byte_cursor_from_c_str("Fri, 01 Mar 2019 17:18:55 GMT"),
        },
        {
            .name = aws_byte_cursor_from_c_str("Location"),
            .value = aws_byte_cursor_from_c_str("/index.html"),
        },
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("16"),
        },
    };
    struct aws_http_message *response;
    ASSERT_SUCCESS(s_create_response(&response, status_int, headers, AWS_ARRAY_SIZE(headers), NULL));

    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, response));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    char expected[500];
    const char *expected_headers = "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
                                   "Location: /index.html\r\n"
                                   "Content-Length: 16\r\n"
                                   "\r\n";

    struct aws_byte_cursor status_text = aws_byte_cursor_from_c_str(aws_http_status_text(status_int));
    char c_status_text[100];
    memcpy(c_status_text, status_text.ptr, status_text.len);
    c_status_text[status_text.len] = '\0';
    snprintf(expected, sizeof(expected), "HTTP/1.1 %d %s\r\n%s", status_int, c_status_text, expected_headers);

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, s_tester.alloc, expected));

    aws_http_message_destroy(response);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_response_to_HEAD_request) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));
    ASSERT_SUCCESS(s_test_send_expected_no_body_response(308, true));
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_304_response) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));
    ASSERT_SUCCESS(s_test_send_expected_no_body_response(304, false));
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_multiple_responses_in_order) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n"
                                   "GET / HTTP/1.1\r\n"
                                   "\r\n"
                                   "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 3);

    struct tester_request *request1 = s_tester.requests;
    struct tester_request *request2 = s_tester.requests + 1;
    struct tester_request *request3 = s_tester.requests + 2;

    /* send response */
    /* response1 */
    struct aws_byte_cursor body_src = aws_byte_cursor_from_c_str("response1");
    request1->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request1->response_body);
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("9"),
        },
    };
    struct aws_http_message *response1;
    ASSERT_SUCCESS(s_create_response(&response1, 200, headers, AWS_ARRAY_SIZE(headers), request1->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request1->request_handler, response1));

    /* response2 */
    body_src = aws_byte_cursor_from_c_str("response2");
    request2->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request2->response_body);
    struct aws_http_message *response2;
    ASSERT_SUCCESS(s_create_response(&response2, 200, headers, AWS_ARRAY_SIZE(headers), request2->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request2->request_handler, response2));
    /* response3 */
    body_src = aws_byte_cursor_from_c_str("response3");
    request3->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request3->response_body);
    struct aws_http_message *response3;
    ASSERT_SUCCESS(s_create_response(&response3, 200, headers, AWS_ARRAY_SIZE(headers), request3->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request3->request_handler, response3));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Check the result */
    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 9\r\n"
                           "\r\n"
                           "response1"
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 9\r\n"
                           "\r\n"
                           "response2"
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 9\r\n"
                           "\r\n"
                           "response3";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    aws_http_message_destroy(response1);
    aws_http_message_destroy(response2);
    aws_http_message_destroy(response3);

    ASSERT_SUCCESS(s_server_tester_clean_up());

    ASSERT_TRUE(request1->on_complete_cb_count == 1);
    ASSERT_TRUE(request2->on_complete_cb_count == 1);
    ASSERT_TRUE(request3->on_complete_cb_count == 1);

    ASSERT_TRUE(request1->on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(request2->on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(request3->on_complete_error_code == AWS_ERROR_SUCCESS);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_multiple_responses_out_of_order) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n"
                                   "GET / HTTP/1.1\r\n"
                                   "\r\n"
                                   "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 3);

    struct tester_request *request1 = s_tester.requests;
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request1->method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request1->uri, "/"));
    struct tester_request *request2 = s_tester.requests + 1;
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request2->method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request2->uri, "/"));
    struct tester_request *request3 = s_tester.requests + 2;
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request3->method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request3->uri, "/"));

    /* send response */
    /* response1 */
    struct aws_byte_cursor body_src = aws_byte_cursor_from_c_str("response1");
    request1->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request1->response_body);
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("9"),
        },
    };
    struct aws_http_message *response1;
    ASSERT_SUCCESS(s_create_response(&response1, 200, headers, AWS_ARRAY_SIZE(headers), request1->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request1->request_handler, response1));

    /* response3 */
    body_src = aws_byte_cursor_from_c_str("response3");
    request3->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request3->response_body);
    struct aws_http_message *response3;
    ASSERT_SUCCESS(s_create_response(&response3, 200, headers, AWS_ARRAY_SIZE(headers), request3->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request3->request_handler, response3));
    /* response2 */
    body_src = aws_byte_cursor_from_c_str("response2");
    request2->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request2->response_body);
    struct aws_http_message *response2;
    ASSERT_SUCCESS(s_create_response(&response2, 200, headers, AWS_ARRAY_SIZE(headers), request2->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request2->request_handler, response2));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Check the result */
    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 9\r\n"
                           "\r\n"
                           "response1"
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 9\r\n"
                           "\r\n"
                           "response2"
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 9\r\n"
                           "\r\n"
                           "response3";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    aws_http_message_destroy(response1);
    aws_http_message_destroy(response2);
    aws_http_message_destroy(response3);

    ASSERT_SUCCESS(s_server_tester_clean_up());

    ASSERT_TRUE(request1->on_complete_cb_count == 1);
    ASSERT_TRUE(request2->on_complete_cb_count == 1);
    ASSERT_TRUE(request3->on_complete_cb_count == 1);

    ASSERT_TRUE(request1->on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(request2->on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(request3->on_complete_error_code == AWS_ERROR_SUCCESS);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_multiple_responses_out_of_order_only_one_sent) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n"
                                   "GET / HTTP/1.1\r\n"
                                   "\r\n"
                                   "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 3);

    struct tester_request *request1 = s_tester.requests;
    struct tester_request *request2 = s_tester.requests + 1;
    struct tester_request *request3 = s_tester.requests + 2;

    /* send response */
    /* response1 */
    struct aws_byte_cursor body_src = aws_byte_cursor_from_c_str("response1");
    request1->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request1->response_body);
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("9"),
        },
    };
    struct aws_http_message *response1;
    ASSERT_SUCCESS(s_create_response(&response1, 200, headers, AWS_ARRAY_SIZE(headers), request1->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request1->request_handler, response1));

    /* response3 */
    body_src = aws_byte_cursor_from_c_str("response3");
    request3->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request3->response_body);
    struct aws_http_message *response3;
    ASSERT_SUCCESS(s_create_response(&response3, 200, headers, AWS_ARRAY_SIZE(headers), request1->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request3->request_handler, response3));
    /* no response2 */

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Check the result */
    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 9\r\n"
                           "\r\n"
                           "response1";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    aws_http_message_destroy(response1);
    aws_http_message_destroy(response3);

    ASSERT_SUCCESS(s_server_tester_clean_up());

    ASSERT_TRUE(request1->on_complete_cb_count == 1);
    ASSERT_TRUE(request2->on_complete_cb_count == 1);
    ASSERT_TRUE(request3->on_complete_cb_count == 1);

    ASSERT_TRUE(request1->on_complete_error_code == AWS_ERROR_SUCCESS);
    /* last two failed, response 2 is missing */
    ASSERT_TRUE(request2->on_complete_error_code == AWS_ERROR_HTTP_CONNECTION_CLOSED);
    ASSERT_TRUE(request3->on_complete_error_code == AWS_ERROR_HTTP_CONNECTION_CLOSED);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_response_before_request_finished) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request_part1 = "PUT /plan.txt HTTP/1.1\r\n"
                                         "Content-Length: 16\r\n"
                                         "\r\n"
                                         "write ";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request_part1));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Only part 1 is sent and the response is made and sent */
    ASSERT_TRUE(s_tester.request_num == 1);
    struct tester_request *request = s_tester.requests;
    struct aws_http_message *response;
    ASSERT_SUCCESS(s_create_response(&response, 200, NULL, 0, NULL));
    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, response));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* stream is not completed */
    ASSERT_TRUE(request->on_complete_cb_count == 0);

    /* check the response */
    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    const char *incoming_request_part2 = "more tests"
                                         "GET / HTTP/1.1\r\n"
                                         "\r\n";

    ASSERT_SUCCESS(s_send_message_c_str(incoming_request_part2));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* finish sending the whole request
     * the stream should be completed now */
    ASSERT_TRUE(request->on_complete_cb_count == 1);
    ASSERT_TRUE(request->on_complete_error_code == AWS_ERROR_SUCCESS);
    /* check the request */
    ASSERT_SUCCESS(s_check_header(request, 0, "Content-Length", "16"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request->method, "PUT"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request->uri, "/plan.txt"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request->body, "write more tests"));

    ASSERT_TRUE(s_tester.request_num == 2);
    request = s_tester.requests + 1;
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request->method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request->uri, "/"));
    /* clean up */
    aws_http_message_destroy(response);
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Check that expected matches data stretched across multiple messages.
 * The event-loop is ticked, and messages are dequed, as this function progresses. */
static int s_check_multiple_messages(struct tester *tester, struct aws_byte_cursor expected, size_t *out_num_messages) {
    size_t num_messages = 0;

    struct aws_linked_list *msgs = testing_channel_get_written_message_queue(&tester->testing_channel);

    size_t progress = 0;
    size_t remaining = expected.len;

    while (remaining > 0) {
        /* Tick event loop if there are no messages already */
        if (aws_linked_list_empty(msgs)) {
            testing_channel_run_currently_queued_tasks(&tester->testing_channel);
        }

        /* There should be EXACTLY 1 aws_io_message after ticking. */
        ASSERT_TRUE(!aws_linked_list_empty(msgs));
        struct aws_linked_list_node *node = aws_linked_list_pop_front(msgs);
        ASSERT_TRUE(aws_linked_list_empty(msgs));

        num_messages++;

        struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

        /* */
        ASSERT_TRUE(msg->message_data.len <= remaining);

        size_t comparing = msg->message_data.len < remaining ? msg->message_data.len : remaining;

        struct aws_byte_cursor compare_cur = aws_byte_cursor_from_array(expected.ptr + progress, comparing);
        ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&compare_cur, &msg->message_data));

        aws_mem_release(msg->allocator, msg);

        progress += comparing;
        remaining -= comparing;
    }

    /* Check that no more messages are produced unexpectedly */
    testing_channel_drain_queued_tasks(&tester->testing_channel);
    ASSERT_TRUE(aws_linked_list_empty(msgs));

    *out_num_messages = num_messages;
    return AWS_OP_SUCCESS;
}

/* Send a response whose body doesn't fit in a single aws_io_message */
TEST_CASE(h1_server_send_response_large_body) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request *request = s_tester.requests;

    /* send response */
    size_t body_len = 1024 * 1024 * 1; /* 1MB */
    struct aws_byte_buf body_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&body_buf, allocator, body_len));
    while (body_buf.len < body_len) {
        int r = rand();
        aws_byte_buf_write_be32(&body_buf, (uint32_t)r);
    }

    struct aws_byte_cursor body_src = aws_byte_cursor_from_buf(&body_buf);
    request->response_body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(request->response_body);

    char content_length_value[100];
    snprintf(content_length_value, sizeof(content_length_value), "%zu", body_len);

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str(content_length_value),
        },
    };

    struct aws_http_message *response;
    ASSERT_SUCCESS(s_create_response(&response, 200, headers, AWS_ARRAY_SIZE(headers), request->response_body));
    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, response));

    const char *expected_head_fmt = "HTTP/1.1 200 OK\r\n"
                                    "Content-Length: %zu\r\n"
                                    "\r\n";

    char expected_head[1024];
    int expected_head_len = snprintf(expected_head, sizeof(expected_head), expected_head_fmt, body_len);

    struct aws_byte_buf expected_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&expected_buf, allocator, body_len + expected_head_len));
    ASSERT_TRUE(aws_byte_buf_write(&expected_buf, (uint8_t *)expected_head, expected_head_len));
    ASSERT_TRUE(aws_byte_buf_write_from_whole_buffer(&expected_buf, body_buf));

    size_t num_io_messages;
    ASSERT_SUCCESS(s_check_multiple_messages(&s_tester, aws_byte_cursor_from_buf(&expected_buf), &num_io_messages));

    ASSERT_TRUE(num_io_messages > 1);

    ASSERT_SUCCESS(s_server_tester_clean_up());
    aws_http_message_destroy(response);
    aws_byte_buf_clean_up(&body_buf);
    aws_byte_buf_clean_up(&expected_buf);
    return AWS_OP_SUCCESS;
}

/* Send a response whose headers doesn't fit in a single aws_io_message */
TEST_CASE(h1_server_send_response_large_head) {

    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request *request = s_tester.requests;

    /* send response */

    /* Generate headers while filling in contents of `expected` buffer */
    struct aws_http_header headers[1000];
    size_t num_headers = AWS_ARRAY_SIZE(headers);
    AWS_ZERO_STRUCT(headers);

    struct aws_byte_buf expected;
    aws_byte_buf_init(&expected, allocator, num_headers * 128); /* approx capacity */

    struct aws_byte_cursor request_line = aws_byte_cursor_from_c_str("HTTP/1.1 200 OK\r\n");
    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&expected, request_line));

    /* Each header just has a UUID for its name and value */
    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header *header = headers + i;

        /* Point to where the UUID is going to be written in the `expected` buffer */
        header->name = aws_byte_cursor_from_array(expected.buffer + expected.len, AWS_UUID_STR_LEN - 1);
        header->value = header->name;

        struct aws_uuid uuid;
        ASSERT_SUCCESS(aws_uuid_init(&uuid));

        ASSERT_SUCCESS(aws_uuid_to_str(&uuid, &expected));
        ASSERT_TRUE(aws_byte_buf_write(&expected, (uint8_t *)": ", 2));
        ASSERT_SUCCESS(aws_uuid_to_str(&uuid, &expected));
        ASSERT_TRUE(aws_byte_buf_write(&expected, (uint8_t *)"\r\n", 2));
    }

    ASSERT_TRUE(aws_byte_buf_write(&expected, (uint8_t *)"\r\n", 2));

    /* sending response */
    struct aws_http_message *response;
    ASSERT_SUCCESS(s_create_response(&response, 200, headers, num_headers, NULL));
    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, response));

    /* check result */
    size_t num_io_messages;
    ASSERT_SUCCESS(s_check_multiple_messages(&s_tester, aws_byte_cursor_from_buf(&expected), &num_io_messages));

    ASSERT_TRUE(num_io_messages > 1);

    ASSERT_SUCCESS(s_server_tester_clean_up());
    aws_http_message_destroy(response);
    aws_byte_buf_clean_up(&expected);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_receive_close_header_ends_connection) {
    (void)ctx;
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    /* receive request with "Connection: close" header */
    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "Connection: close\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    /* send response */
    struct tester_request request = s_tester.requests[0];
    struct aws_http_message *response;
    ASSERT_SUCCESS(s_create_response(&response, 200, NULL, 0, NULL));
    ASSERT_SUCCESS(aws_http_stream_send_response(request.request_handler, response));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    /* stream should complete successfully */
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.requests[0].on_complete_error_code);

    /* connection should have shut down cleanly after sending response */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));

    /* clean up */
    aws_http_message_destroy(response);
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* It's not legal for a client to send another request after sending one with a "Connection: close" */
TEST_CASE(h1_server_receive_close_header_more_requests_illegal) {
    (void)ctx;
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    /* Receive 2 requests, where first one has "Connection: close" header */
    const char *incoming_request = "GET /first HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "Connection: close\r\n"
                                   "\r\n"
                                   "GET /second HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Only the first request should have registered */
    ASSERT_TRUE(s_tester.request_num == 1);
    struct tester_request *request = &s_tester.requests[0];
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request->uri, "/first"));

    /* Not checking any more state.
     * It would be valid behavior for connection to shutdown with an error code
     * OR silently ignore the second request. */

    /* clean up */
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_send_close_header_ends_connection) {
    (void)ctx;
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    /* receive request */
    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 1);

    struct tester_request request = s_tester.requests[0];

    /* send response with "Connection: close" header */
    struct aws_http_message *response;
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Connection"),
            .value = aws_byte_cursor_from_c_str("close"),
        },
    };
    ASSERT_SUCCESS(s_create_response(&response, 200, headers, AWS_ARRAY_SIZE(headers), NULL));
    ASSERT_SUCCESS(aws_http_stream_send_response(request.request_handler, response));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "Connection: close\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    /* stream should complete successfully */
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.requests[0].on_complete_error_code);

    /* connection should have shut down cleanly after sending response */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));

    /* clean up */
    aws_http_message_destroy(response);
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* When pipelining multiple requests
 * and one of the responses has a "Connection: close" header
 * ensure that everything goes correctly */
TEST_CASE(h1_server_send_close_header_with_pipelining) {
    (void)ctx;
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    /* receive 3 requests at once */
    const char *incoming_request = "GET /first HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "\r\n"
                                   "GET /second HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "\r\n"
                                   "GET /third HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_c_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(s_tester.request_num == 3);

    /* Send 3 responses.
     * Only the middle response has the "Connection: close" header */
    struct aws_http_message *responses[3];
    struct aws_http_header close_headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Connection"),
            .value = aws_byte_cursor_from_c_str("close"),
        },
    };

    /* Create responses in order: third, second, first.
     * This lets us check that we can still send a response to the first message
     * even after queueing the response to the second message with a close header. */
    for (int i = 2; i >= 0; --i) {
        struct aws_http_header *headers = NULL;
        size_t num_headers = 0;
        if (i == 1) {
            headers = close_headers;
            num_headers = AWS_ARRAY_SIZE(close_headers);
        }
        ASSERT_SUCCESS(s_create_response(&responses[i], 200, headers, num_headers, NULL));
        ASSERT_SUCCESS(aws_http_stream_send_response(s_tester.requests[i].request_handler, responses[i]));
    }
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Only the first two responses should be sent.
     * The third should not send because the second had the close header. */
    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "\r\n"
                           "HTTP/1.1 200 OK\r\n"
                           "Connection: close\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&s_tester.testing_channel, allocator, expected));

    /* Only the first two streams should complete successfully */
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.requests[0].on_complete_error_code);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.requests[1].on_complete_error_code);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, s_tester.requests[2].on_complete_error_code);

    /* Connection should have shut down due to sending close header. */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));

    /* clean up */
    for (size_t i = 0; i < 3; ++i) {
        aws_http_message_destroy(responses[i]);
    }
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Test for errors returned from callbacks */
/* The connection is closed before the message is sent */

enum request_handler_callback {
    REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST,
    REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS,
    REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS_DONE,
    REQUEST_HANDLER_CALLBACK_INCOMING_BODY,
    REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST_DONE,
    REQUEST_HANDLER_CALLBACK_OUTGOING_BODY,
    REQUEST_HANDLER_CALLBACK_COMPLETE,
    REQUEST_HANDLER_CALLBACK_COUNT,
};

static const int ERROR_FROM_CALLBACK_ERROR_CODE = (int)0xBEEFCAFE;

struct error_from_callback_tester {
    struct aws_input_stream base;
    enum request_handler_callback error_at;
    int callback_counts[REQUEST_HANDLER_CALLBACK_COUNT];
    bool has_errored;

    struct aws_allocator *alloc;
    struct aws_logger logger;

    struct aws_http_connection *server_connection;
    struct testing_channel testing_channel;

    struct tester_request requests[100];

    struct aws_stream_status outgoing_body_status;
    int request_num;
    int on_complete_error_code;
};

static int s_error_from_callback_common(
    struct error_from_callback_tester *error_tester,
    enum request_handler_callback current_callback) {

    error_tester->callback_counts[current_callback]++;

    /* After error code returned, no more callbacks should fire (except for on_complete) */
    AWS_FATAL_ASSERT(!error_tester->has_errored);
    AWS_FATAL_ASSERT(current_callback <= error_tester->error_at);
    if (current_callback == error_tester->error_at) {
        error_tester->has_errored = true;
        return aws_raise_error(ERROR_FROM_CALLBACK_ERROR_CODE);
    }

    return AWS_OP_SUCCESS;
}

static int s_error_from_outgoing_body_read(struct aws_input_stream *body, struct aws_byte_buf *dest) {

    (void)dest;

    struct error_from_callback_tester *error_tester = AWS_CONTAINER_OF(body, struct error_from_callback_tester, base);
    ASSERT_SUCCESS(s_error_from_callback_common(error_tester, REQUEST_HANDLER_CALLBACK_OUTGOING_BODY));

    /* If the common fn was successful, write out some data and end the stream */
    ASSERT_TRUE(aws_byte_buf_write(dest, (const uint8_t *)"abcd", 4));
    error_tester->outgoing_body_status.is_end_of_stream = true;
    return AWS_OP_SUCCESS;
}

static int s_error_from_outgoing_body_get_status(struct aws_input_stream *body, struct aws_stream_status *status) {
    struct error_from_callback_tester *error_tester = AWS_CONTAINER_OF(body, struct error_from_callback_tester, base);
    *status = error_tester->outgoing_body_status;
    return AWS_OP_SUCCESS;
}

static void s_error_from_outgoing_body_destroy(struct aws_input_stream *body) {
    (void)body;
}

static struct aws_input_stream_vtable s_error_from_outgoing_body_vtable = {
    .seek = NULL,
    .read = s_error_from_outgoing_body_read,
    .get_status = s_error_from_outgoing_body_get_status,
    .get_length = NULL,
};

static int s_error_from_incoming_headers(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)stream;
    (void)header_block;
    (void)header_array;
    (void)num_headers;
    return s_error_from_callback_common(user_data, REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS);
}

static int s_error_from_incoming_headers_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    (void)stream;
    (void)header_block;
    return s_error_from_callback_common(user_data, REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS_DONE);
}

static int s_error_from_incoming_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;
    (void)data;
    return s_error_from_callback_common(user_data, REQUEST_HANDLER_CALLBACK_INCOMING_BODY);
}

static int s_error_from_incoming_request_done(struct aws_http_stream *stream, void *user_data) {
    (void)stream;
    return s_error_from_callback_common(user_data, REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST_DONE);
}

static void s_error_tester_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    struct error_from_callback_tester *error_tester = user_data;
    error_tester->callback_counts[REQUEST_HANDLER_CALLBACK_COMPLETE]++;
    error_tester->on_complete_error_code = error_code;
}

static struct aws_http_stream *s_tester_close_on_incoming_request(
    struct aws_http_connection *connection,
    void *user_data) {

    struct aws_http_request_handler_options options = AWS_HTTP_REQUEST_HANDLER_OPTIONS_INIT;
    struct error_from_callback_tester *tester = user_data;

    int index = tester->request_num;
    /* initialize the new request */
    tester->requests[index].num_headers = 0;
    tester->requests[index].header_done = false;
    aws_byte_buf_init(&tester->requests[index].storage, tester->alloc, 1024 * 1024 * 1);

    options.server_connection = connection;
    options.user_data = tester;
    options.on_request_headers = s_error_from_incoming_headers;
    options.on_request_header_block_done = s_error_from_incoming_headers_done;
    options.on_request_body = s_error_from_incoming_body;
    options.on_request_done = s_error_from_incoming_request_done;
    options.on_complete = s_error_tester_on_stream_complete;

    struct aws_http_stream *stream = aws_http_stream_new_server_request_handler(&options);
    AWS_FATAL_ASSERT(stream);
    tester->requests[index].request_handler = stream;

    tester->request_num++;

    int err = s_error_from_callback_common(tester, REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST);
    if (err) {
        return NULL;
    }

    return stream;
}

static int s_error_tester_init(struct aws_allocator *alloc, struct error_from_callback_tester *tester) {

    aws_http_library_init(alloc);

    tester->alloc = alloc;
    s_tester.alloc = alloc;

    tester->request_num = 0;
    tester->outgoing_body_status.is_valid = true;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    struct aws_testing_channel_options test_channel_options = {.clock_fn = aws_high_res_clock_get_ticks};
    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc, &test_channel_options));

    struct aws_http1_connection_options http1_options;
    AWS_ZERO_STRUCT(http1_options);
    tester->server_connection = aws_http_connection_new_http1_1_server(alloc, true, SIZE_MAX, &http1_options);
    ASSERT_NOT_NULL(tester->server_connection);
    struct aws_http_server_connection_options options = AWS_HTTP_SERVER_CONNECTION_OPTIONS_INIT;
    options.connection_user_data = tester;
    options.on_incoming_request = s_tester_close_on_incoming_request;

    ASSERT_SUCCESS(aws_http_connection_configure_server(tester->server_connection, &options));

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &tester->server_connection->channel_handler));
    tester->server_connection->vtable->on_channel_handler_installed(&tester->server_connection->channel_handler, slot);

    testing_channel_drain_queued_tasks(&tester->testing_channel);

    return AWS_OP_SUCCESS;
}

static int s_server_close_request_clean_up(struct error_from_callback_tester *tester) {
    for (int i = 0; i < tester->request_num; i++) {
        aws_http_stream_release(tester->requests[i].request_handler);
        aws_byte_buf_clean_up(&tester->requests[i].storage);
    }
    return AWS_OP_SUCCESS;
}

static int s_server_error_tester_clean_up(struct error_from_callback_tester *tester) {
    s_server_close_request_clean_up(tester);
    aws_http_connection_release(tester->server_connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&tester->testing_channel));
    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);

    return AWS_OP_SUCCESS;
}

static int s_send_message_cursor_close(struct aws_byte_cursor data, struct error_from_callback_tester *tester) {

    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        tester->testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, data.len);
    ASSERT_NOT_NULL(msg);

    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&msg->message_data, data));

    ASSERT_SUCCESS(testing_channel_push_read_message(&tester->testing_channel, msg));

    return AWS_OP_SUCCESS;
}

static int s_test_error_from_callback(struct aws_allocator *allocator, enum request_handler_callback error_at) {

    struct error_from_callback_tester error_tester;

    AWS_ZERO_STRUCT(error_tester);
    error_tester.error_at = error_at;

    ASSERT_SUCCESS(s_error_tester_init(allocator, &error_tester));

    /* send request */
    const char *incoming_request = "POST / HTTP/1.1\r\n"
                                   "Transfer-Encoding: chunked\r\n"
                                   "\r\n"
                                   "3\r\n"
                                   "two\r\n"
                                   "6\r\n"
                                   "chunks\r\n"
                                   "0\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_cursor_close(aws_byte_cursor_from_c_str(incoming_request), &error_tester));
    testing_channel_drain_queued_tasks(&error_tester.testing_channel);

    ASSERT_TRUE(error_tester.request_num == 1);
    struct tester_request *request = error_tester.requests;

    /* send response */
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("4"),
        },
    };

    error_tester.base.vtable = &s_error_from_outgoing_body_vtable;
    aws_ref_count_init(
        &error_tester.base.ref_count,
        &error_tester,
        (aws_simple_completion_callback *)s_error_from_outgoing_body_destroy);

    struct aws_input_stream *error_from_outgoing_body_stream = &error_tester.base;

    struct aws_http_message *response;
    ASSERT_SUCCESS(
        s_create_response(&response, 200, headers, AWS_ARRAY_SIZE(headers), error_from_outgoing_body_stream));

    /* send_response() may succeed or fail, depending on when things shut down */
    aws_http_stream_send_response(request->request_handler, response);

    testing_channel_drain_queued_tasks(&error_tester.testing_channel);
    /* check that callbacks were invoked before error_at, but not after */
    for (int i = 0; i < REQUEST_HANDLER_CALLBACK_COMPLETE; ++i) {
        if (i <= error_at) {
            ASSERT_TRUE(error_tester.callback_counts[i] > 0);
        } else {
            ASSERT_INT_EQUALS(0, error_tester.callback_counts[i]);
        }
    }

    /* the on_complete callback should always fire though */
    ASSERT_INT_EQUALS(1, error_tester.callback_counts[REQUEST_HANDLER_CALLBACK_COMPLETE]);
    ASSERT_INT_EQUALS(ERROR_FROM_CALLBACK_ERROR_CODE, error_tester.on_complete_error_code);

    aws_http_message_destroy(response);
    aws_input_stream_release(error_from_outgoing_body_stream);
    ASSERT_SUCCESS(s_server_error_tester_clean_up(&error_tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_before_message_is_sent) {
    (void)ctx;

    struct error_from_callback_tester error_tester;

    AWS_ZERO_STRUCT(error_tester);

    ASSERT_SUCCESS(s_error_tester_init(allocator, &error_tester));

    /* close the connection */
    aws_http_connection_close(error_tester.server_connection);
    testing_channel_drain_queued_tasks(&error_tester.testing_channel);

    /* send request */
    const char *incoming_request = "POST / HTTP/1.1\r\n"
                                   "Transfer-Encoding: chunked\r\n"
                                   "\r\n"
                                   "3\r\n"
                                   "two\r\n"
                                   "6\r\n"
                                   "chunks\r\n"
                                   "0\r\n"
                                   "\r\n";
    ASSERT_SUCCESS(s_send_message_cursor_close(aws_byte_cursor_from_c_str(incoming_request), &error_tester));
    testing_channel_drain_queued_tasks(&error_tester.testing_channel);

    /* no request handler was made */
    ASSERT_TRUE(error_tester.request_num == 0);

    /* all callbacks were not invoked */
    for (int i = 0; i < REQUEST_HANDLER_CALLBACK_COMPLETE; ++i) {
        ASSERT_INT_EQUALS(0, error_tester.callback_counts[i]);
    }

    ASSERT_SUCCESS(s_server_error_tester_clean_up(&error_tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_error_from_incoming_request_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_error_from_incoming_headers_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_error_from_incoming_headers_done_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS_DONE));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_error_from_incoming_body_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_BODY));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_error_from_incoming_request_done_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST_DONE));
    return AWS_OP_SUCCESS;
}
TEST_CASE(h1_server_error_from_outgoing_body_callback_stops_sending) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_HANDLER_CALLBACK_OUTGOING_BODY));
    return AWS_OP_SUCCESS;
}

/* After aws_http_connection_close() is called, aws_http_connection_is_open() should return false,
 * even if both calls were made from outside the event-loop thread. */
TEST_CASE(h1_server_close_from_off_thread_makes_not_open) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    testing_channel_set_is_on_users_thread(&s_tester.testing_channel, false);

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.server_connection));
    aws_http_connection_close(s_tester.server_connection);
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.server_connection));

    testing_channel_set_is_on_users_thread(&s_tester.testing_channel, true);

    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_from_on_thread_makes_not_open) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    testing_channel_set_is_on_users_thread(&s_tester.testing_channel, false);
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.server_connection));

    testing_channel_set_is_on_users_thread(&s_tester.testing_channel, true);
    aws_http_connection_close(s_tester.server_connection);

    testing_channel_set_is_on_users_thread(&s_tester.testing_channel, false);
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.server_connection));

    testing_channel_set_is_on_users_thread(&s_tester.testing_channel, true);

    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}
