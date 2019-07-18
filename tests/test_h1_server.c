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
#include <aws/http/private/connection_impl.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/http/request_response.h>
#include <aws/http/server.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/log_writer.h>
#include <aws/common/uuid.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

#include <aws/testing/io_testing_channel.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct simple_body_sender {
    struct aws_byte_cursor src;
    size_t progress;
};

struct tester_request {
    struct aws_http_stream *request_handler;

    /* All cursors in tester_request point into here */
    struct aws_byte_buf storage;

    struct aws_byte_cursor method;
    struct aws_byte_cursor uri;
    struct aws_http_header headers[100];
    size_t num_headers;

    bool header_done;
    bool has_incoming_body;

    size_t on_complete_cb_count;
    int on_complete_error_code;

    bool stop_auto_window_update;

    struct aws_byte_cursor body;

    struct simple_body_sender response_body;
};

/* Singleton used by tests in this file */
struct tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;

    struct aws_http_connection *server_connection;
    struct testing_channel testing_channel;

    struct tester_request requests[100];
    int request_num;

    bool server_connection_is_shutdown;

} s_tester;

static void s_tester_on_request_header(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)stream;
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
}

static void s_tester_on_request_header_block_done(struct aws_http_stream *stream, bool has_body, void *user_data) {
    (void)stream;
    struct tester_request *request = user_data;
    AWS_FATAL_ASSERT(request->header_done == false);
    request->header_done = true;
    request->has_incoming_body = has_body;

    struct aws_http_stream *r_handler = request->request_handler;
    AWS_FATAL_ASSERT(!aws_http_stream_get_incoming_request_method(r_handler, &request->method));
    AWS_FATAL_ASSERT(!aws_http_stream_get_incoming_request_uri(r_handler, &request->uri));
}

static void s_tester_on_request_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    size_t *out_window_update_size,
    void *user_data) {

    (void)out_window_update_size;
    (void)stream;
    struct tester_request *request = user_data;

    AWS_FATAL_ASSERT(request->header_done == true);

    AWS_FATAL_ASSERT(request->has_incoming_body);

    /* Copy data into storage, and point body cursor at that */
    AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_cursor(&request->storage, *data));
    request->body.len += data->len;
    if (!request->body.ptr) {
        request->body.ptr = request->storage.buffer + request->storage.len - request->body.len;
    }

    if (request->stop_auto_window_update) {
        *out_window_update_size = 0;
    }
}

static void s_tester_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct tester_request *request = user_data;
    (void)stream;
    request->on_complete_cb_count++;
    request->on_complete_error_code = error_code;
}

/* Create a new request handler */
static void s_tester_on_incoming_request(
    struct aws_http_connection *connection,
    struct aws_http_stream *stream,
    void *user_data) {
    (void)connection;
    struct aws_http_request_handler_options options = AWS_HTTP_REQUEST_HANDLER_OPTIONS_INIT;
    struct tester *tester = user_data;

    int index = tester->request_num;
    /* initialize the new request */
    tester->requests[index].num_headers = 0;
    tester->requests[index].has_incoming_body = false;
    tester->requests[index].header_done = false;

    aws_byte_buf_init(&tester->requests[index].storage, tester->alloc, 1024 * 1024 * 1);
    options.user_data = &tester->requests[index];
    tester->requests[index].request_handler = stream;
    options.on_request_headers = s_tester_on_request_header;
    options.on_request_header_block_done = s_tester_on_request_header_block_done;
    options.on_request_body = s_tester_on_request_body;
    options.on_complete = s_tester_on_stream_complete;

    tester->request_num++;
    aws_http_stream_configure_server_request_handler(stream, &options);
}

static int s_tester_init(struct aws_allocator *alloc) {

    aws_load_error_strings();
    aws_common_load_log_subject_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();
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

    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, alloc));

    s_tester.server_connection = aws_http_connection_new_http1_1_server(alloc, SIZE_MAX);
    ASSERT_NOT_NULL(s_tester.server_connection);
    struct aws_http_server_connection_options options = AWS_HTTP_SERVER_CONNECTION_OPTIONS_INIT;
    options.connection_user_data = &s_tester;
    options.on_incoming_request = s_tester_on_incoming_request;

    ASSERT_SUCCESS(aws_http_connection_configure_server(s_tester.server_connection, &options));

    struct aws_channel_slot *slot = aws_channel_slot_new(s_tester.testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    s_tester.server_connection->channel_slot = slot;
    ASSERT_SUCCESS(aws_channel_slot_insert_end(s_tester.testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &s_tester.server_connection->channel_handler));

    aws_channel_acquire_hold(s_tester.testing_channel.channel);

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    return AWS_OP_SUCCESS;
}

static int s_server_request_clean_up(void) {
    for (int i = 0; i < s_tester.request_num; i++) {
        aws_http_stream_release(s_tester.requests[i].request_handler);
        aws_byte_buf_clean_up(&s_tester.requests[i].storage);
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
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PARSE, request.on_complete_error_code);
    /* clean up */
    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

/* Pop first message from queue and compare its contents to expected string. */
static int s_check_written_message(struct tester *tester, const char *expected) {
    struct aws_linked_list *msgs = testing_channel_get_written_message_queue(&tester->testing_channel);
    ASSERT_TRUE(!aws_linked_list_empty(msgs));
    struct aws_linked_list_node *node = aws_linked_list_pop_front(msgs);
    struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

    ASSERT_TRUE(aws_byte_buf_eq_c_str(&msg->message_data, expected));

    aws_mem_release(msg->allocator, msg);

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

    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 204;
    opt.num_headers = 0;
    ASSERT_SUCCESS(aws_http_stream_send_response(request.request_handler, &opt));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    const char *expected = "HTTP/1.1 204 No Content\r\n"
                           "\r\n";

    ASSERT_SUCCESS(s_check_written_message(&s_tester, expected));

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
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 308;
    opt.num_headers = 2;
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
    opt.header_array = headers;
    ASSERT_SUCCESS(aws_http_stream_send_response(request.request_handler, &opt));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    const char *expected = "HTTP/1.1 308 Permanent Redirect\r\n"
                           "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
                           "Location: /index.html\r\n"
                           "\r\n";

    ASSERT_SUCCESS(s_check_written_message(&s_tester, expected));

    ASSERT_SUCCESS(s_server_tester_clean_up());
    return AWS_OP_SUCCESS;
}

static enum aws_http_outgoing_body_state s_simple_send_body(
    struct aws_http_stream *stream,
    struct aws_byte_buf *buf,
    void *user_data) {

    (void)user_data;
    (void)stream;
    struct tester_request *request = user_data;
    struct simple_body_sender *data = &request->response_body;
    size_t remaining = data->src.len - data->progress;
    size_t available = buf->capacity - buf->len;
    size_t writing = remaining < available ? remaining : available;
    aws_byte_buf_write(buf, data->src.ptr + data->progress, writing);
    data->progress += writing;

    return (writing == remaining) ? AWS_HTTP_OUTGOING_BODY_DONE : AWS_HTTP_OUTGOING_BODY_IN_PROGRESS;
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
    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_c_str("write more tests"),
        .progress = 0,
    };
    request->response_body = body_sender;
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 308;
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
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.header_array = headers;
    opt.stream_outgoing_body = s_simple_send_body;
    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, &opt));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    const char *expected = "HTTP/1.1 308 Permanent Redirect\r\n"
                           "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
                           "Location: /index.html\r\n"
                           "Content-Length: 16\r\n"
                           "\r\n"
                           "write more tests";

    ASSERT_SUCCESS(s_check_written_message(&s_tester, expected));

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
    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_c_str("response1"),
        .progress = 0,
    };
    request1->response_body = body_sender;
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 200;
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("9"),
        },
    };
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.header_array = headers;
    opt.stream_outgoing_body = s_simple_send_body;
    ASSERT_SUCCESS(aws_http_stream_send_response(request1->request_handler, &opt));

    /* response2 */
    body_sender.src = aws_byte_cursor_from_c_str("response2");
    body_sender.progress = 0;
    request2->response_body = body_sender;
    ASSERT_SUCCESS(aws_http_stream_send_response(request2->request_handler, &opt));
    /* response3 */
    body_sender.src = aws_byte_cursor_from_c_str("response3");
    body_sender.progress = 0;
    request3->response_body = body_sender;
    ASSERT_SUCCESS(aws_http_stream_send_response(request3->request_handler, &opt));
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

    ASSERT_SUCCESS(s_check_written_message(&s_tester, expected));

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
    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_c_str("response1"),
        .progress = 0,
    };
    request1->response_body = body_sender;
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 200;
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("9"),
        },
    };
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.header_array = headers;
    opt.stream_outgoing_body = s_simple_send_body;
    ASSERT_SUCCESS(aws_http_stream_send_response(request1->request_handler, &opt));

    /* response3 */
    body_sender.src = aws_byte_cursor_from_c_str("response3");
    body_sender.progress = 0;
    request3->response_body = body_sender;
    ASSERT_SUCCESS(aws_http_stream_send_response(request3->request_handler, &opt));
    /* response2 */
    body_sender.src = aws_byte_cursor_from_c_str("response2");
    body_sender.progress = 0;
    request2->response_body = body_sender;
    ASSERT_SUCCESS(aws_http_stream_send_response(request2->request_handler, &opt));

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

    ASSERT_SUCCESS(s_check_written_message(&s_tester, expected));

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
    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_c_str("response1"),
        .progress = 0,
    };
    request1->response_body = body_sender;
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 200;
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("9"),
        },
    };
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.header_array = headers;
    opt.stream_outgoing_body = s_simple_send_body;
    ASSERT_SUCCESS(aws_http_stream_send_response(request1->request_handler, &opt));

    /* response3 */
    body_sender.src = aws_byte_cursor_from_c_str("response3");
    body_sender.progress = 0;
    request3->response_body = body_sender;
    ASSERT_SUCCESS(aws_http_stream_send_response(request3->request_handler, &opt));
    /* no response2 */

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Check the result */
    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 9\r\n"
                           "\r\n"
                           "response1";

    ASSERT_SUCCESS(s_check_written_message(&s_tester, expected));

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
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 200;
    opt.num_headers = 0;
    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, &opt));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* stream is not completed */
    ASSERT_TRUE(request->on_complete_cb_count == 0);

    /* check the response */
    const char *expected = "HTTP/1.1 200 OK\r\n"
                           "\r\n";

    ASSERT_SUCCESS(s_check_written_message(&s_tester, expected));

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

    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_buf(&body_buf),
        .progress = 0,
    };
    request->response_body = body_sender;

    char content_length_value[100];
    snprintf(content_length_value, sizeof(content_length_value), "%zu", body_len);

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str(content_length_value),
        },
    };

    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 200;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.header_array = headers;
    opt.stream_outgoing_body = s_simple_send_body;
    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, &opt));

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
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 200;
    opt.num_headers = num_headers;
    opt.header_array = headers;
    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, &opt));

    /* check result */
    size_t num_io_messages;
    ASSERT_SUCCESS(s_check_multiple_messages(&s_tester, aws_byte_cursor_from_buf(&expected), &num_io_messages));

    ASSERT_TRUE(num_io_messages > 1);

    ASSERT_SUCCESS(s_server_tester_clean_up());
    aws_byte_buf_clean_up(&expected);
    return AWS_OP_SUCCESS;
}

/* Test for close connection */
/* The connection is closed before the message is sent */

enum request_handler_callback {
    REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST,
    REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS,
    REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS_DONE,
    REQUEST_HANDLER_CALLBACK_INCOMING_BODY,
    REQUEST_HANDLER_CALLBACK_OUTGOING_BODY,
    REQUEST_HANDLER_CALLBACK_COMPLETE,
    REQUEST_HANDLER_CALLBACK_COUNT,
};

struct close_from_callback_tester {
    enum request_handler_callback close_at;
    int callback_counts[REQUEST_HANDLER_CALLBACK_COUNT];
    bool is_closed;

    struct aws_allocator *alloc;
    struct aws_logger logger;

    struct aws_http_connection *server_connection;
    struct testing_channel testing_channel;

    struct tester_request requests[100];
    int request_num;

    bool server_connection_is_shutdown;
};

static void s_close_from_callback_common(
    struct aws_http_stream *stream,
    struct close_from_callback_tester *close_tester,
    enum request_handler_callback current_callback) {

    close_tester->callback_counts[current_callback]++;

    /* After connection closed, no more callbacks should fire (except for on_complete) */
    if (current_callback == REQUEST_HANDLER_CALLBACK_COMPLETE) {
        if (close_tester->close_at < REQUEST_HANDLER_CALLBACK_COMPLETE) {
            AWS_FATAL_ASSERT(close_tester->is_closed);
        }
    } else {
        AWS_FATAL_ASSERT(!close_tester->is_closed);
        AWS_FATAL_ASSERT(current_callback <= close_tester->close_at);
    }

    if (current_callback == close_tester->close_at) {
        aws_http_connection_close(aws_http_stream_get_connection(stream));
        close_tester->is_closed = true;
    }
}

static enum aws_http_outgoing_body_state s_close_from_outgoing_body(
    struct aws_http_stream *stream,
    struct aws_byte_buf *buf,
    void *user_data) {

    (void)buf;
    s_close_from_callback_common(stream, user_data, REQUEST_HANDLER_CALLBACK_OUTGOING_BODY);

    /* If we're closing from this function, try and keep going. It's a failure if we're invoked again. */
    struct close_from_callback_tester *close_tester = user_data;
    if (close_tester->close_at == REQUEST_HANDLER_CALLBACK_OUTGOING_BODY) {
        return AWS_HTTP_OUTGOING_BODY_IN_PROGRESS;
    } else {
        return AWS_HTTP_OUTGOING_BODY_DONE;
    }
}

static void s_close_from_incoming_headers(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)header_array;
    (void)num_headers;
    s_close_from_callback_common(stream, user_data, REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS);
}

static void s_close_from_incoming_headers_done(struct aws_http_stream *stream, bool has_body, void *user_data) {
    (void)has_body;
    s_close_from_callback_common(stream, user_data, REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS_DONE);
}

static void s_close_from_incoming_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    /* NOLINTNEXTLINE(readability-non-const-parameter) */
    size_t *out_window_update_size,
    void *user_data) {

    (void)data;
    (void)out_window_update_size;
    s_close_from_callback_common(stream, user_data, REQUEST_HANDLER_CALLBACK_INCOMING_BODY);
}

static void s_close_from_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)error_code;
    s_close_from_callback_common(stream, user_data, REQUEST_HANDLER_CALLBACK_COMPLETE);
}

static void s_tester_close_on_incoming_request(
    struct aws_http_connection *connection,
    struct aws_http_stream *stream,
    void *user_data) {
    (void)connection;
    struct aws_http_request_handler_options options = AWS_HTTP_REQUEST_HANDLER_OPTIONS_INIT;
    struct close_from_callback_tester *tester = user_data;

    int index = tester->request_num;
    /* initialize the new request */
    tester->requests[index].num_headers = 0;
    tester->requests[index].has_incoming_body = false;
    tester->requests[index].header_done = false;

    aws_byte_buf_init(&tester->requests[index].storage, tester->alloc, 1024 * 1024 * 1);
    options.user_data = tester;
    tester->requests[index].request_handler = stream;
    options.on_request_headers = s_close_from_incoming_headers;
    options.on_request_header_block_done = s_close_from_incoming_headers_done;
    options.on_request_body = s_close_from_incoming_body;
    options.on_complete = s_close_from_stream_complete;

    tester->request_num++;
    aws_http_stream_configure_server_request_handler(stream, &options);

    s_close_from_callback_common(stream, user_data, REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST);
}

static int s_close_tester_init(struct aws_allocator *alloc, struct close_from_callback_tester *tester) {

    aws_load_error_strings();
    aws_common_load_log_subject_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();
    aws_http_library_init(alloc);

    tester->alloc = alloc;

    tester->request_num = 0;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc));

    tester->server_connection = aws_http_connection_new_http1_1_server(alloc, SIZE_MAX);
    ASSERT_NOT_NULL(tester->server_connection);
    struct aws_http_server_connection_options options = AWS_HTTP_SERVER_CONNECTION_OPTIONS_INIT;
    options.connection_user_data = tester;
    options.on_incoming_request = s_tester_close_on_incoming_request;

    ASSERT_SUCCESS(aws_http_connection_configure_server(tester->server_connection, &options));

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    tester->server_connection->channel_slot = slot;
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &tester->server_connection->channel_handler));

    aws_channel_acquire_hold(tester->testing_channel.channel);

    testing_channel_drain_queued_tasks(&tester->testing_channel);

    return AWS_OP_SUCCESS;
}

static int s_server_close_request_clean_up(struct close_from_callback_tester *tester) {
    for (int i = 0; i < tester->request_num; i++) {
        aws_http_stream_release(tester->requests[i].request_handler);
        aws_byte_buf_clean_up(&tester->requests[i].storage);
    }
    return AWS_OP_SUCCESS;
}

static int s_server_close_tester_clean_up(struct close_from_callback_tester *tester) {
    s_server_close_request_clean_up(tester);
    aws_http_connection_release(tester->server_connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&tester->testing_channel));
    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);

    return AWS_OP_SUCCESS;
}

static int s_send_message_cursor_close(struct aws_byte_cursor data, struct close_from_callback_tester *tester) {

    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        tester->testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, data.len);
    ASSERT_NOT_NULL(msg);

    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&msg->message_data, data));

    ASSERT_SUCCESS(testing_channel_push_read_message(&tester->testing_channel, msg));

    return AWS_OP_SUCCESS;
}

static int s_test_close_from_callback(struct aws_allocator *allocator, enum request_handler_callback close_at) {

    struct close_from_callback_tester close_tester;

    AWS_ZERO_STRUCT(close_tester);
    close_tester.close_at = close_at;

    ASSERT_SUCCESS(s_close_tester_init(allocator, &close_tester));

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
    ASSERT_SUCCESS(s_send_message_cursor_close(aws_byte_cursor_from_c_str(incoming_request), &close_tester));
    testing_channel_drain_queued_tasks(&close_tester.testing_channel);

    ASSERT_TRUE(close_tester.request_num == 1);
    struct tester_request *request = close_tester.requests;

    /* send response */
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("999"),
        },
    };

    opt.status = 200;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.header_array = headers;
    opt.stream_outgoing_body = s_close_from_outgoing_body;
    ASSERT_SUCCESS(aws_http_stream_send_response(request->request_handler, &opt));
    testing_channel_drain_queued_tasks(&close_tester.testing_channel);
    /* check that callbacks were invoked before close_at, but not after */
    for (int i = 0; i < REQUEST_HANDLER_CALLBACK_COMPLETE; ++i) {
        if (i <= close_at) {
            ASSERT_TRUE(close_tester.callback_counts[i] > 0);
        } else {
            ASSERT_INT_EQUALS(0, close_tester.callback_counts[i]);
        }
    }

    /* the on_complete callback should always fire though */
    ASSERT_INT_EQUALS(1, close_tester.callback_counts[REQUEST_HANDLER_CALLBACK_COMPLETE]);

    ASSERT_SUCCESS(s_server_close_tester_clean_up(&close_tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_before_message_is_sent) {
    (void)ctx;

    struct close_from_callback_tester close_tester;

    AWS_ZERO_STRUCT(close_tester);

    ASSERT_SUCCESS(s_close_tester_init(allocator, &close_tester));

    /* close the connection */
    aws_http_connection_close(close_tester.server_connection);
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
    ASSERT_SUCCESS(s_send_message_cursor_close(aws_byte_cursor_from_c_str(incoming_request), &close_tester));
    testing_channel_drain_queued_tasks(&close_tester.testing_channel);

    /* no request handler was made */
    ASSERT_TRUE(close_tester.request_num == 0);

    /* all callbacks were not invoked */
    for (int i = 0; i < REQUEST_HANDLER_CALLBACK_COMPLETE; ++i) {
        ASSERT_INT_EQUALS(0, close_tester.callback_counts[i]);
    }

    ASSERT_SUCCESS(s_server_close_tester_clean_up(&close_tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_from_incoming_request_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_REQUEST));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_from_incoming_headers_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_from_incoming_headers_done_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_HEADERS_DONE));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_from_incoming_body_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_HANDLER_CALLBACK_INCOMING_BODY));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_from_outgoing_body_callback_stops_sending) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_HANDLER_CALLBACK_OUTGOING_BODY));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_close_from_stream_complete_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_HANDLER_CALLBACK_COMPLETE));
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
