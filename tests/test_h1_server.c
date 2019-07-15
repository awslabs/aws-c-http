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

static void s_tester_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data){
    struct tester_request *request = user_data;
    (void) stream;
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
    struct tester *test = user_data;

    int index = test->request_num;
    /* initialize the new request */
    test->requests[index].num_headers = 0;
    test->requests[index].has_incoming_body = false;
    test->requests[index].header_done = false;

    aws_byte_buf_init(&test->requests[index].storage, test->alloc, 1024 * 1024 * 1);
    options.user_data = &test->requests[index];
    test->requests[index].request_handler = stream;
    options.on_request_headers = s_tester_on_request_header;
    options.on_request_header_block_done = s_tester_on_request_header_block_done;
    options.on_request_body = s_tester_on_request_body;
    options.on_complete = s_tester_on_stream_complete;

    test->request_num++;
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
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.uri, "/"));

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
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.uri, "/"));

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

struct simple_body_sender {
    struct aws_byte_cursor src;
    size_t progress;
} s_body_sender;

static enum aws_http_outgoing_body_state s_simple_send_body(
    struct aws_http_stream *stream,
    struct aws_byte_buf *buf,
    void *user_data) {

    (void)user_data;
    (void)stream;
    struct simple_body_sender *data = &s_body_sender;
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

    struct tester_request request = s_tester.requests[0];
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.method, "GET"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request.uri, "/"));

    /* send response */
    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_c_str("write more tests"),
        .progress = 0,
    };
    s_body_sender = body_sender;
    struct aws_http_response_options opt = AWS_HTTP_RESPONSE_OPTIONS_INIT;
    opt.status = 308;
    opt.num_headers = 3;
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
    opt.header_array = headers;
    opt.stream_outgoing_body = s_simple_send_body;
    ASSERT_SUCCESS(aws_http_stream_send_response(request.request_handler, &opt));
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