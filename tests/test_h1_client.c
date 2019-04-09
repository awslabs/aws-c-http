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

#include <aws/http/private/connection_impl.h>
#include <aws/http/request_response.h>

#include <aws/common/uuid.h>
#include <aws/io/logging.h>
#include <aws/testing/io_testing_channel.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define H1_CLIENT_TEST_CASE(NAME)                                                                                      \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct tester {
    struct aws_allocator *alloc;
    struct testing_channel testing_channel;
    struct aws_http_connection *connection;
    bool is_shut_down;
    int shutdown_error_code;
    struct aws_logger logger;
};

static void s_on_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)connection;
    struct tester *tester = user_data;
    tester->is_shut_down = true;
    tester->shutdown_error_code = error_code;
}

static int s_tester_init(struct tester *tester, struct aws_allocator *alloc) {
    aws_load_error_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();
    aws_http_library_init(alloc);

    AWS_ZERO_STRUCT(*tester);

    tester->alloc = alloc;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc));

    struct aws_http_client_connection_impl_options options = {
        .alloc = alloc,
        .initial_window_size = SIZE_MAX,
        .user_data = tester,
        .on_shutdown = s_on_shutdown,
    };
    tester->connection = aws_http_connection_new_http1_1_client(&options);
    ASSERT_NOT_NULL(tester->connection);

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    tester->connection->channel_slot = slot;
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &tester->connection->channel_handler));

    aws_channel_acquire_hold(tester->testing_channel.channel);

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    aws_http_connection_release(tester->connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&tester->testing_channel));
    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);
    return AWS_OP_SUCCESS;
}

/* Check that we can set and tear down the `tester` used by all other tests in this file */
H1_CLIENT_TEST_CASE(h1_client_sanity_check) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Pop first message from queue and compare its contents to expected string. */
static int s_check_message(struct tester *tester, const char *expected) {
    struct aws_linked_list *msgs = testing_channel_get_written_message_queue(&tester->testing_channel);
    ASSERT_TRUE(!aws_linked_list_empty(msgs));
    struct aws_linked_list_node *node = aws_linked_list_pop_front(msgs);
    struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

    ASSERT_TRUE(aws_byte_buf_eq_c_str(&msg->message_data, expected));

    aws_mem_release(msg->allocator, msg);

    return AWS_OP_SUCCESS;
}

/* Pop all messages from queue and compare their contents to expected string */
static int s_check_all_messages(struct tester *tester, const char *expected) {
    struct aws_byte_buf all_msgs;
    ASSERT_SUCCESS(aws_byte_buf_init(&all_msgs, tester->alloc, 1024));

    struct aws_linked_list *msgs = testing_channel_get_written_message_queue(&tester->testing_channel);
    while (!aws_linked_list_empty(msgs)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(msgs);
        struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

        struct aws_byte_cursor msg_cursor = aws_byte_cursor_from_buf(&msg->message_data);
        aws_byte_buf_append_dynamic(&all_msgs, &msg_cursor);

        aws_mem_release(msg->allocator, msg);
    }

    ASSERT_TRUE(aws_byte_buf_eq_c_str(&all_msgs, expected));
    aws_byte_buf_clean_up(&all_msgs);
    return AWS_OP_SUCCESS;
}

/* Send 1 line request, doesn't care about response */
H1_CLIENT_TEST_CASE(h1_client_request_send_1liner) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "\r\n";
    ASSERT_SUCCESS(s_check_message(&tester, expected));

    /* clean up */
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_headers) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Host"),
            .value = aws_byte_cursor_from_c_str("example.com"),
        },
        {
            .name = aws_byte_cursor_from_c_str("Accept"),
            .value = aws_byte_cursor_from_c_str("*/*"),
        },
    };

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");
    opt.header_array = headers;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "Host: example.com\r\n"
                           "Accept: */*\r\n"
                           "\r\n";
    ASSERT_SUCCESS(s_check_message(&tester, expected));

    /* clean up */
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

struct simple_body_sender {
    struct aws_byte_cursor src;
    size_t progress;
};

enum aws_http_outgoing_body_state s_simple_send_body(
    struct aws_http_stream *stream,
    struct aws_byte_buf *buf,
    void *user_data) {

    (void)stream;
    struct simple_body_sender *data = user_data;
    size_t remaining = data->src.len - data->progress;
    size_t available = buf->capacity - buf->len;
    size_t writing = remaining < available ? remaining : available;
    aws_byte_buf_write(buf, data->src.ptr + data->progress, writing);
    data->progress += writing;

    return (writing == remaining) ? AWS_HTTP_OUTGOING_BODY_DONE : AWS_HTTP_OUTGOING_BODY_IN_PROGRESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_body) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_c_str("write more tests"),
    };

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("16"),
        },
    };

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("PUT");
    opt.uri = aws_byte_cursor_from_c_str("/plan.txt");
    opt.header_array = headers;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.user_data = &body_sender;
    opt.stream_outgoing_body = s_simple_send_body;
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Content-Length: 16\r\n"
                           "\r\n"
                           "write more tests";
    ASSERT_SUCCESS(s_check_message(&tester, expected));

    /* clean up */
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* For checking outgoing data across multiple aws_io_messages */
struct cross_message_checker {
    struct aws_byte_buf expected;
    size_t compare_progress;
};

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
            testing_channel_execute_queued_tasks(&tester->testing_channel);
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
    testing_channel_execute_queued_tasks(&tester->testing_channel);
    ASSERT_TRUE(aws_linked_list_empty(msgs));

    *out_num_messages = num_messages;
    return AWS_OP_SUCCESS;
}

/* Send a request whose body doesn't fit in a single aws_io_message */
H1_CLIENT_TEST_CASE(h1_client_request_send_large_body) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request with large body full of random data */
    size_t body_len = 1024 * 1024 * 1; /* 1MB */
    struct aws_byte_buf body_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&body_buf, allocator, body_len));
    while (body_buf.len < body_len) {
        int r = rand();
        aws_byte_buf_write_be32(&body_buf, (uint32_t)r);
    }

    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_buf(&body_buf),
    };

    char content_length_value[100];
    snprintf(content_length_value, sizeof(content_length_value), "%zu", body_len);
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str(content_length_value),
        },
    };

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("PUT");
    opt.uri = aws_byte_cursor_from_c_str("/large.txt");
    opt.header_array = headers;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.user_data = &body_sender;
    opt.stream_outgoing_body = s_simple_send_body;
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    /* check result */
    const char *expected_head_fmt = "PUT /large.txt HTTP/1.1\r\n"
                                    "Content-Length: %zu\r\n"
                                    "\r\n";
    char expected_head[1024];
    int expected_head_len = snprintf(expected_head, sizeof(expected_head), expected_head_fmt, body_len);

    struct aws_byte_buf expected_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&expected_buf, allocator, body_len + expected_head_len));
    ASSERT_TRUE(aws_byte_buf_write(&expected_buf, (uint8_t *)expected_head, expected_head_len));
    ASSERT_TRUE(aws_byte_buf_write_from_whole_buffer(&expected_buf, body_buf));

    size_t num_io_messages;
    ASSERT_SUCCESS(s_check_multiple_messages(&tester, aws_byte_cursor_from_buf(&expected_buf), &num_io_messages));

    ASSERT_TRUE(num_io_messages > 1);

    /* clean up */
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    aws_byte_buf_clean_up(&body_buf);
    aws_byte_buf_clean_up(&expected_buf);
    return AWS_OP_SUCCESS;
}

/* Send a request whose headers don't fit in a single aws_io_message */
H1_CLIENT_TEST_CASE(h1_client_request_send_large_head) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Generate headers while filling in contents of `expected` buffer */
    struct aws_http_header headers[1000];
    size_t num_headers = AWS_ARRAY_SIZE(headers);
    AWS_ZERO_STRUCT(headers);

    struct aws_byte_buf expected;
    aws_byte_buf_init(&expected, allocator, num_headers * 128); /* approx capacity */

    struct aws_byte_cursor request_line = aws_byte_cursor_from_c_str("GET / HTTP/1.1\r\n");
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

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");
    opt.header_array = headers;
    opt.num_headers = num_headers;
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    /* check result */
    size_t num_io_messages;
    ASSERT_SUCCESS(s_check_multiple_messages(&tester, aws_byte_cursor_from_buf(&expected), &num_io_messages));

    ASSERT_TRUE(num_io_messages > 1);

    /* clean up */
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    aws_byte_buf_clean_up(&expected);
    return AWS_OP_SUCCESS;
}

/* Check that as many requests as possible will be packed into each aws_io_message */
H1_CLIENT_TEST_CASE(h1_client_request_send_multiple_in_1_io_message) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send requests */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct aws_http_stream *streams[3];
    size_t num_streams = AWS_ARRAY_SIZE(streams);
    for (size_t i = 0; i < num_streams; ++i) {
        streams[i] = aws_http_stream_new_client_request(&opt);
        ASSERT_NOT_NULL(streams[i]);
    }

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "\r\n"
                           "GET / HTTP/1.1\r\n"
                           "\r\n"
                           "GET / HTTP/1.1\r\n"
                           "\r\n";
    ASSERT_SUCCESS(s_check_message(&tester, expected));

    /* clean up */
    for (size_t i = 0; i < num_streams; ++i) {
        aws_http_stream_release(streams[i]);
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

struct response_tester {
    struct aws_http_stream *stream;

    int status;
    struct aws_http_header headers[100];
    size_t num_headers;
    struct aws_byte_cursor body;

    /* All cursors in response_tester point into here */
    struct aws_byte_buf storage;

    size_t on_response_headers_cb_count;
    size_t on_response_header_block_done_cb_count;
    size_t on_response_body_cb_count;
    size_t on_complete_cb_count;

    bool has_incoming_body;
    int on_complete_error_code;

    bool stop_auto_window_update;

    /* If a specific test needs to add some custom data */
    void *specific_test_data;
};

void s_response_tester_on_headers(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)stream;
    struct response_tester *response = user_data;
    response->on_response_headers_cb_count++;

    struct aws_byte_buf *storage = &response->storage;
    const struct aws_http_header *in_header = header_array;
    struct aws_http_header *my_header = response->headers + response->num_headers;
    for (size_t i = 0; i < num_headers; ++i) {
        /* copy-by-value, then update cursors to point into permanent storage */
        *my_header = *in_header;

        my_header->name.ptr = storage->buffer + storage->len;
        AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_cursor(storage, in_header->name));

        my_header->value.ptr = storage->buffer + storage->len;
        AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_cursor(storage, in_header->value));

        in_header++;
        my_header++;
        response->num_headers++;
    }
}

void s_response_tester_on_header_block_done(struct aws_http_stream *stream, bool has_body, void *user_data) {
    (void)stream;
    struct response_tester *response = user_data;

    AWS_FATAL_ASSERT(response->on_response_header_block_done_cb_count == 0);
    response->on_response_header_block_done_cb_count++;

    response->has_incoming_body = has_body;

    AWS_FATAL_ASSERT(!aws_http_stream_get_incoming_response_status(response->stream, &response->status));
}

void s_response_tester_on_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    size_t *out_window_update_size,
    void *user_data) {

    (void)stream;
    struct response_tester *response = user_data;
    response->on_response_body_cb_count++;

    /* Header block should finish before body */
    AWS_FATAL_ASSERT(response->on_response_header_block_done_cb_count == 1);

    AWS_FATAL_ASSERT(response->has_incoming_body);

    /* Copy data into storage, and point body cursor at that */
    if (!response->body.ptr) {
        response->body.ptr = response->storage.buffer + response->storage.len;
    }
    response->body.len += data->len;

    AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_cursor(&response->storage, *data));

    /* Stop the window size from auto updating */
    if (response->stop_auto_window_update) {
        *out_window_update_size = 0;
    }
}

void s_response_tester_on_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    struct response_tester *response = user_data;
    AWS_FATAL_ASSERT(response->on_complete_cb_count == 0);
    response->on_complete_cb_count++;
    response->on_complete_error_code = error_code;

    if (error_code == AWS_ERROR_SUCCESS) {
        /* Body callback should fire if and only if the response was reported to have a body */
        AWS_FATAL_ASSERT(response->has_incoming_body == (response->on_response_body_cb_count > 0));
    }
}

/* Create request stream and hook it up so callbacks feed data to the response_tester */
int s_response_tester_init_ex(
    struct response_tester *response,
    struct aws_allocator *alloc,
    struct aws_http_request_options *opt,
    void *specific_test_data) {

    AWS_ZERO_STRUCT(*response);
    ASSERT_SUCCESS(aws_byte_buf_init(&response->storage, alloc, 1024 * 1024 * 1)); /* big enough */

    opt->user_data = response;
    opt->on_response_headers = s_response_tester_on_headers;
    opt->on_response_header_block_done = s_response_tester_on_header_block_done;
    opt->on_response_body = s_response_tester_on_body;
    opt->on_complete = s_response_tester_on_complete;

    response->specific_test_data = specific_test_data;
    response->stream = aws_http_stream_new_client_request(opt);
    ASSERT_NOT_NULL(response->stream);

    return AWS_OP_SUCCESS;
}

int s_response_tester_init(
    struct response_tester *response,
    struct aws_allocator *alloc,
    struct aws_http_request_options *opt) {

    return s_response_tester_init_ex(response, alloc, opt, NULL);
}

int s_response_tester_clean_up(struct response_tester *response) {
    aws_http_stream_release(response->stream);
    aws_byte_buf_clean_up(&response->storage);
    return AWS_OP_SUCCESS;
}

int s_send_response_ex(struct tester *tester, struct aws_byte_cursor data, bool ignore_send_message_errors) {
    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        tester->testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, data.len);
    ASSERT_NOT_NULL(msg);

    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&msg->message_data, data));

    int err = testing_channel_push_read_message(&tester->testing_channel, msg);
    if (!ignore_send_message_errors) {
        ASSERT_SUCCESS(err);
    }

    return AWS_OP_SUCCESS;
}

int s_send_response(struct tester *tester, struct aws_byte_cursor data) {
    return s_send_response_ex(tester, data, false);
}

int s_send_response_str(struct tester *tester, const char *str) {
    return s_send_response(tester, aws_byte_cursor_from_c_str(str));
}

int s_send_response_str_ignore_errors(struct tester *tester, const char *str) {
    return s_send_response_ex(tester, aws_byte_cursor_from_c_str(str), true);
}

H1_CLIENT_TEST_CASE(h1_client_response_get_1liner) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    ASSERT_SUCCESS(s_send_response_str(&tester, "HTTP/1.1 204 No Content\r\n\r\n"));

    /* check result */
    ASSERT_TRUE(response.on_complete_cb_count == 1);
    ASSERT_TRUE(response.on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(response.status == 204);
    ASSERT_TRUE(response.on_response_header_block_done_cb_count == 1);
    ASSERT_TRUE(response.num_headers == 0);
    ASSERT_TRUE(response.body.len == 0);

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

static int s_check_header(struct response_tester *response, size_t i, const char *name_str, const char *value) {

    ASSERT_TRUE(i < response->num_headers);
    struct aws_http_header *header = response->headers + i;
    ASSERT_TRUE(aws_byte_cursor_eq_c_str_ignore_case(&header->name, name_str));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str_ignore_case(&header->value, value));

    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_response_get_headers) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    ASSERT_SUCCESS(s_send_response_str(
        &tester,
        "HTTP/1.1 308 Permanent Redirect\r\n"
        "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
        "Location: /index.html\r\n"
        "\r\n"));

    /* check result */
    ASSERT_TRUE(response.on_complete_cb_count == 1);
    ASSERT_TRUE(response.on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(response.status == 308);
    ASSERT_TRUE(response.on_response_header_block_done_cb_count == 1);
    ASSERT_TRUE(response.num_headers == 2);
    ASSERT_SUCCESS(s_check_header(&response, 0, "Date", "Fri, 01 Mar 2019 17:18:55 GMT"));
    ASSERT_SUCCESS(s_check_header(&response, 1, "Location", "/index.html"));
    ASSERT_TRUE(response.body.len == 0);

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_response_get_body) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    ASSERT_SUCCESS(s_send_response_str(
        &tester,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 9\r\n"
        "\r\n"
        "Call Momo"));

    /* check result */
    ASSERT_TRUE(response.on_complete_cb_count == 1);
    ASSERT_TRUE(response.on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(response.status == 200);
    ASSERT_TRUE(response.on_response_header_block_done_cb_count == 1);
    ASSERT_TRUE(response.num_headers == 1);
    ASSERT_SUCCESS(s_check_header(&response, 0, "Content-Length", "9"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&response.body, "Call Momo"));

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Check that a response spread across multiple aws_io_messages comes through */
H1_CLIENT_TEST_CASE(h1_client_response_get_1_from_multiple_io_messages) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response with each byte in its own aws_io_message */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 9\r\n"
                               "\r\n"
                               "Call Momo";
    size_t response_str_len = strlen(response_str);
    for (size_t i = 0; i < response_str_len; ++i) {
        s_send_response(&tester, aws_byte_cursor_from_array(response_str + i, 1));
    }

    /* check result */
    ASSERT_TRUE(response.on_complete_cb_count == 1);
    ASSERT_TRUE(response.on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(response.status == 200);
    ASSERT_TRUE(response.on_response_header_block_done_cb_count == 1);
    ASSERT_TRUE(response.num_headers == 1);
    ASSERT_SUCCESS(s_check_header(&response, 0, "Content-Length", "9"));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&response.body, "Call Momo"));

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Check that multiple responses in a single aws_io_message all come through */
H1_CLIENT_TEST_CASE(h1_client_response_get_multiple_from_1_io_message) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send requests */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester responses[3];
    for (size_t i = 0; i < AWS_ARRAY_SIZE(responses); ++i) {
        ASSERT_SUCCESS(s_response_tester_init(&responses[i], allocator, &opt));

        testing_channel_execute_queued_tasks(&tester.testing_channel);
    }

    /* send all responses in a single aws_io_message  */
    ASSERT_SUCCESS(s_send_response_str(
        &tester,
        "HTTP/1.1 204 No Content\r\n\r\n"
        "HTTP/1.1 204 No Content\r\n\r\n"
        "HTTP/1.1 204 No Content\r\n\r\n"));

    /* check results */
    for (size_t i = 0; i < AWS_ARRAY_SIZE(responses); ++i) {
        ASSERT_TRUE(responses[i].on_complete_cb_count == 1);
        ASSERT_TRUE(responses[i].on_complete_error_code == AWS_ERROR_SUCCESS);
        ASSERT_TRUE(responses[i].status == 204);
        ASSERT_TRUE(responses[i].on_response_header_block_done_cb_count == 1);
        ASSERT_TRUE(responses[i].num_headers == 0);
        ASSERT_TRUE(responses[i].body.len == 0);

        ASSERT_SUCCESS(s_response_tester_clean_up(&responses[i]));
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_response_with_bad_data_shuts_down_connection) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    ASSERT_SUCCESS(s_send_response_str_ignore_errors(&tester, "Mmmm garbage data\r\n\r\n"));

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(response.on_complete_cb_count == 1);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PARSE, response.on_complete_error_code);

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test case is: 1 request has been sent. Then 2 responses arrive in 1 io message.
 * The 1st request should complete just fine, then the connection should shutdown with error */
H1_CLIENT_TEST_CASE(h1_client_response_with_too_much_data_shuts_down_connection) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send 1 request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));
    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send 2 responses in a single aws_io_message. */
    ASSERT_SUCCESS(s_send_response_ex(
        &tester,
        aws_byte_cursor_from_c_str("HTTP/1.1 204 No Content\r\n\r\n"
                                   "HTTP/1.1 204 No Content\r\n\r\n"),
        true /* ignore send errors */));

    /* 1st response should have come across successfully */
    ASSERT_TRUE(response.on_complete_cb_count == 1);
    ASSERT_TRUE(response.on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(response.status == 204);
    ASSERT_TRUE(response.on_response_header_block_done_cb_count == 1);
    ASSERT_TRUE(response.num_headers == 0);
    ASSERT_TRUE(response.body.len == 0);
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));

    /* extra data should have caused channel shutdown */
    testing_channel_execute_queued_tasks(&tester.testing_channel);
    ASSERT_TRUE(tester.is_shut_down);
    ASSERT_TRUE(tester.shutdown_error_code != AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

struct slow_body_sender {
    struct aws_byte_cursor cursor;
    size_t delay_ticks;    /* Don't send anything the first N ticks */
    size_t bytes_per_tick; /* Don't send more than N bytes per tick */
};

enum aws_http_outgoing_body_state s_slow_send_body(
    struct aws_http_stream *stream,
    struct aws_byte_buf *buf,
    void *user_data) {

    (void)stream;
    struct response_tester *response = user_data;
    struct slow_body_sender *sender = response->specific_test_data;
    size_t dst_available = buf->capacity - buf->len;
    size_t writing = 0;
    if (sender->delay_ticks > 0) {
        sender->delay_ticks--;
    } else {
        writing = sender->cursor.len;

        if (dst_available < writing) {
            writing = dst_available;
        }

        if ((sender->bytes_per_tick < writing) && (sender->bytes_per_tick > 0)) {
            writing = sender->bytes_per_tick;
        }
    }

    aws_byte_buf_write(buf, sender->cursor.ptr, writing);
    aws_byte_cursor_advance(&sender->cursor, writing);

    return (sender->cursor.len == 0) ? AWS_HTTP_OUTGOING_BODY_DONE : AWS_HTTP_OUTGOING_BODY_IN_PROGRESS;
}

/* It should be fine to receive a response before the request has finished sending */
H1_CLIENT_TEST_CASE(h1_client_response_arrives_before_request_done_sending_is_ok) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* set up request whose body won't send immediately */
    struct slow_body_sender body_sender = {
        .cursor = aws_byte_cursor_from_c_str("write more tests"),
        .delay_ticks = 5,
        .bytes_per_tick = 1,
    };

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("16"),
        },
    };

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("PUT");
    opt.uri = aws_byte_cursor_from_c_str("/plan.txt");
    opt.header_array = headers;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.stream_outgoing_body = s_slow_send_body;

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init_ex(&response, allocator, &opt, &body_sender));

    /* send head of request */
    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    ASSERT_SUCCESS(s_send_response_str(&tester, "HTTP/1.1 200 OK\r\n\r\n"));

    /* tick loop until body finishes sending.*/
    while (body_sender.cursor.len > 0) {
        testing_channel_execute_queued_tasks(&tester.testing_channel);
    }

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Content-Length: 16\r\n"
                           "\r\n"
                           "write more tests";
    ASSERT_SUCCESS(s_check_all_messages(&tester, expected));

    ASSERT_TRUE(response.on_complete_cb_count == 1);
    ASSERT_TRUE(response.on_complete_error_code == AWS_ERROR_SUCCESS);
    ASSERT_TRUE(response.status == 200);
    ASSERT_TRUE(response.on_response_header_block_done_cb_count == 1);
    ASSERT_TRUE(response.num_headers == 0);
    ASSERT_TRUE(response.body.len == 0);

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Response data arrives, but there was no outstanding request */
H1_CLIENT_TEST_CASE(h1_client_response_without_request_shuts_down_connection) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    ASSERT_SUCCESS(s_send_response_str_ignore_errors(&tester, "HTTP/1.1 200 OK\r\n\r\n"));
    testing_channel_execute_queued_tasks(&tester.testing_channel);

    ASSERT_TRUE(tester.is_shut_down);
    ASSERT_TRUE(tester.shutdown_error_code != AWS_ERROR_SUCCESS);

    /* clean up */
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* By default, after reading an aws_io_message of N bytes, the connection should issue window update of N bytes */
H1_CLIENT_TEST_CASE(h1_client_window_reopens_by_default) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 9\r\n"
                               "\r\n"
                               "Call Momo";
    ASSERT_SUCCESS(s_send_response_str(&tester, response_str));

    /* check result */
    size_t window_update = testing_channel_last_window_update(&tester.testing_channel);
    ASSERT_TRUE(window_update == strlen(response_str));

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* The user's body reading callback can prevent the window from fully re-opening. */
H1_CLIENT_TEST_CASE(h1_client_window_shrinks_if_user_says_so) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));
    response.stop_auto_window_update = true;

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 9\r\n"
                               "\r\n"
                               "Call Momo";
    ASSERT_SUCCESS(s_send_response_str(&tester, response_str));

    /* check result */
    size_t window_update = testing_channel_last_window_update(&tester.testing_channel);
    size_t message_sans_body = strlen(response_str) - 9;
    ASSERT_TRUE(window_update == message_sans_body);

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Stop window from fully re-opening, then open it manually afterwards*/
static int s_window_update(struct aws_allocator *allocator, bool on_thread) {
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");

    struct response_tester response;
    ASSERT_SUCCESS(s_response_tester_init(&response, allocator, &opt));
    response.stop_auto_window_update = true;

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 9\r\n"
                               "\r\n"
                               "Call Momo";
    ASSERT_SUCCESS(s_send_response_str(&tester, response_str));

    /* check result */
    if (!on_thread) {
        testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    }

    aws_http_stream_update_window(response.stream, 9);

    if (!on_thread) {
        testing_channel_set_is_on_users_thread(&tester.testing_channel, true);
        testing_channel_execute_queued_tasks(&tester.testing_channel);
    }

    size_t window_update = testing_channel_last_window_update(&tester.testing_channel);
    ASSERT_TRUE(window_update == 9);

    /* clean up */
    ASSERT_SUCCESS(s_response_tester_clean_up(&response));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_window_manual_update) {
    (void)ctx;
    return s_window_update(allocator, true);
}

H1_CLIENT_TEST_CASE(h1_client_window_manual_update_off_thread) {
    (void)ctx;
    return s_window_update(allocator, false);
}

void s_on_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    int *completion_error_code = user_data;
    *completion_error_code = error_code;
}

H1_CLIENT_TEST_CASE(h1_client_request_cancelled_by_channel_shutdown) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    int completion_error_code = 0;

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");
    opt.user_data = &completion_error_code;
    opt.on_complete = s_on_complete;
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* shutdown channel before request completes */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* even though the channel shut down with error_code 0,
     * the stream should not get code 0 because it did not complete successfully */
    ASSERT_TRUE(completion_error_code != AWS_ERROR_SUCCESS);

    /* clean up */
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_multiple_requests_cancelled_by_channel_shutdown) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct aws_http_stream *streams[3];
    int completion_error_codes[3];
    memset(completion_error_codes, 0, sizeof(completion_error_codes));

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");
    opt.on_complete = s_on_complete;

    for (int i = 0; i < 2; ++i) {
        opt.user_data = &completion_error_codes[i];
        streams[i] = aws_http_stream_new_client_request(&opt);
        ASSERT_NOT_NULL(streams[i]);
    }

    /* 2 streams are now in-progress */
    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* Make 1 more stream that's still locked away in the pending queue */
    opt.user_data = &completion_error_codes[2];
    streams[2] = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(streams[2]);

    /* shutdown channel */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check results */
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(completion_error_codes[i] != AWS_ERROR_SUCCESS);
        aws_http_stream_release(streams[i]);
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_new_request_fails_if_channel_shut_down) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NULL(stream);
    ASSERT_INT_EQUALS(aws_last_error(), AWS_ERROR_HTTP_CONNECTION_CLOSED);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

enum request_callback {
    REQUEST_CALLBACK_OUTGOING_BODY,
    REQUEST_CALLBACK_INCOMING_HEADERS,
    REQUEST_CALLBACK_INCOMING_HEADERS_DONE,
    REQUEST_CALLBACK_INCOMING_BODY,
    REQUEST_CALLBACK_COMPLETE,
    REQUEST_CALLBACK_COUNT,
};

struct close_from_callback_tester {
    enum request_callback close_at;
    int callback_counts[REQUEST_CALLBACK_COUNT];
    bool is_closed;
};

void s_close_from_callback_common(
    struct aws_http_stream *stream,
    struct close_from_callback_tester *close_tester,
    enum request_callback current_callback) {

    close_tester->callback_counts[current_callback]++;

    /* After connection closed, no more callbacks should fire (except for on_complete) */
    if (current_callback == REQUEST_CALLBACK_COMPLETE) {
        if (close_tester->close_at < REQUEST_CALLBACK_COMPLETE) {
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

enum aws_http_outgoing_body_state s_close_from_outgoing_body(
    struct aws_http_stream *stream,
    struct aws_byte_buf *buf,
    void *user_data) {

    (void)buf;
    s_close_from_callback_common(stream, user_data, REQUEST_CALLBACK_OUTGOING_BODY);

    /* If we're closing from this function, try and keep going. It's a failure if we're invoked again. */
    struct close_from_callback_tester *close_tester = user_data;
    if (close_tester->close_at == REQUEST_CALLBACK_OUTGOING_BODY) {
        return AWS_HTTP_OUTGOING_BODY_IN_PROGRESS;
    } else {
        return AWS_HTTP_OUTGOING_BODY_DONE;
    }
}

void s_close_from_incoming_headers(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)header_array;
    (void)num_headers;
    s_close_from_callback_common(stream, user_data, REQUEST_CALLBACK_INCOMING_HEADERS);
}

void s_close_from_incoming_headers_done(struct aws_http_stream *stream, bool has_body, void *user_data) {
    (void)has_body;
    s_close_from_callback_common(stream, user_data, REQUEST_CALLBACK_INCOMING_HEADERS_DONE);
}

void s_close_from_incoming_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    /* NOLINTNEXTLINE(readability-non-const-parameter) */
    size_t *out_window_update_size,
    void *user_data) {

    (void)data;
    (void)out_window_update_size;
    s_close_from_callback_common(stream, user_data, REQUEST_CALLBACK_INCOMING_BODY);
}

void s_close_from_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)error_code;
    s_close_from_callback_common(stream, user_data, REQUEST_CALLBACK_COMPLETE);
}

int s_test_close_from_callback(struct aws_allocator *allocator, enum request_callback close_at) {
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    testing_channel_execute_queued_tasks(&tester.testing_channel);

    struct close_from_callback_tester close_tester = {
        .close_at = close_at,
    };

    /* send request */
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("999"),
        },
    };

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method = aws_byte_cursor_from_c_str("POST");
    opt.uri = aws_byte_cursor_from_c_str("/");
    opt.header_array = headers;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.stream_outgoing_body = s_close_from_outgoing_body;
    opt.on_response_headers = s_close_from_incoming_headers;
    opt.on_response_header_block_done = s_close_from_incoming_headers_done;
    opt.on_response_body = s_close_from_incoming_body;
    opt.on_complete = s_close_from_stream_complete;
    opt.user_data = &close_tester;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* send response */
    ASSERT_SUCCESS(s_send_response_str_ignore_errors(
        &tester,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
        "\r\n"
        "3\r\n"
        "two\r\n"
        "6\r\n"
        "chunks\r\n"
        "0\r\n"
        "\r\n"));

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check that callbacks were invoked before close_at, but not after */
    for (int i = 0; i < REQUEST_CALLBACK_COMPLETE; ++i) {
        if (i <= close_at) {
            ASSERT_TRUE(close_tester.callback_counts[i] > 0);
        } else {
            ASSERT_INT_EQUALS(0, close_tester.callback_counts[i]);
        }
    }

    /* the on_complete callback should always fire though */
    ASSERT_INT_EQUALS(1, close_tester.callback_counts[REQUEST_CALLBACK_COMPLETE]);

    aws_http_stream_release(stream);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_close_from_outgoing_body_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_CALLBACK_OUTGOING_BODY));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_close_from_incoming_headers_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_CALLBACK_INCOMING_HEADERS));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_close_from_incoming_headers_done_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_CALLBACK_INCOMING_HEADERS_DONE));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_close_from_incoming_body_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_CALLBACK_INCOMING_BODY));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_close_from_stream_complete_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_close_from_callback(allocator, REQUEST_CALLBACK_COMPLETE));
    return AWS_OP_SUCCESS;
}

/* After aws_http_connection_close() is called, aws_http_connection_is_open() should return false,
 * even if both calls were made from outside the event-loop thread. */
H1_CLIENT_TEST_CASE(h1_client_close_from_off_thread_makes_not_open) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);

    ASSERT_TRUE(aws_http_connection_is_open(tester.connection));
    aws_http_connection_close(tester.connection);
    ASSERT_FALSE(aws_http_connection_is_open(tester.connection));

    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_close_from_on_thread_makes_not_open) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    ASSERT_TRUE(aws_http_connection_is_open(tester.connection));

    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);
    aws_http_connection_close(tester.connection);

    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    ASSERT_FALSE(aws_http_connection_is_open(tester.connection));

    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
