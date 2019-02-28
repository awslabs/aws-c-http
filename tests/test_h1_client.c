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
#include <aws/testing/io_testing_channel.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define H1_CLIENT_TEST_CASE(NAME)                                                                                      \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx);                                              \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct tester {
    struct aws_allocator *alloc;
    struct testing_channel testing_channel;
    struct aws_http_connection *connection;
};

static int s_tester_init(struct tester *tester, struct aws_allocator *alloc) {
    AWS_ZERO_STRUCT(*tester);

    tester->alloc = alloc;
    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc));

    struct aws_http_client_connection_impl_options options = {
        .alloc = alloc,
        .initial_window_size = SIZE_MAX,
        .user_data = tester,
    };
    tester->connection = aws_http_connection_new_http1_1_client(&options);
    ASSERT_NOT_NULL(tester->connection);

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    tester->connection->channel_slot = slot;
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &tester->connection->channel_handler));

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    ASSERT_SUCCESS(testing_channel_clean_up(&tester->testing_channel));
    return AWS_OP_SUCCESS;
}

/* Check that we can set and tear down the `tester` used by all other tests in this file */
H1_CLIENT_TEST_CASE(h1_client_sanity_check) {
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

    struct aws_byte_cursor expected_cur = aws_byte_cursor_from_c_str(expected);
    ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&expected_cur, &msg->message_data));

    aws_mem_release(msg->allocator, msg);

    return AWS_OP_SUCCESS;
}

/* Send 1 line request, doesn't care about response */
H1_CLIENT_TEST_CASE(h1_client_request_send_1liner) {
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method_str = aws_byte_cursor_from_c_str("GET");
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
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_header headers[] = {
        {
            .name = AWS_HTTP_HEADER_HOST,
            .value = aws_byte_cursor_from_c_str("example.com"),
        },
        {
            .name_str = aws_byte_cursor_from_c_str("Accept"),
            .value = aws_byte_cursor_from_c_str("*/*"),
        },
    };

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method_str = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");
    opt.header_array = headers;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "HOST: example.com\r\n"
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

enum aws_http_body_sender_state s_simple_body_sender(
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

    return (writing == remaining) ? AWS_HTTP_BODY_SENDER_DONE : AWS_HTTP_BODY_SENDER_IN_PROGRESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_body) {
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct simple_body_sender body_sender = {
        .src = aws_byte_cursor_from_c_str("write more tests"),
    };

    struct aws_http_header headers[] = {
        {
            .name_str = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("16"),
        },
    };

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method_str = aws_byte_cursor_from_c_str("PUT");
    opt.uri = aws_byte_cursor_from_c_str("/todo.txt");
    opt.header_array = headers;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.user_data = &body_sender;
    opt.body_sender = s_simple_body_sender;
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "PUT /todo.txt HTTP/1.1\r\n"
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
    sprintf(content_length_value, "%zu", body_len);
    struct aws_http_header headers[] = {
        {
            .name_str = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str(content_length_value),
        },
    };

    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method_str = aws_byte_cursor_from_c_str("PUT");
    opt.uri = aws_byte_cursor_from_c_str("/large.txt");
    opt.header_array = headers;
    opt.num_headers = AWS_ARRAY_SIZE(headers);
    opt.user_data = &body_sender;
    opt.body_sender = s_simple_body_sender;
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    /* check result */
    const char *expected_head_fmt = "PUT /large.txt HTTP/1.1\r\n"
                                    "Content-Length: %zu\r\n"
                                    "\r\n";
    char expected_head[1024];
    int expected_head_len = sprintf(expected_head, expected_head_fmt, body_len);

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
        header->name_str = aws_byte_cursor_from_array(expected.buffer + expected.len, AWS_UUID_STR_LEN - 1);
        header->value = header->name_str;

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
    opt.method_str = aws_byte_cursor_from_c_str("GET");
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
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send requests */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method_str = aws_byte_cursor_from_c_str("GET");
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

/* Tests TODO
-   On/Off thread behavior
    -   new items in pending_request_list while still processing those in requst_list?
-   Responses
    -   Responses finishing before request done sending
    -   Multiple responses in 1 io_msg
    -   Window update stuff
    -   bad data
        -   data comes in but no incoming_stream
        -   invalid data freaks out the decoder
-   Completion callbacks
-   Shutdown scenarios
    -   data coming in after shutdown is ignored and cleaned
*/
