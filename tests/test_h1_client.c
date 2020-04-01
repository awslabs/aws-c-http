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

#include "stream_test_helper.h"
#include <aws/common/uuid.h>
#include <aws/http/private/h1_connection.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/logging.h>
#include <aws/io/stream.h>
#include <aws/testing/io_testing_channel.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define H1_CLIENT_TEST_CASE(NAME)                                                                                      \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

static struct aws_http_message *s_new_default_get_request(struct aws_allocator *allocator) {
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    AWS_FATAL_ASSERT(request);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_method(request, aws_http_method_get));
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));

    return request;
}

static struct aws_http_message *s_new_default_head_request(struct aws_allocator *allocator) {
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    AWS_FATAL_ASSERT(request);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_method(request, aws_http_method_head));
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));

    return request;
}

struct tester {
    struct aws_allocator *alloc;
    struct testing_channel testing_channel;
    struct aws_http_connection *connection;
    struct aws_logger logger;
    bool manual_window_management;
};

static int s_tester_init(struct tester *tester, struct aws_allocator *alloc) {
    aws_http_library_init(alloc);

    AWS_ZERO_STRUCT(*tester);

    tester->alloc = alloc;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    struct aws_testing_channel_options test_channel_options = {.clock_fn = aws_high_res_clock_get_ticks};
    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc, &test_channel_options));

    /* Use small window so that we can observe it opening in tests.
     * Channel may wait until the window is small before issuing the increment command. */
    tester->connection = aws_http_connection_new_http1_1_client(alloc, true, 256);
    ASSERT_NOT_NULL(tester->connection);

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &tester->connection->channel_handler));
    tester->connection->vtable->on_channel_handler_installed(&tester->connection->channel_handler, slot);

    testing_channel_drain_queued_tasks(&tester->testing_channel);

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

/* Send 1 line request, doesn't care about response */
H1_CLIENT_TEST_CASE(h1_client_request_send_1liner) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = s_new_default_get_request(allocator),
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_message_str(&tester.testing_channel, expected));

    /* clean up */
    aws_http_message_destroy(opt.request);
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
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("example.com"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Accept"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("*/*"),
        },
    };

    struct aws_http_message *request = s_new_default_get_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "Host: example.com\r\n"
                           "Accept: */*\r\n"
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_message_str(&tester.testing_channel, expected));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_body) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("16"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/plan.txt")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));
    aws_http_message_set_body_stream(request, body_stream);

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Content-Length: 16\r\n"
                           "\r\n"
                           "write more tests";
    ASSERT_SUCCESS(testing_channel_check_written_message_str(&tester.testing_channel, expected));

    /* clean up */
    aws_input_stream_destroy(body_stream);
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_content_length_0_ok) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request with Content-Length: 0 and NO body stream */
    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("0"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/plan.txt")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Content-Length: 0\r\n"
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_message_str(&tester.testing_channel, expected));
    aws_http_stream_release(stream);

    /* send Content-Length: 0 request again, but this time with a body stream whose length is 0 */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);
    aws_http_message_set_body_stream(request, body_stream);

    stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_SUCCESS(testing_channel_check_written_message_str(&tester.testing_channel, expected));

    /* clean up */
    aws_input_stream_destroy(body_stream);
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
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

    const struct aws_byte_cursor body = aws_byte_cursor_from_buf(&body_buf);
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);

    char content_length_value[100];
    snprintf(content_length_value, sizeof(content_length_value), "%zu", body_len);
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str(content_length_value),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/large.txt")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));
    aws_http_message_set_body_stream(request, body_stream);

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

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

    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_SUCCESS(testing_channel_check_written_messages(
        &tester.testing_channel, allocator, aws_byte_cursor_from_buf(&expected_buf)));

    /* clean up */
    aws_input_stream_destroy(body_stream);
    aws_http_message_destroy(request);
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

    struct aws_http_message *request = s_new_default_get_request(allocator);
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));

    /* send request */
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    /* check result */
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_SUCCESS(testing_channel_check_written_messages(
        &tester.testing_channel, allocator, aws_byte_cursor_from_buf(&expected)));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    aws_byte_buf_clean_up(&expected);
    return AWS_OP_SUCCESS;
}

/* Check that if many requests are made (pipelining) they all get sent */
H1_CLIENT_TEST_CASE(h1_client_request_send_multiple) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send requests */
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = s_new_default_get_request(allocator),
    };

    struct aws_http_stream *streams[3];
    size_t num_streams = AWS_ARRAY_SIZE(streams);
    for (size_t i = 0; i < num_streams; ++i) {
        streams[i] = aws_http_connection_make_request(tester.connection, &opt);
        ASSERT_NOT_NULL(streams[i]);
        aws_http_stream_activate(streams[i]);
    }

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(opt.request);

    /* check result */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "\r\n"
                           "GET / HTTP/1.1\r\n"
                           "\r\n"
                           "GET / HTTP/1.1\r\n"
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    for (size_t i = 0; i < num_streams; ++i) {
        aws_http_stream_release(streams[i]);
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

static int s_stream_tester_init(
    struct client_stream_tester *tester,
    struct tester *master_tester,
    struct aws_http_message *request) {

    struct client_stream_tester_options options = {
        .request = request,
        .connection = master_tester->connection,
    };
    return client_stream_tester_init(tester, master_tester->alloc, &options);
}

H1_CLIENT_TEST_CASE(h1_client_response_get_1liner) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, "HTTP/1.1 204 No Content\r\n\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(204, stream_tester.response_status);
    ASSERT_UINT_EQUALS(0, aws_http_headers_count(stream_tester.response_headers));
    ASSERT_UINT_EQUALS(0, stream_tester.response_body.len);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

static int s_check_header(const struct aws_http_headers *headers, size_t i, const char *name_str, const char *value) {

    size_t headers_num = aws_http_headers_count(headers);
    ASSERT_TRUE(i < headers_num);
    struct aws_http_header header;
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, i, &header));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&header.name, name_str));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&header.value, value));

    return AWS_OP_SUCCESS;
}

static int s_check_info_response_header(
    const struct client_stream_tester *stream_tester,
    size_t response_i,
    size_t header_i,
    const char *name_str,
    const char *value) {

    ASSERT_TRUE(response_i < stream_tester->num_info_responses);
    const struct aws_http_headers *headers =
        aws_http_message_get_const_headers(stream_tester->info_responses[response_i]);
    return s_check_header(headers, header_i, name_str, value);
}

H1_CLIENT_TEST_CASE(h1_client_response_get_headers) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 308 Permanent Redirect\r\n"
        "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
        "Location: /index.html\r\n"
        "\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(308, stream_tester.response_status);
    ASSERT_UINT_EQUALS(2, aws_http_headers_count(stream_tester.response_headers));
    ASSERT_SUCCESS(s_check_header(stream_tester.response_headers, 0, "Date", "Fri, 01 Mar 2019 17:18:55 GMT"));
    ASSERT_SUCCESS(s_check_header(stream_tester.response_headers, 1, "Location", "/index.html"));
    ASSERT_UINT_EQUALS(0, stream_tester.response_body.len);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_response_get_body) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 9\r\n"
        "\r\n"
        "Call Momo"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(stream_tester.response_headers));
    ASSERT_SUCCESS(s_check_header(stream_tester.response_headers, 0, "Content-Length", "9"));
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&stream_tester.response_body, "Call Momo"));

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

static int s_test_expected_no_body_response(struct aws_allocator *allocator, int status_int, bool head_request) {

    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request =
        head_request ? s_new_default_head_request(allocator) : s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* form response */
    struct aws_byte_cursor status_text = aws_byte_cursor_from_c_str(aws_http_status_text(status_int));
    char c_status_text[100];
    memcpy(c_status_text, status_text.ptr, status_text.len);
    c_status_text[status_text.len] = '\0';
    char response_text[500];
    char *response_headers = "Content-Length: 9\r\n"
                             "\r\n";
    snprintf(response_text, sizeof(response_text), "HTTP/1.1 %d %s\r\n%s", status_int, c_status_text, response_headers);
    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, response_text));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(status_int, stream_tester.response_status);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(stream_tester.response_headers));
    ASSERT_SUCCESS(s_check_header(stream_tester.response_headers, 0, "Content-Length", "9"));

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_response_get_no_body_for_head_request) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_expected_no_body_response(allocator, 200, true));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_response_get_no_body_from_304) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_expected_no_body_response(allocator, 304, false));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_response_get_100) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 100 Continue\r\n"
        "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
        "\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 9\r\n"
        "\r\n"
        "Call Momo"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);

    ASSERT_UINT_EQUALS(1, stream_tester.num_info_responses);
    int info_response_status;
    ASSERT_SUCCESS(aws_http_message_get_response_status(stream_tester.info_responses[0], &info_response_status));
    ASSERT_INT_EQUALS(100, info_response_status);
    ASSERT_SUCCESS(s_check_info_response_header(&stream_tester, 0, 0, "Date", "Fri, 01 Mar 2019 17:18:55 GMT"));
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(stream_tester.response_headers));
    ASSERT_SUCCESS(s_check_header(stream_tester.response_headers, 0, "Content-Length", "9"));

    ASSERT_TRUE(aws_byte_buf_eq_c_str(&stream_tester.response_body, "Call Momo"));

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Check that a response spread across multiple aws_io_messages comes through */
H1_CLIENT_TEST_CASE(h1_client_response_get_1_from_multiple_io_messages) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response with each byte in its own aws_io_message */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 9\r\n"
                               "\r\n"
                               "Call Momo";
    size_t response_str_len = strlen(response_str);
    for (size_t i = 0; i < response_str_len; ++i) {
        ASSERT_SUCCESS(
            testing_channel_push_read_data(&tester.testing_channel, aws_byte_cursor_from_array(response_str + i, 1)));
    }

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(stream_tester.response_headers));
    ASSERT_SUCCESS(s_check_header(stream_tester.response_headers, 0, "Content-Length", "9"));
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&stream_tester.response_body, "Call Momo"));

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Check that multiple responses in a single aws_io_message all come through */
H1_CLIENT_TEST_CASE(h1_client_response_get_multiple_from_1_io_message) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send requests */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_testers[3];
    for (size_t i = 0; i < AWS_ARRAY_SIZE(stream_testers); ++i) {
        ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[i], &tester, request));
    }
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send all responses in a single aws_io_message  */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 204 No Content\r\n\r\n"
        "HTTP/1.1 204 No Content\r\n\r\n"
        "HTTP/1.1 204 No Content\r\n\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check results */
    for (size_t i = 0; i < AWS_ARRAY_SIZE(stream_testers); ++i) {
        ASSERT_TRUE(stream_testers[i].complete);
        ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_testers[i].on_complete_error_code);
        ASSERT_INT_EQUALS(204, stream_testers[i].response_status);
        ASSERT_UINT_EQUALS(0, aws_http_headers_count(stream_testers[i].response_headers));
        ASSERT_UINT_EQUALS(0, stream_testers[i].response_body.len);

        client_stream_tester_clean_up(&stream_testers[i]);
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_response_with_bad_data_shuts_down_connection) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str_ignore_errors(&tester.testing_channel, "Mmmm garbage data\r\n\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
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
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send 2 responses in a single aws_io_message. */
    ASSERT_SUCCESS(testing_channel_push_read_str_ignore_errors(
        &tester.testing_channel,
        "HTTP/1.1 204 No Content\r\n\r\n"
        "HTTP/1.1 204 No Content\r\n\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* 1st response should have come across successfully */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(204, stream_tester.response_status);
    ASSERT_UINT_EQUALS(0, aws_http_headers_count(stream_tester.response_headers));
    ASSERT_UINT_EQUALS(0, stream_tester.response_body.len);
    client_stream_tester_clean_up(&stream_tester);

    /* extra data should have caused channel shutdown */
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));
    ASSERT_TRUE(testing_channel_get_shutdown_error_code(&tester.testing_channel) != AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

struct slow_body_sender {
    struct aws_stream_status status;
    struct aws_byte_cursor cursor;
    size_t delay_ticks;    /* Don't send anything the first N ticks */
    size_t bytes_per_tick; /* Don't send more than N bytes per tick */
};

int s_slow_stream_read(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    struct slow_body_sender *sender = stream->impl;

    size_t dst_available = dest->capacity - dest->len;
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

    aws_byte_buf_write(dest, sender->cursor.ptr, writing);
    aws_byte_cursor_advance(&sender->cursor, writing);

    if (sender->cursor.len == 0) {
        sender->status.is_end_of_stream = true;
    }

    return AWS_OP_SUCCESS;
}
int s_slow_stream_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    struct slow_body_sender *sender = stream->impl;
    *status = sender->status;
    return AWS_OP_SUCCESS;
}
int s_slow_stream_get_length(struct aws_input_stream *stream, int64_t *out_length) {
    struct slow_body_sender *sender = stream->impl;
    *out_length = sender->cursor.len;
    return AWS_OP_SUCCESS;
}
void s_slow_stream_destroy(struct aws_input_stream *stream) {
    aws_mem_release(stream->allocator, stream);
}

static struct aws_input_stream_vtable s_slow_stream_vtable = {
    .seek = NULL,
    .read = s_slow_stream_read,
    .get_status = s_slow_stream_get_status,
    .get_length = s_slow_stream_get_length,
    .destroy = s_slow_stream_destroy,
};

/* It should be fine to receive a response before the request has finished sending */
H1_CLIENT_TEST_CASE(h1_client_response_arrives_before_request_done_sending_is_ok) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* set up request whose body won't send immediately */
    struct slow_body_sender body_sender = {
        .status =
            {
                .is_end_of_stream = false,
                .is_valid = true,
            },
        .cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests"),
        .delay_ticks = 5,
        .bytes_per_tick = 1,
    };
    struct aws_input_stream body_stream = {
        .allocator = allocator,
        .impl = &body_sender,
        .vtable = &s_slow_stream_vtable,
    };

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("16"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/plan.txt")));
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));
    aws_http_message_set_body_stream(request, &body_stream);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    /* send head of request */
    testing_channel_run_currently_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, "HTTP/1.1 200 OK\r\n\r\n"));

    /* tick loop until body finishes sending.*/
    while (body_sender.cursor.len > 0) {
        /* on_complete shouldn't fire until all outgoing data sent AND all incoming data received */
        ASSERT_FALSE(stream_tester.complete);

        testing_channel_run_currently_queued_tasks(&tester.testing_channel);
    }

    /* flush any further work so that stream completes */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Content-Length: 16\r\n"
                           "\r\n"
                           "write more tests";
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_UINT_EQUALS(0, aws_http_headers_count(stream_tester.response_headers));
    ASSERT_UINT_EQUALS(0, stream_tester.response_body.len);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Response data arrives, but there was no outstanding request */
H1_CLIENT_TEST_CASE(h1_client_response_without_request_shuts_down_connection) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    ASSERT_SUCCESS(testing_channel_push_read_str_ignore_errors(&tester.testing_channel, "HTTP/1.1 200 OK\r\n\r\n"));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));
    ASSERT_TRUE(testing_channel_get_shutdown_error_code(&tester.testing_channel) != AWS_ERROR_SUCCESS);

    /* clean up */
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* A response with the "Connection: close" header should result in the connection shutting down
 * after the stream completes. */
H1_CLIENT_TEST_CASE(h1_client_response_close_header_ends_connection) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 200 OK\r\n"
        "Connection: close\r\n"
        "\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Response should come across successfully
     * but connection should be closing when the stream-complete callback fires */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_FALSE(stream_tester.on_complete_connection_is_open);

    /* Connection should have shut down cleanly after delivering response */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, testing_channel_get_shutdown_error_code(&tester.testing_channel));

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* A request with the "Connection: close" header should result in the connection shutting down
 * after the stream completes. */
H1_CLIENT_TEST_CASE(h1_client_request_close_header_ends_connection) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Request has "Connection: close" header */
    struct aws_http_message *request = s_new_default_get_request(allocator);
    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("example.com"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Connection"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("close"),
        },
    };
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));

    /* Set up response tester, which sends the request as a side-effect */
    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Check that request was sent */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "Host: example.com\r\n"
                           "Connection: close\r\n"
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_message_str(&tester.testing_channel, expected));

    /* Connection shouldn't be "open" at this point, but it also shouldn't shut down until response is received */
    ASSERT_FALSE(aws_http_connection_is_open(tester.connection));
    ASSERT_FALSE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    /* Send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 200 OK\r\n"
        "\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Response should come across successfully */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_FALSE(stream_tester.on_complete_connection_is_open);

    /* Connection should have shut down cleanly after delivering response */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, testing_channel_get_shutdown_error_code(&tester.testing_channel));

    /* clean up */
    aws_http_message_destroy(request);
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* While pipelining 3 requests, and 2nd response has a "Connection: close" header.
 * 2 requests should complete successfully and the connection should close. */
H1_CLIENT_TEST_CASE(h1_client_response_close_header_with_pipelining) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Send 3 requests before receiving any responses */
    enum { NUM_STREAMS = 3 };
    struct aws_http_message *requests[NUM_STREAMS];
    struct client_stream_tester stream_testers[NUM_STREAMS];
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        requests[i] = s_new_default_get_request(allocator);
        ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[i], &tester, requests[i]));
    };

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Send "Connection: close" header in 2nd response.
     * Do not send 3rd response. */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        /* Response 1 */
        "HTTP/1.1 200 OK\r\n"
        "\r\n"
        /* Response 2 */
        "HTTP/1.1 200 OK\r\n"
        "Connection: close\r\n"
        "\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    { /* First stream should be successful, and connection should be open when it completes */
        const struct client_stream_tester *first = &stream_testers[0];
        ASSERT_TRUE(first->complete);
        ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, first->on_complete_error_code);
        ASSERT_INT_EQUALS(200, first->response_status);
        ASSERT_TRUE(first->on_complete_connection_is_open);
    }

    { /* Second stream should be successful, BUT connection should NOT be open when it completes */
        const struct client_stream_tester *second = &stream_testers[1];
        ASSERT_TRUE(second->complete);
        ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, second->on_complete_error_code);
        ASSERT_INT_EQUALS(200, second->response_status);
        ASSERT_FALSE(second->on_complete_connection_is_open);
    }

    { /* Third stream should complete with error, since connection should close after 2nd stream completes. */
        const struct client_stream_tester *third = &stream_testers[2];
        ASSERT_TRUE(third->complete);
        ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, third->on_complete_error_code);
        ASSERT_FALSE(third->on_complete_connection_is_open);
    }

    /* Connection should have shut down after delivering response.
     * Not going to check error_code because it's pretty ambiguous what it ought to be in this circumstance */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    /* clean up */
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        aws_http_message_destroy(requests[i]);
        client_stream_tester_clean_up(&stream_testers[i]);
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* While pipelining 3 requests, and 2nd request has a "Connection: close" header.
 * 2 requests should complete successfully and the connection should close. */
H1_CLIENT_TEST_CASE(h1_client_request_close_header_with_pipelining) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Queue up 3 requests, where the middle request has a "Connection: close" header */
    enum { NUM_STREAMS = 3 };
    struct aws_http_message *requests[NUM_STREAMS];
    struct client_stream_tester stream_testers[NUM_STREAMS];
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        requests[i] = s_new_default_get_request(allocator);

        if (i == 1) {
            struct aws_http_header close_header = {
                .name = aws_byte_cursor_from_c_str("Connection"),
                .value = aws_byte_cursor_from_c_str("close"),
            };
            ASSERT_SUCCESS(aws_http_message_add_header(requests[i], close_header));
        }

        /* Response tester sends requests as a side-effect */
        ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[i], &tester, requests[i]));
    };

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Check that ONLY first 2 requests were sent */
    const char *expected = "GET / HTTP/1.1\r\n"
                           "\r\n"
                           "GET / HTTP/1.1\r\n"
                           "Connection: close\r\n"
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* Send 2 responses. */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        /* Response 1 */
        "HTTP/1.1 200 OK\r\n"
        "\r\n"
        /* Response 2 */
        "HTTP/1.1 200 OK\r\n"
        "\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    { /* First stream should be successful */
        const struct client_stream_tester *first = &stream_testers[0];
        ASSERT_TRUE(first->complete);
        ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, first->on_complete_error_code);
        ASSERT_INT_EQUALS(200, first->response_status);
    }

    { /* Second stream should be successful */
        const struct client_stream_tester *second = &stream_testers[1];
        ASSERT_TRUE(second->complete);
        ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, second->on_complete_error_code);
        ASSERT_INT_EQUALS(200, second->response_status);
    }

    { /* Third stream should complete with error, since connection should close after 2nd stream completes. */
        const struct client_stream_tester *third = &stream_testers[2];
        ASSERT_TRUE(third->complete);
        ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, third->on_complete_error_code);
    }

    /* Connection should have shut down after delivering second response.
     * Not going to check error_code because it's pretty ambiguous what it ought to be in this circumstance */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    /* clean up */
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        aws_http_message_destroy(requests[i]);
        client_stream_tester_clean_up(&stream_testers[i]);
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* The user's body reading callback can prevent the window from fully re-opening. */
H1_CLIENT_TEST_CASE(h1_client_window_shrinks_if_user_says_so) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 9\r\n"
                               "\r\n"
                               "Call Momo";
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, response_str));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    size_t window_update = testing_channel_last_window_update(&tester.testing_channel);
    size_t message_sans_body = strlen(response_str) - 9;
    ASSERT_UINT_EQUALS(message_sans_body, window_update);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Stop window from fully re-opening, then open it manually afterwards*/
static int s_window_update(struct aws_allocator *allocator, bool on_thread) {
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 9\r\n"
                               "\r\n"
                               "Call Momo";
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, response_str));

    /* drain the task queue, in case there's an update window task in there from the headers */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    if (!on_thread) {
        testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    }

    aws_http_stream_update_window(stream_tester.stream, 9);

    if (!on_thread) {
        testing_channel_set_is_on_users_thread(&tester.testing_channel, true);
    }

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    size_t window_update = testing_channel_last_window_update(&tester.testing_channel);
    ASSERT_INT_EQUALS(9, window_update);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
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

static void s_on_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    int *completion_error_code = user_data;
    *completion_error_code = error_code;
}

static int s_test_content_length_mismatch_is_error(
    struct aws_allocator *allocator,
    const char *body,
    const char *wrong_length) {

    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request whose Content-Length does not match body length */
    const struct aws_byte_cursor body_cur = aws_byte_cursor_from_c_str(body);
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body_cur);

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
            .value = aws_byte_cursor_from_c_str(wrong_length),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/plan.txt")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));
    aws_http_message_set_body_stream(request, body_stream);

    int completion_error_code = 0;

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
        .on_complete = s_on_complete,
        .user_data = &completion_error_code,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT, completion_error_code);

    /* clean up */
    aws_input_stream_destroy(body_stream);
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_content_length_too_small_is_error) {
    (void)ctx;
    return s_test_content_length_mismatch_is_error(allocator, "I am very long", "1");
}

H1_CLIENT_TEST_CASE(h1_client_request_content_length_too_large_is_error) {
    (void)ctx;
    return s_test_content_length_mismatch_is_error(allocator, "I am very short", "999");
}

H1_CLIENT_TEST_CASE(h1_client_request_cancelled_by_channel_shutdown) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    int completion_error_code = 0;

    /* send request */
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = s_new_default_get_request(allocator),
        .user_data = &completion_error_code,
        .on_complete = s_on_complete,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(opt.request);

    /* shutdown channel before request completes */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

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

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = s_new_default_get_request(allocator),
        .on_complete = s_on_complete,
    };

    for (int i = 0; i < 2; ++i) {
        opt.user_data = &completion_error_codes[i];
        streams[i] = aws_http_connection_make_request(tester.connection, &opt);
        ASSERT_NOT_NULL(streams[i]);
        aws_http_stream_activate(streams[i]);
    }

    /* 2 streams are now in-progress */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Make 1 more stream that's still locked away in the pending queue */
    opt.user_data = &completion_error_codes[2];
    streams[2] = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(streams[2]);
    aws_http_stream_activate(streams[2]);

    /* shutdown channel */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(opt.request);

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
    /* wait for shutdown complete */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* send request */
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = s_new_default_get_request(allocator),
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NULL(stream);

    ASSERT_INT_EQUALS(aws_last_error(), AWS_ERROR_HTTP_CONNECTION_CLOSED);

    aws_http_message_destroy(opt.request);
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

static const int ERROR_FROM_CALLBACK_ERROR_CODE = (int)0xBEEFCAFE;

struct error_from_callback_tester {
    enum request_callback error_at;
    int callback_counts[REQUEST_CALLBACK_COUNT];
    bool has_errored;
    struct aws_stream_status status;
    int on_complete_error_code;
};

static int s_error_from_callback_common(
    struct error_from_callback_tester *error_tester,
    enum request_callback current_callback) {

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

    struct error_from_callback_tester *error_tester = body->impl;
    ASSERT_SUCCESS(s_error_from_callback_common(error_tester, REQUEST_CALLBACK_OUTGOING_BODY));

    /* If the common fn was successful, write out some data and end the stream */
    ASSERT_TRUE(aws_byte_buf_write(dest, (const uint8_t *)"abcd", 4));
    error_tester->status.is_end_of_stream = true;
    return AWS_OP_SUCCESS;
}

static int s_error_from_outgoing_body_get_status(struct aws_input_stream *body, struct aws_stream_status *status) {
    struct error_from_callback_tester *error_tester = body->impl;
    *status = error_tester->status;
    return AWS_OP_SUCCESS;
}

static void s_error_from_outgoing_body_destroy(struct aws_input_stream *stream) {
    aws_mem_release(stream->allocator, stream);
}

static struct aws_input_stream_vtable s_error_from_outgoing_body_vtable = {
    .seek = NULL,
    .read = s_error_from_outgoing_body_read,
    .get_status = s_error_from_outgoing_body_get_status,
    .get_length = NULL,
    .destroy = s_error_from_outgoing_body_destroy,
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
    return s_error_from_callback_common(user_data, REQUEST_CALLBACK_INCOMING_HEADERS);
}

static int s_error_from_incoming_headers_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    (void)stream;
    (void)header_block;
    return s_error_from_callback_common(user_data, REQUEST_CALLBACK_INCOMING_HEADERS_DONE);
}

static int s_error_from_incoming_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;
    (void)data;
    return s_error_from_callback_common(user_data, REQUEST_CALLBACK_INCOMING_BODY);
}

static void s_error_tester_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    struct error_from_callback_tester *error_tester = user_data;
    error_tester->callback_counts[REQUEST_CALLBACK_COMPLETE]++;
    error_tester->on_complete_error_code = error_code;
}

static int s_test_error_from_callback(struct aws_allocator *allocator, enum request_callback error_at) {
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct error_from_callback_tester error_tester = {
        .error_at = error_at,
        .status =
            {
                .is_valid = true,
                .is_end_of_stream = false,
            },
    };
    struct aws_input_stream error_from_outgoing_body_stream = {
        .allocator = allocator,
        .impl = &error_tester,
        .vtable = &s_error_from_outgoing_body_vtable,
    };

    /* send request */
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Content-Length"),
            .value = aws_byte_cursor_from_c_str("4"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_http_method_post));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));
    aws_http_message_set_body_stream(request, &error_from_outgoing_body_stream);

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
        .on_response_headers = s_error_from_incoming_headers,
        .on_response_header_block_done = s_error_from_incoming_headers_done,
        .on_response_body = s_error_from_incoming_body,
        .on_complete = s_error_tester_on_stream_complete,
        .user_data = &error_tester,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(opt.request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str_ignore_errors(
        &tester.testing_channel,
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

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check that callbacks were invoked before error_at, but not after */
    for (int i = 0; i < REQUEST_CALLBACK_COMPLETE; ++i) {
        if (i <= error_at) {
            ASSERT_TRUE(error_tester.callback_counts[i] > 0);
        } else {
            ASSERT_INT_EQUALS(0, error_tester.callback_counts[i]);
        }
    }

    /* the on_complete callback should always fire though, and should receive the proper error_code */
    ASSERT_INT_EQUALS(1, error_tester.callback_counts[REQUEST_CALLBACK_COMPLETE]);
    ASSERT_INT_EQUALS(ERROR_FROM_CALLBACK_ERROR_CODE, error_tester.on_complete_error_code);

    aws_http_stream_release(stream);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_error_from_outgoing_body_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_CALLBACK_OUTGOING_BODY));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_error_from_incoming_headers_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_CALLBACK_INCOMING_HEADERS));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_error_from_incoming_headers_done_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_CALLBACK_INCOMING_HEADERS_DONE));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_error_from_incoming_body_callback_stops_decoder) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, REQUEST_CALLBACK_INCOMING_BODY));
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

H1_CLIENT_TEST_CASE(h1_client_unactivated_stream_cleans_up) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_TRUE(aws_http_connection_is_open(tester.connection));

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("GET")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));

    struct aws_http_make_request_options options = {
        .self_size = sizeof(struct aws_http_make_request_options),
        .request = request,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &options);
    aws_http_message_release(request);
    ASSERT_NOT_NULL(stream);
    /* we do not activate, that is the test. */
    aws_http_stream_release(stream);
    aws_http_connection_close(tester.connection);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

struct protocol_switcher {
    /* Settings */
    struct tester *tester;
    size_t downstream_handler_window_size;
    const char *data_after_upgrade_response;
    bool install_downstream_handler;

    /* Results */
    int upgrade_response_status;
    bool has_installed_downstream_handler;
};

static int s_switch_protocols_on_response_header_block_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    (void)header_block;

    struct protocol_switcher *switcher = user_data;
    aws_http_stream_get_incoming_response_status(stream, &switcher->upgrade_response_status);

    /* install downstream hander */
    if (switcher->install_downstream_handler &&
        (switcher->upgrade_response_status == AWS_HTTP_STATUS_CODE_101_SWITCHING_PROTOCOLS)) {

        int err = testing_channel_install_downstream_handler(
            &switcher->tester->testing_channel, switcher->downstream_handler_window_size);
        if (!err) {
            switcher->has_installed_downstream_handler = true;
        }
    }

    return AWS_OP_SUCCESS;
}

/* Send "Connection: Upgrade" request and receive "101 Switching Protocols" response.
 * Optionally, install a downstream handler when response is received
 */
static int s_switch_protocols(struct protocol_switcher *switcher) {
    /* send upgrade request */
    struct aws_http_header request_headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Connection"),
            .value = aws_byte_cursor_from_c_str("Upgrade"),
        },
        {
            .name = aws_byte_cursor_from_c_str("Upgrade"),
            .value = aws_byte_cursor_from_c_str("MyProtocol"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(switcher->tester->alloc);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_http_method_get));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, request_headers, AWS_ARRAY_SIZE(request_headers)));

    struct aws_http_make_request_options upgrade_request = {
        .self_size = sizeof(upgrade_request),
        .request = request,
        .user_data = switcher,
        .on_response_header_block_done = s_switch_protocols_on_response_header_block_done,
    };

    struct aws_http_stream *upgrade_stream =
        aws_http_connection_make_request(switcher->tester->connection, &upgrade_request);
    ASSERT_NOT_NULL(upgrade_stream);
    aws_http_stream_activate(upgrade_stream);
    testing_channel_drain_queued_tasks(&switcher->tester->testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(upgrade_request.request);

    /* clear all messages written thus far to the testing-channel */
    while (!aws_linked_list_empty(testing_channel_get_written_message_queue(&switcher->tester->testing_channel))) {
        struct aws_linked_list_node *node =
            aws_linked_list_pop_front(testing_channel_get_written_message_queue(&switcher->tester->testing_channel));
        struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
        aws_mem_release(msg->allocator, msg);
    }

    /* send upgrade response (followed by any extra data) */
    struct aws_byte_cursor response = aws_byte_cursor_from_c_str("HTTP/1.1 101 Switching Protocols\r\n"
                                                                 "Upgrade: MyProtocol\r\n"
                                                                 "\r\n");
    struct aws_byte_cursor extra_data = aws_byte_cursor_from_c_str(switcher->data_after_upgrade_response);
    struct aws_byte_buf sending_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&sending_buf, switcher->tester->alloc, response.len + extra_data.len));
    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&sending_buf, response));
    if (extra_data.len) {
        ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&sending_buf, extra_data));
    }

    ASSERT_SUCCESS(
        testing_channel_push_read_data(&switcher->tester->testing_channel, aws_byte_cursor_from_buf(&sending_buf)));

    /* wait for response to complete, and check results */
    testing_channel_drain_queued_tasks(&switcher->tester->testing_channel);
    ASSERT_INT_EQUALS(101, switcher->upgrade_response_status);

    /* if we wanted downstream handler installed, ensure that happened */
    if (switcher->install_downstream_handler) {
        ASSERT_TRUE(switcher->has_installed_downstream_handler);
    }

    /* cleanup */
    aws_byte_buf_clean_up(&sending_buf);
    aws_http_stream_release(upgrade_stream);
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_midchannel_sanity_check) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = true,
    };
    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    /* clean up */
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* confirm data passes through http-handler untouched in the read direction */
H1_CLIENT_TEST_CASE(h1_client_midchannel_read) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = true,
        .downstream_handler_window_size = SIZE_MAX,
    };
    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    const char *test_str = "inmyprotocolspacesarestrictlyforbidden";
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, test_str));
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_SUCCESS(testing_channel_check_midchannel_read_messages_str(&tester.testing_channel, allocator, test_str));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* confirm that, if new-protocol-data arrives packed into the same aws_io_message as the upgrade response,
 * that data is properly passed dowstream. */
H1_CLIENT_TEST_CASE(h1_client_midchannel_read_immediately) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    const char *test_str = "inmyprotocoleverythingwillbebetter";

    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = true,
        .downstream_handler_window_size = SIZE_MAX,
        .data_after_upgrade_response = test_str, /* Note extra data */
    };
    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    ASSERT_SUCCESS(testing_channel_check_midchannel_read_messages_str(&tester.testing_channel, allocator, test_str));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Have a tiny downstream read-window and increment it in little chunks. */
H1_CLIENT_TEST_CASE(h1_client_midchannel_read_with_small_downstream_window) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = true,
        .downstream_handler_window_size = 1 /* Note tiny starting window. */,
    };
    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    const char *test_str = "inmyprotocolcapitallettersarethedevil";
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, test_str));

    /* open window in tiny increments */
    for (size_t i = 0; i < strlen(test_str); ++i) {
        ASSERT_SUCCESS(testing_channel_increment_read_window(&tester.testing_channel, 1));
        testing_channel_drain_queued_tasks(&tester.testing_channel);
    }

    /* ensure that the handler actually sent multiple messages */
    size_t num_read_messages = 0;
    struct aws_linked_list *list = testing_channel_get_read_message_queue(&tester.testing_channel);
    struct aws_linked_list_node *node = aws_linked_list_front(list);
    while (node != aws_linked_list_end(list)) {
        num_read_messages++;
        node = aws_linked_list_next(node);
    }
    ASSERT_TRUE(num_read_messages > 1);

    ASSERT_SUCCESS(testing_channel_check_midchannel_read_messages_str(&tester.testing_channel, allocator, test_str));

    /* cleanup */
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* confirm data passes through http-handler untouched in the write direction */
H1_CLIENT_TEST_CASE(h1_client_midchannel_write) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = true,
        .downstream_handler_window_size = SIZE_MAX,
    };
    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    const char *test_str = "inmyprotocolthereisnomoney";
    testing_channel_push_write_str(&tester.testing_channel, test_str);
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, test_str));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test that, when HTTP is a midchannel handler, it will continue processing aws_io_messages write messages
 * in the time between shutdown-in-the-read-direction and shutdown-in-the-write-direction */
static const char *s_write_after_shutdown_in_read_dir_str = "inmyprotocolfrowningisnotallowed";

static void s_downstream_handler_write_on_shutdown(
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately,
    void *user_data) {

    (void)error_code;
    (void)free_scarce_resources_immediately;

    struct tester *tester = user_data;

    if (dir == AWS_CHANNEL_DIR_WRITE) {
        testing_channel_push_write_str(&tester->testing_channel, s_write_after_shutdown_in_read_dir_str);
    }
}

H1_CLIENT_TEST_CASE(h1_client_midchannel_write_continues_after_shutdown_in_read_dir) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = true,
        .downstream_handler_window_size = SIZE_MAX,
    };
    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    /* Downstream handler will write data while shutting down in write direction */
    testing_channel_set_downstream_handler_shutdown_callback(
        &tester.testing_channel, s_downstream_handler_write_on_shutdown, &tester);

    /* Shutdown cannel */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Did the late message get through? */
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(
        &tester.testing_channel, tester.alloc, s_write_after_shutdown_in_read_dir_str));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

static void s_on_message_write_complete_save_error_code(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data) {

    (void)channel;
    (void)message;
    int *save = user_data;
    *save = err_code;
}

/* Ensure that things fail if a downstream handler is installed without switching protocols.
 * This test is weird in that failure must occur, but we're not prescriptive about where it occurs. */
H1_CLIENT_TEST_CASE(h1_client_midchannel_requires_switching_protocols) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* The act of installing the downstream handler might fail */
    int err = testing_channel_install_downstream_handler(&tester.testing_channel, SIZE_MAX);
    if (err) {
        goto installation_failed;
    }

    /* Sending the message might fail */
    int msg_completion_error_code = 0;
    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        tester.testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, SIZE_MAX);
    ASSERT_NOT_NULL(msg);
    msg->on_completion = s_on_message_write_complete_save_error_code;
    msg->user_data = &msg_completion_error_code;

    err = testing_channel_push_write_message(&tester.testing_channel, msg);
    if (err) {
        aws_mem_release(msg->allocator, msg);
        goto push_message_failed;
    }

    /* The message might fail to reach the socket */
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    if (msg_completion_error_code) {
        goto message_completion_failed;
    }

    /* This is bad, we should have failed by now */
    ASSERT_TRUE(false);

message_completion_failed:
push_message_failed:
installation_failed:

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_switching_protocols_fails_pending_requests) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* queue a connection upgrade request */
    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Connection"),
            .value = aws_byte_cursor_from_c_str("Upgrade"),
        },
        {
            .name = aws_byte_cursor_from_c_str("Upgrade"),
            .value = aws_byte_cursor_from_c_str("MyProtocol"),
        },
    };

    struct aws_http_message *upgrade_request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(upgrade_request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(upgrade_request, aws_http_method_get));
    ASSERT_SUCCESS(aws_http_message_set_request_path(upgrade_request, aws_byte_cursor_from_c_str("/")));
    ASSERT_SUCCESS(aws_http_message_add_header_array(upgrade_request, headers, AWS_ARRAY_SIZE(headers)));

    struct client_stream_tester upgrade_stream;
    ASSERT_SUCCESS(s_stream_tester_init(&upgrade_stream, &tester, upgrade_request));

    /* queue another request behind it */
    struct aws_http_message *next_request = s_new_default_get_request(allocator);

    struct client_stream_tester next_stream;
    ASSERT_SUCCESS(s_stream_tester_init(&next_stream, &tester, next_request));

    /* send upgrade response */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(upgrade_request);
    aws_http_message_destroy(next_request);

    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: MyProtocol\r\n"
        "\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* confirm that the next request was cancelled */
    ASSERT_TRUE(next_stream.complete);
    ASSERT_TRUE(next_stream.on_complete_error_code != AWS_OP_SUCCESS);

    /* clean up */
    client_stream_tester_clean_up(&upgrade_stream);
    client_stream_tester_clean_up(&next_stream);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_switching_protocols_fails_subsequent_requests) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Successfully switch protocols */
    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = true,
    };
    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    /* Attempting to send a request after this should fail. */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    int err = s_stream_tester_init(&stream_tester, &tester, request);
    if (err) {
        ASSERT_INT_EQUALS(AWS_ERROR_HTTP_SWITCHED_PROTOCOLS, aws_last_error());
    } else {
        testing_channel_drain_queued_tasks(&tester.testing_channel);
        ASSERT_TRUE(stream_tester.complete);
        ASSERT_INT_EQUALS(AWS_ERROR_HTTP_SWITCHED_PROTOCOLS, stream_tester.on_complete_error_code);
    }

    /* clean up */
    aws_http_message_destroy(request);
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_switching_protocols_requires_downstream_handler) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Successfully switch protocols, but don't install downstream handler. */
    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = false,
    };

    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    /* If new data arrives and no downstream handler is installed to deal with it, the connection should shut down. */
    ASSERT_SUCCESS(
        testing_channel_push_read_str_ignore_errors(&tester.testing_channel, "herecomesnewprotocoldatachoochoo"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));
    ASSERT_TRUE(testing_channel_get_shutdown_error_code(&tester.testing_channel) != AWS_ERROR_SUCCESS);

    /* clean up */
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
