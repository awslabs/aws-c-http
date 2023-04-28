/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "stream_test_helper.h"
#include <aws/common/uuid.h>
#include <aws/http/private/h1_connection.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/logging.h>
#include <aws/io/stream.h>
#include <aws/testing/io_testing_channel.h>

#ifdef _MSC_VER
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

static void s_destroy_stream_on_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    (void)error_code;
    struct aws_input_stream *data_stream = user_data;
    aws_input_stream_release(data_stream);
}

static struct aws_http1_chunk_options s_default_chunk_options(struct aws_input_stream *stream, size_t stream_size) {
    struct aws_http1_chunk_options options;
    AWS_ZERO_STRUCT(options);
    options.chunk_data = stream;
    options.chunk_data_size = stream_size;
    options.on_complete = s_destroy_stream_on_complete;
    options.user_data = stream;
    return options;
}

static int s_write_termination_chunk(struct aws_allocator *allocator, struct aws_http_stream *stream) {
    static const struct aws_byte_cursor empty_str = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("");
    struct aws_input_stream *termination_marker = aws_input_stream_new_from_cursor(allocator, &empty_str);
    ASSERT_NOT_NULL(termination_marker);
    struct aws_http1_chunk_options options = s_default_chunk_options(termination_marker, empty_str.len);
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    return AWS_OP_SUCCESS;
}

static struct aws_http_message *s_new_default_chunked_put_request(struct aws_allocator *allocator) {
    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    AWS_FATAL_ASSERT(request);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    AWS_FATAL_ASSERT(
        AWS_OP_SUCCESS == aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/plan.txt")));
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));

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

struct tester_options {
    bool manual_window_management;
    size_t initial_stream_window_size;
    size_t read_buffer_capacity;
};

static int s_tester_init_ex(struct tester *tester, struct aws_allocator *alloc, const struct tester_options *options) {
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

    struct aws_http1_connection_options http1_options;
    AWS_ZERO_STRUCT(http1_options);
    http1_options.read_buffer_capacity = options->read_buffer_capacity;

    tester->connection = aws_http_connection_new_http1_1_client(
        alloc, options->manual_window_management, options->initial_stream_window_size, &http1_options);
    ASSERT_NOT_NULL(tester->connection);

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &tester->connection->channel_handler));
    tester->connection->vtable->on_channel_handler_installed(&tester->connection->channel_handler, slot);

    testing_channel_drain_queued_tasks(&tester->testing_channel);

    return AWS_OP_SUCCESS;
}

static int s_tester_init(struct tester *tester, struct aws_allocator *alloc) {
    struct tester_options options = {
        .manual_window_management = false,
    };
    return s_tester_init_ex(tester, alloc, &options);
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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

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
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    aws_input_stream_release(body_stream);
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_body_chunked) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);

    /* Initialize and send the stream chunks */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);
    struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body.len);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

int chunked_test_helper(
    const struct aws_byte_cursor *body,
    struct aws_http_headers *trailers,
    const char *expected,
    struct tester tester,
    struct aws_allocator *allocator) {

    /* send request */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);

    /* Initialize and send the stream chunks */
    ASSERT_SUCCESS(aws_http_stream_activate(stream));
    if (body != NULL) {
        struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, body);
        struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body->len);
        ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    }
    ASSERT_SUCCESS(aws_http1_stream_add_chunked_trailer(stream, trailers));
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);
    return AWS_OP_SUCCESS;
}

int chunked_trailer_succeed(
    const struct aws_byte_cursor *body,
    struct aws_http_headers *trailers,
    struct tester tester,
    struct aws_allocator *allocator) {

    /* send request */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);

    /* Initialize and send the stream chunks */
    ASSERT_SUCCESS(aws_http_stream_activate(stream));
    if (body != NULL) {
        struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, body);
        struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body->len);
        ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    }

    /* kind of gross, but good enough for now */
    int err = aws_http1_stream_add_chunked_trailer(stream, trailers);
    if (err) {
        aws_http_message_destroy(request);
        aws_http_stream_release(stream);
        return err;
    }
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_chunked_trailer) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    struct aws_http_headers *trailers = aws_http_headers_new(allocator);
    const struct aws_http_header trailer = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked"),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("trailer"),
    };
    const struct aws_http_header trailer1 = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("another"),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("test"),
    };
    aws_http_headers_add_header(trailers, &trailer);
    aws_http_headers_add_header(trailers, &trailer1);

    /* Initialize and send the stream chunks */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");

    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
                           "chunked: trailer\r\n"
                           "another: test\r\n"
                           "\r\n";

    ASSERT_SUCCESS(chunked_test_helper(&body, trailers, expected, tester, allocator));
    /* clean up */
    aws_http_headers_release(trailers);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_empty_chunked_trailer) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    struct aws_http_headers *trailers = aws_http_headers_new(allocator);

    /* Initialize and send the stream chunks */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");

    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
                           "\r\n";

    ASSERT_SUCCESS(chunked_test_helper(&body, trailers, expected, tester, allocator));
    /* clean up */
    aws_http_headers_release(trailers);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_forbidden_trailer) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct aws_http_headers *success = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        success,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("should"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("succeed"),
        });
    struct aws_http_headers *transfer_encoding = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        transfer_encoding,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("gzip, chunked"),
        });
    struct aws_http_headers *content_length = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        content_length,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("3495"),
        });
    struct aws_http_headers *host = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        host,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("www.example.org"),
        });
    struct aws_http_headers *cache_control = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        cache_control,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Cache-Control"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("private"),
        });
    struct aws_http_headers *expect = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        expect,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Expect"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("100-continue"),
        });
    struct aws_http_headers *max_forwards = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        max_forwards,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("max-forwards"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("123"),
        });
    struct aws_http_headers *pragma = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        pragma,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("pragma"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("no-cache"),
        });
    struct aws_http_headers *range = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        range,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("range"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("bytes=0-1023"),
        });
    struct aws_http_headers *te = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        te,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("te"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("trailers, deflate;q=0.5"),
        });
    struct aws_http_headers *www_authenticate = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        www_authenticate,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("www-authenticate"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(
                "Newauth realm=\"apps\", type=1,title=\"Login to \"apps\"\", Basic realm=\"simple\""),
        });
    struct aws_http_headers *authorization = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        authorization,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("authorization"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("credentials"),
        });
    struct aws_http_headers *proxy_authenticate = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        proxy_authenticate,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("proxy-authenticate"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Basic YWxhZGRpbjpvcGVuc2VzYW1l"),
        });
    struct aws_http_headers *proxy_authorization = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        proxy_authorization,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("proxy-authorization"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("credentials"),
        });
    struct aws_http_headers *set_cookie = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        set_cookie,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("set-cookie"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("sessionId=38afes7a8"),
        });
    struct aws_http_headers *cookie = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        cookie,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("cookie"),
            .value =
                AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1"),
        });
    struct aws_http_headers *age = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        age,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("age"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("24"),
        });
    struct aws_http_headers *expires = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        expires,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("expires"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Wed, 21 Oct 2015 07:28:00 GMT"),
        });
    struct aws_http_headers *date = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        date,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("date"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Wed, 21 Oct 2015 07:28:00 GMT"),
        });
    struct aws_http_headers *location = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        location,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("location"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/index.html"),
        });
    struct aws_http_headers *retry_after = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        retry_after,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("retry-after"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("120"),
        });
    struct aws_http_headers *vary = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        vary,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("vary"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("User-Agent"),
        });

    struct aws_http_headers *warning = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        warning,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("warning"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("110 anderson/1.3.37 \"Response is stale\""),
        });
    struct aws_http_headers *content_encoding = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        content_encoding,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("content-encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("gzip"),
        });

    struct aws_http_headers *content_type = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        content_type,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("content-type"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("text/html"),
        });
    struct aws_http_headers *content_range = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        content_range,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("content-range"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("bytes 200-1000/67589"),
        });

    struct aws_http_headers *trailer = aws_http_headers_new(allocator);
    aws_http_headers_add_header(
        trailer,
        &(struct aws_http_header){
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("trailer"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Expires"),
        });

    ASSERT_SUCCESS(chunked_trailer_succeed(NULL, success, tester, allocator));
    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, transfer_encoding, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, content_length, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, host, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, cache_control, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, expect, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, max_forwards, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, pragma, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, range, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, te, tester, allocator));
    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, www_authenticate, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, authorization, tester, allocator));
    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, proxy_authenticate, tester, allocator));
    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, proxy_authorization, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, set_cookie, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, cookie, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, age, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, expires, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, date, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, location, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, retry_after, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, vary, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, warning, tester, allocator));
    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, content_encoding, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, content_type, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, content_range, tester, allocator));
    ASSERT_ERROR(AWS_ERROR_HTTP_INVALID_HEADER_FIELD, chunked_trailer_succeed(NULL, trailer, tester, allocator));
    /* clean up */
    aws_http_headers_release(success);
    aws_http_headers_release(transfer_encoding);
    aws_http_headers_release(content_length);
    aws_http_headers_release(host);
    aws_http_headers_release(cache_control);
    aws_http_headers_release(expect);
    aws_http_headers_release(max_forwards);
    aws_http_headers_release(pragma);
    aws_http_headers_release(range);
    aws_http_headers_release(te);
    aws_http_headers_release(www_authenticate);
    aws_http_headers_release(authorization);
    aws_http_headers_release(proxy_authenticate);
    aws_http_headers_release(proxy_authorization);
    aws_http_headers_release(set_cookie);
    aws_http_headers_release(cookie);
    aws_http_headers_release(age);
    aws_http_headers_release(expires);
    aws_http_headers_release(date);
    aws_http_headers_release(location);
    aws_http_headers_release(retry_after);
    aws_http_headers_release(vary);
    aws_http_headers_release(warning);
    aws_http_headers_release(content_encoding);
    aws_http_headers_release(content_type);
    aws_http_headers_release(content_range);
    aws_http_headers_release(trailer);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_chunked_extensions) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    /* Initialize and send the stream chunks */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");

    /* create a chunk with a single extension */
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);
    struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body.len);
    struct aws_http1_chunk_extension single_extension[] = {
        {
            .key = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("foo"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("bar"),
        },
    };
    options.extensions = (struct aws_http1_chunk_extension *)&single_extension;
    options.num_extensions = AWS_ARRAY_SIZE(single_extension);
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));

    /* create a chunk with a multiple_single extensions */
    static const struct aws_byte_cursor multi_ext_body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    struct aws_input_stream *multi_ext_body_stream = aws_input_stream_new_from_cursor(allocator, &multi_ext_body);
    struct aws_http1_chunk_options multi_ext_opts = s_default_chunk_options(multi_ext_body_stream, multi_ext_body.len);
    struct aws_http1_chunk_extension multi_extension[] = {
        {
            .key = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("foo"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("bar"),
        },
        {
            .key = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("baz"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("cux"),
        },
    };
    multi_ext_opts.extensions = (struct aws_http1_chunk_extension *)&multi_extension;
    multi_ext_opts.num_extensions = AWS_ARRAY_SIZE(multi_extension);
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &multi_ext_opts));

    /* terminate the stream */
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

    /* Run it! */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10;foo=bar\r\n"
                           "write more tests"
                           "\r\n"
                           "10;foo=bar;baz=cux\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

struct chunk_writer_data {
    size_t num_chunks;
    const char **payloads;
    struct aws_http_stream *stream;
    struct aws_allocator *allocator;
    long delay_between_writes_ns;
};

H1_CLIENT_TEST_CASE(h1_client_request_waits_for_chunks) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request with Transfer-Encoding: chunked and body stream */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    /* activate stream *before* sending any data. */
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    char *payloads[] = {"write more tests", "write more tests", ""};
    struct chunk_writer_data chunk_data = {
        .num_chunks = sizeof(payloads) / sizeof(payloads[0]),
        .payloads = (const char **)&payloads,
        .stream = stream,
        .allocator = allocator,
        .delay_between_writes_ns = 10000,
    };

    /* write and pause, in a loop. This exercises the rescheduling path. */
    for (size_t i = 0; i < chunk_data.num_chunks; ++i) {
        testing_channel_drain_queued_tasks(&tester.testing_channel);
        ASSERT_FALSE(
            aws_task_scheduler_has_tasks(&tester.testing_channel.loop_impl->scheduler, NULL),
            "Everything should be paused when no chunks are pending");

        struct aws_byte_cursor body = aws_byte_cursor_from_c_str(chunk_data.payloads[i]);
        struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(chunk_data.allocator, &body);
        struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body.len);
        ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));

        testing_channel_drain_queued_tasks(&tester.testing_channel);
        ASSERT_FALSE(
            aws_task_scheduler_has_tasks(&tester.testing_channel.loop_impl->scheduler, NULL),
            "Everything should be paused when no chunks are pending");
    }

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
                           "\r\n";

    /* check result */
    ASSERT_SUCCESS(testing_channel_check_written_messages(
        &tester.testing_channel, allocator, aws_byte_cursor_from_c_str(expected)));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

struct chunk_that_writes_another {
    struct aws_allocator *allocator;
    struct aws_input_stream *body_data;
};

static void s_on_chunk_complete_write_another_chunk(struct aws_http_stream *stream, int error_code, void *user_data) {
    AWS_FATAL_ASSERT(0 == error_code);
    struct chunk_that_writes_another *chunk = user_data;

    aws_input_stream_release(chunk->body_data);

    const struct aws_byte_cursor chunk2_body = aws_byte_cursor_from_c_str("chunk 2.");
    struct aws_input_stream *chunk2_body_stream = aws_input_stream_new_from_cursor(chunk->allocator, &chunk2_body);
    AWS_FATAL_ASSERT(chunk2_body_stream != NULL);

    struct aws_http1_chunk_options chunk2_options = s_default_chunk_options(chunk2_body_stream, chunk2_body.len);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http1_stream_write_chunk(stream, &chunk2_options));
}

/* Test that it's safe to start a new chunk from the chunk-complete callback */
H1_CLIENT_TEST_CASE(h1_client_request_send_chunk_from_chunk_complete_callback) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request with Transfer-Encoding: chunked and body stream */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);

    /* activate stream *before* sending any data. */
    aws_http_stream_activate(stream);

    /* write chunk 1 */
    const struct aws_byte_cursor chunk1_body = aws_byte_cursor_from_c_str("chunk 1.");
    struct aws_input_stream *chunk1_body_stream = aws_input_stream_new_from_cursor(allocator, &chunk1_body);
    ASSERT_NOT_NULL(chunk1_body_stream);

    struct chunk_that_writes_another chunk1_userdata = {
        .allocator = allocator,
        .body_data = chunk1_body_stream,
    };

    struct aws_http1_chunk_options chunk1_options = {
        .chunk_data = chunk1_body_stream,
        .chunk_data_size = chunk1_body.len,
        .on_complete = s_on_chunk_complete_write_another_chunk,
        .user_data = &chunk1_userdata,
    };

    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &chunk1_options));

    /* run tasks, the 1st chunk should complete, which writes the 2nd chunk,
     * which should also complete */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "8\r\n"
                           "chunk 1."
                           "\r\n"
                           "8\r\n"
                           "chunk 2."
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Regression test: Once upon a time there was a bug where the outgoing_stream_task got double-scheduled.
 * The situation was:
 * - An aws_io_message had been written to the channel, but not yet completed.
 * - The encoder was paused, waiting for more chunks.
 * Then at more-or-less the same time:
 * - The aws_io_message finished writing, which resulted in the outgoing_stream_task getting rescheduled.
 * - A new chunk was added, which resulted in the outgoing_stream_task getting rescheduled.
 * And then the task's linked_list_node got all screwed up and we crashed iterating a list. */
H1_CLIENT_TEST_CASE(h1_client_request_write_chunk_as_write_completes_regression) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* To repro this bug, testing channel must wait to mark aws_io_messages complete */
    testing_channel_complete_written_messages_immediately(&tester.testing_channel, false, 0);

    /* Send request */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    /* Drain tasks. The head of the request gets written to aws_io_message and sent down channel.
     * The outgoing_stream_task should be paused waiting for more chunks. */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Write a chunk. When bug occurred, this would reschedule the outgoing_stream_task */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);
    struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body.len);
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

    /* Have the previously sent aws_io_message complete.
     * When bug occurred, this would ALSO reschedule the outgoing_stream_task */
    struct aws_linked_list *written_msgs = testing_channel_get_written_message_queue(&tester.testing_channel);
    for (struct aws_linked_list_node *node = aws_linked_list_begin(written_msgs);
         node != aws_linked_list_end(written_msgs);
         node = aws_linked_list_next(node)) {

        struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
        msg->on_completion(tester.testing_channel.channel, msg, 0, msg->user_data);
        msg->on_completion = NULL;
    }

    /* Run the scheduler. When bug occurred, this would crash */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_SUCCESS(testing_channel_check_written_message_str(&tester.testing_channel, expected));

    /* clean up */
    aws_input_stream_release(body_stream);
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_chunk_size_0_ok) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Send request with Transfer-Encoding: chunked and an empty body stream. */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "0\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_chunk_size_0_with_extensions_ok) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Send request with Transfer-Encoding: chunked and an empty body stream. */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    static const struct aws_byte_cursor empty_str = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("");
    struct aws_input_stream *termination_marker = aws_input_stream_new_from_cursor(allocator, &empty_str);
    struct aws_http1_chunk_options options = s_default_chunk_options(termination_marker, empty_str.len);
    struct aws_http1_chunk_extension single_extension[] = {
        {
            .key = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("foo"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("bar"),
        },
        {
            .key = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("baz"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("cux"),
        },
    };
    options.extensions = (struct aws_http1_chunk_extension *)&single_extension;
    options.num_extensions = AWS_ARRAY_SIZE(single_extension);
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));

    testing_channel_drain_queued_tasks(&tester.testing_channel);
    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "0;foo=bar;baz=cux\r\n"
                           "\r\n";

    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Send a request whose body doesn't fit in a single aws_io_message using content length*/
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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

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
    aws_input_stream_release(body_stream);
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    aws_byte_buf_clean_up(&body_buf);
    aws_byte_buf_clean_up(&expected_buf);
    return AWS_OP_SUCCESS;
}

static int s_parse_chunked_extensions(
    const char *extensions,
    struct aws_http1_chunk_extension *expected_extensions,
    size_t num_extensions) {

    size_t i;
    for (i = 0; i < num_extensions; ++i) {
        struct aws_http1_chunk_extension *expected_extension = expected_extensions + i;
        /* parse the key */
        char *key_val_delimiter = strchr(extensions, '=');
        if (NULL == key_val_delimiter) {
            return false;
        }
        *key_val_delimiter = '\0';
        struct aws_byte_cursor key = aws_byte_cursor_from_c_str(extensions);
        ASSERT_BIN_ARRAYS_EQUALS(expected_extension->key.ptr, expected_extension->key.len, key.ptr, key.len);
        extensions = key_val_delimiter + 1;

        /* parse the value */
        char *val_end_delimiter = strchr(extensions, ';');
        if (NULL != val_end_delimiter) {
            *val_end_delimiter = '\0';
        }
        struct aws_byte_cursor value = aws_byte_cursor_from_c_str(extensions++);
        ASSERT_BIN_ARRAYS_EQUALS(expected_extension->value.ptr, expected_extension->value.len, value.ptr, value.len);
        extensions = val_end_delimiter + 1;
    }
    if (i == num_extensions) {
        return AWS_OP_SUCCESS;
    } else {
        return AWS_OP_ERR;
    }
}

static int s_can_parse_as_chunked_encoding(
    struct aws_allocator *allocator,
    struct aws_byte_buf *chunked_http_request_headers_and_body,
    struct aws_byte_buf *expected_head,
    struct aws_http1_chunk_extension *expected_extensions,
    size_t num_extensions,
    char body_char) {

    /* Check that the HTTP header matches the expected value */
    ASSERT_TRUE(chunked_http_request_headers_and_body->len > expected_head->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_head->buffer, expected_head->len, chunked_http_request_headers_and_body->buffer, expected_head->len);

    /* move the cursor past the head and enter the chunked body */
    struct aws_byte_cursor request_cursor = aws_byte_cursor_from_buf(chunked_http_request_headers_and_body);
    aws_byte_cursor_advance(&request_cursor, expected_head->len);
    struct aws_byte_cursor crlf_cursor = aws_byte_cursor_from_c_str("\r\n");
    struct aws_byte_cursor match_cursor;
    /* Provide a max iterations in case of a bug the test doesn't infinite loop but fails fast. */
    int max_iter = 128;
    int i = 0;
    /* 3MB to hold a massive chunked extension size */
    char *chunk_ascii_hex = aws_mem_calloc(allocator, 3, 1024 * 1024);
    for (i = 0; i < max_iter; ++i) {
        ASSERT_SUCCESS(aws_byte_cursor_find_exact(&request_cursor, &crlf_cursor, &match_cursor));
        memset(chunk_ascii_hex, 0, 3 * 1024 * 1024);
        memcpy(chunk_ascii_hex, (char *)request_cursor.ptr, match_cursor.ptr - request_cursor.ptr);
        char *chunk_ext_start = strchr(chunk_ascii_hex, ';');
        if (NULL != chunk_ext_start) {
            /* write a null character over where the first ';' of the stream so that strtol finds the right hex size. */
            *chunk_ext_start = '\0';
            if (0 < num_extensions) {
                ++chunk_ext_start;
                ASSERT_SUCCESS(s_parse_chunked_extensions(chunk_ext_start, expected_extensions, num_extensions));
            }
        }
        long chunk_size = strtol((char *)chunk_ascii_hex, 0, 16);
        long total_chunk_size_with_overhead = (long)
            (match_cursor.ptr -  request_cursor.ptr /* size of the chunk in ascii hex */
                + crlf_cursor.len                       /* size of the crlf */
                + chunk_size                            /* size of the payload */
                + crlf_cursor.len);                     /* size of the chunk terminating crlf */

        /* 0 length chunk signals end of stream. Check for the terminatino string and exit with success */
        if (0 == chunk_size) {
            struct aws_byte_cursor terminate_cursor = aws_byte_cursor_from_c_str("0\r\n\r\n");
            ASSERT_TRUE(aws_byte_cursor_eq(&request_cursor, &terminate_cursor));
            break;
        }

        /* The buffer should be filled with the character specified for the whole length of the chunk */
        for (int j = (int)(match_cursor.ptr - request_cursor.ptr + crlf_cursor.len); j < chunk_size; ++j) {
            ASSERT_TRUE(body_char == (char)request_cursor.ptr[j]);
        }
        /* advance to the next chunk */
        aws_byte_cursor_advance(&request_cursor, total_chunk_size_with_overhead);
    }
    aws_mem_release(allocator, chunk_ascii_hex);
    /* Test that we didn't exit the loop due to hitting the max iterations */
    ASSERT_TRUE(i < (max_iter - 1));

    return AWS_OP_SUCCESS;
}

/* Send a request whose body doesn't fit in a single aws_io_message using chunked transfer encoding*/
H1_CLIENT_TEST_CASE(h1_client_request_send_large_body_chunked) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Transfer-Encoding"),
            .value = aws_byte_cursor_from_c_str("chunked"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/large.txt")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    /* Initialize and send the stream chunks */
    /* send request with large body full of data */
    size_t body_len = 1024 * 1024 * 1; /* 1MB */
    struct aws_byte_buf body_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&body_buf, allocator, body_len));
    char body_char = 'z';
    while (body_buf.len < body_len) {
        aws_byte_buf_write_u8(&body_buf, body_char);
    }

    const struct aws_byte_cursor body = aws_byte_cursor_from_buf(&body_buf);
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);
    struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body.len);

    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    /* this call will trigger a pause/wake internally after a large write */
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

    /* check result */
    const char expected_head_fmt[] = "PUT /large.txt HTTP/1.1\r\n"
                                     "Transfer-Encoding: chunked\r\n"
                                     "\r\n";
    struct aws_byte_buf expected_head_buf = aws_byte_buf_from_c_str((char *)&expected_head_fmt);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    struct aws_byte_buf written_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&written_buf, allocator, body_len * 2));
    ASSERT_SUCCESS(testing_channel_drain_written_messages(&tester.testing_channel, &written_buf));

    ASSERT_SUCCESS(s_can_parse_as_chunked_encoding(allocator, &written_buf, &expected_head_buf, NULL, 0, body_char));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    aws_byte_buf_clean_up(&body_buf);
    aws_byte_buf_clean_up(&expected_head_buf);
    aws_byte_buf_clean_up(&written_buf);
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_send_large_chunk_extensions) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct aws_http_header headers[] = {
        {
            .name = aws_byte_cursor_from_c_str("Transfer-Encoding"),
            .value = aws_byte_cursor_from_c_str("chunked"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/large.txt")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    /* Initialize and send the stream chunks */
    /* send request with large body full of data */
    size_t body_len = 1024 * 1024 * 1; /* 1MB */
    struct aws_byte_buf body_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&body_buf, allocator, body_len));
    char body_char = 'z';
    while (body_buf.len < body_len) {
        aws_byte_buf_write_u8(&body_buf, body_char);
    }

    const struct aws_byte_cursor body = aws_byte_cursor_from_buf(&body_buf);
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);
    struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body.len);
    /* No one should ever be using 1MB extensions. In fact, it is a DDoS vector to your server and you should protect
     * against it for any sort of production software. That said, the spec doesn't place a size limit on how much the
     * client can send. For this test, we have a 1MB key and a 1MB value in each pair respectively to test that the
     * state machine can fill across the key/value larger than the size of a message in the channel. */
    struct aws_http1_chunk_extension extensions[] = {
        {
            .key = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("foo"),
            .value = aws_byte_cursor_from_buf(&body_buf),
        },
        {
            .key = aws_byte_cursor_from_buf(&body_buf),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("bar"),
        },
    };
    options.extensions = (struct aws_http1_chunk_extension *)&extensions;
    options.num_extensions = AWS_ARRAY_SIZE(extensions);

    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    /* this call will trigger a pause/wake internally after a large write */
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

    /* check result */
    const char expected_head_fmt[] = "PUT /large.txt HTTP/1.1\r\n"
                                     "Transfer-Encoding: chunked\r\n"
                                     "\r\n";
    struct aws_byte_buf expected_head_buf = aws_byte_buf_from_c_str((char *)&expected_head_fmt);

    struct aws_http1_chunk_extension expected_extensions[] = {
        {
            .key = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("foo"),
            .value = aws_byte_cursor_from_buf(&body_buf),
        },
        {
            .key = aws_byte_cursor_from_buf(&body_buf),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("bar"),
        },
    };

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    struct aws_byte_buf written_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&written_buf, allocator, body_len * 2));
    ASSERT_SUCCESS(testing_channel_drain_written_messages(&tester.testing_channel, &written_buf));

    ASSERT_SUCCESS(s_can_parse_as_chunked_encoding(
        allocator, &written_buf, &expected_head_buf, expected_extensions, AWS_ARRAY_SIZE(extensions), body_char));

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    aws_byte_buf_clean_up(&body_buf);
    aws_byte_buf_clean_up(&expected_head_buf);
    aws_byte_buf_clean_up(&written_buf);
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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

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
        ASSERT_SUCCESS(aws_http_stream_activate(streams[i]));
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

/* Check that if many requests are made (pipelining) they all get sent */
H1_CLIENT_TEST_CASE(h1_client_request_send_multiple_chunked_encoding) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send requests */
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = s_new_default_chunked_put_request(allocator),
    };

    struct aws_http_stream *streams[3];
    struct aws_byte_buf index_strs[AWS_ARRAY_SIZE(streams)];
    size_t num_streams = AWS_ARRAY_SIZE(streams);
    for (size_t i = 0; i < num_streams; ++i) {
        streams[i] = aws_http_connection_make_request(tester.connection, &opt);
        ASSERT_NOT_NULL(streams[i]);
        ASSERT_SUCCESS(aws_byte_buf_init(&index_strs[i], allocator, 4));
        index_strs[i].len = snprintf((char *)index_strs[i].buffer, index_strs[i].capacity, "%03zu", i);
        ASSERT_SUCCESS(aws_http_stream_activate(streams[i]));
    }

    /* All streams will pause and wait for data */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Write to all the streams */
    for (size_t i = 0; i < num_streams; ++i) {
        static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
        struct aws_byte_cursor index_str_cursor = aws_byte_cursor_from_buf(&index_strs[i]);

        struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);
        struct aws_input_stream *index_stream = aws_input_stream_new_from_cursor(allocator, &index_str_cursor);

        struct aws_http1_chunk_options options_1 = s_default_chunk_options(body_stream, body.len);
        struct aws_http1_chunk_options options_2 = s_default_chunk_options(index_stream, index_str_cursor.len);

        ASSERT_SUCCESS(aws_http1_stream_write_chunk(streams[i], &options_1));
        ASSERT_SUCCESS(aws_http1_stream_write_chunk(streams[i], &options_2));
        ASSERT_SUCCESS(s_write_termination_chunk(allocator, streams[i]));
    }

    testing_channel_drain_queued_tasks(&tester.testing_channel);
    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(opt.request);

    /* check result */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "3\r\n"
                           "000"
                           "\r\n"
                           "0\r\n"
                           "\r\n"
                           "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "3\r\n"
                           "001"
                           "\r\n"
                           "0\r\n"
                           "\r\n"
                           "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "3\r\n"
                           "002"
                           "\r\n"
                           "0\r\n"
                           "\r\n";

    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    /* clean up */
    for (size_t i = 0; i < num_streams; ++i) {
        aws_http_stream_release(streams[i]);
        aws_byte_buf_clean_up(&index_strs[i]);
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

static int s_stream_tester_init(
    struct client_stream_tester *tester,
    struct tester *main_tester,
    struct aws_http_message *request) {

    struct client_stream_tester_options options = {
        .request = request,
        .connection = main_tester->connection,
    };
    return client_stream_tester_init(tester, main_tester->alloc, &options);
}

H1_CLIENT_TEST_CASE(h1_client_stream_release_after_complete) {
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
    ASSERT_FALSE(stream_tester.destroyed);

    aws_http_stream_release(stream_tester.stream);
    stream_tester.stream = NULL;
    ASSERT_TRUE(stream_tester.destroyed);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_stream_release_before_complete) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));
    aws_http_stream_release(stream_tester.stream);
    stream_tester.stream = NULL;
    ASSERT_FALSE(stream_tester.destroyed);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, "HTTP/1.1 204 No Content\r\n\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_TRUE(stream_tester.destroyed);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
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

    ASSERT_TRUE(stream_tester.metrics.receive_end_timestamp_ns > 0);
    ASSERT_TRUE(stream_tester.metrics.receive_start_timestamp_ns > 0);
    ASSERT_TRUE(stream_tester.metrics.receive_end_timestamp_ns > stream_tester.metrics.receive_start_timestamp_ns);
    ASSERT_TRUE(
        stream_tester.metrics.receiving_duration_ns ==
        stream_tester.metrics.receive_end_timestamp_ns - stream_tester.metrics.receive_start_timestamp_ns);
    ASSERT_TRUE(stream_tester.metrics.send_start_timestamp_ns > 0);
    ASSERT_TRUE(stream_tester.metrics.send_end_timestamp_ns > 0);
    ASSERT_TRUE(stream_tester.metrics.send_end_timestamp_ns > stream_tester.metrics.send_start_timestamp_ns);
    ASSERT_TRUE(
        stream_tester.metrics.sending_duration_ns ==
        stream_tester.metrics.send_end_timestamp_ns - stream_tester.metrics.send_start_timestamp_ns);
    ASSERT_TRUE(stream_tester.metrics.stream_id == stream_tester.stream->id);

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
    struct aws_input_stream base;
    struct aws_stream_status status;
    struct aws_byte_cursor cursor;
    size_t delay_ticks;    /* Don't send anything the first N ticks */
    size_t bytes_per_tick; /* Don't send more than N bytes per tick */
};

static int s_slow_stream_read(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    struct slow_body_sender *sender = AWS_CONTAINER_OF(stream, struct slow_body_sender, base);

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
static int s_slow_stream_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    struct slow_body_sender *sender = AWS_CONTAINER_OF(stream, struct slow_body_sender, base);
    *status = sender->status;
    return AWS_OP_SUCCESS;
}
static int s_slow_stream_get_length(struct aws_input_stream *stream, int64_t *out_length) {
    struct slow_body_sender *sender = AWS_CONTAINER_OF(stream, struct slow_body_sender, base);
    *out_length = sender->cursor.len;
    return AWS_OP_SUCCESS;
}
static void s_slow_stream_destroy(struct aws_input_stream *stream) {
    (void)stream;
}

static struct aws_input_stream_vtable s_slow_stream_vtable = {
    .seek = NULL,
    .read = s_slow_stream_read,
    .get_status = s_slow_stream_get_status,
    .get_length = s_slow_stream_get_length,
};

static void s_slow_body_sender_init(struct slow_body_sender *body_sender) {
    /* set up request whose body won't send immediately */
    struct aws_input_stream empty_stream_base;
    AWS_ZERO_STRUCT(empty_stream_base);
    body_sender->base = empty_stream_base;
    body_sender->status.is_end_of_stream = false;
    body_sender->status.is_valid = true;
    struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    body_sender->cursor = body;
    body_sender->delay_ticks = 5;
    body_sender->bytes_per_tick = 1;

    body_sender->base.vtable = &s_slow_stream_vtable;
    aws_ref_count_init(
        &body_sender->base.ref_count, &body_sender, (aws_simple_completion_callback *)s_slow_stream_destroy);
}

/* It should be fine to receive a response before the request has finished sending */
H1_CLIENT_TEST_CASE(h1_client_response_arrives_before_request_done_sending_is_ok) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* set up request whose body won't send immediately */
    struct slow_body_sender body_sender;
    AWS_ZERO_STRUCT(body_sender);
    s_slow_body_sender_init(&body_sender);
    struct aws_input_stream *body_stream = &body_sender.base;

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
    aws_http_message_set_body_stream(request, body_stream);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    /* send head of request */
    testing_channel_run_currently_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);
    aws_input_stream_release(body_stream);

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

/* It should be fine to receive a response before the request has finished sending */
H1_CLIENT_TEST_CASE(h1_client_response_arrives_before_request_chunks_done_sending_is_ok) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* set up request whose body won't send immediately */
    struct aws_input_stream empty_stream_base;
    AWS_ZERO_STRUCT(empty_stream_base);
    struct slow_body_sender body_sender = {
        .base = empty_stream_base,
        .status =
            {
                .is_end_of_stream = false,
                .is_valid = true,
            },
        .cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests"),
        .delay_ticks = 5,
        .bytes_per_tick = 1,
    };
    body_sender.base.vtable = &s_slow_stream_vtable;
    aws_ref_count_init(
        &body_sender.base.ref_count, &body_sender, (aws_simple_completion_callback *)s_slow_stream_destroy);

    struct aws_input_stream *body_stream = &body_sender.base;

    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    /* send head of request */
    testing_channel_run_currently_queued_tasks(&tester.testing_channel);

    /* send response */
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, "HTTP/1.1 200 OK\r\n\r\n"));

    testing_channel_run_currently_queued_tasks(&tester.testing_channel);

    struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body_sender.cursor.len);
    options.on_complete = NULL; /* The stream_tester takes care of the stream deletion */
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream_tester.stream, &options));
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream_tester.stream));

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);
    aws_input_stream_release(body_stream);

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
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
                           "\r\n";

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

/* While pipelining 3 requests, and 2nd request has a "Connection: close" header.
 * 2 requests should complete successfully and the connection should close. */
H1_CLIENT_TEST_CASE(h1_client_request_close_header_with_chunked_encoding_and_pipelining) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Queue up 3 requests, where the middle request has a "Connection: close" header */
    enum { NUM_STREAMS = 3 };
    struct aws_http_message *requests[NUM_STREAMS];
    struct client_stream_tester stream_testers[NUM_STREAMS];
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        requests[i] = s_new_default_chunked_put_request(allocator);

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

    /* Write to all the streams */
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
        struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);
        struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body.len);
        ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream_testers[i].stream, &options));
        ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream_testers[i].stream));
    }

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Check that ONLY first 2 requests were sent */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
                           "\r\n"
                           "PUT /plan.txt HTTP/1.1\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "10\r\n"
                           "write more tests"
                           "\r\n"
                           "0\r\n"
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

/* Test that the stream window rules are respected. These rules are:
 * - Each new stream's window starts at initial_stream_window_size.
 * - Only body data counts against the stream's window.
 * - The stream will not receive more body data than its window allows.
 * - Any future streams on the same connection also start with initial_stream_window_size,
 *   they should not be affected if a previous stream had a very small or very large window when it ended.
 */
H1_CLIENT_TEST_CASE(h1_client_respects_stream_window) {
    (void)ctx;

    /* This test only checks that the stream window is respected.
     * We're not testing the connection window, so just use a giant buffer */
    struct tester_options tester_opts = {
        .manual_window_management = true,
        .initial_stream_window_size = 5,
        .read_buffer_capacity = SIZE_MAX,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init_ex(&tester, allocator, &tester_opts));

    /**
     * Request/Response 1
     */

    struct aws_http_message *request = s_new_default_get_request(allocator);

    struct client_stream_tester stream_tester1;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester1, &tester, request));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* send response whose body is 2X the initial_stream_window_size */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 10\r\n"
                               "\r\n"
                               "0123456789";
    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, response_str));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* stream window should reach 0 before entire body has been received */
    ASSERT_BIN_ARRAYS_EQUALS("01234", 5, stream_tester1.response_body.buffer, stream_tester1.response_body.len);
    struct aws_h1_window_stats window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_TRUE(window_stats.has_incoming_stream);
    ASSERT_UINT_EQUALS(0, window_stats.stream_window);

    /* open window just enough to get the rest of the body */
    aws_http_stream_update_window(stream_tester1.stream, 5);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_BIN_ARRAYS_EQUALS("0123456789", 10, stream_tester1.response_body.buffer, stream_tester1.response_body.len);
    ASSERT_TRUE(stream_tester1.complete);
    ASSERT_SUCCESS(stream_tester1.on_complete_error_code);
    client_stream_tester_clean_up(&stream_tester1);

    /**
     * Stream 2.
     * Send same request/response as before.
     * Everything should work fine, even though the previous stream left off with 0 window.
     */
    struct client_stream_tester stream_tester2;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester2, &tester, request));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, response_str));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_BIN_ARRAYS_EQUALS("01234", 5, stream_tester2.response_body.buffer, stream_tester2.response_body.len);
    window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_TRUE(window_stats.has_incoming_stream);
    ASSERT_UINT_EQUALS(0, window_stats.stream_window);

    /**
     * Stream 3.
     * Stress pipelining by sending the 3rd request and response before stream 2
     * has opened its window enough to complete.
     */
    struct client_stream_tester stream_tester3;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester3, &tester, request));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_SUCCESS(testing_channel_push_read_str(&tester.testing_channel, response_str));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* now open stream 2's window TO THE MAX to complete it. */
    aws_http_stream_update_window(stream_tester2.stream, SIZE_MAX);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_BIN_ARRAYS_EQUALS("0123456789", 10, stream_tester2.response_body.buffer, stream_tester2.response_body.len);
    ASSERT_TRUE(stream_tester2.complete);
    ASSERT_SUCCESS(stream_tester2.on_complete_error_code);
    client_stream_tester_clean_up(&stream_tester2);

    /* even though stream2 completed with a WIDE OPEN window, stream3's window should be at the initial size */
    ASSERT_BIN_ARRAYS_EQUALS("01234", 5, stream_tester3.response_body.buffer, stream_tester3.response_body.len);
    window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_TRUE(window_stats.has_incoming_stream);
    ASSERT_UINT_EQUALS(0, window_stats.stream_window);

    /* finish up stream 3 */
    aws_http_stream_update_window(stream_tester3.stream, 100);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_BIN_ARRAYS_EQUALS("0123456789", 10, stream_tester3.response_body.buffer, stream_tester3.response_body.len);
    ASSERT_TRUE(stream_tester3.complete);
    ASSERT_SUCCESS(stream_tester3.on_complete_error_code);
    client_stream_tester_clean_up(&stream_tester3);

    /* clean up */
    aws_http_message_destroy(request);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* This tests the specific way that HTTP/1 manages its connection window. */
H1_CLIENT_TEST_CASE(h1_client_connection_window_with_buffer) {
    (void)ctx;

    struct tester_options tester_opts = {
        .manual_window_management = true,
        .initial_stream_window_size = 0,
        .read_buffer_capacity = 100,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init_ex(&tester, allocator, &tester_opts));

    struct aws_http_message *request = s_new_default_get_request(allocator);
    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* confirm starting stats before any data received.
     * connection window should match buffer capacity. */
    struct aws_h1_window_stats window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_UINT_EQUALS(100, window_stats.buffer_capacity);
    ASSERT_UINT_EQUALS(0, window_stats.buffer_pending_bytes);
    ASSERT_UINT_EQUALS(100, window_stats.connection_window);
    ASSERT_UINT_EQUALS(0, window_stats.recent_window_increments);

    if (window_stats.has_incoming_stream) {
        /* It's an implementation detail whether the incoming stream ptr is set at this point,
         * but if it is, it should use initial-window-size*/
        ASSERT_UINT_EQUALS(0, window_stats.stream_window);
    }

    /* send 49 byte response 1 byte at a time, so we can see the message queue in action */
    const char *response_str = "HTTP/1.1 200 OK\r\n"
                               "Content-Length: 10\r\n"
                               "\r\n"
                               "0123456789";
    struct aws_byte_cursor response_cursor = aws_byte_cursor_from_c_str(response_str);
    while (response_cursor.len > 0) {
        struct aws_byte_cursor one_byte = aws_byte_cursor_advance(&response_cursor, 1);
        ASSERT_SUCCESS(testing_channel_push_read_data(&tester.testing_channel, one_byte));
    }
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* The stream should not have received any body, since its initial-window-size is zero.
     * At time of writing, the connection would not process headers if stream window was zero,
     * but that might change in the future, so not testing window stats here. */
    ASSERT_UINT_EQUALS(0, stream_tester.response_body.len);

    /* Open the stream window by 1 byte and check stats.
     * 40 bytes should be processed: 39 bytes of headers and metadata + 1 byte of body data */
    aws_http_stream_update_window(stream_tester.stream, 1);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_UINT_EQUALS(1, stream_tester.response_body.len);

    window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_UINT_EQUALS(
        40, window_stats.recent_window_increments); /* window incremented to account for processed data */
    ASSERT_UINT_EQUALS(100, window_stats.buffer_capacity);
    ASSERT_UINT_EQUALS(9, window_stats.buffer_pending_bytes);
    ASSERT_UINT_EQUALS(91, window_stats.connection_window);
    ASSERT_TRUE(window_stats.has_incoming_stream);
    ASSERT_UINT_EQUALS(0, window_stats.stream_window);

    /* Open stream window enough to finish */
    aws_http_stream_update_window(stream_tester.stream, 9);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_UINT_EQUALS(10, stream_tester.response_body.len);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_SUCCESS(stream_tester.on_complete_error_code);

    window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_UINT_EQUALS(9, window_stats.recent_window_increments); /* window incremented to account for processed data */
    ASSERT_UINT_EQUALS(100, window_stats.buffer_capacity);
    ASSERT_UINT_EQUALS(0, window_stats.buffer_pending_bytes);
    ASSERT_UINT_EQUALS(100, window_stats.connection_window);
    ASSERT_FALSE(window_stats.has_incoming_stream);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    aws_http_message_release(request);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test a connection with read_buffer_capacity < initial_window_size */
H1_CLIENT_TEST_CASE(h1_client_connection_window_with_small_buffer) {
    (void)ctx;

    struct tester_options tester_opts = {
        .manual_window_management = true,
        .initial_stream_window_size = 10,
        .read_buffer_capacity = 5,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init_ex(&tester, allocator, &tester_opts));

    struct aws_http_message *request = s_new_default_get_request(allocator);
    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* can't send response all at once because channel-window is too small. */
    const char *response_head_str = "HTTP/1.1 200 OK\r\n"
                                    "Content-Length: 20\r\n"
                                    "\r\n";
    const char *response_body_str = "0123456789"
                                    "ABCDEFGHIJ";

    /* send response head in little increments, it should flow through to the stream no problem */
    struct aws_byte_cursor response_cursor = aws_byte_cursor_from_c_str(response_head_str);
    while (response_cursor.len > 0) {
        struct aws_byte_cursor one_byte = aws_byte_cursor_advance(&response_cursor, 1);
        ASSERT_SUCCESS(testing_channel_push_read_data(&tester.testing_channel, one_byte));
        testing_channel_drain_queued_tasks(&tester.testing_channel);
    }

    ASSERT_UINT_EQUALS(0, stream_tester.response_body.len);

    /* send enough body data that stream's window is reduced to zero. */
    response_cursor = aws_byte_cursor_from_c_str(response_body_str);
    for (int i = 0; i < 10; ++i) {
        struct aws_byte_cursor one_byte = aws_byte_cursor_advance(&response_cursor, 1);
        ASSERT_SUCCESS(testing_channel_push_read_data(&tester.testing_channel, one_byte));
        testing_channel_drain_queued_tasks(&tester.testing_channel);
    }

    ASSERT_UINT_EQUALS(10, stream_tester.response_body.len);

    struct aws_h1_window_stats window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_UINT_EQUALS(0, window_stats.stream_window);
    ASSERT_UINT_EQUALS(0, window_stats.buffer_pending_bytes);
    ASSERT_UINT_EQUALS(5, window_stats.buffer_capacity);

    /* now that stream's window is 0, further data should fill the connection's read-buffer */
    for (int i = 0; i < 5; ++i) {
        struct aws_byte_cursor one_byte = aws_byte_cursor_advance(&response_cursor, 1);
        ASSERT_SUCCESS(testing_channel_push_read_data(&tester.testing_channel, one_byte));
    }
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_UINT_EQUALS(5, window_stats.buffer_pending_bytes);

    /* open the stream's window enough to finish the response, the buffered bytes should be consumed */
    aws_http_stream_update_window(stream_tester.stream, SIZE_MAX);
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_UINT_EQUALS(15, stream_tester.response_body.len);

    window_stats = aws_h1_connection_window_stats(tester.connection);
    ASSERT_UINT_EQUALS(0, window_stats.buffer_pending_bytes);

    /* send the remainder of the response */
    while (response_cursor.len > 0) {
        struct aws_byte_cursor one_byte = aws_byte_cursor_advance(&response_cursor, 1);
        ASSERT_SUCCESS(testing_channel_push_read_data(&tester.testing_channel, one_byte));
        testing_channel_drain_queued_tasks(&tester.testing_channel);
    }
    ASSERT_UINT_EQUALS(20, stream_tester.response_body.len);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_UINT_EQUALS(0, stream_tester.on_complete_error_code);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    aws_http_message_release(request);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT, completion_error_code);

    /* clean up */
    aws_input_stream_release(body_stream);
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

static int s_test_chunk_length_mismatch_is_error(
    struct aws_allocator *allocator,
    const char *body,
    size_t wrong_length) {

    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    const struct aws_byte_cursor body_cur = aws_byte_cursor_from_c_str(body);
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body_cur);

    /* send request */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);

    int completion_error_code = 0;
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
        .on_complete = s_on_complete,
        .user_data = &completion_error_code,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    /* Initialize with an off by one body length */
    struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, wrong_length);
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* check result */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT, completion_error_code);

    /* clean up */
    aws_http_message_destroy(request);
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

H1_CLIENT_TEST_CASE(h1_client_request_chunk_size_too_small_is_error) {
    (void)ctx;
    return s_test_chunk_length_mismatch_is_error(allocator, "I am very long", 2);
}

H1_CLIENT_TEST_CASE(h1_client_request_chunk_size_too_large_is_error) {
    (void)ctx;
    return s_test_chunk_length_mismatch_is_error(allocator, "I am very short", 999);
}

H1_CLIENT_TEST_CASE(h1_client_request_chunks_cancelled_by_channel_shutdown) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_message *request = s_new_default_chunked_put_request(allocator);
    int completion_error_code = 0;
    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
        .user_data = &completion_error_code,
        .on_complete = s_on_complete,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));
    const struct aws_byte_cursor body_cur = aws_byte_cursor_from_c_str("write more tests");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body_cur);

    /* This will "pause" the connection loop as there is an empty stream. */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Now write 2 chunks. The chunk memory should be automatically released when the http stream is destroyed. */
    struct aws_http1_chunk_options options = s_default_chunk_options(body_stream, body_cur.len);
    ASSERT_SUCCESS(aws_http1_stream_write_chunk(stream, &options));
    ASSERT_SUCCESS(s_write_termination_chunk(allocator, stream));

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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

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
        ASSERT_SUCCESS(aws_http_stream_activate(streams[i]));
    }

    /* 2 streams are now in-progress */
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Make 1 more stream that's still locked away in the pending queue */
    opt.user_data = &completion_error_codes[2];
    streams[2] = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(streams[2]);
    ASSERT_SUCCESS(aws_http_stream_activate(streams[2]));

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
    struct aws_input_stream base;
    enum request_callback error_at;
    int callback_counts[REQUEST_CALLBACK_COUNT];
    bool has_errored;
    struct aws_stream_status status;
    int on_complete_error_code;
    struct aws_allocator *alloc;
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

    struct error_from_callback_tester *error_tester = AWS_CONTAINER_OF(body, struct error_from_callback_tester, base);
    if (s_error_from_callback_common(error_tester, REQUEST_CALLBACK_OUTGOING_BODY)) {
        return AWS_OP_ERR;
    }

    /* If the common fn was successful, write out some data and end the stream */
    ASSERT_TRUE(aws_byte_buf_write(dest, (const uint8_t *)"abcd", 4));
    error_tester->status.is_end_of_stream = true;
    return AWS_OP_SUCCESS;
}

static int s_error_from_outgoing_body_get_status(struct aws_input_stream *body, struct aws_stream_status *status) {
    struct error_from_callback_tester *error_tester = AWS_CONTAINER_OF(body, struct error_from_callback_tester, base);
    *status = error_tester->status;
    return AWS_OP_SUCCESS;
}

static void s_error_from_outgoing_body_destroy(struct aws_input_stream *stream) {
    (void)stream;
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

    struct aws_input_stream empty_stream_base;
    AWS_ZERO_STRUCT(empty_stream_base);
    struct error_from_callback_tester error_tester = {
        .base = empty_stream_base,
        .error_at = error_at,
        .status =
            {
                .is_valid = true,
                .is_end_of_stream = false,
            },
    };
    error_tester.base.vtable = &s_error_from_outgoing_body_vtable;
    aws_ref_count_init(
        &error_tester.base.ref_count,
        &error_tester,
        (aws_simple_completion_callback *)s_error_from_outgoing_body_destroy);
    struct aws_input_stream *error_from_outgoing_body_stream = &error_tester.base;
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
    aws_http_message_set_body_stream(request, error_from_outgoing_body_stream);

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
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(opt.request);
    aws_input_stream_release(error_from_outgoing_body_stream);

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

static void s_unactivated_stream_cleans_up_on_destroy(void *data) {
    bool *destroyed = data;
    *destroyed = true;
}

H1_CLIENT_TEST_CASE(h1_client_unactivated_stream_cleans_up) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_TRUE(aws_http_connection_is_open(tester.connection));
    bool destroyed = false;

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("GET")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));

    struct aws_http_make_request_options options = {
        .self_size = sizeof(struct aws_http_make_request_options),
        .request = request,
        .on_destroy = s_unactivated_stream_cleans_up_on_destroy,
        .user_data = &destroyed,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &options);
    aws_http_message_release(request);
    ASSERT_NOT_NULL(stream);
    /* we do not activate, that is the test. */
    ASSERT_FALSE(destroyed);
    aws_http_stream_release(stream);
    ASSERT_TRUE(destroyed);
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
    ASSERT_SUCCESS(aws_http_stream_activate(upgrade_stream));
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

H1_CLIENT_TEST_CASE(h1_client_new_request_allowed) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* prepare request */
    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = s_new_default_get_request(allocator),
    };

    /* validate the new request is allowed for now */
    ASSERT_TRUE(aws_http_connection_new_requests_allowed(tester.connection));

    /* switch protocols */
    struct protocol_switcher switcher = {
        .tester = &tester,
        .install_downstream_handler = true,
    };
    ASSERT_SUCCESS(s_switch_protocols(&switcher));

    /* validate the new request is not allowed anymore when goaway received */
    ASSERT_FALSE(aws_http_connection_new_requests_allowed(tester.connection));
    /* Make new request will fail */
    ASSERT_NULL(aws_http_connection_make_request(tester.connection, &options));
    ASSERT_UINT_EQUALS(AWS_ERROR_HTTP_SWITCHED_PROTOCOLS, aws_last_error());

    /* close connection */
    aws_http_connection_close(tester.connection);
    /* Make new request will fail */
    ASSERT_NULL(aws_http_connection_make_request(tester.connection, &options));
    ASSERT_UINT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, aws_last_error());

    /* clean up */
    aws_http_message_destroy(options.request);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
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

H1_CLIENT_TEST_CASE(h1_client_connection_close_before_request_finishes) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* set up request whose body won't send immediately */
    struct slow_body_sender body_sender;
    AWS_ZERO_STRUCT(body_sender);
    s_slow_body_sender_init(&body_sender);
    struct aws_input_stream *body_stream = &body_sender.base;

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
    aws_http_message_set_body_stream(request, body_stream);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    /* send head of request */
    testing_channel_run_currently_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);
    aws_input_stream_release(body_stream);

    /* send close connection response */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 404 Not Found\r\n"
        "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
        "\r\n"));

    testing_channel_run_currently_queued_tasks(&tester.testing_channel);

    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    /* Wait for channel to finish shutdown */
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    /* check result, should not receive any body */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Content-Length: 16\r\n"
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* When response has `connection: close` any further request body should not be sent. */
H1_CLIENT_TEST_CASE(h1_client_response_close_connection_before_request_finishes) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* set up request whose body won't send immediately */
    struct slow_body_sender body_sender;
    AWS_ZERO_STRUCT(body_sender);
    s_slow_body_sender_init(&body_sender);
    struct aws_input_stream *body_stream = &body_sender.base;

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
    aws_http_message_set_body_stream(request, body_stream);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, &tester, request));

    /* send head of request */
    testing_channel_run_currently_queued_tasks(&tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_destroy(request);
    aws_input_stream_release(body_stream);

    /* send close connection response */
    ASSERT_SUCCESS(testing_channel_push_read_str(
        &tester.testing_channel,
        "HTTP/1.1 404 Not Found\r\n"
        "Date: Fri, 01 Mar 2019 17:18:55 GMT\r\n"
        "Connection: close\r\n"
        "\r\n"));

    testing_channel_drain_queued_tasks(&tester.testing_channel);
    /* check result, should not receive any body */
    const char *expected = "PUT /plan.txt HTTP/1.1\r\n"
                           "Content-Length: 16\r\n"
                           "\r\n";
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));
    /* Check if the testing channel has shut down. */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);

    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
