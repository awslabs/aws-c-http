/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/h1_encoder.h>

#include <aws/common/array_list.h>
#include <aws/io/logging.h>
#include <aws/testing/aws_test_harness.h>

#include <aws/io/stream.h>
#include <ctype.h>
#include <stdio.h>

#define H1_ENCODER_TEST_CASE(NAME)                                                                                     \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

static struct aws_logger s_logger;

static void s_test_init(struct aws_allocator *allocator) {
    aws_http_library_init(allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    aws_logger_init_standard(&s_logger, allocator, &logger_options);
    aws_logger_set(&s_logger);
}

static void s_test_clean_up(void) {
    aws_http_library_clean_up();
    aws_logger_clean_up(&s_logger);
}

H1_ENCODER_TEST_CASE(h1_encoder_content_length_put_request_headers) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("16"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));
    aws_http_message_set_body_stream(request, body_stream);

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;
    aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list);

    ASSERT_FALSE(encoder_message.has_chunked_encoding_header);
    ASSERT_FALSE(encoder_message.has_connection_close_header);
    ASSERT_UINT_EQUALS(body.len, encoder_message.content_length);

    aws_input_stream_destroy(body_stream);
    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_chunked_put_request_headers) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;
    aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list);

    ASSERT_TRUE(encoder_message.has_chunked_encoding_header);
    ASSERT_FALSE(encoder_message.has_connection_close_header);
    ASSERT_UINT_EQUALS(0, encoder_message.content_length);

    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_chunked_put_request_multiple_te_headers) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("gzip"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;
    aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list);

    ASSERT_TRUE(encoder_message.has_chunked_encoding_header);
    ASSERT_FALSE(encoder_message.has_connection_close_header);
    ASSERT_UINT_EQUALS(0, encoder_message.content_length);

    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_chunked_put_request_headers_case_insensitivity) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("traNsfeR-EncODIng"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;
    aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list);

    ASSERT_TRUE(encoder_message.has_chunked_encoding_header);
    ASSERT_FALSE(encoder_message.has_connection_close_header);
    ASSERT_UINT_EQUALS(0, encoder_message.content_length);

    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_not_chunked_put_request_headers) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("gzip"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));
    aws_http_message_set_body_stream(request, body_stream);

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;
    aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list);

    ASSERT_FALSE(encoder_message.has_chunked_encoding_header);
    ASSERT_FALSE(encoder_message.has_connection_close_header);
    ASSERT_UINT_EQUALS(0, encoder_message.content_length);

    aws_input_stream_destroy(body_stream);
    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_set_body_stream_errors) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));
    /* Setting the body stream should cause an error */
    aws_http_message_set_body_stream(request, body_stream);

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;
    aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list);

    ASSERT_FALSE(encoder_message.has_chunked_encoding_header);
    ASSERT_FALSE(encoder_message.has_connection_close_header);
    ASSERT_UINT_EQUALS(0, encoder_message.content_length);

    aws_input_stream_destroy(body_stream);
    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_not_ending_in_chunked_put_request_headers) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("gzip"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;
    aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list);

    ASSERT_FALSE(encoder_message.has_chunked_encoding_header);
    ASSERT_FALSE(encoder_message.has_connection_close_header);
    ASSERT_UINT_EQUALS(0, encoder_message.content_length);

    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_chunked_multiple_put_request_headers) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("gzip, chunked"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;
    aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list);

    ASSERT_TRUE(encoder_message.has_chunked_encoding_header);
    ASSERT_FALSE(encoder_message.has_connection_close_header);
    ASSERT_UINT_EQUALS(0, encoder_message.content_length);

    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_chunked_and_content_length_put_request_headers) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */
    static const struct aws_byte_cursor body = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("write more tests");
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body);

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("16"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;

    /* Per RFC 2656 (https://tools.ietf.org/html/rfc2616#section-4.4), if both the Content-Length and Transfer-Encoding
     * header are defined, the client should not send the request. */
    ASSERT_INT_EQUALS(
        AWS_OP_ERR, aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list));

    aws_input_stream_destroy(body_stream);
    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

H1_ENCODER_TEST_CASE(h1_encoder_transfer_encoding_chunked_not_final_encoding_put_request_headers) {
    (void)ctx;
    s_test_init(allocator);
    struct aws_h1_encoder encoder;
    aws_h1_encoder_init(&encoder, allocator);

    /* request to send - we won't actually send it, we want to validate headers are set correctly. */

    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Transfer-Encoding"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("chunked;gzip"), /* must end with chunked */
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

    struct aws_linked_list chunk_list;
    aws_linked_list_init(&chunk_list);

    struct aws_h1_encoder_message encoder_message;

    /* Per RFC 2656 (https://tools.ietf.org/html/rfc2616#section-4.4), if both the Content-Length and Transfer-Encoding
     * header are defined, the client should not send the request. */
    ASSERT_INT_EQUALS(
        AWS_OP_ERR, aws_h1_encoder_message_init_from_request(&encoder_message, allocator, request, &chunk_list));

    aws_http_message_destroy(request);
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_h1_encoder_clean_up(&encoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}
