/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/http/private/h2_frames.h>
#include <aws/http/private/hpack.h>

enum { S_BUFFER_SIZE = 128 };

struct header_test_fixture;

/* Function type used to init and cleanup a fixture */
typedef int(header_init_fn)(struct header_test_fixture *);
/* Function used to tear down header instances */
typedef int(header_clean_up_fn)(void *);

/* Header compare function */
static int s_header_block_eq(
    const struct aws_http_headers *l_header_fields,
    const struct aws_http_headers *r_header_fields) {

    const size_t l_size = aws_http_headers_count(l_header_fields);
    const size_t r_size = aws_http_headers_count(r_header_fields);
    ASSERT_UINT_EQUALS(l_size, r_size);

    for (size_t i = 0; i < l_size; ++i) {
        struct aws_http_header l_field;
        ASSERT_SUCCESS(aws_http_headers_get_index(l_header_fields, i, &l_field));

        struct aws_http_header r_field;
        ASSERT_SUCCESS(aws_http_headers_get_index(r_header_fields, i, &r_field));

        ASSERT_INT_EQUALS(l_field.compression, r_field.compression);
        ASSERT_TRUE(aws_byte_cursor_eq(&l_field.name, &r_field.name));
        ASSERT_TRUE(aws_byte_cursor_eq(&l_field.value, &r_field.value));
    }

    return AWS_OP_SUCCESS;
}

/* Contains all of the information required to run a header's test case */
struct header_test_fixture {
    header_init_fn *init;
    header_clean_up_fn *header_clean_up;
    header_init_fn *teardown;

    struct aws_allocator *allocator;
    bool one_byte_at_a_time; /* T: decode one byte at a time. F: decode whole buffer at once */

    struct aws_hpack_context *encoder;
    struct aws_hpack_context *decoder;

    struct aws_http_headers *headers_to_encode;
    struct aws_byte_buf expected_encoding_buf;
    struct aws_http_headers *decoded_headers;
};

static int s_header_test_before(struct aws_allocator *allocator, void *ctx) {

    struct header_test_fixture *fixture = ctx;
    fixture->allocator = allocator;

    aws_http_library_init(allocator);

    fixture->encoder = aws_hpack_context_new(allocator, AWS_LS_HTTP_ENCODER, NULL);
    ASSERT_NOT_NULL(fixture->encoder);
    fixture->decoder = aws_hpack_context_new(allocator, AWS_LS_HTTP_DECODER, NULL);
    ASSERT_NOT_NULL(fixture->decoder);
    fixture->headers_to_encode = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(fixture->headers_to_encode);

    ASSERT_SUCCESS(aws_byte_buf_init(&fixture->expected_encoding_buf, allocator, S_BUFFER_SIZE));
    fixture->decoded_headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(fixture->decoded_headers);

    return AWS_OP_SUCCESS;
}

static int s_header_test_run(struct aws_allocator *allocator, void *ctx) {

    struct header_test_fixture *fixture = ctx;

    /* Init the in_header & buffer */
    ASSERT_SUCCESS(fixture->init(fixture));

    /* Encode */

    /* Create the output buffer */
    struct aws_byte_buf output_buffer;
    ASSERT_SUCCESS(aws_byte_buf_init(&output_buffer, allocator, S_BUFFER_SIZE));

    /* Encode the headers */
    ASSERT_SUCCESS(aws_hpack_encode_header_block(fixture->encoder, fixture->headers_to_encode, &output_buffer));

    /* Compare the encoded output against the expected header block fragment */
    ASSERT_BIN_ARRAYS_EQUALS(
        fixture->expected_encoding_buf.buffer,
        fixture->expected_encoding_buf.len,
        output_buffer.buffer,
        output_buffer.len);

    /* Decode */
    struct aws_byte_cursor payload = aws_byte_cursor_from_buf(&output_buffer);
    while (payload.len) {
        struct aws_hpack_decode_result result;

        if (fixture->one_byte_at_a_time) {
            struct aws_byte_cursor one_byte_payload = aws_byte_cursor_advance(&payload, 1);
            ASSERT_SUCCESS(aws_hpack_decode(fixture->decoder, &one_byte_payload, &result));
            ASSERT_UINT_EQUALS(0, one_byte_payload.len);
        } else {
            ASSERT_SUCCESS(aws_hpack_decode(fixture->decoder, &payload, &result));
        }

        if (result.type == AWS_HPACK_DECODE_T_HEADER_FIELD) {
            ASSERT_SUCCESS(aws_http_headers_add_header(fixture->decoded_headers, &result.data.header_field));
        }
    }

    /* Compare the headers */
    ASSERT_SUCCESS(s_header_block_eq(fixture->headers_to_encode, fixture->decoded_headers));

    aws_byte_buf_clean_up(&output_buffer);
    return AWS_OP_SUCCESS;
}

static int s_header_test_after(struct aws_allocator *allocator, int setup_res, void *ctx) {

    (void)allocator;

    if (!setup_res) {
        struct header_test_fixture *fixture = ctx;

        /* Tear down the header & buffer */
        if (fixture->teardown) {
            fixture->teardown(fixture);
        }

        /* Tear down the fixture */
        aws_http_headers_release(fixture->decoded_headers);
        aws_byte_buf_clean_up(&fixture->expected_encoding_buf);
        aws_http_headers_release(fixture->headers_to_encode);
        aws_hpack_context_destroy(fixture->decoder);
        aws_hpack_context_destroy(fixture->encoder);
    }
    aws_http_library_clean_up();

    return AWS_OP_SUCCESS;
}

#define HEADER_TEST(t_name, i, t)                                                                                      \
    static struct header_test_fixture s_##t_name##_fixture = {                                                         \
        .init = (i),                                                                                                   \
        .teardown = (t),                                                                                               \
    };                                                                                                                 \
    AWS_TEST_CASE_FIXTURE(t_name, s_header_test_before, s_header_test_run, s_header_test_after, &s_##t_name##_fixture) \
    static struct header_test_fixture s_##t_name##_one_byte_at_a_time_fixture = {                                      \
        .init = (i),                                                                                                   \
        .teardown = (t),                                                                                               \
        .one_byte_at_a_time = true,                                                                                    \
    };                                                                                                                 \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        t_name##_one_byte_at_a_time,                                                                                   \
        s_header_test_before,                                                                                          \
        s_header_test_run,                                                                                             \
        s_header_test_after,                                                                                           \
        &s_##t_name##_one_byte_at_a_time_fixture)

#define DEFINE_STATIC_HEADER(_key, _value, _behavior)                                                                  \
    {                                                                                                                  \
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_key), .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_value),   \
        .compression = AWS_HTTP_HEADER_COMPRESSION_##_behavior,                                                        \
    }

/* Test HEADERS frame with empty payload */
static int s_test_empty_payload(struct header_test_fixture *fixture) {
    (void)fixture;
    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_empty_payload, s_test_empty_payload, NULL);

/* RFC-7541 - Header Field Representation Examples - C.2.1. Literal Header Field with Indexing */
static int s_test_ex_2_1_init(struct header_test_fixture *fixture) {

    aws_hpack_set_huffman_mode(fixture->encoder, AWS_HPACK_HUFFMAN_NEVER);

    struct aws_http_header headers[] = {
        DEFINE_STATIC_HEADER("custom-key", "custom-header", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode, headers, AWS_ARRAY_SIZE(headers)));

    static const uint8_t encoded[] = {
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0d,
        0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_2_1, s_test_ex_2_1_init, NULL);

/* RFC-7541 - Header Field Representation Examples - C.2.2. Literal Header Field without Indexing */
static int s_test_ex_2_2_init(struct header_test_fixture *fixture) {

    aws_hpack_set_huffman_mode(fixture->encoder, AWS_HPACK_HUFFMAN_NEVER);

    struct aws_http_header headers[] = {
        DEFINE_STATIC_HEADER(":path", "/sample/path", NO_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode, headers, AWS_ARRAY_SIZE(headers)));

    static const uint8_t encoded[] = {
        0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68};

    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_2_2, s_test_ex_2_2_init, NULL);

/* RFC-7541 - Header Field Representation Examples - C.2.3. Literal Header Field Never Indexed */
static int s_test_ex_2_3_init(struct header_test_fixture *fixture) {

    aws_hpack_set_huffman_mode(fixture->encoder, AWS_HPACK_HUFFMAN_NEVER);

    struct aws_http_header headers[] = {
        DEFINE_STATIC_HEADER("password", "secret", NO_FORWARD_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode, headers, AWS_ARRAY_SIZE(headers)));

    static const uint8_t encoded[] = {
        0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74};

    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_2_3, s_test_ex_2_3_init, NULL);

/* RFC-7541 - Header Field Representation Examples - C.2.3. Indexed Header Field */
static int s_test_ex_2_4_init(struct header_test_fixture *fixture) {

    aws_hpack_set_huffman_mode(fixture->encoder, AWS_HPACK_HUFFMAN_NEVER);

    struct aws_http_header headers[] = {
        DEFINE_STATIC_HEADER(":method", "GET", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode, headers, AWS_ARRAY_SIZE(headers)));

    static const uint8_t encoded[] = {
        0x82,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_2_4, s_test_ex_2_4_init, NULL);

struct header_request_response_test_fixture;
/* Function type used to init for request and response */
typedef int(header_request_response_init_fn)(struct header_request_response_test_fixture *);

/* Contains all of the information required to run a header's test case */
struct header_request_response_test_fixture {
    header_request_response_init_fn *init;
    header_clean_up_fn *header_clean_up;
    header_request_response_init_fn *teardown;

    struct aws_allocator *allocator;
    bool one_byte_at_a_time; /* T: decode one byte at a time. F: decode whole buffer at once */

    struct aws_hpack_context *encoder;
    struct aws_hpack_context *decoder;

    struct aws_http_headers *headers_to_encode[3];
    struct aws_byte_buf expected_encoding_buf[3];
    struct aws_http_header last_entry_dynamic_table[3];
    size_t dynamic_table_len[3];

    struct aws_http_headers *decoded_headers;
};

static int s_header_request_response_test_before(struct aws_allocator *allocator, void *ctx) {

    struct header_request_response_test_fixture *fixture = ctx;
    fixture->allocator = allocator;

    aws_http_library_init(allocator);

    fixture->encoder = aws_hpack_context_new(allocator, AWS_LS_HTTP_ENCODER, NULL);
    ASSERT_NOT_NULL(fixture->encoder);
    fixture->decoder = aws_hpack_context_new(allocator, AWS_LS_HTTP_DECODER, NULL);
    ASSERT_NOT_NULL(fixture->decoder);
    for (int i = 0; i < 3; i++) {
        fixture->headers_to_encode[i] = aws_http_headers_new(allocator);
        ASSERT_NOT_NULL(fixture->headers_to_encode[i]);
        ASSERT_SUCCESS(aws_byte_buf_init(&fixture->expected_encoding_buf[i], allocator, S_BUFFER_SIZE));
    }

    fixture->decoded_headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(fixture->decoded_headers);

    return AWS_OP_SUCCESS;
}

static int s_encoder_result_check(
    struct header_request_response_test_fixture *fixture,
    struct aws_http_headers *headers_to_encode,
    struct aws_byte_buf expected_encoding_buf,
    struct aws_byte_buf *output_buffer) {
    /* Encode the headers */
    ASSERT_SUCCESS(aws_hpack_encode_header_block(fixture->encoder, headers_to_encode, output_buffer));

    /* Compare the encoded output against the expected header block fragment */
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_encoding_buf.buffer, expected_encoding_buf.len, output_buffer->buffer, output_buffer->len);

    /* Decode */
    struct aws_byte_cursor payload = aws_byte_cursor_from_buf(output_buffer);
    while (payload.len) {
        struct aws_hpack_decode_result result;

        if (fixture->one_byte_at_a_time) {
            struct aws_byte_cursor one_byte_payload = aws_byte_cursor_advance(&payload, 1);
            ASSERT_SUCCESS(aws_hpack_decode(fixture->decoder, &one_byte_payload, &result));
            ASSERT_UINT_EQUALS(0, one_byte_payload.len);
        } else {
            ASSERT_SUCCESS(aws_hpack_decode(fixture->decoder, &payload, &result));
        }

        if (result.type == AWS_HPACK_DECODE_T_HEADER_FIELD) {
            ASSERT_SUCCESS(aws_http_headers_add_header(fixture->decoded_headers, &result.data.header_field));
        }
    }

    /* Compare the headers */
    ASSERT_SUCCESS(s_header_block_eq(headers_to_encode, fixture->decoded_headers));
    /* Reset state */
    aws_byte_buf_reset(output_buffer, false);
    aws_http_headers_clear(fixture->decoded_headers);
    return AWS_OP_SUCCESS;
}

static int s_dynamic_table_last_entry_check(
    struct header_request_response_test_fixture *fixture,
    struct aws_http_header *expected_entry,
    size_t dynamic_table_len) {
    /* check the decoder's dynamic table */
    struct aws_hpack_context *context = fixture->decoder;
    /* get the last element in dynamic table, which will be the absolute index plus all the elements in static table */
    ASSERT_TRUE(dynamic_table_len == aws_hpack_get_dynamic_table_num_elements(context));
    const struct aws_http_header *back = aws_hpack_get_header(context, dynamic_table_len + 61);
    ASSERT_TRUE(aws_byte_cursor_eq(&back->name, &expected_entry->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&back->value, &expected_entry->value));
    /* check the encoder's dynamic table */
    context = fixture->encoder;
    ASSERT_TRUE(dynamic_table_len == aws_hpack_get_dynamic_table_num_elements(context));
    back = aws_hpack_get_header(context, dynamic_table_len + 61);
    ASSERT_TRUE(aws_byte_cursor_eq(&back->name, &expected_entry->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&back->value, &expected_entry->value));
    return AWS_OP_SUCCESS;
}

static int s_header_request_response_test_run(struct aws_allocator *allocator, void *ctx) {

    struct header_request_response_test_fixture *fixture = ctx;

    /* Init the in_header & buffer */
    ASSERT_SUCCESS(fixture->init(fixture));

    /* Encode */

    /* Create the output buffer */
    struct aws_byte_buf output_buffer;
    ASSERT_SUCCESS(aws_byte_buf_init(&output_buffer, allocator, S_BUFFER_SIZE));
    /* check three results */
    for (int i = 0; i < 3; i++) {
        ASSERT_SUCCESS(s_encoder_result_check(
            fixture, fixture->headers_to_encode[i], fixture->expected_encoding_buf[i], &output_buffer));
        ASSERT_SUCCESS(s_dynamic_table_last_entry_check(
            fixture, &fixture->last_entry_dynamic_table[i], fixture->dynamic_table_len[i]));
    }

    aws_byte_buf_clean_up(&output_buffer);
    return AWS_OP_SUCCESS;
}

static int s_header_request_response_test_after(struct aws_allocator *allocator, int setup_res, void *ctx) {

    (void)allocator;

    if (!setup_res) {
        struct header_request_response_test_fixture *fixture = ctx;

        /* Tear down the header & buffer */
        if (fixture->teardown) {
            fixture->teardown(fixture);
        }

        /* Tear down the fixture */
        aws_http_headers_release(fixture->decoded_headers);
        for (int i = 0; i < 3; i++) {
            aws_byte_buf_clean_up(&fixture->expected_encoding_buf[i]);
            aws_http_headers_release(fixture->headers_to_encode[i]);
        }
        aws_hpack_context_destroy(fixture->decoder);
        aws_hpack_context_destroy(fixture->encoder);
    }
    aws_http_library_clean_up();

    return AWS_OP_SUCCESS;
}

#define HEADER_REQUEST_RESPONSE_TEST(t_name, i, t)                                                                     \
    static struct header_request_response_test_fixture s_##t_name##_fixture = {                                        \
        .init = (i),                                                                                                   \
        .teardown = (t),                                                                                               \
    };                                                                                                                 \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        t_name,                                                                                                        \
        s_header_request_response_test_before,                                                                         \
        s_header_request_response_test_run,                                                                            \
        s_header_request_response_test_after,                                                                          \
        &s_##t_name##_fixture)                                                                                         \
    static struct header_request_response_test_fixture s_##t_name##_one_byte_at_a_time_fixture = {                     \
        .init = (i),                                                                                                   \
        .teardown = (t),                                                                                               \
        .one_byte_at_a_time = true,                                                                                    \
    };                                                                                                                 \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        t_name##_one_byte_at_a_time,                                                                                   \
        s_header_request_response_test_before,                                                                         \
        s_header_request_response_test_run,                                                                            \
        s_header_request_response_test_after,                                                                          \
        &s_##t_name##_one_byte_at_a_time_fixture)

/* RFC-7541 - Request Examples without Huffman Coding - C.3 */
static int s_test_ex_3_init(struct header_request_response_test_fixture *fixture) {

    aws_hpack_set_huffman_mode(fixture->encoder, AWS_HPACK_HUFFMAN_NEVER);
    int index = 0;
    /* First Request RFC-7541 C.3.1 */
    struct aws_http_header headers_1[] = {
        DEFINE_STATIC_HEADER(":method", "GET", USE_CACHE),
        DEFINE_STATIC_HEADER(":scheme", "http", USE_CACHE),
        DEFINE_STATIC_HEADER(":path", "/", USE_CACHE),
        DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_1, AWS_ARRAY_SIZE(headers_1)));

    static const uint8_t encoded_1[] = {
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_1, sizeof(encoded_1));

    struct aws_http_header last_entry_1 = DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_1;
    fixture->dynamic_table_len[index] = 1;
    index++;

    /* Second Request RFC-7541 C.3.2 */
    struct aws_http_header headers_2[] = {
        DEFINE_STATIC_HEADER(":method", "GET", USE_CACHE),
        DEFINE_STATIC_HEADER(":scheme", "http", USE_CACHE),
        DEFINE_STATIC_HEADER(":path", "/", USE_CACHE),
        DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE),
        DEFINE_STATIC_HEADER("cache-control", "no-cache", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_2, AWS_ARRAY_SIZE(headers_2)));

    static const uint8_t encoded_2[] = {
        0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65};
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_2, sizeof(encoded_2));

    struct aws_http_header last_entry_2 = DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_2;
    fixture->dynamic_table_len[index] = 2;
    index++;

    /* Third Request RFC-7541 C.3.3 */
    struct aws_http_header headers_3[] = {
        DEFINE_STATIC_HEADER(":method", "GET", USE_CACHE),
        DEFINE_STATIC_HEADER(":scheme", "https", USE_CACHE),
        DEFINE_STATIC_HEADER(":path", "/index.html", USE_CACHE),
        DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE),
        DEFINE_STATIC_HEADER("custom-key", "custom-value", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_3, AWS_ARRAY_SIZE(headers_3)));

    static const uint8_t encoded_3[] = {
        0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
        0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_3, sizeof(encoded_3));

    struct aws_http_header last_entry_3 = DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_3;
    fixture->dynamic_table_len[index] = 3;

    return AWS_OP_SUCCESS;
}
HEADER_REQUEST_RESPONSE_TEST(h2_header_ex_3, s_test_ex_3_init, NULL);

/* RFC-7541 - Request Examples with Huffman Coding - C.4 */
static int s_test_ex_4_init(struct header_request_response_test_fixture *fixture) {

    aws_hpack_set_huffman_mode(fixture->encoder, AWS_HPACK_HUFFMAN_ALWAYS);
    int index = 0;
    /* First Request RFC-7541 C.4.1 */
    struct aws_http_header headers_1[] = {
        DEFINE_STATIC_HEADER(":method", "GET", USE_CACHE),
        DEFINE_STATIC_HEADER(":scheme", "http", USE_CACHE),
        DEFINE_STATIC_HEADER(":path", "/", USE_CACHE),
        DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_1, AWS_ARRAY_SIZE(headers_1)));

    static const uint8_t encoded_1[] = {
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};

    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_1, sizeof(encoded_1));

    struct aws_http_header last_entry_1 = DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_1;
    fixture->dynamic_table_len[index] = 1;
    index++;

    /* Second Request RFC-7541 C.4.2 */
    struct aws_http_header headers_2[] = {
        DEFINE_STATIC_HEADER(":method", "GET", USE_CACHE),
        DEFINE_STATIC_HEADER(":scheme", "http", USE_CACHE),
        DEFINE_STATIC_HEADER(":path", "/", USE_CACHE),
        DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE),
        DEFINE_STATIC_HEADER("cache-control", "no-cache", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_2, AWS_ARRAY_SIZE(headers_2)));

    static const uint8_t encoded_2[] = {0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_2, sizeof(encoded_2));

    struct aws_http_header last_entry_2 = DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_2;
    fixture->dynamic_table_len[index] = 2;
    index++;

    /* Third Request RFC-7541 C.4.3 */
    struct aws_http_header headers_3[] = {
        DEFINE_STATIC_HEADER(":method", "GET", USE_CACHE),
        DEFINE_STATIC_HEADER(":scheme", "https", USE_CACHE),
        DEFINE_STATIC_HEADER(":path", "/index.html", USE_CACHE),
        DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE),
        DEFINE_STATIC_HEADER("custom-key", "custom-value", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_3, AWS_ARRAY_SIZE(headers_3)));

    static const uint8_t encoded_3[] = {
        0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9,
        0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_3, sizeof(encoded_3));

    struct aws_http_header last_entry_3 = DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_3;
    fixture->dynamic_table_len[index] = 3;

    return AWS_OP_SUCCESS;
}
HEADER_REQUEST_RESPONSE_TEST(h2_header_ex_4, s_test_ex_4_init, NULL);

/* RFC-7541 - Response Examples without Huffman Coding - C.5 */
static int s_test_ex_5_init(struct header_request_response_test_fixture *fixture) {

    /* set the max table size to 256 */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(fixture->encoder, 256));
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(fixture->decoder, 256));

    aws_hpack_set_huffman_mode(fixture->encoder, AWS_HPACK_HUFFMAN_NEVER);
    int index = 0;
    /* First Response RFC-7541 C.5.1 */
    struct aws_http_header headers_1[] = {
        DEFINE_STATIC_HEADER(":status", "302", USE_CACHE),
        DEFINE_STATIC_HEADER("cache-control", "private", USE_CACHE),
        DEFINE_STATIC_HEADER("date", "Mon, 21 Oct 2013 20:13:21 GMT", USE_CACHE),
        DEFINE_STATIC_HEADER("location", "https://www.example.com", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_1, AWS_ARRAY_SIZE(headers_1)));

    static const uint8_t encoded_1[] = {
        0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x61, 0x1d, 0x4d, 0x6f,
        0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a,
        0x31, 0x33, 0x3a, 0x32, 0x31, 0x20, 0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
        0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_1, sizeof(encoded_1));

    struct aws_http_header last_entry_1 = DEFINE_STATIC_HEADER(":status", "302", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_1;
    fixture->dynamic_table_len[index] = 4;
    index++;

    /* Second Response RFC-7541 C.5.2 */
    struct aws_http_header headers_2[] = {
        DEFINE_STATIC_HEADER(":status", "307", USE_CACHE),
        DEFINE_STATIC_HEADER("cache-control", "private", USE_CACHE),
        DEFINE_STATIC_HEADER("date", "Mon, 21 Oct 2013 20:13:21 GMT", USE_CACHE),
        DEFINE_STATIC_HEADER("location", "https://www.example.com", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_2, AWS_ARRAY_SIZE(headers_2)));

    static const uint8_t encoded_2[] = {0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf};
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_2, sizeof(encoded_2));

    struct aws_http_header last_entry_2 = DEFINE_STATIC_HEADER("cache-control", "private", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_2;
    fixture->dynamic_table_len[index] = 4;
    index++;

    /* Third Response RFC-7541 C.5.3 */
    struct aws_http_header headers_3[] = {
        DEFINE_STATIC_HEADER(":status", "200", USE_CACHE),
        DEFINE_STATIC_HEADER("cache-control", "private", USE_CACHE),
        DEFINE_STATIC_HEADER("date", "Mon, 21 Oct 2013 20:13:22 GMT", USE_CACHE),
        DEFINE_STATIC_HEADER("location", "https://www.example.com", USE_CACHE),
        DEFINE_STATIC_HEADER("content-encoding", "gzip", USE_CACHE),
        DEFINE_STATIC_HEADER("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_3, AWS_ARRAY_SIZE(headers_3)));

    static const uint8_t encoded_3[] = {
        0x88, 0xc1, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32,
        0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x32, 0x20, 0x47, 0x4d, 0x54, 0xc0,
        0x5a, 0x04, 0x67, 0x7a, 0x69, 0x70, 0x77, 0x38, 0x66, 0x6f, 0x6f, 0x3d, 0x41, 0x53, 0x44, 0x4a, 0x4b,
        0x48, 0x51, 0x4b, 0x42, 0x5a, 0x58, 0x4f, 0x51, 0x57, 0x45, 0x4f, 0x50, 0x49, 0x55, 0x41, 0x58, 0x51,
        0x57, 0x45, 0x4f, 0x49, 0x55, 0x3b, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, 0x3d, 0x33, 0x36,
        0x30, 0x30, 0x3b, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x31,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_3, sizeof(encoded_3));

    struct aws_http_header last_entry_3 = DEFINE_STATIC_HEADER("date", "Mon, 21 Oct 2013 20:13:22 GMT", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_3;
    fixture->dynamic_table_len[index] = 3;
    return AWS_OP_SUCCESS;
}
HEADER_REQUEST_RESPONSE_TEST(h2_header_ex_5, s_test_ex_5_init, NULL);

/* RFC-7541 - Response Examples with Huffman Coding - C.6 */
static int s_test_ex_6_init(struct header_request_response_test_fixture *fixture) {

    /* set the max table size to 256 */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(fixture->encoder, 256));
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(fixture->decoder, 256));

    aws_hpack_set_huffman_mode(fixture->encoder, AWS_HPACK_HUFFMAN_ALWAYS);

    int index = 0;
    /* First Response RFC-7541 C.6.1 */
    struct aws_http_header headers_1[] = {
        DEFINE_STATIC_HEADER(":status", "302", USE_CACHE),
        DEFINE_STATIC_HEADER("cache-control", "private", USE_CACHE),
        DEFINE_STATIC_HEADER("date", "Mon, 21 Oct 2013 20:13:21 GMT", USE_CACHE),
        DEFINE_STATIC_HEADER("location", "https://www.example.com", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_1, AWS_ARRAY_SIZE(headers_1)));

    static const uint8_t encoded_1[] = {
        0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10,
        0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff, 0x6e,
        0x91, 0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_1, sizeof(encoded_1));

    struct aws_http_header last_entry_1 = DEFINE_STATIC_HEADER(":status", "302", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_1;
    fixture->dynamic_table_len[index] = 4;
    index++;

    /* Second Response RFC-7541 C.6.2 */
    struct aws_http_header headers_2[] = {
        DEFINE_STATIC_HEADER(":status", "307", USE_CACHE),
        DEFINE_STATIC_HEADER("cache-control", "private", USE_CACHE),
        DEFINE_STATIC_HEADER("date", "Mon, 21 Oct 2013 20:13:21 GMT", USE_CACHE),
        DEFINE_STATIC_HEADER("location", "https://www.example.com", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_2, AWS_ARRAY_SIZE(headers_2)));

    static const uint8_t encoded_2[] = {0x48, 0x83, 0x64, 0x0e, 0xff, 0xc1, 0xc0, 0xbf};
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_2, sizeof(encoded_2));

    struct aws_http_header last_entry_2 = DEFINE_STATIC_HEADER("cache-control", "private", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_2;
    fixture->dynamic_table_len[index] = 4;
    index++;

    /* Third Response RFC-7541 C.6.3 */
    struct aws_http_header headers_3[] = {
        DEFINE_STATIC_HEADER(":status", "200", USE_CACHE),
        DEFINE_STATIC_HEADER("cache-control", "private", USE_CACHE),
        DEFINE_STATIC_HEADER("date", "Mon, 21 Oct 2013 20:13:22 GMT", USE_CACHE),
        DEFINE_STATIC_HEADER("location", "https://www.example.com", USE_CACHE),
        DEFINE_STATIC_HEADER("content-encoding", "gzip", USE_CACHE),
        DEFINE_STATIC_HEADER("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", USE_CACHE),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(fixture->headers_to_encode[index], headers_3, AWS_ARRAY_SIZE(headers_3)));

    static const uint8_t encoded_3[] = {
        0x88, 0xc1, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95,
        0x04, 0x0b, 0x81, 0x66, 0xe0, 0x84, 0xa6, 0x2d, 0x1b, 0xff, 0xc0, 0x5a, 0x83, 0x9b, 0xd9, 0xab,
        0x77, 0xad, 0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2, 0xe6, 0xc7, 0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b,
        0x39, 0x60, 0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36, 0x72, 0xc1, 0xab, 0x27, 0x0f, 0xb5, 0x29, 0x1f,
        0x95, 0x87, 0x31, 0x60, 0x65, 0xc0, 0x03, 0xed, 0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07};
    aws_byte_buf_write(&fixture->expected_encoding_buf[index], encoded_3, sizeof(encoded_3));

    struct aws_http_header last_entry_3 = DEFINE_STATIC_HEADER("date", "Mon, 21 Oct 2013 20:13:22 GMT", USE_CACHE);
    fixture->last_entry_dynamic_table[index] = last_entry_3;
    fixture->dynamic_table_len[index] = 3;

    return AWS_OP_SUCCESS;
}
HEADER_REQUEST_RESPONSE_TEST(h2_header_ex_6, s_test_ex_6_init, NULL);
