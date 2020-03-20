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
#include <aws/testing/aws_test_harness.h>

#include <aws/http/private/hpack.h>

#include <aws/http/request_response.h>

/* #TODO test that buffer is resized if space is insufficient */

AWS_TEST_CASE(hpack_encode_integer, test_hpack_encode_integer)
static int test_hpack_encode_integer(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;
    /* Test encoding integers
       Test cases taken from https://httpwg.org/specs/rfc7541.html#integer.representation.examples */

    uint8_t zeros[4];
    AWS_ZERO_ARRAY(zeros);

    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 4));

    /* Test 10 in 5 bits */
    aws_byte_buf_secure_zero(&output);
    ASSERT_SUCCESS(aws_hpack_encode_integer(10, 0, 5, &output));
    /**
     * Expected:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     */
    ASSERT_UINT_EQUALS(1, output.len);
    ASSERT_UINT_EQUALS(10, output.buffer[0]);
    ASSERT_BIN_ARRAYS_EQUALS(zeros, 3, &output.buffer[1], 3);

    /* Test full first byte (6 bits) */
    aws_byte_buf_secure_zero(&output);
    ASSERT_SUCCESS(aws_hpack_encode_integer(63, 0, 6, &output));
    /**
     * Expected:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | 1 | 1 | 1 | 1 | 1 | 1 |  63
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |  0
     * +---+---+---+---+---+---+---+---+
     */
    ASSERT_UINT_EQUALS(2, output.len);
    ASSERT_UINT_EQUALS(63, output.buffer[0]);
    ASSERT_UINT_EQUALS(0, output.buffer[1]);
    ASSERT_BIN_ARRAYS_EQUALS(zeros, 2, &output.buffer[2], 2);

    /* Test 42 in 8 bits */
    aws_byte_buf_secure_zero(&output);
    ASSERT_SUCCESS(aws_hpack_encode_integer(42, 0, 8, &output));
    /**
     * Expected:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 0 |  42
     * +---+---+---+---+---+---+---+---+
     */
    ASSERT_UINT_EQUALS(1, output.len);
    ASSERT_UINT_EQUALS(42, output.buffer[0]);
    ASSERT_BIN_ARRAYS_EQUALS(zeros, 3, &output.buffer[1], 3);

    /* Test 1337 with 5bit prefix */
    aws_byte_buf_secure_zero(&output);
    ASSERT_SUCCESS(aws_hpack_encode_integer(1337, 0, 5, &output));
    /**
     * Expected:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 1 | 1 | 1 | 1 | 1 |  31
     * | 1 | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 154
     * | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     */
    ASSERT_UINT_EQUALS(3, output.len);
    ASSERT_UINT_EQUALS(UINT8_MAX >> 3, output.buffer[0]);
    ASSERT_UINT_EQUALS(154, output.buffer[1]);
    ASSERT_UINT_EQUALS(10, output.buffer[2]);
    ASSERT_UINT_EQUALS(0, output.buffer[3]);

    aws_byte_buf_clean_up(&output);
    return AWS_OP_SUCCESS;
}

struct decode_fixture {
    struct aws_hpack_context *hpack;
    bool one_byte_at_a_time;
};

static int s_decode_fixture_setup(struct aws_allocator *allocator, void *ctx) {
    struct decode_fixture *fixture = ctx;

    fixture->hpack = aws_hpack_context_new(allocator, AWS_LS_HTTP_DECODER, NULL);
    ASSERT_NOT_NULL(fixture->hpack);

    return AWS_OP_SUCCESS;
}

static int s_decode_fixture_teardown(struct aws_allocator *allocator, int setup_result, void *ctx) {
    (void)allocator;
    if (setup_result) {
        return AWS_OP_ERR;
    }

    struct decode_fixture *fixture = ctx;
    aws_hpack_context_destroy(fixture->hpack);
    return AWS_OP_SUCCESS;
}

/* Call aws_hpack_decode_integer() either one-byte-at-a-time, or all at once */
static int s_decode_integer(
    struct decode_fixture *fixture,
    struct aws_byte_cursor *to_decode,
    uint8_t prefix_size,
    uint64_t *integer,
    bool *complete) {

    if (fixture->one_byte_at_a_time) {
        do {
            struct aws_byte_cursor one_byte = aws_byte_cursor_advance(to_decode, 1);
            if (aws_hpack_decode_integer(fixture->hpack, &one_byte, prefix_size, integer, complete)) {
                return AWS_OP_ERR;
            }
            ASSERT_UINT_EQUALS(0, one_byte.len);
        } while (!*complete && to_decode->len);

        return AWS_OP_SUCCESS;

    } else {
        return aws_hpack_decode_integer(fixture->hpack, to_decode, prefix_size, integer, complete);
    }
}

/* Call aws_hpack_decode_string() either one-byte-at-a-time, or all at once */
static int s_decode_string(
    struct decode_fixture *fixture,
    struct aws_byte_cursor *to_decode,
    struct aws_byte_buf *output,
    bool *complete) {

    if (fixture->one_byte_at_a_time) {
        do {
            struct aws_byte_cursor one_byte = aws_byte_cursor_advance(to_decode, 1);
            if (aws_hpack_decode_string(fixture->hpack, &one_byte, output, complete)) {
                return AWS_OP_ERR;
            }
            ASSERT_UINT_EQUALS(0, one_byte.len);
        } while (!*complete && to_decode->len);

        return AWS_OP_SUCCESS;

    } else {
        return aws_hpack_decode_string(fixture->hpack, to_decode, output, complete);
    }
}

/* declare 2 tests, where the first decodes the input all at once,
 * and the other decodes the input one byte at a time. */
#define TEST_DECODE_ONE_BYTE_AT_A_TIME(NAME)                                                                           \
    static struct decode_fixture s_##NAME##_fixture = {.one_byte_at_a_time = false};                                   \
    static struct decode_fixture s_##NAME##_one_byte_at_a_time_fixture = {.one_byte_at_a_time = true};                 \
    AWS_TEST_CASE_FIXTURE(NAME, s_decode_fixture_setup, s_test_##NAME, s_decode_fixture_teardown, &s_##NAME##_fixture) \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        NAME##_one_byte_at_a_time,                                                                                     \
        s_decode_fixture_setup,                                                                                        \
        s_test_##NAME,                                                                                                 \
        s_decode_fixture_teardown,                                                                                     \
        &s_##NAME##_one_byte_at_a_time_fixture)                                                                        \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

/* RFC-7541 - Integer Representation Examples - C.1.1. Encoding 10 Using a 5-Bit Prefix */
TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_integer_5bits) {
    (void)allocator;
    struct decode_fixture *fixture = ctx;

    /* Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_0[] = {10};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(test_0, AWS_ARRAY_SIZE(test_0));
    uint64_t result;
    bool complete;
    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 5, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_UINT_EQUALS(10, result);
    return AWS_OP_SUCCESS;
}

/* Encoding 63 across a 6-bit prefix + one byte */
TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_integer_14bits) {
    (void)allocator;
    struct decode_fixture *fixture = ctx;

    /* Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | 1 | 1 | 1 | 1 | 1 | 1 |  63
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |  0
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_1[] = {63, 0};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(test_1, AWS_ARRAY_SIZE(test_1));
    uint64_t result;
    bool complete;
    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 6, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_UINT_EQUALS(63, result);
    return AWS_OP_SUCCESS;
}

/* RFC-7541 - Integer Representation Examples - C.1.3. Encoding 42 Starting at an Octet Boundary */
TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_integer_8bits) {
    (void)allocator;
    struct decode_fixture *fixture = ctx;

    /* Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 0 |  42
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_2[] = {42};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(test_2, AWS_ARRAY_SIZE(test_2));
    uint64_t result;
    bool complete;
    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 8, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_UINT_EQUALS(42, result);
    return AWS_OP_SUCCESS;
}

/* RFC-7541 - Integer Representation Examples - C.1.2. Encoding 1337 Using a 5-Bit Prefix */
TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_integer_21bits) {
    (void)allocator;
    struct decode_fixture *fixture = ctx;

    /* Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 1 | 1 | 1 | 1 | 1 |  31
     * | 1 | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 154
     * | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_3[] = {UINT8_MAX >> 3, 154, 10};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(test_3, AWS_ARRAY_SIZE(test_3));
    uint64_t result;
    bool complete;
    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 5, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_UINT_EQUALS(1337, result);
    return AWS_OP_SUCCESS;
}

TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_integer_ongoing) {
    (void)allocator;
    struct decode_fixture *fixture = ctx;

    /* Test number ending with continue byte
     * Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 1 | 1 | 1 | 1 | 1 |  31
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_4[] = {UINT8_MAX >> 3, UINT8_MAX};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(test_4, AWS_ARRAY_SIZE(test_4));
    uint64_t result;
    bool complete;
    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 5, &result, &complete));
    ASSERT_FALSE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    return AWS_OP_SUCCESS;
}

TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_integer_too_big) {
    (void)allocator;
    struct decode_fixture *fixture = ctx;

    /* Test number too big
     * Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 1 | 1 | 1 | 1 | 1 |  31
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_5[] = {
        UINT8_MAX >> 3,
        UINT8_MAX,
        UINT8_MAX,
        UINT8_MAX,
        UINT8_MAX,
        UINT8_MAX,
        UINT8_MAX,
        UINT8_MAX,
        UINT8_MAX,
        UINT8_MAX,
        UINT8_MAX,
    };
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(test_5, AWS_ARRAY_SIZE(test_5));
    uint64_t result;
    bool complete;
    ASSERT_FAILS(s_decode_integer(fixture, &to_decode, 5, &result, &complete));
    ASSERT_UINT_EQUALS(AWS_ERROR_OVERFLOW_DETECTED, aws_last_error());
    return AWS_OP_SUCCESS;
}

/* Test that decoder properly resets itself between integers.
 * Trying every type of transition:
 * - from 1 byte to 1 byte
 * - from 1 byte to multibyte
 * - from multibyte to multibyte
 * - from multibyte to 1 byte */
TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_integer_few_in_a_row) {
    (void)allocator;
    struct decode_fixture *fixture = ctx;

    uint8_t input[] = {
        /* 10 with 5-bit prefix
         * +---+---+---+---+---+---+---+---+
         * | X | X | X | 0 | 1 | 0 | 1 | 0 |
         * +---+---+---+---+---+---+---+---+ */
        10,
        /* 42 with 8-bit prefix
         * +---+---+---+---+---+---+---+---+
         * | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 0 |
         * +---+---+---+---+---+---+---+---+
         */
        42,
        /* 63 with 6-bit prefix
         * +---+---+---+---+---+---+---+---+
         * | X | X | 1 | 1 | 1 | 1 | 1 | 1 |
         * +---+---+---+---+---+---+---+---+
         * | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
         * +---+---+---+---+---+---+---+---+
         */
        63,
        0,
        /* 1337 with 5-bit prefix
         * +---+---+---+---+---+---+---+---+
         * | X | X | X | 1 | 1 | 1 | 1 | 1 |
         * | 1 | 0 | 0 | 1 | 1 | 0 | 1 | 0 |
         * | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |
         * +---+---+---+---+---+---+---+---+
         */
        UINT8_MAX >> 3,
        154,
        10,
        /* 10 with 5-bit prefix
         * +---+---+---+---+---+---+---+---+
         * | X | X | X | 0 | 1 | 0 | 1 | 0 |
         * +---+---+---+---+---+---+---+---+
         */
        10,
    };

    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(input, AWS_ARRAY_SIZE(input));
    uint64_t result;
    bool complete;

    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 5, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(10, result);

    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 8, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(42, result);

    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 6, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(63, result);

    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 5, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(1337, result);

    ASSERT_SUCCESS(s_decode_integer(fixture, &to_decode, 5, &result, &complete));
    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(10, result);

    ASSERT_UINT_EQUALS(0, to_decode.len);
    return AWS_OP_SUCCESS;
}

TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_string_blank) {
    struct decode_fixture *fixture = ctx;

    uint8_t input[] = {0};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(input, AWS_ARRAY_SIZE(input));
    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 4));
    bool complete;
    ASSERT_SUCCESS(s_decode_string(fixture, &to_decode, &output, &complete));

    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_BIN_ARRAYS_EQUALS("", 0, output.buffer, output.len);

    aws_byte_buf_clean_up(&output);
    return AWS_OP_SUCCESS;
}

/* Test a string that is NOT Huffman encoded */
TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_string_uncompressed) {
    struct decode_fixture *fixture = ctx;

    uint8_t input[] = {5, 'h', 'e', 'l', 'l', 'o'};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(input, AWS_ARRAY_SIZE(input));
    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 5));
    bool complete;
    ASSERT_SUCCESS(s_decode_string(fixture, &to_decode, &output, &complete));

    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_BIN_ARRAYS_EQUALS("hello", 5, output.buffer, output.len);

    aws_byte_buf_clean_up(&output);
    return AWS_OP_SUCCESS;
}

TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_string_huffman) {
    struct decode_fixture *fixture = ctx;

    /* This is Huffman-encoded "www.example.com", copied from:
     * RFC-7541 - Request Examples with Huffman Coding - C.4.1. First Request */
    uint8_t input[] = {0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(input, AWS_ARRAY_SIZE(input));

    const char *expected = "www.example.com";

    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, strlen(expected)));
    bool complete;
    ASSERT_SUCCESS(s_decode_string(fixture, &to_decode, &output, &complete));

    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_BIN_ARRAYS_EQUALS(expected, strlen(expected), output.buffer, output.len);

    aws_byte_buf_clean_up(&output);
    return AWS_OP_SUCCESS;
}

/* Test that partial input doesn't register as "complete" */
TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_string_ongoing) {
    struct decode_fixture *fixture = ctx;

    uint8_t input[] = {5, 'h', 'e', 'l'};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(input, AWS_ARRAY_SIZE(input));
    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 5));
    bool complete;
    ASSERT_SUCCESS(s_decode_string(fixture, &to_decode, &output, &complete));

    ASSERT_FALSE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);

    aws_byte_buf_clean_up(&output);
    return AWS_OP_SUCCESS;
}

/* Test that output buffer is gets resized if it's too small */
TEST_DECODE_ONE_BYTE_AT_A_TIME(hpack_decode_string_short_buffer) {
    struct decode_fixture *fixture = ctx;

    uint8_t input[] = {5, 'h', 'e', 'l', 'l', 'o'};
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(input, AWS_ARRAY_SIZE(input));

    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 1)); /* Note buffer is initially too small */
    bool complete;
    ASSERT_SUCCESS(s_decode_string(fixture, &to_decode, &output, &complete));

    ASSERT_TRUE(complete);
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_BIN_ARRAYS_EQUALS("hello", 5, output.buffer, output.len);

    aws_byte_buf_clean_up(&output);
    return AWS_OP_SUCCESS;
}

#define DEFINE_STATIC_HEADER(_name, _header, _value)                                                                   \
    static const struct aws_http_header _name = {                                                                      \
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_header),                                                        \
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_value),                                                        \
    }

AWS_TEST_CASE(hpack_static_table_find, test_hpack_static_table_find)
static int test_hpack_static_table_find(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, AWS_LS_HTTP_GENERAL, NULL);
    ASSERT_NOT_NULL(context);
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, 0));

    bool found_value = false;

    DEFINE_STATIC_HEADER(s_authority, ":authority", "amazon.com");
    DEFINE_STATIC_HEADER(s_get, ":method", "GET");
    DEFINE_STATIC_HEADER(s_other_method, ":method", "TEAPOT");
    DEFINE_STATIC_HEADER(s_garbage, "colden's favorite ice cream flavor", "cookie dough");

    /* Test header without value */
    ASSERT_UINT_EQUALS(1, aws_hpack_find_index(context, &s_authority, &found_value));
    ASSERT_FALSE(found_value);

    /* Test header with value */
    ASSERT_UINT_EQUALS(2, aws_hpack_find_index(context, &s_get, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(2, aws_hpack_find_index(context, &s_other_method, &found_value));
    ASSERT_FALSE(found_value);

    /* Check invalid header */
    ASSERT_UINT_EQUALS(0, aws_hpack_find_index(context, &s_garbage, &found_value));

    aws_hpack_context_destroy(context);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_static_table_get, test_hpack_static_table_get)
static int test_hpack_static_table_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, AWS_LS_HTTP_GENERAL, NULL);
    ASSERT_NOT_NULL(context);
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, 0));

    const struct aws_http_header *found = NULL;

    DEFINE_STATIC_HEADER(s_get, ":path", "/index.html");
    DEFINE_STATIC_HEADER(s_age, "age", "25");

    found = aws_hpack_get_header(context, 21);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_age.name, &found->name));
    ASSERT_NULL(found->value.ptr);
    ASSERT_UINT_EQUALS(0, found->value.len);

    found = aws_hpack_get_header(context, 5);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_get.name, &found->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&s_get.value, &found->value));

    found = aws_hpack_get_header(context, 69);
    ASSERT_NULL(found);

    aws_hpack_context_destroy(context);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_dynamic_table_find, test_hpack_dynamic_table_find)
static int test_hpack_dynamic_table_find(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, AWS_LS_HTTP_GENERAL, NULL);
    ASSERT_NOT_NULL(context);

    bool found_value = false;

    DEFINE_STATIC_HEADER(s_herp, "herp", "derp");
    DEFINE_STATIC_HEADER(s_herp2, "herp", "something else");
    DEFINE_STATIC_HEADER(s_fizz, "fizz", "buzz");

    /* Test single header */
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &s_herp));
    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &s_herp, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &s_herp2, &found_value));
    ASSERT_FALSE(found_value);

    /* Test 2 headers */
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &s_fizz));
    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &s_fizz, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(63, aws_hpack_find_index(context, &s_herp, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(63, aws_hpack_find_index(context, &s_herp2, &found_value));
    ASSERT_FALSE(found_value);

    /* Test resizing up doesn't break anything */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, 8 * 1024 * 1024));

    /* Check invalid header */
    DEFINE_STATIC_HEADER(s_garbage, "colden's mother's maiden name", "nice try mr hacker");
    ASSERT_UINT_EQUALS(0, aws_hpack_find_index(context, &s_garbage, &found_value));

    /* Test resizing so only the first element stays */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, aws_hpack_get_header_size(&s_fizz)));

    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &s_fizz, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(0, aws_hpack_find_index(context, &s_herp, &found_value));
    ASSERT_FALSE(found_value);

    aws_hpack_context_destroy(context);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_dynamic_table_get, test_hpack_dynamic_table_get)
static int test_hpack_dynamic_table_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, AWS_LS_HTTP_GENERAL, NULL);
    ASSERT_NOT_NULL(context);

    const struct aws_http_header *found = NULL;

    DEFINE_STATIC_HEADER(s_herp, "herp", "derp");
    DEFINE_STATIC_HEADER(s_fizz, "fizz", "buzz");
    DEFINE_STATIC_HEADER(s_status, ":status", "418");

    /* Make the dynamic table only big enough for 2 headers */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(
        context, aws_hpack_get_header_size(&s_fizz) + aws_hpack_get_header_size(&s_status)));

    ASSERT_SUCCESS(aws_hpack_insert_header(context, &s_herp));
    found = aws_hpack_get_header(context, 62);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_herp.name, &found->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&s_herp.value, &found->value));

    ASSERT_SUCCESS(aws_hpack_insert_header(context, &s_fizz));
    found = aws_hpack_get_header(context, 62);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_fizz.name, &found->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&s_fizz.value, &found->value));
    found = aws_hpack_get_header(context, 63);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_herp.name, &found->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&s_herp.value, &found->value));

    /* This one will result in the first header being evicted */
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &s_status));
    found = aws_hpack_get_header(context, 62);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_status.name, &found->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&s_status.value, &found->value));
    found = aws_hpack_get_header(context, 63);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_fizz.name, &found->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&s_fizz.value, &found->value));
    found = aws_hpack_get_header(context, 64);
    ASSERT_NULL(found);

    /* Test resizing to evict entries */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, aws_hpack_get_header_size(&s_status)));

    found = aws_hpack_get_header(context, 62);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_status.name, &found->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&s_status.value, &found->value));
    found = aws_hpack_get_header(context, 63);
    ASSERT_NULL(found);

    aws_hpack_context_destroy(context);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}
