/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/testing/aws_test_harness.h>

#include <aws/http/private/hpack.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/device_random.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* Disable warnings about sprintf() being insecure */
#endif
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
    ASSERT_UINT_EQUALS(1, aws_hpack_find_index(context, &s_authority, false, &found_value));
    ASSERT_FALSE(found_value);

    /* Test header with value */
    ASSERT_UINT_EQUALS(2, aws_hpack_find_index(context, &s_get, true, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(2, aws_hpack_find_index(context, &s_other_method, true, &found_value));
    ASSERT_FALSE(found_value);

    /* Check invalid header */
    ASSERT_UINT_EQUALS(0, aws_hpack_find_index(context, &s_garbage, true, &found_value));

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
    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &s_herp, true, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &s_herp2, true, &found_value));
    ASSERT_FALSE(found_value);

    /* Test 2 headers */
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &s_fizz));
    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &s_fizz, true, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(63, aws_hpack_find_index(context, &s_herp, true, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(63, aws_hpack_find_index(context, &s_herp2, true, &found_value));
    ASSERT_FALSE(found_value);

    /* Test resizing up doesn't break anything */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, 8 * 1024 * 1024));

    /* Check invalid header */
    DEFINE_STATIC_HEADER(s_garbage, "colden's mother's maiden name", "nice try mr hacker");
    ASSERT_UINT_EQUALS(0, aws_hpack_find_index(context, &s_garbage, true, &found_value));

    /* Test resizing so only the first element stays */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, aws_hpack_get_header_size(&s_fizz)));

    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &s_fizz, true, &found_value));
    ASSERT_TRUE(found_value);
    ASSERT_UINT_EQUALS(0, aws_hpack_find_index(context, &s_herp, true, &found_value));
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

static int s_check_header(
    const struct aws_http_header *header_field,
    const char *name,
    const char *value,
    enum aws_http_header_compression compression) {

    ASSERT_BIN_ARRAYS_EQUALS(name, strlen(name), header_field->name.ptr, header_field->name.len);
    ASSERT_BIN_ARRAYS_EQUALS(value, strlen(value), header_field->value.ptr, header_field->value.len);
    ASSERT_INT_EQUALS(compression, header_field->compression);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_decode_indexed_from_dynamic_table, test_hpack_decode_indexed_from_dynamic_table)
static int test_hpack_decode_indexed_from_dynamic_table(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, AWS_LS_HTTP_GENERAL, NULL);
    ASSERT_NOT_NULL(context);

    /* clang-format off */
    uint8_t input[] = {
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - stored to dynamic table */
        0x40, 0x01, 'a', 0x01, 'b',     /* "a: b" - stored to dynamic table */
        /* So at this point dynamic table should look like:
         *  INDEX   NAME    VALUE
         *  62      a       b
         *  63      :status 302
         */
        0xbf,                           /* ":status: 302" - indexed from dynamic table */
    };
    /* clang-format on */
    struct aws_hpack_decode_result result;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    /* Three entries in total, decode them all, and check the result */
    /* First entry */
    ASSERT_SUCCESS(aws_hpack_decode(context, &input_cursor, &result));
    ASSERT_TRUE(result.type == AWS_HPACK_DECODE_T_HEADER_FIELD);
    ASSERT_SUCCESS(s_check_header(&result.data.header_field, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    /* Second entry */
    ASSERT_SUCCESS(aws_hpack_decode(context, &input_cursor, &result));
    ASSERT_TRUE(result.type == AWS_HPACK_DECODE_T_HEADER_FIELD);
    ASSERT_SUCCESS(s_check_header(&result.data.header_field, "a", "b", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    /* Third entry */
    ASSERT_SUCCESS(aws_hpack_decode(context, &input_cursor, &result));
    ASSERT_TRUE(result.type == AWS_HPACK_DECODE_T_HEADER_FIELD);
    ASSERT_SUCCESS(s_check_header(&result.data.header_field, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));

    /* Check the input is fully consumed */
    ASSERT_TRUE(input_cursor.len == 0);

    /* Clean up */
    aws_hpack_context_destroy(context);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* Test header with empty value */
AWS_TEST_CASE(hpack_dynamic_table_empty_value, test_hpack_dynamic_table_empty_value)
static int test_hpack_dynamic_table_empty_value(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, AWS_LS_HTTP_GENERAL, NULL);
    ASSERT_NOT_NULL(context);

    DEFINE_STATIC_HEADER(header1, ":status", "302");
    DEFINE_STATIC_HEADER(empty_value_header, "c", "");
    DEFINE_STATIC_HEADER(header2, "a", "b");

    ASSERT_SUCCESS(aws_hpack_insert_header(context, &header1));
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &empty_value_header));
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &header2));
    /*
    So at this point dynamic table should look like:
        *  INDEX   NAME    VALUE
        *  62       a        b
        *  63       "c"       ""
        *  64      :status 302
    */
    bool found_value = false;
    ASSERT_UINT_EQUALS(64, aws_hpack_find_index(context, &header1, true, &found_value));
    ASSERT_UINT_EQUALS(63, aws_hpack_find_index(context, &empty_value_header, true, &found_value));
    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &header2, true, &found_value));

    /* Clean up */
    aws_hpack_context_destroy(context);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* Test header with empty name and value */
AWS_TEST_CASE(hpack_dynamic_table_with_empty_header, test_hpack_dynamic_table_with_empty_header)
static int test_hpack_dynamic_table_with_empty_header(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, AWS_LS_HTTP_GENERAL, NULL);
    ASSERT_NOT_NULL(context);
    DEFINE_STATIC_HEADER(header1, ":status", "302");
    DEFINE_STATIC_HEADER(empty_header, "", "");
    DEFINE_STATIC_HEADER(header2, "a", "b");

    ASSERT_SUCCESS(aws_hpack_insert_header(context, &header1));
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &empty_header));
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &header2));
    /*
    So at this point dynamic table should look like:
        *  INDEX   NAME    VALUE
        *  62       a        b
        *  63       ""       ""
        *  64      :status 302
    */
    bool found_value = false;
    ASSERT_UINT_EQUALS(64, aws_hpack_find_index(context, &header1, true, &found_value));
    ASSERT_UINT_EQUALS(63, aws_hpack_find_index(context, &empty_header, true, &found_value));
    ASSERT_UINT_EQUALS(62, aws_hpack_find_index(context, &header2, true, &found_value));

    /* Clean up */
    aws_hpack_context_destroy(context);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_dynamic_table_size_update_from_setting, test_hpack_dynamic_table_size_update_from_setting)
static int test_hpack_dynamic_table_size_update_from_setting(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, AWS_LS_HTTP_GENERAL, NULL);
    ASSERT_NOT_NULL(context);

    /* let's pretent multiple times max size update happened from encoder setting */
    aws_hpack_set_max_table_size(context, 10);
    aws_hpack_set_max_table_size(context, 0);
    aws_hpack_set_max_table_size(context, 1337);

    /* encode a header block */
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    /* the 2 entry of static table */
    DEFINE_STATIC_HEADER(header, ":method", "GET");
    ASSERT_SUCCESS(aws_http_headers_add_header(headers, &header));
    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 5));
    ASSERT_SUCCESS(aws_hpack_encode_header_block(context, headers, &output));

    /* Check the output result, it should contain two dynamic table size updates, besides the header */
    /**
     * Expected first table size update (0 0 1) for dynamic table size update, rest is the integer with 5-bit Prefix:
     * size is 0
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |  32
     * +---+---+---+---+---+---+---+---+
     *
     * Expected second table size update:
     * size is 1337
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 1 |  63
     * | 1 | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 154
     * | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     *
     * Expected header block: (1) for indexed header field, rest is the index, which is 2
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |  130
     * +---+---+---+---+---+---+---+---+
     */
    ASSERT_UINT_EQUALS(5, output.len);
    ASSERT_UINT_EQUALS(32, output.buffer[0]);
    ASSERT_UINT_EQUALS(63, output.buffer[1]);
    ASSERT_UINT_EQUALS(154, output.buffer[2]);
    ASSERT_UINT_EQUALS(10, output.buffer[3]);
    ASSERT_UINT_EQUALS(130, output.buffer[4]);

    /* clean up */
    aws_byte_buf_clean_up(&output);
    aws_http_headers_release(headers);
    aws_hpack_context_destroy(context);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

static bool s_echo_body_has_header(const struct aws_byte_cursor echo_body, const struct aws_http_header *header) {
    char str_to_find[256];
    /* Echo body will capitalize the header name, ignore the first char. I think it's fine */
    struct aws_byte_cursor name_without_first_char = header->name;
    aws_byte_cursor_advance(&name_without_first_char, 1);
    sprintf(
        str_to_find,
        "" PRInSTR "\": \"" PRInSTR "\"",
        AWS_BYTE_CURSOR_PRI(name_without_first_char),
        AWS_BYTE_CURSOR_PRI(header->value));
    struct aws_byte_cursor to_find_cur = aws_byte_cursor_from_c_str(str_to_find);
    struct aws_byte_cursor found;
    if (aws_byte_cursor_find_exact(&echo_body, &to_find_cur, &found)) {
        printf("xxxxxxxxxxxx body is" PRInSTR "\n", AWS_BYTE_CURSOR_PRI(echo_body));
        /* cannot find the value */
        return false;
    }
    return true;
}

static bool s_echo_body_has_headers(const struct aws_byte_cursor echo_body, const struct aws_http_headers *headers) {
    for (size_t i = 0; i < aws_http_headers_count(headers); i++) {
        struct aws_http_header out_header;
        if (aws_http_headers_get_index(headers, i, &out_header)) {
            return false;
        }
        if (!s_echo_body_has_header(echo_body, &out_header)) {
            return false;
        }
    }
    return true;
}

static int s_tester_on_echo_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;
    /**
     * Make request to https://httpbin.org/headers, example response body:
     *"{\r\n"
     *"  \"headers\": {\r\n"
     *"    \"Accept\": \"application/xml\", \r\n"
     *"    \"Host\": \"httpbin.org\", \r\n"
     *"    \"Test0\": \"test0\", \r\n"
     *"    \"User-Agent\": \"elasticurl 1.0, Powered by the AWS Common Runtime.\", \r\n"
     *"    \"X-Amzn-Trace-Id\": \"Root=1-6216d59a-16a92b5622bb49a0352cf9a4\"\r\n"
     *"  }\r\n"
     *"}\r\n"
     */
    struct aws_byte_buf *echo_body = (struct aws_byte_buf *)user_data;
    ASSERT_SUCCESS(aws_byte_buf_append_dynamic(echo_body, data));
    return AWS_OP_SUCCESS;
}

struct tester {
    struct aws_allocator *alloc;

    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;
    struct aws_client_bootstrap *client_bootstrap;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_http_connection *connection;

    struct aws_mutex wait_lock;
    struct aws_condition_variable wait_cvar;

    bool shutdown_finished;
    size_t wait_for_stream_completed_count;
    size_t stream_completed_count;
    size_t stream_complete_errors;
    size_t stream_200_count;
    size_t stream_status_not_200_count;
    int stream_completed_error_code;
    bool stream_completed_with_200;

    int wait_result;
};

static struct tester s_tester;

#define DEFINE_HEADER(NAME, VALUE)                                                                                     \
    { .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(NAME), .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(VALUE), }

enum {
    TESTER_TIMEOUT_SEC = 60, /* Give enough time for non-sudo users to enter password */
};

static void s_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {

    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    if (error_code) {
        tester->wait_result = error_code;
        goto done;
    }
    tester->connection = connection;
done:
    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static void s_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {

    (void)connection;
    (void)error_code;
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->shutdown_finished = true;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static bool s_is_connected(void *context) {
    struct tester *tester = context;

    return tester->connection != NULL;
}

static int s_wait_on_connection_connected(struct tester *tester) {

    ASSERT_SUCCESS(aws_mutex_lock(&tester->wait_lock));
    int signal_error = aws_condition_variable_wait_pred(&tester->wait_cvar, &tester->wait_lock, s_is_connected, tester);
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->wait_lock));
    return signal_error;
}

static bool s_is_shutdown(void *context) {
    struct tester *tester = context;

    return tester->shutdown_finished;
}

static int s_wait_on_connection_shutdown(struct tester *tester) {

    ASSERT_SUCCESS(aws_mutex_lock(&tester->wait_lock));
    int signal_error = aws_condition_variable_wait_pred(&tester->wait_cvar, &tester->wait_lock, s_is_shutdown, tester);
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->wait_lock));
    return signal_error;
}

static bool s_is_stream_completed_count_at_least(void *context) {
    (void)context;
    return s_tester.wait_for_stream_completed_count <= s_tester.stream_completed_count;
}

static int s_wait_on_streams_completed_count(size_t count) {

    ASSERT_SUCCESS(aws_mutex_lock(&s_tester.wait_lock));
    s_tester.wait_for_stream_completed_count = count;
    int signal_error = aws_condition_variable_wait_pred(
        &s_tester.wait_cvar, &s_tester.wait_lock, s_is_stream_completed_count_at_least, &s_tester);
    ASSERT_SUCCESS(aws_mutex_unlock(&s_tester.wait_lock));
    return signal_error;
}

static void s_tester_on_stream_completed(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)user_data;
    (void)stream;
    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.wait_lock) == AWS_OP_SUCCESS);
    if (error_code) {
        ++s_tester.stream_complete_errors;
        s_tester.stream_completed_error_code = error_code;
    } else {
        int status = 0;
        if (aws_http_stream_get_incoming_response_status(stream, &status)) {
            ++s_tester.stream_complete_errors;
            s_tester.stream_completed_error_code = aws_last_error();
        } else {
            if (status == 200) {
                s_tester.stream_completed_with_200 = true;
                ++s_tester.stream_200_count;
            } else {
                ++s_tester.stream_status_not_200_count;
            }
        }
    }
    ++s_tester.stream_completed_count;
    aws_condition_variable_notify_one(&s_tester.wait_cvar);
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.wait_lock) == AWS_OP_SUCCESS);
}

static int s_tester_init(struct tester *tester, struct aws_allocator *allocator, struct aws_byte_cursor host_name) {
    aws_http_library_init(allocator);

    ASSERT_SUCCESS(aws_mutex_init(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&tester->wait_cvar));
    tester->event_loop_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = tester->event_loop_group,
        .max_entries = 8,
    };

    tester->host_resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    /* Create http connection */
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = tester->event_loop_group,
        .host_resolver = tester->host_resolver,
    };
    tester->client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    aws_tls_ctx_options_init_default_client(&tester->tls_ctx_options, allocator);
    aws_tls_ctx_options_set_alpn_list(&tester->tls_ctx_options, "h2");
    tester->tls_ctx_options.verify_peer = false;

    tester->tls_ctx = aws_tls_client_ctx_new(allocator, &tester->tls_ctx_options);
    aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);
    aws_tls_connection_options_set_server_name(&tester->tls_connection_options, allocator, &host_name);
    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };
    struct aws_http_client_connection_options client_options = {
        .self_size = sizeof(struct aws_http_client_connection_options),
        .allocator = allocator,
        .bootstrap = tester->client_bootstrap,
        .host_name = host_name,
        .port = 443,
        .socket_options = &socket_options,
        .user_data = tester,
        .tls_options = &tester->tls_connection_options,
        .on_setup = s_on_connection_setup,
        .on_shutdown = s_on_connection_shutdown,
    };
    ASSERT_SUCCESS(aws_http_client_connect(&client_options));
    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    aws_http_connection_release(tester->connection);
    ASSERT_SUCCESS(s_wait_on_connection_shutdown(tester));

    aws_tls_connection_options_clean_up(&tester->tls_connection_options);
    aws_tls_ctx_release(tester->tls_ctx);
    aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    aws_client_bootstrap_release(tester->client_bootstrap);
    aws_host_resolver_release(tester->host_resolver);
    aws_event_loop_group_release(tester->event_loop_group);

    aws_mutex_clean_up(&tester->wait_lock);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_stress, test_hpack_stress)
static int test_hpack_stress(struct aws_allocator *allocator, void *ctx) {
    /* Test that makes tons of streams with all sorts of headers to stress hpack */
    (void)ctx;
    struct aws_byte_cursor host_name = aws_byte_cursor_from_c_str("httpbin.org");
    ASSERT_SUCCESS(s_tester_init(&s_tester, allocator, host_name));
    /* wait for connection connected */
    ASSERT_SUCCESS(s_wait_on_connection_connected(&s_tester));
    // httpbin.org/headers is an echo server that will return the headers of your request from the body.
    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/headers"),
        DEFINE_HEADER(":authority", "httpbin.org"),
    };
    /* The initail settings header table size is 4096 octets, but the frame size limits us to send too many headers in
     * one request. */
    size_t num_to_acquire = 1000;
    size_t accpected_error = 50;
    size_t num_headers_to_make = 100;
    size_t error_count = 0;

    /* Use a pool of headers and a pool of values, pick up randomly from both pool to stress hpack */
    size_t headers_pool_size = 500;
    size_t values_pool_size = 66;

    for (size_t i = 0; i < num_to_acquire; i++) {
        struct aws_http_message *request = aws_http2_message_new_request(allocator);
        ASSERT_NOT_NULL(request);
        aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
        struct aws_http_headers *request_headers = aws_http_message_get_headers(request);
        struct aws_http_headers *test_headers =
            aws_http_headers_new(allocator); /* as request headers has the pesudo headers, make a copy of the real
                                                headers to check the result */
        for (size_t j = 0; j < num_headers_to_make; j++) {
            char test_header_str[256];
            /**
             * - Don't use _ or - between word, the response will capitalize the first char of every word :(
             * - Don't use _, the response will change it to -. :(
             */
            uint64_t random_64_bit_num = 0;
            aws_device_random_u64(&random_64_bit_num);

            size_t headers = (size_t)random_64_bit_num % headers_pool_size;
            sprintf(test_header_str, "crttest-%zu", headers);
            char test_value_str[256];
            size_t value = (size_t)random_64_bit_num % values_pool_size;
            sprintf(test_value_str, "value-%zu", value);
            struct aws_byte_cursor existed_value;
            if (aws_http_headers_get(test_headers, aws_byte_cursor_from_c_str(test_header_str), &existed_value) ==
                AWS_OP_SUCCESS) {
                /* If the header has the same name already exists in the headers, the response will combine the values
                 * together. Do the same thing for the header to check. */
                char combined_value_str[1024];
                sprintf(combined_value_str, "" PRInSTR ",%s", AWS_BYTE_CURSOR_PRI(existed_value), test_value_str);
                aws_http_headers_set(
                    test_headers,
                    aws_byte_cursor_from_c_str(test_header_str),
                    aws_byte_cursor_from_c_str(combined_value_str));
            } else {
                aws_http_headers_add(
                    test_headers,
                    aws_byte_cursor_from_c_str(test_header_str),
                    aws_byte_cursor_from_c_str(test_value_str));
            }
            aws_http_headers_add(
                request_headers,
                aws_byte_cursor_from_c_str(test_header_str),
                aws_byte_cursor_from_c_str(test_value_str));
        }
        struct aws_byte_buf echo_body;
        ASSERT_SUCCESS(aws_byte_buf_init(&echo_body, allocator, 100));
        struct aws_http_make_request_options request_options = {
            .self_size = sizeof(request_options),
            .request = request,
            .user_data = &echo_body,
            .on_response_body = s_tester_on_echo_body,
            .on_complete = s_tester_on_stream_completed,
        };
        struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
        ASSERT_NOT_NULL(stream);
        aws_http_stream_activate(stream);
        aws_http_stream_release(stream);

        /* Wait for the stream to complete */
        ASSERT_SUCCESS(s_wait_on_streams_completed_count(1));
        --s_tester.stream_completed_count;
        if (!s_tester.stream_completed_with_200) {
            /* If error happens, we make sure it's acptiable */
            ++error_count;
        } else {
            s_tester.stream_completed_with_200 = false; /* reset complete code */
            ASSERT_TRUE(s_echo_body_has_headers(
                aws_byte_cursor_from_buf(&echo_body),
                test_headers)); /* Make sure we have the expected headers when 200 received */
        }

        aws_http_message_release(request);
        aws_http_headers_release(test_headers);
        aws_byte_buf_clean_up(&echo_body);
    }

    ASSERT_TRUE(error_count < accpected_error);
    return s_tester_clean_up(&s_tester);
}
