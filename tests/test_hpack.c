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

AWS_TEST_CASE(hpack_encode_integer, test_hpack_encode_integer)
static int test_hpack_encode_integer(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;
    /* Test encoding integers
       Test cases taken from https://httpwg.org/specs/rfc7541.html#integer.representation.examples */

    uint8_t zeros[4];
    AWS_ZERO_ARRAY(zeros);

    uint8_t output_buffer[4];
    struct aws_byte_buf output_buf;

    /* Test 10 in 5 bits */
    AWS_ZERO_ARRAY(output_buffer);
    output_buf = aws_byte_buf_from_empty_array(output_buffer, AWS_ARRAY_SIZE(output_buffer));
    ASSERT_SUCCESS(aws_hpack_encode_integer(10, 5, &output_buf));
    /**
     * Expected:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     */
    ASSERT_UINT_EQUALS(1, output_buf.len);
    ASSERT_UINT_EQUALS(10, output_buffer[0]);
    ASSERT_BIN_ARRAYS_EQUALS(zeros, 3, &output_buffer[1], 3);

    /* Test 42 in 8 bits */
    AWS_ZERO_ARRAY(output_buffer);
    output_buf = aws_byte_buf_from_empty_array(output_buffer, AWS_ARRAY_SIZE(output_buffer));
    ASSERT_SUCCESS(aws_hpack_encode_integer(42, 8, &output_buf));
    /**
     * Expected:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 0 |  42
     * +---+---+---+---+---+---+---+---+
     */
    ASSERT_UINT_EQUALS(1, output_buf.len);
    ASSERT_UINT_EQUALS(42, output_buffer[0]);
    ASSERT_BIN_ARRAYS_EQUALS(zeros, 3, &output_buffer[1], 3);

    /* Test 1337 with 5bit prefix */
    AWS_ZERO_ARRAY(output_buffer);
    output_buf = aws_byte_buf_from_empty_array(output_buffer, AWS_ARRAY_SIZE(output_buffer));
    ASSERT_SUCCESS(aws_hpack_encode_integer(1337, 5, &output_buf));
    /**
     * Expected:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 1 | 1 | 1 | 1 | 1 |  31
     * | 1 | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 154
     * | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     */
    ASSERT_UINT_EQUALS(3, output_buf.len);
    ASSERT_UINT_EQUALS(UINT8_MAX >> 3, output_buffer[0]);
    ASSERT_UINT_EQUALS(154, output_buffer[1]);
    ASSERT_UINT_EQUALS(10, output_buffer[2]);
    ASSERT_UINT_EQUALS(0, output_buffer[3]);

    /* Test 1337 with 5bit prefix and insufficient output space */
    AWS_ZERO_ARRAY(output_buffer);
    output_buf = aws_byte_buf_from_empty_array(output_buffer, 2);
    ASSERT_FAILS(aws_hpack_encode_integer(1337, 5, &output_buf));
    ASSERT_UINT_EQUALS(0, output_buf.len);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_decode_integer, test_hpack_decode_integer)
static int test_hpack_decode_integer(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;
    /* Test encoding integers
       Test cases taken from https://httpwg.org/specs/rfc7541.html#integer.representation.examples */

    uint64_t result = 0;
    struct aws_byte_cursor to_decode;

    /* Test 10 in 5 bits
     * Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_1[] = {10};
    to_decode = aws_byte_cursor_from_array(test_1, AWS_ARRAY_SIZE(test_1));
    ASSERT_SUCCESS(aws_hpack_decode_integer(&to_decode, 5, &result));
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_UINT_EQUALS(10, result);

    /* Test 42 in 8 bits
     * Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 0 |  42
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_2[] = {42};
    to_decode = aws_byte_cursor_from_array(test_2, AWS_ARRAY_SIZE(test_2));
    ASSERT_SUCCESS(aws_hpack_decode_integer(&to_decode, 8, &result));
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_UINT_EQUALS(42, result);

    /* Test 1337 with 5bit prefix
     * Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 1 | 1 | 1 | 1 | 1 |  31
     * | 1 | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 154
     * | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |  10
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_3[] = {UINT8_MAX >> 3, 154, 10};
    to_decode = aws_byte_cursor_from_array(test_3, AWS_ARRAY_SIZE(test_3));
    ASSERT_SUCCESS(aws_hpack_decode_integer(&to_decode, 5, &result));
    ASSERT_UINT_EQUALS(0, to_decode.len);
    ASSERT_UINT_EQUALS(1337, result);

    /* Test number ending with continue byte
     * Layout:
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | X | X | X | 1 | 1 | 1 | 1 | 1 |  31
     * | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 127
     * +---+---+---+---+---+---+---+---+
     */
    uint8_t test_4[] = {UINT8_MAX >> 3, UINT8_MAX};
    to_decode = aws_byte_cursor_from_array(test_4, AWS_ARRAY_SIZE(test_4));
    ASSERT_FAILS(aws_hpack_decode_integer(&to_decode, 5, &result));
    ASSERT_UINT_EQUALS(AWS_ERROR_SHORT_BUFFER, aws_last_error());
    ASSERT_UINT_EQUALS(AWS_ARRAY_SIZE(test_4), to_decode.len);

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
    to_decode = aws_byte_cursor_from_array(test_5, AWS_ARRAY_SIZE(test_5));
    ASSERT_FAILS(aws_hpack_decode_integer(&to_decode, 5, &result));
    ASSERT_UINT_EQUALS(AWS_ERROR_OVERFLOW_DETECTED, aws_last_error());
    ASSERT_UINT_EQUALS(AWS_ARRAY_SIZE(test_5), to_decode.len);

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

    aws_hpack_static_table_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, 0);

    size_t index = 0;

    DEFINE_STATIC_HEADER(s_authority, ":authority", "amazon.com");
    DEFINE_STATIC_HEADER(s_get, ":method", "GET");
    DEFINE_STATIC_HEADER(s_garbage, "colden's favorite ice cream flavor", "cookie dough");

    /* Test header without value */
    ASSERT_SUCCESS(aws_hpack_find_index(context, &s_authority, &index));
    ASSERT_UINT_EQUALS(1, index);

    /* Test header with value */
    ASSERT_SUCCESS(aws_hpack_find_index(context, &s_get, &index));
    ASSERT_UINT_EQUALS(2, index);

    /* Check invalid header */
    ASSERT_FAILS(aws_hpack_find_index(context, &s_garbage, &index));

    aws_hpack_context_destroy(context);
    aws_hpack_static_table_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_static_table_get, test_hpack_static_table_get)
static int test_hpack_static_table_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_hpack_static_table_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, 0);

    struct aws_http_header *found = NULL;

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
    aws_hpack_static_table_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_dynamic_table_find, test_hpack_dynamic_table_find)
static int test_hpack_dynamic_table_find(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_hpack_static_table_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, 2);

    size_t index = 0;

    DEFINE_STATIC_HEADER(s_herp, "herp", "derp");
    DEFINE_STATIC_HEADER(s_fizz, "fizz", "buzz");

    /* Test header without value */
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &s_herp));
    ASSERT_SUCCESS(aws_hpack_find_index(context, &s_herp, &index));
    ASSERT_UINT_EQUALS(62, index);

    /* Test header with value */
    ASSERT_SUCCESS(aws_hpack_insert_header(context, &s_fizz));
    ASSERT_SUCCESS(aws_hpack_find_index(context, &s_fizz, &index));
    ASSERT_UINT_EQUALS(62, index);
    ASSERT_SUCCESS(aws_hpack_find_index(context, &s_herp, &index));
    ASSERT_UINT_EQUALS(63, index);

    /* Check invalid header */
    DEFINE_STATIC_HEADER(s_garbage, "colden's mother's maiden name", "nice try mr hacker");
    ASSERT_FAILS(aws_hpack_find_index(context, &s_garbage, &index));

    /* Test resizing */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, 1));

    ASSERT_SUCCESS(aws_hpack_find_index(context, &s_fizz, &index));
    ASSERT_UINT_EQUALS(62, index);
    ASSERT_FAILS(aws_hpack_find_index(context, &s_herp, &index));

    aws_hpack_context_destroy(context);
    aws_hpack_static_table_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_dynamic_table_get, test_hpack_dynamic_table_get)
static int test_hpack_dynamic_table_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_hpack_static_table_init(allocator);
    struct aws_hpack_context *context = aws_hpack_context_new(allocator, 2);

    struct aws_http_header *found = NULL;

    DEFINE_STATIC_HEADER(s_herp, "herp", "derp");
    DEFINE_STATIC_HEADER(s_fizz, "fizz", "buzz");
    DEFINE_STATIC_HEADER(s_status, ":status", "418");

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

    /* Test resizing */
    ASSERT_SUCCESS(aws_hpack_resize_dynamic_table(context, 1));

    found = aws_hpack_get_header(context, 62);
    ASSERT_NOT_NULL(found);
    ASSERT_TRUE(aws_byte_cursor_eq(&s_status.name, &found->name));
    ASSERT_TRUE(aws_byte_cursor_eq(&s_status.value, &found->value));
    found = aws_hpack_get_header(context, 63);
    ASSERT_NULL(found);

    aws_hpack_context_destroy(context);
    aws_hpack_static_table_clean_up();
    return AWS_OP_SUCCESS;
}
