/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/http/private/strutil.h>

#include <aws/testing/aws_test_harness.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

AWS_TEST_CASE(strutil_read_unsigned_num, s_strutil_read_unsigned_num);
static int s_strutil_read_unsigned_num(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    uint64_t val;

    /* sanity check */
    ASSERT_SUCCESS(aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("0"), &val));
    ASSERT_UINT_EQUALS(0, val);

    /* every acceptable character */
    ASSERT_SUCCESS(aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("9876543210"), &val));
    ASSERT_UINT_EQUALS(9876543210, val);

    /* max value */
    ASSERT_SUCCESS(aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("18446744073709551615"), &val));
    ASSERT_UINT_EQUALS(UINT64_MAX, val);

    /* leading zeros should have no effect */
    ASSERT_SUCCESS(aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("00000000000018446744073709551615"), &val));
    ASSERT_UINT_EQUALS(UINT64_MAX, val);

    /* one bigger than max */
    ASSERT_ERROR(
        AWS_ERROR_OVERFLOW_DETECTED,
        aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("18446744073709551616"), &val));

    /* overflow on base multiply */
    ASSERT_ERROR(
        AWS_ERROR_OVERFLOW_DETECTED,
        aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("184467440737095516150"), &val));

    /* whitespace is not ok */
    ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str(" 0"), &val));

    ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("0 "), &val));

    ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("0 0"), &val));

    /* blank strings are not ok */
    ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str(""), &val));

    /* hex is not ok */
    ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("0x0"), &val));

    ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_strutil_read_unsigned_num(aws_byte_cursor_from_c_str("FF"), &val));

    return 0;
}

AWS_TEST_CASE(strutil_read_unsigned_hex, s_strutil_read_unsigned_hex);
static int s_strutil_read_unsigned_hex(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    uint64_t val;

    /* sanity check */
    ASSERT_SUCCESS(aws_strutil_read_unsigned_hex(aws_byte_cursor_from_c_str("0"), &val));
    ASSERT_UINT_EQUALS(0x0, val);

    /* every possible character */
    ASSERT_SUCCESS(aws_strutil_read_unsigned_hex(aws_byte_cursor_from_c_str("9876543210"), &val));
    ASSERT_UINT_EQUALS(0x9876543210, val);

    ASSERT_SUCCESS(aws_strutil_read_unsigned_hex(aws_byte_cursor_from_c_str("ABCDEFabcdef"), &val));
    ASSERT_UINT_EQUALS(0xABCDEFabcdefULL, val);

    /* max value */
    ASSERT_SUCCESS(aws_strutil_read_unsigned_hex(aws_byte_cursor_from_c_str("ffffffffffffffff"), &val));
    ASSERT_UINT_EQUALS(UINT64_MAX, val);

    /* ignore leading zeroes */
    ASSERT_SUCCESS(aws_strutil_read_unsigned_hex(aws_byte_cursor_from_c_str("0000000000000000ffffffffffffffff"), &val));
    ASSERT_UINT_EQUALS(UINT64_MAX, val);

    /* overflow */
    ASSERT_ERROR(
        AWS_ERROR_OVERFLOW_DETECTED,
        aws_strutil_read_unsigned_hex(aws_byte_cursor_from_c_str("10000000000000000"), &val));

    /* overflow - regression test */
    ASSERT_ERROR(
        AWS_ERROR_OVERFLOW_DETECTED,
        aws_strutil_read_unsigned_hex(aws_byte_cursor_from_c_str("fffffffffffffffff"), &val));

    /* invalid character */
    ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_strutil_read_unsigned_hex(aws_byte_cursor_from_c_str("g"), &val));

    return 0;
}

AWS_TEST_CASE(strutil_trim_http_whitespace, s_strutil_trim_http_whitespace);
static int s_strutil_trim_http_whitespace(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct test {
        const char *input;
        const char *expected;
    };

    struct test tests[] = {
        {"a", "a"},
        {" a", "a"},
        {"a ", "a"},
        {"  a  ", "a"},
        {"", ""},
        {" ", ""},
        {"         ", ""},
        {"a", "a"},
        {"\t", ""},
        {"\ta", "a"},
        {"a\t", "a"},
        {"\t a \t", "a"},
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(tests); ++i) {
        struct aws_byte_cursor input = aws_byte_cursor_from_c_str(tests[i].input);
        struct aws_byte_cursor expected = aws_byte_cursor_from_c_str(tests[i].expected);
        struct aws_byte_cursor trimmed = aws_strutil_trim_http_whitespace(input);
        ASSERT_TRUE(aws_byte_cursor_eq(&expected, &trimmed));
    }

    return 0;
}