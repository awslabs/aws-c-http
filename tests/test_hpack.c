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

#include <aws/http/hpack.h>

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

    return AWS_OP_SUCCESS;
}
