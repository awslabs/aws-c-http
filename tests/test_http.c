/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/http.h>
#include <aws/testing/aws_test_harness.h>

static int s_test_http_error_code_is_retryable(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    int error_code = 0;
    ASSERT_FALSE(aws_http_error_code_is_retryable(error_code));

    {
        error_code = AWS_ERROR_HTTP_CONNECTION_CLOSED;
        ASSERT_TRUE(aws_http_error_code_is_retryable(error_code));
    }
    {
        error_code = AWS_ERROR_HTTP_SERVER_CLOSED;
        ASSERT_TRUE(aws_http_error_code_is_retryable(error_code));
    }

    error_code = AWS_ERROR_SUCCESS;
    ASSERT_FALSE(aws_http_error_code_is_retryable(error_code));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_http_error_code_is_retryable, s_test_http_error_code_is_retryable);
