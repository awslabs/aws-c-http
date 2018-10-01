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

#include <aws/http/queue.h>

#include <aws/testing/aws_test_harness.h>

AWS_TEST_CASE(http_test_queue_typical_usecase, s_http_test_queue_typical_usecase);
static int s_http_test_queue_typical_usecase(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_queue q;
    aws_queue_init(&q, sizeof(int) * 2, allocator);

    int a = 4;
    int b = 6;

    aws_queue_push(&q, &a, sizeof(int));
    aws_queue_push(&q, &b, sizeof(int));

    int c;

    aws_queue_pull(&q, &c, sizeof(int));
    ASSERT_INT_EQUALS(4, c);

    int d;
    int e = 13;

    aws_queue_push(&q, &e, sizeof(int));
    aws_queue_pull(&q, &d, sizeof(int));
    ASSERT_INT_EQUALS(6, d);

    int f;

    aws_queue_pull(&q, &f, sizeof(int));
    ASSERT_INT_EQUALS(13, f);

    aws_queue_clean_up(&q);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_queue_static, s_http_test_queue_static);
static int s_http_test_queue_static(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    int mem[3];

    struct aws_queue q;
    aws_queue_init_static(&q, mem, sizeof(mem));

    int a = 1;
    int b = 2;
    int c = 3;
    int d;

    aws_queue_push(&q, &a, sizeof(int));
    aws_queue_push(&q, &b, sizeof(int));
    aws_queue_push(&q, &c, sizeof(int));

    aws_queue_pull(&q, &d, sizeof(int));
    ASSERT_INT_EQUALS(a, d);

    aws_queue_pull(&q, &d, sizeof(int));
    ASSERT_INT_EQUALS(b, d);

    aws_queue_push(&q, &c, sizeof(int));
    aws_queue_push(&q, &c, sizeof(int));

    aws_queue_pull(&q, &d, sizeof(int));
    ASSERT_INT_EQUALS(c, d);
    aws_queue_pull(&q, &d, sizeof(int));
    ASSERT_INT_EQUALS(c, d);
    aws_queue_pull(&q, &d, sizeof(int));
    ASSERT_INT_EQUALS(c, d);

    aws_queue_clean_up(&q);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_queue_overflow, s_http_test_queue_overflow);
static int s_http_test_queue_overflow(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_queue q;
    aws_queue_init(&q, sizeof(int) * 2, allocator);

    int a = 4;
    int b = 6;
    int c = 10;
    int d;

    ASSERT_SUCCESS(aws_queue_push(&q, &a, sizeof(int)));
    ASSERT_SUCCESS(aws_queue_push(&q, &b, sizeof(int)));
    ASSERT_FAILS(aws_queue_push(&q, &c, sizeof(int)));

    ASSERT_SUCCESS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(4, d);
    ASSERT_SUCCESS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(6, d);
    ASSERT_FAILS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(6, d);

    aws_queue_clean_up(&q);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_queue_resize, s_http_test_queue_resize);
static int s_http_test_queue_resize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_queue q;
    aws_queue_init(&q, sizeof(int) * 2, allocator);

    int a = 4;
    int b = 6;

    ASSERT_SUCCESS(aws_queue_push(&q, &a, sizeof(int)));
    ASSERT_SUCCESS(aws_queue_push(&q, &b, sizeof(int)));
    ASSERT_FAILS(aws_queue_push(&q, &b, sizeof(int)));

    ASSERT_SUCCESS(aws_queue_resize(&q, sizeof(int) * 3));

    int c;

    ASSERT_SUCCESS(aws_queue_pull(&q, &c, sizeof(int)));
    ASSERT_INT_EQUALS(4, c);
    ASSERT_SUCCESS(aws_queue_pull(&q, &c, sizeof(int)));
    ASSERT_INT_EQUALS(6, c);
    ASSERT_FAILS(aws_queue_pull(&q, &c, sizeof(int)));
    ASSERT_INT_EQUALS(6, c);

    c = 10;

    ASSERT_SUCCESS(aws_queue_push(&q, &a, sizeof(int)));
    ASSERT_SUCCESS(aws_queue_push(&q, &b, sizeof(int)));
    ASSERT_SUCCESS(aws_queue_push(&q, &c, sizeof(int)));
    ASSERT_FAILS(aws_queue_push(&q, &c, sizeof(int)));

    int d;

    ASSERT_SUCCESS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(4, d);
    ASSERT_SUCCESS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(6, d);
    ASSERT_SUCCESS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(10, d);
    ASSERT_FAILS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(10, d);

    ASSERT_SUCCESS(aws_queue_push(&q, &a, sizeof(int)));
    ASSERT_SUCCESS(aws_queue_push(&q, &b, sizeof(int)));
    ASSERT_FAILS(aws_queue_resize(&q, sizeof(int) * 1));
    ASSERT_SUCCESS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(4, d);
    ASSERT_SUCCESS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(6, d);
    ASSERT_FAILS(aws_queue_pull(&q, &d, sizeof(int)));
    ASSERT_INT_EQUALS(6, d);

    aws_queue_clean_up(&q);

    return AWS_OP_SUCCESS;
}
