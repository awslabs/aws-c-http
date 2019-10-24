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

#include <aws/http/private/connection_monitor.h>
#include <aws/http/connection.h>

#include <aws/testing/aws_test_harness.h>

static int s_test_http_connection_monitor_options_is_valid(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_http_connection_monitoring_options options;
    AWS_ZERO_STRUCT(options);

    ASSERT_FALSE(aws_http_connection_monitoring_options_is_valid(NULL));
    ASSERT_FALSE(aws_http_connection_monitoring_options_is_valid(&options));

    options.minimum_throughput_failure_threshold_in_seconds = 5;
    ASSERT_FALSE(aws_http_connection_monitoring_options_is_valid(&options));

    options.minimum_throughput_failure_threshold_in_seconds = 1;
    options.minimum_throughput_bytes_per_second = 1000;
    ASSERT_FALSE(aws_http_connection_monitoring_options_is_valid(&options));

    options.minimum_throughput_failure_threshold_in_seconds = 2;
    ASSERT_TRUE(aws_http_connection_monitoring_options_is_valid(&options));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_options_is_valid, s_test_http_connection_monitor_options_is_valid);

/*

 Options(3, 1000)


 Pattern

 Create a dummy channel with no handlers
 Create and attach a (X,Y) connection monitor
 Call process_statistics

 */