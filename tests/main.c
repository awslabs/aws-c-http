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

#include "http_tests.h"

static int run_tests(int argc, char *argv[]) {
    AWS_RUN_TEST_CASES(
        &http_parse_lots_of_headers,
        &http_parse_and_lookup_header,
        &http_parse_bad_or_empty_input,
        );
}

int main(int argc, char *argv[]) {
    int ret_val = run_tests(argc, argv);
    return ret_val;
}
