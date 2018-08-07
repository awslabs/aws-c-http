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

#include <stdio.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/http/http.h>

static void s_print(struct aws_http_str str) {
    printf("%0.*s", (int)(size_t)(str.end - str.begin), str.begin);
}

static void s_print_request(struct aws_http_request *request) {
    printf("%s\n", aws_http_request_method_to_str(request->method));
    printf("%s\n", aws_http_version_code_to_str(request->version));
    for (int i = 0; i < request->header_count; ++i) {
        s_print(request->headers[i].key_str);
        printf(" : ");
        s_print(request->headers[i].value_str);
        printf("\n");
    }
    s_print(request->body);
    printf("\n");
}

AWS_TEST_CASE(dummy_test, dummy_test_fn)
static int dummy_test_fn(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;

    const char *request_str =
        "GET / HTTP/1.1\r\n"
        "Host: developer.mozilla.org\r\n"
        "Accept-Language: fr\r\n"
        "Content-Length : 6\r\n"
        "\r\n"
        "123456"
        ;

    struct aws_http_request request;
    aws_http_request_init(alloc, &request, request_str, strlen(request_str));
    s_print_request(&request);
    aws_http_request_clean_up(&request);

    return 0;
}
