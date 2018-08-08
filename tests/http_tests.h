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
    s_print(request->target);
    printf("\n");
    printf("%s\n", aws_http_version_code_to_str(request->version));
    for (int i = 0; i < request->data.header_count; ++i) {
        s_print(request->data.headers[i].key_str);
        printf(":");
        s_print(request->data.headers[i].value_str);
        printf("\n");
    }
    s_print(request->data.body);
    printf("\n");
}

AWS_TEST_CASE(dummy_test, dummy_test_fn)
static int dummy_test_fn(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;

    const char *request_strs[] = {
        "GET / HTTP/1.1\r\n"
        "Host: developer.mozilla.org\r\n"
        "Accept-Language: fr\r\n"
        "Content-Length : 6\r\n"
        "\r\n"
        "123456",

        "CONNECT server.example.com:80 HTTP/1.1\r\n"
        "Host: server.example.com:80\r\n"
        "Proxy-Authorization: basic aGVsbG86d29ybGQ=\r\n",

        "DELETE /file.html HTTP/1.1\r\n",

        "HEAD /index.html HTTP/1.1\r\n",

        "OPTIONS /index.html HTTP/1.1\r\n",

        "OPTIONS * HTTP/1.1\r\n",

        "PATCH /file.txt HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Content-Type: application/example\r\n"
        "If-Match: \"e0023aa4e\"\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "0123456789\r\n",

        "POST / HTTP/1.1\r\n"
        "Host: foo.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "say=Hi&to=Mom\r\n",

        "PUT /new.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-type: text/html\r\n"
        "Content-length: 16\r\n"
        "\r\n"
        "<p>New File</p>\r\n",

        "TRACE /index.html HTTP/1.1\r\n",

        "GET /home.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "a-fake-header:      oh   what is this odd     whitespace      \r\n"
        "another-fake-header:   the message data has a trailing crlf beyond it ...  \r\n"
        "Content-Length : 1\r\n"
        "\r\n"
        "X\r\n",
    };

    for (int i = 0; i < sizeof(request_strs) / sizeof(*request_strs); ++i) {
        struct aws_http_request request;
        const char *request_str = request_strs[i];
        ASSERT_SUCCESS(aws_http_request_init(alloc, &request, request_str, strlen(request_str)));
        s_print_request(&request);
        printf("\n");
        aws_http_request_clean_up(&request);
    }

    return 0;
}
