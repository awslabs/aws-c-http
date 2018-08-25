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

#include <aws/http/http_decode.h>

#include <aws/testing/aws_test_harness.h>

#include <ctype.h>
#include <stdio.h>

static bool s_on_header(struct aws_http_header header, void *user_data) {
    (void)header;
    (void)user_data;
    printf("%.*s:%.*s\n", (int)header.name_data.len, header.name_data.ptr, (int)header.value_data.len, header.value_data.ptr);
    return true;
}

bool s_on_body(struct aws_byte_cursor data, bool finished, void *user_data) {
    (void)data;
    (void)finished;
    (void)user_data;
    return true;
}

static int s_http_parse_lots_of_headers(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;

    /*const char *request_strs[] = {
        "GET / HTTP/1.1\r\n"
        "Host: developer.mozilla.org\r\n"
        "Accept-Language: fr\r\n"
        "Content-Length: 6\r\n"
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
    };*/

#if 0
    const char* request = 
        "GET / HTTP/1.1\r\n"
        "Host: developer.mozilla.org\r\n"
        "Accept-Language: fr\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "123456";
#else
    const char* request = 
        "GET / HTTP/1.1\r\n"
        "Host: developer.mozilla.org\r\n"
        "Accept-Language: fr\r\n"
        "Transfer-Encoding:   chunked     \r\n"
        "Trailer: Expires\r\n"
        "\r\n"
        "7\r\n"
        "Mozilla\r\n"
        "9\r\n"
        "Developer\r\n"
        "7\r\n"
        "Network\r\n"
        "0\r\n"
        "Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
        "\r\n";
#endif
    size_t request_len = strlen(request);

    struct aws_byte_buf scratch_space;
    aws_byte_buf_init(alloc, &scratch_space, 1024);

    struct aws_http_decoder_params params;
    params.alloc = alloc;
    params.scratch_space = scratch_space;
    params.on_header = s_on_header;
    params.on_body = s_on_body;
    params.true_for_request_false_for_response = true;
    params.user_data = NULL;

    struct aws_http_decoder *decoder = aws_http_decode_new(&params);

    for (int i = 0; i < (int)request_len; ++i) {
        ASSERT_SUCCESS(aws_http_decode(decoder, request + i, 1));
    }

    return 0;
}

AWS_TEST_CASE_FIXTURE(
    http_parse_lots_of_headers,
    s_http_parse_lots_of_headers,
    NULL
);
