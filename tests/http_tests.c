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

#include <aws/common/array_list.h>

#include <aws/testing/aws_test_harness.h>

#include <ctype.h>
#include <stdio.h>

static const char *s_typical_request = "GET / HTTP/1.1\r\n"
                                       "Host: developer.mozilla.org\r\n"
                                       "Accept-Language: fr\r\n";

static const char *s_typical_response = "HTTP/1.1 200 OK\r\n"
                                        "Server: some-server\r\n"
                                        "Content-Length: 11\r\n"
                                        "\r\n"
                                        "Hello noob.";

static bool s_on_header_stub(struct aws_http_header header, void *user_data) {
    (void)header;
    (void)user_data;
    return true;
}

static bool s_on_body_stub(struct aws_byte_cursor data, bool finished, void *user_data) {
    (void)data;
    (void)finished;
    (void)user_data;
    return true;
}

static struct aws_http_decoder *s_common_test_setup(
    struct aws_allocator *allocator,
    struct aws_byte_buf *scratch_space,
    struct aws_http_decoder_params *params,
    bool type) {
    aws_byte_buf_init(allocator, scratch_space, 1024);

    params->alloc = allocator;
    params->scratch_space = *scratch_space;
    params->on_header = s_on_header_stub;
    params->on_body = s_on_body_stub;
    params->true_for_request_false_for_response = type;
    params->user_data = NULL;
    struct aws_http_decoder *decoder = aws_http_decoder_new(params);

    return decoder;
}

static void s_common_teardown(struct aws_http_decoder *decoder, struct aws_byte_buf *scratch_space) {
    aws_http_decoder_destroy(decoder);
    aws_byte_buf_clean_up(scratch_space);
}

AWS_TEST_CASE(http_test_get_version, s_http_test_get_version);
static int s_http_test_get_version(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = s_typical_request;
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, true);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    enum aws_http_version version;
    ASSERT_SUCCESS(aws_http_decoder_get_version(decoder, &version));
    ASSERT_TRUE(version == AWS_HTTP_VERSION_1_1);

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

static inline int s_strcmp_cursor(struct aws_byte_cursor cursor, const char *str) {
    size_t len = strlen(str);
    return strncmp((const char *)cursor.ptr, str, len < cursor.len ? len : cursor.len);
}

AWS_TEST_CASE(http_test_get_uri, s_http_test_get_uri);
static int s_http_test_get_uri(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = s_typical_request;
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, true);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    struct aws_byte_cursor uri_data;
    ASSERT_SUCCESS(aws_http_decoder_get_uri(decoder, &uri_data));
    ASSERT_TRUE(!s_strcmp_cursor(uri_data, "/"));

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

AWS_TEST_CASE(http_test_get_status_code, s_http_test_get_status_code);
static int s_http_test_get_status_code(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = s_typical_response;
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, false);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    enum aws_http_code code;
    ASSERT_SUCCESS(aws_http_decoder_get_code(decoder, &code));
    ASSERT_TRUE(code == AWS_HTTP_CODE_OK);

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

AWS_TEST_CASE(http_test_overflow_scratch_space, s_http_test_overflow_scratch_space);
static int s_http_test_overflow_scratch_space(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = s_typical_response;
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    aws_byte_buf_init(allocator, &scratch_space, 4);

    params.alloc = allocator;
    params.scratch_space = scratch_space;
    params.on_header = s_on_header_stub;
    params.on_body = s_on_body_stub;
    params.true_for_request_false_for_response = false;
    params.user_data = NULL;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    enum aws_http_code code;
    ASSERT_SUCCESS(aws_http_decoder_get_code(decoder, &code));
    ASSERT_TRUE(code == AWS_HTTP_CODE_OK);

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

struct s_header_params {
    int index;
    int max_index;
    int first_error;
    const char **header_names;
};

static inline bool s_got_header(struct aws_http_header header, void *user_data) {
    struct s_header_params *params = (struct s_header_params *)user_data;
    if (params->index < params->max_index) {
        if (params->first_error == AWS_OP_SUCCESS) {
            params->first_error =
                s_strcmp_cursor(header.name_data, params->header_names[params->index]) ? AWS_OP_ERR : AWS_OP_SUCCESS;
        }
        params->index++;
    } else {
        return false;
    }

    return true;
}

AWS_TEST_CASE(http_test_recieve_request_headers, s_http_test_recieve_request_headers);
static int s_http_test_recieve_request_headers(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = s_typical_request;
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct s_header_params header_params;

    aws_byte_buf_init(allocator, &scratch_space, 1024);

    const char *header_names[] = {"Host", "Accept-Language"};
    header_params.index = 0;
    header_params.max_index = AWS_ARRAY_SIZE(header_names);
    header_params.first_error = AWS_OP_SUCCESS;
    header_params.header_names = header_names;

    params.alloc = allocator;
    params.scratch_space = scratch_space;
    params.on_header = s_got_header;
    params.on_body = s_on_body_stub;
    params.true_for_request_false_for_response = true;
    params.user_data = &header_params;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_SUCCESS(header_params.first_error);

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

AWS_TEST_CASE(http_test_recieve_response_headers, s_http_test_recieve_response_headers);
static int s_http_test_recieve_response_headers(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = s_typical_response;
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct s_header_params header_params;

    aws_byte_buf_init(allocator, &scratch_space, 1024);

    const char *header_names[] = {"Server", "Content-Length"};
    header_params.index = 0;
    header_params.max_index = AWS_ARRAY_SIZE(header_names);
    header_params.first_error = AWS_OP_SUCCESS;
    header_params.header_names = header_names;

    params.alloc = allocator;
    params.scratch_space = scratch_space;
    params.on_header = s_got_header;
    params.on_body = s_on_body_stub;
    params.true_for_request_false_for_response = false;
    params.user_data = &header_params;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_SUCCESS(header_params.first_error);

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

AWS_TEST_CASE(http_test_get_transfer_encoding_flags, s_http_test_get_transfer_encoding_flags);
static int s_http_test_get_transfer_encoding_flags(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = "HTTP/1.1 200 OK\r\n"
                      "Server: some-server\r\n"
                      "Content-Length: 11\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "Transfer-Encoding: compress\r\n"
                      "Transfer-Encoding: gzip, deflate\r\n"
                      "Transfer-Encoding: identity\r\n"
                      "\r\n"
                      "Hello noob.";
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, false);

    size_t len = strlen(msg);
    /* Not a valid HTTP1.1 message, but not the job of decoder to return error here. */
    /* Instead, the user should know their buffer has been processed without returning any body data, and
     * report the error in user-space. */
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    int flags;
    ASSERT_SUCCESS(aws_http_decoder_get_encoding_flags(decoder, &flags));
    ASSERT_TRUE(
        flags == (AWS_HTTP_TRANSFER_ENCODING_CHUNKED | AWS_HTTP_TRANSFER_ENCODING_GZIP |
                  AWS_HTTP_TRANSFER_ENCODING_DEFLATE | AWS_HTTP_TRANSFER_ENCODING_DEPRECATED_COMPRESS));

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

struct s_body_params {
    struct aws_array_list body_data;
};

static bool s_on_body(struct aws_byte_cursor data, bool finished, void *user_data) {
    (void)finished;

    struct s_body_params *params = (struct s_body_params *)user_data;
    for (int i = 0; i < (int)data.len; ++i) {
        aws_array_list_push_back(&params->body_data, data.ptr + i);
    }

    return true;
}

AWS_TEST_CASE(http_test_body_unchunked, s_http_test_body_unchunked);
static int s_http_test_body_unchunked(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = s_typical_response;
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct s_body_params body_params;

    aws_array_list_init_dynamic(&body_params.body_data, allocator, 256, sizeof(uint8_t));
    aws_byte_buf_init(allocator, &scratch_space, 1024);

    params.alloc = allocator;
    params.scratch_space = scratch_space;
    params.on_header = s_on_header_stub;
    params.on_body = s_on_body;
    params.true_for_request_false_for_response = false;
    params.user_data = &body_params;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_SUCCESS(memcmp(body_params.body_data.data, "Hello noob.", body_params.body_data.length));

    s_common_teardown(decoder, &scratch_space);
    aws_array_list_clean_up(&body_params.body_data);

    return 0;
}

AWS_TEST_CASE(http_test_body_chunked, s_http_test_body_chunked);
static int s_http_test_body_chunked(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *msg = "GET / HTTP/1.1\r\n"
                      "Host: amazon.com\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "\r\n"
                      "D\r\n"
                      "Hello, there \r\n"
                      "1C\r\n"
                      "should be a carriage return \r\n"
                      "9\r\n"
                      "in\r\nhere.\r\n"
                      "0\r\n"
                      "\r\n";
    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct s_body_params body_params;

    aws_array_list_init_dynamic(&body_params.body_data, allocator, 256, sizeof(uint8_t));
    aws_byte_buf_init(allocator, &scratch_space, 1024);

    params.alloc = allocator;
    params.scratch_space = scratch_space;
    params.on_header = s_on_header_stub;
    params.on_body = s_on_body;
    params.true_for_request_false_for_response = true;
    params.user_data = &body_params;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_SUCCESS(memcmp(
        body_params.body_data.data,
        "Hello, there should be a carriage return in\r\nhere.",
        body_params.body_data.length));

    s_common_teardown(decoder, &scratch_space);
    aws_array_list_clean_up(&body_params.body_data);

    return 0;
}

AWS_TEST_CASE(http_decode_one_byte_at_a_time_and_trailers, s_http_decode_one_byte_at_a_time_and_trailers);
static int s_http_decode_one_byte_at_a_time_and_trailers(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *request = "GET / HTTP/1.1\r\n"
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

    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, true);

    size_t len = strlen(request);
    for (int i = 0; i < len; ++i) {
        ASSERT_SUCCESS(aws_http_decode(decoder, request + i, 1, NULL));
    }

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

static inline int s_rand(int lo, int hi) {
    return rand() % (hi + 1 - lo) + lo;
}

AWS_TEST_CASE(http_decode_messages_at_random_intervals, s_http_decode_messages_at_random_intervals);
static int s_http_decode_messages_at_random_intervals(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *requests[] = {
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
        "0123456789",

        "POST / HTTP/1.1\r\n"
        "Host: foo.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "say=Hi&to=Mom",

        "PUT /new.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-type: text/html\r\n"
        "Content-length: 16\r\n"
        "\r\n"
        "<p>New File</p>",

        "TRACE /index.html HTTP/1.1\r\n",

        "GET /home.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "a-fake-header:      oh   what is this odd     whitespace      \r\n"
        "Content-Length: 1\r\n"
        "\r\n"
        "X",
    };

    /* Just seed something for determinism. */
    srand(1);

    for (int iter = 0; iter < AWS_ARRAY_SIZE(requests); ++iter) {
        const char *request = requests[iter];

        struct aws_byte_buf scratch_space;
        struct aws_http_decoder_params params;
        struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, true);

        /* Decode message at randomized input buffer sizes from 0 to 10 bytes. */
        size_t len = strlen(request);
        while (len) {
            int lo = 1;
            int hi = 10;
            if (hi > (int)len) {
                hi = (int)len;
            }
            int interval = s_rand(lo, hi);
            ASSERT_SUCCESS(aws_http_decode(decoder, request, interval, NULL));
            request += interval;
            len -= (size_t)interval;
        }

        s_common_teardown(decoder, &scratch_space);
    }

    return 0;
}

AWS_TEST_CASE(http_decode_bad_messages_and_assert_failure, s_http_decode_bad_messages_and_assert_failure);
static int s_http_decode_bad_messages_and_assert_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *requests[] = {
        /* Incorrect chunk size. */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "7\r\n"
        "Mozilla\r\n"
        "2\r\n" /* Incorrect chunk size here. */
        "Developer\r\n"
        "7\r\n"
        "Network\r\n"
        "0\r\n"
        "\r\n",

        /* Invalid transfer encoding. */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: punked\r\n"
        "\r\n",

        /* Invalid hex-int as chunk size. */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "7\r\n"
        "Mozilla\r\n"
        "S\r\n" /* Incorrect chunk size here. */
        "Developer\r\n"
        "7\r\n"
        "Network\r\n"
        "0\r\n"
        "\r\n"

        /* Invalid chunk size terminator. */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "7\r0asa90",

        /* Go ahead and add more cases here. */
    };

    for (int iter = 0; iter < AWS_ARRAY_SIZE(requests); ++iter) {
        const char *request = requests[iter];

        struct aws_byte_buf scratch_space;
        struct aws_http_decoder_params params;
        struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, true);

        size_t len = strlen(request);
        ASSERT_FAILS(aws_http_decode(decoder, request, len, NULL));

        s_common_teardown(decoder, &scratch_space);
    }

    return 0;
}

AWS_TEST_CASE(
    http_test_extraneous_buffer_data_ensure_not_processed,
    s_http_test_extraneous_buffer_data_ensure_not_processed);
static int s_http_test_extraneous_buffer_data_ensure_not_processed(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *request = "GET / HTTP/1.1\r\n"
                          "Wow look here. That's a lot of extra random stuff!";

    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, true);

    size_t len = strlen("GET / HTTP/1.1\r\n");
    size_t size_read;
    ASSERT_SUCCESS(aws_http_decode(decoder, request, len, &size_read));
    ASSERT_TRUE(size_read == len);

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

AWS_TEST_CASE(http_test_ignore_transfer_extensions, s_http_test_ignore_transfer_extensions);
static int s_http_test_ignore_transfer_extensions(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *request = "GET / HTTP/1.1\r\n"
                          "Transfer-Encoding: token; fake=extension";

    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, true);

    size_t len = strlen(request);
    ASSERT_SUCCESS(aws_http_decode(decoder, request, len, NULL));

    s_common_teardown(decoder, &scratch_space);

    return 0;
}

AWS_TEST_CASE(http_test_ignore_chunk_extensions, s_http_test_ignore_chunk_extensions);
static int s_http_test_ignore_chunk_extensions(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *request = "GET / HTTP/1.1\r\n"
                          "Host: developer.mozilla.org\r\n"
                          "Accept-Language: fr\r\n"
                          "Transfer-Encoding:   chunked     \r\n"
                          "Trailer: Expires\r\n"
                          "\r\n"
                          "7;some-dumb-chunk-extension-name=some-dumb-chunk-extension-value\r\n"
                          "Mozilla\r\n"
                          "9\r\n"
                          "Developer\r\n"
                          "7\r\n"
                          "Network\r\n"
                          "0\r\n"
                          "Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
                          "\r\n";

    struct aws_byte_buf scratch_space;
    struct aws_http_decoder_params params;
    struct aws_http_decoder *decoder = s_common_test_setup(allocator, &scratch_space, &params, true);

    size_t len = strlen(request);
    ASSERT_SUCCESS(aws_http_decode(decoder, request, len, NULL));

    s_common_teardown(decoder, &scratch_space);

    return 0;
}
