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

#include <aws/http/private/decode.h>

#include <aws/common/array_list.h>
#include <aws/io/logging.h>
#include <aws/testing/aws_test_harness.h>

#include <ctype.h>
#include <stdio.h>

static const char *s_typical_request = "GET / HTTP/1.1\r\n"
                                       "Host: amazon.com\r\n"
                                       "Accept-Language: fr\r\n"
                                       "\r\n";

static const char *s_typical_response = "HTTP/1.1 200 OK\r\n"
                                        "Server: some-server\r\n"
                                        "Content-Length: 11\r\n"
                                        "\r\n"
                                        "Hello noob.";

static const bool s_request = true;
static const bool s_response = false;

static struct aws_logger s_logger;

static int s_on_header_stub(const struct aws_http_decoded_header *header, void *user_data) {
    (void)header;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

static int s_on_body_stub(const struct aws_byte_cursor *data, bool finished, void *user_data) {
    (void)data;
    (void)finished;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

static int s_on_response(int code, void *user_data) {
    int *ptr = (int *)user_data;
    if (ptr) {
        *ptr = code;
    }
    return AWS_OP_SUCCESS;
}

static int s_on_response_stub(int code, void *user_data) {
    (void)code;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

struct request_data {
    enum aws_http_method method_enum;
    struct aws_byte_cursor method_str;
    struct aws_byte_cursor uri;
    uint8_t buffer[1024];
};

static int s_on_request(
    enum aws_http_method method_enum,
    const struct aws_byte_cursor *method_str,
    const struct aws_byte_cursor *uri,
    void *user_data) {

    struct request_data *request_data = (struct request_data *)user_data;
    assert(sizeof(request_data->buffer) >= uri->len + method_str->len);
    if (request_data) {
        request_data->method_enum = method_enum;

        memcpy(request_data->buffer, method_str->ptr, method_str->len);
        request_data->method_str = aws_byte_cursor_from_array(request_data->buffer, method_str->len);

        uint8_t *uri_dst = request_data->buffer + method_str->len;
        memcpy(uri_dst, uri->ptr, uri->len);
        request_data->uri = aws_byte_cursor_from_array(uri_dst, uri->len);
    }

    return AWS_OP_SUCCESS;
}

static int s_on_request_stub(
    enum aws_http_method method_enum,
    const struct aws_byte_cursor *method_str,
    const struct aws_byte_cursor *uri,
    void *user_data) {

    (void)method_enum;
    (void)method_str;
    (void)uri;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

static int s_on_done(void *user_data) {
    (void)user_data;
    return AWS_OP_SUCCESS;
}

static void s_test_init(struct aws_allocator *allocator) {

    aws_load_error_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();
    aws_http_library_init(allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    aws_logger_init_standard(&s_logger, allocator, &logger_options);
    aws_logger_set(&s_logger);
}

static void s_test_clean_up(void) {
    aws_http_library_clean_up();
    aws_logger_clean_up(&s_logger);
}

static void s_common_decoder_setup(
    struct aws_allocator *allocator,
    size_t scratch_space_size,
    struct aws_http_decoder_params *params,
    bool type,
    void *user_data) {

    params->alloc = allocator;
    params->scratch_space_initial_size = scratch_space_size;
    params->is_decoding_requests = type;
    params->user_data = user_data;
    params->vtable.on_header = s_on_header_stub;
    params->vtable.on_body = s_on_body_stub;
    params->vtable.on_request = s_on_request_stub;
    params->vtable.on_response = s_on_response_stub;
    params->vtable.on_done = s_on_done;
}

AWS_TEST_CASE(http_test_get_request, s_http_test_get_request);
static int s_http_test_get_request(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);

    struct request_data request_data;

    const char *msg = "HEAD / HTTP/1.1\r\n\r\n";

    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_request, &request_data);
    params.vtable.on_request = s_on_request;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_INT_EQUALS(AWS_HTTP_METHOD_HEAD, request_data.method_enum);

    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request_data.method_str, "HEAD"));

    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&request_data.uri, "/"));

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_request_bad_version, s_http_test_request_bad_version);
static int s_http_test_request_bad_version(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *msg = "GET / HTTP/1.0\r\n\r\n"; /* Note version is 1.0 */

    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_request, NULL);
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_FAILS(aws_http_decode(decoder, msg, len, NULL));

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_response_bad_version, s_http_test_response_bad_version);
static int s_http_test_response_bad_version(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *msg = "HTTP/1.0 200 OK\r\n\r\n"; /* Note version is "1.0" */

    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_response, NULL);
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_FAILS(aws_http_decode(decoder, msg, len, NULL));

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_get_status_code, s_http_test_get_status_code);
static int s_http_test_get_status_code(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    int code;

    const char *msg = s_typical_response;
    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_response, &code);
    params.vtable.on_response = s_on_response;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_INT_EQUALS(200, code);

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_overflow_scratch_space, s_http_test_overflow_scratch_space);
static int s_http_test_overflow_scratch_space(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);

    const char *msg = s_typical_response;
    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 4, &params, s_response, NULL);
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

struct s_header_params {
    int index;
    int max_index;
    int first_error;
    const char **header_names;
};

static int s_got_header(const struct aws_http_decoded_header *header, void *user_data) {
    struct s_header_params *params = (struct s_header_params *)user_data;
    if (params->index < params->max_index) {
        if (params->first_error == AWS_OP_SUCCESS) {
            if (!aws_byte_cursor_eq_c_str(&header->name_data, params->header_names[params->index])) {
                params->first_error = AWS_OP_ERR;
            }
        }
        params->index++;
    } else {
        return aws_raise_error(AWS_ERROR_UNKNOWN);
    }

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_receive_request_headers, s_http_test_receive_request_headers);
static int s_http_test_receive_request_headers(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *msg = s_typical_request;
    struct aws_http_decoder_params params;
    struct s_header_params header_params;
    s_common_decoder_setup(allocator, 1024, &params, s_request, &header_params);

    const char *header_names[] = {"Host", "Accept-Language"};
    header_params.index = 0;
    header_params.max_index = AWS_ARRAY_SIZE(header_names);
    header_params.first_error = AWS_OP_SUCCESS;
    header_params.header_names = header_names;

    params.vtable.on_header = s_got_header;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_SUCCESS(header_params.first_error);

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_receive_response_headers, s_http_test_receive_response_headers);
static int s_http_test_receive_response_headers(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *msg = s_typical_response;
    struct aws_http_decoder_params params;
    struct s_header_params header_params;
    s_common_decoder_setup(allocator, 1024, &params, s_response, &header_params);

    const char *header_names[] = {"Server", "Content-Length"};
    header_params.index = 0;
    header_params.max_index = AWS_ARRAY_SIZE(header_names);
    header_params.first_error = AWS_OP_SUCCESS;
    header_params.header_names = header_names;

    params.vtable.on_header = s_got_header;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_SUCCESS(header_params.first_error);

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_get_transfer_encoding_flags, s_http_test_get_transfer_encoding_flags);
static int s_http_test_get_transfer_encoding_flags(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *msg = "HTTP/1.1 200 OK\r\n"
                      "Server: some-server\r\n"
                      "Transfer-Encoding: compress\r\n"
                      "Transfer-Encoding: gzip, ,deflate\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "Transfer-Encoding:\r\n"
                      "\r\n"
                      "Hello noob.";
    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_response, NULL);
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    /* Not a valid HTTP1.1 message, but not the job of decoder to return error here. */
    /* Instead, the user should know their buffer has been processed without returning any body data, and
     * report the error in user-space. */
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    int flags = aws_http_decoder_get_encoding_flags(decoder);
    ASSERT_INT_EQUALS(
        (AWS_HTTP_TRANSFER_ENCODING_CHUNKED | AWS_HTTP_TRANSFER_ENCODING_GZIP | AWS_HTTP_TRANSFER_ENCODING_DEFLATE |
         AWS_HTTP_TRANSFER_ENCODING_DEPRECATED_COMPRESS),
        flags);

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

struct s_body_params {
    struct aws_array_list body_data;
};

static int s_on_body(const struct aws_byte_cursor *data, bool finished, void *user_data) {
    (void)finished;

    struct s_body_params *params = (struct s_body_params *)user_data;
    for (int i = 0; i < (int)data->len; ++i) {
        aws_array_list_push_back(&params->body_data, data->ptr + i);
    }

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_body_unchunked, s_http_test_body_unchunked);
static int s_http_test_body_unchunked(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *msg = s_typical_response;
    struct aws_http_decoder_params params;
    struct s_body_params body_params;
    s_common_decoder_setup(allocator, 1024, &params, s_response, NULL);

    aws_array_list_init_dynamic(&body_params.body_data, allocator, 256, sizeof(uint8_t));

    params.alloc = allocator;
    params.scratch_space_initial_size = 1024;
    params.vtable.on_header = s_on_header_stub;
    params.vtable.on_body = s_on_body;
    params.is_decoding_requests = false;
    params.user_data = &body_params;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_SUCCESS(memcmp(body_params.body_data.data, "Hello noob.", body_params.body_data.length));

    aws_http_decoder_destroy(decoder);
    aws_array_list_clean_up(&body_params.body_data);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_body_chunked, s_http_test_body_chunked);
static int s_http_test_body_chunked(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *msg = "GET / HTTP/1.1\r\n"
                      "Host: amazon.com\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "\r\n"
                      "D\r\n"
                      "Hello, there \r\n"
                      "1c\r\n"
                      "should be a carriage return \r\n"
                      "9\r\n"
                      "in\r\nhere.\r\n"
                      "0\r\n"
                      "\r\n";

    struct aws_http_decoder_params params;
    struct s_body_params body_params;
    s_common_decoder_setup(allocator, 1024, &params, s_request, &body_params);

    aws_array_list_init_dynamic(&body_params.body_data, allocator, 256, sizeof(uint8_t));

    params.vtable.on_body = s_on_body;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(msg);
    ASSERT_SUCCESS(aws_http_decode(decoder, msg, len, NULL));
    ASSERT_SUCCESS(memcmp(
        body_params.body_data.data,
        "Hello, there should be a carriage return in\r\nhere.",
        body_params.body_data.length));

    aws_http_decoder_destroy(decoder);
    aws_array_list_clean_up(&body_params.body_data);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_decode_trailers, s_http_decode_trailers);
static int s_http_decode_trailers(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *request = "GET / HTTP/1.1\r\n"
                          "Host: amazon.com\r\n"
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

    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_request, NULL);
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(request);
    ASSERT_SUCCESS(aws_http_decode(decoder, request, len, NULL));

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_decode_one_byte_at_a_time, s_http_decode_one_byte_at_a_time);
static int s_http_decode_one_byte_at_a_time(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *request = s_typical_request;

    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_request, NULL);
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(request);
    for (int i = 0; i < (int)len; ++i) {
        ASSERT_SUCCESS(aws_http_decode(decoder, request + i, 1, NULL));
    }

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

static int s_rand(int lo, int hi) {
    return rand() % (hi + 1 - lo) + lo;
}

AWS_TEST_CASE(http_decode_messages_at_random_intervals, s_http_decode_messages_at_random_intervals);
static int s_http_decode_messages_at_random_intervals(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *requests[] = {
        "GET / HTTP/1.1\r\n"
        "Host: amazon.com\r\n"
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

        struct aws_http_decoder_params params;
        s_common_decoder_setup(allocator, 1024, &params, s_request, NULL);
        struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

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

        aws_http_decoder_destroy(decoder);
    }

    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_decode_bad_requests_and_assert_failure, s_http_decode_bad_requests_and_assert_failure);
static int s_http_decode_bad_requests_and_assert_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
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

        /* Chunked should be final encoding */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked, gzip\r\n"
        "\r\n",

        /* Chunked should be final encoding, p2 */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: gzip\r\n"
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
        "\r\n",

        /* Chunk size should not have spaces. */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        " 7 \r\n",

        /* Chunk size should not start with "0x". */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0x7\r\n",

        /* Invalid chunk size terminator. */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "7\r0asa90\r\n"
        "0\r\n"
        "\r\n",

        /* Invalid transfer coding. */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: shrinkydinky, chunked\r\n",

        /* My chunk size is too big */
        "GET / HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "FFFFFFFFFFFFFFFFF\r\n",

        /* My content-Length is too big */
        "POST / HTTP/1.1\r\n"
        "Content-Length: 99999999999999999999\r\n",

        /* My content-Length is empty */
        "POST / HTTP/1.1\r\n"
        "Content-Length:\r\n",

        /* Has both content-Length and transfer-encoding */
        "POST / HTTP/1.1\r\n"
        "Content-Length: 999\r\n"
        "Transfer-Encoding: chunked\r\n",

        /* Header is missing colon */
        "GET / HTTP/1.1\r\n"
        "Header-Missing-Colon yes it is\r\n"
        "\r\n",

        /* Header with empty name */
        "GET / HTTP/1.1\r\n"
        ": header with empty name\r\n"
        "\r\n",

        /* Method is blank */
        " / HTTP/1.1\r\n",

        /* URI is blank */
        "GET  HTTP/1.1\r\n",

        /* HTTP version is blank */
        "GET / \r\n",

        /* Missing spaces */
        "GET /HTTP/1.1\r\n",

        /* Missing spaces */
        "GET/HTTP/1.1\r\n",

        /* Extra space at end */
        "GET / HTTP/1.1 \r\n",

        /* Go ahead and add more cases here. */
    };

    for (int iter = 0; iter < AWS_ARRAY_SIZE(requests); ++iter) {
        const char *request = requests[iter];

        struct aws_http_decoder_params params;
        s_common_decoder_setup(allocator, 1024, &params, s_request, NULL);
        struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

        size_t len = strlen(request);
        ASSERT_FAILS(aws_http_decode(decoder, request, len, NULL));

        aws_http_decoder_destroy(decoder);
    }

    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_decode_bad_responses_and_assert_failure, s_http_decode_bad_responses_and_assert_failure);
static int s_http_decode_bad_responses_and_assert_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *responses[] = {
        /* Response code not 3 digits */
        "HTTP/1.1 1000 PHRASE\r\n",

        /* Response code not 3 digits */
        "HTTP/1.1 99 PHRASE\r\n",

        /* Response code should not be in hex */
        "HTTP/1.1 0x1 PHRASE\r\n",

        /* Response code should not be in hex */
        "HTTP/1.1 FFF PHRASE\r\n",

        /* Go ahead and add more cases here. */
    };

    for (int iter = 0; iter < AWS_ARRAY_SIZE(responses); ++iter) {
        const char *response = responses[iter];

        struct aws_http_decoder_params params;
        s_common_decoder_setup(allocator, 1024, &params, s_response, NULL);
        struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

        size_t len = strlen(response);
        ASSERT_FAILS(aws_http_decode(decoder, response, len, NULL));

        aws_http_decoder_destroy(decoder);
    }

    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    http_test_extraneous_buffer_data_ensure_not_processed,
    s_http_test_extraneous_buffer_data_ensure_not_processed);
static int s_http_test_extraneous_buffer_data_ensure_not_processed(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *request = "GET / HTTP/1.1\r\n"
                          "Wow look here. That's a lot of extra random stuff!";

    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_request, NULL);
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen("GET / HTTP/1.1\r\n");
    size_t size_read;
    ASSERT_SUCCESS(aws_http_decode(decoder, request, len, &size_read));
    ASSERT_INT_EQUALS(len, size_read);

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_ignore_chunk_extensions, s_http_test_ignore_chunk_extensions);
static int s_http_test_ignore_chunk_extensions(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_test_init(allocator);
    const char *request = "GET / HTTP/1.1\r\n"
                          "Host: amazon.com\r\n"
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

    struct aws_http_decoder_params params;
    s_common_decoder_setup(allocator, 1024, &params, s_request, NULL);
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);

    size_t len = strlen(request);
    ASSERT_SUCCESS(aws_http_decode(decoder, request, len, NULL));

    aws_http_decoder_destroy(decoder);
    s_test_clean_up();
    return AWS_OP_SUCCESS;
}
