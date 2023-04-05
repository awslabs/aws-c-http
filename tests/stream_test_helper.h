#ifndef AWS_HTTP_STREAM_TEST_HELPER_H
#define AWS_HTTP_STREAM_TEST_HELPER_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/request_response.h>

struct aws_http_connection;
struct aws_http_headers;
struct aws_http_message;
struct aws_http_stream;

struct client_stream_tester {
    struct aws_allocator *alloc;
    struct aws_http_stream *stream;

    int response_status;

    enum aws_http_header_block current_header_block;

    /* Array of completed Informational (1xx) responses */
    struct aws_http_message *info_responses[4];
    size_t num_info_responses;

    /* As Informational (1xx) headers arrive, they're buffered here.
     * They copied into a new `info_responses` entry when the block is done */
    struct aws_http_headers *current_info_headers;

    /* Main header-block */
    struct aws_http_headers *response_headers;
    bool response_headers_done;

    /* Trailing header-block */
    struct aws_http_headers *response_trailer;
    bool response_trailer_done;

    struct aws_byte_buf response_body;

    bool complete;
    int on_complete_error_code;

    /* Whether connection is open when on_complete fires */
    bool on_complete_connection_is_open;
    struct aws_http_stream_metrics metrics;

    bool destroyed;
};

struct client_stream_tester_options {
    struct aws_http_message *request;
    struct aws_http_connection *connection;
};

int client_stream_tester_init(
    struct client_stream_tester *tester,
    struct aws_allocator *alloc,
    const struct client_stream_tester_options *options);

void client_stream_tester_clean_up(struct client_stream_tester *tester);

#endif /* AWS_HTTP_STREAM_TEST_HELPER_H */
