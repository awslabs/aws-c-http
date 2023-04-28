/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "stream_test_helper.h"

#include <aws/http/connection.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/testing/aws_test_harness.h>

#define UNKNOWN_HEADER_BLOCK ((enum aws_http_header_block) - 1)

static int s_on_headers(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)stream;
    struct client_stream_tester *tester = user_data;
    ASSERT_FALSE(tester->complete);

    if (tester->current_header_block == UNKNOWN_HEADER_BLOCK) {
        tester->current_header_block = header_block;
    } else {
        ASSERT_INT_EQUALS(tester->current_header_block, header_block);
    }

    /* Response consists of:
     * - 0+ informational (1xx) header-blocks
     * - 1 block of main headers arrives
     * - Optional trailing header-block may come after body */
    switch (header_block) {
        case AWS_HTTP_HEADER_BLOCK_INFORMATIONAL:
            ASSERT_SUCCESS(aws_http_headers_add_array(tester->current_info_headers, header_array, num_headers));
            break;

        case AWS_HTTP_HEADER_BLOCK_MAIN:
            ASSERT_SUCCESS(aws_http_headers_add_array(tester->response_headers, header_array, num_headers));
            break;

        case AWS_HTTP_HEADER_BLOCK_TRAILING:
            ASSERT_SUCCESS(aws_http_headers_add_array(tester->response_trailer, header_array, num_headers));
            break;
    }

    return AWS_OP_SUCCESS;
}

static int s_on_header_block_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {

    struct client_stream_tester *tester = user_data;
    ASSERT_FALSE(tester->complete);

    if (tester->current_header_block != UNKNOWN_HEADER_BLOCK) {
        ASSERT_INT_EQUALS(tester->current_header_block, header_block);
    }
    tester->current_header_block = UNKNOWN_HEADER_BLOCK;

    /* Response consists of:
     * - 0+ informational (1xx) header-blocks
     * - 1 block of main headers arrives
     * - Optional trailing header-block may come after body */
    switch (header_block) {
        case AWS_HTTP_HEADER_BLOCK_INFORMATIONAL: {
            ASSERT_FALSE(tester->response_headers_done);
            ASSERT_FALSE(tester->response_trailer_done);
            ASSERT_UINT_EQUALS(0, tester->response_body.len);

            /* Create new entry in info_responses[], copy in headers and status_code */
            struct aws_http_message *info_response = aws_http_message_new_response(tester->alloc);
            ASSERT_NOT_NULL(info_response);
            tester->info_responses[tester->num_info_responses++] = info_response;

            int status_code;
            ASSERT_SUCCESS(aws_http_stream_get_incoming_response_status(stream, &status_code));
            ASSERT_SUCCESS(aws_http_message_set_response_status(info_response, status_code));

            for (size_t i = 0; i < aws_http_headers_count(tester->current_info_headers); ++i) {
                struct aws_http_header header;
                ASSERT_SUCCESS(aws_http_headers_get_index(tester->current_info_headers, i, &header));
                ASSERT_SUCCESS(aws_http_message_add_header(info_response, header));
            }

            aws_http_headers_clear(tester->current_info_headers);
            break;
        }

        case AWS_HTTP_HEADER_BLOCK_MAIN:
            ASSERT_FALSE(tester->response_headers_done);
            ASSERT_FALSE(tester->response_trailer_done);
            ASSERT_UINT_EQUALS(0, tester->response_body.len);

            tester->response_headers_done = true;
            break;

        case AWS_HTTP_HEADER_BLOCK_TRAILING:
            ASSERT_FALSE(tester->response_trailer_done);
            ASSERT_TRUE(tester->response_headers_done || aws_http_headers_count(tester->response_headers) == 0);
            tester->response_trailer_done = true;
            break;
    }

    return AWS_OP_SUCCESS;
}

static int s_on_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;
    struct client_stream_tester *tester = user_data;
    ASSERT_FALSE(tester->complete);
    ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&tester->response_body, data));
    return AWS_OP_SUCCESS;
}
static void s_on_metrics(
    struct aws_http_stream *stream,
    const struct aws_http_stream_metrics *metrics,
    void *user_data) {
    (void)stream;
    struct client_stream_tester *tester = user_data;
    tester->metrics = *metrics;

    AWS_FATAL_ASSERT(metrics->stream_id == stream->id);
    if (metrics->receive_end_timestamp_ns > 0) {
        AWS_FATAL_ASSERT(
            metrics->receiving_duration_ns == metrics->receive_end_timestamp_ns - metrics->receive_start_timestamp_ns);
    }
    if (metrics->send_end_timestamp_ns > 0) {
        AWS_FATAL_ASSERT(
            metrics->sending_duration_ns == metrics->send_end_timestamp_ns - metrics->send_start_timestamp_ns);
    }
    if (metrics->receiving_duration_ns != -1) {
        AWS_FATAL_ASSERT(metrics->receive_end_timestamp_ns > 0);
    }
    if (metrics->sending_duration_ns != -1) {
        AWS_FATAL_ASSERT(metrics->send_end_timestamp_ns > 0);
    }
}

static void s_on_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct client_stream_tester *tester = user_data;

    /* Validate things are firing properly */
    AWS_FATAL_ASSERT(!tester->complete);
    if (error_code == AWS_ERROR_SUCCESS) {
        AWS_FATAL_ASSERT(tester->current_header_block == UNKNOWN_HEADER_BLOCK);
        AWS_FATAL_ASSERT(aws_http_headers_count(tester->current_info_headers) == 0); /* is cleared when block done */
        AWS_FATAL_ASSERT(tester->response_headers_done || aws_http_headers_count(tester->response_headers) == 0);
        AWS_FATAL_ASSERT(tester->response_trailer_done || aws_http_headers_count(tester->response_trailer) == 0);
    }

    tester->complete = true;
    tester->on_complete_error_code = error_code;
    tester->on_complete_connection_is_open = aws_http_connection_is_open(aws_http_stream_get_connection(stream));
    aws_http_stream_get_incoming_response_status(stream, &tester->response_status);
}

static void s_on_destroy(void *user_data) {
    struct client_stream_tester *tester = user_data;

    /* Validate things are firing properly */
    AWS_FATAL_ASSERT(!tester->destroyed);
    tester->destroyed = true;
}

int client_stream_tester_init(
    struct client_stream_tester *tester,
    struct aws_allocator *alloc,
    const struct client_stream_tester_options *options) {

    AWS_ZERO_STRUCT(*tester);
    tester->alloc = alloc;

    tester->response_status = AWS_HTTP_STATUS_CODE_UNKNOWN;

    tester->current_header_block = UNKNOWN_HEADER_BLOCK;

    tester->current_info_headers = aws_http_headers_new(alloc);
    ASSERT_NOT_NULL(tester->current_info_headers);

    tester->response_headers = aws_http_headers_new(alloc);
    ASSERT_NOT_NULL(tester->response_headers);

    tester->response_trailer = aws_http_headers_new(alloc);
    ASSERT_NOT_NULL(tester->response_trailer);

    ASSERT_SUCCESS(aws_byte_buf_init(&tester->response_body, alloc, 128));

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = options->request,
        .user_data = tester,
        .on_response_headers = s_on_headers,
        .on_response_header_block_done = s_on_header_block_done,
        .on_response_body = s_on_body,
        .on_metrics = s_on_metrics,
        .on_complete = s_on_complete,
        .on_destroy = s_on_destroy,
    };
    tester->stream = aws_http_connection_make_request(options->connection, &request_options);
    ASSERT_NOT_NULL(tester->stream);

    ASSERT_SUCCESS(aws_http_stream_activate(tester->stream));
    return AWS_OP_SUCCESS;
}

void client_stream_tester_clean_up(struct client_stream_tester *tester) {
    for (size_t i = 0; i < tester->num_info_responses; ++i) {
        aws_http_message_release(tester->info_responses[i]);
    }

    aws_http_headers_release(tester->current_info_headers);
    aws_http_headers_release(tester->response_headers);
    aws_http_headers_release(tester->response_trailer);
    aws_byte_buf_clean_up(&tester->response_body);
    aws_http_stream_release(tester->stream);
    AWS_ZERO_STRUCT(*tester);
}
