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
#include <aws/http/private/h1_encoder.h>

#include <aws/io/logging.h>
#include <aws/io/stream.h>

#define ENCODER_LOGF(level, encoder, text, ...)                                                                        \
    AWS_LOGF_##level(AWS_LS_HTTP_STREAM, "id=%p: " text, encoder->logging_id, __VA_ARGS__)
#define ENCODER_LOG(level, encoder, text) ENCODER_LOGF(level, encoder, "%s", text)

void aws_h1_encoder_init(struct aws_h1_encoder *encoder, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*encoder);
    encoder->allocator = allocator;
}

void aws_h1_encoder_clean_up(struct aws_h1_encoder *encoder) {
    aws_byte_buf_clean_up(&encoder->outgoing_head_buf);
}

int aws_h1_encoder_start_request(
    struct aws_h1_encoder *encoder,
    const struct aws_http_request *request,
    void *log_as_stream) {

    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(request);

    if (encoder->is_stream_in_progress) {
        ENCODER_LOG(ERROR, encoder, "Attempting to start new request while previous request is in progress.");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    void *prev_logging_id = encoder->logging_id;
    encoder->logging_id = log_as_stream;

    struct aws_byte_cursor method;
    if (aws_http_request_get_method(request, &method)) {
        AWS_ASSERT(0);
    }

    struct aws_byte_cursor uri;
    if (aws_http_request_get_path(request, &uri)) {
        AWS_ASSERT(0);
    }

    struct aws_byte_cursor version = aws_http_version_to_str(AWS_HTTP_VERSION_1_1);
    const size_t num_headers = aws_http_request_get_header_count(request);

    /**
     * Calculate total size needed for outgoing_head_buffer, then write to buffer.
     */
    int err = 0;

    /* request-line: "{method} {uri} {version}\r\n" */
    size_t request_line_len = 4; /* 2 spaces + "\r\n" */
    err |= aws_add_size_checked(method.len, request_line_len, &request_line_len);
    err |= aws_add_size_checked(uri.len, request_line_len, &request_line_len);
    err |= aws_add_size_checked(version.len, request_line_len, &request_line_len);

    /* head-end: "\r\n" */
    size_t head_end_len = 2;

    /* header-line: "{name}: {value}\r\n" */
    size_t header_lines_len = 0;
    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header;
        aws_http_request_get_header(request, &header, i);
        AWS_ASSERT((header.name.len > 0) && (header.value.len > 0));

        err |= aws_add_size_checked(header.name.len, header_lines_len, &header_lines_len);
        err |= aws_add_size_checked(header.value.len, header_lines_len, &header_lines_len);
        err |= aws_add_size_checked(4, header_lines_len, &header_lines_len); /* ": " + "\r\n" */
    }

    size_t head_total_len = request_line_len;
    err |= aws_add_size_checked(header_lines_len, head_total_len, &head_total_len);
    err |= aws_add_size_checked(head_end_len, head_total_len, &head_total_len);

    if (err) {
        ENCODER_LOGF(
            ERROR,
            encoder,
            "Encoding failure, size calculation had error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    err = aws_byte_buf_init(&encoder->outgoing_head_buf, encoder->allocator, head_total_len);
    if (err) {
        ENCODER_LOGF(
            ERROR,
            encoder,
            "Encoding failure, buffer initialization had error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    bool wrote_all = true;

    wrote_all &= aws_byte_buf_write_from_whole_cursor(&encoder->outgoing_head_buf, method);
    wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&encoder->outgoing_head_buf, uri);
    wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&encoder->outgoing_head_buf, version);
    wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, '\n');

    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header;
        aws_http_request_get_header(request, &header, i);

        /* header-line: "{name}: {value}\r\n" */
        wrote_all &= aws_byte_buf_write_from_whole_cursor(&encoder->outgoing_head_buf, header.name);
        wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, ':');
        wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, ' ');
        wrote_all &= aws_byte_buf_write_from_whole_cursor(&encoder->outgoing_head_buf, header.value);
        wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, '\r');
        wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, '\n');
    }

    wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&encoder->outgoing_head_buf, '\n');
    (void)wrote_all;
    AWS_ASSERT(wrote_all);

    /* Can start writing head next */
    encoder->is_stream_in_progress = true;
    encoder->body = aws_http_request_get_body_stream(request);
    encoder->state = AWS_H1_ENCODER_STATE_HEAD;
    encoder->outgoing_head_progress = 0;

    return AWS_OP_SUCCESS;

error:
    encoder->logging_id = prev_logging_id;
    return AWS_OP_ERR;
}

int aws_h1_encoder_process(struct aws_h1_encoder *encoder, struct aws_byte_buf *out_buf) {
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(out_buf);

    struct aws_byte_buf *dst = out_buf;

    if (encoder->state == AWS_H1_ENCODER_STATE_HEAD) {
        size_t dst_available = dst->capacity - dst->len;
        if (dst_available == 0) {
            /* Can't write anymore */
            ENCODER_LOG(TRACE, encoder, "Cannot fit any more head data in this message.");
            return AWS_OP_SUCCESS;
        }

        /* Copy data from stream->outgoing_head_buf */
        struct aws_byte_buf *src = &encoder->outgoing_head_buf;
        size_t src_progress = encoder->outgoing_head_progress;
        size_t src_remaining = src->len - src_progress;
        size_t transferring = src_remaining < dst_available ? src_remaining : dst_available;

        bool success = aws_byte_buf_write(dst, src->buffer + src_progress, transferring);
        (void)success;
        AWS_ASSERT(success);

        encoder->outgoing_head_progress += transferring;

        ENCODER_LOGF(
            TRACE,
            encoder,
            "Writing to message, outgoing head progress %zu/%zu.",
            encoder->outgoing_head_progress,
            encoder->outgoing_head_buf.len);

        if (encoder->outgoing_head_progress == src->len) {
            /* Don't NEED to free this buffer now, but we don't need it anymore, so why not */
            aws_byte_buf_clean_up(&encoder->outgoing_head_buf);

            encoder->state++;
        }
    }

    if (encoder->state == AWS_H1_ENCODER_STATE_BODY) {
        if (!encoder->body) {
            ENCODER_LOG(TRACE, encoder, "No body to send.")
            encoder->state++;
        } else {
            while (true) {
                if (dst->capacity == dst->len) {
                    /* Can't write anymore */
                    ENCODER_LOG(TRACE, encoder, "Cannot fit any more body data in this message");

                    /* Return success because we want to try again later */
                    return AWS_OP_SUCCESS;
                }

                size_t amount_read = 0;
                int err = aws_input_stream_read(encoder->body, dst, &amount_read);
                if (err) {
                    ENCODER_LOGF(
                        ERROR,
                        encoder,
                        "Failed to read body stream, error %d (%s)",
                        aws_last_error(),
                        aws_error_name(aws_last_error()));

                    return AWS_OP_ERR;
                }

                ENCODER_LOGF(TRACE, encoder, "Writing %zu body bytes to message", amount_read);

                struct aws_stream_status status;
                err = aws_input_stream_get_status(encoder->body, &status);
                if (err) {
                    ENCODER_LOGF(
                        TRACE,
                        encoder,
                        "Failed to query body stream status, error %d (%s)",
                        aws_last_error(),
                        aws_error_name(aws_last_error()));

                    return AWS_OP_ERR;
                }
                if (status.is_end_of_stream) {
                    ENCODER_LOG(TRACE, encoder, "Done sending body.");

                    encoder->state++;
                    break;
                }

                /* Return if user failed to write anything. Maybe their data isn't ready yet. */
                if (amount_read == 0) {
                    ENCODER_LOG(
                        TRACE,
                        encoder,
                        "No body data written, concluding this message. "
                        "Will try to write body data again in the next message.");
                    return AWS_OP_SUCCESS;
                }
            }
        }
    }

    if (encoder->state == AWS_H1_ENCODER_STATE_DONE) {
        ENCODER_LOG(TRACE, encoder, "Done sending data.");

        encoder->is_stream_in_progress = false;
        aws_byte_buf_clean_up(&encoder->outgoing_head_buf);
    }

    return AWS_OP_SUCCESS;
}
