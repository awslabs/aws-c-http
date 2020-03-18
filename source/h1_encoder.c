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
#include <aws/http/private/strutil.h>
#include <aws/http/status_code.h>
#include <aws/io/logging.h>
#include <aws/io/stream.h>

#include <inttypes.h>

#define ENCODER_LOGF(level, encoder, text, ...)                                                                        \
    AWS_LOGF_##level(AWS_LS_HTTP_STREAM, "id=%p: " text, encoder->logging_id, __VA_ARGS__)
#define ENCODER_LOG(level, encoder, text) ENCODER_LOGF(level, encoder, "%s", text)

/**
 * Scan headers to detect errors and determine anything we'll need to know later (ex: total length).
 */
static int s_scan_outgoing_headers(
    struct aws_h1_encoder_message *encoder_message,
    const struct aws_http_message *message,
    size_t *out_header_lines_len,
    bool body_headers_ignored,
    bool body_headers_forbidden) {

    size_t total = 0;
    bool has_body_stream = aws_http_message_get_body_stream(message);
    bool has_body_headers = false;

    const size_t num_headers = aws_http_message_get_header_count(message);
    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header;
        aws_http_message_get_header(message, &header, i);

        enum aws_http_header_name name_enum = aws_http_str_to_header_name(header.name);
        switch (name_enum) {
            case AWS_HTTP_HEADER_CONNECTION: {
                struct aws_byte_cursor trimmed_value = aws_strutil_trim_http_whitespace(header.value);
                if (aws_byte_cursor_eq_c_str(&trimmed_value, "close")) {
                    encoder_message->has_connection_close_header = true;
                }
            } break;
            case AWS_HTTP_HEADER_CONTENT_LENGTH: {
                struct aws_byte_cursor trimmed_value = aws_strutil_trim_http_whitespace(header.value);
                if (aws_strutil_read_unsigned_num(trimmed_value, &encoder_message->content_length)) {
                    AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=static: Invalid Content-Length");
                    return aws_raise_error(AWS_ERROR_HTTP_INVALID_HEADER_VALUE);
                }
                if (encoder_message->content_length > 0) {
                    has_body_headers = true;
                }
            } break;
            case AWS_HTTP_HEADER_TRANSFER_ENCODING:
                AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=static: Sending of chunked messages not yet implemented");
                return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
            default:
                break;
        }

        /* header-line: "{name}: {value}\r\n" */
        int err = 0;
        err |= aws_add_size_checked(header.name.len, total, &total);
        err |= aws_add_size_checked(header.value.len, total, &total);
        err |= aws_add_size_checked(4, total, &total); /* ": " + "\r\n" */
        if (err) {
            return AWS_OP_ERR;
        }
    }
    if (body_headers_forbidden && has_body_headers) {
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_HEADER_FIELD);
    }

    if (body_headers_ignored) {
        /* Don't send body, no matter what the headers are */
        has_body_headers = false;
        encoder_message->content_length = 0;
    }

    if (has_body_headers && !has_body_stream) {
        return aws_raise_error(AWS_ERROR_HTTP_MISSING_BODY_STREAM);
    }

    *out_header_lines_len = total;
    return AWS_OP_SUCCESS;
}

static void s_write_headers(struct aws_byte_buf *dst, const struct aws_http_message *message) {

    const size_t num_headers = aws_http_message_get_header_count(message);

    bool wrote_all = true;
    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header;
        aws_http_message_get_header(message, &header, i);

        /* header-line: "{name}: {value}\r\n" */
        wrote_all &= aws_byte_buf_write_from_whole_cursor(dst, header.name);
        wrote_all &= aws_byte_buf_write_u8(dst, ':');
        wrote_all &= aws_byte_buf_write_u8(dst, ' ');
        wrote_all &= aws_byte_buf_write_from_whole_cursor(dst, header.value);
        wrote_all &= aws_byte_buf_write_u8(dst, '\r');
        wrote_all &= aws_byte_buf_write_u8(dst, '\n');
    }
    AWS_ASSERT(wrote_all);
}

int aws_h1_encoder_message_init_from_request(
    struct aws_h1_encoder_message *message,
    struct aws_allocator *allocator,
    const struct aws_http_message *request) {

    AWS_ZERO_STRUCT(*message);

    message->body = aws_http_message_get_body_stream(request);

    struct aws_byte_cursor method;
    int err = aws_http_message_get_request_method(request, &method);
    if (err) {
        aws_raise_error(AWS_ERROR_HTTP_INVALID_METHOD);
        goto error;
    }

    struct aws_byte_cursor uri;
    err = aws_http_message_get_request_path(request, &uri);
    if (err) {
        aws_raise_error(AWS_ERROR_HTTP_INVALID_PATH);
        goto error;
    }

    struct aws_byte_cursor version = aws_http_version_to_str(AWS_HTTP_VERSION_1_1);

    /**
     * Calculate total size needed for outgoing_head_buffer, then write to buffer.
     */

    size_t header_lines_len;
    err = s_scan_outgoing_headers(
        message, request, &header_lines_len, false /*body_headers_ignored*/, false /*body_headers_forbidden*/);
    if (err) {
        goto error;
    }

    /* request-line: "{method} {uri} {version}\r\n" */
    size_t request_line_len = 4; /* 2 spaces + "\r\n" */
    err |= aws_add_size_checked(method.len, request_line_len, &request_line_len);
    err |= aws_add_size_checked(uri.len, request_line_len, &request_line_len);
    err |= aws_add_size_checked(version.len, request_line_len, &request_line_len);

    /* head-end: "\r\n" */
    size_t head_end_len = 2;

    size_t head_total_len = request_line_len;
    err |= aws_add_size_checked(header_lines_len, head_total_len, &head_total_len);
    err |= aws_add_size_checked(head_end_len, head_total_len, &head_total_len);
    if (err) {
        goto error;
    }

    err = aws_byte_buf_init(&message->outgoing_head_buf, allocator, head_total_len);
    if (err) {
        goto error;
    }

    bool wrote_all = true;

    wrote_all &= aws_byte_buf_write_from_whole_cursor(&message->outgoing_head_buf, method);
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&message->outgoing_head_buf, uri);
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&message->outgoing_head_buf, version);
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, '\n');

    s_write_headers(&message->outgoing_head_buf, request);

    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, '\n');
    (void)wrote_all;
    AWS_ASSERT(wrote_all);

    return AWS_OP_SUCCESS;
error:
    aws_h1_encoder_message_clean_up(message);
    return AWS_OP_ERR;
}

int aws_h1_encoder_message_init_from_response(
    struct aws_h1_encoder_message *message,
    struct aws_allocator *allocator,
    const struct aws_http_message *response,
    bool body_headers_ignored) {

    AWS_ZERO_STRUCT(*message);

    message->body = aws_http_message_get_body_stream(response);

    struct aws_byte_cursor version = aws_http_version_to_str(AWS_HTTP_VERSION_1_1);

    int status_int;
    int err = aws_http_message_get_response_status(response, &status_int);
    if (err) {
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_STATUS_CODE);
    }

    /* Status code must fit in 3 digits */
    AWS_ASSERT(status_int >= 0 && status_int <= 999); /* aws_http_message should have already checked this */
    char status_code_str[4] = "XXX";
    snprintf(status_code_str, sizeof(status_code_str), "%03d", status_int);
    struct aws_byte_cursor status_code = aws_byte_cursor_from_c_str(status_code_str);

    struct aws_byte_cursor status_text = aws_byte_cursor_from_c_str(aws_http_status_text(status_int));

    /**
     * Calculate total size needed for outgoing_head_buffer, then write to buffer.
     */

    size_t header_lines_len;
    /**
     * no body needed in the response
     * RFC-7230 section 3.3 Message Body
     */
    body_headers_ignored |= status_int == AWS_HTTP_STATUS_CODE_304_NOT_MODIFIED;
    bool body_headers_forbidden = status_int == AWS_HTTP_STATUS_CODE_204_NO_CONTENT || status_int / 100 == 1;
    err = s_scan_outgoing_headers(message, response, &header_lines_len, body_headers_ignored, body_headers_forbidden);
    if (err) {
        goto error;
    }

    /* valid status must be three digital code, change it into byte_cursor */
    /* response-line: "{version} {status} {status_text}\r\n" */
    size_t response_line_len = 4; /* 2 spaces + "\r\n" */
    err |= aws_add_size_checked(version.len, response_line_len, &response_line_len);
    err |= aws_add_size_checked(status_code.len, response_line_len, &response_line_len);
    err |= aws_add_size_checked(status_text.len, response_line_len, &response_line_len);

    /* head-end: "\r\n" */
    size_t head_end_len = 2;
    size_t head_total_len = response_line_len;
    err |= aws_add_size_checked(header_lines_len, head_total_len, &head_total_len);
    err |= aws_add_size_checked(head_end_len, head_total_len, &head_total_len);
    if (err) {
        goto error;
    }

    err = aws_byte_buf_init(&message->outgoing_head_buf, allocator, head_total_len);
    if (err) {
        return AWS_OP_ERR;
    }

    bool wrote_all = true;

    wrote_all &= aws_byte_buf_write_from_whole_cursor(&message->outgoing_head_buf, version);
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&message->outgoing_head_buf, status_code);
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&message->outgoing_head_buf, status_text);
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, '\n');

    s_write_headers(&message->outgoing_head_buf, response);

    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&message->outgoing_head_buf, '\n');
    (void)wrote_all;
    AWS_ASSERT(wrote_all);

    /* Success! */
    return AWS_OP_SUCCESS;

error:
    aws_h1_encoder_message_clean_up(message);
    return AWS_OP_ERR;
}

void aws_h1_encoder_message_clean_up(struct aws_h1_encoder_message *message) {
    aws_byte_buf_clean_up(&message->outgoing_head_buf);
    AWS_ZERO_STRUCT(*message);
}

void aws_h1_encoder_init(struct aws_h1_encoder *encoder, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*encoder);
    encoder->allocator = allocator;
}

void aws_h1_encoder_clean_up(struct aws_h1_encoder *encoder) {
    AWS_ZERO_STRUCT(*encoder);
}

int aws_h1_encoder_start_message(
    struct aws_h1_encoder *encoder,
    struct aws_h1_encoder_message *message,
    void *log_as_stream) {

    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(message);

    if (encoder->message) {
        ENCODER_LOG(ERROR, encoder, "Attempting to start new request while previous request is in progress.");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    /* Can start writing head next */
    encoder->logging_id = log_as_stream;
    encoder->message = message;
    encoder->state = AWS_H1_ENCODER_STATE_HEAD;
    encoder->progress_bytes = 0;

    return AWS_OP_SUCCESS;
}

int aws_h1_encoder_process(struct aws_h1_encoder *encoder, struct aws_byte_buf *out_buf) {
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(out_buf);

    if (!encoder->message) {
        ENCODER_LOG(ERROR, encoder, "No message is currently set for encoding.");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    struct aws_byte_buf *dst = out_buf;

    if (encoder->state == AWS_H1_ENCODER_STATE_HEAD) {
        size_t dst_available = dst->capacity - dst->len;
        if (dst_available == 0) {
            /* Can't write anymore */
            ENCODER_LOG(TRACE, encoder, "Cannot fit any more head data in this message.");
            return AWS_OP_SUCCESS;
        }

        /* Copy data from outgoing_head_buf */
        struct aws_byte_buf *src = &encoder->message->outgoing_head_buf;
        size_t src_progress = (size_t)encoder->progress_bytes;
        size_t src_remaining = src->len - src_progress;
        size_t transferring = src_remaining < dst_available ? src_remaining : dst_available;

        bool success = aws_byte_buf_write(dst, src->buffer + src_progress, transferring);
        (void)success;
        AWS_ASSERT(success);

        encoder->progress_bytes += transferring;

        ENCODER_LOGF(
            TRACE,
            encoder,
            "Writing to message, outgoing head progress %" PRIu64 "/%zu.",
            encoder->progress_bytes,
            encoder->message->outgoing_head_buf.len);

        if (encoder->progress_bytes == src->len) {
            /* Don't NEED to free this buffer now, but we don't need it anymore, so why not */
            aws_byte_buf_clean_up(&encoder->message->outgoing_head_buf);

            encoder->progress_bytes = 0;
            encoder->state++;
        }
    }

    if (encoder->state == AWS_H1_ENCODER_STATE_BODY) {
        if (!encoder->message->body || !encoder->message->content_length) {
            ENCODER_LOG(TRACE, encoder, "Skipping body")
            encoder->state++;
        } else {
            while (true) {
                if (dst->capacity == dst->len) {
                    /* Can't write anymore */
                    ENCODER_LOG(TRACE, encoder, "Cannot fit any more body data in this message");

                    /* Return success because we want to try again later */
                    return AWS_OP_SUCCESS;
                }

                const size_t prev_len = dst->len;
                int err = aws_input_stream_read(encoder->message->body, dst);
                const size_t amount_read = dst->len - prev_len;

                if (err) {
                    ENCODER_LOGF(
                        ERROR,
                        encoder,
                        "Failed to read body stream, error %d (%s)",
                        aws_last_error(),
                        aws_error_name(aws_last_error()));

                    return AWS_OP_ERR;
                }

                if ((amount_read > encoder->message->content_length) ||
                    (encoder->progress_bytes > encoder->message->content_length - amount_read)) {
                    ENCODER_LOGF(
                        ERROR,
                        encoder,
                        "Body stream has exceeded Content-Length: %" PRIu64,
                        encoder->message->content_length);
                    return aws_raise_error(AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT);
                }

                encoder->progress_bytes += amount_read;

                ENCODER_LOGF(TRACE, encoder, "Writing %zu body bytes to message", amount_read);

                if (encoder->progress_bytes == encoder->message->content_length) {
                    ENCODER_LOG(TRACE, encoder, "Done sending body.");
                    encoder->progress_bytes = 0;
                    encoder->state++;
                    break;
                }

                /* Return if user failed to write anything. Maybe their data isn't ready yet. */
                if (amount_read == 0) {
                    /* Ensure we're not at end-of-stream too early */
                    struct aws_stream_status status;
                    err = aws_input_stream_get_status(encoder->message->body, &status);
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
                        ENCODER_LOGF(
                            ERROR,
                            encoder,
                            "Reached end of body stream before Content-Length: %" PRIu64 " sent",
                            encoder->message->content_length);
                        return aws_raise_error(AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT);
                    }

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

        encoder->message = NULL;
    }

    return AWS_OP_SUCCESS;
}

bool aws_h1_encoder_is_message_in_progress(const struct aws_h1_encoder *encoder) {
    return encoder->message;
}
