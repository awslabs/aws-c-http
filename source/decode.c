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

#include <aws/common/string.h>
#include <aws/io/logging.h>

AWS_STATIC_STRING_FROM_LITERAL(s_transfer_coding_chunked, "chunked");
AWS_STATIC_STRING_FROM_LITERAL(s_transfer_coding_compress, "compress");
AWS_STATIC_STRING_FROM_LITERAL(s_transfer_coding_x_compress, "x-compress");
AWS_STATIC_STRING_FROM_LITERAL(s_transfer_coding_deflate, "deflate");
AWS_STATIC_STRING_FROM_LITERAL(s_transfer_coding_gzip, "gzip");
AWS_STATIC_STRING_FROM_LITERAL(s_transfer_coding_x_gzip, "x-gzip");

/* Decoder runs a state machine.
 * Each state consumes data until it sets the next state.
 * A common state is the "line state", which handles consuming one line ending in CRLF
 * and feeding the line to a linestate_fn, which should process data and set the next state.
 */
typedef int(state_fn)(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed);
typedef int(linestate_fn)(struct aws_http_decoder *decoder, struct aws_byte_cursor input);

struct aws_http_decoder {
    /* Implementation data. */
    struct aws_allocator *alloc;
    struct aws_byte_buf scratch_space;
    state_fn *run_state;
    linestate_fn *process_line;
    int transfer_encoding;
    size_t content_processed;
    size_t content_length;
    size_t chunk_processed;
    size_t chunk_size;
    bool doing_trailers;
    bool is_done;
    void *logging_id;

    /* User callbacks and settings. */
    struct aws_http_decoder_vtable vtable;
    bool is_decoding_requests;
    void *user_data;
};

static int s_linestate_request(struct aws_http_decoder *decoder, struct aws_byte_cursor input);
static int s_linestate_response(struct aws_http_decoder *decoder, struct aws_byte_cursor input);
static int s_linestate_header(struct aws_http_decoder *decoder, struct aws_byte_cursor input);
static int s_linestate_chunk_size(struct aws_http_decoder *decoder, struct aws_byte_cursor input);

static struct aws_byte_cursor s_trim_trailing_whitespace(struct aws_byte_cursor cursor) {
    while (cursor.len && cursor.ptr[cursor.len - 1] == (uint8_t)' ') {
        cursor.len--;
    }
    return cursor;
}

static struct aws_byte_cursor s_trim_leading_whitespace(struct aws_byte_cursor cursor) {
    while (cursor.len && *cursor.ptr == (uint8_t)' ') {
        cursor.ptr++;
        cursor.len--;
    }
    return cursor;
}

static struct aws_byte_cursor s_trim_whitespace(struct aws_byte_cursor cursor) {
    cursor = s_trim_leading_whitespace(cursor);
    cursor = s_trim_trailing_whitespace(cursor);
    return cursor;
}

static bool s_scan_for_crlf(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    AWS_ASSERT(input.len > 0);

    /* In a loop, scan for "\n", then look one char back for "\r" */
    uint8_t *ptr = input.ptr;
    uint8_t *end = input.ptr + input.len;
    while (ptr != end) {
        uint8_t *newline = (uint8_t *)memchr(ptr, '\n', end - ptr);
        if (!newline) {
            break;
        }

        uint8_t prev_char;
        if (newline == input.ptr) {
            /* If "\n" is first character check scratch_space for previous character */
            if (decoder->scratch_space.len > 0) {
                prev_char = decoder->scratch_space.buffer[decoder->scratch_space.len - 1];
            } else {
                prev_char = 0;
            }
        } else {
            prev_char = *(newline - 1);
        }

        if (prev_char == '\r') {
            *bytes_processed = 1 + (newline - input.ptr);
            return true;
        }

        ptr = newline + 1;
    }

    *bytes_processed = input.len;
    return false;
}

static int s_cat(struct aws_http_decoder *decoder, uint8_t *data, size_t len) {
    struct aws_byte_buf *buffer = &decoder->scratch_space;
    struct aws_byte_cursor to_append = aws_byte_cursor_from_array(data, len);
    int op = AWS_OP_ERR;
    if (buffer->buffer != NULL) {
        if ((aws_byte_buf_append(buffer, &to_append) == AWS_OP_SUCCESS)) {
            op = AWS_OP_SUCCESS;
        }
    }

    if (op != AWS_OP_SUCCESS) {
        size_t new_size = buffer->capacity ? buffer->capacity : 128;
        do {
            new_size <<= 1;      /* new_size *= 2 */
            if (new_size == 0) { /* check for overflow */
                return aws_raise_error(AWS_ERROR_OOM);
            }
        } while (new_size < (buffer->len + len));

        uint8_t *new_data = aws_mem_acquire(buffer->allocator, new_size);
        if (!new_data) {
            return AWS_OP_ERR;
        }

        if (buffer->buffer != NULL) {
            memcpy(new_data, buffer->buffer, buffer->len);
        }

        aws_mem_release(buffer->allocator, buffer->buffer);
        buffer->capacity = new_size;
        buffer->buffer = new_data;

        return aws_byte_buf_append(buffer, &to_append);
    }

    return op;
}

/* strtoull() is too permissive, allows things like whitespace and inputs that start with "0x" */
static int s_read_size_impl(struct aws_byte_cursor cursor, size_t *size, bool hex) {
    size_t val = 0;
    size_t base = hex ? 16 : 10;

    if (cursor.len == 0) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    for (; cursor.len > 0; aws_byte_cursor_advance(&cursor, 1)) {
        uint8_t c = cursor.ptr[0];

        if (aws_mul_size_checked(val, base, &val)) {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }

        if (c >= '0' && c <= '9') {
            if (aws_add_size_checked(val, c - '0', &val)) {
                return aws_raise_error(AWS_ERROR_HTTP_PARSE);
            }
        } else if (hex && (c >= 'a' && c <= 'f')) {
            if (aws_add_size_checked(val, c - 'a' + 10, &val)) {
                return aws_raise_error(AWS_ERROR_HTTP_PARSE);
            }
        } else if (hex && (c >= 'A' && c <= 'F')) {
            if (aws_add_size_checked(val, c - 'A' + 10, &val)) {
                return aws_raise_error(AWS_ERROR_HTTP_PARSE);
            }
        } else {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }
    }

    *size = val;
    return AWS_OP_SUCCESS;
}

static int s_read_size(struct aws_byte_cursor cursor, size_t *size) {
    return s_read_size_impl(cursor, size, false);
}

static int s_read_size_hex(struct aws_byte_cursor cursor, size_t *size) {
    return s_read_size_impl(cursor, size, true);
}

/* This state consumes an entire line, then calls a linestate_fn to process the line. */
static int s_state_getline(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    /* If preceding runs of this state failed to find CRLF, their data is stored in the scratch_space
     * and new data needs to be combined with the old data for processing. */
    bool has_prev_data = decoder->scratch_space.len;

    bool found_crlf = s_scan_for_crlf(decoder, input, bytes_processed);

    bool use_scratch = !found_crlf | has_prev_data;
    if (AWS_UNLIKELY(use_scratch)) {
        int err = s_cat(decoder, input.ptr, *bytes_processed);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_STREAM,
                "id=%p: Internal buffer write failed with error code %d (%s)",
                decoder->logging_id,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            return AWS_OP_ERR;
        }
    }

    if (AWS_LIKELY(found_crlf)) {
        /* Found end of line! Run the line processor on it */
        struct aws_byte_cursor line;
        if (use_scratch) {
            line = aws_byte_cursor_from_buf(&decoder->scratch_space);
        } else {
            line = aws_byte_cursor_from_array(input.ptr, *bytes_processed);
        }

        /* Backup so "\r\n" is not included. */
        /* RFC-7230 section 3 Message Format */
        AWS_ASSERT(line.len >= 2);
        line.len -= 2;

        return decoder->process_line(decoder, line);
    }

    /* Didn't find crlf, we'll continue scanning when more data comes in */
    return AWS_OP_SUCCESS;
}

static int s_cursor_split_impl(
    struct aws_byte_cursor input,
    char split_on,
    struct aws_byte_cursor *cursor_array,
    size_t num_cursors,
    bool error_if_more_splits_possible) {

    struct aws_byte_cursor split;
    AWS_ZERO_STRUCT(split);
    for (size_t i = 0; i < num_cursors; ++i) {
        if (!aws_byte_cursor_next_split(&input, split_on, &split)) {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }
        cursor_array[i] = split;
    }

    if (error_if_more_splits_possible) {
        if (aws_byte_cursor_next_split(&input, split_on, &split)) {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }
    } else {
        /* Otherwise, the last cursor will contain the remainder of the string */
        struct aws_byte_cursor *last_cursor = &cursor_array[num_cursors - 1];
        last_cursor->len = (input.ptr + input.len) - last_cursor->ptr;
    }

    return AWS_OP_SUCCESS;
}

/* Final cursor contains remainder of input. */
static int s_cursor_split_first_n_times(
    struct aws_byte_cursor input,
    char split_on,
    struct aws_byte_cursor *cursor_array,
    size_t num_cursors) {

    return s_cursor_split_impl(input, split_on, cursor_array, num_cursors, false);
}

/* Error if input could have been split more times */
static int s_cursor_split_exactly_n_times(
    struct aws_byte_cursor input,
    char split_on,
    struct aws_byte_cursor *cursor_array,
    size_t num_cursors) {

    return s_cursor_split_impl(input, split_on, cursor_array, num_cursors, true);
}

static void s_set_state(struct aws_http_decoder *decoder, state_fn *state) {
    decoder->scratch_space.len = 0;
    decoder->run_state = state;
    decoder->process_line = NULL;
}

/* Set next state to capture a full line, then call the specified linestate_fn on it */
static void s_set_line_state(struct aws_http_decoder *decoder, linestate_fn *line_processor) {
    s_set_state(decoder, s_state_getline);
    decoder->process_line = line_processor;
}

static int s_mark_done(struct aws_http_decoder *decoder) {
    decoder->is_done = true;

    return decoder->vtable.on_done(decoder->user_data);
}

/* Reset state, in preparation for processing a new message */
void s_reset_state(struct aws_http_decoder *decoder) {
    if (decoder->is_decoding_requests) {
        s_set_line_state(decoder, s_linestate_request);
    } else {
        s_set_line_state(decoder, s_linestate_response);
    }

    decoder->transfer_encoding = 0;
    decoder->content_processed = 0;
    decoder->content_length = 0;
    decoder->chunk_processed = 0;
    decoder->chunk_size = 0;
    decoder->doing_trailers = false;
    decoder->is_done = false;
}

static int s_state_unchunked_body(
    struct aws_http_decoder *decoder,
    struct aws_byte_cursor input,
    size_t *bytes_processed) {

    size_t processed_bytes = 0;
    AWS_FATAL_ASSERT(decoder->content_processed < decoder->content_length); /* shouldn't be possible */

    if ((decoder->content_processed + input.len) > decoder->content_length) {
        processed_bytes = decoder->content_length - decoder->content_processed;
    } else {
        processed_bytes = input.len;
    }

    decoder->content_processed += processed_bytes;

    bool finished = decoder->content_processed == decoder->content_length;
    struct aws_byte_cursor body = aws_byte_cursor_from_array(input.ptr, processed_bytes);
    int err = decoder->vtable.on_body(&body, finished, decoder->user_data);
    if (err) {
        return AWS_OP_ERR;
    }

    if (AWS_LIKELY(finished)) {
        err = s_mark_done(decoder);
        if (err) {
            return AWS_OP_ERR;
        }
    }

    *bytes_processed = processed_bytes;

    return AWS_OP_SUCCESS;
}

static int s_linestate_chunk_terminator(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {

    /* Expecting CRLF at end of each chunk */
    /* RFC-7230 section 4.1 Chunked Transfer Encoding */
    if (AWS_UNLIKELY(input.len != 0)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_STREAM, "id=%p: Incoming chunk is invalid, does not end with CRLF.", decoder->logging_id);
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    s_set_line_state(decoder, s_linestate_chunk_size);

    return AWS_OP_SUCCESS;
}

static int s_state_chunk(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    size_t processed_bytes = 0;
    AWS_ASSERT(decoder->chunk_processed < decoder->chunk_size);

    if ((decoder->chunk_processed + input.len) > decoder->chunk_size) {
        processed_bytes = decoder->chunk_size - decoder->chunk_processed;
    } else {
        processed_bytes = input.len;
    }

    decoder->chunk_processed += processed_bytes;

    bool finished = decoder->chunk_processed == decoder->chunk_size;
    struct aws_byte_cursor body = aws_byte_cursor_from_array(input.ptr, decoder->chunk_size);
    int err = decoder->vtable.on_body(&body, false, decoder->user_data);
    if (err) {
        return AWS_OP_ERR;
    }

    if (AWS_LIKELY(finished)) {
        s_set_line_state(decoder, s_linestate_chunk_terminator);
    }

    *bytes_processed = processed_bytes;

    return AWS_OP_SUCCESS;
}

static int s_linestate_chunk_size(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {
    struct aws_byte_cursor size;
    AWS_ZERO_STRUCT(size);
    if (!aws_byte_cursor_next_split(&input, ';', &size)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_STREAM, "id=%p: Incoming chunk is invalid, first line is malformed.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Bad chunk line is: '" PRInSTR "'",
            decoder->logging_id,
            AWS_BYTE_CURSOR_PRI(input));

        return AWS_OP_ERR;
    }

    int err = s_read_size_hex(size, &decoder->chunk_size);
    if (err) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Failed to parse size of incoming chunk.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Bad chunk size is: '" PRInSTR "'",
            decoder->logging_id,
            AWS_BYTE_CURSOR_PRI(size));

        return AWS_OP_ERR;
    }
    decoder->chunk_processed = 0;

    /* Empty chunk signifies all chunks have been read. */
    if (AWS_UNLIKELY(decoder->chunk_size == 0)) {
        struct aws_byte_cursor cursor;
        cursor.ptr = NULL;
        cursor.len = 0;
        err = decoder->vtable.on_body(&cursor, true, decoder->user_data);
        if (err) {
            return AWS_OP_ERR;
        }

        /* Expected empty newline and end of message. */
        decoder->doing_trailers = true;
        s_set_line_state(decoder, s_linestate_header);
        return AWS_OP_SUCCESS;
    }

    /* Skip all chunk extensions, as they are optional. */
    /* RFC-7230 section 4.1.1 Chunk Extensions */

    s_set_state(decoder, s_state_chunk);

    return AWS_OP_SUCCESS;
}

static int s_linestate_header(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {
    int err;

    /* The \r\n was just processed by `s_state_getline`. */
    /* Empty line signifies end of headers, and beginning of body or end of trailers. */
    /* RFC-7230 section 3 Message Format */
    if (input.len == 0) {
        if (AWS_LIKELY(!decoder->doing_trailers)) {
            if (decoder->transfer_encoding & AWS_HTTP_TRANSFER_ENCODING_CHUNKED) {
                s_set_line_state(decoder, s_linestate_chunk_size);
            } else if (decoder->content_length > 0) {
                s_set_state(decoder, s_state_unchunked_body);
            } else {
                err = s_mark_done(decoder);
                if (err) {
                    return AWS_OP_ERR;
                }
            }
        } else {
            /* Empty line means end of message. */
            err = s_mark_done(decoder);
            if (err) {
                return AWS_OP_ERR;
            }
        }

        return AWS_OP_SUCCESS;
    }

    /* Each header field consists of a case-insensitive field name followed by a colon (":"),
     * optional leading whitespace, the field value, and optional trailing whitespace.
     * RFC-7230 3.2 */
    struct aws_byte_cursor splits[2];
    err = s_cursor_split_first_n_times(input, ':', splits, 2); /* value may contain more colons */
    if (err) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Invalid incoming header, missing colon.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM, "id=%p: Bad header is: '" PRInSTR "'", decoder->logging_id, AWS_BYTE_CURSOR_PRI(input));
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    struct aws_byte_cursor name = splits[0];
    if (name.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Invalid incoming header, name is empty.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM, "id=%p: Bad header is: '" PRInSTR "'", decoder->logging_id, AWS_BYTE_CURSOR_PRI(input));
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    struct aws_byte_cursor value = s_trim_whitespace(splits[1]);

    struct aws_http_decoded_header header;
    header.name = aws_http_str_to_header_name(name);
    header.name_data = name;
    header.value_data = value;
    header.data = input;

    switch (header.name) {
        case AWS_HTTP_HEADER_CONTENT_LENGTH:
            if (decoder->transfer_encoding) {
                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_STREAM,
                    "id=%p: Incoming headers for both content-length and transfer-encoding received. This is illegal.",
                    decoder->logging_id);
                return aws_raise_error(AWS_ERROR_HTTP_PARSE);
            }

            if (s_read_size(header.value_data, &decoder->content_length) != AWS_OP_SUCCESS) {
                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_STREAM,
                    "id=%p: Incoming content-length header has invalid value.",
                    decoder->logging_id);
                AWS_LOGF_DEBUG(
                    AWS_LS_HTTP_STREAM,
                    "id=%p: Bad content-length value is: '" PRInSTR "'",
                    decoder->logging_id,
                    AWS_BYTE_CURSOR_PRI(header.value_data));
                return AWS_OP_ERR;
            }
            break;

        case AWS_HTTP_HEADER_TRANSFER_ENCODING: {
            if (decoder->content_length) {
                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_STREAM,
                    "id=%p: Incoming headers for both content-length and transfer-encoding received. This is illegal.",
                    decoder->logging_id);
                return aws_raise_error(AWS_ERROR_HTTP_PARSE);
            }

            /* RFC-7230 section 3.3.1 Transfer-Encoding */
            /* RFC-7230 section 4.2 Compression Codings */

            /* Note that it's possible for multiple Transfer-Encoding headers to exist, in which case the values
             * should be appended with those from any previously encountered Transfer-Encoding headers. */
            struct aws_byte_cursor split;
            AWS_ZERO_STRUCT(split);
            while (aws_byte_cursor_next_split(&header.value_data, ',', &split)) {
                struct aws_byte_cursor coding = s_trim_whitespace(split);
                int prev_flags = decoder->transfer_encoding;

                if (aws_string_eq_byte_cursor_ignore_case(s_transfer_coding_chunked, &coding)) {
                    decoder->transfer_encoding |= AWS_HTTP_TRANSFER_ENCODING_CHUNKED;

                } else if (
                    aws_string_eq_byte_cursor_ignore_case(s_transfer_coding_compress, &coding) ||
                    aws_string_eq_byte_cursor_ignore_case(s_transfer_coding_x_compress, &coding)) {
                    /* A recipient SHOULD consider "x-compress" to be equivalent to "compress". RFC-7230 4.2.1 */
                    decoder->transfer_encoding |= AWS_HTTP_TRANSFER_ENCODING_DEPRECATED_COMPRESS;

                } else if (aws_string_eq_byte_cursor_ignore_case(s_transfer_coding_deflate, &coding)) {
                    decoder->transfer_encoding |= AWS_HTTP_TRANSFER_ENCODING_DEFLATE;

                } else if (
                    aws_string_eq_byte_cursor_ignore_case(s_transfer_coding_gzip, &coding) ||
                    aws_string_eq_byte_cursor_ignore_case(s_transfer_coding_x_gzip, &coding)) {
                    /* A recipient SHOULD consider "x-gzip" to be equivalent to "gzip". RFC-7230 4.2.3 */
                    decoder->transfer_encoding |= AWS_HTTP_TRANSFER_ENCODING_GZIP;

                } else if (coding.len > 0) {
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_STREAM,
                        "id=%p: Incoming transfer-encoding header lists unrecognized coding.",
                        decoder->logging_id);
                    AWS_LOGF_DEBUG(
                        AWS_LS_HTTP_STREAM,
                        "id=%p: Unrecognized coding is: '" PRInSTR "'",
                        decoder->logging_id,
                        AWS_BYTE_CURSOR_PRI(coding));
                    return aws_raise_error(AWS_ERROR_HTTP_PARSE);
                }

                /* If any transfer coding other than chunked is applied to a request payload body, the sender MUST
                 * apply chunked as the final transfer coding to ensure that the message is properly framed.
                 * RFC-7230 3.3.1 */
                if ((prev_flags & AWS_HTTP_TRANSFER_ENCODING_CHUNKED) && (decoder->transfer_encoding != prev_flags)) {
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_STREAM,
                        "id=%p: Incoming transfer-encoding header lists a coding after 'chunked', this is illegal.",
                        decoder->logging_id);
                    AWS_LOGF_DEBUG(
                        AWS_LS_HTTP_STREAM,
                        "id=%p: Misplaced coding is '" PRInSTR "'",
                        decoder->logging_id,
                        AWS_BYTE_CURSOR_PRI(coding));
                    return aws_raise_error(AWS_ERROR_HTTP_PARSE);
                }
            }

            /* TODO: deal with body of indeterminate length, marking it as successful when connection is closed:
             *
             * A response that has neither chunked transfer coding nor Content-Length is terminated by closure of
             * the connection and, thus, is considered complete regardless of the number of message body octets
             * received, provided that the header section was received intact.
             * RFC-7230 3.4 */
        } break;

        default:
            break;
    }

    err = decoder->vtable.on_header(&header, decoder->user_data);
    if (err) {
        return AWS_OP_ERR;
    }

    s_set_line_state(decoder, s_linestate_header);

    return AWS_OP_SUCCESS;
}

static int s_linestate_request(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {
    struct aws_byte_cursor cursors[3];
    int err = s_cursor_split_exactly_n_times(input, ' ', cursors, 3); /* extra spaces not allowed */
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_STREAM, "id=%p: Incoming request line has wrong number of spaces.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Bad request line is: '" PRInSTR "'",
            decoder->logging_id,
            AWS_BYTE_CURSOR_PRI(input));
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    for (size_t i = 0; i < AWS_ARRAY_SIZE(cursors); ++i) {
        if (cursors[i].len == 0) {
            AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Incoming request line has empty values.", decoder->logging_id);
            AWS_LOGF_DEBUG(
                AWS_LS_HTTP_STREAM,
                "id=%p: Bad request line is: '" PRInSTR "'",
                decoder->logging_id,
                AWS_BYTE_CURSOR_PRI(input));
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }
    }

    struct aws_byte_cursor method = cursors[0];
    struct aws_byte_cursor uri = cursors[1];
    struct aws_byte_cursor version = cursors[2];

    struct aws_byte_cursor version_expected = aws_http_version_to_str(AWS_HTTP_VERSION_1_1);
    if (!aws_byte_cursor_eq(&version, &version_expected)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_STREAM, "id=%p: Incoming request uses unsupported HTTP version.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Unsupported version is: '" PRInSTR "'",
            decoder->logging_id,
            AWS_BYTE_CURSOR_PRI(version));
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    err = decoder->vtable.on_request(aws_http_str_to_method(method), &method, &uri, decoder->user_data);
    if (err) {
        return AWS_OP_ERR;
    }

    s_set_line_state(decoder, s_linestate_header);

    return AWS_OP_SUCCESS;
}

static int s_linestate_response(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {
    struct aws_byte_cursor cursors[3];
    int err = s_cursor_split_first_n_times(input, ' ', cursors, 3); /* phrase may contain spaces */
    if (err) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Incoming response status line is invalid.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Bad status line is: '" PRInSTR "'",
            decoder->logging_id,
            AWS_BYTE_CURSOR_PRI(input));
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    struct aws_byte_cursor version = cursors[0];
    struct aws_byte_cursor code = cursors[1];
    struct aws_byte_cursor phrase = cursors[2];
    (void)phrase; /* Unused for now. */

    struct aws_byte_cursor version_expected = aws_http_version_to_str(AWS_HTTP_VERSION_1_1);
    if (!aws_byte_cursor_eq(&version, &version_expected)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_STREAM, "id=%p: Incoming response uses unsupported HTTP version.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Unsupported version is: '" PRInSTR "'",
            decoder->logging_id,
            AWS_BYTE_CURSOR_PRI(version));
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    /* Status-code is a 3-digit integer. RFC7230 section 3.1.2 */
    size_t code_val;
    err = s_read_size(code, &code_val);
    if (err || code.len != 3 || code_val > 999) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Incoming response has invalid status code.", decoder->logging_id);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Bad status code is: '" PRInSTR "'",
            decoder->logging_id,
            AWS_BYTE_CURSOR_PRI(code));
        return AWS_OP_ERR;
    }

    err = decoder->vtable.on_response((int)code_val, decoder->user_data);
    if (err) {
        return AWS_OP_ERR;
    }

    s_set_line_state(decoder, s_linestate_header);
    return AWS_OP_SUCCESS;
}

struct aws_http_decoder *aws_http_decoder_new(struct aws_http_decoder_params *params) {
    AWS_ASSERT(params);

    struct aws_http_decoder *decoder = aws_mem_acquire(params->alloc, sizeof(struct aws_http_decoder));
    if (!decoder) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*decoder);

    decoder->alloc = params->alloc;
    decoder->user_data = params->user_data;
    decoder->vtable = params->vtable;
    decoder->is_decoding_requests = params->is_decoding_requests;

    aws_byte_buf_init(&decoder->scratch_space, params->alloc, params->scratch_space_initial_size);

    s_reset_state(decoder);

    return decoder;
}

void aws_http_decoder_destroy(struct aws_http_decoder *decoder) {
    aws_byte_buf_clean_up(&decoder->scratch_space);
    aws_mem_release(decoder->alloc, decoder);
}

int aws_http_decode(struct aws_http_decoder *decoder, const void *data, size_t data_bytes, size_t *bytes_read) {
    AWS_ASSERT(decoder);
    AWS_ASSERT(data);

    struct aws_byte_cursor input = aws_byte_cursor_from_array(data, data_bytes);
    size_t total_bytes_processed = 0;

    while (data_bytes && !decoder->is_done) {
        size_t bytes_processed = 0;
        int err = decoder->run_state(decoder, input, &bytes_processed);
        if (err) {
            return AWS_OP_ERR;
        }
        data_bytes -= bytes_processed;
        total_bytes_processed += bytes_processed;
        aws_byte_cursor_advance(&input, bytes_processed);
    }

    if (bytes_read) {
        *bytes_read = total_bytes_processed;
    }

    if (decoder->is_done) {
        s_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}

int aws_http_decoder_get_encoding_flags(const struct aws_http_decoder *decoder) {
    return decoder->transfer_encoding;
}

size_t aws_http_decoder_get_content_length(const struct aws_http_decoder *decoder) {
    return decoder->content_length;
}

void aws_http_decoder_set_logging_id(struct aws_http_decoder *decoder, void *id) {
    decoder->logging_id = id;
}
