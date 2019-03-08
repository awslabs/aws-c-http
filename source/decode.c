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

#include <assert.h>

struct aws_http_decoder;

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
    bool expect_100_continue_skip_on_done;

    /* User callbacks and settings. */
    struct aws_http_decoder_vtable vtable;
    bool is_decoding_requests;
    void *user_data;
};

static int s_linestate_request(struct aws_http_decoder *decoder, struct aws_byte_cursor input);
static int s_linestate_response(struct aws_http_decoder *decoder, struct aws_byte_cursor input);
static int s_linestate_header(struct aws_http_decoder *decoder, struct aws_byte_cursor input);
static int s_linestate_chunk_size(struct aws_http_decoder *decoder, struct aws_byte_cursor input);

static char s_upper(char c) {
    if (c >= 'a' && c <= 'z') {
        c = (char)(c - ('a' - 'A'));
    }
    return c;
}

/* Works like memcmp or strcmp, except is case-agnostic. */
static int s_strcmp_case_insensitive(const char *a, size_t len_a, const char *b, size_t len_b) {
    if (len_a != len_b) {
        return 1;
    }

    for (size_t i = 0; i < len_a; ++i) {
        int d = s_upper(a[i]) - s_upper(b[i]);
        if (d) {
            return d;
        }
    }
    return 0;
}

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
    assert(input.len > 0);

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

static int s_read_int64(struct aws_byte_cursor cursor, int64_t *val) {
    char *end;
    *val = (int64_t)strtoll((const char *)cursor.ptr, &end, 10);
    if ((char *)cursor.ptr != end) {
        return AWS_OP_SUCCESS;
    } else {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }
}

static int s_read_hex_int64(struct aws_byte_cursor cursor, int64_t *val) {
    char *end;
    *val = (int64_t)strtoll((const char *)cursor.ptr, &end, 16);
    if ((char *)cursor.ptr != end) {
        return AWS_OP_SUCCESS;
    } else {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }
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
        assert(line.len >= 2);
        line.len -= 2;

        return decoder->process_line(decoder, line);
    }

    /* Didn't find crlf, we'll continue scanning when more data comes in */
    return AWS_OP_SUCCESS;
}

static size_t s_byte_buf_split(struct aws_byte_cursor line, struct aws_byte_cursor *cursors, char split_on, size_t n) {

    struct aws_array_list string_list;
    aws_array_list_init_static(&string_list, cursors, n, sizeof(struct aws_byte_cursor));
    aws_byte_cursor_split_on_char_n(&line, split_on, n, &string_list);
    return string_list.length;
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

/* Reset state, in preparation for processing a new message */
void s_reset_state(struct aws_http_decoder *decoder, bool message_done) {
    if (message_done && !decoder->expect_100_continue_skip_on_done && decoder->vtable.on_done) {
        decoder->vtable.on_done(decoder->user_data);
    }

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
    decoder->expect_100_continue_skip_on_done = false;
}

static int s_state_unchunked_body(
    struct aws_http_decoder *decoder,
    struct aws_byte_cursor input,
    size_t *bytes_processed) {

    size_t processed_bytes = 0;
    if (decoder->content_processed > decoder->content_length) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    if ((decoder->content_processed + input.len) > decoder->content_length) {
        processed_bytes = decoder->content_length - decoder->content_processed;
    } else {
        processed_bytes = input.len;
    }

    decoder->content_processed += processed_bytes;

    bool finished = decoder->content_processed == decoder->content_length;
    struct aws_byte_cursor body = aws_byte_cursor_from_array(input.ptr, processed_bytes);
    if (!decoder->vtable.on_body(&body, finished, decoder->user_data)) {
        return aws_raise_error(AWS_ERROR_HTTP_USER_CALLBACK_EXIT);
    }

    if (AWS_LIKELY(finished)) {
        s_reset_state(decoder, true);
    }

    *bytes_processed = processed_bytes;

    return AWS_OP_SUCCESS;
}

static int s_linestate_chunk_terminator(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {

    /* Expecting CRLF at end of each chunk */
    /* RFC-7230 section 4.1 Chunked Transfer Encoding */
    if (AWS_UNLIKELY(input.len != 0)) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    s_set_line_state(decoder, s_linestate_chunk_size);

    return AWS_OP_SUCCESS;
}

static int s_state_chunk(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    size_t processed_bytes = 0;
    assert(decoder->chunk_processed < decoder->chunk_size);

    if ((decoder->chunk_processed + input.len) > decoder->chunk_size) {
        processed_bytes = decoder->chunk_size - decoder->chunk_processed;
    } else {
        processed_bytes = input.len;
    }

    decoder->chunk_processed += processed_bytes;

    bool finished = decoder->chunk_processed == decoder->chunk_size;
    struct aws_byte_cursor body = aws_byte_cursor_from_array(input.ptr, decoder->chunk_size);
    if (!decoder->vtable.on_body(&body, false, decoder->user_data)) {
        return aws_raise_error(AWS_ERROR_HTTP_USER_CALLBACK_EXIT);
    }

    if (AWS_LIKELY(finished)) {
        s_set_line_state(decoder, s_linestate_chunk_terminator);
    }

    *bytes_processed = processed_bytes;

    return AWS_OP_SUCCESS;
}

static int s_linestate_chunk_size(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {
    if (AWS_UNLIKELY(s_read_hex_int64(input, (int64_t *)&decoder->chunk_size) != AWS_OP_SUCCESS)) {
        return AWS_OP_ERR;
    }
    decoder->chunk_processed = 0;

    /* Empty chunk signifies all chunks have been read. */
    if (AWS_UNLIKELY(decoder->chunk_size == 0)) {
        struct aws_byte_cursor cursor;
        cursor.ptr = NULL;
        cursor.len = 0;
        if (!decoder->vtable.on_body(&cursor, true, decoder->user_data)) {
            return aws_raise_error(AWS_ERROR_HTTP_USER_CALLBACK_EXIT);
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

    struct aws_byte_cursor cursors[2];
    if (AWS_UNLIKELY(s_byte_buf_split(input, cursors, ':', 2) != 2)) {
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
                    s_reset_state(decoder, true);
                }
            } else {
                /* Empty line means end of message. */
                s_reset_state(decoder, true);
            }

            return AWS_OP_SUCCESS;
        } else {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }
    }

    struct aws_byte_cursor header_name = s_trim_whitespace(cursors[0]);
    struct aws_byte_cursor header_value = s_trim_whitespace(cursors[1]);

    struct aws_http_decoded_header header;
    header.name = aws_http_str_to_header_name(header_name);
    header.name_data = header_name;
    header.value_data = header_value;
    header.data = input;

    switch (header.name) {
        case AWS_HTTP_HEADER_CONTENT_LENGTH:
            if (s_read_int64(header.value_data, (int64_t *)&decoder->content_length) != AWS_OP_SUCCESS) {
                return AWS_OP_ERR;
            }
            break;

        case AWS_HTTP_HEADER_TRANSFER_ENCODING: {
            /* Is 8 a good cap? Typically only 2, max of 3, could be realistic, afaik. */
            /* RFC-7230 section 3.3.1 Transfer-Encoding */
            /* RFC-7230 section 4.2 Compression Codings */
            struct aws_byte_cursor codings[8];
            int flags = 0;
            const size_t n = s_byte_buf_split(header.value_data, codings, ',', 8);
            if (n < 1 || n > AWS_ARRAY_SIZE(codings)) {
                /* At least 1 coding must be passed */
                return aws_raise_error(AWS_ERROR_HTTP_PARSE);
            }
            for (size_t i = 0; i < n; ++i) {
                struct aws_byte_cursor coding = s_trim_whitespace(codings[i]);
                if (!s_strcmp_case_insensitive((const char *)coding.ptr, coding.len, "chunked", strlen("chunked"))) {
                    flags |= AWS_HTTP_TRANSFER_ENCODING_CHUNKED;
                    if (i != (n - 1)) {
                        /* chunked must be the final transfer coding */
                        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
                    }
                } else if (!s_strcmp_case_insensitive(
                               (const char *)coding.ptr, coding.len, "compress", strlen("compress"))) {
                    flags |= AWS_HTTP_TRANSFER_ENCODING_DEPRECATED_COMPRESS;
                } else if (!s_strcmp_case_insensitive(
                               (const char *)coding.ptr, coding.len, "deflate", strlen("deflate"))) {
                    flags |= AWS_HTTP_TRANSFER_ENCODING_DEFLATE;
                } else if (!s_strcmp_case_insensitive((const char *)coding.ptr, coding.len, "gzip", strlen("gzip"))) {
                    flags |= AWS_HTTP_TRANSFER_ENCODING_GZIP;
                }
            }

            if (!(flags & AWS_HTTP_TRANSFER_ENCODING_CHUNKED)) {
                /* If a message with Transfer-Encoding doesn't specify chunked, then
                 * the body of the message will go on forever, only ending when the connection is closed */

                /* TODO: better support than just pretending it's a really long message */
                decoder->content_length = SIZE_MAX;
            }

            decoder->transfer_encoding |= flags;
        } break;

        case AWS_HTTP_HEADER_EXPECT:
            if (!s_strcmp_case_insensitive(
                    (const char *)header.value_data.ptr, header.value_data.len, "100-continue", 12)) {
                decoder->expect_100_continue_skip_on_done = true;
            }
            break;

        default:
            break;
    }

    if (!decoder->vtable.on_header(&header, decoder->user_data)) {
        return aws_raise_error(AWS_ERROR_HTTP_USER_CALLBACK_EXIT);
    }

    s_set_line_state(decoder, s_linestate_header);

    return AWS_OP_SUCCESS;
}

static int s_linestate_request(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {
    struct aws_byte_cursor cursors[3];
    if (s_byte_buf_split(input, cursors, ' ', 3) != 3) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }
    struct aws_byte_cursor method = cursors[0];
    struct aws_byte_cursor uri = cursors[1];
    struct aws_byte_cursor version = cursors[2];

    if (decoder->vtable.on_method) {
        decoder->vtable.on_method(aws_http_str_to_method(method), decoder->user_data);
    }

    if (decoder->vtable.on_version) {
        decoder->vtable.on_version(aws_http_str_to_version(version), decoder->user_data);
    }

    if (decoder->vtable.on_uri) {
        decoder->vtable.on_uri(&uri, decoder->user_data);
    }

    s_set_line_state(decoder, s_linestate_header);

    return AWS_OP_SUCCESS;
}

static int s_linestate_response(struct aws_http_decoder *decoder, struct aws_byte_cursor input) {
    struct aws_byte_cursor cursors[3];
    if (s_byte_buf_split(input, cursors, ' ', 3) != 3) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    struct aws_byte_cursor version = cursors[0];
    struct aws_byte_cursor code = cursors[1];
    struct aws_byte_cursor phrase = cursors[2];
    (void)phrase; /* Unused for now. */

    if (decoder->vtable.on_version) {
        decoder->vtable.on_version(aws_http_str_to_version(version), decoder->user_data);
    }

    int64_t code_val;
    int err = s_read_int64(code, &code_val);
    if (err) {
        return AWS_OP_ERR;
    }

    /* Status-code is a 3-digit integer. RFC7230 section 3.1.2 */
    if (code.len != 3 || code_val < 0 || code_val > 999) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    if (decoder->vtable.on_code) {
        decoder->vtable.on_code(aws_http_int_to_code((int)code_val), decoder->user_data);
    }

    s_set_line_state(decoder, s_linestate_header);
    return AWS_OP_SUCCESS;
}

struct aws_http_decoder *aws_http_decoder_new(struct aws_http_decoder_params *params) {
    assert(params);

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

    s_reset_state(decoder, false);

    return decoder;
}

void aws_http_decoder_destroy(struct aws_http_decoder *decoder) {
    aws_byte_buf_clean_up(&decoder->scratch_space);
    aws_mem_release(decoder->alloc, decoder);
}

int aws_http_decode(struct aws_http_decoder *decoder, const void *data, size_t data_bytes, size_t *bytes_read) {
    assert(decoder);
    assert(data);

    struct aws_byte_cursor input = aws_byte_cursor_from_array(data, data_bytes);
    size_t total_bytes_processed = 0;

    int ret = AWS_OP_SUCCESS;
    while (ret == AWS_OP_SUCCESS && data_bytes) {
        if (!decoder->run_state) {
            /* Attempted to call decoder on an invalid decoder state. */
            ret = aws_raise_error(AWS_ERROR_HTTP_INVALID_PARSE_STATE);
            break;
        }

        size_t bytes_processed = 0;
        ret = decoder->run_state(decoder, input, &bytes_processed);
        data_bytes -= bytes_processed;
        total_bytes_processed += bytes_processed;
        aws_byte_cursor_advance(&input, bytes_processed);
    }

    if (bytes_read) {
        *bytes_read = total_bytes_processed;
    }

    return ret;
}

void aws_http_decoder_set_vtable(struct aws_http_decoder *decoder, const struct aws_http_decoder_vtable *vtable) {
    decoder->vtable = *vtable;
}

int aws_http_decoder_get_encoding_flags(const struct aws_http_decoder *decoder) {
    return decoder->transfer_encoding;
}

size_t aws_http_decoder_get_content_length(const struct aws_http_decoder *decoder) {
    return decoder->content_length;
}
