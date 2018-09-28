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

#include <aws/http/decode.h>

#include <assert.h>
#include <stdlib.h>

struct aws_http_decoder;
typedef int(s_aws_http_decoder_state_fn)(
    struct aws_http_decoder *decoder,
    struct aws_byte_cursor input,
    size_t *bytes_processed);

struct aws_http_decoder {
    /* Implementation data. */
    struct aws_allocator *alloc;
    bool cleanup_scratch;
    struct aws_byte_buf scratch_space;
    s_aws_http_decoder_state_fn *state_cb;
    s_aws_http_decoder_state_fn *next_state_cb;
    struct aws_byte_cursor cursor;
    bool found_carriage;
    int transfer_encoding;
    size_t content_processed;
    size_t content_length;
    size_t chunk_processed;
    size_t chunk_size;
    bool doing_trailers;

    /* User callbacks and settings. */
    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;
    aws_http_decoder_on_version_fn *on_version;
    aws_http_decoder_on_uri_fn *on_uri;
    aws_http_decoder_on_method_fn *on_method;
    aws_http_decoder_on_response_code_fn *on_code;
    bool true_for_request_false_for_response;
    void *user_data;
};

static inline char s_upper(char c) {
    if (c >= 'a' && c <= 'z') {
        c += ('A' - 'a');
    }
    return c;
}

/* Works like memcmp or strcmp, except is case-agnostic. */
static inline int s_strcmp_case_insensitive(const char *a, size_t len_a, const char *b, size_t len_b) {
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

static inline struct aws_byte_cursor s_trim_trailing_whitespace(struct aws_byte_cursor cursor) {
    while (cursor.len && cursor.ptr[cursor.len - 1] == (uint8_t)' ') {
        cursor.len--;
    }
    return cursor;
}

static inline struct aws_byte_cursor s_trim_leading_whitespace(struct aws_byte_cursor cursor) {
    while (cursor.len && *cursor.ptr == (uint8_t)' ') {
        cursor.ptr++;
        cursor.len--;
    }
    return cursor;
}

static inline struct aws_byte_cursor s_trim_whitespace(struct aws_byte_cursor cursor) {
    cursor = s_trim_leading_whitespace(cursor);
    cursor = s_trim_trailing_whitespace(cursor);
    return cursor;
}

static bool s_scan_for_newline(
    struct aws_http_decoder *decoder,
    struct aws_byte_cursor input,
    size_t *bytes_processed) {
    size_t index = 0;
    bool done = false;
    uint8_t *ptr;

    if (!decoder->found_carriage) {
        ptr = (uint8_t *)memchr(input.ptr, '\r', input.len);
        if (ptr) {
            decoder->found_carriage = true;
        }
    } else {
        ptr = input.ptr;
        bool found = input.len && *input.ptr == (uint8_t)'\n';
        if (found) {
            decoder->found_carriage = false;
            done = true;
        }
    }

    if (ptr) {
        index = ptr - input.ptr + 1;
    } else {
        index = input.len;
    }

    *bytes_processed = index;
    return done;
}

static int s_cat(struct aws_http_decoder *decoder, uint8_t *data, size_t len) {
    struct aws_byte_buf *buffer = &decoder->scratch_space;
    struct aws_byte_cursor to_append = aws_byte_cursor_from_array(data, len);
    if (AWS_LIKELY(aws_byte_buf_append(buffer, &to_append) == AWS_OP_SUCCESS)) {
        return AWS_OP_SUCCESS;
    } else {
        size_t new_size = buffer->capacity;
        do {
            new_size <<= 1;      /* new_size *= 2 */
            if (new_size == 0) { /* check for overflow */
                return aws_raise_error(AWS_ERROR_OOM);
            }
        } while (new_size < (buffer->len + len));

        uint8_t *new_data = aws_mem_acquire(decoder->alloc, new_size);
        if (!new_data) {
            return AWS_OP_ERR;
        }

        memcpy(new_data, buffer->buffer, buffer->len);
        if (decoder->cleanup_scratch) {
            aws_mem_release(decoder->alloc, buffer->buffer);
        }
        buffer->capacity = new_size;
        buffer->buffer = new_data;

        decoder->cleanup_scratch = true;

        return aws_byte_buf_append(buffer, &to_append);
    }
}

static inline int s_read_int64(struct aws_byte_cursor cursor, int64_t *val) {
    char *end;
    *val = (int64_t)strtoll((const char *)cursor.ptr, &end, 10);
    if ((char *)cursor.ptr != end) {
        return AWS_OP_SUCCESS;
    } else {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }
}

static inline int s_read_hex_int64(struct aws_byte_cursor cursor, int64_t *val) {
    char *end;
    *val = (int64_t)strtoll((const char *)cursor.ptr, &end, 16);
    if ((char *)cursor.ptr != end) {
        return AWS_OP_SUCCESS;
    } else {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }
}

static int s_state_getline(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    int ret = AWS_OP_SUCCESS;
    bool done = s_scan_for_newline(decoder, input, bytes_processed);

    bool needs_split = !done;
    bool was_split_before = decoder->scratch_space.len;
    bool needs_cat = needs_split | was_split_before;

    if (AWS_UNLIKELY(needs_cat)) {
        ret = s_cat(decoder, input.ptr, *bytes_processed);
    }

    if (AWS_LIKELY(done)) {
        if (AWS_UNLIKELY(needs_cat)) {
            decoder->cursor = aws_byte_cursor_from_buf(&decoder->scratch_space);
        } else {
            decoder->cursor.ptr = input.ptr;
            decoder->cursor.len = *bytes_processed;
        }

        /* Backup so "\r\n" is not included. */
        /* RFC-7230 section 3 Message Format */
        decoder->cursor.len -= 2;
        decoder->state_cb = decoder->next_state_cb;
        decoder->next_state_cb = NULL;
    }

    return ret;
}

static inline size_t s_byte_buf_split(
    struct aws_byte_cursor line,
    struct aws_byte_cursor *cursors,
    char split_on,
    size_t n) {
    struct aws_byte_buf line_buf = aws_byte_buf_from_array(line.ptr, line.len);
    struct aws_array_list string_list;
    aws_array_list_init_static(&string_list, cursors, n, sizeof(struct aws_byte_cursor));
    aws_byte_buf_split_on_char_n(&line_buf, split_on, &string_list, n);
    return string_list.length;
}

static inline void s_set_next_state(
    struct aws_http_decoder *decoder,
    s_aws_http_decoder_state_fn *state,
    s_aws_http_decoder_state_fn *next) {
    decoder->scratch_space.len = 0;
    decoder->state_cb = state;
    decoder->next_state_cb = next;
}

static int s_state_unchunked(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    size_t processed_bytes = 0;
    if (decoder->content_processed < decoder->content_length) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    if ((decoder->content_processed + input.len) > decoder->content_length) {
        processed_bytes = decoder->content_length - decoder->content_processed;
    } else {
        processed_bytes = input.len;
    }

    decoder->content_processed += processed_bytes;

    bool finished = decoder->content_processed == decoder->content_length;
    struct aws_byte_cursor body = aws_byte_cursor_from_array(input.ptr, decoder->content_length);
    if (!decoder->on_body(&body, finished, decoder->user_data)) {
        return aws_raise_error(AWS_ERROR_HTTP_USER_CALLBACK_EXIT);
    }

    if (AWS_LIKELY(finished)) {
        s_set_next_state(decoder, NULL, NULL);
    }

    *bytes_processed = processed_bytes;

    return AWS_OP_SUCCESS;
}

static int s_state_chunk_size(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed);
static int s_state_header(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed);

static int s_state_chunk_terminator(
    struct aws_http_decoder *decoder,
    struct aws_byte_cursor input,
    size_t *bytes_processed) { /* NOLINT */
    /*
     * Input params are unused here. This state operates on `decoder->cursor`, which has been setup to contain
     * and entire line of input by the `s_state_getline` state.
     */
    (void)input;
    (void)bytes_processed;

    /* Expecting an empty line ending in CRLF for chunk termination. */
    /* RFC-7230 section 4.1 Chunked Transfer Encoding */
    if (AWS_UNLIKELY(decoder->cursor.len != 0)) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    s_set_next_state(decoder, s_state_getline, s_state_chunk_size);

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
    if (!decoder->on_body(&body, false, decoder->user_data)) {
        return aws_raise_error(AWS_ERROR_HTTP_USER_CALLBACK_EXIT);
    }

    if (AWS_LIKELY(finished)) {
        s_set_next_state(decoder, s_state_getline, s_state_chunk_terminator);
    }

    *bytes_processed = processed_bytes;

    return AWS_OP_SUCCESS;
}

/* NOLINTNEXTLINE(readability-non-const-parameter) */
static int s_state_chunk_size(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    /*
     * Input params are unused here. This state operates on `decoder->cursor`, which has been setup to contain
     * and entire line of input by the `s_state_getline` state.
     */
    (void)input;
    (void)bytes_processed;

    if (AWS_UNLIKELY(s_read_hex_int64(decoder->cursor, (int64_t *)&decoder->chunk_size) != AWS_OP_SUCCESS)) {
        return AWS_OP_ERR;
    }
    decoder->chunk_processed = 0;

    /* Empty chunk signifies all chunks have been read. */
    if (AWS_UNLIKELY(decoder->chunk_size == 0)) {
        struct aws_byte_cursor cursor;
        cursor.ptr = NULL;
        cursor.len = 0;
        if (!decoder->on_body(&cursor, true, decoder->user_data)) {
            return aws_raise_error(AWS_ERROR_HTTP_USER_CALLBACK_EXIT);
        }

        /* Expected empty newline and end of message. */
        decoder->doing_trailers = true;
        s_set_next_state(decoder, s_state_getline, s_state_header);
        return AWS_OP_SUCCESS;
    }

    /* Skip all chunk extensions, as they are optional. */
    /* RFC-7230 section 4.1.1 Chunk Extensions */

    s_set_next_state(decoder, s_state_chunk, NULL);

    return AWS_OP_SUCCESS;
}

/* NOLINTNEXTLINE(readability-non-const-parameter) */
static int s_state_header(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    /*
     * Input params are unused here. This state operates on `decoder->cursor`, which has been setup to contain
     * and entire line of input by the `s_state_getline` state.
     */
    (void)input;
    (void)bytes_processed;

    struct aws_byte_cursor cursors[2];
    if (AWS_UNLIKELY(s_byte_buf_split(decoder->cursor, cursors, ':', 2) != 2)) {
        /* The \r\n was just processed by `s_state_getline`. */
        /* Empty line signifies end of headers, and beginning of body or end of trailers. */
        /* RFC-7230 section 3 Message Format */

        if (decoder->cursor.len == 0) {
            if (AWS_LIKELY(!decoder->doing_trailers)) {
                if (decoder->transfer_encoding & AWS_HTTP_TRANSFER_ENCODING_CHUNKED) {
                    s_set_next_state(decoder, s_state_getline, s_state_chunk_size);
                } else {
                    s_set_next_state(decoder, s_state_unchunked, NULL);
                }
            } else {
                /* Expected empty newline and end of message. */
                s_set_next_state(decoder, s_state_getline, NULL);
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
    header.data = decoder->cursor;

    switch (header.name) {
        case AWS_HTTP_HEADER_CONTENT_LENGTH:
            if (s_read_int64(header.value_data, (int64_t *)&decoder->content_length) != AWS_OP_SUCCESS) {
                return AWS_OP_ERR;
            }
            break;

        case AWS_HTTP_HEADER_TRANSFER_ENCODING: {
            /* Is 8 a good cap? Typically only 2, max of 3, could be realistic, afaik. */
            /* RFC-7230 section 4.2 Compression Codings */
            struct aws_byte_cursor codings[8];
            int flags = 0;
            int n = (int)s_byte_buf_split(header.value_data, codings, ',', 8);
            for (int i = 0; i < n; ++i) {
                struct aws_byte_cursor coding = s_trim_whitespace(codings[i]);
                if (!s_strcmp_case_insensitive((const char *)coding.ptr, coding.len, "chunked", strlen("chunked"))) {
                    flags |= AWS_HTTP_TRANSFER_ENCODING_CHUNKED;
                } else if (!s_strcmp_case_insensitive(
                               (const char *)coding.ptr, coding.len, "compress", strlen("compress"))) {
                    flags |= AWS_HTTP_TRANSFER_ENCODING_DEPRECATED_COMPRESS;
                } else if (!s_strcmp_case_insensitive(
                               (const char *)coding.ptr, coding.len, "deflate", strlen("deflate"))) {
                    flags |= AWS_HTTP_TRANSFER_ENCODING_DEFLATE;
                } else if (!s_strcmp_case_insensitive((const char *)coding.ptr, coding.len, "gzip", strlen("gzip"))) {
                    flags |= AWS_HTTP_TRANSFER_ENCODING_GZIP;
                } else if (!s_strcmp_case_insensitive(
                               (const char *)coding.ptr, coding.len, "identity", strlen("identity"))) {
                    /* `identity` means do nothing. */
                } else {
                    /* Invalid token for transfer encoding. */
                    return aws_raise_error(AWS_ERROR_HTTP_PARSE);
                }
            }
            decoder->transfer_encoding |= flags;
        } break;

        default:
            break;
    }

    if (!decoder->on_header(&header, decoder->user_data)) {
        return aws_raise_error(AWS_ERROR_HTTP_USER_CALLBACK_EXIT);
    }

    s_set_next_state(decoder, s_state_getline, s_state_header);

    return AWS_OP_SUCCESS;
}

/* NOLINTNEXTLINE(readability-non-const-parameter) */
static int s_state_method(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    (void)input;
    (void)bytes_processed;

    struct aws_byte_cursor cursors[3];
    if (s_byte_buf_split(decoder->cursor, cursors, ' ', 3) != 3) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }
    struct aws_byte_cursor method = cursors[0];
    struct aws_byte_cursor uri = cursors[1];
    struct aws_byte_cursor version = cursors[2];

    if (decoder->on_method) {
        decoder->on_method(aws_http_str_to_method(method), decoder->user_data);
    }

    if (decoder->on_version) {
        decoder->on_version(aws_http_str_to_version(version), decoder->user_data);
    }

    if (decoder->on_uri) {
        decoder->on_uri(&uri, decoder->user_data);
    }

    s_set_next_state(decoder, s_state_getline, s_state_header);

    return AWS_OP_SUCCESS;
}

/* NOLINTNEXTLINE(readability-non-const-parameter) */
static int s_state_response(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    (void)input;
    (void)bytes_processed;

    struct aws_byte_cursor cursors[3];
    if (s_byte_buf_split(decoder->cursor, cursors, ' ', 3) != 3) {
        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    struct aws_byte_cursor version = cursors[0];
    struct aws_byte_cursor code = cursors[1];
    struct aws_byte_cursor phrase = cursors[2];
    (void)phrase; /* Unused for now. */

    if (decoder->on_version) {
        decoder->on_version(aws_http_str_to_version(version), decoder->user_data);
    }

    int64_t code_val;
    int ret = s_read_int64(code, &code_val);
    if (ret != AWS_OP_SUCCESS) {
        return ret;
    }

    if (decoder->on_code) {
        decoder->on_code(aws_http_int_to_code((int)code_val), decoder->user_data);
    }

    s_set_next_state(decoder, s_state_getline, s_state_header);

    return AWS_OP_SUCCESS;
}

void aws_http_decoder_reset(struct aws_http_decoder *decoder, struct aws_http_decoder_params *params) {
    struct aws_allocator *alloc;
    struct aws_byte_buf buffer;
    bool true_for_request_false_for_response;
    void *user_data;

    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;
    aws_http_decoder_on_version_fn *on_version;
    aws_http_decoder_on_uri_fn *on_uri;
    aws_http_decoder_on_method_fn *on_method;
    aws_http_decoder_on_response_code_fn *on_code;

    if (params) {
        alloc = params->alloc;
        buffer = params->scratch_space;
        buffer.allocator = params->alloc;
        true_for_request_false_for_response = params->true_for_request_false_for_response;
        user_data = params->user_data;

        on_header = params->on_header;
        on_body = params->on_body;
        on_version = params->on_version;
        on_uri = params->on_uri;
        on_method = params->on_method;
        on_code = params->on_code;
    } else {
        alloc = decoder->alloc;
        buffer = decoder->scratch_space;
        true_for_request_false_for_response = decoder->true_for_request_false_for_response;
        user_data = decoder->user_data;

        on_header = decoder->on_header;
        on_body = decoder->on_body;
        on_version = decoder->on_version;
        on_uri = decoder->on_uri;
        on_method = decoder->on_method;
        on_code = decoder->on_code;
    }

    AWS_ZERO_STRUCT(*decoder);

    decoder->alloc = alloc;
    decoder->scratch_space = buffer;
    decoder->user_data = user_data;
    decoder->true_for_request_false_for_response = true_for_request_false_for_response;

    decoder->on_header = on_header;
    decoder->on_body = on_body;
    decoder->on_version = on_version;
    decoder->on_uri = on_uri;
    decoder->on_method = on_method;
    decoder->on_code = on_code;

    if (true_for_request_false_for_response) {
        decoder->state_cb = s_state_getline;
        decoder->next_state_cb = s_state_method;
    } else {
        decoder->state_cb = s_state_getline;
        decoder->next_state_cb = s_state_response;
    }
}

struct aws_http_decoder *aws_http_decoder_new(struct aws_http_decoder_params *params) {
    if (!params) {
        return NULL;
    }

    struct aws_http_decoder *decoder =
        (struct aws_http_decoder *)aws_mem_acquire(params->alloc, sizeof(struct aws_http_decoder));

    if (!decoder) {
        return NULL;
    }

    aws_http_decoder_reset(decoder, params);

    return decoder;
}

void aws_http_decoder_destroy(struct aws_http_decoder *decoder) {
    if (decoder->cleanup_scratch) {
        aws_byte_buf_clean_up(&decoder->scratch_space);
    }
    aws_mem_release(decoder->alloc, decoder);
}

int aws_http_decode(struct aws_http_decoder *decoder, const void *data, size_t data_bytes, size_t *bytes_read) {
    assert(decoder);
    assert(data);

    struct aws_byte_cursor input = aws_byte_cursor_from_array(data, data_bytes);
    size_t total_bytes_processed = 0;

    int ret = AWS_OP_SUCCESS;
    while (ret == AWS_OP_SUCCESS && data_bytes) {
        if (!decoder->state_cb) {
            /* Attempted to call decoder on an invalid decoder state. */
            ret = aws_raise_error(AWS_ERROR_HTTP_INVALID_PARSE_STATE);
            break;
        }

        size_t bytes_processed = 0;
        ret = decoder->state_cb(decoder, input, &bytes_processed);
        data_bytes -= bytes_processed;
        total_bytes_processed += bytes_processed;
        aws_byte_cursor_advance(&input, bytes_processed);
    }

    if (bytes_read) {
        *bytes_read = total_bytes_processed;
    }

    return ret;
}

AWS_HTTP_API int aws_http_decoder_get_encoding_flags(struct aws_http_decoder *decoder, int *flags) {
    *flags = decoder->transfer_encoding;
    return AWS_OP_SUCCESS;
}
