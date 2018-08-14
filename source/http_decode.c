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

#include <assert.h>

struct aws_http_decoder;

/* For internal use. */
typedef int (s_aws_http_decoder_state_fn)(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed);

/*
 * Streaming decoder for parsing messages from a segmented input stream (a series of buffers).
 */
struct aws_http_decoder {
    /* Implementation data. */
    struct aws_allocator *alloc;
    struct aws_byte_buf scratch_space;
    s_aws_http_decoder_state_fn *state_cb;
    s_aws_http_decoder_state_fn *next_state_cb;
    struct aws_byte_cursor cursor;
    bool found_carriage;

    /* Common HTTP header data. */
    enum aws_http_method method;
    enum aws_http_version version;
    struct aws_byte_buf uri_data;
    enum aws_http_code code;

    /* User callbacks and settings. */
    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;
    bool true_for_request_false_for_response;
    void *user_data;
};

static bool s_aws_http_scan_for_newline(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    size_t index = 0;
    bool done = false;
    while (input.len - index) {
        if (!decoder->found_carriage) {
            if (input.ptr[index] == (uint8_t)'\r') {
                decoder->found_carriage = true;
            }
        } else {
            if (input.ptr[index] == (uint8_t)'\n') {
                decoder->found_carriage = false;
                done = true;
            }
        }
        ++index;
    }
    *bytes_processed = index;
    return done;
}

static int s_aws_http_cat(struct aws_byte_buf* buffer, uint8_t *data, size_t len) {
    struct aws_byte_cursor to_append = aws_byte_cursor_from_array(data, len);
    if (AWS_LIKELY(aws_byte_buf_append(buffer, &to_append) == AWS_OP_SUCCESS)) {
        return AWS_OP_SUCCESS;
    } else {
        size_t new_size = buffer->capacity * 2;
        uint8_t* new_data = aws_mem_acquire(buffer->allocator, new_size);
        if (!new_data) {
            return AWS_OP_ERR;
        }

        memcpy(new_data, buffer->buffer, buffer->len);
        aws_mem_release(buffer->allocator, buffer);
        buffer->capacity = new_size;
        buffer->buffer = new_data;

        return aws_byte_buf_append(buffer, &to_append);
    }
}

static inline int s_aws_http_read_int(struct aws_byte_cursor str, int* val) {
    char *end;
    *val = strtol((const char *)str.ptr, &end, 10);
    if ((char *)str.ptr != end) {
        return AWS_OP_SUCCESS;
    } else {
        return AWS_OP_ERR;
    }
}

static int s_aws_http_decoder_state_get_header_line(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    int ret = AWS_OP_SUCCESS;
    bool done = s_aws_http_scan_for_newline(decoder, input, bytes_processed);

    bool needs_split = !done;
    bool was_split_before = decoder->scratch_space.len;
    bool needs_cat = needs_split | was_split_before;

    if (needs_cat) {
        ret = s_aws_http_cat(&decoder->scratch_space, input.ptr, *bytes_processed);
    }
    
    if (done) {
        if (needs_cat) {
            decoder->cursor = aws_byte_cursor_from_buf(&decoder->scratch_space);
        } else {
            decoder->cursor.ptr = input.ptr - *bytes_processed;
            decoder->cursor.len = *bytes_processed;
        }

        decoder->cursor.len -= 2; /* Backup so "\r\n" is not included. */
        decoder->state_cb = decoder->next_state_cb;
        decoder->next_state_cb = NULL;
    }

    return ret;
}

static inline int s_aws_http_byte_buf_split(struct aws_byte_cursor line, struct aws_byte_cursor *cursors, char split_on, int n) {
    struct aws_byte_buf line_buf = aws_byte_buf_from_array(line.ptr, line.len);
    struct aws_array_list string_list;
    aws_array_list_init_static(&string_list, cursors, n, sizeof(struct aws_byte_cursor));
    int ret = aws_byte_buf_split_on_char_n(&line_buf, split_on, &string_list, n);
    if (string_list.length != n) {
        return AWS_OP_ERR;
    }
    return ret;
}

static inline void s_http_set_next_state(struct aws_http_decoder *decoder, s_aws_http_decoder_state_fn *state, s_aws_http_decoder_state_fn *next) {
    decoder->scratch_space.len = 0;
    decoder->state_cb = state;
    decoder->next_state_cb = next;
}

static int s_aws_http_decoder_state_body(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    (void)decoder;
    (void)input;
    (void)bytes_processed;
    return AWS_OP_ERR;
}

static int s_aws_http_decoder_state_header(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    (void)decoder;
    (void)input;
    (void)bytes_processed;

    struct aws_byte_cursor cursors[2];
    if (s_aws_http_byte_buf_split(decoder->cursor, cursors, ':', 2) != AWS_OP_SUCCESS) {
        /* Empty line signifies end of headers, and beginning of body. */
        if (decoder->cursor.len == 0) {
            s_http_set_next_state(decoder, s_aws_http_decoder_state_body, NULL);
            return AWS_OP_SUCCESS;
        }
    }

    struct aws_byte_cursor header_name = cursors[0];
    struct aws_byte_cursor header_value = cursors[1];

    struct aws_http_header header;
    header.name = aws_http_str_to_header_name(header_name);
    header.name_data = header_name;
    header.value_data = header_value;
    header.data = decoder->cursor;

    if (!decoder->on_header(&header, decoder->user_data)) {
        return AWS_OP_ERR;
    }

    s_http_set_next_state(decoder, s_aws_http_decoder_state_get_header_line, s_aws_http_decoder_state_header);

    return AWS_OP_SUCCESS;
}

static int s_aws_http_decoder_state_method(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    (void)input;
    (void)bytes_processed;

    struct aws_byte_cursor cursors[3];
    s_aws_http_byte_buf_split(decoder->cursor, cursors, ' ', 3);
    struct aws_byte_cursor method = cursors[0];
    struct aws_byte_cursor uri = cursors[1];
    struct aws_byte_cursor version = cursors[2];

    decoder->method = aws_http_str_to_method(method);
    decoder->version = aws_http_str_to_version(version);
    struct aws_byte_buf uri_data = aws_byte_buf_from_array(uri.ptr, uri.len);
    if (aws_byte_buf_init_copy(decoder->alloc, &decoder->uri_data, &uri_data) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    s_http_set_next_state(decoder, s_aws_http_decoder_state_get_header_line, s_aws_http_decoder_state_header);

    return AWS_OP_SUCCESS;
}

static int s_aws_http_decoder_state_begin_response(struct aws_http_decoder *decoder, struct aws_byte_cursor input, size_t *bytes_processed) {
    (void)decoder;
    (void)input;
    (void)bytes_processed;
    return AWS_OP_ERR;
}

struct aws_http_decoder *aws_http_decode_init(struct aws_http_decoder_params *params) {
    struct aws_http_decoder *decoder = (struct aws_http_decoder *)aws_mem_acquire(params->alloc, sizeof(struct aws_http_decoder));
    decoder->alloc = params->alloc;
    decoder->scratch_space = params->scratch_space;
    if (params->true_for_request_false_for_response) {
        decoder->state_cb = s_aws_http_decoder_state_get_header_line;
        decoder->next_state_cb = s_aws_http_decoder_state_method;
    } else {
        decoder->state_cb = NULL;
        decoder->next_state_cb = NULL;
    }
    decoder->found_carriage = false;
    decoder->on_header = params->on_header;
    decoder->on_body = params->on_body;
    decoder->user_data = params->user_data;
    return decoder;
}

void aws_http_decode_clean_up(struct aws_http_decoder* decoder) {
    (void)decoder;
}

int aws_http_decode(struct aws_http_decoder *decoder, const void *data, size_t data_bytes) {
    assert(decoder);
    assert(data);

    int ret = AWS_OP_SUCCESS;
    while (ret == AWS_OP_SUCCESS && data_bytes) {
        size_t bytes_processed = 0;
        struct aws_byte_cursor input = aws_byte_cursor_from_array(data, data_bytes);
        ret = decoder->state_cb(decoder, input, &bytes_processed);
        data_bytes -= bytes_processed;
    }

    return ret;
}

int aws_http_decode_version_get(struct aws_http_decoder *decoder, enum aws_http_version *version) {
    (void)decoder;
    (void)version;
    return AWS_OP_ERR;
}

int aws_http_decode_uri_get(struct aws_http_decoder *decoder, struct aws_byte_cursor *uri_data) {
    (void)decoder;
    (void)uri_data;
    return AWS_OP_ERR;
}

int aws_http_decode_code_get(struct aws_http_decoder *decoder, enum aws_http_code *code, struct aws_byte_cursor *code_data) {
    (void)decoder;
    (void)code;
    (void)code_data;
    return AWS_OP_ERR;
}
