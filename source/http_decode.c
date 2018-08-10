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

/* Works like memcmp or strcmp, except is case-agonstic. */
static inline int s_aws_byte_cursorcmp_case_insensitive(const char *a, const char *b, size_t key_len) {
    for (size_t i = 0; i < key_len; ++i) {
        int d = toupper(a[i]) - toupper(b[i]);
        if (d) {
            return d;
        }
    }
    return 0;
}

static bool s_aws_http_eol(char c) {
    switch (c) {
    case '\n': return true;
    case '\r': return true;
    }
    return false;
}

#if 0
static inline int s_aws_http_skip_space(struct aws_byte_cursor *input) {
    const char *scan = input->begin;
    do
    {
        if (!(scan < input->end)) {
            return AWS_OP_ERR;
        }
    } while (*scan++ == ' ');
    input->begin = scan - 1;
    return AWS_OP_SUCCESS;
}

static inline void s_aws_http_trim_trailing_space(struct aws_byte_cursor *str) {
    assert(str->end >= str->begin);
    const char *end = str->end - 1;
    while (end > str->begin && *end == ' ') {
        end--;
    }
    str->end = end + 1;
}

static int s_aws_http_scan(struct aws_byte_cursor *input, struct aws_byte_cursor *out, char search) {
    const char *scan = input->begin;
    if (!scan) {
        return AWS_OP_ERR;
    }
    char c;
    do {
        c = *scan;
        if (!(scan < input->end) | s_aws_http_eol(c)) {
            return AWS_OP_ERR;
        }
        ++scan;
    } while (c != search);
    out->begin = input->begin;
    out->end = scan - 1;
    input->begin = scan;
    s_aws_http_trim_trailing_space(out);
    return AWS_OP_SUCCESS;
}

static int s_aws_http_scan_for_eol_or_eos(struct aws_byte_cursor *input, struct aws_byte_cursor *out) {
    const char *scan = input->begin;
    if (!scan) {
        return AWS_OP_ERR;
    }
    char c;
    do {
        c = *scan;
        if (!(scan < input->end)) {
            out->begin = input->begin;
            out->end = input->begin = scan;
            return AWS_OP_SUCCESS;
        }
        ++scan;
    } while (!s_aws_http_eol(c));
    if (c == '\r') {
        if (scan < input->end + 1 && *scan++ != '\n') {
            return AWS_OP_ERR;
        }
    }
    out->begin = input->begin;
    out->end = scan - 2;
    input->begin = scan;
    s_aws_http_trim_trailing_space(out);
    return AWS_OP_SUCCESS;
}

static bool s_aws_http_expect_eol(struct aws_byte_cursor *input) {
    if (input->begin < input->end && !s_aws_http_eol(*input->begin++)) return false;
    if (input->begin < input->end && !s_aws_http_eol(*input->begin++)) return false;
    return true;
}

static inline bool s_aws_http_is_end_of_headers(struct aws_byte_cursor *input) {
    if (input->begin < input->end - 1) {
        if (input->begin[0] == '\r' && input->begin[1] == '\n') {
            return true;
        } else {
            return false;
        }
    } else {
        return true;
    }
}

static inline int s_aws_http_read_int(struct aws_byte_cursor str, int* val) {
    char *end;
    *val = strtol(str.begin, &end, 10);
    if (str.begin != end) {
        return AWS_OP_SUCCESS;
    } else {
        return AWS_OP_ERR;
    }
}

static inline int s_aws_http_get_status_code_class(char c, enum aws_http_response_status_code_class *code_class) {
    switch (c) {
    case '1': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_INFORMATIONAL; return AWS_OP_SUCCESS;
    case '2': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_SUCCESSFUL;    return AWS_OP_SUCCESS;
    case '3': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_REDIRECTION;   return AWS_OP_SUCCESS;
    case '4': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_CLIENT_ERROR;  return AWS_OP_SUCCESS;
    case '5': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_SERVER_ERROR;  return AWS_OP_SUCCESS;
    default: return AWS_OP_ERR;
    }
}

#define AWS_HTTP_CHECK_OP(X) do { if ((X) != AWS_OP_SUCCESS) { goto aws_error; } } while (0)
#define AWS_HTTP_ASSERT(X) do { if (!(X)) { goto aws_error; } } while (0)

static int s_aws_http_read_headers_and_optional_body(struct aws_http_message_data *data, struct aws_byte_cursor *input, struct aws_array_list *headers, int *cache, bool one_request_zero_response) {
    struct aws_byte_cursor str;
    size_t cache_max_index = one_request_zero_response ? AWS_HTTP_RESPONSE_LAST : AWS_HTTP_REQUEST_LAST;
    int content_length_key = one_request_zero_response ? AWS_HTTP_REQUEST_CONTENT_LENGTH : AWS_HTTP_RESPONSE_CONTENT_LENGTH;

    /* Scan for headers. */
    int content_length = 0;
    while (!s_aws_http_is_end_of_headers(input)) {
        /* Read in header key. */
        struct aws_http_header header_field;
        AWS_HTTP_CHECK_OP(s_aws_http_scan(input, &str, ':'));
        header_field.key_str = str;
        header_field.key = one_request_zero_response ? s_aws_byte_cursor_to_request_key(str) : s_aws_byte_cursor_to_response_key(str);

        if (header_field.key) {
            size_t index = (size_t)header_field.key - 1;
            if (index > cache_max_index) {
                return AWS_OP_ERR;
            }
            cache[index] = (int)aws_array_list_length(headers) + 1;
        }

        bool has_content = false;
        if (header_field.key == content_length_key) {
            has_content = true;
        }

        /* Read in header value string. */
        AWS_HTTP_CHECK_OP(s_aws_http_skip_space(input));
        AWS_HTTP_CHECK_OP(s_aws_http_scan_for_eol_or_eos(input, &str));
        header_field.value_str = str;

        if (has_content) {
            AWS_HTTP_CHECK_OP(s_aws_http_read_int(header_field.value_str, &content_length));
        }

        /* Record header key-value pair. */
        aws_array_list_push_back(headers, &header_field);
    }

    data->headers = (struct aws_http_header *)headers->data;
    data->header_count = (int)headers->length;

    if (content_length) {
        AWS_HTTP_CHECK_OP(s_aws_http_expect_eol(input));

        /* Read in content here. TODO: Handle chunked encoding? */

        data->body.begin = input->begin;
        data->body.end = input->begin + content_length;
    } else {
        data->body.begin = NULL;
        data->body.end = NULL;
    }

    return AWS_OP_SUCCESS;

aws_error:
    return AWS_OP_ERR;
}

#define AWS_HTTP_HEADER_CACHE_INVALID (~0)

static inline void s_aws_http_init_header_cache(int *cache, int count) {
    for (int i = 0; i < count; ++i ) {
        cache[i] = AWS_HTTP_HEADER_CACHE_INVALID;
    }
}

int aws_http_request_init(struct aws_http_request *request, struct aws_allocator *alloc, const void *buffer, size_t buffer_size) {
    struct aws_byte_cursor input;
    struct aws_byte_cursor str;
    struct aws_array_list headers;
    aws_array_list_init_dynamic(&headers, alloc, 16, sizeof(struct aws_http_header));
    AWS_ZERO_STRUCT(*request);
    s_aws_http_init_header_cache(request->header_cache, (int)AWS_HTTP_REQUEST_LAST);
    request->data.alloc = alloc;

    input.begin = (const char *)buffer;
    input.end = input.begin + buffer_size;

    /* Method. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan(&input, &str, ' '));
    request->method = s_aws_byte_cursor_to_method(str);
    AWS_HTTP_ASSERT(request->method != AWS_HTTP_METHOD_UNKNOWN);

    /* Target URI. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan(&input, &str, ' '));
    request->target = str;

    /* HTTP version. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan_for_eol_or_eos(&input, &str));
    request->version = s_aws_byte_cursor_to_version(str);
    AWS_HTTP_ASSERT(request->version != AWS_HTTP_VERSION_UNKNOWN);

    /* Read in headers and optional body data. */
    s_aws_http_read_headers_and_optional_body(&request->data, &input, &headers, request->header_cache, 1);

    return AWS_OP_SUCCESS;

aws_error:
    aws_array_list_clean_up(&headers);
    AWS_ZERO_STRUCT(*request);
    aws_raise_error(AWS_HTTP_ERROR_PARSE);
    return AWS_OP_ERR;
}

void aws_http_request_clean_up(struct aws_http_request *request) {
    assert(request);
    if (request->data.alloc) {
        aws_mem_release(request->data.alloc, request->data.headers);
    }
    AWS_ZERO_STRUCT(*request);
}

int aws_http_request_get_header_by_enum(const struct aws_http_request *request, struct aws_http_header *header, enum aws_http_request_key key) {
    size_t index = (size_t)key - 1;
    if (index > AWS_HTTP_REQUEST_LAST - 1) {
        return AWS_OP_ERR;
    }

    int at = request->header_cache[index];
    if (at != AWS_HTTP_HEADER_CACHE_INVALID) {
        assert(at >= 0 && at < request->data.header_count);
        *header = request->data.headers[at];
        return AWS_OP_SUCCESS;
    }
    return AWS_OP_ERR;
}

static inline int s_aws_http_get_header_by_str(const struct aws_http_message_data *data, struct aws_http_header *header, const char *key, size_t key_len) {
    for (int i = 0; i < data->header_count; ++i) {
        struct aws_byte_cursor str = data->headers[i].key_str;
        size_t len = str.end - str.begin;
        if (len != key_len) {
            continue;
        }
        if (!s_aws_byte_cursorcmp_case_insensitive(str.begin, key, len)) {
            *header = data->headers[i];
            return AWS_OP_SUCCESS;
        }
    }
    return AWS_OP_ERR;
}

int aws_http_request_get_header_by_str(const struct aws_http_request *request, struct aws_http_header *header, const char *key, size_t key_len) {
    return s_aws_http_get_header_by_str(&request->data, header, key, (int)key_len);
}

int aws_http_response_init(struct aws_http_response *response, struct aws_allocator *alloc, const void *buffer, size_t buffer_size) {
    struct aws_byte_cursor input;
    struct aws_byte_cursor str;
    struct aws_array_list headers;
    aws_array_list_init_dynamic(&headers, alloc, 16, sizeof(struct aws_http_header));
    AWS_ZERO_STRUCT(*response);
    s_aws_http_init_header_cache(response->header_cache, (int)AWS_HTTP_RESPONSE_LAST);
    response->data.alloc = alloc;

    input.begin = (const char *)buffer;
    input.end = input.begin + buffer_size;

    /* HTTP version. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan(&input, &str, ' '));
    response->version = s_aws_byte_cursor_to_version(str);
    AWS_HTTP_ASSERT(response->version != AWS_HTTP_VERSION_UNKNOWN);

    /* Integral status code. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan(&input, &str, ' '));
    int status_code;
    AWS_HTTP_CHECK_OP(s_aws_http_read_int(str, &status_code));
    AWS_HTTP_CHECK_OP(s_aws_http_get_status_code_class(str.begin[0], &response->status_code_class));
    response->status_code = status_code;
    response->status_code_reason_phrase = str;

    /* Reason phrase associated with the status code. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan_for_eol_or_eos(&input, &str));

    /* Read in headers and optional body data. */
    s_aws_http_read_headers_and_optional_body(&response->data, &input, &headers, response->header_cache, 0);

    return AWS_OP_SUCCESS;

aws_error:
    aws_array_list_clean_up(&headers);
    AWS_ZERO_STRUCT(*response);
    aws_raise_error(AWS_HTTP_ERROR_PARSE);
    return AWS_OP_ERR;
}

void aws_http_response_clean_up(struct aws_http_response *response) {
    assert(response);
    if (response->data.alloc) {
        aws_mem_release(response->data.alloc, response->data.headers);
    }
    AWS_ZERO_STRUCT(*response);
}

int aws_http_response_get_header_by_enum(const struct aws_http_response *response, struct aws_http_header *header, enum aws_http_request_key key) {
    size_t index = (size_t)key - 1;
    if (index > AWS_HTTP_RESPONSE_LAST - 1) {
        return AWS_OP_ERR;
    }

    int at = response->header_cache[index];
    if (at != AWS_HTTP_HEADER_CACHE_INVALID) {
        assert(at >= 0 && at < response->data.header_count);
        *header = response->data.headers[at];
        return AWS_OP_SUCCESS;
    }
    return AWS_OP_ERR;
}

int aws_http_response_get_header_by_str(const struct aws_http_response *response, struct aws_http_header *header, const char *key, size_t key_len) {
    return s_aws_http_get_header_by_str(&response->data, header, key, (int)key_len);
}
#endif

typedef int (s_aws_http_decoder_state_fn)(struct aws_http_decoder *decoder, const uint8_t *data, size_t data_bytes, size_t *bytes_processed);

int aws_http_decode_init(struct aws_http_decoder* decoder, struct aws_http_decoder_params *params) {
}

void aws_http_decode_clean_up(struct aws_http_decoder* decoder) {
}

int aws_http_decode(struct aws_http_decoder *decoder, const void *data, size_t data_bytes) {
}
