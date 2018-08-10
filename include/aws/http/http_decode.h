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

#ifndef AWS_HTTP_DECODE_H
#define AWS_HTTP_DECODE_H

#include <aws/http/http.h>

#include <aws/common/byte_buf.h>

struct aws_http_header {
    /* Name of the header. If the type is `AWS_HTTP_HEADER_NAME_UNKNOWN` then `name_data` must be parsed manually. */
    enum aws_http_header_name name;

    /* Raw buffer storing the header's name. */
    struct aws_byte_cursor name_data;

    /* Raw buffer storing the header's value. */
    struct aws_byte_cursor value_data;

    /* Raw buffer storing the entire header. */
    struct aws_byte_cursor data;
};

struct aws_http_decoder;

/**
 * Called from `aws_http_decode` when an http response code has been recieved.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 * Return true to keep decoding, false to signal an error and immediately return from `aws_http_decode`.
 */
typedef bool (aws_http_decoder_on_code_fn)(struct aws_byte_cursor data, enum aws_http_code code, void *user_data);

/**
 * Called from `aws_http_decode` when an http header has been recieved.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 * Return true to keep decoding, false to immediately return from `aws_http_decode`.
 */
typedef bool (aws_http_decoder_on_header_fn)(struct aws_http_header *header, void *user_data);

/**
 * Called from `aws_http_decode` when a portion of the http body has been recieved.
 * `finished` is true if this is the last section of the http body, and false if more body data is yet to be recieved.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 * Return true to keep decoding, false to return from `aws_http_decode`.
 */
typedef bool (aws_http_decoder_on_body_fn)(struct aws_byte_cursor *data, bool finished, void *user_data);

/**
 * Called from `aws_http_decode` when an http version has been recieved.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 * Return true to keep decoding, false to immediately return from `aws_http_decode`.
 */
typedef bool (aws_http_decoder_on_version_fn)(enum aws_http_version version, void *user_data);

/**
 * Called from `aws_http_decode` when an http uri has been recieved.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 * Return true to keep decoding, false to immediately return from `aws_http_decode`.
 */
typedef bool (aws_http_decoder_on_uri_fn)(struct aws_byte_cursor *uri_data, void *user_data);

/**
 * Structure used to initialize an `aws_http_decoder`. Each function pointer can be NULL to opt-out of recieving
 * callbacks for particular events.
 */
struct aws_http_decoder_params {
    struct aws_allocator *alloc;
    aws_http_decoder_on_code_fn *on_code;
    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;
    aws_http_decoder_on_version_fn *on_version;
    aws_http_decoder_on_uri_fn *on_uri;
    void *user_data;
};

/*
 * Streaming decoder for parsing HTTP 1.1 messages from a segmented input stream (a series of buffers).
 */
struct AWS_CACHE_ALIGN aws_http_decoder {
    /* Implementation data. */
    struct aws_allocator *alloc;
    void *state_cb;

    /* User callbacks. */
    aws_http_decoder_on_code_fn *on_code;
    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;
    aws_http_decoder_on_version_fn *on_version;
    aws_http_decoder_on_uri_fn *on_uri;
    void *user_data;
};

#ifdef __cplusplus
extern "C" {
#endif

AWS_HTTP_API int aws_http_decode_init(struct aws_http_decoder* decoder, struct aws_http_decoder_params *params);
AWS_HTTP_API void aws_http_decode_clean_up(struct aws_http_decoder* decoder);
AWS_HTTP_API int aws_http_decode(struct aws_http_decoder *decoder, const void *data, size_t data_bytes);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_DECODE_H */
