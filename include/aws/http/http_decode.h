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

/**
 * Called from `aws_http_decode` when an http header has been received.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 * Return true to keep decoding, false to immediately return from `aws_http_decode`.
 */
typedef bool(aws_http_decoder_on_header_fn)(struct aws_http_header header, void *user_data);

/**
 * Called from `aws_http_decode` when a portion of the http body has been received.
 * `finished` is true if this is the last section of the http body, and false if more body data is yet to be received.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 * Return true to keep decoding, false to return from `aws_http_decode`.
 */
typedef bool(aws_http_decoder_on_body_fn)(struct aws_byte_cursor data, bool finished, void *user_data);

/**
 * Structure used to initialize an `aws_http_decoder`.
 */
struct aws_http_decoder_params {
    struct aws_allocator *alloc;

    /*
     * The `scratch_space` buffer will be used by the decoder until the decoder needs a larger buffer. At this point
     * the decoder will allocate a new `aws_byte_buf` and free it when finished. The decoder will never clean up the
     * the `scratch_space` buffer, as it is completely owned by the provider. The allocator inside of `scratch_space`
     * is always ignored.
     */
    struct aws_byte_buf scratch_space;
    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;
    bool true_for_request_false_for_response;
    void *user_data;
};

struct aws_http_decoder;

#ifdef __cplusplus
extern "C" {
#endif

AWS_HTTP_API struct aws_http_decoder *aws_http_decoder_new(struct aws_http_decoder_params *params);
AWS_HTTP_API void aws_http_decoder_destroy(struct aws_http_decoder *decoder);
AWS_HTTP_API int aws_http_decode(struct aws_http_decoder *decoder, const void *data, size_t data_bytes);

/**
 * These functions can only be called once the decoder has called `on_header` at least once. It would be
 * simplest to call these functions once decoding is completely finished, just before calling `aws_http_decode_destroy`.
 */
AWS_HTTP_API int aws_http_decoder_get_version(struct aws_http_decoder *decoder, enum aws_http_version *version);
AWS_HTTP_API int aws_http_decoder_get_uri(struct aws_http_decoder *decoder, struct aws_byte_cursor *uri_data);
AWS_HTTP_API int aws_http_decoder_get_code(struct aws_http_decoder *decoder, enum aws_http_code *code);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_DECODE_H */
