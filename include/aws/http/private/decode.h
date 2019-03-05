#ifndef AWS_HTTP_DECODE_H
#define AWS_HTTP_DECODE_H

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

#include <aws/http/http.h>

struct aws_http_decoded_header {
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
 * Return true to keep decoding, or false to immediately stop decoding and place the decoder in an invalid state, where
 * the only valid operation is to destroy the decoder with `aws_http_decoder_destroy`.
 */
typedef bool(aws_http_decoder_on_header_fn)(const struct aws_http_decoded_header *header, void *user_data);

/**
 * Called from `aws_http_decode` when a portion of the http body has been received.
 * `finished` is true if this is the last section of the http body, and false if more body data is yet to be received.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 * Return true to keep decoding, or false to immediately stop decoding and place the decoder in an invalid state, where
 * the only valid operation is to destroy or reset the decoder with `aws_http_decoder_destroy` or
 * `aws_http_decoder_reset`.
 */
typedef bool(aws_http_decoder_on_body_fn)(const struct aws_byte_cursor *data, bool finished, void *user_data);

typedef void(aws_http_decoder_on_version_fn)(enum aws_http_version version, void *user_data);
typedef void(aws_http_decoder_on_uri_fn)(struct aws_byte_cursor *uri, void *user_data);
typedef void(aws_http_decoder_on_response_code_fn)(enum aws_http_code code, void *user_data);
typedef void(aws_http_decoder_on_method_fn)(enum aws_http_method method, void *user_data);
typedef void(aws_http_decoder_done_fn)(void *user_data);

struct aws_http_decoder_vtable {
    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;
    aws_http_decoder_on_version_fn *on_version;

    /* Only needed for requests, can be NULL for responses. */
    aws_http_decoder_on_uri_fn *on_uri;
    aws_http_decoder_on_method_fn *on_method;

    /* Only needed for responses, can be NULL for requests. */
    aws_http_decoder_on_response_code_fn *on_code;

    aws_http_decoder_done_fn *on_done;
};

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
    bool true_for_request_false_for_response;
    void *user_data;
    struct aws_http_decoder_vtable vtable;
};

struct aws_http_decoder;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API struct aws_http_decoder *aws_http_decoder_new(struct aws_http_decoder_params *params);

/**
 * Places the decoder in a usable state, assuming the `params` are properly setup, or a previous call to
 * `aws_http_decoder` was made with a proper `params` setup. `params` can be NULL in order to re-use a previous valid
 * set of `params` values.
 */
AWS_HTTP_API void aws_http_decoder_reset(struct aws_http_decoder *decoder, struct aws_http_decoder_params *params);
AWS_HTTP_API void aws_http_decoder_destroy(struct aws_http_decoder *decoder);
AWS_HTTP_API int aws_http_decode(
    struct aws_http_decoder *decoder,
    const void *data,
    size_t data_bytes,
    size_t *bytes_read);
AWS_HTTP_API void aws_http_decoder_set_vtable(
    struct aws_http_decoder *decoder,
    const struct aws_http_decoder_vtable *vtable);

/* RFC-7230 section 4.2 Message Format */
#define AWS_HTTP_TRANSFER_ENCODING_CHUNKED (1 << 0)
#define AWS_HTTP_TRANSFER_ENCODING_GZIP (1 << 1)
#define AWS_HTTP_TRANSFER_ENCODING_DEFLATE (1 << 2)
#define AWS_HTTP_TRANSFER_ENCODING_DEPRECATED_COMPRESS (1 << 3)
AWS_HTTP_API int aws_http_decoder_get_encoding_flags(const struct aws_http_decoder *decoder);

AWS_HTTP_API size_t aws_http_decoder_get_content_length(const struct aws_http_decoder *decoder);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_DECODE_H */
