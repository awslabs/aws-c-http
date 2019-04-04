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

#include <aws/http/private/http_impl.h>

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
 */
typedef int(aws_http_decoder_on_header_fn)(const struct aws_http_decoded_header *header, void *user_data);

/**
 * Called from `aws_http_decode` when a portion of the http body has been received.
 * `finished` is true if this is the last section of the http body, and false if more body data is yet to be received.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 */
typedef int(aws_http_decoder_on_body_fn)(const struct aws_byte_cursor *data, bool finished, void *user_data);

typedef int(aws_http_decoder_on_request_fn)(
    enum aws_http_method method_enum,
    const struct aws_byte_cursor *method_str,
    const struct aws_byte_cursor *uri,
    void *user_data);

typedef int(aws_http_decoder_on_response_fn)(int status_code, void *user_data);

typedef int(aws_http_decoder_done_fn)(void *user_data);

struct aws_http_decoder_vtable {
    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;

    /* Only needed for requests, can be NULL for responses. */
    aws_http_decoder_on_request_fn *on_request;

    /* Only needed for responses, can be NULL for requests. */
    aws_http_decoder_on_response_fn *on_response;

    aws_http_decoder_done_fn *on_done;
};

/**
 * Structure used to initialize an `aws_http_decoder`.
 */
struct aws_http_decoder_params {
    struct aws_allocator *alloc;
    size_t scratch_space_initial_size;
    /* Set false if decoding responses */
    bool is_decoding_requests;
    void *user_data;
    struct aws_http_decoder_vtable vtable;
};

struct aws_http_decoder;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API struct aws_http_decoder *aws_http_decoder_new(struct aws_http_decoder_params *params);
AWS_HTTP_API void aws_http_decoder_destroy(struct aws_http_decoder *decoder);
AWS_HTTP_API int aws_http_decode(
    struct aws_http_decoder *decoder,
    const void *data,
    size_t data_bytes,
    size_t *bytes_read);

AWS_HTTP_API void aws_http_decoder_set_logging_id(struct aws_http_decoder *decoder, void *id);

/* RFC-7230 section 4.2 Message Format */
#define AWS_HTTP_TRANSFER_ENCODING_CHUNKED (1 << 0)
#define AWS_HTTP_TRANSFER_ENCODING_GZIP (1 << 1)
#define AWS_HTTP_TRANSFER_ENCODING_DEFLATE (1 << 2)
#define AWS_HTTP_TRANSFER_ENCODING_DEPRECATED_COMPRESS (1 << 3)
AWS_HTTP_API int aws_http_decoder_get_encoding_flags(const struct aws_http_decoder *decoder);

AWS_HTTP_API size_t aws_http_decoder_get_content_length(const struct aws_http_decoder *decoder);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_DECODE_H */
