#ifndef AWS_HTTP_H1_DECODER_H
#define AWS_HTTP_H1_DECODER_H

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
#include <aws/http/private/request_response_impl.h>

/**
 * Structure used to initialize an `aws_h1_decoder`.
 */
struct aws_h1_decoder_params {
    struct aws_allocator *alloc;
    size_t scratch_space_initial_size;
    /* Set false if decoding responses */
    bool is_decoding_requests;
    void *user_data;
    struct aws_http_decoder_vtable vtable;
};

struct aws_h1_decoder;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API struct aws_h1_decoder *aws_h1_decoder_new(struct aws_h1_decoder_params *params);
AWS_HTTP_API void aws_h1_decoder_destroy(struct aws_h1_decoder *decoder);
AWS_HTTP_API int aws_h1_decode(struct aws_h1_decoder *decoder, struct aws_byte_cursor *data);

AWS_HTTP_API void aws_h1_decoder_set_logging_id(struct aws_h1_decoder *decoder, void *id);
AWS_HTTP_API void aws_h1_decoder_set_body_headers_ignored(struct aws_h1_decoder *decoder, bool body_headers_ignored);

/* RFC-7230 section 4.2 Message Format */
#define AWS_HTTP_TRANSFER_ENCODING_CHUNKED (1 << 0)
#define AWS_HTTP_TRANSFER_ENCODING_GZIP (1 << 1)
#define AWS_HTTP_TRANSFER_ENCODING_DEFLATE (1 << 2)
#define AWS_HTTP_TRANSFER_ENCODING_DEPRECATED_COMPRESS (1 << 3)
AWS_HTTP_API int aws_h1_decoder_get_encoding_flags(const struct aws_h1_decoder *decoder);

AWS_HTTP_API uint64_t aws_h1_decoder_get_content_length(const struct aws_h1_decoder *decoder);
AWS_HTTP_API bool aws_h1_decoder_get_body_headers_ignored(const struct aws_h1_decoder *decoder);
AWS_HTTP_API enum aws_http_header_block aws_h1_decoder_get_header_block(const struct aws_h1_decoder *decoder);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H1_DECODER_H */
