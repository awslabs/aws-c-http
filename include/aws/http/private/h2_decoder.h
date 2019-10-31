#ifndef AWS_HTTP_H2_DECODER_H
#define AWS_HTTP_H2_DECODER_H

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

/**
 * Structure used to initialize an `aws_h2_decoder`.
 */
struct aws_h2_decoder_params {
    struct aws_allocator *alloc;
    void *user_data;
    struct aws_http_decoder_vtable vtable;
};

struct aws_h2_decoder;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API struct aws_h2_decoder *aws_h2_decoder_new(struct aws_h2_decoder_params *params);
AWS_HTTP_API void aws_h2_decoder_destroy(struct aws_h2_decoder *decoder);
AWS_HTTP_API int aws_h2_decode(struct aws_h2_decoder *decoder, struct aws_byte_cursor *data);

AWS_HTTP_API void aws_h2_decoder_set_logging_id(struct aws_h2_decoder *decoder, void *id);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H2_DECODER_H */
