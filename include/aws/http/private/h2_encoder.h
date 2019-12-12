#ifndef AWS_HTTP_H2_ENCODER_H
#define AWS_HTTP_H2_ENCODER_H

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

#include <aws/http/private/h2_frames.h>
#include <aws/http/private/http_impl.h>

struct aws_h2_encoder;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API struct aws_h2_encoder *aws_h2_encoder_new(struct aws_allocator *alloc);
AWS_HTTP_API void aws_h2_encoder_destroy(struct aws_h2_encoder *encoder);

AWS_HTTP_API int aws_h2_encode(
    struct aws_h2_encoder *encoder,
    struct aws_h2_frame_header *frame,
    struct aws_byte_buf *output);

AWS_HTTP_API void aws_h2_encoder_set_logging_id(struct aws_h2_encoder *encoder, void *id);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H2_ENCODER_H */
