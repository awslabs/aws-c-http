#ifndef AWS_HTTP_H2_STREAM_H
#define AWS_HTTP_H2_STREAM_H

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

enum aws_h2_stream_state {
    AWS_H2_STREAM_STATE_IDLE,
    AWS_H2_STREAM_STATE_RESERVED_LOCAL,
    AWS_H2_STREAM_STATE_RESERVED_REMOTE,
    AWS_H2_STREAM_STATE_OPEN,
    AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL,
    AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE,
    AWS_H2_STREAM_STATE_CLOSED,

    AWS_H2_STREAM_STATE_COUNT,
};

struct aws_h2_stream;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
struct aws_h2_stream *aws_h2_stream_new(struct aws_allocator *allocator, uint32_t stream_id);
AWS_HTTP_API
void aws_h2_stream_destroy(struct aws_h2_stream *stream);

AWS_HTTP_API
int aws_h2_stream_handle_frame(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H2_STREAM_H */
