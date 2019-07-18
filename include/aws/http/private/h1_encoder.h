#ifndef AWS_HTTP_H1_ENCODER_H
#define AWS_HTTP_H1_ENCODER_H
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

enum aws_h1_encoder_state {
    AWS_H1_ENCODER_STATE_INIT,
    AWS_H1_ENCODER_STATE_HEAD,
    AWS_H1_ENCODER_STATE_BODY,
    AWS_H1_ENCODER_STATE_DONE,
};

struct aws_h1_encoder {
    struct aws_allocator *allocator;

    enum aws_h1_encoder_state state;
    struct aws_input_stream *body;
    bool is_stream_in_progress;
    void *logging_id;

    /* Upon message start, the "head" (everything preceding body) is buffered here. */
    struct aws_byte_buf outgoing_head_buf;
    size_t outgoing_head_progress;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
void aws_h1_encoder_init(struct aws_h1_encoder *encoder, struct aws_allocator *allocator);

AWS_HTTP_API
void aws_h1_encoder_clean_up(struct aws_h1_encoder *encoder);

AWS_HTTP_API
int aws_h1_encoder_start_request(
    struct aws_h1_encoder *encoder,
    const struct aws_http_request *request,
    void *log_as_stream);

AWS_HTTP_API
int aws_h1_encoder_process(struct aws_h1_encoder *encoder, struct aws_byte_buf *out_buf);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H1_ENCODER_H */
