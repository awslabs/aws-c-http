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

#include <aws/http/private/h2_decoder.h>

#include <aws/common/string.h>
#include <aws/io/logging.h>

struct aws_h2_decoder {
    /* Implementation data. */
    struct aws_allocator *alloc;
    void *logging_id;

    /* User callbacks and settings. */
    struct aws_http_decoder_vtable vtable;
    void *user_data;
};

struct aws_h2_decoder *aws_h2_decoder_new(struct aws_h2_decoder_params *params) {
    AWS_ASSERT(params);

    struct aws_h2_decoder *decoder = aws_mem_calloc(params->alloc, 1, sizeof(struct aws_h2_decoder));
    if (!decoder) {
        return NULL;
    }

    decoder->alloc = params->alloc;
    decoder->user_data = params->user_data;
    decoder->vtable = params->vtable;

    return decoder;
}

void aws_h2_decoder_destroy(struct aws_h2_decoder *decoder) {
    aws_mem_release(decoder->alloc, decoder);
}

int aws_h2_decode(struct aws_h2_decoder *decoder, struct aws_byte_cursor *data) {
    AWS_ASSERT(decoder);
    AWS_ASSERT(data);

    return AWS_OP_ERR;
}

void aws_h2_decoder_set_logging_id(struct aws_h2_decoder *decoder, void *id) {
    decoder->logging_id = id;
}
