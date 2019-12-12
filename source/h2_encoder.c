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
#include <aws/common/allocator.h>
#include <aws/common/error.h>
#include <aws/common/linked_list.h>
#include <aws/common/macros.h>
#include <aws/http/private/h2_encoder.h>

#include <aws/http/private/h2_frames.h>
#include <aws/http/private/hpack.h>

#define ENCODER_LOGF(level, decoder, text, ...)                                                                        \
    AWS_LOGF_##level(AWS_LS_HTTP_ENCODER, "id=%p " text, (decoder)->logging_id, __VA_ARGS__)
#define ENCODER_LOG(level, decoder, text) ENCODER_LOGF(level, decoder, "%s", text)

struct aws_h2_encoder {
    /* Implementation data. */
    struct aws_allocator *alloc;
    void *logging_id;
    struct aws_hpack_context *hpack;

    /* #TODO: Merge the frame encoder into this class */
    struct aws_h2_frame_encoder frame_encoder;
};

struct aws_h2_encoder *aws_h2_encoder_new(struct aws_allocator *alloc) {
    AWS_PRECONDITION(alloc);

    struct aws_h2_encoder *encoder = aws_mem_calloc(alloc, 1, sizeof(struct aws_h2_encoder));
    if (!encoder) {
        goto failed_alloc;
    }

    AWS_ZERO_STRUCT(*encoder);
    encoder->alloc = alloc;

    if (aws_h2_frame_encoder_init(&encoder->frame_encoder, alloc)) {
        goto failed_init_frame_encoder;
    }

    encoder->hpack = aws_hpack_context_new(alloc);
    if (!encoder->hpack) {
        goto failed_new_hpack;
    }

    return encoder;

failed_new_hpack:
    aws_h2_frame_encoder_clean_up(&encoder->frame_encoder);
failed_init_frame_encoder:
    aws_mem_release(alloc, encoder);
failed_alloc:
    return NULL;
}

void aws_h2_encoder_destroy(struct aws_h2_encoder *encoder) {

    aws_h2_frame_encoder_clean_up(&encoder->frame_encoder);
    aws_hpack_context_destroy(encoder->hpack);
    aws_mem_release(encoder->alloc, encoder);
}

void aws_h2_encoder_set_logging_id(struct aws_h2_encoder *encoder, void *id) {
    encoder->logging_id = id;
}

int aws_h2_encode(struct aws_h2_encoder *encoder, struct aws_h2_frame_header *frame, struct aws_byte_buf *output) {

    /* Try to encode the frame */
    int err = AWS_ERROR_SUCCESS;
    if (aws_h2_frame_encode(frame, &encoder->frame_encoder, output)) {
        err = aws_last_error();

        /* If the error was short buffer, it means we filled output, and should try again next iteration */
        if (err == AWS_ERROR_SHORT_BUFFER) {
            return AWS_OP_SUCCESS;
        }
    }

    return AWS_OP_SUCCESS;
}
