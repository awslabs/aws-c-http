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
#include <aws/http/private/hpack.h>

#include <aws/testing/aws_test_harness.h>

AWS_EXTERN_C_BEGIN

AWS_TEST_ALLOCATOR_INIT(fuzz_h2_frames)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    struct aws_allocator *allocator = &fuzz_h2_frames_allocator;
    struct memory_test_allocator *alloc_impl = &fuzz_h2_frames_alloc_impl;
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(data, size);

    AWS_ZERO_STRUCT(*alloc_impl);
    aws_mutex_init(&alloc_impl->mutex);

    aws_hpack_static_table_init(allocator);

    struct aws_h2_frame_decoder decoder;
    if (aws_h2_frame_decoder_init(&decoder, allocator)) {
        goto cleanup;
    }
    if (aws_h2_frame_decoder_begin(&decoder, &to_decode)) {
        goto cleanup;
    }

    switch (decoder.header.type) {
        case AWS_H2_FRAME_T_DATA: {
            struct aws_h2_frame_data frame;
            aws_h2_frame_data_decode(&frame, &decoder);
            aws_h2_frame_data_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_HEADERS: {
            struct aws_h2_frame_headers frame;
            aws_h2_frame_headers_decode(&frame, &decoder);
            aws_h2_frame_headers_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_PRIORITY: {
            struct aws_h2_frame_priority frame;
            aws_h2_frame_priority_decode(&frame, &decoder);
            aws_h2_frame_priority_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_RST_STREAM: {
            struct aws_h2_frame_rst_stream frame;
            aws_h2_frame_rst_stream_decode(&frame, &decoder);
            aws_h2_frame_rst_stream_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_SETTINGS: {
            struct aws_h2_frame_settings frame;
            aws_h2_frame_settings_decode(&frame, &decoder);
            aws_h2_frame_settings_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_PUSH_PROMISE: {
            struct aws_h2_frame_push_promise frame;
            aws_h2_frame_push_promise_decode(&frame, &decoder);
            aws_h2_frame_push_promise_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_PING: {
            struct aws_h2_frame_ping frame;
            aws_h2_frame_ping_decode(&frame, &decoder);
            aws_h2_frame_ping_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_GOAWAY: {
            struct aws_h2_frame_goaway frame;
            aws_h2_frame_goaway_decode(&frame, &decoder);
            aws_h2_frame_goaway_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_WINDOW_UPDATE: {
            struct aws_h2_frame_window_update frame;
            aws_h2_frame_window_update_decode(&frame, &decoder);
            aws_h2_frame_window_update_clean_up(&frame);
            break;
        }
        case AWS_H2_FRAME_T_CONTINUATION: {
            struct aws_h2_frame_continuation frame;
            aws_h2_frame_continuation_decode(&frame, &decoder);
            aws_h2_frame_continuation_clean_up(&frame);
            break;
        }
    }

cleanup:
    aws_h2_frame_decoder_clean_up(&decoder);
    aws_hpack_static_table_clean_up();

    ASSERT_UINT_EQUALS(
        alloc_impl->allocated,
        alloc_impl->freed,
        "Memory Leak Detected %d bytes were allocated, "
        "but only %d were freed.",
        alloc_impl->allocated,
        alloc_impl->freed);

    return 0;
}

AWS_EXTERN_C_END
