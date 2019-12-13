#ifndef AWS_HTTP_H2_CONNECTION_H
#define AWS_HTTP_H2_CONNECTION_H

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

#include <aws/common/atomics.h>
#include <aws/common/mutex.h>

#include <aws/http/private/connection_impl.h>
#include <aws/http/private/h2_frames.h>

struct aws_h2_connection {
    struct aws_http_connection base;

    /* Single task used for moving new streams to the outgoing_requests list */
    struct aws_channel_task new_stream_task;

    /* Single task used repeatedly for sending data from streams */
    struct aws_channel_task run_encoder_task;

    /* Only the event-loop thread may touch this data */
    struct {
        struct aws_h2_decoder *decoder;
        struct aws_h2_encoder *encoder;

        /* uint32_t -> aws_h2_stream * */
        struct aws_hash_table streams;

        /* Outgoing request queue */
        struct aws_linked_list outgoing_requests;
    } thread_data;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

        /* Refers to the next stream id to vend */
        uint32_t next_stream_id;

        /* New streams that have not been moved to streams yet */
        struct aws_linked_list pending_stream_list;

        /* queued_frame */
        struct aws_linked_list frame_queue;

        bool encode_task_in_progress;
    } synced_data;
};

typedef void aws_h2_frame_complete_fn(struct aws_h2_frame_header *frame, int error_code, void *userdata);

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http2_server(
    struct aws_allocator *allocator,
    size_t initial_window_size);

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http2_client(
    struct aws_allocator *allocator,
    size_t initial_window_size);

/* Helper callback that cleans up and destroys the frame (userdata must be the allocator) */
aws_h2_frame_complete_fn aws_h2_frame_complete_destroy;

/* Queue a frame to be written */
AWS_HTTP_API
int aws_h2_connection_queue_frame(
    struct aws_h2_connection *connection,
    struct aws_h2_frame_header *frame,
    aws_h2_frame_complete_fn *on_complete,
    void *userdata);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H2_CONNECTION_H */
