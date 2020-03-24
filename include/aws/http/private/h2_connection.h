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
#include <aws/common/hash_table.h>
#include <aws/common/mutex.h>

#include <aws/http/private/connection_impl.h>
#include <aws/http/private/h2_frames.h>

struct aws_h2_decoder;

struct aws_h2_connection {
    struct aws_http_connection base;

    struct aws_channel_task cross_thread_work_task;
    struct aws_channel_task outgoing_frames_task;

    /* Only the event-loop thread may touch this data */
    struct {
        struct aws_h2_decoder *decoder;
        struct aws_h2_frame_encoder encoder;

        /* True when reading/writing has stopped, whether due to errors or normal channel shutdown. */
        bool is_reading_stopped;
        bool is_writing_stopped;

        bool is_outgoing_frames_task_active;

        /* Maps stream-id to aws_h2_stream*.
         * Contains all streams in the open, reserved, and half-closed states (terms from RFC-7540 5.1).
         * Once a stream enters closed state, it is removed from this map. */
        struct aws_hash_table active_streams_map;

        /* List using aws_h2_stream.node.
         * Contains all streams with DATA frames to send.
         * Any stream in this list is also in the active_streams_map. */
        struct aws_linked_list outgoing_streams_list;

        /* List using aws_h2_frame.node.
         * Queues all frames (except DATA frames) for connection to send.
         * When queue is empty, then we send DATA frames from the outgoing_streams_list */
        struct aws_linked_list outgoing_frames_queue;

    } thread_data;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

        /* New `aws_h2_stream *` that haven't moved to `thread_data` yet */
        struct aws_linked_list pending_stream_list;

        /* If non-zero, reason to immediately reject new streams. (ex: closing) */
        int new_stream_error_code;

        bool is_cross_thread_work_task_scheduled;

        /* For checking status from outside the event-loop thread. */
        bool is_open;

    } synced_data;
};

/* Private functions called from tests... */

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http2_server(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size);

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http2_client(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size);

AWS_EXTERN_C_END

/* Private functions called from multiple .c files... */

/**
 * Enqueue outgoing frame.
 * Connection takes ownership of frame.
 * Frames are sent into FIFO order.
 * Do not enqueue DATA frames, these are sent by other means when the frame queue is empty.
 */
void aws_h2_connection_enqueue_outgoing_frame(struct aws_h2_connection *connection, struct aws_h2_frame *frame);

#endif /* AWS_HTTP_H2_CONNECTION_H */
