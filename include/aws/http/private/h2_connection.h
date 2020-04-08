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
struct aws_h2_stream;

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

        /* Settings received from peer, which restricts the message to send */
        uint32_t settings_peer[AWS_H2_SETTINGS_END_RANGE];
        /* My settings to send/sent to peer, which affects the decoding */
        uint32_t settings_self[AWS_H2_SETTINGS_END_RANGE];

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

        /* Maps stream-id to aws_h2_stream_closed_when.
         * Contains data about streams that were recently closed by this end (sent RST_STREAM frame or END_STREAM flag),
         * but might still receive frames that remote peer sent before learning that the stream was closed.
         * Entries are removed after a period of time. */
        struct aws_hash_table closed_streams_where_frames_might_trickle_in;

    } thread_data;

    /* Any thread may touch this data, but the lock must be held (unless it's an atomic) */
    struct {
        /* For checking status from outside the event-loop thread. */
        struct aws_atomic_var is_open;

        /* If non-zero, reason to immediately reject new streams. (ex: closing) */
        struct aws_atomic_var new_stream_error_code;

        struct aws_mutex lock;

        /* New `aws_h2_stream *` that haven't moved to `thread_data` yet */
        struct aws_linked_list pending_stream_list;

        bool is_cross_thread_work_task_scheduled;

    } synced_data;
};

/**
 * The action which caused the stream to close.
 */
enum aws_h2_stream_closed_when {
    AWS_H2_STREAM_CLOSED_WHEN_BOTH_SIDES_END_STREAM,
    AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_RECEIVED,
    AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_SENT,
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

/**
 * Invoked immediately after a stream enters the CLOSED state.
 * The connection will remove the stream from its "active" datastructures,
 * guaranteeing that no further decoder callbacks are invoked on the stream.
 *
 * This should NOT be invoked in the case of a "Connection Error",
 * though a "Stream Error", in which a RST_STREAM is sent and the stream
 * is closed early, would invoke this.
 */
int aws_h2_connection_on_stream_closed(
    struct aws_h2_connection *connection,
    struct aws_h2_stream *stream,
    enum aws_h2_stream_closed_when closed_when,
    int aws_error_code);

/* Transform the request to h2 style headers */
struct aws_http_headers *aws_h2_create_headers_from_request(
    struct aws_http_message *request,
    struct aws_allocator *alloc);

#endif /* AWS_HTTP_H2_CONNECTION_H */
