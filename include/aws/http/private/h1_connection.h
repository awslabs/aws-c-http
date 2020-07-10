#ifndef AWS_HTTP_H1_CONNECTION_H
#define AWS_HTTP_H1_CONNECTION_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/mutex.h>
#include <aws/http/private/connection_impl.h>
#include <aws/http/private/h1_encoder.h>
#include <aws/http/statistics.h>

struct aws_h1_connection {
    struct aws_http_connection base;

    size_t initial_window_size;

    /* Task responsible for sending data.
     * As long as there is data available to send, the task will be "active" and repeatedly:
     * 1) Encode outgoing stream data to an aws_io_message and send it up the channel.
     * 2) Wait until the aws_io_message's write_complete callback fires.
     * 3) Reschedule the task to run again.
     *
     * `thread_data.is_outgoing_stream_task_active` tells whether the task is "active".
     *
     * If there is no data available to write (waiting for user to add more streams or chunks),
     * then the task stops being active. The task is made active again when the user
     * adds more outgoing data. */
    struct aws_channel_task outgoing_stream_task;

    /* Task that removes items from `synced_data` and does their on-thread work.
     * Runs once and wait until it's scheduled again.
     * `synced_data.is_cross_thread_work_scheduled` tells whether the task is scheduled. */
    struct aws_channel_task cross_thread_work_task;

    /* Only the event-loop thread may touch this data */
    struct {
        /* List of streams being worked on. */
        struct aws_linked_list stream_list;

        /* Points to the stream whose data is currently being sent.
         * This stream is ALWAYS in the `stream_list`.
         * HTTP pipelining is supported, so once the stream is completely written
         * we'll start working on the next stream in the list */
        struct aws_h1_stream *outgoing_stream;

        /* Points to the stream being decoded.
         * This stream is ALWAYS in the `stream_list`. */
        struct aws_h1_stream *incoming_stream;
        struct aws_h1_decoder *incoming_stream_decoder;

        /* Used to encode requests and responses */
        struct aws_h1_encoder encoder;

        /* Amount to let read-window shrink after a channel message has been processed. */
        size_t incoming_message_window_shrink_size;

        /* Messages received after the connection has switched protocols.
         * These are passed downstream to the next handler. */
        struct aws_linked_list midchannel_read_messages;

        struct aws_crt_statistics_http1_channel stats;

        uint64_t outgoing_stream_timestamp_ns;
        uint64_t incoming_stream_timestamp_ns;

        /* True when read and/or writing has stopped, whether due to errors or normal channel shutdown. */
        bool is_reading_stopped : 1;
        bool is_writing_stopped : 1;

        /* If true, the connection has upgraded to another protocol.
         * It will pass data to adjacent channel handlers without altering it.
         * The connection can no longer service request/response streams. */
        bool has_switched_protocols : 1;

        /* Server-only. Request-handler streams can only be created while this is true. */
        bool can_create_request_handler_stream : 1;

        /* see `outgoing_stream_task` */
        bool is_outgoing_stream_task_active : 1;
    } thread_data;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

        /* New client streams that have not been moved to `stream_list` yet.
         * This list is not used on servers. */
        struct aws_linked_list new_client_stream_list;

        /* If non-zero, then window_update_task is scheduled */
        size_t window_update_size;

        /* If non-zero, reason to immediately reject new streams. (ex: closing) */
        int new_stream_error_code;

        /* See `cross_thread_work_task` */
        bool is_cross_thread_work_task_scheduled : 1;

        /* For checking status from outside the event-loop thread. */
        bool is_open : 1;

    } synced_data;
};

AWS_EXTERN_C_BEGIN

/* The functions below are exported so they can be accessed from tests. */

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http1_1_server(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size);

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http1_1_client(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size);

AWS_EXTERN_C_END

/* DO NOT export functions below. They're only used by other .c files in this library */

void aws_h1_connection_lock_synced_data(struct aws_h1_connection *connection);
void aws_h1_connection_unlock_synced_data(struct aws_h1_connection *connection);

/**
 * Try to kick off the outgoing-stream-task.
 * If task is already active, nothing happens.
 * If there's nothing to do, the task will immediately stop itself.
 * Call this whenever the user provides new outgoing data (ex: new stream, new chunk).
 * MUST be called from the connection's thread.
 */
void aws_h1_connection_try_write_outgoing_stream(struct aws_h1_connection *connection);

#endif /* AWS_HTTP_H1_CONNECTION_H */
