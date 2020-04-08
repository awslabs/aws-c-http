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

#include <aws/http/private/h2_connection.h>

#include <aws/http/private/h2_decoder.h>
#include <aws/http/private/h2_stream.h>

#include <aws/common/logging.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define CONNECTION_LOGF(level, connection, text, ...)                                                                  \
    AWS_LOGF_##level(AWS_LS_HTTP_CONNECTION, "id=%p: " text, (void *)(connection), __VA_ARGS__)
#define CONNECTION_LOG(level, connection, text) CONNECTION_LOGF(level, connection, "%s", text)

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message);

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message);

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size);

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately);

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler);
static size_t s_handler_message_overhead(struct aws_channel_handler *handler);
static void s_handler_destroy(struct aws_channel_handler *handler);
static void s_handler_installed(struct aws_channel_handler *handler, struct aws_channel_slot *slot);
static struct aws_http_stream *s_connection_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);
static bool s_connection_is_open(const struct aws_http_connection *connection_base);

static void s_cross_thread_work_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_outgoing_frames_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static int s_encode_outgoing_frames_queue(struct aws_h2_connection *connection, struct aws_byte_buf *output);
static int s_encode_data_from_outgoing_streams(struct aws_h2_connection *connection, struct aws_byte_buf *output);

static int s_decoder_on_headers_begin(uint32_t stream_id, void *userdata);
static int s_decoder_on_headers_i(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type,
    void *userdata);
static int s_decoder_on_headers_end(
    uint32_t stream_id,
    bool malformed,
    enum aws_http_header_block block_type,
    void *userdata);
static int s_decoder_on_data(uint32_t stream_id, struct aws_byte_cursor data, void *userdata);
static int s_decoder_on_end_stream(uint32_t stream_id, void *userdata);
static int s_decoder_on_ping(uint8_t opaque_data[AWS_H2_PING_DATA_SIZE], void *userdata);
static int s_decoder_on_settings(
    const struct aws_h2_frame_setting *settings_array,
    size_t num_settings,
    void *userdata);
static int s_decoder_on_settings_ack(void *userdata);

static struct aws_http_connection_vtable s_h2_connection_vtable = {
    .channel_handler_vtable =
        {
            .process_read_message = s_handler_process_read_message,
            .process_write_message = s_handler_process_write_message,
            .increment_read_window = s_handler_increment_read_window,
            .shutdown = s_handler_shutdown,
            .initial_window_size = s_handler_initial_window_size,
            .message_overhead = s_handler_message_overhead,
            .destroy = s_handler_destroy,
        },

    .on_channel_handler_installed = s_handler_installed,
    .make_request = s_connection_make_request,
    .new_server_request_handler_stream = NULL,
    .stream_send_response = NULL,
    .close = NULL,
    .is_open = s_connection_is_open,
    .update_window = NULL,
};

static const struct aws_h2_decoder_vtable s_h2_decoder_vtable = {
    .on_headers_begin = s_decoder_on_headers_begin,
    .on_headers_i = s_decoder_on_headers_i,
    .on_headers_end = s_decoder_on_headers_end,
    .on_data = s_decoder_on_data,
    .on_end_stream = s_decoder_on_end_stream,
    .on_ping = s_decoder_on_ping,
    .on_settings = s_decoder_on_settings,
    .on_settings_ack = s_decoder_on_settings_ack,
};

static void s_lock_synced_data(struct aws_h2_connection *connection) {
    int err = aws_mutex_lock(&connection->synced_data.lock);
    AWS_ASSERT(!err && "lock failed");
    (void)err;
}

static void s_unlock_synced_data(struct aws_h2_connection *connection) {
    int err = aws_mutex_unlock(&connection->synced_data.lock);
    AWS_ASSERT(!err && "unlock failed");
    (void)err;
}

/**
 * Internal function for bringing connection to a stop.
 * Invoked multiple times, including when:
 * - Channel is shutting down in the read direction.
 * - Channel is shutting down in the write direction.
 * - An error occurs that will shutdown the channel.
 * - User wishes to close the connection (this is the only case where the function may run off-thread).
 */
static void s_stop(
    struct aws_h2_connection *connection,
    bool stop_reading,
    bool stop_writing,
    bool schedule_shutdown,
    int error_code) {

    AWS_ASSERT(stop_reading || stop_writing || schedule_shutdown); /* You are required to stop at least 1 thing */

    if (stop_reading) {
        AWS_ASSERT(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
        connection->thread_data.is_reading_stopped = true;
    }

    if (stop_writing) {
        AWS_ASSERT(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
        connection->thread_data.is_writing_stopped = true;
    }

    /* Even if we're not scheduling shutdown just yet (ex: sent final request but waiting to read final response)
     * we don't consider the connection "open" anymore so user can't create more streams */
    aws_atomic_store_int(&connection->synced_data.new_stream_error_code, AWS_ERROR_HTTP_CONNECTION_CLOSED);
    aws_atomic_store_int(&connection->synced_data.is_open, 0);

    if (schedule_shutdown) {
        AWS_LOGF_INFO(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Shutting down connection with error code %d (%s).",
            (void *)&connection->base,
            error_code,
            aws_error_name(error_code));

        aws_channel_shutdown(connection->base.channel_slot->channel, error_code);
    }
}

static void s_shutdown_due_to_read_err(struct aws_h2_connection *connection, int error_code) {
    AWS_PRECONDITION(error_code);
    s_stop(connection, true /*stop_reading*/, false /*stop_writing*/, true /*schedule_shutdown*/, error_code);
}

static void s_shutdown_due_to_write_err(struct aws_h2_connection *connection, int error_code) {
    AWS_PRECONDITION(error_code);
    s_stop(connection, false /*stop_reading*/, true /*stop_writing*/, true /*schedule_shutdown*/, error_code);
}

/* Common new() logic for server & client */
static struct aws_h2_connection *s_connection_new(
    struct aws_allocator *alloc,
    bool manual_window_management,
    size_t initial_window_size,
    bool server) {

    (void)server;
    (void)initial_window_size; /* #TODO use this for our initial settings */

    struct aws_h2_connection *connection = aws_mem_calloc(alloc, 1, sizeof(struct aws_h2_connection));
    if (!connection) {
        return NULL;
    }

    connection->base.vtable = &s_h2_connection_vtable;
    connection->base.alloc = alloc;
    connection->base.channel_handler.vtable = &s_h2_connection_vtable.channel_handler_vtable;
    connection->base.channel_handler.alloc = alloc;
    connection->base.channel_handler.impl = connection;
    connection->base.http_version = AWS_HTTP_VERSION_2;
    /* Init the next stream id (server must use even ids, client odd [RFC 7540 5.1.1])*/
    connection->base.next_stream_id = (server ? 2 : 1);
    connection->base.manual_window_management = manual_window_management;

    aws_channel_task_init(
        &connection->cross_thread_work_task, s_cross_thread_work_task, connection, "HTTP/2 cross-thread work");

    aws_channel_task_init(
        &connection->outgoing_frames_task, s_outgoing_frames_task, connection, "HTTP/2 outgoing frames");

    /* 1 refcount for user */
    aws_atomic_init_int(&connection->base.refcount, 1);

    aws_atomic_init_int(&connection->synced_data.is_open, 1);
    aws_atomic_init_int(&connection->synced_data.new_stream_error_code, 0);
    aws_linked_list_init(&connection->synced_data.pending_stream_list);

    aws_linked_list_init(&connection->thread_data.outgoing_streams_list);
    aws_linked_list_init(&connection->thread_data.outgoing_frames_queue);

    if (aws_mutex_init(&connection->synced_data.lock)) {
        CONNECTION_LOGF(
            ERROR, connection, "Mutex init error %d (%s).", aws_last_error(), aws_error_name(aws_last_error()));
        goto error;
    }

    if (aws_hash_table_init(
            &connection->thread_data.active_streams_map, alloc, 8, aws_hash_ptr, aws_ptr_eq, NULL, NULL)) {

        CONNECTION_LOGF(
            ERROR, connection, "Hashtable init error %d (%s).", aws_last_error(), aws_error_name(aws_last_error()));
        goto error;
    }

    if (aws_hash_table_init(
            &connection->thread_data.closed_streams_where_frames_might_trickle_in,
            alloc,
            8,
            aws_hash_ptr,
            aws_ptr_eq,
            NULL,
            NULL)) {

        CONNECTION_LOGF(
            ERROR, connection, "Hashtable init error %d (%s).", aws_last_error(), aws_error_name(aws_last_error()));
        goto error;
    }

    /* Initialize the value of settings */
    memcpy(connection->thread_data.settings_peer, aws_h2_settings_initial, sizeof(aws_h2_settings_initial));
    memcpy(connection->thread_data.settings_self, aws_h2_settings_initial, sizeof(aws_h2_settings_initial));

    /* Create a new decoder */
    struct aws_h2_decoder_params params = {
        .alloc = alloc,
        .vtable = &s_h2_decoder_vtable,
        .userdata = connection,
        .logging_id = connection,
        .is_server = server,
    };
    connection->thread_data.decoder = aws_h2_decoder_new(&params);
    if (!connection->thread_data.decoder) {
        CONNECTION_LOGF(
            ERROR, connection, "Decoder init error %d (%s)", aws_last_error(), aws_error_name(aws_last_error()));
        goto error;
    }

    if (aws_h2_frame_encoder_init(&connection->thread_data.encoder, alloc, &connection->base)) {
        CONNECTION_LOGF(
            ERROR, connection, "Encoder init error %d (%s)", aws_last_error(), aws_error_name(aws_last_error()));
        goto error;
    }

    return connection;

error:
    s_handler_destroy(&connection->base.channel_handler);

    return NULL;
}

struct aws_http_connection *aws_http_connection_new_http2_server(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size) {

    struct aws_h2_connection *connection =
        s_connection_new(allocator, manual_window_management, initial_window_size, true);
    if (!connection) {
        return NULL;
    }

    connection->base.server_data = &connection->base.client_or_server_data.server;

    return &connection->base;
}

struct aws_http_connection *aws_http_connection_new_http2_client(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size) {

    struct aws_h2_connection *connection =
        s_connection_new(allocator, manual_window_management, initial_window_size, false);
    if (!connection) {
        return NULL;
    }

    connection->base.client_data = &connection->base.client_or_server_data.client;

    /* #TODO immediately send connection preface string and settings */

    return &connection->base;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_h2_connection *connection = handler->impl;
    CONNECTION_LOG(TRACE, connection, "Destroying connection");

    /* No streams should be left in internal datastructures */
    AWS_ASSERT(
        !aws_hash_table_is_valid(&connection->thread_data.active_streams_map) ||
        aws_hash_table_get_entry_count(&connection->thread_data.active_streams_map) == 0);

    AWS_ASSERT(aws_linked_list_empty(&connection->thread_data.outgoing_streams_list));
    AWS_ASSERT(aws_linked_list_empty(&connection->synced_data.pending_stream_list));

    /* Clean up any unsent frames */
    struct aws_linked_list *outgoing_frames_queue = &connection->thread_data.outgoing_frames_queue;
    while (!aws_linked_list_empty(outgoing_frames_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(outgoing_frames_queue);
        struct aws_h2_frame *frame = AWS_CONTAINER_OF(node, struct aws_h2_frame, node);
        aws_h2_frame_destroy(frame);
    }

    aws_h2_decoder_destroy(connection->thread_data.decoder);
    aws_h2_frame_encoder_clean_up(&connection->thread_data.encoder);
    aws_hash_table_clean_up(&connection->thread_data.active_streams_map);
    aws_hash_table_clean_up(&connection->thread_data.closed_streams_where_frames_might_trickle_in);
    aws_mutex_clean_up(&connection->synced_data.lock);
    aws_mem_release(connection->base.alloc, connection);
}

void aws_h2_connection_enqueue_outgoing_frame(struct aws_h2_connection *connection, struct aws_h2_frame *frame) {
    AWS_PRECONDITION(frame->type != AWS_H2_FRAME_T_DATA);
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    if (frame->high_priority) {
        /* Check from the head of the queue, and find a node with normal priority, and insert before it */
        struct aws_linked_list_node *iter = aws_linked_list_begin(&connection->thread_data.outgoing_frames_queue);
        /* one past the last element */
        const struct aws_linked_list_node *end = aws_linked_list_end(&connection->thread_data.outgoing_frames_queue);
        while (iter != end) {
            struct aws_h2_frame *frame_i = AWS_CONTAINER_OF(iter, struct aws_h2_frame, node);
            if (!frame_i->high_priority) {
                break;
            }
            iter = iter->next;
        }
        aws_linked_list_insert_before(iter, &frame->node);
    } else {
        aws_linked_list_push_back(&connection->thread_data.outgoing_frames_queue, &frame->node);
    }
}

static void s_on_channel_write_complete(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data) {

    (void)message;
    struct aws_h2_connection *connection = user_data;

    if (err_code) {
        CONNECTION_LOGF(ERROR, connection, "Message did not write to network, error %s", aws_error_name(err_code));
        s_shutdown_due_to_write_err(connection, err_code);
        return;
    }

    CONNECTION_LOG(TRACE, connection, "Message finished writing to network. Rescheduling outgoing frame task");

    /* To avoid wasting memory, we only want ONE of our written aws_io_messages in the channel at a time.
     * Therefore, we wait until it's written to the network before trying to send another
     * by running the outgoing-frame-task again.
     *
     * We also want to share the network with other channels.
     * Therefore, when the write completes, we SCHEDULE the outgoing-frame-task
     * to run again instead of calling the function directly.
     * This way, if the message completes synchronously,
     * we're not hogging the network by writing message after message in a tight loop */
    aws_channel_schedule_task_now(channel, &connection->outgoing_frames_task);
}

static void s_outgoing_frames_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_h2_connection *connection = arg;
    struct aws_channel_slot *channel_slot = connection->base.channel_slot;
    struct aws_linked_list *outgoing_frames_queue = &connection->thread_data.outgoing_frames_queue;
    struct aws_linked_list *outgoing_streams_list = &connection->thread_data.outgoing_streams_list;

    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(channel_slot->channel));
    AWS_PRECONDITION(connection->thread_data.is_outgoing_frames_task_active);

    /* If there is nothing to send, then end the task immediately */
    if (aws_linked_list_empty(outgoing_frames_queue) && aws_linked_list_empty(outgoing_streams_list)) {
        CONNECTION_LOG(TRACE, connection, "Outgoing frames task stopped, nothing to send at this time");
        connection->thread_data.is_outgoing_frames_task_active = false;
        return;
    }

    /* Acquire aws_io_message, that we will attempt to fill up */
    struct aws_io_message *msg = aws_channel_slot_acquire_max_message_for_write(channel_slot);
    if (AWS_UNLIKELY(!msg)) {
        CONNECTION_LOG(ERROR, connection, "Failed to acquire message from pool, closing connection.");
        goto error;
    }

    /* Set up callback so we can send another message when this one completes */
    msg->on_completion = s_on_channel_write_complete;
    msg->user_data = connection;

    CONNECTION_LOGF(
        TRACE,
        connection,
        "Outgoing frames task acquired message with %zu bytes available",
        msg->message_data.capacity - msg->message_data.len);

    /* Write as many frames from outgoing_frames_queue as possible. */
    if (s_encode_outgoing_frames_queue(connection, &msg->message_data)) {
        goto error;
    }

    /* If outgoing_frames_queue emptied, then write as many DATA frames from outgoing_streams_list as possible. */
    if (aws_linked_list_empty(outgoing_frames_queue)) {
        if (s_encode_data_from_outgoing_streams(connection, &msg->message_data)) {
            goto error;
        }
    }

    if (msg->message_data.len) {
        /* Write message to channel.
         * outgoing_frames_task will resume when message completes. */
        CONNECTION_LOGF(TRACE, connection, "Outgoing frames task sending message of size %zu", msg->message_data.len);

        if (aws_channel_slot_send_message(channel_slot, msg, AWS_CHANNEL_DIR_WRITE)) {
            CONNECTION_LOGF(
                ERROR,
                connection,
                "Failed to send channel message: %s. Closing connection.",
                aws_error_name(aws_last_error()));

            goto error;
        }
    } else {
        /* Message is empty, warn that no work is being done and reschedule the task to try again next tick.
         * It's likely that body isn't ready, so body streaming function has no data to write yet.
         * If this scenario turns out to be common we should implement a "pause" feature. */
        CONNECTION_LOG(WARN, connection, "Outgoing frames task sent no data, will try again next tick.");

        aws_mem_release(msg->allocator, msg);

        aws_channel_schedule_task_now(channel_slot->channel, task);
    }
    return;

error:;
    int error_code = aws_last_error();

    if (msg) {
        aws_mem_release(msg->allocator, msg);
    }

    s_shutdown_due_to_write_err(connection, error_code);
}

/* Write as many frames from outgoing_frames_queue as possible (contains all non-DATA frames) */
static int s_encode_outgoing_frames_queue(struct aws_h2_connection *connection, struct aws_byte_buf *output) {

    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    struct aws_linked_list *outgoing_frames_queue = &connection->thread_data.outgoing_frames_queue;

    /* Write as many frames from outgoing_frames_queue as possible. */
    while (!aws_linked_list_empty(outgoing_frames_queue)) {
        struct aws_linked_list_node *frame_node = aws_linked_list_front(outgoing_frames_queue);
        struct aws_h2_frame *frame = AWS_CONTAINER_OF(frame_node, struct aws_h2_frame, node);

        bool frame_complete;
        if (aws_h2_encode_frame(&connection->thread_data.encoder, frame, output, &frame_complete)) {
            CONNECTION_LOGF(
                ERROR,
                connection,
                "Error encoding frame: type=%s stream=%" PRIu32 " error=%s",
                aws_h2_frame_type_to_str(frame->type),
                frame->stream_id,
                aws_error_name(aws_last_error()));
            return AWS_OP_ERR;
        }

        if (!frame_complete) {
            if (output->len == 0) {
                /* We're in trouble if an empty message isn't big enough for this frame to do any work with */
                CONNECTION_LOGF(
                    ERROR,
                    connection,
                    "Message is too small for encoder. frame-type=%s stream=%" PRIu32 " available-space=%zu",
                    aws_h2_frame_type_to_str(frame->type),
                    frame->stream_id,
                    output->capacity);
                aws_raise_error(AWS_ERROR_INVALID_STATE);
                return AWS_OP_ERR;
            }

            CONNECTION_LOG(TRACE, connection, "Outgoing frames task filled message, and has more frames to send later");
            break;
        }

        /* Done encoding frame, pop from queue and cleanup*/
        aws_linked_list_remove(frame_node);
        aws_h2_frame_destroy(frame);
    }

    return AWS_OP_SUCCESS;
}

/* Write as many DATA frames from outgoing_streams_list as possible. */
static int s_encode_data_from_outgoing_streams(struct aws_h2_connection *connection, struct aws_byte_buf *output) {

    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    struct aws_linked_list *outgoing_streams_list = &connection->thread_data.outgoing_streams_list;

    /* If a stream stalls, put it in this list until the function ends so we don't keep trying to read from it.
     * We put it back at the end of function. */
    struct aws_linked_list stalled_streams_list;
    aws_linked_list_init(&stalled_streams_list);

    int aws_error_code = 0;

    /* We simply round-robin through streams, instead of using stream priority.
     * Respecting priority is not required (RFC-7540 5.3), so we're ignoring it for now. This also keeps use safe
     * from priority DOS attacks: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9513 */
    while (!aws_linked_list_empty(outgoing_streams_list)) {

        /* Stop looping if message is so full it's not worth the bother */
        size_t space_available = output->capacity - output->len;
        size_t worth_trying_threshold = AWS_H2_FRAME_PREFIX_SIZE * 2;
        if (space_available < worth_trying_threshold) {
            CONNECTION_LOG(TRACE, connection, "Outgoing frames task filled message, and has more frames to send later");
            goto done;
        }

        struct aws_linked_list_node *node = aws_linked_list_pop_front(outgoing_streams_list);
        struct aws_h2_stream *stream = AWS_CONTAINER_OF(node, struct aws_h2_stream, node);

        /* Ask stream to encode a data frame.
         * Stream may complete itself as a result of encoding its data,
         * in which case it will vanish from the connection's datastructures as a side-effect of this call.
         * But if stream has more data to send, push it back into the appropriate list. */
        bool has_more_data;
        bool stream_stalled;
        if (aws_h2_stream_encode_data_frame(
                stream, &connection->thread_data.encoder, output, &has_more_data, &stream_stalled)) {

            aws_error_code = aws_last_error();
            CONNECTION_LOGF(
                ERROR,
                connection,
                "Connection error while encoding DATA on stream %" PRIu32 ", %s",
                stream->base.id,
                aws_error_name(aws_error_code));
            goto done;
        }

        /* If stream has more data, push it into the appropriate list. */
        if (has_more_data) {
            if (stream_stalled) {
                aws_linked_list_push_back(&stalled_streams_list, node);
            } else {
                aws_linked_list_push_back(outgoing_streams_list, node);
            }
        }
    }

done:
    /* Return any stalled streams to outgoing_streams_list */
    while (!aws_linked_list_empty(&stalled_streams_list)) {
        aws_linked_list_push_back(outgoing_streams_list, aws_linked_list_pop_front(&stalled_streams_list));
    }

    if (aws_error_code) {
        return aws_raise_error(aws_error_code);
    }

    return AWS_OP_SUCCESS;
}

/* If the outgoing-frames-task isn't scheduled, run it immediately. */
static void s_try_write_outgoing_frames(struct aws_h2_connection *connection) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    if (connection->thread_data.is_outgoing_frames_task_active) {
        return;
    }

    CONNECTION_LOG(TRACE, connection, "Starting outgoing frames task");
    connection->thread_data.is_outgoing_frames_task_active = true;
    s_outgoing_frames_task(&connection->outgoing_frames_task, connection, AWS_TASK_STATUS_RUN_READY);
}

/**
 * Returns AWS_OP_SUCCESS and sets `out_stream` if stream is currently active.
 * Returns AWS_OP_SUCCESS and sets `out_stream` to NULL if the frame should be ignored.
 * Returns AWS_OP_ERR if it is a connection error to receive this frame.
 */
int s_get_active_stream_for_incoming_frame(
    struct aws_h2_connection *connection,
    uint32_t stream_id,
    enum aws_h2_frame_type frame_type,
    struct aws_h2_stream **out_stream) {

    *out_stream = NULL;

    /* Check active streams */
    struct aws_hash_element *found = NULL;
    const void *stream_id_key = (void *)(size_t)stream_id;
    aws_hash_table_find(&connection->thread_data.active_streams_map, stream_id_key, &found);
    if (found) {
        /* Found it! return */
        *out_stream = found->value;
        return AWS_OP_SUCCESS;
    }

    /* #TODO account for odd-numbered vs even-numbered stream-ids when we handle PUSH_PROMISE frames */

    /* Stream isn't active, check whether it's idle (doesn't exist yet) or closed. */
    if (stream_id >= connection->base.next_stream_id) {
        /* Illegal to receive frames for a stream in the idle state (stream doesn't exist yet)
         * (except server receiving HEADERS to start a stream, but that's handled elsewhere) */
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Illegal to receive %s frame on stream id=%" PRIu32 " state=IDLE",
            aws_h2_frame_type_to_str(frame_type),
            stream_id);
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    /* Stream is closed, check whether it's legal for a few more frames to trickle in */
    aws_hash_table_find(&connection->thread_data.closed_streams_where_frames_might_trickle_in, stream_id_key, &found);
    if (found) {
        enum aws_h2_stream_closed_when closed_when = (enum aws_h2_stream_closed_when)(size_t)found->value;
        if (closed_when == AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_SENT) {
            /* An endpoint MUST ignore frames that it receives on closed streams after it has sent a RST_STREAM frame */
            CONNECTION_LOGF(
                TRACE,
                connection,
                "Ignoring %s frame on stream id=%" PRIu32 " because RST_STREAM was recently sent.",
                aws_h2_frame_type_to_str(frame_type),
                stream_id);

            return AWS_OP_SUCCESS;

        } else {
            AWS_ASSERT(closed_when == AWS_H2_STREAM_CLOSED_WHEN_BOTH_SIDES_END_STREAM);

            /* WINDOW_UPDATE or RST_STREAM frames can be received ... for a short period after
             * a DATA or HEADERS frame containing an END_STREAM flag is sent.
             * Endpoints MUST ignore WINDOW_UPDATE or RST_STREAM frames received in this state */
            if (frame_type == AWS_H2_FRAME_T_WINDOW_UPDATE || frame_type == AWS_H2_FRAME_T_RST_STREAM) {
                CONNECTION_LOGF(
                    TRACE,
                    connection,
                    "Ignoring %s frame on stream id=%" PRIu32 " because END_STREAM flag was recently sent.",
                    aws_h2_frame_type_to_str(frame_type),
                    stream_id);

                return AWS_OP_SUCCESS;
            }
        }
    }

    /* #TODO An endpoint that receives any frame other than PRIORITY after receiving a RST_STREAM
     * MUST treat that as a stream error (Section 5.4.2) of type STREAM_CLOSED */

    /* Stream was closed long ago, or didn't fit criteria for being ignored */
    CONNECTION_LOGF(
        ERROR,
        connection,
        "Illegal to receive %s frame on stream id=%" PRIu32 " state=closed",
        aws_h2_frame_type_to_str(frame_type),
        stream_id);

    return aws_raise_error(AWS_ERROR_HTTP_STREAM_CLOSED);
}

/* Decoder callbacks */

int s_decoder_on_headers_begin(uint32_t stream_id, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    if (connection->base.server_data) {
        /* Server would create new request-handler stream... */
        return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
    }

    struct aws_h2_stream *stream;
    if (s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_HEADERS, &stream)) {
        return AWS_OP_ERR;
    }

    if (stream) {
        if (aws_h2_stream_on_decoder_headers_begin(stream)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int s_decoder_on_headers_i(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type,
    void *userdata) {

    struct aws_h2_connection *connection = userdata;
    struct aws_h2_stream *stream;
    if (s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_HEADERS, &stream)) {
        return AWS_OP_ERR;
    }

    if (stream) {
        if (aws_h2_stream_on_decoder_headers_i(stream, header, name_enum, block_type)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int s_decoder_on_headers_end(
    uint32_t stream_id,
    bool malformed,
    enum aws_http_header_block block_type,
    void *userdata) {

    struct aws_h2_connection *connection = userdata;
    struct aws_h2_stream *stream;
    if (s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_HEADERS, &stream)) {
        return AWS_OP_ERR;
    }

    if (stream) {
        if (aws_h2_stream_on_decoder_headers_end(stream, malformed, block_type)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int s_decoder_on_data(uint32_t stream_id, struct aws_byte_cursor data, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    /* #TODO Update connection's flow-control window */

    /* Pass data to stream */
    struct aws_h2_stream *stream;
    if (s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_DATA, &stream)) {
        return AWS_OP_ERR;
    }

    if (stream) {
        if (aws_h2_stream_on_decoder_data(stream, data)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int s_decoder_on_end_stream(uint32_t stream_id, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    /* Not calling s_get_active_stream_for_incoming_frame() here because END_STREAM
     * isn't an actual frame type. It's a flag on DATA or HEADERS frames, and we
     * already checked the legality of those frames in their respective callbacks. */

    struct aws_hash_element *found = NULL;
    aws_hash_table_find(&connection->thread_data.active_streams_map, (void *)(size_t)stream_id, &found);
    if (found) {
        struct aws_h2_stream *stream = found->value;
        if (aws_h2_stream_on_decoder_end_stream(stream)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_ping(uint8_t opaque_data[AWS_H2_PING_DATA_SIZE], void *userdata) {
    struct aws_h2_connection *connection = userdata;

    /* send a PING frame with the ACK flag set in response, with an identical payload. */
    struct aws_h2_frame *ping_ack_frame = aws_h2_frame_new_ping(connection->base.alloc, true, opaque_data);
    if (!ping_ack_frame) {
        goto error;
    }

    aws_h2_connection_enqueue_outgoing_frame(connection, ping_ack_frame);
    return AWS_OP_SUCCESS;
error:
    CONNECTION_LOGF(ERROR, connection, "Ping ACK frame failed to be sent, error %s", aws_error_name(aws_last_error()));
    return AWS_OP_ERR;
}

static void s_aws_h2_decoder_change_settings(struct aws_h2_connection *connection) {
    struct aws_h2_decoder *decoder = connection->thread_data.decoder;
    uint32_t *settings_self = connection->thread_data.settings_self;
    aws_h2_decoder_set_setting_header_table_size(decoder, settings_self[AWS_H2_SETTINGS_HEADER_TABLE_SIZE]);
    aws_h2_decoder_set_setting_enable_push(decoder, settings_self[AWS_H2_SETTINGS_ENABLE_PUSH]);
    aws_h2_decoder_set_setting_max_frame_size(decoder, settings_self[AWS_H2_SETTINGS_MAX_FRAME_SIZE]);
}

static int s_decoder_on_settings(
    const struct aws_h2_frame_setting *settings_array,
    size_t num_settings,
    void *userdata) {
    struct aws_h2_connection *connection = userdata;
    /* Once all values have been processed, the recipient MUST immediately emit a SETTINGS frame with the ACK flag
     * set.(RFC-7540 6.5.3) */
    CONNECTION_LOG(TRACE, connection, "Setting frame processing ends");
    struct aws_h2_frame *settings_ack_frame = aws_h2_frame_new_settings(connection->base.alloc, NULL, 0, true);
    if (!settings_ack_frame) {
        CONNECTION_LOGF(
            ERROR, connection, "Settings ACK frame failed to be sent, error %s", aws_error_name(aws_last_error()));
        goto error;
    }
    aws_h2_connection_enqueue_outgoing_frame(connection, settings_ack_frame);
    /* Store the change to encoder and connection after enqueue the setting ACK frame */
    struct aws_h2_frame_encoder *encoder = &connection->thread_data.encoder;
    for (size_t i = 0; i < num_settings; i++) {
        if (connection->thread_data.settings_peer[settings_array[i].id] == settings_array[i].value) {
            /* No change, don't do any work */
            continue;
        }
        switch (settings_array[i].id) {
            case AWS_H2_SETTINGS_HEADER_TABLE_SIZE:
                aws_h2_frame_encoder_set_setting_header_table_size(encoder, settings_array[i].value);
                break;
            case AWS_H2_SETTINGS_MAX_FRAME_SIZE:
                aws_h2_frame_encoder_set_setting_max_frame_size(encoder, settings_array[i].value);
                break;
        }
        connection->thread_data.settings_peer[settings_array[i].id] = settings_array[i].value;
    }
    return AWS_OP_SUCCESS;

error:

    return AWS_OP_ERR;
}

static int s_decoder_on_settings_ack(void *userdata) {
    struct aws_h2_connection *connection = userdata;
    /* #TODO track which SETTINGS frames is ACKed by this */

    /* inform decoder about the settings */
    s_aws_h2_decoder_change_settings(connection);
    return AWS_OP_SUCCESS;
}

/* End decoder callbacks */

static int s_send_connection_preface_client_string(struct aws_h2_connection *connection) {

    /* Just send the magic string on its own aws_io_message. */
    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        connection->base.channel_slot->channel,
        AWS_IO_MESSAGE_APPLICATION_DATA,
        aws_h2_connection_preface_client_string.len);
    if (!msg) {
        goto error;
    }

    if (!aws_byte_buf_write_from_whole_cursor(&msg->message_data, aws_h2_connection_preface_client_string)) {
        aws_raise_error(AWS_ERROR_INVALID_STATE);
        goto error;
    }

    if (aws_channel_slot_send_message(connection->base.channel_slot, msg, AWS_CHANNEL_DIR_WRITE)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    if (msg) {
        aws_mem_release(msg->allocator, msg);
    }
    return AWS_OP_ERR;
}

/* #TODO actually fill with initial settings */
/* #TODO track which SETTINGS frames have been ACK'd */
static int s_enqueue_settings_frame(struct aws_h2_connection *connection) {
    struct aws_allocator *alloc = connection->base.alloc;

    struct aws_h2_frame *settings_frame = aws_h2_frame_new_settings(alloc, NULL, 0, false /*ack*/);
    if (!settings_frame) {
        return AWS_OP_ERR;
    }

    aws_h2_connection_enqueue_outgoing_frame(connection, settings_frame);
    return AWS_OP_SUCCESS;
}

static void s_handler_installed(struct aws_channel_handler *handler, struct aws_channel_slot *slot) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(slot->channel));
    struct aws_h2_connection *connection = handler->impl;

    connection->base.channel_slot = slot;

    /* Acquire a hold on the channel to prevent its destruction until the user has
     * given the go-ahead via aws_http_connection_release() */
    aws_channel_acquire_hold(slot->channel);

    /* Send HTTP/2 connection preface (RFC-7540 3.5)
     * - clients must send magic string
     * - both client and server must send SETTINGS frame */
    if (connection->base.client_data) {
        if (s_send_connection_preface_client_string(connection)) {
            CONNECTION_LOGF(
                ERROR,
                connection,
                "Failed to send client connection preface string, %s",
                aws_error_name(aws_last_error()));
            goto error;
        }
    }

    if (s_enqueue_settings_frame(connection)) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Failed to send SETTINGS frame for connection preface, %s",
            aws_error_name(aws_last_error()));
        goto error;
    }

    s_try_write_outgoing_frames(connection);
    return;

error:
    s_shutdown_due_to_write_err(connection, aws_last_error());
}

static void s_stream_complete(struct aws_h2_connection *connection, struct aws_h2_stream *stream, int error_code) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    /* Nice logging */
    if (error_code) {
        AWS_H2_STREAM_LOGF(
            ERROR, stream, "Stream completed with error %d (%s).", error_code, aws_error_name(error_code));
    } else if (stream->base.client_data) {
        int status = stream->base.client_data->response_status;
        AWS_H2_STREAM_LOGF(
            DEBUG, stream, "Client stream complete, response status %d (%s)", status, aws_http_status_text(status));
    } else {
        AWS_H2_STREAM_LOG(DEBUG, stream, "Server stream complete");
    }

    /* Remove stream from active_streams_map and outgoing_stream_list (if it was in them at all) */
    aws_hash_table_remove(&connection->thread_data.active_streams_map, (void *)(size_t)stream->base.id, NULL, NULL);
    if (stream->node.next) {
        aws_linked_list_remove(&stream->node);
    }

    /* Invoke callback */
    if (stream->base.on_complete) {
        stream->base.on_complete(&stream->base, error_code, stream->base.user_data);
    }

    /* release connection's hold on stream */
    aws_http_stream_release(&stream->base);
}

int aws_h2_connection_on_stream_closed(
    struct aws_h2_connection *connection,
    struct aws_h2_stream *stream,
    enum aws_h2_stream_closed_when closed_when,
    int aws_error_code) {

    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    AWS_PRECONDITION(stream->thread_data.state == AWS_H2_STREAM_STATE_CLOSED);
    AWS_PRECONDITION(stream->base.id != 0);

    uint32_t stream_id = stream->base.id;

    /* Mark stream complete. This removes the stream from any "active" datastructures,
     * invokes its completion callback, and releases its refcount. */
    s_stream_complete(connection, stream, aws_error_code);
    stream = NULL; /* Reference released, do not touch again */

    /* Peer might have already sent/queued frames for this stream before learning that we closed it.
     * But if peer was the one to close the stream via RST_STREAM, they know better than to send more frames. */
    bool frames_might_trickle_in = closed_when != AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_RECEIVED;
    if (frames_might_trickle_in) {
        if (aws_hash_table_put(
                &connection->thread_data.closed_streams_where_frames_might_trickle_in,
                (void *)(size_t)stream_id,
                (void *)(size_t)closed_when,
                NULL)) {

            AWS_H2_STREAM_LOG(ERROR, stream, "Failed inserting ID into map of recently closed streams");
            return AWS_OP_ERR;
        }

        /* #TODO remove entries from closed_streams_where_frames_might_trickle_in after some period of time */
    }

    return AWS_OP_SUCCESS;
}

/* Move stream into "active" datastructures and notify stream that it can send frames now */
static void s_activate_stream(struct aws_h2_connection *connection, struct aws_h2_stream *stream) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    uint32_t max_concurrent_streams = connection->thread_data.settings_peer[AWS_H2_SETTINGS_MAX_CONCURRENT_STREAMS];
    if (aws_hash_table_get_entry_count(&connection->thread_data.active_streams_map) >= max_concurrent_streams) {
        AWS_H2_STREAM_LOG(ERROR, stream, "Failed activating stream, max concurrent streams are reached");
        goto error;
    }

    if (aws_hash_table_put(
            &connection->thread_data.active_streams_map, (void *)(size_t)stream->base.id, stream, NULL)) {
        AWS_H2_STREAM_LOG(ERROR, stream, "Failed inserting stream into map");
        goto error;
    }

    bool has_outgoing_data = false;
    if (aws_h2_stream_on_activated(stream, &has_outgoing_data)) {
        goto error;
    }

    aws_atomic_fetch_add(&stream->base.refcount, 1);

    if (has_outgoing_data) {
        aws_linked_list_push_back(&connection->thread_data.outgoing_streams_list, &stream->node);
    }

    return;
error:
    /* If the stream got into any datastructures, s_stream_complete() will remove it */
    s_stream_complete(connection, stream, aws_last_error());
}

/* Perform on-thread work that is triggered by calls to the connection/stream API */
static void s_cross_thread_work_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_h2_connection *connection = arg;

    struct aws_linked_list pending_streams;
    aws_linked_list_init(&pending_streams);

    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(connection);
        connection->synced_data.is_cross_thread_work_task_scheduled = false;

        aws_linked_list_swap_contents(&connection->synced_data.pending_stream_list, &pending_streams);

        s_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    /* Process new pending_streams */
    while (!aws_linked_list_empty(&pending_streams)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&pending_streams);
        struct aws_h2_stream *stream = AWS_CONTAINER_OF(node, struct aws_h2_stream, node);
        s_activate_stream(connection, stream);
    }

    /* #TODO: process stuff from other API calls (ex: window-updates) */

    /* It's likely that frames were queued while processing cross-thread work.
     * If so, try writing them now */
    s_try_write_outgoing_frames(connection);
}

int aws_h2_stream_activate(struct aws_http_stream *stream) {
    struct aws_h2_stream *h2_stream = AWS_CONTAINER_OF(stream, struct aws_h2_stream, base);

    struct aws_http_connection *base_connection = stream->owning_connection;
    struct aws_h2_connection *connection = AWS_CONTAINER_OF(base_connection, struct aws_h2_connection, base);

    bool was_cross_thread_work_scheduled = false;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(connection);

        if (stream->id) {
            /* stream has already been activated. */
            s_unlock_synced_data(connection);
            return AWS_OP_SUCCESS;
        }

        stream->id = aws_http_connection_get_next_stream_id(base_connection);

        if (stream->id) {
            was_cross_thread_work_scheduled = connection->synced_data.is_cross_thread_work_task_scheduled;
            connection->synced_data.is_cross_thread_work_task_scheduled = true;

            aws_linked_list_push_back(&connection->synced_data.pending_stream_list, &h2_stream->node);
        }
        s_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    if (!stream->id) {
        /* aws_http_connection_get_next_stream_id() raises its own error. */
        return AWS_OP_ERR;
    }

    if (!was_cross_thread_work_scheduled) {
        CONNECTION_LOG(TRACE, connection, "Scheduling cross-thread work task");
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->cross_thread_work_task);
    }

    return AWS_OP_SUCCESS;
}

static struct aws_http_stream *s_connection_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {

    struct aws_h2_connection *connection = AWS_CONTAINER_OF(client_connection, struct aws_h2_connection, base);

    /* #TODO: http/2-ify the request (ex: add ":method" header). Should we mutate a copy or the original? Validate?
     *  Or just pass pointer to headers struct and let encoder transform it while encoding? */

    struct aws_h2_stream *stream = aws_h2_stream_new_request(client_connection, options);
    if (!stream) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Failed to create stream, error %d (%s)",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        return NULL;
    }

    int new_stream_error_code = (int)aws_atomic_load_int(&connection->synced_data.new_stream_error_code);
    if (new_stream_error_code) {
        aws_raise_error(new_stream_error_code);
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Cannot create request stream, error %d (%s)",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    AWS_H2_STREAM_LOG(DEBUG, stream, "Created HTTP/2 request stream"); /* #TODO: print method & path */
    return &stream->base;

error:
    /* Force destruction of the stream, avoiding ref counting */
    stream->base.vtable->destroy(&stream->base);
    return NULL;
}

static bool s_connection_is_open(const struct aws_http_connection *connection_base) {
    struct aws_h2_connection *connection = AWS_CONTAINER_OF(connection_base, struct aws_h2_connection, base);
    bool is_open = aws_atomic_load_int(&connection->synced_data.is_open);
    return is_open;
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;
    struct aws_h2_connection *connection = handler->impl;

    CONNECTION_LOGF(TRACE, connection, "Begin processing message of size %zu.", message->message_data.len);

    if (connection->thread_data.is_reading_stopped) {
        CONNECTION_LOG(ERROR, connection, "Cannot process message because connection is shutting down.");
        aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
        goto shutdown;
    }

    struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);
    if (aws_h2_decode(connection->thread_data.decoder, &message_cursor)) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Decoding message failed, error %d (%s). Closing connection",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto shutdown;
    }

    /* HTTP/2 protocol uses WINDOW_UPDATE frames to coordinate data rates with peer,
     * so we can just keep the aws_channel's read-window wide open */
    if (aws_channel_slot_increment_read_window(slot, message->message_data.len)) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Incrementing read window failed, error %d (%s). Closing connection",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto shutdown;
    }

    /* release message */
    if (message) {
        aws_mem_release(message->allocator, message);
        message = NULL;
    }

    /* Flush any outgoing frames that might have been queued as a result of decoder callbacks. */
    s_try_write_outgoing_frames(connection);
    return AWS_OP_SUCCESS;

shutdown:
    if (message) {
        aws_mem_release(message->allocator, message);
    }

    s_shutdown_due_to_read_err(connection, aws_last_error());
    return AWS_OP_SUCCESS;
}

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    (void)handler;
    (void)slot;
    (void)size;
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    struct aws_h2_connection *connection = handler->impl;
    CONNECTION_LOGF(
        TRACE,
        connection,
        "Channel shutting down in %s direction with error code %d (%s).",
        (dir == AWS_CHANNEL_DIR_READ) ? "read" : "write",
        error_code,
        aws_error_name(error_code));

    if (dir == AWS_CHANNEL_DIR_READ) {
        /* This call ensures that no further streams will be created. */
        s_stop(connection, true /*stop_reading*/, false /*stop_writing*/, false /*schedule_shutdown*/, error_code);

    } else /* AWS_CHANNEL_DIR_WRITE */ {
        s_stop(connection, false /*stop_reading*/, true /*stop_writing*/, false /*schedule_shutdown*/, error_code);

        /* Remove remaining streams from internal datastructures and mark them as complete. */

        struct aws_hash_iter stream_iter = aws_hash_iter_begin(&connection->thread_data.active_streams_map);
        while (!aws_hash_iter_done(&stream_iter)) {
            struct aws_h2_stream *stream = stream_iter.element.value;
            aws_hash_iter_delete(&stream_iter, true);
            aws_hash_iter_next(&stream_iter);

            s_stream_complete(connection, stream, AWS_ERROR_HTTP_CONNECTION_CLOSED);
        }

        /* It's OK to access synced_data.pending_stream_list without holding the lock because
         * no more streams can be added after s_stop() has been invoked. */
        while (!aws_linked_list_empty(&connection->synced_data.pending_stream_list)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->synced_data.pending_stream_list);
            struct aws_h2_stream *stream = AWS_CONTAINER_OF(node, struct aws_h2_stream, node);
            s_stream_complete(connection, stream, AWS_ERROR_HTTP_CONNECTION_CLOSED);
        }
    }

    aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
    return AWS_OP_SUCCESS;
}

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    /* HTTP/2 protocol uses WINDOW_UPDATE frames to coordinate data rates with peer,
     * so we can just keep the aws_channel's read-window wide open */
    return SIZE_MAX;
}

static size_t s_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    /* "All frames begin with a fixed 9-octet header followed by a variable-length payload" (RFC-7540 4.1) */
    return 9;
}
