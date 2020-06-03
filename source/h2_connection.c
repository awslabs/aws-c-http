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
#include <aws/http/private/strutil.h>

#include <aws/common/clock.h>
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
static void s_connection_close(struct aws_http_connection *connection_base);
static bool s_connection_is_open(const struct aws_http_connection *connection_base);
static void s_connection_update_window(struct aws_http_connection *connection_base, size_t increment_size);
static int s_connection_change_settings(
    struct aws_http_connection *connection_base,
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    aws_http2_on_change_settings_complete_fn *on_completed,
    void *user_data);
static int s_connection_ping(
    struct aws_http_connection *connection_base,
    const struct aws_byte_cursor *optional_opaque_data,
    aws_http2_on_ping_complete_fn *on_completed,
    void *user_data);

static void s_cross_thread_work_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_outgoing_frames_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static int s_encode_outgoing_frames_queue(struct aws_h2_connection *connection, struct aws_byte_buf *output);
static int s_encode_data_from_outgoing_streams(struct aws_h2_connection *connection, struct aws_byte_buf *output);
static int s_record_closed_stream(
    struct aws_h2_connection *connection,
    uint32_t stream_id,
    enum aws_h2_stream_closed_when closed_when);
static void s_stream_complete(struct aws_h2_connection *connection, struct aws_h2_stream *stream, int error_code);
static void s_write_outgoing_frames(struct aws_h2_connection *connection, bool first_try);
static void s_finish_shutdown(struct aws_h2_connection *connection);

static struct aws_h2err s_decoder_on_headers_begin(uint32_t stream_id, void *userdata);
static struct aws_h2err s_decoder_on_headers_i(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type,
    void *userdata);
static struct aws_h2err s_decoder_on_headers_end(
    uint32_t stream_id,
    bool malformed,
    enum aws_http_header_block block_type,
    void *userdata);
static struct aws_h2err s_decoder_on_push_promise(uint32_t stream_id, uint32_t promised_stream_id, void *userdata);
static struct aws_h2err s_decoder_on_data_begin(
    uint32_t stream_id,
    uint32_t payload_len,
    bool end_stream,
    void *userdata);
static struct aws_h2err s_decoder_on_data_i(uint32_t stream_id, struct aws_byte_cursor data, void *userdata);
static struct aws_h2err s_decoder_on_end_stream(uint32_t stream_id, void *userdata);
static struct aws_h2err s_decoder_on_rst_stream(uint32_t stream_id, uint32_t h2_error_code, void *userdata);
static struct aws_h2err s_decoder_on_ping_ack(uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE], void *userdata);
static struct aws_h2err s_decoder_on_ping(uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE], void *userdata);
static struct aws_h2err s_decoder_on_settings(
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    void *userdata);
static struct aws_h2err s_decoder_on_settings_ack(void *userdata);
static struct aws_h2err s_decoder_on_window_update(uint32_t stream_id, uint32_t window_size_increment, void *userdata);
struct aws_h2err s_decoder_on_goaway_begin(
    uint32_t last_stream,
    uint32_t error_code,
    uint32_t debug_data_length,
    void *userdata);

static struct aws_h2_pending_settings *s_new_pending_settings(
    struct aws_allocator *allocator,
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    aws_http2_on_change_settings_complete_fn *on_completed,
    void *user_data);

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
    .close = s_connection_close,
    .is_open = s_connection_is_open,
    .update_window = s_connection_update_window,
    .change_settings = s_connection_change_settings,
    .ping = s_connection_ping,
};

static const struct aws_h2_decoder_vtable s_h2_decoder_vtable = {
    .on_headers_begin = s_decoder_on_headers_begin,
    .on_headers_i = s_decoder_on_headers_i,
    .on_headers_end = s_decoder_on_headers_end,
    .on_push_promise_begin = s_decoder_on_push_promise,
    .on_data_begin = s_decoder_on_data_begin,
    .on_data_i = s_decoder_on_data_i,
    .on_end_stream = s_decoder_on_end_stream,
    .on_rst_stream = s_decoder_on_rst_stream,
    .on_ping_ack = s_decoder_on_ping_ack,
    .on_ping = s_decoder_on_ping,
    .on_settings = s_decoder_on_settings,
    .on_settings_ack = s_decoder_on_settings_ack,
    .on_window_update = s_decoder_on_window_update,
    .on_goaway_begin = s_decoder_on_goaway_begin,
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
    aws_atomic_store_int(&connection->atomic.new_stream_error_code, AWS_ERROR_HTTP_CONNECTION_CLOSED);
    aws_atomic_store_int(&connection->atomic.is_open, 0);

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

static void s_shutdown_due_to_write_err(struct aws_h2_connection *connection, int error_code) {
    AWS_PRECONDITION(error_code);

    if (connection->thread_data.channel_shutdown_waiting_for_goaway_to_be_written) {
        /* If shutdown is waiting for writes to complete, but writes are now broken,
         * then we must finish shutdown now */
        s_finish_shutdown(connection);
    } else {
        s_stop(connection, false /*stop_reading*/, true /*stop_writing*/, true /*schedule_shutdown*/, error_code);
    }
}

/* Common new() logic for server & client */
static struct aws_h2_connection *s_connection_new(
    struct aws_allocator *alloc,
    bool manual_window_management,
    const struct aws_http2_connection_options *http2_options,
    bool server) {

    AWS_PRECONDITION(http2_options);

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

    connection->on_goaway_received = http2_options->on_goaway_received;
    connection->on_remote_settings_change = http2_options->on_remote_settings_change;

    aws_channel_task_init(
        &connection->cross_thread_work_task, s_cross_thread_work_task, connection, "HTTP/2 cross-thread work");

    aws_channel_task_init(
        &connection->outgoing_frames_task, s_outgoing_frames_task, connection, "HTTP/2 outgoing frames");

    /* 1 refcount for user */
    aws_atomic_init_int(&connection->base.refcount, 1);

    aws_atomic_init_int(&connection->atomic.is_open, 1);
    aws_atomic_init_int(&connection->atomic.new_stream_error_code, 0);
    aws_linked_list_init(&connection->synced_data.pending_stream_list);
    aws_linked_list_init(&connection->synced_data.pending_frame_list);
    aws_linked_list_init(&connection->synced_data.pending_settings_list);
    aws_linked_list_init(&connection->synced_data.pending_ping_list);

    aws_linked_list_init(&connection->thread_data.outgoing_streams_list);
    aws_linked_list_init(&connection->thread_data.pending_settings_queue);
    aws_linked_list_init(&connection->thread_data.pending_ping_queue);
    aws_linked_list_init(&connection->thread_data.stalled_window_streams_list);
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

    connection->thread_data.closed_streams =
        aws_cache_new_fifo(alloc, aws_hash_ptr, aws_ptr_eq, NULL, NULL, http2_options->max_closed_streams);
    if (!connection->thread_data.closed_streams) {
        CONNECTION_LOGF(
            ERROR, connection, "FIFO cache init error %d (%s).", aws_last_error(), aws_error_name(aws_last_error()));
        goto error;
    }

    /* Initialize the value of settings */
    memcpy(connection->thread_data.settings_peer, aws_h2_settings_initial, sizeof(aws_h2_settings_initial));
    memcpy(connection->thread_data.settings_self, aws_h2_settings_initial, sizeof(aws_h2_settings_initial));

    connection->thread_data.window_size_peer = aws_h2_settings_initial[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE];
    connection->thread_data.window_size_self = aws_h2_settings_initial[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE];

    connection->thread_data.goaway_received_last_stream_id = AWS_H2_STREAM_ID_MAX;
    connection->thread_data.goaway_sent_last_stream_id = AWS_H2_STREAM_ID_MAX;

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
    /* User data from connection base is not ready until the handler installed */
    connection->thread_data.init_pending_settings = s_new_pending_settings(
        connection->base.alloc,
        http2_options->initial_settings_array,
        http2_options->num_initial_settings,
        http2_options->on_initial_settings_completed,
        NULL /* user_data is set later... */);
    if (!connection->thread_data.init_pending_settings) {
        goto error;
    }
    /* We enqueue the inital settings when handler get installed */
    return connection;

error:
    s_handler_destroy(&connection->base.channel_handler);

    return NULL;
}

struct aws_http_connection *aws_http_connection_new_http2_server(
    struct aws_allocator *allocator,
    bool manual_window_management,
    const struct aws_http2_connection_options *http2_options) {

    struct aws_h2_connection *connection = s_connection_new(allocator, manual_window_management, http2_options, true);
    if (!connection) {
        return NULL;
    }

    connection->base.server_data = &connection->base.client_or_server_data.server;

    return &connection->base;
}

struct aws_http_connection *aws_http_connection_new_http2_client(
    struct aws_allocator *allocator,
    bool manual_window_management,
    const struct aws_http2_connection_options *http2_options) {

    struct aws_h2_connection *connection = s_connection_new(allocator, manual_window_management, http2_options, false);
    if (!connection) {
        return NULL;
    }

    connection->base.client_data = &connection->base.client_or_server_data.client;

    return &connection->base;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_h2_connection *connection = handler->impl;
    CONNECTION_LOG(TRACE, connection, "Destroying connection");

    /* No streams should be left in internal datastructures */
    AWS_ASSERT(
        !aws_hash_table_is_valid(&connection->thread_data.active_streams_map) ||
        aws_hash_table_get_entry_count(&connection->thread_data.active_streams_map) == 0);

    AWS_ASSERT(aws_linked_list_empty(&connection->thread_data.stalled_window_streams_list));
    AWS_ASSERT(aws_linked_list_empty(&connection->thread_data.outgoing_streams_list));
    AWS_ASSERT(aws_linked_list_empty(&connection->synced_data.pending_stream_list));
    AWS_ASSERT(aws_linked_list_empty(&connection->synced_data.pending_frame_list));
    AWS_ASSERT(aws_linked_list_empty(&connection->synced_data.pending_settings_list));
    AWS_ASSERT(aws_linked_list_empty(&connection->synced_data.pending_ping_list));
    AWS_ASSERT(aws_linked_list_empty(&connection->thread_data.pending_ping_queue));
    AWS_ASSERT(aws_linked_list_empty(&connection->thread_data.pending_settings_queue));

    /* Clean up any unsent frames and structures */
    struct aws_linked_list *outgoing_frames_queue = &connection->thread_data.outgoing_frames_queue;
    while (!aws_linked_list_empty(outgoing_frames_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(outgoing_frames_queue);
        struct aws_h2_frame *frame = AWS_CONTAINER_OF(node, struct aws_h2_frame, node);
        aws_h2_frame_destroy(frame);
    }
    if (connection->thread_data.init_pending_settings) {
        /* if initial settings were never sent, we need to clear the memory here */
        aws_mem_release(connection->base.alloc, connection->thread_data.init_pending_settings);
    }
    aws_h2_decoder_destroy(connection->thread_data.decoder);
    aws_h2_frame_encoder_clean_up(&connection->thread_data.encoder);
    aws_hash_table_clean_up(&connection->thread_data.active_streams_map);
    aws_cache_destroy(connection->thread_data.closed_streams);
    aws_mutex_clean_up(&connection->synced_data.lock);
    aws_mem_release(connection->base.alloc, connection);
}

static struct aws_h2_pending_settings *s_new_pending_settings(
    struct aws_allocator *allocator,
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    aws_http2_on_change_settings_complete_fn *on_completed,
    void *user_data) {

    size_t settings_storage_size = sizeof(struct aws_http2_setting) * num_settings;
    struct aws_h2_pending_settings *pending_settings;
    void *settings_storage;
    if (!aws_mem_acquire_many(
            allocator,
            2,
            &pending_settings,
            sizeof(struct aws_h2_pending_settings),
            &settings_storage,
            settings_storage_size)) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*pending_settings);
    /* We buffer the settings up, incase the caller has freed them when the ACK arrives */
    pending_settings->settings_array = settings_storage;
    if (settings_array) {
        memcpy(pending_settings->settings_array, settings_array, num_settings * sizeof(struct aws_http2_setting));
    }
    pending_settings->num_settings = num_settings;
    pending_settings->on_completed = on_completed;
    pending_settings->user_data = user_data;

    return pending_settings;
}

static struct aws_h2_pending_ping *s_new_pending_ping(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *optional_opaque_data,
    const uint64_t started_time,
    void *user_data,
    aws_http2_on_ping_complete_fn *on_completed) {

    struct aws_h2_pending_ping *pending_ping = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_pending_ping));
    if (!pending_ping) {
        return NULL;
    }
    if (optional_opaque_data) {
        memcpy(pending_ping->opaque_data, optional_opaque_data->ptr, AWS_HTTP2_PING_DATA_SIZE);
    }
    pending_ping->started_time = started_time;
    pending_ping->on_completed = on_completed;
    pending_ping->user_data = user_data;
    return pending_ping;
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
            if (connection->thread_data.current_outgoing_frame == frame_i) {
                iter = iter->next;
                continue;
            }
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
    (void)task;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_h2_connection *connection = arg;
    s_write_outgoing_frames(connection, false /*first_try*/);
}

static void s_write_outgoing_frames(struct aws_h2_connection *connection, bool first_try) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    AWS_PRECONDITION(connection->thread_data.is_outgoing_frames_task_active);

    struct aws_channel_slot *channel_slot = connection->base.channel_slot;
    struct aws_linked_list *outgoing_frames_queue = &connection->thread_data.outgoing_frames_queue;
    struct aws_linked_list *outgoing_streams_list = &connection->thread_data.outgoing_streams_list;

    if (connection->thread_data.is_writing_stopped) {
        return;
    }

    /* Determine whether there's work to do, and end task immediately if there's not.
     * Note that we stop writing DATA frames if the channel is trying to shut down */
    bool has_control_frames = !aws_linked_list_empty(outgoing_frames_queue);
    bool has_data_frames = !aws_linked_list_empty(outgoing_streams_list);
    bool may_write_data_frames = (connection->thread_data.window_size_peer > AWS_H2_MIN_WINDOW_SIZE) &&
                                 !connection->thread_data.channel_shutdown_waiting_for_goaway_to_be_written;
    bool will_write = has_control_frames || (has_data_frames && may_write_data_frames);

    if (!will_write) {
        if (!first_try) {
            CONNECTION_LOGF(
                TRACE,
                connection,
                "Outgoing frames task stopped. has_control_frames:%d has_data_frames:%d may_write_data_frames:%d",
                has_control_frames,
                has_data_frames,
                may_write_data_frames);
        }

        connection->thread_data.is_outgoing_frames_task_active = false;

        if (connection->thread_data.channel_shutdown_waiting_for_goaway_to_be_written) {
            s_finish_shutdown(connection);
        }

        return;
    }

    if (first_try) {
        CONNECTION_LOG(TRACE, connection, "Starting outgoing frames task");
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

    /* If outgoing_frames_queue emptied, and connection is running normally,
     * then write as many DATA frames from outgoing_streams_list as possible. */
    if (aws_linked_list_empty(outgoing_frames_queue) && may_write_data_frames) {
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

        aws_channel_schedule_task_now(channel_slot->channel, &connection->outgoing_frames_task);
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
        connection->thread_data.current_outgoing_frame = frame;
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
        connection->thread_data.current_outgoing_frame = NULL;
    }

    return AWS_OP_SUCCESS;
}

/* Write as many DATA frames from outgoing_streams_list as possible. */
static int s_encode_data_from_outgoing_streams(struct aws_h2_connection *connection, struct aws_byte_buf *output) {

    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    struct aws_linked_list *outgoing_streams_list = &connection->thread_data.outgoing_streams_list;
    struct aws_linked_list *stalled_window_streams_list = &connection->thread_data.stalled_window_streams_list;

    /* If a stream stalls, put it in this list until the function ends so we don't keep trying to read from it.
     * We put it back at the end of function. */
    struct aws_linked_list stalled_streams_list;
    aws_linked_list_init(&stalled_streams_list);

    int aws_error_code = 0;

    /* We simply round-robin through streams, instead of using stream priority.
     * Respecting priority is not required (RFC-7540 5.3), so we're ignoring it for now. This also keeps use safe
     * from priority DOS attacks: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9513 */
    while (!aws_linked_list_empty(outgoing_streams_list)) {
        if (connection->thread_data.window_size_peer <= AWS_H2_MIN_WINDOW_SIZE) {
            CONNECTION_LOGF(
                DEBUG,
                connection,
                "Peer connection's flow-control window is too small now %zu. Connection will stop sending DATA until "
                "WINDOW_UPDATE is received.",
                connection->thread_data.window_size_peer);
            break;
        }

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
        int data_encode_status;
        if (aws_h2_stream_encode_data_frame(stream, &connection->thread_data.encoder, output, &data_encode_status)) {

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
        switch (data_encode_status) {
            case AWS_H2_DATA_ENCODE_COMPLETE:
                break;
            case AWS_H2_DATA_ENCODE_ONGOING:
                aws_linked_list_push_back(outgoing_streams_list, node);
                break;
            case AWS_H2_DATA_ENCODE_ONGOING_BODY_STALLED:
                aws_linked_list_push_back(&stalled_streams_list, node);
                break;
            case AWS_H2_DATA_ENCODE_ONGOING_WINDOW_STALLED:
                aws_linked_list_push_back(stalled_window_streams_list, node);
                AWS_H2_STREAM_LOG(
                    DEBUG,
                    stream,
                    "Peer stream's flow-control window is too small. Data frames on this stream will not be sent until "
                    "WINDOW_UPDATE. ");
                break;
            default:
                CONNECTION_LOG(ERROR, connection, "Data encode status is invalid.");
                aws_error_code = AWS_ERROR_INVALID_STATE;
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
void aws_h2_try_write_outgoing_frames(struct aws_h2_connection *connection) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    if (connection->thread_data.is_outgoing_frames_task_active) {
        return;
    }

    connection->thread_data.is_outgoing_frames_task_active = true;
    s_write_outgoing_frames(connection, true /*first_try*/);
}

/**
 * Returns successfully and sets `out_stream` if stream is currently active.
 * Returns successfully and sets `out_stream` to NULL if the frame should be ignored.
 * Returns failed aws_h2err if it is a connection error to receive this frame.
 */
struct aws_h2err s_get_active_stream_for_incoming_frame(
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
        return AWS_H2ERR_SUCCESS;
    }

    bool client_initiated = (stream_id % 2) == 1;
    bool self_initiated_stream = client_initiated && (connection->base.client_data != NULL);
    bool peer_initiated_stream = !self_initiated_stream;

    if ((self_initiated_stream && stream_id >= connection->base.next_stream_id) ||
        (peer_initiated_stream && stream_id > connection->thread_data.latest_peer_initiated_stream_id)) {
        /* Illegal to receive frames for a stream in the idle state (stream doesn't exist yet)
         * (except server receiving HEADERS to start a stream, but that's handled elsewhere) */
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Illegal to receive %s frame on stream id=%" PRIu32 " state=IDLE",
            aws_h2_frame_type_to_str(frame_type),
            stream_id);
        return aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR);
    }

    if (peer_initiated_stream && stream_id > connection->thread_data.goaway_sent_last_stream_id) {
        /* Once GOAWAY sent, ignore frames for peer-initiated streams whose id > last-stream-id */
        CONNECTION_LOGF(
            TRACE,
            connection,
            "Ignoring %s frame on stream id=%" PRIu32 " because GOAWAY sent with last-stream-id=%" PRIu32,
            aws_h2_frame_type_to_str(frame_type),
            stream_id,
            connection->thread_data.goaway_sent_last_stream_id);

        return AWS_H2ERR_SUCCESS;
    }

    void *cached_value = NULL;
    /* Stream is closed, check whether it's legal for a few more frames to trickle in */
    if (aws_cache_find(connection->thread_data.closed_streams, stream_id_key, &cached_value)) {
        return aws_h2err_from_last_error();
    }
    if (cached_value) {
        if (frame_type == AWS_H2_FRAME_T_PRIORITY) {
            /* If we support PRIORITY, do something here. Right now just ignore it */
            return AWS_H2ERR_SUCCESS;
        }
        enum aws_h2_stream_closed_when closed_when = (enum aws_h2_stream_closed_when)(size_t)cached_value;
        switch (closed_when) {
            case AWS_H2_STREAM_CLOSED_WHEN_BOTH_SIDES_END_STREAM:
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

                    return AWS_H2ERR_SUCCESS;
                } else {
                    CONNECTION_LOGF(
                        ERROR,
                        connection,
                        "Illegal to receive %s frame on stream id=%" PRIu32 " after END_STREAM has been received.",
                        aws_h2_frame_type_to_str(frame_type),
                        stream_id);

                    return aws_h2err_from_h2_code(AWS_HTTP2_ERR_STREAM_CLOSED);
                }
                break;
            case AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_RECEIVED:
                /* An endpoint that receives any frame other than PRIORITY after receiving a RST_STREAM
                 * MUST treat that as a stream error (Section 5.4.2) of type STREAM_CLOSED */
                CONNECTION_LOGF(
                    ERROR,
                    connection,
                    "Illegal to receive %s frame on stream id=%" PRIu32 " after RST_STREAM has been received",
                    aws_h2_frame_type_to_str(frame_type),
                    stream_id);
                struct aws_h2_frame *rst_stream =
                    aws_h2_frame_new_rst_stream(connection->base.alloc, stream_id, AWS_HTTP2_ERR_STREAM_CLOSED);
                if (!rst_stream) {
                    CONNECTION_LOGF(
                        ERROR, connection, "Error creating RST_STREAM frame, %s", aws_error_name(aws_last_error()));
                    return aws_h2err_from_last_error();
                }
                aws_h2_connection_enqueue_outgoing_frame(connection, rst_stream);
                return AWS_H2ERR_SUCCESS;
            case AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_SENT:
                /* An endpoint MUST ignore frames that it receives on closed streams after it has sent a RST_STREAM
                 * frame */
                CONNECTION_LOGF(
                    TRACE,
                    connection,
                    "Ignoring %s frame on stream id=%" PRIu32 " because RST_STREAM was recently sent.",
                    aws_h2_frame_type_to_str(frame_type),
                    stream_id);

                return AWS_H2ERR_SUCCESS;
                break;
            default:
                CONNECTION_LOGF(
                    ERROR, connection, "Invalid state fo cached closed stream, stream id=%" PRIu32, stream_id);
                return aws_h2err_from_h2_code(AWS_HTTP2_ERR_INTERNAL_ERROR);
                break;
        }
    }
    if (frame_type == AWS_H2_FRAME_T_PRIORITY) {
        /* ignored if the stream has been removed from the dependency tree */
        return AWS_H2ERR_SUCCESS;
    }

    /* Stream closed (purged from closed_streams, or implicitly closed when its ID was skipped) */
    CONNECTION_LOGF(
        ERROR,
        connection,
        "Illegal to receive %s frame on stream id=%" PRIu32
        ", no memory of closed stream (ID skipped, or removed from cache)",
        aws_h2_frame_type_to_str(frame_type),
        stream_id);

    return aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR);
}

/* Decoder callbacks */

struct aws_h2err s_decoder_on_headers_begin(uint32_t stream_id, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    if (connection->base.server_data) {
        /* Server would create new request-handler stream... */
        return aws_h2err_from_aws_code(AWS_ERROR_UNIMPLEMENTED);
    }

    struct aws_h2_stream *stream;
    struct aws_h2err err =
        s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_HEADERS, &stream);
    if (aws_h2err_failed(err)) {
        return err;
    }

    if (stream) {
        err = aws_h2_stream_on_decoder_headers_begin(stream);
        if (aws_h2err_failed(err)) {
            return err;
        }
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err s_decoder_on_headers_i(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type,
    void *userdata) {

    struct aws_h2_connection *connection = userdata;
    struct aws_h2_stream *stream;
    struct aws_h2err err =
        s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_HEADERS, &stream);
    if (aws_h2err_failed(err)) {
        return err;
    }

    if (stream) {
        err = aws_h2_stream_on_decoder_headers_i(stream, header, name_enum, block_type);
        if (aws_h2err_failed(err)) {
            return err;
        }
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err s_decoder_on_headers_end(
    uint32_t stream_id,
    bool malformed,
    enum aws_http_header_block block_type,
    void *userdata) {

    struct aws_h2_connection *connection = userdata;
    struct aws_h2_stream *stream;
    struct aws_h2err err =
        s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_HEADERS, &stream);
    if (aws_h2err_failed(err)) {
        return err;
    }

    if (stream) {
        err = aws_h2_stream_on_decoder_headers_end(stream, malformed, block_type);
        if (aws_h2err_failed(err)) {
            return err;
        }
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err s_decoder_on_push_promise(uint32_t stream_id, uint32_t promised_stream_id, void *userdata) {
    struct aws_h2_connection *connection = userdata;
    AWS_ASSERT(connection->base.client_data); /* decoder has already enforced this */
    AWS_ASSERT(promised_stream_id % 2 == 0);  /* decoder has already enforced this  */

    /* The identifier of a newly established stream MUST be numerically greater
     * than all streams that the initiating endpoint has opened or reserved (RFC-7540 5.1.1) */
    if (promised_stream_id <= connection->thread_data.latest_peer_initiated_stream_id) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Newly promised stream ID %" PRIu32 " must be higher than previously established ID %" PRIu32,
            promised_stream_id,
            connection->thread_data.latest_peer_initiated_stream_id);
        return aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR);
    }
    connection->thread_data.latest_peer_initiated_stream_id = promised_stream_id;

    /* If we ever fully support PUSH_PROMISE, this is where we'd add the
     * promised_stream_id to some reserved_streams datastructure */

    struct aws_h2_stream *stream;
    struct aws_h2err err =
        s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_PUSH_PROMISE, &stream);
    if (aws_h2err_failed(err)) {
        return err;
    }

    if (stream) {
        err = aws_h2_stream_on_decoder_push_promise(stream, promised_stream_id);
        if (aws_h2err_failed(err)) {
            return err;
        }
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err s_decoder_on_data_begin(uint32_t stream_id, uint32_t payload_len, bool end_stream, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    /* A receiver that receives a flow-controlled frame MUST always account for its contribution against the connection
     * flow-control window, unless the receiver treats this as a connection error */
    if (aws_sub_size_checked(
            connection->thread_data.window_size_self, payload_len, &connection->thread_data.window_size_self)) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "DATA length %" PRIu32 " exceeds flow-control window %zu",
            payload_len,
            connection->thread_data.window_size_self);
        return aws_h2err_from_h2_code(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR);
    }

    struct aws_h2_stream *stream;
    struct aws_h2err err = s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_DATA, &stream);
    if (aws_h2err_failed(err)) {
        return err;
    }

    if (stream) {
        err = aws_h2_stream_on_decoder_data_begin(stream, payload_len, end_stream);
        if (aws_h2err_failed(err)) {
            return err;
        }
    }

    /* if manual_window_management is false, we will automatically maintain the connection self window size */
    if (payload_len != 0 && !connection->base.manual_window_management) {
        struct aws_h2_frame *connection_window_update_frame =
            aws_h2_frame_new_window_update(connection->base.alloc, 0, payload_len);
        if (!connection_window_update_frame) {
            CONNECTION_LOGF(
                ERROR,
                connection,
                "WINDOW_UPDATE frame on connection failed to be sent, error %s",
                aws_error_name(aws_last_error()));
            return aws_h2err_from_last_error();
        }
        aws_h2_connection_enqueue_outgoing_frame(connection, connection_window_update_frame);
        connection->thread_data.window_size_self += payload_len;
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err s_decoder_on_data_i(uint32_t stream_id, struct aws_byte_cursor data, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    /* Pass data to stream */
    struct aws_h2_stream *stream;
    struct aws_h2err err = s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_DATA, &stream);
    if (aws_h2err_failed(err)) {
        return err;
    }

    if (stream) {
        err = aws_h2_stream_on_decoder_data_i(stream, data);
        if (aws_h2err_failed(err)) {
            return err;
        }
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err s_decoder_on_end_stream(uint32_t stream_id, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    /* Not calling s_get_active_stream_for_incoming_frame() here because END_STREAM
     * isn't an actual frame type. It's a flag on DATA or HEADERS frames, and we
     * already checked the legality of those frames in their respective callbacks. */

    struct aws_hash_element *found = NULL;
    aws_hash_table_find(&connection->thread_data.active_streams_map, (void *)(size_t)stream_id, &found);
    if (found) {
        struct aws_h2_stream *stream = found->value;
        struct aws_h2err err = aws_h2_stream_on_decoder_end_stream(stream);
        if (aws_h2err_failed(err)) {
            return err;
        }
    }

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_rst_stream(uint32_t stream_id, uint32_t h2_error_code, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    /* Pass RST_STREAM to stream */
    struct aws_h2_stream *stream;
    struct aws_h2err err =
        s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_RST_STREAM, &stream);
    if (aws_h2err_failed(err)) {
        return err;
    }

    if (stream) {
        err = aws_h2_stream_on_decoder_rst_stream(stream, h2_error_code);
        if (aws_h2err_failed(err)) {
            return err;
        }
    }

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_ping_ack(uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE], void *userdata) {
    struct aws_h2_connection *connection = userdata;
    if (aws_linked_list_empty(&connection->thread_data.pending_ping_queue)) {
        CONNECTION_LOG(ERROR, connection, "Received extraneous PING ACK.");
        return aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR);
    }
    struct aws_h2err err;
    struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->thread_data.pending_ping_queue);
    struct aws_h2_pending_ping *pending_ping = AWS_CONTAINER_OF(node, struct aws_h2_pending_ping, node);
    /* Check the payload */
    if (!aws_array_eq(opaque_data, AWS_HTTP2_PING_DATA_SIZE, pending_ping->opaque_data, AWS_HTTP2_PING_DATA_SIZE)) {
        CONNECTION_LOG(ERROR, connection, "Received PING ACK with mismatched opaque-data.");
        err = aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR);
        goto error;
    }
    uint64_t time_stamp;
    if (aws_high_res_clock_get_ticks(&time_stamp)) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Failed getting the time stamp when PING ACK received, error %s",
            aws_error_name(aws_last_error()));
        err = aws_h2err_from_last_error();
        goto error;
    }
    uint64_t rtt;
    if (aws_sub_u64_checked(time_stamp, pending_ping->started_time, &rtt)) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Overflow from time stamp when PING ACK received, error %s",
            aws_error_name(aws_last_error()));
        err = aws_h2err_from_last_error();
        goto error;
    }
    CONNECTION_LOGF(TRACE, connection, "Round trip time is %lf ms, approximately", (double)rtt / 1000000);
    /* fire the callback */
    if (pending_ping->on_completed) {
        pending_ping->on_completed(&connection->base, rtt, AWS_ERROR_SUCCESS, pending_ping->user_data);
    }
    aws_mem_release(connection->base.alloc, pending_ping);
    return AWS_H2ERR_SUCCESS;
error:
    if (pending_ping->on_completed) {
        pending_ping->on_completed(&connection->base, 0 /* fake rtt */, err.aws_code, pending_ping->user_data);
    }
    aws_mem_release(connection->base.alloc, pending_ping);
    return err;
}

static struct aws_h2err s_decoder_on_ping(uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE], void *userdata) {
    struct aws_h2_connection *connection = userdata;

    /* send a PING frame with the ACK flag set in response, with an identical payload. */
    struct aws_h2_frame *ping_ack_frame = aws_h2_frame_new_ping(connection->base.alloc, true, opaque_data);
    if (!ping_ack_frame) {
        CONNECTION_LOGF(
            ERROR, connection, "Ping ACK frame failed to be sent, error %s", aws_error_name(aws_last_error()));
        return aws_h2err_from_last_error();
    }

    aws_h2_connection_enqueue_outgoing_frame(connection, ping_ack_frame);
    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_settings(
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    void *userdata) {
    struct aws_h2_connection *connection = userdata;
    struct aws_h2err err;
    /* Once all values have been processed, the recipient MUST immediately emit a SETTINGS frame with the ACK flag
     * set.(RFC-7540 6.5.3) */
    CONNECTION_LOG(TRACE, connection, "Setting frame processing ends");
    struct aws_h2_frame *settings_ack_frame = aws_h2_frame_new_settings(connection->base.alloc, NULL, 0, true);
    if (!settings_ack_frame) {
        CONNECTION_LOGF(
            ERROR, connection, "Settings ACK frame failed to be sent, error %s", aws_error_name(aws_last_error()));
        return aws_h2err_from_last_error();
    }
    aws_h2_connection_enqueue_outgoing_frame(connection, settings_ack_frame);

    /* Allocate a block of memory for settings_array in callback, which will only includes the settings we changed,
     * freed once the callback finished */
    struct aws_http2_setting *callback_array = NULL;
    if (num_settings) {
        callback_array = aws_mem_acquire(connection->base.alloc, num_settings * sizeof(struct aws_http2_setting));
        if (!callback_array) {
            return aws_h2err_from_last_error();
        }
    }
    size_t callback_array_num = 0;

    /* Apply the change to encoder and connection */
    struct aws_h2_frame_encoder *encoder = &connection->thread_data.encoder;
    for (size_t i = 0; i < num_settings; i++) {
        if (connection->thread_data.settings_peer[settings_array[i].id] == settings_array[i].value) {
            /* No change, don't do any work */
            continue;
        }
        switch (settings_array[i].id) {
            case AWS_HTTP2_SETTINGS_HEADER_TABLE_SIZE: {
                aws_h2_frame_encoder_set_setting_header_table_size(encoder, settings_array[i].value);
            } break;
            case AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE: {
                /* When the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST adjust the size of all stream
                 * flow-control windows that it maintains by the difference between the new value and the old value. */
                int32_t size_changed =
                    settings_array[i].value - connection->thread_data.settings_peer[settings_array[i].id];
                struct aws_hash_iter stream_iter = aws_hash_iter_begin(&connection->thread_data.active_streams_map);
                while (!aws_hash_iter_done(&stream_iter)) {
                    struct aws_h2_stream *stream = stream_iter.element.value;
                    aws_hash_iter_next(&stream_iter);
                    err = aws_h2_stream_window_size_change(stream, size_changed, false /*self*/);
                    if (aws_h2err_failed(err)) {
                        CONNECTION_LOG(
                            ERROR,
                            connection,
                            "Connection error, change to SETTINGS_INITIAL_WINDOW_SIZE caused a stream's flow-control "
                            "window to exceed the maximum size");
                        goto error;
                    }
                }
            } break;
            case AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE: {
                aws_h2_frame_encoder_set_setting_max_frame_size(encoder, settings_array[i].value);
            } break;
            default:
                break;
        }
        connection->thread_data.settings_peer[settings_array[i].id] = settings_array[i].value;
        callback_array[callback_array_num++] = settings_array[i];
    }
    if (connection->on_remote_settings_change) {
        connection->on_remote_settings_change(
            &connection->base, callback_array, callback_array_num, connection->base.user_data);
    }
    aws_mem_release(connection->base.alloc, callback_array);
    return AWS_H2ERR_SUCCESS;
error:
    aws_mem_release(connection->base.alloc, callback_array);
    return err;
}

static struct aws_h2err s_decoder_on_settings_ack(void *userdata) {
    struct aws_h2_connection *connection = userdata;
    if (aws_linked_list_empty(&connection->thread_data.pending_settings_queue)) {
        CONNECTION_LOG(ERROR, connection, "Received a malicious extra SETTINGS acknowledgment");
        return aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR);
    }
    struct aws_h2err err;
    struct aws_h2_pending_settings *pending_settings = NULL;
    struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->thread_data.pending_settings_queue);
    pending_settings = AWS_CONTAINER_OF(node, struct aws_h2_pending_settings, node);

    struct aws_http2_setting *settings_array = pending_settings->settings_array;
    /* Apply the settings */
    struct aws_h2_decoder *decoder = connection->thread_data.decoder;
    for (size_t i = 0; i < pending_settings->num_settings; i++) {
        if (connection->thread_data.settings_self[settings_array[i].id] == settings_array[i].value) {
            /* No change, don't do any work */
            continue;
        }
        switch (settings_array[i].id) {
            case AWS_HTTP2_SETTINGS_HEADER_TABLE_SIZE: {
                aws_h2_decoder_set_setting_header_table_size(decoder, settings_array[i].value);
            } break;
            case AWS_HTTP2_SETTINGS_ENABLE_PUSH: {
                aws_h2_decoder_set_setting_enable_push(decoder, settings_array[i].value);
            } break;
            case AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE: {
                /* When the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST adjust the size of all stream
                 * flow-control windows that it maintains by the difference between the new value and the old value. */
                int32_t size_changed =
                    settings_array[i].value - connection->thread_data.settings_self[settings_array[i].id];
                struct aws_hash_iter stream_iter = aws_hash_iter_begin(&connection->thread_data.active_streams_map);
                while (!aws_hash_iter_done(&stream_iter)) {
                    struct aws_h2_stream *stream = stream_iter.element.value;
                    aws_hash_iter_next(&stream_iter);
                    err = aws_h2_stream_window_size_change(stream, size_changed, true /*self*/);
                    if (aws_h2err_failed(err)) {
                        CONNECTION_LOG(
                            ERROR,
                            connection,
                            "Connection error, change to SETTINGS_INITIAL_WINDOW_SIZE from internal caused a stream's "
                            "flow-control window to exceed the maximum size");
                        goto error;
                    }
                }
            } break;
            case AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE: {
                aws_h2_decoder_set_setting_max_frame_size(decoder, settings_array[i].value);
            } break;
            default:
                break;
        }
        connection->thread_data.settings_self[settings_array[i].id] = settings_array[i].value;
    }
    /* invoke the change settings compeleted user callback */
    if (pending_settings->on_completed) {
        pending_settings->on_completed(&connection->base, AWS_ERROR_SUCCESS, pending_settings->user_data);
    }
    /* clean up the pending_settings */
    aws_mem_release(connection->base.alloc, pending_settings);
    return AWS_H2ERR_SUCCESS;
error:
    /* invoke the user callback with error code */
    if (pending_settings->on_completed) {
        pending_settings->on_completed(&connection->base, err.aws_code, pending_settings->user_data);
    }
    /* clean up the pending settings here */
    aws_mem_release(connection->base.alloc, pending_settings);
    return err;
}

static struct aws_h2err s_decoder_on_window_update(uint32_t stream_id, uint32_t window_size_increment, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    if (stream_id == 0) {
        /* Let's update the connection flow-control window size */
        if (window_size_increment == 0) {
            /* flow-control window increment of 0 MUST be treated as error (RFC7540 6.9.1) */
            CONNECTION_LOG(ERROR, connection, "Window update frame with 0 increment size")
            return aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR);
        }
        if (connection->thread_data.window_size_peer + window_size_increment > AWS_H2_WINDOW_UPDATE_MAX) {
            /* We MUST NOT allow a flow-control window to exceed the max */
            CONNECTION_LOG(
                ERROR,
                connection,
                "Window update frame causes the connection flow-control window exceeding the maximum size")
            return aws_h2err_from_h2_code(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR);
        }
        if (connection->thread_data.window_size_peer <= AWS_H2_MIN_WINDOW_SIZE) {
            CONNECTION_LOGF(
                DEBUG,
                connection,
                "Peer connection's flow-control window is resumed from too small to %" PRIu32
                ". Connection will resume sending DATA.",
                window_size_increment);
        }
        connection->thread_data.window_size_peer += window_size_increment;
        return AWS_H2ERR_SUCCESS;
    } else {
        /* Update the flow-control window size for stream */
        struct aws_h2_stream *stream;
        bool window_resume;
        struct aws_h2err err =
            s_get_active_stream_for_incoming_frame(connection, stream_id, AWS_H2_FRAME_T_WINDOW_UPDATE, &stream);
        if (aws_h2err_failed(err)) {
            return err;
        }
        if (stream) {
            err = aws_h2_stream_on_decoder_window_update(stream, window_size_increment, &window_resume);
            if (aws_h2err_failed(err)) {
                return err;
            }
            if (window_resume) {
                /* Set the stream free from stalled list */
                AWS_H2_STREAM_LOGF(
                    DEBUG,
                    stream,
                    "Peer stream's flow-control window is resumed from 0 or negative to %" PRIu32
                    " Stream will resume sending data.",
                    stream->thread_data.window_size_peer);
                aws_linked_list_remove(&stream->node);
                aws_linked_list_push_back(&connection->thread_data.outgoing_streams_list, &stream->node);
            }
        }
    }
    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err s_decoder_on_goaway_begin(
    uint32_t last_stream,
    uint32_t error_code,
    uint32_t debug_data_length,
    void *userdata) {
    (void)debug_data_length;
    struct aws_h2_connection *connection = userdata;

    if (last_stream > connection->thread_data.goaway_received_last_stream_id) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Received GOAWAY with invalid last-stream-id=%" PRIu32 ", must not exceed previous last-stream-id=%" PRIu32,
            last_stream,
            connection->thread_data.goaway_received_last_stream_id);
        return aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR);
    }
    /* stop sending any new stream and making new request */
    aws_atomic_store_int(&connection->atomic.new_stream_error_code, AWS_ERROR_HTTP_GOAWAY_RECEIVED);
    connection->thread_data.goaway_received_last_stream_id = last_stream;
    CONNECTION_LOGF(
        DEBUG,
        connection,
        "Received GOAWAY error-code=%s(0x%x) last-stream-id=%" PRIu32,
        aws_http2_error_code_to_str(error_code),
        error_code,
        last_stream);
    /* Complete activated streams whose id is higher than last_stream, since they will not process by peer. We should
     * treat them as they had never been created at all.
     * This would be more efficient if we could iterate streams in reverse-id order */
    struct aws_hash_iter stream_iter = aws_hash_iter_begin(&connection->thread_data.active_streams_map);
    while (!aws_hash_iter_done(&stream_iter)) {
        struct aws_h2_stream *stream = stream_iter.element.value;
        aws_hash_iter_next(&stream_iter);
        if (stream->base.id > last_stream) {
            AWS_H2_STREAM_LOG(
                DEBUG,
                stream,
                "stream ID is higher than GOAWAY last stream ID, please retry this stream on a new connection.");
            s_stream_complete(connection, stream, AWS_ERROR_HTTP_GOAWAY_RECEIVED);
        }
    }

    /* #TODO inform user about debug data by fire some kind of API. We buffer it at connection? Or we do a sperate
     * callback on each part of it */
    if (connection->on_goaway_received) {
        /* Inform user about goaway received and the error code. */
        connection->on_goaway_received(&connection->base, last_stream, error_code, connection->base.user_data);
    }
    return AWS_H2ERR_SUCCESS;
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
    struct aws_h2_pending_settings *init_pending_settings = connection->thread_data.init_pending_settings;
    aws_linked_list_push_back(&connection->thread_data.pending_settings_queue, &init_pending_settings->node);
    connection->thread_data.init_pending_settings = NULL;
    /* Set user_data here, the user_data is valid now */
    init_pending_settings->user_data = connection->base.user_data;

    struct aws_h2_frame *init_settings_frame = aws_h2_frame_new_settings(
        connection->base.alloc,
        init_pending_settings->settings_array,
        init_pending_settings->num_settings,
        false /*ACK*/);
    if (!init_settings_frame) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Failed to create the initial settings frame, error %s",
            aws_error_name(aws_last_error()));
        aws_mem_release(connection->base.alloc, init_pending_settings);
        goto error;
    }
    /* enqueue the initial settings frame here */
    aws_linked_list_push_back(&connection->thread_data.outgoing_frames_queue, &init_settings_frame->node);

    aws_h2_try_write_outgoing_frames(connection);
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

struct aws_http_headers *aws_h2_create_headers_from_request(
    struct aws_http_message *request,
    struct aws_allocator *alloc) {

    struct aws_http_headers *old_headers = aws_http_message_get_headers(request);
    bool is_pseudoheader = false;
    struct aws_http_headers *result = aws_http_headers_new(alloc);
    struct aws_http_header header_iter;
    struct aws_byte_buf lower_name_buf;
    AWS_ZERO_STRUCT(lower_name_buf);

    /* Check whether the old_headers have pseudo header or not */
    if (aws_http_headers_count(old_headers)) {
        if (aws_http_headers_get_index(old_headers, 0, &header_iter)) {
            goto error;
        }
        is_pseudoheader = header_iter.name.ptr[0] == ':';
    }
    if (!is_pseudoheader) {
        /* TODO: Set pseudo headers all from message, which will lead an API change to aws_http_message */
        /* No pseudoheader detected, we set them from the request */
        /* Set pseudo headers */
        struct aws_byte_cursor method;
        if (aws_http_message_get_request_method(request, &method)) {
            /* error will happen when the request is invalid */
            aws_raise_error(AWS_ERROR_HTTP_INVALID_METHOD);
            goto error;
        }
        if (aws_http_headers_add(result, aws_http_header_method, method)) {
            goto error;
        }
        /* we set a default value, "https", for now */
        struct aws_byte_cursor scheme_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("https");
        if (aws_http_headers_add(result, aws_http_header_scheme, scheme_cursor)) {
            goto error;
        }
        /* Set an empty authority for now, if host header field is found, we set it as the value of host */
        struct aws_byte_cursor authority_cursor;
        struct aws_byte_cursor host_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("host");
        if (!aws_http_headers_get(old_headers, host_cursor, &authority_cursor)) {
            if (aws_http_headers_add(result, aws_http_header_authority, authority_cursor)) {
                goto error;
            }
        }
        struct aws_byte_cursor path_cursor;
        if (aws_http_message_get_request_path(request, &path_cursor)) {
            aws_raise_error(AWS_ERROR_HTTP_INVALID_PATH);
            goto error;
        }
        if (aws_http_headers_add(result, aws_http_header_path, path_cursor)) {
            goto error;
        }
    }
    /* if pseudoheader is included in message, we just convert all the headers from old_headers to result */
    if (aws_byte_buf_init(&lower_name_buf, alloc, 256)) {
        goto error;
    }
    for (size_t iter = 0; iter < aws_http_headers_count(old_headers); iter++) {
        /* name should be converted to lower case */
        if (aws_http_headers_get_index(old_headers, iter, &header_iter)) {
            goto error;
        }
        /* append lower case name to the buffer */
        aws_byte_buf_append_with_lookup(&lower_name_buf, &header_iter.name, aws_lookup_table_to_lower_get());
        struct aws_byte_cursor lower_name_cursor = aws_byte_cursor_from_buf(&lower_name_buf);
        enum aws_http_header_name name_enum = aws_http_lowercase_str_to_header_name(lower_name_cursor);
        switch (name_enum) {
            case AWS_HTTP_HEADER_COOKIE:
                /* split cookie if USE CACHE */
                if (header_iter.compression == AWS_HTTP_HEADER_COMPRESSION_USE_CACHE) {
                    struct aws_byte_cursor cookie_chunk;
                    AWS_ZERO_STRUCT(cookie_chunk);
                    while (aws_byte_cursor_next_split(&header_iter.value, ';', &cookie_chunk)) {
                        if (aws_http_headers_add(
                                result, lower_name_cursor, aws_strutil_trim_http_whitespace(cookie_chunk))) {
                            goto error;
                        }
                    }
                } else {
                    if (aws_http_headers_add(result, lower_name_cursor, header_iter.value)) {
                        goto error;
                    }
                }
                break;
            case AWS_HTTP_HEADER_HOST:
                /* host header has been converted to :authority, do nothing here */
                break;
            /* TODO: handle connection-specific header field (RFC7540 8.1.2.2) */
            default:
                if (aws_http_headers_add(result, lower_name_cursor, header_iter.value)) {
                    goto error;
                }
                break;
        }
        aws_byte_buf_reset(&lower_name_buf, false);
    }
    aws_byte_buf_clean_up(&lower_name_buf);
    return result;
error:
    aws_http_headers_release(result);
    aws_byte_buf_clean_up(&lower_name_buf);
    return NULL;
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

    if (s_record_closed_stream(connection, stream_id, closed_when)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_record_closed_stream(
    struct aws_h2_connection *connection,
    uint32_t stream_id,
    enum aws_h2_stream_closed_when closed_when) {

    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    if (aws_cache_put(connection->thread_data.closed_streams, (void *)(size_t)stream_id, (void *)(size_t)closed_when)) {
        CONNECTION_LOG(ERROR, connection, "Failed inserting ID into cache of recently closed streams");
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_h2_connection_send_rst_and_close_reserved_stream(
    struct aws_h2_connection *connection,
    uint32_t stream_id,
    uint32_t h2_error_code) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    struct aws_h2_frame *rst_stream = aws_h2_frame_new_rst_stream(connection->base.alloc, stream_id, h2_error_code);
    if (!rst_stream) {
        CONNECTION_LOGF(ERROR, connection, "Error creating RST_STREAM frame, %s", aws_error_name(aws_last_error()));
        return AWS_OP_ERR;
    }
    aws_h2_connection_enqueue_outgoing_frame(connection, rst_stream);

    /* If we ever fully support PUSH_PROMISE, this is where we'd remove the
     * promised_stream_id from some reserved_streams datastructure */

    return s_record_closed_stream(connection, stream_id, AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_SENT);
}

/* Move stream into "active" datastructures and notify stream that it can send frames now */
static void s_move_stream_to_thread(
    struct aws_h2_connection *connection,
    struct aws_h2_stream *stream,
    int new_stream_error_code) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    if (new_stream_error_code) {
        aws_raise_error(new_stream_error_code);
        AWS_H2_STREAM_LOGF(
            ERROR,
            stream,
            "Failed activating stream, error %d (%s)",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    uint32_t max_concurrent_streams = connection->thread_data.settings_peer[AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS];
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

    struct aws_linked_list pending_frames;
    aws_linked_list_init(&pending_frames);

    struct aws_linked_list pending_settings;
    aws_linked_list_init(&pending_settings);
    struct aws_linked_list pending_ping;
    aws_linked_list_init(&pending_ping);

    size_t window_update_size;

    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(connection);
        connection->synced_data.is_cross_thread_work_task_scheduled = false;

        aws_linked_list_swap_contents(&connection->synced_data.pending_frame_list, &pending_frames);
        aws_linked_list_swap_contents(&connection->synced_data.pending_stream_list, &pending_streams);
        aws_linked_list_swap_contents(&connection->synced_data.pending_settings_list, &pending_settings);
        aws_linked_list_swap_contents(&connection->synced_data.pending_ping_list, &pending_ping);
        window_update_size = connection->synced_data.window_update_size;
        connection->synced_data.window_update_size = 0;

        s_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    /* Enqueue new pending control frames */
    while (!aws_linked_list_empty(&pending_frames)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&pending_frames);
        struct aws_h2_frame *frame = AWS_CONTAINER_OF(node, struct aws_h2_frame, node);
        aws_h2_connection_enqueue_outgoing_frame(connection, frame);
    }

    /* We already enqueued the window_update frame, just apply the change and let our peer check this value, no matter
     * overflow happens or not. Peer will detect it for us. */
    connection->thread_data.window_size_self =
        aws_add_size_saturating(connection->thread_data.window_size_self, window_update_size);

    /* Process new pending_streams */
    if (!aws_linked_list_empty(&pending_streams)) {
        int new_stream_error_code = (int)aws_atomic_load_int(&connection->atomic.new_stream_error_code);
        do {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&pending_streams);
            struct aws_h2_stream *stream = AWS_CONTAINER_OF(node, struct aws_h2_stream, node);
            s_move_stream_to_thread(connection, stream, new_stream_error_code);
        } while (!aws_linked_list_empty(&pending_streams));
    }

    /* Move pending settings to thread data */
    while (!aws_linked_list_empty(&pending_settings)) {
        aws_linked_list_push_back(
            &connection->thread_data.pending_settings_queue, aws_linked_list_pop_front(&pending_settings));
    }

    /* Move pending PING to thread data */
    while (!aws_linked_list_empty(&pending_ping)) {
        aws_linked_list_push_back(
            &connection->thread_data.pending_ping_queue, aws_linked_list_pop_front(&pending_ping));
    }

    /* It's likely that frames were queued while processing cross-thread work.
     * If so, try writing them now */
    aws_h2_try_write_outgoing_frames(connection);
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

    /* connection keeps activated stream alive until stream completes */
    aws_atomic_fetch_add(&stream->refcount, 1);

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

    int new_stream_error_code = (int)aws_atomic_load_int(&connection->atomic.new_stream_error_code);
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

static void s_connection_close(struct aws_http_connection *connection_base) {
    struct aws_h2_connection *connection = AWS_CONTAINER_OF(connection_base, struct aws_h2_connection, base);

    /* Don't stop reading/writing immediately, let that happen naturally during the channel shutdown process. */
    s_stop(connection, false /*stop_reading*/, false /*stop_writing*/, true /*schedule_shutdown*/, AWS_ERROR_SUCCESS);
}

static bool s_connection_is_open(const struct aws_http_connection *connection_base) {
    struct aws_h2_connection *connection = AWS_CONTAINER_OF(connection_base, struct aws_h2_connection, base);
    bool is_open = aws_atomic_load_int(&connection->atomic.is_open);
    return is_open;
}

static void s_connection_update_window(struct aws_http_connection *connection_base, size_t increment_size) {
    struct aws_h2_connection *connection = AWS_CONTAINER_OF(connection_base, struct aws_h2_connection, base);
    if (!increment_size) {
        return;
    }
    if (!connection_base->manual_window_management) {
        /* auto-mode, manual update window is not supported */
        CONNECTION_LOG(
            WARN, connection, "Manual window management is off, update window operations are not supported.");
        return;
    }
    /* Type cast the increment size here, if overflow happens, we will detect it later, and the frame will be destroyed
     */
    struct aws_h2_frame *connection_window_update_frame =
        aws_h2_frame_new_window_update(connection->base.alloc, 0, (uint32_t)increment_size);
    if (!connection_window_update_frame) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Failed to create WINDOW_UPDATE frame on connection, error %s",
            aws_error_name(aws_last_error()));
        return;
    }

    int err = 0;
    bool cross_thread_work_should_schedule = false;
    size_t sum_size;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(connection);

        err |= aws_add_size_checked(connection->synced_data.window_update_size, increment_size, &sum_size);
        err |= sum_size > AWS_H2_WINDOW_UPDATE_MAX;

        if (!err) {
            cross_thread_work_should_schedule = !connection->synced_data.is_cross_thread_work_task_scheduled;
            connection->synced_data.is_cross_thread_work_task_scheduled = true;
            aws_linked_list_push_back(
                &connection->synced_data.pending_frame_list, &connection_window_update_frame->node);
            connection->synced_data.window_update_size = sum_size;
        }
        s_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    if (cross_thread_work_should_schedule) {
        CONNECTION_LOG(TRACE, connection, "Scheduling cross-thread work task");
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->cross_thread_work_task);
    }

    if (err) {
        /* The increment_size is still not 100% safe, since we cannot control the incoming data frame. So just
         * ruled out the value that is obviously wrong values */
        CONNECTION_LOGF(
            ERROR,
            connection,
            "The increment size is too big for HTTP/2 protocol, max flow-control "
            "window size is 2147483647. We got %zu, which will cause the flow-control window to exceed the maximum",
            increment_size);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        aws_h2_frame_destroy(connection_window_update_frame);
        return;
    }
}

static int s_connection_change_settings(
    struct aws_http_connection *connection_base,
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    aws_http2_on_change_settings_complete_fn *on_completed,
    void *user_data) {

    struct aws_h2_connection *connection = AWS_CONTAINER_OF(connection_base, struct aws_h2_connection, base);

    if (!settings_array && num_settings) {
        CONNECTION_LOG(ERROR, connection, "Settings_array is NULL and num_settings is not zero.");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_h2_pending_settings *pending_settings =
        s_new_pending_settings(connection->base.alloc, settings_array, num_settings, on_completed, user_data);
    if (!pending_settings) {
        return AWS_OP_ERR;
    }
    struct aws_h2_frame *settings_frame =
        aws_h2_frame_new_settings(connection->base.alloc, settings_array, num_settings, false /*ACK*/);
    if (!settings_frame) {
        CONNECTION_LOGF(
            ERROR, connection, "Failed to create settings frame, error %s", aws_error_name(aws_last_error()));
        aws_mem_release(connection->base.alloc, pending_settings);
        return AWS_OP_ERR;
    }

    bool was_cross_thread_work_scheduled = false;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(connection);

        was_cross_thread_work_scheduled = connection->synced_data.is_cross_thread_work_task_scheduled;
        connection->synced_data.is_cross_thread_work_task_scheduled = true;
        aws_linked_list_push_back(&connection->synced_data.pending_frame_list, &settings_frame->node);
        aws_linked_list_push_back(&connection->synced_data.pending_settings_list, &pending_settings->node);

        s_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    if (!was_cross_thread_work_scheduled) {
        CONNECTION_LOG(TRACE, connection, "Scheduling cross-thread work task");
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->cross_thread_work_task);
    }

    return AWS_OP_SUCCESS;
}

static int s_connection_ping(
    struct aws_http_connection *connection_base,
    const struct aws_byte_cursor *optional_opaque_data,
    aws_http2_on_ping_complete_fn *on_completed,
    void *user_data) {

    struct aws_h2_connection *connection = AWS_CONTAINER_OF(connection_base, struct aws_h2_connection, base);
    if (optional_opaque_data && optional_opaque_data->len != 8) {
        CONNECTION_LOG(ERROR, connection, "Only 8 bytes opaque data supported for PING in HTTP/2");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    uint64_t time_stamp;
    if (aws_high_res_clock_get_ticks(&time_stamp)) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Failed getting the time stamp to start PING, error %s",
            aws_error_name(aws_last_error()));
        return AWS_OP_ERR;
    }
    struct aws_h2_pending_ping *pending_ping =
        s_new_pending_ping(connection->base.alloc, optional_opaque_data, time_stamp, user_data, on_completed);
    if (!pending_ping) {
        return AWS_OP_ERR;
    }
    struct aws_h2_frame *ping_frame =
        aws_h2_frame_new_ping(connection->base.alloc, false /*ACK*/, pending_ping->opaque_data);
    if (!ping_frame) {
        CONNECTION_LOGF(ERROR, connection, "Failed to create PING frame, error %s", aws_error_name(aws_last_error()));
        aws_mem_release(connection->base.alloc, pending_ping);
        return AWS_OP_ERR;
    }

    bool was_cross_thread_work_scheduled = false;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(connection);

        was_cross_thread_work_scheduled = connection->synced_data.is_cross_thread_work_task_scheduled;
        connection->synced_data.is_cross_thread_work_task_scheduled = true;
        aws_linked_list_push_back(&connection->synced_data.pending_frame_list, &ping_frame->node);
        aws_linked_list_push_back(&connection->synced_data.pending_ping_list, &pending_ping->node);

        s_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    if (!was_cross_thread_work_scheduled) {
        CONNECTION_LOG(TRACE, connection, "Scheduling cross-thread work task");
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->cross_thread_work_task);
    }

    return AWS_OP_SUCCESS;
}

/* Send a GOAWAY with the lowest possible last-stream-id */
static void s_send_goaway(struct aws_h2_connection *connection, enum aws_http2_error_code h2_error_code) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    uint32_t last_stream_id = aws_min_u32(
        connection->thread_data.latest_peer_initiated_stream_id, connection->thread_data.goaway_sent_last_stream_id);

    struct aws_byte_cursor debug_data;
    AWS_ZERO_STRUCT(debug_data);

    struct aws_h2_frame *goaway =
        aws_h2_frame_new_goaway(connection->base.alloc, last_stream_id, h2_error_code, debug_data);
    if (!goaway) {
        CONNECTION_LOGF(ERROR, connection, "Error creating GOAWAY frame, %s", aws_error_name(aws_last_error()));
        goto error;
    }

    connection->thread_data.goaway_sent_last_stream_id = last_stream_id;
    aws_h2_connection_enqueue_outgoing_frame(connection, goaway);
    aws_h2_try_write_outgoing_frames(connection);
    return;

error:
    s_shutdown_due_to_write_err(connection, aws_last_error());
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
        goto clean_up;
    }

    /* Any error that bubbles up from the decoder or its callbacks is treated as
     * a Connection Error (a GOAWAY frames is sent, and the connection is closed) */
    struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);
    struct aws_h2err err = aws_h2_decode(connection->thread_data.decoder, &message_cursor);
    if (aws_h2err_failed(err)) {
        CONNECTION_LOGF(
            ERROR,
            connection,
            "Failure while receiving frames, %s. Sending GOAWAY %s(0x%x) and closing connection",
            aws_error_name(err.aws_code),
            aws_http2_error_code_to_str(err.h2_code),
            err.h2_code);
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
        err = aws_h2err_from_last_error();
        goto shutdown;
    }

    goto clean_up;

shutdown:
    s_send_goaway(connection, err.h2_code);
    s_stop(connection, true /*stop_reading*/, false /*stop_writing*/, true /*schedule_shutdown*/, err.aws_code);

clean_up:
    aws_mem_release(message->allocator, message);

    /* Flush any outgoing frames that might have been queued as a result of decoder callbacks. */
    aws_h2_try_write_outgoing_frames(connection);

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

        /* Send GOAWAY if none have been sent so far,
         * or if we've only sent a "graceful shutdown warning" that didn't name a last-stream-id */
        if (connection->thread_data.goaway_sent_last_stream_id == AWS_H2_STREAM_ID_MAX) {
            s_send_goaway(connection, error_code ? AWS_HTTP2_ERR_INTERNAL_ERROR : AWS_HTTP2_ERR_NO_ERROR);
        }

        aws_channel_slot_on_handler_shutdown_complete(
            slot, AWS_CHANNEL_DIR_READ, error_code, free_scarce_resources_immediately);

    } else /* AWS_CHANNEL_DIR_WRITE */ {
        connection->thread_data.channel_shutdown_error_code = error_code;
        connection->thread_data.channel_shutdown_immediately = free_scarce_resources_immediately;
        connection->thread_data.channel_shutdown_waiting_for_goaway_to_be_written = true;

        /* We'd prefer to wait until we know GOAWAY has been written, but don't wait if... */
        if (free_scarce_resources_immediately /* we must finish ASAP */ ||
            connection->thread_data.is_writing_stopped /* write will never complete */ ||
            !connection->thread_data.is_outgoing_frames_task_active /* write is already complete */) {

            s_finish_shutdown(connection);
        } else {
            CONNECTION_LOG(TRACE, connection, "HTTP/2 handler will finish shutdown once GOAWAY frame is written");
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_finish_shutdown(struct aws_h2_connection *connection) {
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    AWS_PRECONDITION(connection->thread_data.channel_shutdown_waiting_for_goaway_to_be_written);

    CONNECTION_LOG(TRACE, connection, "Finishing HTTP/2 handler shutdown");

    connection->thread_data.channel_shutdown_waiting_for_goaway_to_be_written = false;

    s_stop(
        connection,
        false /*stop_reading*/,
        true /*stop_writing*/,
        false /*schedule_shutdown*/,
        connection->thread_data.channel_shutdown_error_code);

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

    while (!aws_linked_list_empty(&connection->synced_data.pending_frame_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->synced_data.pending_frame_list);
        struct aws_h2_frame *frame = AWS_CONTAINER_OF(node, struct aws_h2_frame, node);
        aws_h2_frame_destroy(frame);
    }

    /* invoke pending callbacks moved into thread, and clean up the data */
    while (!aws_linked_list_empty(&connection->synced_data.pending_settings_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->synced_data.pending_settings_list);
        struct aws_h2_pending_settings *settings = AWS_CONTAINER_OF(node, struct aws_h2_pending_settings, node);
        if (settings->on_completed) {
            settings->on_completed(&connection->base, AWS_ERROR_HTTP_CONNECTION_CLOSED, settings->user_data);
        }
        aws_mem_release(connection->base.alloc, settings);
    }

    while (!aws_linked_list_empty(&connection->synced_data.pending_ping_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->synced_data.pending_ping_list);
        struct aws_h2_pending_ping *ping = AWS_CONTAINER_OF(node, struct aws_h2_pending_ping, node);
        if (ping->on_completed) {
            ping->on_completed(&connection->base, 0 /*fake rtt*/, AWS_ERROR_HTTP_CONNECTION_CLOSED, ping->user_data);
        }
        aws_mem_release(connection->base.alloc, ping);
    }
    /* invoke pending callbacks moved into thread, and clean up the data */
    while (!aws_linked_list_empty(&connection->thread_data.pending_settings_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->thread_data.pending_settings_queue);
        struct aws_h2_pending_settings *pending_settings = AWS_CONTAINER_OF(node, struct aws_h2_pending_settings, node);
        /* fire the user callback with error */
        if (pending_settings->on_completed) {
            pending_settings->on_completed(
                &connection->base, AWS_ERROR_HTTP_CONNECTION_CLOSED, pending_settings->user_data);
        }
        aws_mem_release(connection->base.alloc, pending_settings);
    }
    while (!aws_linked_list_empty(&connection->thread_data.pending_ping_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->thread_data.pending_ping_queue);
        struct aws_h2_pending_ping *pending_ping = AWS_CONTAINER_OF(node, struct aws_h2_pending_ping, node);
        /* fire the user callback with error */
        if (pending_ping->on_completed) {
            pending_ping->on_completed(
                &connection->base, 0 /*fake rtt*/, AWS_ERROR_HTTP_CONNECTION_CLOSED, pending_ping->user_data);
        }
        aws_mem_release(connection->base.alloc, pending_ping);
    }
    aws_channel_slot_on_handler_shutdown_complete(
        connection->base.channel_slot,
        AWS_CHANNEL_DIR_WRITE,
        connection->thread_data.channel_shutdown_error_code,
        connection->thread_data.channel_shutdown_immediately);
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
