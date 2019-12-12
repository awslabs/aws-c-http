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
#include <aws/http/private/h2_encoder.h>
#include <aws/http/private/h2_frames.h>
#include <aws/http/private/h2_stream.h>

#include <aws/common/logging.h>
#include <aws/io/channel.h>
#include <aws/io/io.h>

#include <inttypes.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define CONNECTION_LOGF(level, connection, text, ...)                                                                  \
    AWS_LOGF_##level(AWS_LS_HTTP_CONNECTION, "id=%p: " text, (void *)(connection), __VA_ARGS__)
#define CONNECTION_LOG(level, connection, text) CONNECTION_LOGF(level, connection, "%s", text)

/* Stream IDs are only 31 bits [5.1.1] */
static const uint32_t MAX_STREAM_ID = UINT32_MAX >> 1;

/* [4.1]: length (24) + type (8) + flags (8) + stream id (4) */
static const uint32_t EMPTY_FRAME_SIZE = 3 + 1 + 1 + 4;

/* Connection preface [3.5] */
static const uint8_t s_client_connection_preface_bytes[24] = {
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32,
    0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
};
static const struct aws_byte_cursor s_client_connection_preface = {
    .ptr = (uint8_t *)s_client_connection_preface_bytes,
    .len = AWS_ARRAY_SIZE(s_client_connection_preface_bytes),
};

struct queued_frame {
    struct aws_linked_list_node node;

    struct aws_h2_frame_header *frame;
    aws_h2_frame_complete_fn *on_complete;
    void *userdata;
};

/* Handler vtable functions */
static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message);
static int s_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message);
static int s_increment_read_window(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size);
static int s_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately);
static size_t s_initial_window_size(struct aws_channel_handler *handler);
static size_t s_message_overhead(struct aws_channel_handler *handler);
static void s_handler_destroy(struct aws_channel_handler *handler);

/* Connection vtable functions */
static int s_on_setup(struct aws_http_connection *connection_base);
static struct aws_http_stream *s_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);

/* Decoder vtable functions */
static int s_decoder_on_begin_frame(uint32_t stream_id, enum aws_h2_frame_type type, void *userdata);
static int s_decoder_on_end_frame(uint32_t stream_id, enum aws_h2_frame_type type, void *userdata);
static int s_decoder_on_setting(uint16_t setting, uint32_t value, void *userdata);
static int s_decoder_on_settings_ack(void *userdata);
static int s_decoder_do_send_settings_ack(void *userdata);

/* Tasks */
static aws_channel_task_fn s_new_stream_task;

static aws_channel_on_message_write_completed_fn s_message_write_completed;
static aws_channel_task_fn s_run_encoder_task;

/***********************************************************************************************************************
 * Initialization
 **********************************************************************************************************************/

static uint64_t s_uint32_hash(const void *key) {
    const uint32_t *value = key;
    return *value;
}

static bool s_uint32_eq(const void *a, const void *b) {
    const uint32_t *l = a;
    const uint32_t *r = b;

    return *l == *r;
}

static struct aws_http_connection_vtable s_h2_connection_vtable = {
    .channel_handler_vtable =
        {
            .process_read_message = s_handler_process_read_message,
            .process_write_message = s_process_write_message,
            .increment_read_window = s_increment_read_window,
            .shutdown = s_shutdown,
            .initial_window_size = s_initial_window_size,
            .message_overhead = s_message_overhead,
            .destroy = s_handler_destroy,
        },

    .on_setup = s_on_setup,
    .make_request = s_make_request,
    .new_server_request_handler_stream = NULL,
    .stream_send_response = NULL,
    .close = NULL,
    .is_open = NULL,
    .update_window = NULL,
};

static const struct aws_h2_decoder_vtable s_h2_decoder_vtable = {
    .on_begin_frame = s_decoder_on_begin_frame,
    .on_end_frame = s_decoder_on_end_frame,
    .on_setting = s_decoder_on_setting,
    .on_settings_ack = s_decoder_on_settings_ack,

    .do_send_settings_ack = s_decoder_do_send_settings_ack,
};

/* Common new() logic for server & client */
static struct aws_h2_connection *s_connection_new(
    struct aws_allocator *alloc,
    size_t initial_window_size,
    bool server) {

    (void)server;

    struct aws_h2_connection *connection = aws_mem_calloc(alloc, 1, sizeof(struct aws_h2_connection));
    if (!connection) {
        goto error_connection_alloc;
    }

    connection->base.vtable = &s_h2_connection_vtable;
    connection->base.alloc = alloc;
    connection->base.channel_handler.vtable = &s_h2_connection_vtable.channel_handler_vtable;
    connection->base.channel_handler.impl = connection;
    connection->base.http_version = AWS_HTTP_VERSION_2;
    connection->base.initial_window_size = initial_window_size;

    /* 1 refcount for user */
    aws_atomic_init_int(&connection->base.refcount, 1);

    aws_channel_task_init(&connection->new_stream_task, s_new_stream_task, connection, "h2_new_stream");
    aws_channel_task_init(&connection->run_encoder_task, s_run_encoder_task, connection, "h2_run_encoder");

    /* Init the next stream id (server must use odd ids, client even [RFC 7540 5.1.1])*/
    connection->synced_data.next_stream_id = (server ? 2 : 1);

    /* Create a new decoder */
    struct aws_h2_decoder_params params = {
        .alloc = alloc,
        .vtable = s_h2_decoder_vtable,
        .userdata = connection,
    };
    connection->thread_data.decoder = aws_h2_decoder_new(&params);
    if (!connection->thread_data.decoder) {
        goto error_decoder_new;
    }

    connection->thread_data.encoder = aws_h2_encoder_new(alloc);
    if (!connection->thread_data.encoder) {
        goto error_encoder_init;
    }

    if (aws_hash_table_init(&connection->thread_data.streams, alloc, 0, s_uint32_hash, s_uint32_eq, NULL, NULL)) {
        goto error_streams_init;
    }

    aws_linked_list_init(&connection->thread_data.outgoing_requests);

    if (aws_mutex_init(&connection->synced_data.lock)) {
        goto error_mutex;
    }

    aws_linked_list_init(&connection->synced_data.pending_stream_list);
    aws_linked_list_init(&connection->synced_data.frame_queue);

    return connection;

error_mutex:
    aws_hash_table_clean_up(&connection->thread_data.streams);
error_streams_init:
    aws_h2_encoder_destroy(connection->thread_data.encoder);
error_encoder_init:
    aws_h2_decoder_destroy(connection->thread_data.decoder);
error_decoder_new:
    aws_mem_release(alloc, connection);
error_connection_alloc:
    return NULL;
}

struct aws_http_connection *aws_http_connection_new_http2_server(
    struct aws_allocator *allocator,
    size_t initial_window_size) {

    struct aws_h2_connection *connection = s_connection_new(allocator, initial_window_size, true);
    if (!connection) {
        return NULL;
    }

    connection->base.server_data = &connection->base.client_or_server_data.server;

    return &connection->base;
}

struct aws_http_connection *aws_http_connection_new_http2_client(
    struct aws_allocator *allocator,
    size_t initial_window_size) {

    struct aws_h2_connection *connection = s_connection_new(allocator, initial_window_size, false);
    if (!connection) {
        return NULL;
    }

    connection->base.client_data = &connection->base.client_or_server_data.client;

    return &connection->base;
}

int aws_h2_connection_queue_frame(
    struct aws_h2_connection *connection,
    struct aws_h2_frame_header *frame,
    aws_h2_frame_complete_fn *on_complete,
    void *userdata) {

    struct queued_frame *queued_frame = aws_mem_calloc(connection->base.alloc, 1, sizeof(struct queued_frame));
    if (!queued_frame) {
        return AWS_OP_ERR;
    }

    queued_frame->frame = frame;
    queued_frame->on_complete = on_complete;
    queued_frame->userdata = userdata;

    bool should_schedule_task = false;

    { /* BEGIN CRITICAL SECTION */
        int err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);

        aws_linked_list_push_back(&connection->synced_data.frame_queue, &queued_frame->node);
        should_schedule_task = !connection->synced_data.encode_task_in_progress;

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);
    } /* END CRITICAL SECTION */

    if (should_schedule_task) {
        CONNECTION_LOG(TRACE, connection, "queue_frame scheduling encoder task");
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->run_encoder_task);
    } else {
        CONNECTION_LOG(TRACE, connection, "queue_frame not scheduling encoder task, task or message outstanding");
    }

    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * Handler VTable
 **********************************************************************************************************************/

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct aws_h2_connection *connection = handler->impl;

    struct aws_byte_cursor to_decode = aws_byte_cursor_from_buf(&message->message_data);
    const size_t to_decode_len = to_decode.len;

    int err = aws_h2_decode(connection->thread_data.decoder, &to_decode);

    aws_mem_release(message->allocator, message);
    aws_channel_slot_increment_read_window(slot, to_decode_len);

    return err;
}

static int s_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;

    AWS_FATAL_ASSERT(false && "H2 Handler must the right-most slot in the channel");

    /* #TODO: Send a DATA frame with the contents of message->message_data */
}

static int s_increment_read_window(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {

    (void)slot;
    (void)size;

    struct aws_h2_connection *connection = handler->impl;
    (void)connection;
    /* #TODO ? */
    return AWS_OP_SUCCESS;
}

static int s_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)slot;
    (void)error_code;
    (void)free_scarce_resources_immediately;

    struct aws_h2_connection *connection = handler->impl;
    (void)connection;

    if (dir == AWS_CHANNEL_DIR_WRITE) {

    }

    aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);

    return AWS_OP_SUCCESS;
}

static size_t s_initial_window_size(struct aws_channel_handler *handler) {

    struct aws_h2_connection *connection = handler->impl;
    return connection->base.initial_window_size;
}

static size_t s_message_overhead(struct aws_channel_handler *handler) {

    (void)handler;
    return EMPTY_FRAME_SIZE;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_h2_connection *connection = handler->impl;

    CONNECTION_LOG(TRACE, connection, "Destroying connection.");

    aws_h2_decoder_destroy(connection->thread_data.decoder);
    aws_h2_encoder_destroy(connection->thread_data.encoder);
    aws_hash_table_clean_up(&connection->thread_data.streams);

    aws_mutex_clean_up(&connection->synced_data.lock);
    aws_mutex_clean_up(&connection->synced_data.lock);

    aws_mem_release(connection->base.alloc, connection);
}

/***********************************************************************************************************************
 * Connection VTable
 **********************************************************************************************************************/

static int s_on_setup(struct aws_http_connection *connection_base) {
    struct aws_h2_connection *connection = AWS_CONTAINER_OF(connection_base, struct aws_h2_connection, base);

    struct aws_io_message *message = aws_channel_acquire_message_from_pool(
        connection->base.channel_slot->channel,
        AWS_IO_MESSAGE_APPLICATION_DATA,
        s_client_connection_preface.len + EMPTY_FRAME_SIZE + 6);

    /* Write the connection preface */
    aws_byte_buf_write_from_whole_cursor(&message->message_data, s_client_connection_preface);

    /* Write an SETTINGS frame */
    struct aws_h2_frame_settings settings;
    aws_h2_frame_settings_init(&settings, connection->base.alloc);

    /* #TODO: Add any settings we may care about. */
    /* #TODO: Support push promises */
    aws_h2_frame_settings_set(&settings, AWS_H2_SETTINGS_ENABLE_PUSH, 0);

    /* Encode the frame */
    aws_h2_encode(connection->thread_data.encoder, &settings.header, &message->message_data);

    /* Write the message */
    aws_channel_slot_send_message(connection->base.channel_slot, message, AWS_CHANNEL_DIR_WRITE);

    return AWS_OP_SUCCESS;
}

static struct aws_http_stream *s_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {

    struct aws_h2_connection *connection = AWS_CONTAINER_OF(client_connection, struct aws_h2_connection, base);

    struct aws_h2_stream *h2_stream = NULL;
    bool should_schedule_task = false;

    { /* BEGIN CRITICAL SECTION */
        int err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);

        uint32_t next_id = connection->synced_data.next_stream_id;
        connection->synced_data.next_stream_id += 2;

        /* If next fetch would overflow next_stream_id, set it to 0 */
        if (AWS_UNLIKELY(next_id > MAX_STREAM_ID)) {
            CONNECTION_LOG(INFO, connection, "All available stream ids are gone, closing the connection");

            next_id = 0;
            aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
        }

        /* Create and store the stream */
        h2_stream = aws_h2_stream_new_request(connection, next_id, options);
        if (h2_stream) {

            /* Only need to schedule the task if the temp list was empty, otherwise someone already scheduled it */
            should_schedule_task = aws_linked_list_empty(&connection->synced_data.pending_stream_list);

            /* Save the stream so the task can pick it up */
            aws_linked_list_push_back(&connection->synced_data.pending_stream_list, &h2_stream->node);
        }

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);
    } /* END CRITICAL SECTION */

    if (should_schedule_task) {
        CONNECTION_LOG(TRACE, connection, "Scheduling new stream task");
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->new_stream_task);
    }

    return h2_stream ? &h2_stream->base : NULL;
}

/***********************************************************************************************************************
 * Decoder
 **********************************************************************************************************************/

static int s_decoder_on_begin_frame(uint32_t stream_id, enum aws_h2_frame_type type, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    CONNECTION_LOGF(
        INFO, connection, "Beginning decode of frame %s (stream: %d)", aws_h2_frame_type_to_str(type), stream_id);

    return AWS_OP_SUCCESS;
}
static int s_decoder_on_end_frame(uint32_t stream_id, enum aws_h2_frame_type type, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    CONNECTION_LOGF(
        INFO, connection, "Completed decode of frame %s (stream: %d)", aws_h2_frame_type_to_str(type), stream_id);

    return AWS_OP_SUCCESS;
}
static int s_decoder_on_setting(uint16_t setting, uint32_t value, void *userdata) {
    struct aws_h2_connection *connection = userdata;

    CONNECTION_LOGF(INFO, connection, "Received setting %s: %" PRIu32, aws_h2_settings_to_str(setting), value);

    return AWS_OP_SUCCESS;
}
static int s_decoder_on_settings_ack(void *userdata) {
    struct aws_h2_connection *connection = userdata;

    CONNECTION_LOG(INFO, connection, "Received settings ack");

    return AWS_OP_SUCCESS;
}

static void s_on_settings_ack_complete(struct aws_h2_frame_header *frame, int error_code, void *userdata) {

    (void)error_code;

    struct aws_h2_frame_settings *settings = AWS_CONTAINER_OF(frame, struct aws_h2_frame_settings, header);
    struct aws_h2_connection *connection = userdata;

    aws_h2_frame_settings_clean_up(settings);
    aws_mem_release(connection->base.alloc, settings);
}

static int s_decoder_do_send_settings_ack(void *userdata) {
    struct aws_h2_connection *connection = userdata;

    struct aws_h2_frame_settings *settings =
        aws_mem_calloc(connection->base.alloc, 1, sizeof(struct aws_h2_frame_settings));
    aws_h2_frame_settings_init(settings, connection->base.alloc);
    settings->ack = true;

    aws_h2_connection_queue_frame(connection, &settings->header, s_on_settings_ack_complete, connection);

    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * Tasks
 **********************************************************************************************************************/

static void s_new_stream_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_h2_connection *connection = arg;

    CONNECTION_LOG(TRACE, connection, "New stream task is running");

    struct aws_linked_list pending_streams;
    aws_linked_list_init(&pending_streams);

    { /* BEGIN CRITICAL SECTION */
        int err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);

        aws_linked_list_swap_contents(&connection->synced_data.pending_stream_list, &pending_streams);

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);
    } /* END CRITICAL SECTION */

    while (aws_linked_list_empty(&pending_streams)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&pending_streams);
        struct aws_h2_stream *stream = AWS_CONTAINER_OF(node, struct aws_h2_stream, node);

        /* Store the stream in the hash table */
        aws_hash_table_put(&connection->thread_data.streams, &stream->id, stream, NULL);

        /* #TODO Begin writing the request */
    }
}

static void s_message_write_completed(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data) {
    (void)channel;

    struct aws_h2_connection *connection = user_data;

    CONNECTION_LOGF(TRACE, connection, "Message %p done sending", (void *)message);

    bool should_schedule_task = false;

    { /* BEGIN CRITICAL SECTION */
        int err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);

        should_schedule_task = !aws_linked_list_empty(&connection->synced_data.frame_queue);
        connection->synced_data.encode_task_in_progress = should_schedule_task;

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);
    } /* END CRITICAL SECTION */

    if (should_schedule_task) {
        CONNECTION_LOG(TRACE, connection, "Read complete callback scheduling followup run of encoder task");
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->run_encoder_task);
    } else {
        CONNECTION_LOG(TRACE, connection, "Read complete callback skipping encoder task, no work to do");
    }

    /* Call on_complete on the frames that we sent */
    while (!aws_linked_list_empty(&connection->thread_data.outgoing_requests)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection->thread_data.outgoing_requests);
        struct queued_frame *frame = AWS_CONTAINER_OF(node, struct queued_frame, node);

        /* Successfully wrote the frame, call the callback, remove from the list, and free */
        if (frame->on_complete) {
            frame->on_complete(frame->frame, err_code, frame->userdata);
        }

        aws_mem_release(connection->base.alloc, frame);
    }
}

static void s_run_encoder_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_h2_connection *connection = arg;

    CONNECTION_LOG(TRACE, connection, "Run encoder task is running");

    struct aws_io_message *message = aws_channel_acquire_message_from_pool(
        connection->base.channel_slot->channel,
        AWS_IO_MESSAGE_APPLICATION_DATA,
        s_client_connection_preface.len + EMPTY_FRAME_SIZE);

    while (!aws_linked_list_empty(&connection->synced_data.frame_queue) &&
           message->message_data.len < message->message_data.capacity) {

        /* No need to lock here, no other threads can remove from this list */
        struct aws_linked_list_node *node = aws_linked_list_front(&connection->synced_data.frame_queue);
        struct queued_frame *frame = AWS_CONTAINER_OF(node, struct queued_frame, node);

        aws_h2_encode(connection->thread_data.encoder, frame->frame, &message->message_data);

        { /* BEGIN CRITICAL SECTION */
            int err = aws_mutex_lock(&connection->synced_data.lock);
            AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);

            aws_linked_list_pop_front(&connection->synced_data.frame_queue);

            err = aws_mutex_unlock(&connection->synced_data.lock);
            AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);
        } /* END CRITICAL SECTION */

        /* Put the frame in the outgoing frames list */
        aws_linked_list_push_back(&connection->thread_data.outgoing_requests, &frame->node);
    }

    message->on_completion = s_message_write_completed;
    message->user_data = connection;

    CONNECTION_LOGF(TRACE, connection, "Sending message %p", (void *)message);

    aws_channel_slot_send_message(connection->base.channel_slot, message, AWS_CHANNEL_DIR_WRITE);
}
