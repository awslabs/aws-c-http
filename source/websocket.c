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

#include <aws/http/private/websocket_impl.h>

#include <aws/common/atomics.h>
#include <aws/common/device_random.h>
#include <aws/common/mutex.h>
#include <aws/http/private/websocket_decoder.h>
#include <aws/http/private/websocket_encoder.h>
#include <aws/io/channel.h>
#include <aws/io/logging.h>

#include <inttypes.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

/* TODO: echo payload of peer CLOSE */

/* TODO: Can we be sure socket will always mark aws_io_messages as complete? */

/* TODO: If something goes wrong during normal shutdown, do I change the error_code? */

/* TODO: Delayed payload works by sending 0-size io_msgs down pipe and trying again when they're compele.
 *       Do something more efficient? */

/* TODO: don't fire send completion until data written to socket .. which also means delaying on_shutdown cb */

/* TODO: stop using the HTTP_PARSE error, give websocket its own error */

enum {
    MESSAGE_SIZE_HINT = 16 * 1024,
};

struct outgoing_frame {
    struct aws_websocket_send_frame_options def;
    struct aws_linked_list_node node;
};

struct aws_websocket {
    struct aws_allocator *alloc;
    struct aws_channel_handler channel_handler;
    struct aws_channel_slot *channel_slot;
    size_t initial_window_size;

    void *user_data;
    aws_websocket_on_connection_shutdown_fn *on_connection_shutdown;
    aws_websocket_on_incoming_frame_begin_fn *on_incoming_frame_begin;
    aws_websocket_on_incoming_frame_payload_fn *on_incoming_frame_payload;
    aws_websocket_on_incoming_frame_complete_fn *on_incoming_frame_complete;

    struct aws_channel_task move_synced_data_to_thread_task;
    struct aws_channel_task shutdown_channel_task;
    struct aws_channel_task increment_read_window_task;
    struct aws_atomic_var refcount;
    bool is_server;

    struct {
        struct aws_websocket_encoder encoder;
        struct aws_linked_list outgoing_frame_list;
        struct outgoing_frame *current_outgoing_frame;

        struct aws_websocket_decoder decoder;
        struct aws_websocket_incoming_frame *current_incoming_frame;
        struct aws_websocket_incoming_frame incoming_frame_storage;

        /* Amount to increment window after a channel message has been processed. */
        size_t incoming_message_window_update;

        /* True when no more frames will be read, due to:
         * - a CLOSE frame was received
         * - decoder error
         * - channel shutdown in read-dir */
        bool is_reading_stopped;

        /* True when no more frames will be written, due to:
         * - a CLOSE frame was sent
         * - encoder error
         * - channel shutdown in write-dir */
        bool is_writing_stopped;

        /* During normal shutdown websocket ensures that a CLOSE frame is sent */
        bool is_shutting_down_and_waiting_for_close_frame_to_be_written;
        int channel_shutdown_error_code;
        bool channel_shutdown_free_scarce_resources_immediately;

        /* Wait until each aws_io_message is completely written to
         * the socket before sending the next aws_io_message */
        bool is_waiting_for_write_completion;
    } thread_data;

    struct {
        struct aws_mutex lock;

        struct aws_linked_list outgoing_frame_list;

        /* If non-zero, then increment_read_window_task is scheduled */
        size_t window_increment_size;

        /* Error-code returned by aws_websocket_send_frame() when is_writing_stopped is true */
        int send_frame_error_code;

        /* Use a task to issue a channel shutdown. */
        int shutdown_channel_task_error_code;
        bool is_shutdown_channel_task_scheduled;

        bool is_move_synced_data_to_thread_task_scheduled;
    } synced_data;
};

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

static int s_encoder_stream_outgoing_payload(struct aws_byte_buf *out_buf, void *user_data);

static int s_decoder_on_frame(const struct aws_websocket_frame *frame, void *user_data);
static int s_decoder_on_payload(struct aws_byte_cursor data, void *user_data);

static void s_destroy_outgoing_frame(struct aws_websocket *websocket, struct outgoing_frame *frame, int error_code);
static void s_complete_incoming_frame(struct aws_websocket *websocket, int error_code, bool *out_callback_result);
static void s_finish_shutdown(struct aws_websocket *websocket);
static void s_io_message_write_completed(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data);
static void s_move_synced_data_to_thread_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_increment_read_window_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_shutdown_channel_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_schedule_channel_shutdown(struct aws_websocket *websocket, int error_code);
static void s_shutdown_due_to_write_err(struct aws_websocket *websocket, int error_code);
static void s_shutdown_due_to_read_err(struct aws_websocket *websocket, int error_code);
static void s_stop_writing(struct aws_websocket *websocket, int send_frame_error_code);
static void s_try_write_outgoing_frames(struct aws_websocket *websocket);

static struct aws_channel_handler_vtable s_channel_handler_vtable = {
    .process_read_message = s_handler_process_read_message,
    .process_write_message = s_handler_process_write_message,
    .increment_read_window = s_handler_increment_read_window,
    .shutdown = s_handler_shutdown,
    .initial_window_size = s_handler_initial_window_size,
    .message_overhead = s_handler_message_overhead,
    .destroy = s_handler_destroy,
};

const char *aws_websocket_opcode_str(uint8_t opcode) {
    switch (opcode) {
        case AWS_WEBSOCKET_OPCODE_CONTINUATION:
            return "continuation";
        case AWS_WEBSOCKET_OPCODE_TEXT:
            return "text";
        case AWS_WEBSOCKET_OPCODE_BINARY:
            return "binary";
        case AWS_WEBSOCKET_OPCODE_CLOSE:
            return "close";
        case AWS_WEBSOCKET_OPCODE_PING:
            return "ping";
        case AWS_WEBSOCKET_OPCODE_PONG:
            return "pong";
        default:
            return "";
    }
}

bool aws_websocket_is_data_frame(uint8_t opcode) {
    /* RFC-6455 Section 5.6: Most significant bit of (4 bit) data frame opcode is 0 */
    return !(opcode & 0x08);
}

void s_lock_synced_data(struct aws_websocket *websocket) {
    int err = aws_mutex_lock(&websocket->synced_data.lock);
    AWS_ASSERT(!err);
    (void)err;
}

void s_unlock_synced_data(struct aws_websocket *websocket) {
    int err = aws_mutex_unlock(&websocket->synced_data.lock);
    AWS_ASSERT(!err);
    (void)err;
}

struct aws_channel_handler *aws_websocket_handler_new(const struct aws_websocket_handler_options *options) {
    /* TODO: validate options */

    struct aws_websocket *websocket = aws_mem_acquire(options->allocator, sizeof(struct aws_websocket));
    if (!websocket) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*websocket);

    websocket->alloc = options->allocator;
    websocket->channel_handler.vtable = &s_channel_handler_vtable;
    websocket->channel_handler.alloc = options->allocator;
    websocket->channel_handler.impl = websocket;

    websocket->channel_slot = options->channel_slot;

    websocket->initial_window_size = options->initial_window_size;

    websocket->user_data = options->user_data;
    websocket->on_connection_shutdown = options->on_connection_shutdown;
    websocket->on_incoming_frame_begin = options->on_incoming_frame_begin;
    websocket->on_incoming_frame_payload = options->on_incoming_frame_payload;
    websocket->on_incoming_frame_complete = options->on_incoming_frame_complete;

    aws_atomic_init_int(&websocket->refcount, 0);

    websocket->is_server = options->is_server;

    aws_channel_task_init(&websocket->move_synced_data_to_thread_task, s_move_synced_data_to_thread_task, websocket);
    aws_channel_task_init(&websocket->shutdown_channel_task, s_shutdown_channel_task, websocket);
    aws_channel_task_init(&websocket->increment_read_window_task, s_increment_read_window_task, websocket);

    aws_linked_list_init(&websocket->thread_data.outgoing_frame_list);

    aws_websocket_encoder_init(&websocket->thread_data.encoder, s_encoder_stream_outgoing_payload, websocket);

    aws_websocket_decoder_init(&websocket->thread_data.decoder, s_decoder_on_frame, s_decoder_on_payload, websocket);

    int err = aws_mutex_init(&websocket->synced_data.lock);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "static: Failed to initialize mutex, error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    aws_linked_list_init(&websocket->synced_data.outgoing_frame_list);

    return &websocket->channel_handler;

error:
    websocket->channel_handler.vtable->destroy(&websocket->channel_handler);
    return NULL;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_websocket *websocket = handler->impl;
    AWS_ASSERT(!websocket->thread_data.current_outgoing_frame);
    AWS_ASSERT(!websocket->thread_data.current_incoming_frame);

    AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Destroying websocket.", (void *)websocket);

    aws_mutex_clean_up(&websocket->synced_data.lock);
    aws_mem_release(websocket->alloc, websocket);
}

void aws_websocket_acquire_hold(struct aws_websocket *websocket) {
    size_t prev_refcount = aws_atomic_fetch_add(&websocket->refcount, 1);
    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Websocket refcount increased, currently %zu.",
        (void *)websocket,
        prev_refcount + 1);

    if (prev_refcount == 0) {
        /* Prevent channel from destroying the websocket unexpectedly */
        aws_channel_acquire_hold(websocket->channel_slot->channel);
    }
}

void aws_websocket_release_hold(struct aws_websocket *websocket) {
    AWS_ASSERT(websocket);
    AWS_ASSERT(websocket->channel_slot);

    size_t prev_refcount = aws_atomic_fetch_sub(&websocket->refcount, 1);
    if (prev_refcount == 1) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Final websocket refcount released, shut down if necessary.",
            (void *)websocket);

        /* Channel might already be shut down, but make sure */
        aws_channel_shutdown(websocket->channel_slot->channel, AWS_ERROR_SUCCESS);

        /* Channel won't destroy its slots/handlers until its refcount reaches 0 */
        aws_channel_release_hold(websocket->channel_slot->channel);

    } else {
        AWS_ASSERT(prev_refcount != 0);

        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Websocket refcount released, %zu remaining.",
            (void *)websocket,
            prev_refcount - 1);
    }
}

/* Insert frame into list, sorting by priority, then by age (high-priority and older frames towards the front) */
static void s_enqueue_prioritized_frame(struct aws_linked_list *list, struct outgoing_frame *to_add) {
    /* Iterate in reverse so that common case (a bunch of low-priority frames) is O(1) */
    struct aws_linked_list_node *rev_iter = aws_linked_list_rbegin(list);
    const struct aws_linked_list_node *rev_end = aws_linked_list_rend(list);
    while (rev_iter != rev_end) {
        struct outgoing_frame *frame_i = AWS_CONTAINER_OF(rev_iter, struct outgoing_frame, node);
        if (to_add->def.high_priority == frame_i->def.high_priority) {
            break;
        }
        rev_iter = aws_linked_list_prev(rev_iter);
    }

    aws_linked_list_insert_after(rev_iter, &to_add->node);
}

int aws_websocket_send_frame(struct aws_websocket *websocket, const struct aws_websocket_send_frame_options *options) {

    AWS_ASSERT(websocket);
    AWS_ASSERT(options);

    /* Check for bad input. Log about non-obvious errors. */
    if (options->high_priority && aws_websocket_is_data_frame(options->opcode)) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_WEBSOCKET, "id=%p: Data frames cannot be sent as high-priority.", (void *)websocket);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (options->payload_length > 0 && !options->stream_outgoing_payload) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Invalid frame options, payload streaming function required when payload length is non-zero.",
            (void *)websocket);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct outgoing_frame *frame = aws_mem_acquire(websocket->alloc, sizeof(struct outgoing_frame));
    if (!frame) {
        return AWS_OP_ERR;
    }
    AWS_ZERO_STRUCT(*frame);

    frame->def = *options;

    /* Enqueue frame, unless no further sending is allowed. */
    int send_error = 0;
    bool should_schedule_task = false;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    if (websocket->synced_data.send_frame_error_code) {
        send_error = websocket->synced_data.send_frame_error_code;
    } else {
        aws_linked_list_push_back(&websocket->synced_data.outgoing_frame_list, &frame->node);
        if (!websocket->synced_data.is_move_synced_data_to_thread_task_scheduled) {
            websocket->synced_data.is_move_synced_data_to_thread_task_scheduled = true;
            should_schedule_task = true;
        }
    }

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    if (send_error) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Cannot send frame, error %d (%s).",
            (void *)websocket,
            send_error,
            aws_error_name(send_error));

        aws_mem_release(websocket->alloc, frame);
        return aws_raise_error(send_error);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Enqueuing frame with opcode=%" PRIu8 "(%s) length=%" PRIu64 " fin=%s priority=%s",
        (void *)websocket,
        options->opcode,
        aws_websocket_opcode_str(options->opcode),
        options->payload_length,
        options->fin ? "T" : "F",
        options->high_priority ? "high" : "normal");

    if (should_schedule_task) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Scheduling synced data task.", (void *)websocket);
        aws_channel_schedule_task_now(websocket->channel_slot->channel, &websocket->move_synced_data_to_thread_task);
    }

    return AWS_OP_SUCCESS;
}

static void s_move_synced_data_to_thread_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_websocket *websocket = arg;
    struct aws_linked_list tmp_list;
    aws_linked_list_init(&tmp_list);

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    aws_linked_list_swap_contents(&websocket->synced_data.outgoing_frame_list, &tmp_list);

    websocket->synced_data.is_move_synced_data_to_thread_task_scheduled = false;

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    if (!aws_linked_list_empty(&tmp_list)) {
        do {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&tmp_list);
            struct outgoing_frame *frame = AWS_CONTAINER_OF(node, struct outgoing_frame, node);
            s_enqueue_prioritized_frame(&websocket->thread_data.outgoing_frame_list, frame);
        } while (!aws_linked_list_empty(&tmp_list));

        s_try_write_outgoing_frames(websocket);
    }
}

static void s_try_write_outgoing_frames(struct aws_websocket *websocket) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));

    /* Check whether we should be writing data */
    if (!websocket->thread_data.current_outgoing_frame &&
        aws_linked_list_empty(&websocket->thread_data.outgoing_frame_list)) {

        AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: No data to write at this time.", (void *)websocket);
        return;
    }

    if (websocket->thread_data.is_waiting_for_write_completion) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Waiting until outstanding aws_io_message is written to socket before sending more data.",
            (void *)websocket);
        return;
    }

    if (websocket->thread_data.is_writing_stopped) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Websocket is no longer sending data.", (void *)websocket);
        return;
    }

    /* Acquire aws_io_message */
    struct aws_io_message *io_msg = NULL;
    int err;

    size_t io_msg_hint = MESSAGE_SIZE_HINT;
    size_t upstream_overhead = aws_channel_slot_upstream_message_overhead(websocket->channel_slot);
    if (io_msg_hint <= upstream_overhead) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Unexpected error while calculating message size, closing websocket.",
            (void *)websocket);

        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto error;
    }
    io_msg_hint -= upstream_overhead;

    io_msg = aws_channel_acquire_message_from_pool(
        websocket->channel_slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, io_msg_hint);
    if (!io_msg) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Failed acquire message from pool, error %d (%s).",
            (void *)websocket,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    io_msg->user_data = websocket;
    io_msg->on_completion = s_io_message_write_completed;

    /* Loop through frames, writing their data into the io_msg */
    bool wrote_close_frame = false;
    while (!websocket->thread_data.is_writing_stopped) {
        if (websocket->thread_data.current_outgoing_frame) {
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: Resuming write of frame=%p opcode=%" PRIu8 "(%s) payload-length=%" PRIu64 ".",
                (void *)websocket,
                (void *)websocket->thread_data.current_outgoing_frame,
                websocket->thread_data.current_outgoing_frame->def.opcode,
                aws_websocket_opcode_str(websocket->thread_data.current_outgoing_frame->def.opcode),
                websocket->thread_data.current_outgoing_frame->def.payload_length);

        } else {
            /* We're not in the middle of encoding a frame, so pop off the next one to encode. */
            if (aws_linked_list_empty(&websocket->thread_data.outgoing_frame_list)) {
                AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: No more frames to write.", (void *)websocket);
                break;
            }

            struct aws_linked_list_node *node = aws_linked_list_pop_front(&websocket->thread_data.outgoing_frame_list);
            websocket->thread_data.current_outgoing_frame = AWS_CONTAINER_OF(node, struct outgoing_frame, node);

            struct aws_websocket_frame frame = {
                .fin = websocket->thread_data.current_outgoing_frame->def.fin,
                .opcode = websocket->thread_data.current_outgoing_frame->def.opcode,
                .payload_length = websocket->thread_data.current_outgoing_frame->def.payload_length,
            };

            /* RFC-6455 Section 5.3 Client-to-Server Masking
             * Clients must mask payload with key derived from an unpredictable source of entropy. */
            if (!websocket->is_server) {
                frame.masked = true;
                /* TODO: faster source of random (but still seeded by device_random) */
                struct aws_byte_buf masking_key_buf = aws_byte_buf_from_empty_array(frame.masking_key, 4);
                err = aws_device_random_buffer(&masking_key_buf);
                if (err) {
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_WEBSOCKET,
                        "id=%p: Failed to derive masking key, error %d (%s).",
                        (void *)websocket,
                        aws_last_error(),
                        aws_error_name(aws_last_error()));
                    goto error;
                }
            }

            err = aws_websocket_encoder_start_frame(&websocket->thread_data.encoder, &frame);
            if (err) {
                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_WEBSOCKET,
                    "id=%p: Failed to start frame encoding, error %d (%s).",
                    (void *)websocket,
                    aws_last_error(),
                    aws_error_name(aws_last_error()));
                goto error;
            }

            AWS_LOGF_TRACE(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: Start writing frame=%p opcode=%" PRIu8 "(%s) payload-length=%" PRIu64 ".",
                (void *)websocket,
                (void *)websocket->thread_data.current_outgoing_frame,
                websocket->thread_data.current_outgoing_frame->def.opcode,
                aws_websocket_opcode_str(websocket->thread_data.current_outgoing_frame->def.opcode),
                websocket->thread_data.current_outgoing_frame->def.payload_length);
        }

        err = aws_websocket_encoder_process(&websocket->thread_data.encoder, &io_msg->message_data);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: Frame encoding failed with error %d (%s).",
                (void *)websocket,
                aws_last_error(),
                aws_error_name(aws_last_error()));
            goto error;
        }

        if (aws_websocket_encoder_is_frame_in_progress(&websocket->thread_data.encoder)) {
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: Frame still in progress, but no more data can be written at this time.",
                (void *)websocket);
            break;
        }

        if (websocket->thread_data.current_outgoing_frame->def.opcode == AWS_WEBSOCKET_OPCODE_CLOSE) {
            wrote_close_frame = true;
        }

        s_destroy_outgoing_frame(websocket, websocket->thread_data.current_outgoing_frame, AWS_ERROR_SUCCESS);
        websocket->thread_data.current_outgoing_frame = NULL;

        if (wrote_close_frame) {
            break;
        }
    }

    /* Send aws_io_message up the channel */
    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Sending aws_io_message of size %zu.",
        (void *)websocket,
        io_msg->message_data.len);

    err = aws_channel_slot_send_message(websocket->channel_slot, io_msg, AWS_CHANNEL_DIR_WRITE);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Failed to send message up channel, error %d (%s).",
            (void *)websocket,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    websocket->thread_data.is_waiting_for_write_completion = true;

    /* If CLOSE frame was written, that's the last data we'll write */
    if (wrote_close_frame) {
        s_stop_writing(websocket, AWS_ERROR_HTTP_WEBSOCKET_CLOSE_FRAME_SENT);

        if (websocket->thread_data.is_shutting_down_and_waiting_for_close_frame_to_be_written) {
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: CLOSE frame sent, finishing handler shutdown sequence.",
                (void *)websocket);

            s_finish_shutdown(websocket);
        }
    }

    return;

error:
    if (io_msg) {
        aws_mem_release(io_msg->allocator, io_msg);
    }

    s_shutdown_due_to_write_err(websocket, aws_last_error());
}

/* Encoder's outgoing_payload callback invokes current frame's callback */
static int s_encoder_stream_outgoing_payload(struct aws_byte_buf *out_buf, void *user_data) {
    struct aws_websocket *websocket = user_data;
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));
    AWS_ASSERT(websocket->thread_data.current_outgoing_frame);

    struct outgoing_frame *current_frame = websocket->thread_data.current_outgoing_frame;
    AWS_ASSERT(current_frame->def.stream_outgoing_payload);

    bool callback_result = current_frame->def.stream_outgoing_payload(websocket, out_buf, current_frame->def.user_data);
    if (!callback_result) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Outgoing payload callback has reported a failure.", (void *)websocket);
        return aws_raise_error(AWS_ERROR_HTTP_CALLBACK_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static void s_io_message_write_completed(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data) {

    (void)channel;
    (void)message;
    struct aws_websocket *websocket = user_data;
    AWS_ASSERT(aws_channel_thread_is_callers_thread(channel));

    if (err_code == AWS_ERROR_SUCCESS) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: aws_io_message written to socket, sending more data...", (void *)websocket);

        websocket->thread_data.is_waiting_for_write_completion = false;
        s_try_write_outgoing_frames(websocket);
    } else {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: aws_io_message did not finish writing to socket, error %d (%s).",
            (void *)websocket,
            err_code,
            aws_error_name(err_code));

        s_shutdown_due_to_write_err(websocket, err_code);
    }
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

static void s_destroy_outgoing_frame(struct aws_websocket *websocket, struct outgoing_frame *frame, int error_code) {
    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Completed outgoing frame=%p opcode=%" PRIu8 "(%s) payload-length=%" PRIu64 " with error_code %d (%s).",
        (void *)websocket,
        (void *)frame,
        frame->def.opcode,
        aws_websocket_opcode_str(frame->def.opcode),
        frame->def.payload_length,
        error_code,
        aws_error_name(error_code));

    if (frame->def.on_complete) {
        frame->def.on_complete(websocket, error_code, frame->def.user_data);
    }

    aws_mem_release(websocket->alloc, frame);
}

static void s_stop_writing(struct aws_websocket *websocket, int send_frame_error_code) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));
    AWS_ASSERT(send_frame_error_code != AWS_ERROR_SUCCESS);

    if (websocket->thread_data.is_writing_stopped) {
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Websocket will send no more data, future attempts to send will get error %d (%s).",
        (void *)websocket,
        send_frame_error_code,
        aws_error_name(send_frame_error_code));

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    websocket->synced_data.send_frame_error_code = send_frame_error_code;

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    websocket->thread_data.is_writing_stopped = true;
}

static void s_shutdown_due_to_write_err(struct aws_websocket *websocket, int error_code) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));

    /* No more writing allowed (it's ok to call this redundantly). */
    s_stop_writing(websocket, AWS_ERROR_HTTP_CONNECTION_CLOSED);

    /* If there's a current outgoing frame, complete it with the specific error code.
     * Any other pending frames will complete with the generic CONNECTION_CLOSED error. */
    if (websocket->thread_data.current_outgoing_frame) {
        s_destroy_outgoing_frame(websocket, websocket->thread_data.current_outgoing_frame, error_code);
        websocket->thread_data.current_outgoing_frame = NULL;
    }

    /* If we're in the final stages of shutdown, ensure shutdown completes.
     * Otherwise tell the channel to shutdown (it's ok to shutdown the channel redundantly). */
    if (websocket->thread_data.is_shutting_down_and_waiting_for_close_frame_to_be_written) {
        s_finish_shutdown(websocket);
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Closing websocket due to failure during write, error %d (%s).",
            (void *)websocket,
            error_code,
            aws_error_name(error_code));
        s_schedule_channel_shutdown(websocket, error_code);
    }
}

static void s_shutdown_due_to_read_err(struct aws_websocket *websocket, int error_code) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));

    AWS_LOGF_ERROR(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Closing websocket due to failure during read, error %d (%s).",
        (void *)websocket,
        error_code,
        aws_error_name(error_code));

    websocket->thread_data.is_reading_stopped = true;

    /* If there's a current incoming frame, complete it with the specific error code. */
    if (websocket->thread_data.current_incoming_frame) {
        s_complete_incoming_frame(websocket, error_code, NULL);
    }

    /* Tell channel to shutdown (it's ok to call this redundantly) */
    s_schedule_channel_shutdown(websocket, error_code);
}

static void s_shutdown_channel_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_websocket *websocket = arg;
    int error_code;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    error_code = websocket->synced_data.shutdown_channel_task_error_code;

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    aws_channel_shutdown(websocket->channel_slot->channel, error_code);
}

/* Tell the channel to shut down. It is safe to call this multiple times.
 * The call to aws_channel_shutdown() is delayed so that a user invoking aws_websocket_close doesn't
 * have completion callbacks firing before the function call even returns */
static void s_schedule_channel_shutdown(struct aws_websocket *websocket, int error_code) {
    bool schedule_shutdown = false;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    if (!websocket->synced_data.is_shutdown_channel_task_scheduled) {
        schedule_shutdown = true;
        websocket->synced_data.is_shutdown_channel_task_scheduled = true;
        websocket->synced_data.shutdown_channel_task_error_code = error_code;
    }

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    if (schedule_shutdown) {
        aws_channel_schedule_task_now(websocket->channel_slot->channel, &websocket->shutdown_channel_task);
    }
}

void aws_websocket_close(struct aws_websocket *websocket, bool free_scarce_resources_immediately) {
    int error_code = AWS_ERROR_SUCCESS;

    /* TODO: aws_channel_shutdown() should let users specify error_code and "immediate" as separate parameters.
     * Currently, any non-zero error_code results in "immediate" shutdown */
    if (free_scarce_resources_immediately) {
        error_code = AWS_ERROR_HTTP_CONNECTION_CLOSED;
    }

    s_schedule_channel_shutdown(websocket, error_code);
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    AWS_ASSERT(aws_channel_thread_is_callers_thread(slot->channel));
    struct aws_websocket *websocket = handler->impl;
    int err;

    AWS_LOGF_DEBUG(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Websocket handler shutting down dir=%s error_code=%d immediate=%d.",
        (void *)websocket,
        dir == AWS_CHANNEL_DIR_READ ? "READ" : "WRITE",
        error_code,
        free_scarce_resources_immediately);

    if (dir == AWS_CHANNEL_DIR_READ) {
        /* Shutdown in the read direction is immediate and simple. */
        websocket->thread_data.is_reading_stopped = true;
        aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);

    } else {
        websocket->thread_data.channel_shutdown_error_code = error_code;
        websocket->thread_data.channel_shutdown_free_scarce_resources_immediately = free_scarce_resources_immediately;
        websocket->thread_data.is_shutting_down_and_waiting_for_close_frame_to_be_written = true;

        if (websocket->thread_data.channel_shutdown_free_scarce_resources_immediately ||
            websocket->thread_data.is_writing_stopped) {

            AWS_LOGF_TRACE(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: Finishing handler shutdown immediately, without ensuring a CLOSE frame was sent.",
                (void *)websocket);

            s_stop_writing(websocket, AWS_ERROR_HTTP_CONNECTION_CLOSED);
            s_finish_shutdown(websocket);
        } else {
            /* Attempt to queue a CLOSE frame, then wait for it to send before finishing shutdown. */
            struct aws_websocket_send_frame_options close_frame = {
                .opcode = AWS_WEBSOCKET_OPCODE_CLOSE,
                .fin = true,
            };
            err = aws_websocket_send_frame(websocket, &close_frame);
            if (err) {
                AWS_LOGF_WARN(
                    AWS_LS_HTTP_WEBSOCKET,
                    "id=%p: Failed to send CLOSE frame, error %d (%s).",
                    (void *)websocket,
                    aws_last_error(),
                    aws_error_name(aws_last_error()));

                s_stop_writing(websocket, AWS_ERROR_HTTP_CONNECTION_CLOSED);
                s_finish_shutdown(websocket);
            } else {
                AWS_LOGF_TRACE(
                    AWS_LS_HTTP_WEBSOCKET,
                    "id=%p: CLOSE frame queued, handler will finish shutdown once it's sent.",
                    (void *)websocket);
            }
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_finish_shutdown(struct aws_websocket *websocket) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));
    AWS_ASSERT(websocket->thread_data.is_writing_stopped);
    AWS_ASSERT(websocket->thread_data.is_shutting_down_and_waiting_for_close_frame_to_be_written);

    AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Finishing websocket handler shutdown.", (void *)websocket);

    websocket->thread_data.is_shutting_down_and_waiting_for_close_frame_to_be_written = false;

    /* Cancel all incomplete frames */
    if (websocket->thread_data.current_incoming_frame) {
        s_complete_incoming_frame(websocket, AWS_ERROR_HTTP_CONNECTION_CLOSED, NULL);
    }

    if (websocket->thread_data.current_outgoing_frame) {
        s_destroy_outgoing_frame(
            websocket, websocket->thread_data.current_outgoing_frame, AWS_ERROR_HTTP_CONNECTION_CLOSED);
        websocket->thread_data.current_outgoing_frame = NULL;
    }

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    while (!aws_linked_list_empty(&websocket->synced_data.outgoing_frame_list)) {
        /* Move frames from synced_data to thread_data, then cancel them together outside critical section */
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&websocket->synced_data.outgoing_frame_list);
        aws_linked_list_push_back(&websocket->thread_data.outgoing_frame_list, node);
    }

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    while (!aws_linked_list_empty(&websocket->thread_data.outgoing_frame_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&websocket->thread_data.outgoing_frame_list);
        struct outgoing_frame *frame = AWS_CONTAINER_OF(node, struct outgoing_frame, node);
        s_destroy_outgoing_frame(websocket, frame, AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    if (websocket->on_connection_shutdown) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Invoking user's shutdown callback.", (void *)websocket);
        websocket->on_connection_shutdown(
            websocket, websocket->thread_data.channel_shutdown_error_code, websocket->user_data);
    }

    aws_channel_slot_on_handler_shutdown_complete(
        websocket->channel_slot,
        AWS_CHANNEL_DIR_WRITE,
        websocket->thread_data.channel_shutdown_error_code,
        websocket->thread_data.channel_shutdown_free_scarce_resources_immediately);
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    AWS_ASSERT(message);
    AWS_ASSERT(aws_channel_thread_is_callers_thread(slot->channel));
    struct aws_websocket *websocket = handler->impl;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&message->message_data);
    int err;

    websocket->thread_data.incoming_message_window_update = message->message_data.len;

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Begin processing message of size %zu.",
        (void *)websocket,
        message->message_data.len);

    while (cursor.len) {
        if (websocket->thread_data.is_reading_stopped) {
            goto clean_up;
        }

        bool frame_complete;
        err = aws_websocket_decoder_process(&websocket->thread_data.decoder, &cursor, &frame_complete);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: Message processing failed, error %d (%s). Closing connection.",
                (void *)websocket,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            goto error;
        }

        if (frame_complete) {
            bool callback_result;
            s_complete_incoming_frame(websocket, AWS_ERROR_SUCCESS, &callback_result);
            if (!callback_result) {
                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_WEBSOCKET,
                    "id=%p: Incoming frame completion callback has reported a failure. Closing connection",
                    (void *)websocket);

                aws_raise_error(AWS_ERROR_HTTP_CALLBACK_FAILURE);
                goto error;
            }
        }
    }

    if (websocket->thread_data.incoming_message_window_update > 0) {
        err = aws_channel_slot_increment_read_window(slot, websocket->thread_data.incoming_message_window_update);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: Failed to increment read window after message processing, error %d (%s). Closing connection.",
                (void *)websocket,
                aws_last_error(),
                aws_error_name(aws_last_error()));
            goto error;
        }
    }

    goto clean_up;

error:
    s_shutdown_due_to_read_err(websocket, aws_last_error());

clean_up:
    if (cursor.len > 0) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Done processing message, final %zu bytes ignored.",
            (void *)websocket,
            cursor.len);
    } else {
        AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Done processing message.", (void *)websocket);
    }
    aws_mem_release(message->allocator, message);
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_frame(const struct aws_websocket_frame *frame, void *user_data) {
    struct aws_websocket *websocket = user_data;
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));
    AWS_ASSERT(!websocket->thread_data.current_incoming_frame);
    AWS_ASSERT(!websocket->thread_data.is_reading_stopped);

    websocket->thread_data.current_incoming_frame = &websocket->thread_data.incoming_frame_storage;

    websocket->thread_data.current_incoming_frame->payload_length = frame->payload_length;
    websocket->thread_data.current_incoming_frame->opcode = frame->opcode;
    websocket->thread_data.current_incoming_frame->fin = frame->fin;
    websocket->thread_data.current_incoming_frame->rsv[0] = frame->rsv[0];
    websocket->thread_data.current_incoming_frame->rsv[1] = frame->rsv[1];
    websocket->thread_data.current_incoming_frame->rsv[2] = frame->rsv[2];

    /* Invoke user cb */
    bool callback_result = true;
    if (websocket->on_incoming_frame_begin) {
        callback_result = websocket->on_incoming_frame_begin(
            websocket, websocket->thread_data.current_incoming_frame, websocket->user_data);
    }

    if (!callback_result) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Incoming frame callback has reported a failure.", (void *)websocket);
        return aws_raise_error(AWS_ERROR_HTTP_CALLBACK_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_payload(struct aws_byte_cursor data, void *user_data) {
    struct aws_websocket *websocket = user_data;
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));
    AWS_ASSERT(websocket->thread_data.current_incoming_frame);
    AWS_ASSERT(!websocket->thread_data.is_reading_stopped);

    /* Invoke user cb */
    bool callback_result = true;
    if (websocket->on_incoming_frame_payload) {
        size_t window_update_size = data.len;

        callback_result = websocket->on_incoming_frame_payload(
            websocket, websocket->thread_data.current_incoming_frame, data, &window_update_size, websocket->user_data);

        /* If user reduced window_update_size, reduce how much the websocket will update its window */
        size_t reduce = data.len - window_update_size;
        AWS_ASSERT(reduce <= websocket->thread_data.incoming_message_window_update);
        websocket->thread_data.incoming_message_window_update -= reduce;

        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Incoming payload callback changed window update size, window will shrink by %zu.",
            (void *)websocket,
            reduce);
    }

    /* TODO: pass data to channel handler on right */

    if (!callback_result) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Incoming payload callback has reported a failure.", (void *)websocket);
        return aws_raise_error(AWS_ERROR_HTTP_CALLBACK_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static void s_complete_incoming_frame(struct aws_websocket *websocket, int error_code, bool *out_callback_result) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));
    AWS_ASSERT(websocket->thread_data.current_incoming_frame);

    if (error_code == AWS_OP_SUCCESS) {
        /* If this was a CLOSE frame, don't read any more data. */
        if (websocket->thread_data.current_incoming_frame->opcode == AWS_WEBSOCKET_OPCODE_CLOSE) {
            AWS_LOGF_DEBUG(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: Close frame received, any further data received will be ignored.",
                (void *)websocket);
            websocket->thread_data.is_reading_stopped = true;

            /* TODO: auto-close if there's a channel-handler to the right */
        }

        /* TODO: auto-respond to PING with PONG */
    }

    /* Invoke user cb */
    bool callback_result = true;
    if (websocket->on_incoming_frame_complete) {
        callback_result = websocket->on_incoming_frame_complete(
            websocket, websocket->thread_data.current_incoming_frame, error_code, websocket->user_data);
    }

    if (out_callback_result) {
        *out_callback_result = callback_result;
    }

    websocket->thread_data.current_incoming_frame = NULL;
}

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    struct aws_websocket *websocket = handler->impl;
    return websocket->initial_window_size;
}

static size_t s_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return AWS_WEBSOCKET_MAX_FRAME_OVERHEAD;
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

static void s_increment_read_window_action(struct aws_websocket *websocket, size_t size) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));

    int err = aws_channel_slot_increment_read_window(websocket->channel_slot, size);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Failed to increment read window, error %d (%s). Closing websocket.",
            (void *)websocket,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        s_schedule_channel_shutdown(websocket, aws_last_error());
    }
}

static void s_increment_read_window_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_websocket *websocket = arg;
    size_t size;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    size = websocket->synced_data.window_increment_size;
    websocket->synced_data.window_increment_size = 0;

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET, "id=%p: Running task to increment read window by %zu.", (void *)websocket, size);

    s_increment_read_window_action(websocket, size);
}

void aws_websocket_increment_read_window(struct aws_websocket *websocket, size_t size) {
    if (size == 0) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Ignoring window increment of size 0.", (void *)websocket);
        return;
    }

    /* If we're on thread just do it. */
    if (aws_channel_thread_is_callers_thread(websocket->channel_slot->channel)) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Incrementing read window immediately with size %zu.",
            (void *)websocket,
            size);
        s_increment_read_window_action(websocket, size);
        return;
    }

    /* Otherwise schedule a task to do it.
     * If task is already scheduled, just increase size to be incremented */
    bool should_schedule_task = false;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    if (websocket->synced_data.window_increment_size == 0) {
        should_schedule_task = true;
        websocket->synced_data.window_increment_size = size;
    } else {
        websocket->synced_data.window_increment_size =
            aws_add_size_saturating(websocket->synced_data.window_increment_size, size);
    }

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    if (should_schedule_task) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Scheduling task to increment read window by %zu.", (void *)websocket, size);
        aws_channel_schedule_task_now(websocket->channel_slot->channel, &websocket->increment_read_window_task);
    } else {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Task to increment read window already scheduled, increasing scheduled size by %zu.",
            (void *)websocket,
            size);
    }
}
