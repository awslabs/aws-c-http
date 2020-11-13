/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/websocket_impl.h>

#include <aws/common/atomics.h>
#include <aws/common/device_random.h>
#include <aws/common/encoding.h>
#include <aws/common/mutex.h>
#include <aws/http/private/websocket_decoder.h>
#include <aws/http/private/websocket_encoder.h>
#include <aws/http/request_response.h>
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

struct outgoing_frame {
    struct aws_websocket_send_frame_options def;
    struct aws_linked_list_node node;
};

struct aws_websocket {
    struct aws_allocator *alloc;
    struct aws_channel_handler channel_handler;
    struct aws_channel_slot *channel_slot;
    size_t initial_window_size;
    bool manual_window_update;

    void *user_data;
    aws_websocket_on_incoming_frame_begin_fn *on_incoming_frame_begin;
    aws_websocket_on_incoming_frame_payload_fn *on_incoming_frame_payload;
    aws_websocket_on_incoming_frame_complete_fn *on_incoming_frame_complete;

    struct aws_channel_task move_synced_data_to_thread_task;
    struct aws_channel_task shutdown_channel_task;
    struct aws_channel_task increment_read_window_task;
    struct aws_channel_task waiting_on_payload_stream_task;
    struct aws_channel_task close_timeout_task;
    bool is_server;

    /* Data that should only be accessed from the websocket's channel thread. */
    struct {
        struct aws_websocket_encoder encoder;
        struct aws_linked_list outgoing_frame_list;
        struct outgoing_frame *current_outgoing_frame;

        struct aws_websocket_decoder decoder;
        struct aws_websocket_incoming_frame *current_incoming_frame;
        struct aws_websocket_incoming_frame incoming_frame_storage;

        /* If current incoming frame is CONTINUATION, this is the data type it is a continuation of. */
        enum aws_websocket_opcode continuation_of_opcode;

        /* Amount to increment window after a channel message has been processed. */
        size_t incoming_message_window_update;

        /* Cached slot to right */
        struct aws_channel_slot *last_known_right_slot;

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

        /* If, while writing out data from a payload stream, we experience "read would block",
         * schedule a task to try again in the near-future. */
        bool is_waiting_on_payload_stream_task;

        /* True if this websocket is being used as a dumb mid-channel handler.
         * The websocket will no longer respond to its public API or invoke callbacks. */
        bool is_midchannel_handler;
    } thread_data;

    /* Data that may be touched from any thread (lock must be held). */
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

        /* Mirrors variable from thread_data */
        bool is_midchannel_handler;

        /* Whether aws_websocket_release() has been called */
        bool is_released;
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
static int s_decoder_on_user_payload(struct aws_websocket *websocket, struct aws_byte_cursor data);
static int s_decoder_on_midchannel_payload(struct aws_websocket *websocket, struct aws_byte_cursor data);

static void s_destroy_outgoing_frame(struct aws_websocket *websocket, struct outgoing_frame *frame, int error_code);
static void s_complete_incoming_frame(struct aws_websocket *websocket, int error_code, bool *out_callback_result);
static void s_finish_shutdown(struct aws_websocket *websocket);
static void s_io_message_write_completed(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data);
static int s_send_frame(
    struct aws_websocket *websocket,
    const struct aws_websocket_send_frame_options *options,
    bool from_public_api);
static bool s_midchannel_send_payload(struct aws_websocket *websocket, struct aws_byte_buf *out_buf, void *user_data);
static void s_midchannel_send_complete(struct aws_websocket *websocket, int error_code, void *user_data);
static void s_move_synced_data_to_thread_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_increment_read_window_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_shutdown_channel_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_waiting_on_payload_stream_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static void s_close_timeout_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
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

static void s_lock_synced_data(struct aws_websocket *websocket) {
    int err = aws_mutex_lock(&websocket->synced_data.lock);
    AWS_ASSERT(!err);
    (void)err;
}

static void s_unlock_synced_data(struct aws_websocket *websocket) {
    int err = aws_mutex_unlock(&websocket->synced_data.lock);
    AWS_ASSERT(!err);
    (void)err;
}

struct aws_websocket *aws_websocket_handler_new(const struct aws_websocket_handler_options *options) {
    /* TODO: validate options */

    struct aws_channel_slot *slot = NULL;
    struct aws_websocket *websocket = NULL;
    int err;

    slot = aws_channel_slot_new(options->channel);
    if (!slot) {
        goto error;
    }

    err = aws_channel_slot_insert_end(options->channel, slot);
    if (err) {
        goto error;
    }

    websocket = aws_mem_calloc(options->allocator, 1, sizeof(struct aws_websocket));
    if (!websocket) {
        goto error;
    }

    websocket->alloc = options->allocator;
    websocket->channel_handler.vtable = &s_channel_handler_vtable;
    websocket->channel_handler.alloc = options->allocator;
    websocket->channel_handler.impl = websocket;

    websocket->channel_slot = slot;

    websocket->initial_window_size = options->initial_window_size;
    websocket->manual_window_update = options->manual_window_update;

    websocket->user_data = options->user_data;
    websocket->on_incoming_frame_begin = options->on_incoming_frame_begin;
    websocket->on_incoming_frame_payload = options->on_incoming_frame_payload;
    websocket->on_incoming_frame_complete = options->on_incoming_frame_complete;

    websocket->is_server = options->is_server;

    aws_channel_task_init(
        &websocket->move_synced_data_to_thread_task,
        s_move_synced_data_to_thread_task,
        websocket,
        "websocket_move_synced_data_to_thread");
    aws_channel_task_init(
        &websocket->shutdown_channel_task, s_shutdown_channel_task, websocket, "websocket_shutdown_channel");
    aws_channel_task_init(
        &websocket->increment_read_window_task,
        s_increment_read_window_task,
        websocket,
        "websocket_increment_read_window");
    aws_channel_task_init(
        &websocket->waiting_on_payload_stream_task,
        s_waiting_on_payload_stream_task,
        websocket,
        "websocket_waiting_on_payload_stream");
    aws_channel_task_init(&websocket->close_timeout_task, s_close_timeout_task, websocket, "websocket_close_timeout");

    aws_linked_list_init(&websocket->thread_data.outgoing_frame_list);

    aws_websocket_encoder_init(&websocket->thread_data.encoder, s_encoder_stream_outgoing_payload, websocket);

    aws_websocket_decoder_init(&websocket->thread_data.decoder, s_decoder_on_frame, s_decoder_on_payload, websocket);

    aws_linked_list_init(&websocket->synced_data.outgoing_frame_list);

    err = aws_mutex_init(&websocket->synced_data.lock);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "static: Failed to initialize mutex, error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    err = aws_channel_slot_set_handler(slot, &websocket->channel_handler);
    if (err) {
        goto error;
    }

    /* Ensure websocket (and the rest of the channel) can't be destroyed until aws_websocket_release() is called */
    aws_channel_acquire_hold(options->channel);

    return websocket;

error:
    if (slot) {
        if (websocket && !slot->handler) {
            websocket->channel_handler.vtable->destroy(&websocket->channel_handler);
        }
        aws_channel_slot_remove(slot);
    }
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

void aws_websocket_release(struct aws_websocket *websocket) {
    AWS_ASSERT(websocket);
    AWS_ASSERT(websocket->channel_slot);

    bool was_already_released;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);
    if (websocket->synced_data.is_released) {
        was_already_released = true;
    } else {
        was_already_released = false;
        websocket->synced_data.is_released = true;
    }
    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    if (was_already_released) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Ignoring multiple calls to websocket release.", (void *)websocket);
        return;
    }

    AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Websocket released, shut down if necessary.", (void *)websocket);

    /* Channel might already be shut down, but make sure */
    s_schedule_channel_shutdown(websocket, AWS_ERROR_SUCCESS);

    /* Channel won't destroy its slots/handlers until its refcount reaches 0 */
    aws_channel_release_hold(websocket->channel_slot->channel);
}

struct aws_channel *aws_websocket_get_channel(const struct aws_websocket *websocket) {
    return websocket->channel_slot->channel;
}

int aws_websocket_convert_to_midchannel_handler(struct aws_websocket *websocket) {
    if (!aws_channel_thread_is_callers_thread(websocket->channel_slot->channel)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Cannot convert to midchannel handler on this thread.", (void *)websocket);
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (websocket->thread_data.is_midchannel_handler) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Websocket has already converted to midchannel handler.", (void *)websocket);
        return aws_raise_error(AWS_ERROR_HTTP_WEBSOCKET_IS_MIDCHANNEL_HANDLER);
    }

    if (websocket->thread_data.is_reading_stopped || websocket->thread_data.is_writing_stopped) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Cannot convert websocket to midchannel handler because it is closed or closing.",
            (void *)websocket);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    if (websocket->thread_data.current_incoming_frame) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Cannot convert to midchannel handler in the middle of an incoming frame.",
            (void *)websocket);
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    bool was_released = false;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);
    if (websocket->synced_data.is_released) {
        was_released = true;
    } else {
        websocket->synced_data.is_midchannel_handler = true;
    }
    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    if (was_released) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Cannot convert websocket to midchannel handler because it was already released.",
            (void *)websocket);
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    websocket->thread_data.is_midchannel_handler = true;

    return AWS_OP_SUCCESS;
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

static int s_send_frame(
    struct aws_websocket *websocket,
    const struct aws_websocket_send_frame_options *options,
    bool from_public_api) {

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

    struct outgoing_frame *frame = aws_mem_calloc(websocket->alloc, 1, sizeof(struct outgoing_frame));
    if (!frame) {
        return AWS_OP_ERR;
    }

    frame->def = *options;

    /* Enqueue frame, unless no further sending is allowed. */
    int send_error = 0;
    bool should_schedule_task = false;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    if (websocket->synced_data.is_midchannel_handler && from_public_api) {
        send_error = AWS_ERROR_HTTP_WEBSOCKET_IS_MIDCHANNEL_HANDLER;
    } else if (websocket->synced_data.send_frame_error_code) {
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
        "id=%p: Enqueuing outgoing frame with opcode=%" PRIu8 "(%s) length=%" PRIu64 " fin=%s priority=%s",
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

int aws_websocket_send_frame(struct aws_websocket *websocket, const struct aws_websocket_send_frame_options *options) {
    return s_send_frame(websocket, options, true);
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
    int err;

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
    struct aws_io_message *io_msg = aws_channel_slot_acquire_max_message_for_write(websocket->channel_slot);
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
                "id=%p: Outgoing frame still in progress, but no more data can be written at this time.",
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

    /* If payload stream didn't have any bytes available to read right now, then the aws_io_message might be empty.
     * If this is the case schedule a task to try again in the future. */
    if (io_msg->message_data.len == 0) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Reading from payload stream would block, will try again later.",
            (void *)websocket);

        if (!websocket->thread_data.is_waiting_on_payload_stream_task) {
            websocket->thread_data.is_waiting_on_payload_stream_task = true;

            /* Future Optimization Idea: Minimize work while we wait. Use some kind of backoff for the retry timing,
             * or have some way for stream to notify when more data is available. */
            aws_channel_schedule_task_now(websocket->channel_slot->channel, &websocket->waiting_on_payload_stream_task);
        }

        aws_mem_release(io_msg->allocator, io_msg);
        return;
    }

    /* Prepare to send aws_io_message up the channel.
     * Note that the write-completion callback may fire before send_message() returns */

    /* If CLOSE frame was written, that's the last data we'll write */
    if (wrote_close_frame) {
        s_stop_writing(websocket, AWS_ERROR_HTTP_WEBSOCKET_CLOSE_FRAME_SENT);
    }

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Sending aws_io_message of size %zu in write direction.",
        (void *)websocket,
        io_msg->message_data.len);

    websocket->thread_data.is_waiting_for_write_completion = true;
    err = aws_channel_slot_send_message(websocket->channel_slot, io_msg, AWS_CHANNEL_DIR_WRITE);
    if (err) {
        websocket->thread_data.is_waiting_for_write_completion = false;
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Failed to send message in write direction, error %d (%s).",
            (void *)websocket,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    /* Finish shutdown if we were waiting for the CLOSE frame to be written */
    if (wrote_close_frame && websocket->thread_data.is_shutting_down_and_waiting_for_close_frame_to_be_written) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: CLOSE frame sent, finishing handler shutdown sequence.", (void *)websocket);

        s_finish_shutdown(websocket);
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

static void s_waiting_on_payload_stream_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        /* If channel has shut down, don't need to resume sending payload */
        return;
    }

    struct aws_websocket *websocket = arg;
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET, "id=%p: Done waiting for payload stream, sending more data...", (void *)websocket);

    websocket->thread_data.is_waiting_on_payload_stream_task = false;
    s_try_write_outgoing_frames(websocket);
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

    (void)slot;
    struct aws_websocket *websocket = handler->impl;
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));

    /* For each aws_io_message headed in the write direction, send a BINARY frame,
     * where the frame's payload is the data from this aws_io_message. */
    struct aws_websocket_send_frame_options options = {
        .payload_length = message->message_data.len,
        .user_data = message,
        .stream_outgoing_payload = s_midchannel_send_payload,
        .on_complete = s_midchannel_send_complete,
        .opcode = AWS_WEBSOCKET_OPCODE_BINARY,
        .fin = true,
    };

    /* Use copy_mark to track progress as the data is streamed out */
    message->copy_mark = 0;

    int err = s_send_frame(websocket, &options, false);
    if (err) {
        /* TODO: mqtt handler needs to clean up messsages that fail to send. */
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/* Callback for writing data from downstream aws_io_messages into payload of BINARY frames headed upstream */
static bool s_midchannel_send_payload(struct aws_websocket *websocket, struct aws_byte_buf *out_buf, void *user_data) {
    (void)websocket;
    struct aws_io_message *io_msg = user_data;

    /* copy_mark is used to track progress */
    size_t src_available = io_msg->message_data.len - io_msg->copy_mark;
    size_t dst_available = out_buf->capacity - out_buf->len;
    size_t sending = dst_available < src_available ? dst_available : src_available;

    bool success = aws_byte_buf_write(out_buf, io_msg->message_data.buffer + io_msg->copy_mark, sending);

    io_msg->copy_mark += sending;
    return success;
}

/* Callback when data from downstream aws_io_messages, finishes being sent as a BINARY frame upstream. */
static void s_midchannel_send_complete(struct aws_websocket *websocket, int error_code, void *user_data) {
    (void)websocket;
    struct aws_io_message *io_msg = user_data;

    if (io_msg->on_completion) {
        io_msg->on_completion(io_msg->owning_channel, io_msg, error_code, io_msg->user_data);
    }

    aws_mem_release(io_msg->allocator, io_msg);
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
    bool is_midchannel_handler;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);
    is_midchannel_handler = websocket->synced_data.is_midchannel_handler;
    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    if (is_midchannel_handler) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Ignoring close call, websocket has converted to midchannel handler.",
            (void *)websocket);
        return;
    }

    /* TODO: aws_channel_shutdown() should let users specify error_code and "immediate" as separate parameters.
     * Currently, any non-zero error_code results in "immediate" shutdown */
    int error_code = AWS_ERROR_SUCCESS;
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
            err = s_send_frame(websocket, &close_frame, false);
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
                    "id=%p: Outgoing CLOSE frame queued, handler will finish shutdown once it's sent.",
                    (void *)websocket);
                /* schedule a task to run after 1 sec. If the CLOSE still not sent at that time, we should just cancel
                 * sending it and shutdown the channel. */
                uint64_t schedule_time = 0;
                aws_channel_current_clock_time(websocket->channel_slot->channel, &schedule_time);
                schedule_time += AWS_WEBSOCKET_CLOSE_TIMEOUT;
                AWS_LOGF_TRACE(
                    AWS_LS_HTTP_WEBSOCKET,
                    "id=%p: websocket_close_timeout task will be run at timestamp %" PRIu64,
                    (void *)websocket,
                    schedule_time);
                aws_channel_schedule_task_future(
                    websocket->channel_slot->channel, &websocket->close_timeout_task, schedule_time);
            }
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_close_timeout_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        /* If channel has shut down, don't need to resume sending payload */
        return;
    }

    struct aws_websocket *websocket = arg;
    AWS_ASSERT(aws_channel_thread_is_callers_thread(websocket->channel_slot->channel));

    if (!websocket->thread_data.is_shutting_down_and_waiting_for_close_frame_to_be_written) {
        /* Not waiting for write to complete, which means the CLOSE frame has sent, just do nothing */
        return;
    }

    AWS_LOGF_WARN(
        AWS_LS_HTTP_WEBSOCKET,
        "id=%p: Failed to send CLOSE frame, timeout happened, shutdown the channel",
        (void *)websocket);

    s_stop_writing(websocket, AWS_ERROR_HTTP_CONNECTION_CLOSED);
    s_finish_shutdown(websocket);
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
        "id=%p: Begin processing incoming message of size %zu.",
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
                "id=%p: Failed processing incoming message, error %d (%s). Closing connection.",
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
                "id=%p: Failed to increment read window after message processing, error %d (%s). Closing "
                "connection.",
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
            "id=%p: Done processing incoming message, final %zu bytes ignored.",
            (void *)websocket,
            cursor.len);
    } else {
        AWS_LOGF_TRACE(AWS_LS_HTTP_WEBSOCKET, "id=%p: Done processing incoming message.", (void *)websocket);
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

    /* If CONTINUATION frames are expected, remember which type of data is being continued.
     * RFC-6455 Section 5.4 Fragmentation */
    if (aws_websocket_is_data_frame(frame->opcode)) {
        if (frame->opcode != AWS_WEBSOCKET_OPCODE_CONTINUATION) {
            if (frame->fin) {
                websocket->thread_data.continuation_of_opcode = 0;
            } else {
                websocket->thread_data.continuation_of_opcode = frame->opcode;
            }
        }
    }

    /* Invoke user cb */
    bool callback_result = true;
    if (websocket->on_incoming_frame_begin && !websocket->thread_data.is_midchannel_handler) {
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

    if (websocket->thread_data.is_midchannel_handler) {
        return s_decoder_on_midchannel_payload(websocket, data);
    }

    return s_decoder_on_user_payload(websocket, data);
}

/* Invoke user cb */
static int s_decoder_on_user_payload(struct aws_websocket *websocket, struct aws_byte_cursor data) {
    if (!websocket->on_incoming_frame_payload) {
        return AWS_OP_SUCCESS;
    }

    if (!websocket->on_incoming_frame_payload(
            websocket, websocket->thread_data.current_incoming_frame, data, websocket->user_data)) {

        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Incoming payload callback has reported a failure.", (void *)websocket);
        return aws_raise_error(AWS_ERROR_HTTP_CALLBACK_FAILURE);
    }

    /* If user reduced window_update_size, reduce how much the websocket will update its window */
    if (websocket->manual_window_update) {
        size_t reduce = data.len;
        websocket->thread_data.incoming_message_window_update -= data.len;
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Incoming payload callback changed window update size, window will shrink by %zu.",
            (void *)websocket,
            reduce);
    }

    return AWS_OP_SUCCESS;
}

/* Pass data to channel handler on the right */
static int s_decoder_on_midchannel_payload(struct aws_websocket *websocket, struct aws_byte_cursor data) {
    struct aws_io_message *io_msg = NULL;

    /* Only pass data to next handler if it's from a BINARY frame (or the CONTINUATION of a BINARY frame) */
    bool is_binary_data = websocket->thread_data.current_incoming_frame->opcode == AWS_WEBSOCKET_OPCODE_BINARY ||
                          (websocket->thread_data.current_incoming_frame->opcode == AWS_WEBSOCKET_OPCODE_CONTINUATION &&
                           websocket->thread_data.continuation_of_opcode == AWS_WEBSOCKET_OPCODE_BINARY);
    if (!is_binary_data) {
        return AWS_OP_SUCCESS;
    }

    AWS_ASSERT(websocket->channel_slot->adj_right); /* Expected another slot in the read direction */

    /* Note that current implementation of websocket handler does not buffer data travelling in the "read" direction,
     * so the downstream read window needs to be large enough to immediately receive incoming data. */
    if (aws_channel_slot_downstream_read_window(websocket->channel_slot) < data.len) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Cannot send entire message without exceeding read window.",
            (void *)websocket);
        aws_raise_error(AWS_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW);
        goto error;
    }

    io_msg = aws_channel_acquire_message_from_pool(
        websocket->channel_slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, data.len);
    if (!io_msg) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_WEBSOCKET, "id=%p: Failed to acquire message.", (void *)websocket);
        goto error;
    }

    if (io_msg->message_data.capacity < data.len) {
        /* Probably can't happen. Data is coming an aws_io_message, should be able to acquire another just as big */
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET, "id=%p: Failed to acquire sufficiently large message.", (void *)websocket);
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto error;
    }

    if (!aws_byte_buf_write_from_whole_cursor(&io_msg->message_data, data)) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_WEBSOCKET, "id=%p: Unexpected error while copying data.", (void *)websocket);
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto error;
    }

    int err = aws_channel_slot_send_message(websocket->channel_slot, io_msg, AWS_CHANNEL_DIR_READ);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Failed to send read message, error %d (%s).",
            (void *)websocket,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    /* Reduce amount by which websocket will update its read window */
    AWS_ASSERT(websocket->thread_data.incoming_message_window_update >= data.len);
    websocket->thread_data.incoming_message_window_update -= data.len;

    return AWS_OP_SUCCESS;

error:
    if (io_msg) {
        aws_mem_release(io_msg->allocator, io_msg);
    }
    return AWS_OP_ERR;
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
    if (websocket->on_incoming_frame_complete && !websocket->thread_data.is_midchannel_handler) {
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

    struct aws_websocket *websocket = handler->impl;
    AWS_ASSERT(aws_channel_thread_is_callers_thread(slot->channel));
    AWS_ASSERT(websocket->thread_data.is_midchannel_handler);

    /* NOTE: This is pretty hacky and should change if it ever causes issues.
     *
     * Currently, all read messages are processed the moment they're received.
     * If the downstream read window is open enough to accept this data, we can send it right along.
     * BUT if the downstream window were too small, we'd need to buffer the data and wait until
     * the downstream window opened again to finish sending.
     *
     * To avoid that complexity, we go to pains here to ensure that the websocket's window exactly
     * matches the window to the right, allowing us to avoid buffering in the read direction.
     */
    size_t increment = size;
    if (websocket->thread_data.last_known_right_slot != slot->adj_right) {
        if (size < slot->window_size) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_WEBSOCKET,
                "id=%p: The websocket does not support downstream handlers with a smaller window.",
                (void *)websocket);
            aws_raise_error(AWS_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW);
            goto error;
        }

        /* New handler to the right, make sure websocket's window matches its window. */
        websocket->thread_data.last_known_right_slot = slot->adj_right;
        increment = size - slot->window_size;
    }

    if (increment != 0) {
        int err = aws_channel_slot_increment_read_window(slot, increment);
        if (err) {
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    websocket->thread_data.is_reading_stopped = true;
    /* Shutting down channel because I know that no one ever checks these errors */
    s_shutdown_due_to_read_err(websocket, aws_last_error());
    return AWS_OP_ERR;
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

    /* Schedule a task to do the increment.
     * If task is already scheduled, just increase size to be incremented */
    bool is_midchannel_handler = false;
    bool should_schedule_task = false;

    /* BEGIN CRITICAL SECTION */
    s_lock_synced_data(websocket);

    if (websocket->synced_data.is_midchannel_handler) {
        is_midchannel_handler = true;
    } else if (websocket->synced_data.window_increment_size == 0) {
        should_schedule_task = true;
        websocket->synced_data.window_increment_size = size;
    } else {
        websocket->synced_data.window_increment_size =
            aws_add_size_saturating(websocket->synced_data.window_increment_size, size);
    }

    s_unlock_synced_data(websocket);
    /* END CRITICAL SECTION */

    if (is_midchannel_handler) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Ignoring window increment call, websocket has converted to midchannel handler.",
            (void *)websocket);
    } else if (should_schedule_task) {
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

int aws_websocket_random_handshake_key(struct aws_byte_buf *dst) {
    /* RFC-6455 Section 4.1.
     * Derive random 16-byte value, base64-encoded, for the Sec-WebSocket-Key header */
    uint8_t key_random_storage[16];
    struct aws_byte_buf key_random_buf = aws_byte_buf_from_empty_array(key_random_storage, sizeof(key_random_storage));
    int err = aws_device_random_buffer(&key_random_buf);
    if (err) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor key_random_cur = aws_byte_cursor_from_buf(&key_random_buf);
    err = aws_base64_encode(&key_random_cur, dst);
    if (err) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

struct aws_http_message *aws_http_message_new_websocket_handshake_request(
    struct aws_allocator *allocator,
    struct aws_byte_cursor path,
    struct aws_byte_cursor host) {

    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&path))
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&host))

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    if (!request) {
        goto error;
    }

    int err = aws_http_message_set_request_method(request, aws_http_method_get);
    if (err) {
        goto error;
    }

    err = aws_http_message_set_request_path(request, path);
    if (err) {
        goto error;
    }

    uint8_t key_storage[AWS_WEBSOCKET_MAX_HANDSHAKE_KEY_LENGTH];
    struct aws_byte_buf key_buf = aws_byte_buf_from_empty_array(key_storage, sizeof(key_storage));
    err = aws_websocket_random_handshake_key(&key_buf);
    if (err) {
        goto error;
    }

    struct aws_http_header required_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
            .value = host,
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("websocket"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Connection"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Upgrade"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Key"),
            .value = aws_byte_cursor_from_buf(&key_buf),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Version"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("13"),
        },
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(required_headers); ++i) {
        err = aws_http_message_add_header(request, required_headers[i]);
        if (err) {
            goto error;
        }
    }

    return request;

error:
    aws_http_message_destroy(request);
    return NULL;
}
