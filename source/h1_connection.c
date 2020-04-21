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
#include <aws/common/clock.h>
#include <aws/common/math.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/private/h1_connection.h>
#include <aws/http/private/h1_decoder.h>
#include <aws/http/private/h1_encoder.h>
#include <aws/http/private/h1_stream.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/http/statistics.h>
#include <aws/http/status_code.h>
#include <aws/io/logging.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

enum {
    DECODER_INITIAL_SCRATCH_SIZE = 256,
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
static void s_handler_installed(struct aws_channel_handler *handler, struct aws_channel_slot *slot);
static struct aws_http_stream *s_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);
static struct aws_http_stream *s_new_server_request_handler_stream(
    const struct aws_http_request_handler_options *options);
static int s_stream_send_response(struct aws_http_stream *stream, struct aws_http_message *response);
static void s_connection_close(struct aws_http_connection *connection_base);
static bool s_connection_is_open(const struct aws_http_connection *connection_base);
static void s_connection_update_window(struct aws_http_connection *connection_base, size_t increment_size);
static int s_decoder_on_request(
    enum aws_http_method method_enum,
    const struct aws_byte_cursor *method_str,
    const struct aws_byte_cursor *uri,
    void *user_data);
static int s_decoder_on_response(int status_code, void *user_data);
static int s_decoder_on_header(const struct aws_h1_decoded_header *header, void *user_data);
static int s_decoder_on_body(const struct aws_byte_cursor *data, bool finished, void *user_data);
static int s_decoder_on_done(void *user_data);
static void s_reset_statistics(struct aws_channel_handler *handler);
static void s_gather_statistics(struct aws_channel_handler *handler, struct aws_array_list *stats);

static struct aws_http_connection_vtable s_h1_connection_vtable = {
    .channel_handler_vtable =
        {
            .process_read_message = s_handler_process_read_message,
            .process_write_message = s_handler_process_write_message,
            .increment_read_window = s_handler_increment_read_window,
            .shutdown = s_handler_shutdown,
            .initial_window_size = s_handler_initial_window_size,
            .message_overhead = s_handler_message_overhead,
            .destroy = s_handler_destroy,
            .reset_statistics = s_reset_statistics,
            .gather_statistics = s_gather_statistics,
        },
    .on_channel_handler_installed = s_handler_installed,
    .make_request = s_make_request,
    .new_server_request_handler_stream = s_new_server_request_handler_stream,
    .stream_send_response = s_stream_send_response,
    .close = s_connection_close,
    .is_open = s_connection_is_open,
    .update_window = s_connection_update_window,
};

static const struct aws_h1_decoder_vtable s_h1_decoder_vtable = {
    .on_request = s_decoder_on_request,
    .on_response = s_decoder_on_response,
    .on_header = s_decoder_on_header,
    .on_body = s_decoder_on_body,
    .on_done = s_decoder_on_done,
};

struct h1_connection {
    struct aws_http_connection base;

    size_t initial_window_size;

    /* Single task used repeatedly for sending data from streams. */
    struct aws_channel_task outgoing_stream_task;

    /* Single task used for issuing window updates from off-thread */
    struct aws_channel_task window_update_task;

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

        /* True when read and/or writing has stopped, whether due to errors or normal channel shutdown. */
        bool is_reading_stopped;
        bool is_writing_stopped;

        /* If true, the connection has upgraded to another protocol.
         * It will pass data to adjacent channel handlers without altering it.
         * The connection can no longer service request/response streams. */
        bool has_switched_protocols;

        /* Server-only. Request-handler streams can only be created while this is true. */
        bool can_create_request_handler_stream;

        struct aws_crt_statistics_http1_channel stats;

        uint64_t outgoing_stream_timestamp_ns;
        uint64_t incoming_stream_timestamp_ns;

    } thread_data;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

        /* New client streams that have not been moved to `stream_list` yet.
         * This list is not used on servers. */
        struct aws_linked_list new_client_stream_list;

        bool is_outgoing_stream_task_active;

        /* For checking status from outside the event-loop thread. */
        bool is_open;

        /* If non-zero, reason to immediately reject new streams. (ex: closing, switched protocols) */
        int new_stream_error_code;

        /* If non-zero, then window_update_task is scheduled */
        size_t window_update_size;
    } synced_data;
};

void s_h1_connection_lock_synced_data(struct h1_connection *connection) {
    int err = aws_mutex_lock(&connection->synced_data.lock);
    AWS_ASSERT(!err);
    (void)err;
}

void s_h1_connection_unlock_synced_data(struct h1_connection *connection) {
    int err = aws_mutex_unlock(&connection->synced_data.lock);
    AWS_ASSERT(!err);
    (void)err;
}

/**
 * Internal function for bringing connection to a stop.
 * Invoked multiple times, including when:
 * - Channel is shutting down in the read direction.
 * - Channel is shutting down in the write direction.
 * - An error occurs.
 * - User wishes to close the connection (this is the only case where the function may run off-thread).
 */
static void s_stop(
    struct h1_connection *connection,
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
    { /* BEGIN CRITICAL SECTION */
        s_h1_connection_lock_synced_data(connection);

        /* Even if we're not scheduling shutdown just yet (ex: sent final request but waiting to read final response)
         * we don't consider the connection "open" anymore so user can't create more streams */
        connection->synced_data.new_stream_error_code = AWS_ERROR_HTTP_CONNECTION_CLOSED;
        connection->synced_data.is_open = false;

        s_h1_connection_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

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

static void s_shutdown_due_to_error(struct h1_connection *connection, int error_code) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));

    if (!error_code) {
        error_code = AWS_ERROR_UNKNOWN;
    }

    /* Stop reading AND writing if an error occurs.
     *
     * It doesn't currently seem worth the complexity to distinguish between read errors and write errors.
     * The only scenarios that would benefit from this are pipelining scenarios (ex: A server
     * could continue sending a response to request A if there was an error reading request B).
     * But pipelining in HTTP/1.1 is known to be fragile with regards to errors, so let's just keep it simple.
     */
    s_stop(connection, true /*stop_reading*/, true /*stop_writing*/, true /*schedule_shutdown*/, error_code);
}

/**
 * Public function for closing connection.
 */
static void s_connection_close(struct aws_http_connection *connection_base) {
    struct h1_connection *connection = AWS_CONTAINER_OF(connection_base, struct h1_connection, base);

    /* Don't stop reading/writing immediately, let that happen naturally during the channel shutdown process. */
    s_stop(connection, false /*stop_reading*/, false /*stop_writing*/, true /*schedule_shutdown*/, AWS_ERROR_SUCCESS);
}

static bool s_connection_is_open(const struct aws_http_connection *connection_base) {
    struct h1_connection *connection = AWS_CONTAINER_OF(connection_base, struct h1_connection, base);
    bool is_open;

    { /* BEGIN CRITICAL SECTION */
        s_h1_connection_lock_synced_data(connection);
        is_open = connection->synced_data.is_open;
        s_h1_connection_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    return is_open;
}

static int s_stream_send_response(struct aws_http_stream *stream, struct aws_http_message *response) {
    AWS_PRECONDITION(stream);
    AWS_PRECONDITION(response);

    int err;
    int send_err = AWS_ERROR_SUCCESS;
    struct aws_h1_stream *h1_stream = AWS_CONTAINER_OF(stream, struct aws_h1_stream, base);
    struct h1_connection *connection = AWS_CONTAINER_OF(stream->owning_connection, struct h1_connection, base);

    /* Validate the response and cache info that encoder will eventually need.
     * The encoder_message object will be moved into the stream later while holding the lock */
    struct aws_h1_encoder_message encoder_message;
    bool body_headers_ignored = h1_stream->base.request_method == AWS_HTTP_METHOD_HEAD;
    err = aws_h1_encoder_message_init_from_response(&encoder_message, stream->alloc, response, body_headers_ignored);
    if (err) {
        send_err = aws_last_error();
        goto response_error;
    }

    bool should_schedule_task = false;
    { /* BEGIN CRITICAL SECTION */
        s_h1_connection_lock_synced_data(connection);
        if (h1_stream->synced_data.has_outgoing_response) {
            AWS_LOGF_ERROR(AWS_LS_HTTP_CONNECTION, "id=%p: Response already created on the stream", (void *)stream);
            send_err = AWS_ERROR_INVALID_STATE;
        } else {
            h1_stream->synced_data.has_outgoing_response = true;
            h1_stream->encoder_message = encoder_message;
            if (encoder_message.has_connection_close_header) {
                h1_stream->is_final_stream = true;
            }

            if (!connection->synced_data.is_outgoing_stream_task_active) {
                connection->synced_data.is_outgoing_stream_task_active = true;
                should_schedule_task = true;
            }
        }
        s_h1_connection_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    if (send_err) {
        goto response_error;
    }

    /* Success! */
    AWS_LOGF_DEBUG(
        AWS_LS_HTTP_STREAM, "id=%p: Created response on connection=%p: ", (void *)stream, (void *)connection);

    if (should_schedule_task) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Scheduling outgoing stream task.", (void *)&connection->base);
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->outgoing_stream_task);
    }

    return AWS_OP_SUCCESS;

response_error:
    aws_h1_encoder_message_clean_up(&encoder_message);
    aws_raise_error(send_err);
    AWS_LOGF_ERROR(
        AWS_LS_HTTP_STREAM,
        "id=%p: Sending response on the stream failed, error %d (%s)",
        (void *)stream,
        aws_last_error(),
        aws_error_name(aws_last_error()));
    return AWS_OP_ERR;
}

static void s_update_window_action(struct h1_connection *connection, size_t increment_size) {
    int err = aws_channel_slot_increment_read_window(connection->base.channel_slot, increment_size);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Failed to increment read window, error %d (%s). Closing connection.",
            (void *)&connection->base,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        s_shutdown_due_to_error(connection, aws_last_error());
    }
}

static void s_connection_update_window(struct aws_http_connection *connection_base, size_t increment_size) {
    struct h1_connection *connection = AWS_CONTAINER_OF(connection_base, struct h1_connection, base);

    if (increment_size == 0) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Ignoring window update of size 0.", (void *)&connection->base);
        return;
    }

    /* If we're on the thread, just do it. */
    if (aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel)) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Issuing immediate window update of %zu.",
            (void *)&connection->base,
            increment_size);
        s_update_window_action(connection, increment_size);
        return;
    }

    /* Otherwise, schedule a task to do it.
     * If task is already scheduled, just increase size to be updated */

    /* BEGIN CRITICAL SECTION */
    s_h1_connection_lock_synced_data(connection);

    /* if this is not volatile, gcc-4x will load window_update_size's address into a register
     * and then read it as should_schedule_task down below, which will invert its meaning */
    volatile bool should_schedule_task = (connection->synced_data.window_update_size == 0);
    connection->synced_data.window_update_size =
        aws_add_size_saturating(connection->synced_data.window_update_size, increment_size);

    s_h1_connection_unlock_synced_data(connection);
    /* END CRITICAL SECTION */

    if (should_schedule_task) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Scheduling task for window update of %zu.",
            (void *)&connection->base,
            increment_size);

        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->window_update_task);
    } else {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Window update must already scheduled, increased scheduled size by %zu.",
            (void *)&connection->base,
            increment_size);
    }
}

int aws_h1_stream_activate(struct aws_http_stream *stream) {
    struct aws_h1_stream *h1_stream = AWS_CONTAINER_OF(stream, struct aws_h1_stream, base);

    struct aws_http_connection *base_connection = stream->owning_connection;
    struct h1_connection *connection = AWS_CONTAINER_OF(base_connection, struct h1_connection, base);

    bool should_schedule_task = false;

    { /* BEGIN CRITICAL SECTION */
        s_h1_connection_lock_synced_data(connection);

        if (stream->id) {
            /* stream has already been activated. */
            s_h1_connection_unlock_synced_data(connection);
            return AWS_OP_SUCCESS;
        }

        stream->id = aws_http_connection_get_next_stream_id(base_connection);

        if (stream->id) {
            aws_linked_list_push_back(&connection->synced_data.new_client_stream_list, &h1_stream->node);
            if (!connection->synced_data.is_outgoing_stream_task_active) {
                connection->synced_data.is_outgoing_stream_task_active = true;
                should_schedule_task = true;
            }
        }

        s_h1_connection_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    if (!stream->id) {
        /* aws_http_connection_get_next_stream_id() raises its own error. */
        return AWS_OP_ERR;
    }

    /* connection keeps activated stream alive until stream completes */
    aws_atomic_fetch_add(&stream->refcount, 1);

    if (should_schedule_task) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Scheduling outgoing stream task.", (void *)&connection->base);
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->outgoing_stream_task);
    }

    return AWS_OP_SUCCESS;
}

struct aws_http_stream *s_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {
    struct aws_h1_stream *stream = aws_h1_stream_new_request(client_connection, options);
    if (!stream) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create request stream, error %d (%s)",
            (void *)client_connection,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        return NULL;
    }

    struct h1_connection *connection = AWS_CONTAINER_OF(client_connection, struct h1_connection, base);

    /* Insert new stream into pending list, and schedule outgoing_stream_task if it's not already running. */
    int new_stream_error_code = AWS_ERROR_SUCCESS;

    { /* BEGIN CRITICAL SECTION */
        s_h1_connection_lock_synced_data(connection);
        if (connection->synced_data.new_stream_error_code) {
            new_stream_error_code = connection->synced_data.new_stream_error_code;
        }
        s_h1_connection_unlock_synced_data(connection);
    } /* END CRITICAL SECTION */

    if (new_stream_error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create request stream, error %d (%s)",
            (void *)client_connection,
            new_stream_error_code,
            aws_error_name(new_stream_error_code));

        aws_raise_error(new_stream_error_code);
        goto error;
    }

    /* Success! */
    struct aws_byte_cursor method;
    aws_http_message_get_request_method(options->request, &method);
    stream->base.request_method = aws_http_str_to_method(method);
    struct aws_byte_cursor path;
    aws_http_message_get_request_path(options->request, &path);
    AWS_LOGF_DEBUG(
        AWS_LS_HTTP_STREAM,
        "id=%p: Created client request on connection=%p: " PRInSTR " " PRInSTR " " PRInSTR,
        (void *)&stream->base,
        (void *)client_connection,
        AWS_BYTE_CURSOR_PRI(method),
        AWS_BYTE_CURSOR_PRI(path),
        AWS_BYTE_CURSOR_PRI(aws_http_version_to_str(connection->base.http_version)));

    return &stream->base;

error:
    /* Force destruction of the stream, avoiding ref counting */
    stream->base.vtable->destroy(&stream->base);
    return NULL;
}

static void s_update_window_task(struct aws_channel_task *channel_task, void *arg, enum aws_task_status status) {
    (void)channel_task;
    struct h1_connection *connection = arg;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    /* BEGIN CRITICAL SECTION */
    s_h1_connection_lock_synced_data(connection);

    size_t window_update_size = connection->synced_data.window_update_size;
    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Zeroing window update size, was %zu",
        (void *)&connection->base,
        window_update_size);
    connection->synced_data.window_update_size = 0;

    s_h1_connection_unlock_synced_data(connection);
    /* END CRITICAL SECTION */

    s_update_window_action(connection, window_update_size);
}

static void s_stream_complete(struct aws_h1_stream *stream, int error_code) {
    struct h1_connection *connection = AWS_CONTAINER_OF(stream->base.owning_connection, struct h1_connection, base);

    /* Remove stream from list. */
    aws_linked_list_remove(&stream->node);

    /* Nice logging */
    if (error_code) {
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Stream completed with error code %d (%s).",
            (void *)&stream->base,
            error_code,
            aws_error_name(error_code));

    } else if (stream->base.client_data) {
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Client request complete, response status: %d (%s).",
            (void *)&stream->base,
            stream->base.client_data->response_status,
            aws_http_status_text(stream->base.client_data->response_status));
    } else {
        AWS_ASSERT(stream->base.server_data);
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Server response to " PRInSTR " request complete.",
            (void *)&stream->base,
            AWS_BYTE_CURSOR_PRI(stream->base.server_data->request_method_str));
    }

    /* If connection must shut down, do it BEFORE invoking stream-complete callback.
     * That way, if aws_http_connection_is_open() is called from stream-complete callback, it returns false. */
    if (stream->is_final_stream) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Closing connection due to completion of final stream.",
            (void *)&connection->base);

        s_connection_close(&connection->base);
    }

    /* Invoke callback and clean up stream. */
    if (stream->base.on_complete) {
        stream->base.on_complete(&stream->base, error_code, stream->base.user_data);
    }

    aws_http_stream_release(&stream->base);
}

static void s_add_time_measurement_to_stats(uint64_t start_ns, uint64_t end_ns, uint64_t *output_ms) {
    if (end_ns > start_ns) {
        *output_ms += aws_timestamp_convert(end_ns - start_ns, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_MILLIS, NULL);
    }
}

static void s_set_outgoing_stream_ptr(struct h1_connection *connection, struct aws_h1_stream *next_outgoing_stream) {
    struct aws_h1_stream *prev = connection->thread_data.outgoing_stream;

    uint64_t now_ns = 0;
    aws_channel_current_clock_time(connection->base.channel_slot->channel, &now_ns);
    if (prev == NULL && next_outgoing_stream != NULL) {
        /* transition from nothing to write -> something to write */
        connection->thread_data.outgoing_stream_timestamp_ns = now_ns;
    } else if (prev != NULL && next_outgoing_stream == NULL) {
        /* transition from something to write -> nothing to write */
        s_add_time_measurement_to_stats(
            connection->thread_data.outgoing_stream_timestamp_ns,
            now_ns,
            &connection->thread_data.stats.pending_outgoing_stream_ms);
    }

    connection->thread_data.outgoing_stream = next_outgoing_stream;
}

static void s_set_incoming_stream_ptr(struct h1_connection *connection, struct aws_h1_stream *next_incoming_stream) {
    struct aws_h1_stream *prev = connection->thread_data.incoming_stream;

    uint64_t now_ns = 0;
    aws_channel_current_clock_time(connection->base.channel_slot->channel, &now_ns);
    if (prev == NULL && next_incoming_stream != NULL) {
        /* transition from nothing to read -> something to read */
        connection->thread_data.incoming_stream_timestamp_ns = now_ns;
    } else if (prev != NULL && next_incoming_stream == NULL) {
        /* transition from something to read -> nothing to read */
        s_add_time_measurement_to_stats(
            connection->thread_data.incoming_stream_timestamp_ns,
            now_ns,
            &connection->thread_data.stats.pending_incoming_stream_ms);
    }

    connection->thread_data.incoming_stream = next_incoming_stream;
}

/**
 * Ensure `incoming_stream` is pointing at the correct stream, and update state if it changes.
 */
static void s_client_update_incoming_stream_ptr(struct h1_connection *connection) {
    struct aws_linked_list *list = &connection->thread_data.stream_list;
    struct aws_h1_stream *desired;
    if (connection->thread_data.is_reading_stopped) {
        desired = NULL;
    } else if (aws_linked_list_empty(list)) {
        desired = NULL;
    } else {
        desired = AWS_CONTAINER_OF(aws_linked_list_begin(list), struct aws_h1_stream, node);
    }

    if (connection->thread_data.incoming_stream == desired) {
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Current incoming stream is now %p.",
        (void *)&connection->base,
        desired ? (void *)&desired->base : NULL);

    s_set_incoming_stream_ptr(connection, desired);
}

/**
 * If necessary, update `outgoing_stream` so it is pointing at a stream
 * with data to send, or NULL if all streams are done sending data.
 *
 * Called from event-loop thread.
 * This function has lots of side effects.
 */
static struct aws_h1_stream *s_update_outgoing_stream_ptr(struct h1_connection *connection) {
    struct aws_h1_stream *current = connection->thread_data.outgoing_stream;
    bool current_changed = false;
    int err;

    /* If current stream is done sending data... */
    if (current && !aws_h1_encoder_is_message_in_progress(&connection->thread_data.encoder)) {
        current->is_outgoing_message_done = true;

        /* RFC-7230 section 6.6: Tear-down.
         * If this was the final stream, don't allows any further streams to be sent */
        if (current->is_final_stream) {
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Done sending final stream, no further streams will be sent.",
                (void *)&connection->base);

            s_stop(
                connection,
                false /*stop_reading*/,
                true /*stop_writing*/,
                false /*schedule_shutdown*/,
                AWS_ERROR_SUCCESS);
        }

        /* If it's also done receiving data, then it's complete! */
        if (current->is_incoming_message_done) {
            /* Only 1st stream in list could finish receiving before it finished sending */
            AWS_ASSERT(&current->node == aws_linked_list_begin(&connection->thread_data.stream_list));

            /* This removes stream from list */
            s_stream_complete(current, AWS_ERROR_SUCCESS);
        }

        current = NULL;
        current_changed = true;
    }

    /* If current stream is NULL, look for more work. */
    if (!current && !connection->thread_data.is_writing_stopped) {

        /* ----- BEGIN CRITICAL SECTION ----- */
        s_h1_connection_lock_synced_data(connection);

        /* Move any streams from new_client_stream_list to stream_list.
         * NOTE: Can't just swap lists because stream_list might not be empty. */
        while (!aws_linked_list_empty(&connection->synced_data.new_client_stream_list)) {
            aws_linked_list_push_back(
                &connection->thread_data.stream_list,
                aws_linked_list_pop_front(&connection->synced_data.new_client_stream_list));
        }

        /* Look for next stream we can work on. */
        for (struct aws_linked_list_node *node = aws_linked_list_begin(&connection->thread_data.stream_list);
             node != aws_linked_list_end(&connection->thread_data.stream_list);
             node = aws_linked_list_next(node)) {

            struct aws_h1_stream *stream = AWS_CONTAINER_OF(node, struct aws_h1_stream, node);

            /* If we already sent this stream's data, keep looking... */
            if (stream->is_outgoing_message_done) {
                continue;
            }

            /* STOP if we're a server, and this stream's response isn't ready to send.
             * It's not like we can skip this and start on the next stream because responses must be sent in order.
             * Don't need a check like this for clients because their streams always start with data to send. */
            if (connection->base.server_data && !stream->synced_data.has_outgoing_response) {
                break;
            }

            /* We found a stream to work on! */
            current = stream;
            current_changed = true;
            break;
        }

        if (!current) {
            /* If no more work to do. Set this false while we're holding the lock. */
            connection->synced_data.is_outgoing_stream_task_active = false;
        }

        s_h1_connection_unlock_synced_data(connection);
        /* ----- END CRITICAL SECTION ----- */
    }

    /* Update current incoming and outgoing streams. */
    if (current_changed) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Current outgoing stream is now %p.",
            (void *)&connection->base,
            current ? (void *)&current->base : NULL);

        s_set_outgoing_stream_ptr(connection, current);

        if (current) {
            err = aws_h1_encoder_start_message(
                &connection->thread_data.encoder, &current->encoder_message, &current->base);
            (void)err;
            AWS_ASSERT(!err);
        }

        /* incoming_stream update is only for client */
        if (connection->base.client_data) {
            s_client_update_incoming_stream_ptr(connection);
        }
    }

    return current;
}

/* Runs after an aws_io_message containing HTTP has completed (written to the network, or failed).
 * This does NOT run after switching protocols, when we're dumbly forwarding aws_io_messages
 * as a midchannel handler. */
static void s_on_channel_write_complete(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data) {

    (void)message;
    struct h1_connection *connection = user_data;

    if (err_code) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Message did not write to network, error %d (%s)",
            (void *)&connection->base,
            err_code,
            aws_error_name(err_code));

        s_shutdown_due_to_error(connection, err_code);
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Message finished writing to network. Rescheduling outgoing stream task.",
        (void *)&connection->base);

    /* To avoid wasting memory, we only want ONE of our written aws_io_messages in the channel at a time.
     * Therefore, we wait until it's written to the network before trying to send another
     * by running the outgoing-stream-task again.
     *
     * We also want to share the network with other channels.
     * Therefore, when the write completes, we SCHEDULE the outgoing-stream-task
     * to run again instead of calling the function directly.
     * This way, if the message completes synchronously,
     * we're not hogging the network by writing message after message in a tight loop */
    aws_channel_schedule_task_now(channel, &connection->outgoing_stream_task);
}

static void s_outgoing_stream_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct h1_connection *connection = arg;
    struct aws_channel *channel = connection->base.channel_slot->channel;
    struct aws_io_message *msg = NULL;

    /* Stop task if we're no longer writing stream data */
    if (connection->thread_data.is_writing_stopped || connection->thread_data.has_switched_protocols) {
        return;
    }

    AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Outgoing stream task is running.", (void *)&connection->base);

    struct aws_h1_stream *outgoing_stream = s_update_outgoing_stream_ptr(connection);
    if (!outgoing_stream) {
        /* Note: outgoing_stream_task_active is set false by s_update_outgoing_stream_ptr()
         * if there are no streams are ready to write. We do it there while holding the lock. */
        AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Outgoing stream task complete.", (void *)&connection->base);
        return;
    }

    msg = aws_channel_slot_acquire_max_message_for_write(connection->base.channel_slot);
    if (!msg) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Failed to acquire message from pool, error %d (%s). Closing connection.",
            (void *)&connection->base,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    /* Set up callback so we can send another message when this one completes */
    msg->on_completion = s_on_channel_write_complete;
    msg->user_data = connection;

    /**
     * Fill message data from the outgoing stream.
     * Note that we might be resuming work on a stream from a previous run of this task.
     */
    if (aws_h1_encoder_process(&connection->thread_data.encoder, &msg->message_data)) {
        /* Error sending data, abandon ship */
        goto error;
    }

    if (msg->message_data.len > 0) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Outgoing stream task is sending message of size %zu.",
            (void *)&connection->base,
            msg->message_data.len);

        if (aws_channel_slot_send_message(connection->base.channel_slot, msg, AWS_CHANNEL_DIR_WRITE)) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Failed to send message down channel, error %d (%s). Closing connection.",
                (void *)&connection->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            goto error;
        }

    } else {
        /* If message is empty, warn that no work is being done
         * and reschedule the task to try again next tick.
         * It's likely that body isn't ready, so body streaming function has no data to write yet.
         * If this scenario turns out to be common we should implement a "pause" feature. */
        AWS_LOGF_WARN(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Current outgoing stream %p sent no data, will try again next tick.",
            (void *)&connection->base,
            outgoing_stream ? (void *)&outgoing_stream->base : NULL);

        aws_mem_release(msg->allocator, msg);

        aws_channel_schedule_task_now(channel, task);
    }

    return;
error:
    if (msg) {
        aws_mem_release(msg->allocator, msg);
    }

    s_shutdown_due_to_error(connection, aws_last_error());
}

static int s_decoder_on_request(
    enum aws_http_method method_enum,
    const struct aws_byte_cursor *method_str,
    const struct aws_byte_cursor *uri,
    void *user_data) {

    struct h1_connection *connection = user_data;
    struct aws_h1_stream *incoming_stream = connection->thread_data.incoming_stream;

    AWS_FATAL_ASSERT(connection->thread_data.incoming_stream->base.server_data); /* Request but I'm a client?!?!? */

    AWS_ASSERT(incoming_stream->base.server_data->request_method_str.len == 0);
    AWS_ASSERT(incoming_stream->base.server_data->request_path.len == 0);

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM,
        "id=%p: Incoming request: method=" PRInSTR " uri=" PRInSTR,
        (void *)&incoming_stream->base,
        AWS_BYTE_CURSOR_PRI(*method_str),
        AWS_BYTE_CURSOR_PRI(*uri));

    /* Copy strings to internal buffer */
    struct aws_byte_buf *storage_buf = &incoming_stream->incoming_storage_buf;
    AWS_ASSERT(storage_buf->capacity == 0);

    size_t storage_size = 0;
    int err = aws_add_size_checked(uri->len, method_str->len, &storage_size);
    if (err) {
        goto error;
    }

    err = aws_byte_buf_init(storage_buf, incoming_stream->base.alloc, storage_size);
    if (err) {
        goto error;
    }

    aws_byte_buf_write_from_whole_cursor(storage_buf, *method_str);
    incoming_stream->base.server_data->request_method_str = aws_byte_cursor_from_buf(storage_buf);

    aws_byte_buf_write_from_whole_cursor(storage_buf, *uri);
    incoming_stream->base.server_data->request_path = aws_byte_cursor_from_buf(storage_buf);
    aws_byte_cursor_advance(&incoming_stream->base.server_data->request_path, storage_buf->len - uri->len);
    incoming_stream->base.request_method = method_enum;

    /* No user callbacks, so we're not checking for shutdown */
    return AWS_OP_SUCCESS;

error:
    AWS_LOGF_ERROR(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Failed to process new incoming request, error %d (%s).",
        (void *)&connection->base,
        aws_last_error(),
        aws_error_name(aws_last_error()));

    return AWS_OP_ERR;
}

static int s_decoder_on_response(int status_code, void *user_data) {
    struct h1_connection *connection = user_data;

    AWS_FATAL_ASSERT(connection->thread_data.incoming_stream->base.client_data); /* Response but I'm a server?!?!? */

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM,
        "id=%p: Incoming response status: %d (%s).",
        (void *)&connection->thread_data.incoming_stream->base,
        status_code,
        aws_http_status_text(status_code));

    connection->thread_data.incoming_stream->base.client_data->response_status = status_code;

    /* No user callbacks, so we're not checking for shutdown */
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_header(const struct aws_h1_decoded_header *header, void *user_data) {
    struct h1_connection *connection = user_data;
    struct aws_h1_stream *incoming_stream = connection->thread_data.incoming_stream;

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM,
        "id=%p: Incoming header: " PRInSTR ": " PRInSTR,
        (void *)&incoming_stream->base,
        AWS_BYTE_CURSOR_PRI(header->name_data),
        AWS_BYTE_CURSOR_PRI(header->value_data));

    enum aws_http_header_block header_block =
        aws_h1_decoder_get_header_block(connection->thread_data.incoming_stream_decoder);

    /* RFC-7230 section 6.1.
     * "Connection: close" header signals that a connection will not persist after the current request/response */
    if (header->name == AWS_HTTP_HEADER_CONNECTION) {
        /* Certain L7 proxies send a connection close header on a 200/OK response to a CONNECT request. This is nutty
         * behavior, but the obviously desired behavior on a 200 CONNECT response is to leave the connection open
         * for the tunneling. */
        bool ignore_connection_close =
            incoming_stream->base.request_method == AWS_HTTP_METHOD_CONNECT && incoming_stream->base.client_data &&
            incoming_stream->base.client_data->response_status == AWS_HTTP_STATUS_CODE_200_OK;

        if (!ignore_connection_close && aws_byte_cursor_eq_c_str_ignore_case(&header->value_data, "close")) {
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_STREAM,
                "id=%p: Received 'Connection: close' header. This will be the final stream on this connection.",
                (void *)&incoming_stream->base);

            incoming_stream->is_final_stream = true;
        }
    }

    if (incoming_stream->base.on_incoming_headers) {
        struct aws_http_header deliver = {
            .name = header->name_data,
            .value = header->value_data,
        };

        int err = incoming_stream->base.on_incoming_headers(
            &incoming_stream->base, header_block, &deliver, 1, incoming_stream->base.user_data);

        if (err) {
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_STREAM,
                "id=%p: Incoming header callback raised error %d (%s).",
                (void *)&incoming_stream->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_mark_head_done(struct aws_h1_stream *incoming_stream) {
    /* Bail out if we've already done this */
    if (incoming_stream->is_incoming_head_done) {
        return AWS_OP_SUCCESS;
    }

    struct h1_connection *connection =
        AWS_CONTAINER_OF(incoming_stream->base.owning_connection, struct h1_connection, base);

    enum aws_http_header_block header_block =
        aws_h1_decoder_get_header_block(connection->thread_data.incoming_stream_decoder);

    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Main header block done.", (void *)&incoming_stream->base);
        incoming_stream->is_incoming_head_done = true;

    } else if (header_block == AWS_HTTP_HEADER_BLOCK_INFORMATIONAL) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Informational header block done.", (void *)&incoming_stream->base);

        /* Only clients can receive informational headers.
         * Check whether we're switching protocols */
        if (incoming_stream->base.client_data->response_status == AWS_HTTP_STATUS_CODE_101_SWITCHING_PROTOCOLS) {

            /* Switching protocols while there are multiple streams is too complex to deal with.
             * Ensure stream_list has exactly this 1 stream in it. */
            if (aws_linked_list_begin(&connection->thread_data.stream_list) !=
                aws_linked_list_rbegin(&connection->thread_data.stream_list)) {
                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_CONNECTION,
                    "id=%p: Cannot switch protocols while further streams are pending, closing connection.",
                    (void *)&connection->base);

                return aws_raise_error(AWS_ERROR_INVALID_STATE);
            }

            AWS_LOGF_TRACE(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Connection has switched protocols, another channel handler must be installed to"
                " deal with further data.",
                (void *)&connection->base);

            connection->thread_data.has_switched_protocols = true;

            { /* BEGIN CRITICAL SECTION */
                s_h1_connection_lock_synced_data(connection);
                connection->synced_data.new_stream_error_code = AWS_ERROR_HTTP_SWITCHED_PROTOCOLS;
                s_h1_connection_unlock_synced_data(connection);
            } /* END CRITICAL SECTION */
        }
    }

    /* Invoke user cb */
    if (incoming_stream->base.on_incoming_header_block_done) {
        int err = incoming_stream->base.on_incoming_header_block_done(
            &incoming_stream->base, header_block, incoming_stream->base.user_data);
        if (err) {
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_STREAM,
                "id=%p: Incoming-header-block-done callback raised error %d (%s).",
                (void *)&incoming_stream->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_body(const struct aws_byte_cursor *data, bool finished, void *user_data) {
    (void)finished;

    struct h1_connection *connection = user_data;
    struct aws_h1_stream *incoming_stream = connection->thread_data.incoming_stream;
    AWS_ASSERT(incoming_stream);

    int err = s_mark_head_done(incoming_stream);
    if (err) {
        return AWS_OP_ERR;
    }

    /* No need to invoke callback for 0-length data */
    if (data->len == 0) {
        return AWS_OP_SUCCESS;
    }

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM, "id=%p: Incoming body: %zu bytes received.", (void *)&incoming_stream->base, data->len);

    /* If the user wishes to manually increment windows, by default shrink the window by the amount of data read. */
    if (incoming_stream->base.manual_window_management) {
        connection->thread_data.incoming_message_window_shrink_size += data->len;
    }

    if (incoming_stream->base.on_incoming_body) {
        err = incoming_stream->base.on_incoming_body(&incoming_stream->base, data, incoming_stream->base.user_data);
        if (err) {
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_STREAM,
                "id=%p: Incoming body callback raised error %d (%s).",
                (void *)&incoming_stream->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_done(void *user_data) {
    struct h1_connection *connection = user_data;
    struct aws_h1_stream *incoming_stream = connection->thread_data.incoming_stream;
    AWS_ASSERT(incoming_stream);

    /* Ensure head was marked done */
    int err = s_mark_head_done(incoming_stream);
    if (err) {
        return AWS_OP_ERR;
    }
    /* If it is a informational response, we stop here, keep waiting for new response */
    enum aws_http_header_block header_block =
        aws_h1_decoder_get_header_block(connection->thread_data.incoming_stream_decoder);
    if (header_block == AWS_HTTP_HEADER_BLOCK_INFORMATIONAL) {
        return AWS_OP_SUCCESS;
    }

    /* Otherwise the incoming stream is finished decoding and we will update it if needed */
    incoming_stream->is_incoming_message_done = true;

    /* RFC-7230 section 6.6
     * After reading the final message, the connection must not read any more */
    if (incoming_stream->is_final_stream) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Done reading final stream, no further streams will be read.",
            (void *)&connection->base);

        s_stop(
            connection, true /*stop_reading*/, false /*stop_writing*/, false /*schedule_shutdown*/, AWS_ERROR_SUCCESS);
    }

    if (connection->base.server_data) {
        /* Server side */
        aws_http_on_incoming_request_done_fn *on_request_done = incoming_stream->base.server_data->on_request_done;
        if (on_request_done) {
            err = on_request_done(&incoming_stream->base, incoming_stream->base.user_data);
            if (err) {
                AWS_LOGF_TRACE(
                    AWS_LS_HTTP_STREAM,
                    "id=%p: Incoming request done callback raised error %d (%s).",
                    (void *)&incoming_stream->base,
                    aws_last_error(),
                    aws_error_name(aws_last_error()));
                return AWS_OP_ERR;
            }
        }
        if (incoming_stream->is_outgoing_message_done) {
            AWS_ASSERT(&incoming_stream->node == aws_linked_list_begin(&connection->thread_data.stream_list));
            s_stream_complete(incoming_stream, AWS_ERROR_SUCCESS);
        }
        s_set_incoming_stream_ptr(connection, NULL);

    } else if (incoming_stream->is_outgoing_message_done) {
        /* Client side */
        AWS_ASSERT(&incoming_stream->node == aws_linked_list_begin(&connection->thread_data.stream_list));

        s_stream_complete(incoming_stream, AWS_ERROR_SUCCESS);

        s_client_update_incoming_stream_ptr(connection);
    }

    /* Report success even if user's on_complete() callback shuts down on the connection.
     * We don't want it to look like something went wrong while decoding.
     * The decode() function returns after each message completes,
     * and we won't call decode() again if the connection has been shut down */
    return AWS_OP_SUCCESS;
}

/* Common new() logic for server & client */
static struct h1_connection *s_connection_new(
    struct aws_allocator *alloc,
    bool manual_window_management,
    size_t initial_window_size,
    bool server) {

    struct h1_connection *connection = aws_mem_calloc(alloc, 1, sizeof(struct h1_connection));
    if (!connection) {
        goto error_connection_alloc;
    }

    connection->base.vtable = &s_h1_connection_vtable;
    connection->base.alloc = alloc;
    connection->base.channel_handler.vtable = &s_h1_connection_vtable.channel_handler_vtable;
    connection->base.channel_handler.alloc = alloc;
    connection->base.channel_handler.impl = connection;
    connection->base.http_version = AWS_HTTP_VERSION_1_1;
    connection->base.manual_window_management = manual_window_management;

    /* Init the next stream id (server must use even ids, client odd [RFC 7540 5.1.1])*/
    connection->base.next_stream_id = server ? 2 : 1;

    /* 1 refcount for user */
    aws_atomic_init_int(&connection->base.refcount, 1);

    connection->initial_window_size = initial_window_size;

    aws_h1_encoder_init(&connection->thread_data.encoder, alloc);

    aws_channel_task_init(
        &connection->outgoing_stream_task, s_outgoing_stream_task, connection, "http1_outgoing_stream");
    aws_channel_task_init(&connection->window_update_task, s_update_window_task, connection, "http1_update_window");
    aws_linked_list_init(&connection->thread_data.stream_list);
    aws_linked_list_init(&connection->thread_data.midchannel_read_messages);
    aws_crt_statistics_http1_channel_init(&connection->thread_data.stats);

    int err = aws_mutex_init(&connection->synced_data.lock);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Failed to initialize mutex, error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error_mutex;
    }

    aws_linked_list_init(&connection->synced_data.new_client_stream_list);
    connection->synced_data.is_open = true;

    struct aws_h1_decoder_params options = {
        .alloc = alloc,
        .is_decoding_requests = server,
        .user_data = connection,
        .vtable = s_h1_decoder_vtable,
        .scratch_space_initial_size = DECODER_INITIAL_SCRATCH_SIZE,
    };
    connection->thread_data.incoming_stream_decoder = aws_h1_decoder_new(&options);
    if (!connection->thread_data.incoming_stream_decoder) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Failed to create decoder, error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error_decoder;
    }

    return connection;

error_decoder:
    aws_mutex_clean_up(&connection->synced_data.lock);
error_mutex:
    aws_mem_release(alloc, connection);
error_connection_alloc:
    return NULL;
}

struct aws_http_connection *aws_http_connection_new_http1_1_server(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size) {

    struct h1_connection *connection = s_connection_new(allocator, manual_window_management, initial_window_size, true);
    if (!connection) {
        return NULL;
    }

    connection->base.server_data = &connection->base.client_or_server_data.server;

    return &connection->base;
}

struct aws_http_connection *aws_http_connection_new_http1_1_client(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size) {

    struct h1_connection *connection =
        s_connection_new(allocator, manual_window_management, initial_window_size, false);
    if (!connection) {
        return NULL;
    }

    connection->base.client_data = &connection->base.client_or_server_data.client;

    return &connection->base;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct h1_connection *connection = handler->impl;

    AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Destroying connection.", (void *)&connection->base);

    AWS_ASSERT(aws_linked_list_empty(&connection->thread_data.midchannel_read_messages));
    AWS_ASSERT(aws_linked_list_empty(&connection->thread_data.stream_list));
    AWS_ASSERT(aws_linked_list_empty(&connection->synced_data.new_client_stream_list));

    aws_h1_decoder_destroy(connection->thread_data.incoming_stream_decoder);
    aws_h1_encoder_clean_up(&connection->thread_data.encoder);
    aws_mutex_clean_up(&connection->synced_data.lock);
    aws_mem_release(connection->base.alloc, connection);
}

static void s_handler_installed(struct aws_channel_handler *handler, struct aws_channel_slot *slot) {
    struct h1_connection *connection = handler->impl;
    connection->base.channel_slot = slot;

    /* Acquire a hold on the channel to prevent its destruction until the user has
     * given the go-ahead via aws_http_connection_release() */
    aws_channel_acquire_hold(slot->channel);
}

static void s_connection_try_send_read_messages(struct h1_connection *connection) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    AWS_ASSERT(connection->thread_data.has_switched_protocols);
    AWS_ASSERT(!connection->thread_data.is_reading_stopped);

    struct aws_io_message *sending_msg = NULL;

    if (!connection->base.channel_slot->adj_right) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Connection has switched protocols, but no handler is installed to deal with this data.",
            (void *)connection);

        aws_raise_error(AWS_ERROR_HTTP_SWITCHED_PROTOCOLS);
        goto error;
    }

    /* Send messages until none remain, or downstream window reaches zero */
    while (!aws_linked_list_empty(&connection->thread_data.midchannel_read_messages)) {
        sending_msg = NULL;

        size_t downstream_window = aws_channel_slot_downstream_read_window(connection->base.channel_slot);
        if (!downstream_window) {
            break;
        }

        struct aws_linked_list_node *queued_msg_node =
            aws_linked_list_front(&connection->thread_data.midchannel_read_messages);
        struct aws_io_message *queued_msg = AWS_CONTAINER_OF(queued_msg_node, struct aws_io_message, queueing_handle);

        /* If we can't send the whole entire queued_msg, copy its data into a new aws_io_message and send that.
         * Note that copy_mark is used to mark the progress of partially sent messages. */
        if (queued_msg->copy_mark || queued_msg->message_data.len > downstream_window) {
            sending_msg = aws_channel_acquire_message_from_pool(
                connection->base.channel_slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, downstream_window);
            if (!sending_msg) {
                goto error;
            }

            AWS_ASSERT(queued_msg->message_data.len > queued_msg->copy_mark);
            size_t sending_bytes = queued_msg->message_data.len - queued_msg->copy_mark;
            if (sending_msg->message_data.capacity < sending_bytes) {
                sending_bytes = sending_msg->message_data.capacity;
            }

            aws_byte_buf_write(
                &sending_msg->message_data, queued_msg->message_data.buffer + queued_msg->copy_mark, sending_bytes);

            queued_msg->copy_mark += sending_bytes;

            AWS_LOGF_TRACE(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Sending partial (%zu/%zu) switched-protocol message to next handler.",
                (void *)&connection->base,
                sending_bytes,
                queued_msg->message_data.len);

            /* If the last of queued_msg has been copied, it can be deleted now. */
            if (queued_msg->copy_mark == queued_msg->message_data.len) {
                aws_linked_list_remove(queued_msg_node);
                aws_mem_release(queued_msg->allocator, queued_msg);
            }

        } else {
            /* Sending all of queued_msg along. */
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Sending full switched-protocol message of size %zu to next handler.",
                (void *)&connection->base,
                queued_msg->message_data.len);

            aws_linked_list_remove(queued_msg_node);
            sending_msg = queued_msg;
        }

        int err = aws_channel_slot_send_message(connection->base.channel_slot, sending_msg, AWS_CHANNEL_DIR_READ);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Failed to send message, error %d (%s).",
                (void *)&connection->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));
            goto error;
        }
    }

    return;

error:
    if (sending_msg) {
        aws_mem_release(sending_msg->allocator, sending_msg);
    }
    s_shutdown_due_to_error(connection, aws_last_error());
}

static struct aws_http_stream *s_new_server_request_handler_stream(
    const struct aws_http_request_handler_options *options) {

    struct h1_connection *connection = AWS_CONTAINER_OF(options->server_connection, struct h1_connection, base);

    if (!aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel) ||
        !connection->thread_data.can_create_request_handler_stream) {

        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: aws_http_stream_new_server_request_handler() can only be called during incoming request callback.",
            (void *)&connection->base);

        aws_raise_error(AWS_ERROR_INVALID_STATE);
        return NULL;
    }

    struct aws_h1_stream *stream = aws_h1_stream_new_request_handler(options);
    if (!stream) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Failed to create request handler stream, error %d (%s).",
            (void *)&connection->base,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        return NULL;
    }

    /*
     * Success!
     * Everything beyond this point cannot fail
     */

    /* Prevent further streams from being created until it's ok to do so. */
    connection->thread_data.can_create_request_handler_stream = false;

    /* Stream is waiting for response. */
    aws_linked_list_push_back(&connection->thread_data.stream_list, &stream->node);

    /* Connection owns stream, and must outlive stream */
    aws_http_connection_acquire(&connection->base);

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM,
        "id=%p: Created request handler stream on server connection=%p",
        (void *)&stream->base,
        (void *)&connection->base);

    return &stream->base;
}

/* Invokes the on_incoming_request callback and returns new stream. */
static struct aws_h1_stream *s_server_invoke_on_incoming_request(struct h1_connection *connection) {
    AWS_PRECONDITION(connection->base.server_data);
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    AWS_PRECONDITION(!connection->thread_data.can_create_request_handler_stream);
    AWS_PRECONDITION(!connection->thread_data.incoming_stream);

    /**
     * The user MUST create the new request-handler stream during the on-incoming-request callback.
     */
    connection->thread_data.can_create_request_handler_stream = true;

    struct aws_http_stream *new_stream =
        connection->base.server_data->on_incoming_request(&connection->base, connection->base.user_data);

    connection->thread_data.can_create_request_handler_stream = false;

    return new_stream ? AWS_CONTAINER_OF(new_stream, struct aws_h1_stream, base) : NULL;
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct h1_connection *connection = handler->impl;
    int err;

    const size_t incoming_message_size = message->message_data.len;

    /* By default, after processing message, we will increment the read window by the same amount we just read in. */
    connection->thread_data.incoming_message_window_shrink_size = 0;

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Begin processing message of size %zu.",
        (void *)&connection->base,
        message->message_data.len);

    /* Run decoder until all message data is processed */
    struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);
    while (message_cursor.len > 0) {
        if (connection->thread_data.is_reading_stopped) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Cannot process message because connection is shutting down.",
                (void *)&connection->base);

            aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
            goto shutdown;
        }

        /* When connection has switched protocols, messages are processed very differently.
         * They're queued and sent along whenever the downstream read-window can accommodate them.
         *
         * We need to do this check in the middle of the normal processing loop,
         * in case the switch happens in the middle of processing a message. */
        if (connection->thread_data.has_switched_protocols) {
            size_t bytes_processed = message->message_data.len - message_cursor.len;
            size_t bytes_to_be_processed = message_cursor.len;

            /* Don't auto-increment read window for parts of message using the new protocol. */
            connection->thread_data.incoming_message_window_shrink_size += bytes_to_be_processed;

            /* Use the copy_mark to indicate how much of this message was already processed. */
            message->copy_mark = bytes_processed;

            /* Queue the message, then try to send it (and any others that might be queued) */
            aws_linked_list_push_back(&connection->thread_data.midchannel_read_messages, &message->queueing_handle);
            s_connection_try_send_read_messages(connection);

            /* Don't let the message be freed later in this function. It will be freed when it's finally sent. */
            message = NULL;

            /* Note that we break out of the loop. */
            break;

        } else {
            /* Else processing message as normal HTTP data. */
            if (!connection->thread_data.incoming_stream) {
                if (aws_http_connection_is_client(&connection->base)) {
                    /* Client side */
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_CONNECTION,
                        "id=%p: Cannot process message because no requests are currently awaiting response, closing "
                        "connection.",
                        (void *)&connection->base);

                    aws_raise_error(AWS_ERROR_INVALID_STATE);
                    goto shutdown;

                } else {
                    /* Server side.
                     * Invoke on-incoming-request callback. The user MUST create a new stream from this callback.
                     * The new stream becomes the current incoming stream */
                    s_set_incoming_stream_ptr(connection, s_server_invoke_on_incoming_request(connection));
                    if (!connection->thread_data.incoming_stream) {
                        AWS_LOGF_ERROR(
                            AWS_LS_HTTP_CONNECTION,
                            "id=%p: Incoming request callback failed to provide a new stream, last error %d (%s). "
                            "Closing connection.",
                            (void *)&connection->base,
                            aws_last_error(),
                            aws_error_name(aws_last_error()));

                        goto shutdown;
                    }
                }
            }

            /* Decoder will invoke the internal s_decoder_X callbacks, which in turn invoke user callbacks */
            aws_h1_decoder_set_logging_id(
                connection->thread_data.incoming_stream_decoder, connection->thread_data.incoming_stream);

            /* Tell the decoder about the request method, and let it know whether no body is needed or not */
            bool body_headers_ignored =
                connection->thread_data.incoming_stream->base.request_method == AWS_HTTP_METHOD_HEAD;
            aws_h1_decoder_set_body_headers_ignored(
                connection->thread_data.incoming_stream_decoder, body_headers_ignored);

            /* Decoder will stop once it hits the end of the request/response OR the end of the message data. */
            err = aws_h1_decode(connection->thread_data.incoming_stream_decoder, &message_cursor);
            if (err) {
                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_CONNECTION,
                    "id=%p: Message processing failed, error %d (%s). Closing connection.",
                    (void *)&connection->base,
                    aws_last_error(),
                    aws_error_name(aws_last_error()));

                goto shutdown;
            }
        }
    }

    AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Done processing message.", (void *)&connection->base);
    if (message) {
        /* release message back to pool before re-opening window */
        aws_mem_release(message->allocator, message);
        message = NULL;
    }

    /* Increment read window */
    if (incoming_message_size > connection->thread_data.incoming_message_window_shrink_size) {
        size_t increment = incoming_message_size - connection->thread_data.incoming_message_window_shrink_size;
        err = aws_channel_slot_increment_read_window(slot, increment);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Failed to increment read window, error %d (%s). Closing connection.",
                (void *)&connection->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            goto shutdown;
        }
    }

    return AWS_OP_SUCCESS;

shutdown:
    if (message) {
        aws_mem_release(message->allocator, message);
    }
    s_shutdown_due_to_error(connection, aws_last_error());
    return AWS_OP_SUCCESS;
}

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct h1_connection *connection = handler->impl;

    if (connection->thread_data.is_writing_stopped) {
        aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
        goto error;
    }

    if (!connection->thread_data.has_switched_protocols) {
        aws_raise_error(AWS_ERROR_INVALID_STATE);
        goto error;
    }

    /* Pass the message right along. */
    int err = aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_WRITE);
    if (err) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    AWS_LOGF_ERROR(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Destroying write message without passing it along, error %d (%s)",
        (void *)&connection->base,
        aws_last_error(),
        aws_error_name(aws_last_error()));

    if (message->on_completion) {
        message->on_completion(connection->base.channel_slot->channel, message, aws_last_error(), message->user_data);
    }
    aws_mem_release(message->allocator, message);
    s_shutdown_due_to_error(connection, aws_last_error());
    return AWS_OP_SUCCESS;
}

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    struct h1_connection *connection = handler->impl;

    if (connection->thread_data.is_reading_stopped) {
        aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
        goto error;
    }

    if (!connection->thread_data.has_switched_protocols) {
        aws_raise_error(AWS_ERROR_INVALID_STATE);
        goto error;
    }

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Read window incremented by %zu. Sending queued messages, if any.",
        (void *)&connection->base,
        size);

    /* If there are any queued messages, send them along. */
    s_connection_try_send_read_messages(connection);

    aws_channel_slot_increment_read_window(slot, size);
    return AWS_OP_SUCCESS;

error:
    AWS_LOGF_ERROR(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Failed to increment read window, error %d (%s)",
        (void *)&connection->base,
        aws_last_error(),
        aws_error_name(aws_last_error()));

    s_shutdown_due_to_error(connection, aws_last_error());
    return AWS_OP_SUCCESS;
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)free_scarce_resources_immediately;
    struct h1_connection *connection = handler->impl;

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Channel shutting down in %s direction with error code %d (%s).",
        (void *)&connection->base,
        (dir == AWS_CHANNEL_DIR_READ) ? "read" : "write",
        error_code,
        aws_error_name(error_code));

    if (dir == AWS_CHANNEL_DIR_READ) {
        /* This call ensures that no further streams will be created or worked on. */
        s_stop(connection, true /*stop_reading*/, false /*stop_writing*/, false /*schedule_shutdown*/, error_code);

        /* Clean up any queued midchannel read messages. */
        while (!aws_linked_list_empty(&connection->thread_data.midchannel_read_messages)) {
            struct aws_linked_list_node *node =
                aws_linked_list_pop_front(&connection->thread_data.midchannel_read_messages);
            struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
            aws_mem_release(msg->allocator, msg);
        }
    } else /* dir == AWS_CHANNEL_DIR_WRITE */ {

        s_stop(connection, false /*stop_reading*/, true /*stop_writing*/, false /*schedule_shutdown*/, error_code);

        /* Mark all pending streams as complete. */
        int stream_error_code = error_code == AWS_ERROR_SUCCESS ? AWS_ERROR_HTTP_CONNECTION_CLOSED : error_code;

        while (!aws_linked_list_empty(&connection->thread_data.stream_list)) {
            struct aws_linked_list_node *node = aws_linked_list_front(&connection->thread_data.stream_list);
            s_stream_complete(AWS_CONTAINER_OF(node, struct aws_h1_stream, node), stream_error_code);
        }

        /* It's OK to access synced_data.new_client_stream_list without holding the lock because
         * no more streams can be added after s_stop() has been invoked. */
        while (!aws_linked_list_empty(&connection->synced_data.new_client_stream_list)) {
            struct aws_linked_list_node *node = aws_linked_list_front(&connection->synced_data.new_client_stream_list);
            s_stream_complete(AWS_CONTAINER_OF(node, struct aws_h1_stream, node), stream_error_code);
        }
    }

    aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
    return AWS_OP_SUCCESS;
}

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    struct h1_connection *connection = handler->impl;
    return connection->initial_window_size;
}

static size_t s_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}

static void s_reset_statistics(struct aws_channel_handler *handler) {
    struct h1_connection *connection = handler->impl;

    aws_crt_statistics_http1_channel_reset(&connection->thread_data.stats);
}

static void s_pull_up_stats_timestamps(struct h1_connection *connection) {
    uint64_t now_ns = 0;
    if (aws_channel_current_clock_time(connection->base.channel_slot->channel, &now_ns)) {
        return;
    }

    if (connection->thread_data.outgoing_stream) {
        s_add_time_measurement_to_stats(
            connection->thread_data.outgoing_stream_timestamp_ns,
            now_ns,
            &connection->thread_data.stats.pending_outgoing_stream_ms);

        connection->thread_data.outgoing_stream_timestamp_ns = now_ns;

        connection->thread_data.stats.current_outgoing_stream_id =
            aws_http_stream_get_id(&connection->thread_data.outgoing_stream->base);
    }

    if (connection->thread_data.incoming_stream) {
        s_add_time_measurement_to_stats(
            connection->thread_data.incoming_stream_timestamp_ns,
            now_ns,
            &connection->thread_data.stats.pending_incoming_stream_ms);

        connection->thread_data.incoming_stream_timestamp_ns = now_ns;

        connection->thread_data.stats.current_incoming_stream_id =
            aws_http_stream_get_id(&connection->thread_data.incoming_stream->base);
    }
}

static void s_gather_statistics(struct aws_channel_handler *handler, struct aws_array_list *stats) {
    struct h1_connection *connection = handler->impl;

    s_pull_up_stats_timestamps(connection);

    void *stats_base = &connection->thread_data.stats;
    aws_array_list_push_back(stats, &stats_base);
}

struct aws_crt_statistics_http1_channel *aws_h1_connection_get_statistics(struct aws_http_connection *connection) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(connection->channel_slot->channel));

    struct h1_connection *h1_conn = (void *)connection;

    return &h1_conn->thread_data.stats;
}
