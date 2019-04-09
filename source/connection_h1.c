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

#include <aws/http/private/connection_impl.h>

#include <aws/common/math.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/private/decode.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/io/logging.h>

#include <stdio.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

enum {
    MESSAGE_SIZE_HINT = 16 * 1024,
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
static struct aws_http_stream *s_new_client_request_stream(const struct aws_http_request_options *options);
static void s_connection_close(struct aws_http_connection *connection_base);
static bool s_connection_is_open(const struct aws_http_connection *connection_base);
static void s_stream_destroy(struct aws_http_stream *stream_base);
static void s_stream_update_window(struct aws_http_stream *stream, size_t increment_size);
static int s_decoder_on_request(
    enum aws_http_method method_enum,
    const struct aws_byte_cursor *method_str,
    const struct aws_byte_cursor *uri,
    void *user_data);
static int s_decoder_on_response(int status_code, void *user_data);
static int s_decoder_on_header(const struct aws_http_decoded_header *header, void *user_data);
static int s_decoder_on_body(const struct aws_byte_cursor *data, bool finished, void *user_data);
static int s_decoder_on_done(void *user_data);

static struct aws_http_connection_vtable s_connection_vtable = {
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

    .new_client_request_stream = s_new_client_request_stream,
    .close = s_connection_close,
    .is_open = s_connection_is_open,
};

static const struct aws_http_stream_vtable s_stream_vtable = {
    .destroy = s_stream_destroy,
    .update_window = s_stream_update_window,
};

static const struct aws_http_decoder_vtable s_decoder_vtable = {
    .on_request = s_decoder_on_request,
    .on_response = s_decoder_on_response,
    .on_header = s_decoder_on_header,
    .on_body = s_decoder_on_body,
    .on_done = s_decoder_on_done,
};

struct h1_connection {
    struct aws_http_connection base;

    /* Single task used repeatedly for sending data from streams. */
    struct aws_channel_task outgoing_stream_task;

    /* Single task used for issuing window updates from off-thread */
    struct aws_channel_task window_update_task;

    /* Task used once during shutdown. */
    struct aws_channel_task shutdown_delay_task;

    /* Only the event-loop thread may touch this data */
    struct {
        /* List of streams being worked on. */
        struct aws_linked_list stream_list;

        /* Points to the stream whose data is currently being sent.
         * This stream is ALWAYS in the `stream_list`.
         * HTTP pipelining is supported, so once the stream is completely written
         * we'll start working on the next stream in the list */
        struct h1_stream *outgoing_stream;

        /* Points to the stream being decoded, which is always the first entry in `stream_list` */
        struct h1_stream *incoming_stream;
        struct aws_http_decoder *incoming_stream_decoder;

        /* Amount to increment window after a channel message has been processed. */
        size_t incoming_message_window_update;

        /* For checking status from the event-loop thread. Duplicates synced_data.is_shutting_down */
        bool is_shutting_down;

        int shutdown_error_code;

        /* Ideal size for outgoing messages. Cannot be calculated until channel is fully set up */
        size_t outgoing_message_size_hint;
    } thread_data;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

        /* New streams that have not been moved to `stream_list` yet. */
        struct aws_linked_list pending_stream_list;

        bool is_outgoing_stream_task_active;

        /* For checking status from outside the event-loop thread. Duplicates thread_data.is_shutting_down */
        bool is_shutting_down;

        /* If non-zero, then window_update_task is scheduled */
        size_t window_update_size;
    } synced_data;
};

enum stream_type {
    STREAM_TYPE_OUTGOING_REQUEST,
    STREAM_TYPE_INCOMING_REQUEST,
};

enum stream_outgoing_state {
    STREAM_OUTGOING_STATE_HEAD,
    STREAM_OUTGOING_STATE_BODY,
    STREAM_OUTGOING_STATE_DONE,
};

struct h1_stream {
    struct aws_http_stream base;

    enum stream_type type;
    struct aws_linked_list_node node;
    enum stream_outgoing_state outgoing_state;

    /* Upon creation, the "head" (everything preceding body) is buffered here. */
    struct aws_byte_buf outgoing_head_buf;
    size_t outgoing_head_progress;
    bool has_outgoing_body;

    bool is_incoming_message_done;
    bool is_incoming_head_done;

    /* Buffer for incoming data that needs to stick around. */
    struct aws_byte_buf incoming_storage_buf;
};

/**
 * Internal function for shutting down the connection.
 * This function can be called multiple times, from on-thread or off.
 * This function is always run once on-thread during channel shutdown.
 */
static void s_shutdown_connection(struct h1_connection *connection, int error_code) {
    bool on_thread = aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel);
    if (on_thread) {
        /* If thread_data already knew about shutdown, then no more work to do here. */
        if (connection->thread_data.is_shutting_down) {
            return;
        }

        connection->thread_data.is_shutting_down = true;
        connection->thread_data.shutdown_error_code = error_code;
    }

    bool was_shutdown_known;
    { /* BEGIN CRITICAL SECTION */
        int err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);

        was_shutdown_known = connection->synced_data.is_shutting_down;
        connection->synced_data.is_shutting_down = true;

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);
    } /* END CRITICAL SECTION */

    if (!was_shutdown_known) {
        AWS_LOGF_INFO(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Connection shutting down with error code %d (%s).",
            (void *)&connection->base,
            error_code,
            aws_error_name(error_code));

        /* Delay the call to aws_channel_shutdown().
         * This ensures that a user calling aws_http_connection_close() won't have completion callbacks
         * firing before aws_http_connection_close() has even returned. */
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->shutdown_delay_task);
    }
}

static void s_shutdown_delay_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct h1_connection *connection = arg;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        /* If channel is already shutting down, this call has no effect */
        aws_channel_shutdown(connection->base.channel_slot->channel, connection->thread_data.shutdown_error_code);
    }
}

/**
 * Public function for closing connection.
 */
static void s_connection_close(struct aws_http_connection *connection_base) {
    struct h1_connection *connection = AWS_CONTAINER_OF(connection_base, struct h1_connection, base);
    s_shutdown_connection(connection, AWS_ERROR_SUCCESS);
}

static bool s_connection_is_open(const struct aws_http_connection *connection_base) {
    struct h1_connection *connection = AWS_CONTAINER_OF(connection_base, struct h1_connection, base);
    bool is_shutting_down;

    { /* BEGIN CRITICAL SECTION */
        int err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);

        is_shutting_down = connection->synced_data.is_shutting_down;

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);
    } /* END CRITICAL SECTION */

    return !is_shutting_down;
}

/**
 * Scan headers and determine the length necessary to write them all.
 * Also update the stream with any special data it needs to know from these headers.
 */
static int s_stream_scan_outgoing_headers(
    struct h1_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    size_t *out_header_lines_len) {

    size_t total = 0;

    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header = header_array[i];

        enum aws_http_header_name name_enum;

        if (header.name.len > 0) {
            name_enum = aws_http_str_to_header_name(header.name);
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Failed to create stream, no name set for header[%zu].",
                (void *)stream->base.owning_connection,
                i);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }

        switch (name_enum) {
            case AWS_HTTP_HEADER_CONTENT_LENGTH:
            case AWS_HTTP_HEADER_TRANSFER_ENCODING:
                stream->has_outgoing_body = true;

                if (!stream->base.stream_outgoing_body) {
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_CONNECTION,
                        "id=%p: Failed to create stream, '" PRInSTR
                        "' header specified but body-streaming callback is not set.",
                        (void *)stream->base.owning_connection,
                        AWS_BYTE_CURSOR_PRI(header.name));

                    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
                }
                break;
            default:
                break;
        }

        /* header-line: "{name}: {value}\r\n" */
        int err = 0;
        err |= aws_add_size_checked(header.name.len, total, &total);
        err |= aws_add_size_checked(header.value.len, total, &total);
        err |= aws_add_size_checked(4, total, &total); /* ": " + "\r\n" */
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Failed to create stream, header size calculation produced error %d (%s)'",
                (void *)stream->base.owning_connection,
                aws_last_error(),
                aws_error_name(aws_last_error()));
            return AWS_OP_ERR;
        }
    }

    *out_header_lines_len = total;
    return AWS_OP_SUCCESS;
}

static void s_write_headers(struct aws_byte_buf *dst, const struct aws_http_header *header_array, size_t num_headers) {

    bool wrote_all = true;
    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header = header_array[i];

        /* header-line: "{name}: {value}\r\n" */
        wrote_all &= aws_byte_buf_write_from_whole_cursor(dst, header.name);
        wrote_all &= aws_byte_buf_write_u8(dst, ':');
        wrote_all &= aws_byte_buf_write_u8(dst, ' ');
        wrote_all &= aws_byte_buf_write_from_whole_cursor(dst, header.value);
        wrote_all &= aws_byte_buf_write_u8(dst, '\r');
        wrote_all &= aws_byte_buf_write_u8(dst, '\n');
    }
    assert(wrote_all);
}

struct aws_http_stream *s_new_client_request_stream(const struct aws_http_request_options *options) {
    if (options->uri.len == 0 || options->method.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create client request, options are invalid.",
            (void *)options->client_connection);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct h1_stream *stream = aws_mem_acquire(options->client_connection->alloc, sizeof(struct h1_stream));
    if (!stream) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*stream);

    stream->base.vtable = &s_stream_vtable;
    stream->base.alloc = options->client_connection->alloc;
    stream->base.owning_connection = options->client_connection;
    stream->base.user_data = options->user_data;
    stream->base.stream_outgoing_body = options->stream_outgoing_body;
    stream->base.on_incoming_headers = options->on_response_headers;
    stream->base.on_incoming_header_block_done = options->on_response_header_block_done;
    stream->base.on_incoming_body = options->on_response_body;
    stream->base.on_complete = options->on_complete;
    stream->base.incoming_response_status = AWS_HTTP_STATUS_UNKNOWN;

    /* Stream refcount starts at 2. 1 for user and 1 for connection to release it's done with the stream */
    aws_atomic_init_int(&stream->base.refcount, 2);

    struct aws_byte_cursor version = aws_http_version_to_str(AWS_HTTP_VERSION_1_1);

    /**
     * Calculate total size needed for outgoing_head_buffer, then write to buffer.
     */

    size_t header_lines_len;
    int err = s_stream_scan_outgoing_headers(stream, options->header_array, options->num_headers, &header_lines_len);
    if (err) {
        /* errors already logged by scan_outgoing_headers() function */
        goto error_scanning_headers;
    }

    /* request-line: "{method} {uri} {version}\r\n" */
    size_t request_line_len = 4; /* 2 spaces + "\r\n" */
    err |= aws_add_size_checked(options->method.len, request_line_len, &request_line_len);
    err |= aws_add_size_checked(options->uri.len, request_line_len, &request_line_len);
    err |= aws_add_size_checked(version.len, request_line_len, &request_line_len);

    /* head-end: "\r\n" */
    size_t head_end_len = 2;

    size_t head_total_len = request_line_len;
    err |= aws_add_size_checked(header_lines_len, head_total_len, &head_total_len);
    err |= aws_add_size_checked(head_end_len, head_total_len, &head_total_len);

    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Failed to create request, size calculation had error %d (%s).",
            (void *)options->client_connection,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error_calculating_size;
    }

    err = aws_byte_buf_init(&stream->outgoing_head_buf, stream->base.alloc, head_total_len);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Failed to create request, buffer initialization had error %d (%s).",
            (void *)options->client_connection,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error_initializing_buf;
    }

    bool wrote_all = true;

    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, options->method);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, options->uri);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, version);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\n');

    s_write_headers(&stream->outgoing_head_buf, options->header_array, options->num_headers);

    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\n');

    assert(wrote_all);

    /* Insert new stream into pending list, and schedule outgoing_stream_task if it's not already running. */
    bool is_shutting_down = false;
    bool should_schedule_task = false;

    struct h1_connection *connection = AWS_CONTAINER_OF(options->client_connection, struct h1_connection, base);
    { /* BEGIN CRITICAL SECTION */
        err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);

        if (connection->synced_data.is_shutting_down) {
            is_shutting_down = true;
        } else {
            aws_linked_list_push_back(&connection->synced_data.pending_stream_list, &stream->node);
            if (!connection->synced_data.is_outgoing_stream_task_active) {
                connection->synced_data.is_outgoing_stream_task_active = true;
                should_schedule_task = true;
            }
        }

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);
    } /* END CRITICAL SECTION */

    if (is_shutting_down) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Connection is closed, cannot create request.",
            (void *)options->client_connection);

        aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
        goto error_connection_closed;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_HTTP_STREAM,
        "id=%p: Created client request on connection=%p: " PRInSTR " " PRInSTR " " PRInSTR,
        (void *)&stream->base,
        (void *)options->client_connection,
        AWS_BYTE_CURSOR_PRI(options->method),
        AWS_BYTE_CURSOR_PRI(options->uri),
        AWS_BYTE_CURSOR_PRI(aws_http_version_to_str(connection->base.http_version)));

    if (should_schedule_task) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Scheduling outgoing stream task.", (void *)&connection->base);
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->outgoing_stream_task);
    }

    return &stream->base;

error_connection_closed:
    aws_byte_buf_clean_up(&stream->outgoing_head_buf);
error_initializing_buf:
error_calculating_size:
error_scanning_headers:
    aws_mem_release(stream->base.alloc, stream);
    return NULL;
}

static void s_stream_destroy(struct aws_http_stream *stream_base) {
    AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Stream destroyed.", (void *)stream_base);

    struct h1_stream *stream = AWS_CONTAINER_OF(stream_base, struct h1_stream, base);

    aws_byte_buf_clean_up(&stream->incoming_storage_buf);
    aws_byte_buf_clean_up(&stream->outgoing_head_buf);
    aws_mem_release(stream->base.alloc, stream);
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

        s_shutdown_connection(connection, aws_last_error());
    }
}

static void s_update_window_task(struct aws_channel_task *channel_task, void *arg, enum aws_task_status status) {
    (void)channel_task;
    struct h1_connection *connection = arg;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    /* BEGIN CRITICAL SECTION */
    int err = aws_mutex_lock(&connection->synced_data.lock);
    AWS_FATAL_ASSERT(!err);

    size_t window_update_size = connection->synced_data.window_update_size;
    connection->synced_data.window_update_size = 0;

    err = aws_mutex_unlock(&connection->synced_data.lock);
    AWS_FATAL_ASSERT(!err);
    /* END CRITICAL SECTION */

    s_update_window_action(connection, window_update_size);
}

static void s_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    struct h1_connection *connection = AWS_CONTAINER_OF(stream->owning_connection, struct h1_connection, base);

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
    int err = aws_mutex_lock(&connection->synced_data.lock);
    AWS_FATAL_ASSERT(!err);

    bool should_schedule_task = connection->synced_data.window_update_size == 0;

    connection->synced_data.window_update_size =
        aws_add_size_saturating(connection->synced_data.window_update_size, increment_size);

    err = aws_mutex_unlock(&connection->synced_data.lock);
    AWS_FATAL_ASSERT(!err);
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

/**
 * Write as much data to msg as possible.
 * The stream's state is updated as necessary to track progress.
 */
static void s_stream_write_outgoing_data(struct h1_stream *stream, struct aws_io_message *msg) {
    struct aws_byte_buf *dst = &msg->message_data;

    if (stream->outgoing_state == STREAM_OUTGOING_STATE_HEAD) {
        size_t dst_available = dst->capacity - dst->len;
        if (dst_available == 0) {
            /* Can't write anymore */
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_STREAM, "id=%p: Cannot fit any more head data in this message.", (void *)&stream->base);
            return;
        }

        /* Copy data from stream->outgoing_head_buf */
        struct aws_byte_buf *src = &stream->outgoing_head_buf;
        size_t src_progress = stream->outgoing_head_progress;
        size_t src_remaining = src->len - src_progress;
        size_t transferring = src_remaining < dst_available ? src_remaining : dst_available;

        bool success = aws_byte_buf_write(dst, src->buffer + src_progress, transferring);
        (void)success;
        assert(success);

        stream->outgoing_head_progress += transferring;

        AWS_LOGF_TRACE(
            AWS_LS_HTTP_STREAM,
            "id=%p: Writing to message, outgoing head progress %zu/%zu.",
            (void *)&stream->base,
            stream->outgoing_head_progress,
            stream->outgoing_head_buf.len);

        if (stream->outgoing_head_progress == src->len) {
            /* Don't NEED to free this buffer now, but we don't need it anymore, so why not */
            aws_byte_buf_clean_up(&stream->outgoing_head_buf);

            stream->outgoing_state++;
        }
    }

    if (stream->outgoing_state == STREAM_OUTGOING_STATE_BODY) {
        if (!stream->has_outgoing_body) {
            AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: No body to send.", (void *)&stream->base);
            stream->outgoing_state++;
        } else {
            while (true) {
                if (dst->capacity == dst->len) {
                    /* Can't write anymore */
                    AWS_LOGF_TRACE(
                        AWS_LS_HTTP_STREAM,
                        "id=%p: Cannot fit any more body data in this message.",
                        (void *)&stream->base);
                    return;
                }

                size_t prev_len = dst->len;

                enum aws_http_outgoing_body_state state =
                    stream->base.stream_outgoing_body(&stream->base, dst, stream->base.user_data);

                AWS_FATAL_ASSERT(prev_len <= dst->len);

                AWS_LOGF_TRACE(
                    AWS_LS_HTTP_STREAM,
                    "id=%p: Writing %zu body bytes to message.",
                    (void *)&stream->base,
                    dst->len - prev_len);

                if (state == AWS_HTTP_OUTGOING_BODY_DONE) {
                    AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Done sending body.", (void *)&stream->base);
                    stream->outgoing_state++;
                    break;
                }

                /* Return if user failed to write anything. Maybe their data isn't ready yet. */
                if (prev_len == dst->len) {
                    AWS_LOGF_TRACE(
                        AWS_LS_HTTP_STREAM,
                        "id=%p: No body data written, concluding this message."
                        " Will try to write body data again in the next message.",
                        (void *)&stream->base);
                    return;
                }
            }
        }
    }

    if (stream->outgoing_state == STREAM_OUTGOING_STATE_DONE) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Stream is done sending data.", (void *)&stream->base);
        return;
    }
}

static void s_stream_complete(struct h1_stream *stream, int error_code) {
    /* Nice logging */
    if (error_code) {
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Stream completed with error code %d (%s).",
            (void *)&stream->base,
            error_code,
            aws_error_name(error_code));

    } else if (stream->type == STREAM_TYPE_OUTGOING_REQUEST) {
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Client request complete, response status: %d (%s).",
            (void *)&stream->base,
            stream->base.incoming_response_status,
            aws_http_status_text(stream->base.incoming_response_status));
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_STREAM,
            "id=%p: Server response to " PRInSTR " request complete.",
            (void *)&stream->base,
            AWS_BYTE_CURSOR_PRI(stream->base.incoming_request_method_str));
    }

    /* Do actual work*/
    aws_linked_list_remove(&stream->node);

    if (stream->base.on_complete) {
        stream->base.on_complete(&stream->base, error_code, stream->base.user_data);
    }

    aws_http_stream_release(&stream->base);
}

/**
 * Ensure `incoming_stream` is pointing at the correct stream, and update state if it changes.
 */
static void s_update_incoming_stream_ptr(struct h1_connection *connection) {
    struct aws_linked_list *list = &connection->thread_data.stream_list;
    struct h1_stream *desired;
    if (aws_linked_list_empty(list)) {
        desired = NULL;
    } else {
        desired = AWS_CONTAINER_OF(aws_linked_list_begin(list), struct h1_stream, node);
    }

    if (connection->thread_data.incoming_stream == desired) {
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Current incoming stream is now %p.",
        (void *)&connection->base,
        desired ? (void *)&desired->base : NULL);

    connection->thread_data.incoming_stream = desired;
}

/**
 * If necessary, update `outgoing_stream` so it is pointing at a stream
 * with data to send, or NULL if all streams are done sending data.
 *
 * Called from event-loop thread.
 * This function has lots of side effects.
 */
static struct h1_stream *s_update_outgoing_stream_ptr(struct h1_connection *connection) {
    struct h1_stream *current = connection->thread_data.outgoing_stream;
    struct h1_stream *prev = current;
    int err;

    /* If current stream is done sending data... */
    if (current && (current->outgoing_state == STREAM_OUTGOING_STATE_DONE)) {
        struct aws_linked_list_node *next_node = aws_linked_list_next(&current->node);

        /* If it's also done receiving data, then it's complete! */
        if (current->is_incoming_message_done) {
            /* Only 1st stream in list could finish receiving before it finished sending */
            assert(&current->node == aws_linked_list_begin(&connection->thread_data.stream_list));

            /* This removes stream from list */
            s_stream_complete(current, AWS_ERROR_SUCCESS);
        }

        /* Iterate current stream to the next item in stream_list. */
        if (next_node == aws_linked_list_end(&connection->thread_data.stream_list)) {
            current = NULL;
        } else {
            current = AWS_CONTAINER_OF(next_node, struct h1_stream, node);
        }
    }

    /* If current stream is NULL, look in synced_data.pending_stream_list for more work */
    if (!current) {

        /* BEGIN CRITICAL SECTION */
        err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);

        if (aws_linked_list_empty(&connection->synced_data.pending_stream_list)) {
            /* No more work to do. Set this false while we're holding the lock. */
            connection->synced_data.is_outgoing_stream_task_active = false;

        } else {
            /* Front of pending_stream_list becomes new current_stream */
            current = AWS_CONTAINER_OF(
                aws_linked_list_front(&connection->synced_data.pending_stream_list), struct h1_stream, node);

            /* Move contents from pending_stream_list to stream_list. */
            do {
                aws_linked_list_push_back(
                    &connection->thread_data.stream_list,
                    aws_linked_list_pop_front(&connection->synced_data.pending_stream_list));

            } while (!aws_linked_list_empty(&connection->synced_data.pending_stream_list));
        }

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);
        /* END CRITICAL SECTION */
    }

    /* Update current incoming and outgoing streams. */
    if (prev != current) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Current outgoing stream is now %p.",
            (void *)&connection->base,
            current ? (void *)&current->base : NULL);

        connection->thread_data.outgoing_stream = current;

        s_update_incoming_stream_ptr(connection);
    }

    return current;
}

static void s_outgoing_stream_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct h1_connection *connection = arg;
    struct aws_channel *channel = connection->base.channel_slot->channel;
    struct aws_io_message *msg = NULL;
    int err;

    /* If connection is shutting down, stop sending data */
    if (connection->thread_data.is_shutting_down) {
        return;
    }

    AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Outgoing stream task is running.", (void *)&connection->base);

    /* If outgoing_message_size_hint isn't set yet, calculate it */
    if (!connection->thread_data.outgoing_message_size_hint) {
        size_t overhead = aws_channel_slot_upstream_message_overhead(connection->base.channel_slot);
        if (overhead >= MESSAGE_SIZE_HINT) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Unexpected error while calculating message size, closing connection.",
                (void *)&connection->base);

            aws_raise_error(AWS_ERROR_INVALID_STATE);
            goto error;
        }

        connection->thread_data.outgoing_message_size_hint = MESSAGE_SIZE_HINT - overhead;
    }

    msg = aws_channel_acquire_message_from_pool(
        channel, AWS_IO_MESSAGE_APPLICATION_DATA, connection->thread_data.outgoing_message_size_hint);
    if (!msg) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Failed to acquire message from pool, error %d (%s). Closing connection.",
            (void *)&connection->base,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    /**
     * Fill message with as much data as possible before sending.
     * At first, we might be resuming work on a stream from a previous run of this task.
     * Loop until no more streams have data to send,
     * OR a stream still is unable to continue writing to the msg (probably because msg is full).
     */
    struct h1_stream *outgoing_stream;
    do {
        outgoing_stream = s_update_outgoing_stream_ptr(connection);
        if (!outgoing_stream) {
            break;
        }

        s_stream_write_outgoing_data(outgoing_stream, msg);

        /* If stream is done sending data, loop and start sending the next stream's data */
    } while (outgoing_stream->outgoing_state == STREAM_OUTGOING_STATE_DONE);

    if (msg->message_data.len > 0) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Outgoing stream task is sending message of size %zu.",
            (void *)&connection->base,
            msg->message_data.len);

        err = aws_channel_slot_send_message(connection->base.channel_slot, msg, AWS_CHANNEL_DIR_WRITE);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Failed to send message up channel, error %d (%s). Closing connection.",
                (void *)&connection->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            goto error;
        }
    } else {
        /* If message is empty, warn that no work is being done.
         * It's likely that body isn't ready, so body streaming function has no data to write yet.
         * If this scenario turns out to be common we should implement a "pause" feature. */
        AWS_LOGF_WARN(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Current outgoing stream %p sent no data, will try again next tick.",
            (void *)&connection->base,
            outgoing_stream ? (void *)&outgoing_stream->base : NULL);

        aws_mem_release(msg->allocator, msg);
    }

    /* Reschedule task if there's still more work to do. */
    if (outgoing_stream) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Outgoing stream task has written all it can, but there's still more work to do, rescheduling task.",
            (void *)&connection->base);

        aws_channel_schedule_task_now(channel, task);
    } else {
        AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Outgoing stream task complete.", (void *)&connection->base);
    }

    return;
error:
    if (msg) {
        aws_mem_release(msg->allocator, msg);
    }

    s_shutdown_connection(connection, aws_last_error());
}

static int s_decoder_on_request(
    enum aws_http_method method_enum,
    const struct aws_byte_cursor *method_str,
    const struct aws_byte_cursor *uri,
    void *user_data) {

    struct h1_connection *connection = user_data;
    struct h1_stream *incoming_stream = connection->thread_data.incoming_stream;

    assert(incoming_stream->base.incoming_request_method_str.len == 0);
    assert(incoming_stream->base.incoming_request_uri.len == 0);

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM,
        "id=%p: Incoming request: method=" PRInSTR " uri=" PRInSTR,
        (void *)&incoming_stream->base,
        AWS_BYTE_CURSOR_PRI(*method_str),
        AWS_BYTE_CURSOR_PRI(*uri));

    /* Copy strings to internal buffer */
    struct aws_byte_buf *storage_buf = &incoming_stream->incoming_storage_buf;
    assert(storage_buf->capacity == 0);

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
    incoming_stream->base.incoming_request_method_str = aws_byte_cursor_from_buf(storage_buf);

    aws_byte_buf_write_from_whole_cursor(storage_buf, *uri);
    incoming_stream->base.incoming_request_uri = aws_byte_cursor_from_buf(storage_buf);
    aws_byte_cursor_advance(&incoming_stream->base.incoming_request_method_str, storage_buf->len - uri->len);

    incoming_stream->base.incoming_request_method = method_enum;

    /* No user callbacks, so we're not checking for shutdown */
    return AWS_OP_SUCCESS;

error:
    err = aws_last_error();
    s_shutdown_connection(connection, err);
    return aws_raise_error(err);
}

static int s_decoder_on_response(int status_code, void *user_data) {
    struct h1_connection *connection = user_data;

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM,
        "id=%p: Incoming response status: %d (%s).",
        (void *)&connection->thread_data.incoming_stream->base,
        status_code,
        aws_http_status_text(status_code));

    connection->thread_data.incoming_stream->base.incoming_response_status = status_code;

    /* No user callbacks, so we're not checking for shutdown */
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_header(const struct aws_http_decoded_header *header, void *user_data) {
    struct h1_connection *connection = user_data;
    struct h1_stream *incoming_stream = connection->thread_data.incoming_stream;

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM,
        "id=%p: Incoming header: " PRInSTR ": " PRInSTR,
        (void *)&incoming_stream->base,
        AWS_BYTE_CURSOR_PRI(header->name_data),
        AWS_BYTE_CURSOR_PRI(header->value_data));

    if (incoming_stream->base.on_incoming_headers) {
        struct aws_http_header deliver = {
            .name = header->name_data,
            .value = header->value_data,
        };

        incoming_stream->base.on_incoming_headers(&incoming_stream->base, &deliver, 1, incoming_stream->base.user_data);
    }

    /* Stop decoding if user callback shut down the connection. */
    if (connection->thread_data.is_shutting_down) {
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    return AWS_OP_SUCCESS;
}

static int s_mark_head_done(struct h1_stream *incoming_stream) {
    /* Bail out if we've already done this */
    if (incoming_stream->is_incoming_head_done) {
        return AWS_OP_SUCCESS;
    }

    incoming_stream->is_incoming_head_done = true;

    /* Determine if message will have a body */
    struct h1_connection *connection =
        AWS_CONTAINER_OF(incoming_stream->base.owning_connection, struct h1_connection, base);

    bool has_incoming_body = false;
    int transfer_encoding = aws_http_decoder_get_encoding_flags(connection->thread_data.incoming_stream_decoder);
    has_incoming_body |= (transfer_encoding & AWS_HTTP_TRANSFER_ENCODING_CHUNKED);
    has_incoming_body |= aws_http_decoder_get_content_length(connection->thread_data.incoming_stream_decoder);

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM,
        "id=%p: Incoming head is done, %s.",
        (void *)&incoming_stream->base,
        has_incoming_body ? "body is next" : "there will be no body");

    /* Invoke user cb */
    if (incoming_stream->base.on_incoming_header_block_done) {
        incoming_stream->base.on_incoming_header_block_done(
            &incoming_stream->base, has_incoming_body, incoming_stream->base.user_data);
    }

    /* Stop decoding if user callback shut down the connection. */
    if (connection->thread_data.is_shutting_down) {
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_body(const struct aws_byte_cursor *data, bool finished, void *user_data) {
    (void)finished;

    struct h1_connection *connection = user_data;
    struct h1_stream *incoming_stream = connection->thread_data.incoming_stream;
    assert(incoming_stream);

    int err = s_mark_head_done(incoming_stream);
    if (err) {
        return AWS_OP_ERR;
    }

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_STREAM, "id=%p: Incoming body: %zu bytes received.", (void *)&incoming_stream->base, data->len);

    if (incoming_stream->base.on_incoming_body) {
        size_t window_update_size = data->len;

        incoming_stream->base.on_incoming_body(
            &incoming_stream->base, data, &window_update_size, incoming_stream->base.user_data);

        /* If user reduced window_update_size, reduce how much the connection will update its window. */
        if (window_update_size < data->len) {
            size_t reduce = data->len - window_update_size;
            assert(reduce <= connection->thread_data.incoming_message_window_update);
            connection->thread_data.incoming_message_window_update -= reduce;

            AWS_LOGF_DEBUG(
                AWS_LS_HTTP_STREAM,
                "id=%p: Incoming body callback changed window update size, window will shrink by %zu.",
                (void *)&incoming_stream->base,
                reduce);
        }
    }

    /* Stop decoding if user callback shut down the connection. */
    if (connection->thread_data.is_shutting_down) {
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_done(void *user_data) {
    struct h1_connection *connection = user_data;
    struct h1_stream *incoming_stream = connection->thread_data.incoming_stream;
    assert(incoming_stream);

    /* Ensure head was marked done */
    int err = s_mark_head_done(incoming_stream);
    if (err) {
        return AWS_OP_ERR;
    }

    incoming_stream->is_incoming_message_done = true;

    if (incoming_stream->outgoing_state == STREAM_OUTGOING_STATE_DONE) {
        assert(&incoming_stream->node == aws_linked_list_begin(&connection->thread_data.stream_list));

        s_stream_complete(incoming_stream, AWS_ERROR_SUCCESS);

        s_update_incoming_stream_ptr(connection);
    }

    /* Report success even if user's on_complete() callback shuts down on the connection.
     * We don't want it to look like something went wrong while decoding.
     * The decode() function returns after each message completes,
     * and we won't call decode() again if the connection has been shut down */
    return AWS_OP_SUCCESS;
}

/* Common new() logic for server & client */
static struct h1_connection *s_connection_new(struct aws_allocator *alloc) {

    struct h1_connection *connection = aws_mem_acquire(alloc, sizeof(struct h1_connection));
    if (!connection) {
        goto error_connection_alloc;
    }
    AWS_ZERO_STRUCT(*connection);

    connection->base.vtable = &s_connection_vtable;
    connection->base.alloc = alloc;
    connection->base.channel_handler.vtable = &s_connection_vtable.channel_handler_vtable;
    connection->base.channel_handler.impl = connection;
    connection->base.http_version = AWS_HTTP_VERSION_1_1;

    /* 1 refcount for user */
    aws_atomic_init_int(&connection->base.refcount, 1);

    aws_channel_task_init(&connection->outgoing_stream_task, s_outgoing_stream_task, connection);
    aws_channel_task_init(&connection->window_update_task, s_update_window_task, connection);
    aws_channel_task_init(&connection->shutdown_delay_task, s_shutdown_delay_task, connection);
    aws_linked_list_init(&connection->thread_data.stream_list);

    int err = aws_mutex_init(&connection->synced_data.lock);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION, "static: Failed to initialize mutex, error %d (%s).", err, aws_error_name(err));

        goto error_mutex;
    }

    aws_linked_list_init(&connection->synced_data.pending_stream_list);

    struct aws_http_decoder_params options = {
        .alloc = alloc,
        .is_decoding_requests = connection->base.server_data != NULL,
        .user_data = connection,
        .vtable = s_decoder_vtable,
        .scratch_space_initial_size = DECODER_INITIAL_SCRATCH_SIZE,
    };
    connection->thread_data.incoming_stream_decoder = aws_http_decoder_new(&options);
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
    const struct aws_http_server_connection_impl_options *options) {

    struct h1_connection *connection = s_connection_new(options->alloc);
    if (!connection) {
        return NULL;
    }

    connection->base.initial_window_size = options->initial_window_size;
    connection->base.server_data = &connection->base.client_or_server_data.server;

    return &connection->base;
}

struct aws_http_connection *aws_http_connection_new_http1_1_client(
    const struct aws_http_client_connection_impl_options *options) {

    struct h1_connection *connection = s_connection_new(options->alloc);
    if (!connection) {
        return NULL;
    }

    connection->base.initial_window_size = options->initial_window_size;
    connection->base.user_data = options->user_data;
    connection->base.client_data = &connection->base.client_or_server_data.client;
    connection->base.client_data->on_shutdown = options->on_shutdown;

    return &connection->base;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct h1_connection *connection = handler->impl;

    AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Destroying connection.", (void *)&connection->base);

    assert(aws_linked_list_empty(&connection->thread_data.stream_list));
    assert(aws_linked_list_empty(&connection->synced_data.pending_stream_list));

    aws_http_decoder_destroy(connection->thread_data.incoming_stream_decoder);
    aws_mutex_clean_up(&connection->synced_data.lock);
    aws_mem_release(connection->base.alloc, connection);
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct h1_connection *connection = handler->impl;
    int err;

    /* By default, we will increment the read window by the same amount we just read in.
     * However, users have the opportunity to tweak this number in their aws_http_on_incoming_body_fn() callback. */
    connection->thread_data.incoming_message_window_update = message->message_data.len;

    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Begin processing message of size %zu.",
        (void *)&connection->base,
        message->message_data.len);

    /* Run decoder until all message data is processed */
    struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);
    while (message_cursor.len > 0) {
        if (connection->thread_data.is_shutting_down) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Cannot process message because connection is shutting down.",
                (void *)&connection->base);

            aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
            goto error;
        }

        if (!connection->thread_data.incoming_stream) {
            /* TODO: Server connection would create new request-handler stream at this point. */

            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Cannot process message because no requests are currently awaiting response, closing "
                "connection.",
                (void *)&connection->base);

            aws_raise_error(AWS_ERROR_HTTP_INVALID_PARSE_STATE);
            goto error;
        }

        /* Decoder will invoke the internal s_decoder_X callbacks, which in turn invoke user callbacks */
        aws_http_decoder_set_logging_id(
            connection->thread_data.incoming_stream_decoder, connection->thread_data.incoming_stream);

        size_t decoded_len = 0;
        err = aws_http_decode(
            connection->thread_data.incoming_stream_decoder, message_cursor.ptr, message_cursor.len, &decoded_len);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Message processing failed, error %d (%s). Closing connection.",
                (void *)&connection->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            goto error;
        }

        AWS_FATAL_ASSERT(decoded_len > 0);
        aws_byte_cursor_advance(&message_cursor, decoded_len);
    }

    AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Done processing message.", (void *)&connection->base);

    if (connection->thread_data.incoming_message_window_update > 0) {
        err = aws_channel_slot_increment_read_window(slot, connection->thread_data.incoming_message_window_update);
        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Failed to increment read window, error %d (%s). Closing connection.",
                (void *)&connection->base,
                aws_last_error(),
                aws_error_name(aws_last_error()));

            goto error;
        }
    }

    aws_mem_release(message->allocator, message);
    return AWS_OP_SUCCESS;
error:
    aws_mem_release(message->allocator, message);
    s_shutdown_connection(connection, aws_last_error());
    return AWS_OP_ERR;
}

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;
    assert(false); /* Should not be called until websocket stuff comes along. */
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    (void)handler;
    (void)slot;
    (void)size;
    assert(false); /* Should not be called until websocket stuff comes along. */
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)free_scarce_resources_immediately;
    struct h1_connection *connection = handler->impl;

    /* Shut everything down the first time we get this callback (DIR_READ). */
    if (dir == AWS_CHANNEL_DIR_READ) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Channel shutting down with error code %d (%s).",
            (void *)&connection->base,
            error_code,
            aws_error_name(error_code));

        /* This call ensures that no further streams will be created or worked on. */
        s_shutdown_connection(connection, error_code);

        /* Mark all pending streams as complete. */
        int stream_error_code = error_code == AWS_ERROR_SUCCESS ? AWS_ERROR_HTTP_CONNECTION_CLOSED : error_code;

        while (!aws_linked_list_empty(&connection->thread_data.stream_list)) {
            struct aws_linked_list_node *node = aws_linked_list_front(&connection->thread_data.stream_list);
            s_stream_complete(AWS_CONTAINER_OF(node, struct h1_stream, node), stream_error_code);
        }

        /* It's OK to access synced_data.pending_stream_list without holding the lock because
         * no more streams can be added after s_shutdown_connection() has been invoked. */
        while (!aws_linked_list_empty(&connection->synced_data.pending_stream_list)) {
            struct aws_linked_list_node *node = aws_linked_list_front(&connection->synced_data.pending_stream_list);
            s_stream_complete(AWS_CONTAINER_OF(node, struct h1_stream, node), stream_error_code);
        }

        struct aws_http_connection *base = &connection->base;
        if (base->server_data && base->server_data->on_shutdown) {
            base->server_data->on_shutdown(base, error_code, base->user_data);
        } else if (base->client_data && base->client_data->on_shutdown) {
            base->client_data->on_shutdown(base, error_code, base->user_data);
        }
    }

    aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
    return AWS_OP_SUCCESS;
}

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    struct h1_connection *connection = handler->impl;
    return connection->base.initial_window_size;
}

static size_t s_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}
