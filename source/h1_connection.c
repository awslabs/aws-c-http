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
#include <aws/http/private/h1_decoder.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/io/logging.h>
#include <aws/io/stream.h>

/* TODO: try to continue processing channel messages during shutdown */

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
        },

    .new_client_request_stream = s_new_client_request_stream,
    .close = s_connection_close,
    .is_open = s_connection_is_open,
};

static const struct aws_http_stream_vtable s_stream_vtable = {
    .destroy = s_stream_destroy,
    .update_window = s_stream_update_window,
};

static const struct aws_http_decoder_vtable s_h1_decoder_vtable = {
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
        struct aws_h1_decoder *incoming_stream_decoder;

        /* Amount to let read-window shrink after a channel message has been processed. */
        size_t incoming_message_window_shrink_size;

        /* Messages received after the connection has switched protocols.
         * These are passed downstream to the next handler. */
        struct aws_linked_list midchannel_read_messages;

        /* For checking status from the event-loop thread. Duplicates synced_data.is_shutting_down */
        bool is_shutting_down;

        int shutdown_error_code;

        /* If true, the connection has upgraded to another protocol.
         * It will pass data to adjacent channel handlers without altering it.
         * The connection can no longer service request/response streams. */
        bool has_switched_protocols;
    } thread_data;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

        /* New streams that have not been moved to `stream_list` yet. */
        struct aws_linked_list pending_stream_list;

        bool is_outgoing_stream_task_active;

        /* For checking status from outside the event-loop thread. Duplicates thread_data.is_shutting_down */
        bool is_shutting_down;

        /* If non-zero, reason to immediately reject new streams. (ex: closing, switched protocols, */
        int new_stream_error_code;

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
        connection->synced_data.new_stream_error_code = AWS_ERROR_HTTP_CONNECTION_CLOSED;

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
    const struct aws_http_request *request,
    size_t *out_header_lines_len) {

    size_t total = 0;

    const size_t num_headers = aws_http_request_get_header_count(request);

    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header;
        aws_http_request_get_header(request, &header, i);

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

                if (!stream->base.outgoing_body) {
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_CONNECTION,
                        "id=%p: Failed to create stream, '" PRInSTR "' header specified but body stream is not set.",
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

static void s_write_headers(struct aws_byte_buf *dst, const struct aws_http_request *request) {

    const size_t num_headers = aws_http_request_get_header_count(request);

    bool wrote_all = true;
    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header;
        aws_http_request_get_header(request, &header, i);

        /* header-line: "{name}: {value}\r\n" */
        wrote_all &= aws_byte_buf_write_from_whole_cursor(dst, header.name);
        wrote_all &= aws_byte_buf_write_u8(dst, ':');
        wrote_all &= aws_byte_buf_write_u8(dst, ' ');
        wrote_all &= aws_byte_buf_write_from_whole_cursor(dst, header.value);
        wrote_all &= aws_byte_buf_write_u8(dst, '\r');
        wrote_all &= aws_byte_buf_write_u8(dst, '\n');
    }
    AWS_ASSERT(wrote_all);
}

struct aws_http_stream *s_new_client_request_stream(const struct aws_http_request_options *options) {
    if (options->request == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create client request, options are invalid.",
            (void *)options->client_connection);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_byte_cursor method;
    int err = aws_http_request_get_method(options->request, &method);
    struct aws_byte_cursor uri;
    err |= aws_http_request_get_path(options->request, &uri);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Failed to create request, HTTP pethod and path must be set.",
            (void *)options->client_connection);

        return NULL;
    }

    struct h1_stream *stream = aws_mem_calloc(options->client_connection->alloc, 1, sizeof(struct h1_stream));
    if (!stream) {
        return NULL;
    }

    stream->base.vtable = &s_stream_vtable;
    stream->base.alloc = options->client_connection->alloc;
    stream->base.owning_connection = options->client_connection;
    stream->base.outgoing_body = aws_http_request_get_body_stream(options->request);
    stream->base.user_data = options->user_data;
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
    err = s_stream_scan_outgoing_headers(stream, options->request, &header_lines_len);
    if (err) {
        /* errors already logged by scan_outgoing_headers() function */
        goto error_scanning_headers;
    }

    /* request-line: "{method} {uri} {version}\r\n" */
    size_t request_line_len = 4; /* 2 spaces + "\r\n" */
    err |= aws_add_size_checked(method.len, request_line_len, &request_line_len);
    err |= aws_add_size_checked(uri.len, request_line_len, &request_line_len);
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

    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, method);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, uri);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, version);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\n');

    s_write_headers(&stream->outgoing_head_buf, options->request);

    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\n');
    (void)wrote_all;
    AWS_ASSERT(wrote_all);

    /* Insert new stream into pending list, and schedule outgoing_stream_task if it's not already running. */
    int new_stream_error_code = AWS_ERROR_SUCCESS;
    bool should_schedule_task = false;

    struct h1_connection *connection = AWS_CONTAINER_OF(options->client_connection, struct h1_connection, base);
    { /* BEGIN CRITICAL SECTION */
        err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(!err);

        if (connection->synced_data.new_stream_error_code) {
            new_stream_error_code = connection->synced_data.new_stream_error_code;
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

    if (new_stream_error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create request, error %d (%s)",
            (void *)options->client_connection,
            new_stream_error_code,
            aws_error_name(new_stream_error_code));

        aws_raise_error(new_stream_error_code);
        goto error_from_connection;
    }

    /* Success! */
    AWS_LOGF_DEBUG(
        AWS_LS_HTTP_STREAM,
        "id=%p: Created client request on connection=%p: " PRInSTR " " PRInSTR " " PRInSTR,
        (void *)&stream->base,
        (void *)options->client_connection,
        AWS_BYTE_CURSOR_PRI(method),
        AWS_BYTE_CURSOR_PRI(uri),
        AWS_BYTE_CURSOR_PRI(aws_http_version_to_str(connection->base.http_version)));

    if (should_schedule_task) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Scheduling outgoing stream task.", (void *)&connection->base);
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->outgoing_stream_task);
    }

    return &stream->base;

error_from_connection:
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
    AWS_LOGF_TRACE(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: Zeroing window update size, was %zu",
        (void *)&connection->base,
        window_update_size);
    connection->synced_data.window_update_size = 0;

    err = aws_mutex_unlock(&connection->synced_data.lock);
    AWS_FATAL_ASSERT(!err);
    /* END CRITICAL SECTION */

    s_update_window_action(connection, window_update_size);
}

static void s_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    struct h1_connection *connection = AWS_CONTAINER_OF(stream->owning_connection, struct h1_connection, base);

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
    int err = aws_mutex_lock(&connection->synced_data.lock);
    AWS_FATAL_ASSERT(!err);

    /* if this is not volatile, gcc-4x will load window_update_size's address into a register
     * and then read it as should_schedule_task down below, which will invert its meaning */
    volatile bool should_schedule_task = (connection->synced_data.window_update_size == 0);
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
static int s_stream_write_outgoing_data(struct h1_stream *stream, struct aws_io_message *msg) {
    struct aws_byte_buf *dst = &msg->message_data;

    if (stream->outgoing_state == STREAM_OUTGOING_STATE_HEAD) {
        size_t dst_available = dst->capacity - dst->len;
        if (dst_available == 0) {
            /* Can't write anymore */
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_STREAM, "id=%p: Cannot fit any more head data in this message.", (void *)&stream->base);
            return AWS_OP_SUCCESS;
        }

        /* Copy data from stream->outgoing_head_buf */
        struct aws_byte_buf *src = &stream->outgoing_head_buf;
        size_t src_progress = stream->outgoing_head_progress;
        size_t src_remaining = src->len - src_progress;
        size_t transferring = src_remaining < dst_available ? src_remaining : dst_available;

        bool success = aws_byte_buf_write(dst, src->buffer + src_progress, transferring);
        (void)success;
        AWS_ASSERT(success);

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
                    /* Return success because we want to try again later */
                    return AWS_OP_SUCCESS;
                }

                struct aws_stream_status status;
                int err = aws_input_stream_get_status(stream->base.outgoing_body, &status);
                if (err || !status.is_valid) {
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_STREAM, "id=%p: Body stream reporting status invalid", (void *)&stream->base);
                    return aws_raise_error(AWS_IO_STREAM_READ_FAILED);
                }

                size_t amount_read = 0;
                err = aws_input_stream_read(stream->base.outgoing_body, dst, &amount_read);
                if (err) {
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_STREAM, "id=%p: Body stream reporting error reading", (void *)&stream->base);
                    return aws_raise_error(AWS_IO_STREAM_READ_FAILED);
                }

                AWS_LOGF_TRACE(
                    AWS_LS_HTTP_STREAM,
                    "id=%p: Writing %zu body bytes to message.",
                    (void *)&stream->base,
                    amount_read);

                err = aws_input_stream_get_status(stream->base.outgoing_body, &status);
                if (err || !status.is_valid) {
                    AWS_LOGF_ERROR(
                        AWS_LS_HTTP_STREAM, "id=%p: Body stream reporting status invalid", (void *)&stream->base);
                    return aws_raise_error(AWS_IO_STREAM_READ_FAILED);
                }
                if (status.is_end_of_stream) {
                    AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Done sending body.", (void *)&stream->base);
                    stream->outgoing_state++;
                    break;
                }

                /* Return if user failed to write anything. Maybe their data isn't ready yet. */
                if (amount_read == 0) {
                    AWS_LOGF_TRACE(
                        AWS_LS_HTTP_STREAM,
                        "id=%p: No body data written, concluding this message."
                        " Will try to write body data again in the next message.",
                        (void *)&stream->base);
                    return AWS_OP_SUCCESS;
                }
            }
        }
    }

    if (stream->outgoing_state == STREAM_OUTGOING_STATE_DONE) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Stream is done sending data.", (void *)&stream->base);
    }
    return AWS_OP_SUCCESS;
}

static void s_stream_complete(struct h1_stream *stream, int error_code) {
    struct h1_connection *connection = AWS_CONTAINER_OF(stream->base.owning_connection, struct h1_connection, base);

    /* Remove stream from list. */
    aws_linked_list_remove(&stream->node);

    /* If stream completed successfully, check for ways it might alter the state of the connection.
     * If anything goes wrong here, modify error_code, and the connection will get shut down as a result. */
    const int original_error_code = error_code;
    if (!error_code) {

        /* Check whether connection is switching protocols. */
        if (stream->base.incoming_response_status == AWS_HTTP_STATUS_101_SWITCHING_PROTOCOLS) {
            /* TODO: confirm that request had sent "Connection: Upgrade" header */

            /* Switching protocols while there are pending streams is too complex to deal with. */
            bool has_pending_streams = false;
            if (!aws_linked_list_empty(&connection->thread_data.stream_list)) {
                has_pending_streams = true;
            } else {
                { /* BEGIN CRITICAL SECTION */
                    int err = aws_mutex_lock(&connection->synced_data.lock);
                    AWS_FATAL_ASSERT(!err);

                    if (aws_linked_list_empty(&connection->synced_data.pending_stream_list)) {
                        connection->synced_data.new_stream_error_code = AWS_ERROR_HTTP_SWITCHED_PROTOCOLS;
                    } else {
                        has_pending_streams = true;
                    }

                    err = aws_mutex_unlock(&connection->synced_data.lock);
                    AWS_FATAL_ASSERT(!err);
                } /* END CRITICAL SECTION */
            }

            if (has_pending_streams) {
                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_CONNECTION,
                    "id=%p: Cannot switch protocols while streams are pending, closing connection.",
                    (void *)&connection->base);

                error_code = AWS_ERROR_INVALID_STATE;
                goto finish_up;
            } else {
                AWS_LOGF_TRACE(
                    AWS_LS_HTTP_CONNECTION,
                    "id=%p: Connection has switched protocols, another channel handler must be installed to"
                    " deal with further data.",
                    (void *)&connection->base);

                connection->thread_data.has_switched_protocols = true;
            }
        }
    }

finish_up:

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

    /* Invoke callback and clean up stream. */
    if (stream->base.on_complete) {
        stream->base.on_complete(&stream->base, error_code, stream->base.user_data);
    }

    aws_http_stream_release(&stream->base);

    /* If this function started out ok, but ended badly, shut down the connection. */
    if (!original_error_code && error_code) {
        s_shutdown_connection(connection, error_code);
    }
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
            AWS_ASSERT(&current->node == aws_linked_list_begin(&connection->thread_data.stream_list));

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
    if (connection->thread_data.is_shutting_down || connection->thread_data.has_switched_protocols) {
        return;
    }

    AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "id=%p: Outgoing stream task is running.", (void *)&connection->base);

    /* If outgoing_message_size_hint isn't set yet, calculate it */
    size_t overhead = aws_channel_slot_upstream_message_overhead(connection->base.channel_slot);
    if (overhead >= MESSAGE_SIZE_HINT) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Unexpected error while calculating message size, closing connection.",
            (void *)&connection->base);

        aws_raise_error(AWS_ERROR_INVALID_STATE);
        goto error;
    }

    size_t outgoing_message_size_hint = MESSAGE_SIZE_HINT - overhead;

    msg = aws_channel_acquire_message_from_pool(channel, AWS_IO_MESSAGE_APPLICATION_DATA, outgoing_message_size_hint);
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

        if (s_stream_write_outgoing_data(outgoing_stream, msg)) {
            /* Error sending data, abandon ship */
            goto error;
        }

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

    AWS_ASSERT(incoming_stream->base.incoming_request_method_str.len == 0);
    AWS_ASSERT(incoming_stream->base.incoming_request_uri.len == 0);

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
    int transfer_encoding = aws_h1_decoder_get_encoding_flags(connection->thread_data.incoming_stream_decoder);
    has_incoming_body |= (transfer_encoding & AWS_HTTP_TRANSFER_ENCODING_CHUNKED);
    has_incoming_body |= aws_h1_decoder_get_content_length(connection->thread_data.incoming_stream_decoder);

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
    AWS_ASSERT(incoming_stream);

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
            connection->thread_data.incoming_message_window_shrink_size += reduce;

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
    AWS_ASSERT(incoming_stream);

    /* Ensure head was marked done */
    int err = s_mark_head_done(incoming_stream);
    if (err) {
        return AWS_OP_ERR;
    }

    incoming_stream->is_incoming_message_done = true;

    if (incoming_stream->outgoing_state == STREAM_OUTGOING_STATE_DONE) {
        AWS_ASSERT(&incoming_stream->node == aws_linked_list_begin(&connection->thread_data.stream_list));

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
static struct h1_connection *s_connection_new(struct aws_allocator *alloc, size_t initial_window_size) {

    struct h1_connection *connection = aws_mem_calloc(alloc, 1, sizeof(struct h1_connection));
    if (!connection) {
        goto error_connection_alloc;
    }

    connection->base.vtable = &s_h1_connection_vtable;
    connection->base.alloc = alloc;
    connection->base.channel_handler.vtable = &s_h1_connection_vtable.channel_handler_vtable;
    connection->base.channel_handler.impl = connection;
    connection->base.http_version = AWS_HTTP_VERSION_1_1;
    connection->base.initial_window_size = initial_window_size;

    /* 1 refcount for user */
    aws_atomic_init_int(&connection->base.refcount, 1);

    aws_channel_task_init(
        &connection->outgoing_stream_task, s_outgoing_stream_task, connection, "http1_outgoing_stream");
    aws_channel_task_init(&connection->window_update_task, s_update_window_task, connection, "http1_update_window");
    aws_channel_task_init(&connection->shutdown_delay_task, s_shutdown_delay_task, connection, "http1_delay_shutdown");
    aws_linked_list_init(&connection->thread_data.stream_list);
    aws_linked_list_init(&connection->thread_data.midchannel_read_messages);

    int err = aws_mutex_init(&connection->synced_data.lock);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION, "static: Failed to initialize mutex, error %d (%s).", err, aws_error_name(err));

        goto error_mutex;
    }

    aws_linked_list_init(&connection->synced_data.pending_stream_list);

    struct aws_h1_decoder_params options = {
        .alloc = alloc,
        .is_decoding_requests = connection->base.server_data != NULL,
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
    size_t initial_window_size) {

    struct h1_connection *connection = s_connection_new(allocator, initial_window_size);
    if (!connection) {
        return NULL;
    }

    connection->base.server_data = &connection->base.client_or_server_data.server;

    return &connection->base;
}

struct aws_http_connection *aws_http_connection_new_http1_1_client(
    struct aws_allocator *allocator,
    size_t initial_window_size) {

    struct h1_connection *connection = s_connection_new(allocator, initial_window_size);
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
    AWS_ASSERT(aws_linked_list_empty(&connection->synced_data.pending_stream_list));

    aws_h1_decoder_destroy(connection->thread_data.incoming_stream_decoder);
    aws_mutex_clean_up(&connection->synced_data.lock);
    aws_mem_release(connection->base.alloc, connection);
}

static void s_connection_try_send_read_messages(struct h1_connection *connection) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(connection->base.channel_slot->channel));
    AWS_ASSERT(connection->thread_data.has_switched_protocols);
    AWS_ASSERT(!connection->thread_data.is_shutting_down);

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

        struct aws_linked_list_node *node = aws_linked_list_front(&connection->thread_data.midchannel_read_messages);
        struct aws_io_message *queued_msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

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
                aws_linked_list_pop_front(&connection->thread_data.midchannel_read_messages);
                aws_mem_release(queued_msg->allocator, queued_msg);
            }

        } else {
            /* Sending all of queued_msg along. */
            AWS_LOGF_TRACE(
                AWS_LS_HTTP_CONNECTION,
                "id=%p: Sending full switched-protocol message of size %zu to next handler.",
                (void *)&connection->base,
                queued_msg->message_data.len);

            aws_linked_list_pop_front(&connection->thread_data.midchannel_read_messages);
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
    s_shutdown_connection(connection, aws_last_error());
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct h1_connection *connection = handler->impl;
    int err;

    const size_t incoming_message_size = message->message_data.len;

    /* By default, after processing message, we will increment the read window by the same amount we just read in.
     * But users can let the window shrink by tweaking numbers from their aws_http_on_incoming_body_fn() callback. */
    connection->thread_data.incoming_message_window_shrink_size = 0;

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
                /* TODO: Server connection would create new request-handler stream at this point. */

                AWS_LOGF_ERROR(
                    AWS_LS_HTTP_CONNECTION,
                    "id=%p: Cannot process message because no requests are currently awaiting response, closing "
                    "connection.",
                    (void *)&connection->base);

                aws_raise_error(AWS_ERROR_INVALID_STATE);
                goto shutdown;
            }

            /* Decoder will invoke the internal s_decoder_X callbacks, which in turn invoke user callbacks */
            aws_h1_decoder_set_logging_id(
                connection->thread_data.incoming_stream_decoder, connection->thread_data.incoming_stream);

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

    if (message) {
        aws_mem_release(message->allocator, message);
    }
    return AWS_OP_SUCCESS;

shutdown:
    if (message) {
        aws_mem_release(message->allocator, message);
    }
    s_shutdown_connection(connection, aws_last_error());
    return AWS_OP_SUCCESS;
}

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct h1_connection *connection = handler->impl;

    if (connection->thread_data.is_shutting_down) {
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
    return AWS_OP_SUCCESS;
}

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    struct h1_connection *connection = handler->impl;

    if (connection->thread_data.is_shutting_down) {
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

    s_shutdown_connection(connection, aws_last_error());
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

        /* Clean up any queued midchannel read messages. */
        while (!aws_linked_list_empty(&connection->thread_data.midchannel_read_messages)) {
            struct aws_linked_list_node *node =
                aws_linked_list_pop_front(&connection->thread_data.midchannel_read_messages);
            struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
            aws_mem_release(msg->allocator, msg);
        }

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
