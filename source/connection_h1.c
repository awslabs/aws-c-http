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

#include <aws/common/mutex.h>
#include <aws/http/private/request_response_impl.h>

#include <stdio.h>

enum {
    MESSAGE_SIZE_HINT = 16 * 1024,
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
static void s_stream_destroy(struct aws_http_stream *stream_base);

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
};

const static struct aws_http_stream_vtable s_stream_vtable = {
    .destroy = s_stream_destroy,
};

struct h1_connection {
    struct aws_http_connection base;

    /* Single task used repeatedly for sending data from streams. */
    struct aws_channel_task outgoing_stream_task;

    /* Only the event-loop thread may touch this data */
    struct {
        /* List of streams being worked on. */
        struct aws_linked_list stream_list;

        /* Points to the stream whose data is currently being sent.
         * This stream is ALWAYS in the `stream_list`.
         * HTTP pipelining is supported, so once the stream is completely written
         * we'll start working on the next stream in the list */
        struct h1_stream *outgoing_stream;
    } el_thread_data;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

        /* New streams that have not been moved to `stream_list` yet. */
        struct aws_linked_list pending_stream_list;

        bool is_outgoing_stream_task_active;
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
};

/**
 * Scan headers and determine the length necessary to write them all.
 * Also update the stream with any special data it needs to know from these headers.
 */
static int s_stream_scan_outgoing_headers(
    struct h1_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    size_t *out_header_lines_len) {

    *out_header_lines_len = 0;

    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header = header_array[i];

        enum aws_http_header_name name_enum;
        size_t name_len;

        if (header.name_str.len > 0) {
            name_len = header.name_str.len;
            name_enum = aws_http_str_to_header_name(header.name_str);
        } else if (header.name != AWS_HTTP_HEADER_UNKNOWN) {
            name_len = strlen(aws_http_header_name_to_str(header.name));
            name_enum = header.name;
        } else {
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }

        switch (name_enum) {
            case AWS_HTTP_HEADER_CONTENT_LENGTH:
            case AWS_HTTP_HEADER_TRANSFER_ENCODING:
                /* TODO: actually process the values in these headers*/
                stream->has_outgoing_body = true;

                if (!stream->base.user_cb_outgoing_body_sender) {
                    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
                }
                break;
            default:
                break;
        }

        /* header-line: "{name}: {value}\r\n" */
        *out_header_lines_len += name_len + 2 + header.value.len + 2;
    }

    return AWS_OP_SUCCESS;
}

static void s_write_headers(
    struct aws_byte_buf *dst,
    const struct aws_http_header *header_array,
    size_t num_headers) {

    bool wrote_all = true;
    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header header = header_array[i];
        struct aws_byte_cursor name_cursor;
        if (header.name_str.len > 0) {
            name_cursor = header.name_str;
        } else {
            name_cursor = aws_byte_cursor_from_c_str(aws_http_header_name_to_str(header.name));
        }

        /* header-line: "{name}: {value}\r\n" */
        wrote_all &= aws_byte_buf_write_from_whole_cursor(dst, name_cursor);
        wrote_all &= aws_byte_buf_write_u8(dst, ':');
        wrote_all &= aws_byte_buf_write_u8(dst, ' ');
        wrote_all &= aws_byte_buf_write_from_whole_cursor(dst, header.value);
        wrote_all &= aws_byte_buf_write_u8(dst, '\r');
        wrote_all &= aws_byte_buf_write_u8(dst, '\n');
    }
    assert(wrote_all);
}

struct aws_http_stream *s_new_client_request_stream(const struct aws_http_request_options *options) {
    if (options->uri.len == 0 || (options->method == AWS_HTTP_METHOD_UNKNOWN && options->method_str.len == 0)) {
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
    stream->base.user_cb_outgoing_body_sender = options->body_sender;
    stream->base.user_cb_on_incoming_headers = options->on_response_headers;
    stream->base.user_cb_on_incoming_header_block_done = options->on_response_header_block_done;
    stream->base.user_cb_on_incoming_body = options->on_response_body;
    stream->base.user_cb_on_complete = options->on_complete;

    /* Stream refcount starts at 2. 1 for user and 1 for connection to release it's done with the stream */
    aws_atomic_init_int(&stream->base.refcount, 2);

    struct aws_byte_cursor method_cursor;
    if (options->method_str.len > 0) {
        method_cursor = options->method_str;
    } else {
        /* TODO: make _to_cursor() versions of these _to_str() functions to avoid runtime strlen() */
        method_cursor = aws_byte_cursor_from_c_str(aws_http_method_to_str(options->method));
    }

    struct aws_byte_cursor version_cursor = aws_byte_cursor_from_c_str(aws_http_version_to_str(AWS_HTTP_VERSION_1_1));

    /**
     * Calculate total size needed for outgoing_head_buffer, then write to buffer.
     * The head will look like this:
     * request-line: "{method} {uri} {version}\r\n"
     * header-line: "{name}: {value}\r\n"
     * head-end: "\r\n"
     */
    size_t request_line_len = method_cursor.len + 1 + options->uri.len + 1 + version_cursor.len + 2;
    size_t header_lines_len;
    int err = s_stream_scan_outgoing_headers(stream, options->header_array, options->num_headers, &header_lines_len);
    if (err) {
        goto error;
    }

    size_t head_end_len = 2;

    size_t head_total_len = request_line_len + header_lines_len + head_end_len;
    err = aws_byte_buf_init(&stream->outgoing_head_buf, stream->base.alloc, head_total_len);
    if (err) {
        goto error;
    }

    bool wrote_all = true;

    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, method_cursor);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, options->uri);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, version_cursor);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\n');

    s_write_headers(&stream->outgoing_head_buf, options->header_array, options->num_headers);

    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\n');

    assert(wrote_all);

    /* Insert new stream into pending list, and schedule outgoing_stream_task if it's not already running. */
    bool should_schedule_task = false;
    struct h1_connection *connection = AWS_CONTAINER_OF(options->client_connection, struct h1_connection, base);

    { /* BEGIN CRITICAL SECTION */
        err = aws_mutex_lock(&connection->synced_data.lock);
        assert(!err);

        aws_linked_list_push_back(&connection->synced_data.pending_stream_list, &stream->node);
        if (!connection->synced_data.is_outgoing_stream_task_active) {
            connection->synced_data.is_outgoing_stream_task_active = true;
            should_schedule_task = true;
        }

        err = aws_mutex_unlock(&connection->synced_data.lock);
        assert(!err);
    } /* END CRITICAL SECTION */

    if (should_schedule_task) {
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &connection->outgoing_stream_task);
    }

    return &stream->base;

error:
    aws_byte_buf_clean_up(&stream->outgoing_head_buf);
    aws_mem_release(stream->base.alloc, stream);
    return NULL;
}

static void s_stream_destroy(struct aws_http_stream *stream_base) {
    struct h1_stream *stream = AWS_CONTAINER_OF(stream_base, struct h1_stream, base);

    aws_byte_buf_clean_up(&stream->outgoing_head_buf);
    aws_mem_release(stream->base.alloc, stream);
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

        if (stream->outgoing_head_progress == src->len) {
            /* Don't NEED to free this buffer now, but we don't need it anymore, so why not */
            aws_byte_buf_clean_up(&stream->outgoing_head_buf);

            stream->outgoing_state++;
        }
    }

    if (stream->outgoing_state == STREAM_OUTGOING_STATE_BODY) {
        if (!stream->has_outgoing_body) {
            stream->outgoing_state++;
        } else {
            while (true) {
                if (dst->capacity == dst->len) {
                    /* Can't write anymore */
                    return;
                }

                size_t prev_len = dst->len;

                enum aws_http_body_sender_state state =
                    stream->base.user_cb_outgoing_body_sender(&stream->base, dst, stream->base.user_data);

                if (state == AWS_HTTP_BODY_SENDER_DONE) {
                    stream->outgoing_state++;
                    break;
                }

                /* Return if user failed to write anything. Maybe their data isn't ready yet. */
                if (prev_len == dst->len) {
                    return;
                }
            }
        }
    }
}

static void s_stream_complete(struct h1_stream *stream, int error_code) {
    if (stream->base.user_cb_on_complete) {
        stream->base.user_cb_on_complete(&stream->base, error_code, stream->base.user_data);
    }

    aws_http_stream_release(&stream->base);
}

/**
 * If necessary, update `outgoing_stream` so it is pointing at a stream
 * with data to send, or NULL if all streams are done sending data.
 *
 * Called from event-loop thread.
 * This function has lots of side effects.
 */
static struct h1_stream *s_acquire_current_outgoing_stream(struct h1_connection *connection) {
    struct h1_stream *current = connection->el_thread_data.outgoing_stream;
    int err;

    /* If current stream is done sending data... */
    if (current && (current->outgoing_state == STREAM_OUTGOING_STATE_DONE)) {
        struct aws_linked_list_node *next_node = aws_linked_list_next(&current->node);

        /* If it's also done receiving data, then it's complete! */
        if (current->is_incoming_message_done) {
            assert(&current->node == aws_linked_list_begin(&connection->el_thread_data.stream_list));

            aws_linked_list_remove(&current->node);
            s_stream_complete(current, AWS_ERROR_SUCCESS);
        }

        /* Iterate current stream to the next item in stream_list. */
        if (next_node == aws_linked_list_end(&connection->el_thread_data.stream_list)) {
            current = NULL;
        } else {
            current = AWS_CONTAINER_OF(next_node, struct h1_stream, node);
        }
    }

    /* If current stream is NULL, look in synced_data.pending_stream_list for more work */
    if (!current) {

        /* BEGIN CRITICAL SECTION */
        err = aws_mutex_lock(&connection->synced_data.lock);
        assert(!err);

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
                    &connection->el_thread_data.stream_list,
                    aws_linked_list_pop_front(&connection->synced_data.pending_stream_list));

            } while (!aws_linked_list_empty(&connection->synced_data.pending_stream_list));
        }

        err = aws_mutex_unlock(&connection->synced_data.lock);
        assert(!err);
        /* END CRITICAL SECTION */
    }

    connection->el_thread_data.outgoing_stream = current;
    return current;
}

static void s_outgoing_stream_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct h1_connection *connection = arg;
    struct aws_channel *channel = connection->base.channel_slot->channel;
    int err;

    // TODO: aws_channel_slot_upstream_message_overhead() ???
    struct aws_io_message *msg =
        aws_channel_acquire_message_from_pool(channel, AWS_IO_MESSAGE_APPLICATION_DATA, MESSAGE_SIZE_HINT);
    if (!msg) {
        goto error;
    }

    /**
     * Fill message with as much data as possible before sending.
     * At first, we might be resuming work on a stream from a previous run of this task.
     * Loop until no more streams have data to send,
     * OR a stream still is unable to continue writing to the msg (probably because msg is full).
     */
    struct h1_stream *outgoing_stream;
    while (true) {
        outgoing_stream = s_acquire_current_outgoing_stream(connection);
        if (!outgoing_stream) {
            break;
        }

        s_stream_write_outgoing_data(outgoing_stream, msg);

        if (outgoing_stream->outgoing_state != STREAM_OUTGOING_STATE_DONE) {
            break;
        }
    }

    err = aws_channel_slot_send_message(connection->base.channel_slot, msg, AWS_CHANNEL_DIR_WRITE);
    if (err) {
        goto error;
    }

    /* Reschedule task if there's still more work to do. */
    if (outgoing_stream) {
        aws_channel_schedule_task_now(channel, task);
    }

    return;
error:
    /* Any error should shutdown the channel.
     * We leave is_outgoing_stream_task_active=true so that the task is never rescheduled. */

    // TODO: not totally true, task_active might be false, but msg failed to send. Think about how to handle this...
    if (msg) {
        aws_mem_release(msg->allocator, msg);
    }

    aws_channel_shutdown(channel, aws_last_error());
}

/* Common new() logic for server & client */
static struct h1_connection *s_connection_new(struct aws_allocator *alloc) {
    struct h1_connection *connection = aws_mem_acquire(alloc, sizeof(struct h1_connection));
    if (!connection) {
        return NULL;
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
    aws_linked_list_init(&connection->el_thread_data.stream_list);

    aws_mutex_init(&connection->synced_data.lock);
    aws_linked_list_init(&connection->synced_data.pending_stream_list);

    return connection;
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
    connection->base.client_data->user_cb_on_shutdown = options->user_cb_on_shutdown;

    return &connection->base;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct h1_connection *connection = handler->impl;

    // TODO: cleanup new data types

    aws_mem_release(connection->base.alloc, connection);
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;
    /* TODO: implement function */
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
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

    struct h1_connection *connection = handler->impl;

    /* Invoke user shutdown callback */
    if (dir == AWS_CHANNEL_DIR_WRITE) {
        struct aws_http_connection *base = &connection->base;
        if (base->server_data && base->server_data->user_cb_on_shutdown) {
            base->server_data->user_cb_on_shutdown(base, error_code, base->user_data);
        } else if (base->client_data && base->client_data->user_cb_on_shutdown) {
            base->client_data->user_cb_on_shutdown(base, error_code, base->user_data);
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
