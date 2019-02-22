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
#include <aws/http/request_response.h>

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

static struct aws_http_connection_vtable s_vtable = {
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
};

struct h1_connection {
    struct aws_http_connection base;

    /* Single task used repeatedly for sending data from streams. */
    struct aws_channel_task outgoing_stream_task;

    /* Only the event-loop thread may touch this data */
    struct {
        /* List of streams being worked on. */
        struct aws_linked_list stream_list;

        /* Points to the stream currently being sent.
         * The stream begin pointed to is ALWAYS in the `stream_list`.
         * HTTP Pipelining is supported, so once the stream is completely written
         * this pointer will iterate to the next stream in the list. */
        struct aws_http_stream *current_outgoing_stream;
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

struct aws_http_stream {
    enum stream_type type;
    struct h1_connection *connection;

    void *user_data;
    aws_http_body_sender_fn *user_cb_outgoing_body_sender;
    aws_http_on_incoming_headers_fn *user_cb_on_incoming_headers;
    aws_http_on_incoming_header_block_done_fn *user_cb_on_incoming_header_block_done;
    aws_http_on_incoming_body_fn *user_cb_on_incoming_body;
    aws_http_on_stream_complete_fn *user_cb_on_complete;

    struct aws_linked_list_node node;

    enum stream_outgoing_state outgoing_state;

    /* Upon creation, the "head" (everything preceding body) is buffered here. */
    struct aws_byte_buf outgoing_head_buf;
    size_t outgoing_head_progress;

    bool is_incoming_message_done;

    bool has_outgoing_body;
};

/**
 * Scan headers and determine the length necessary to write them all.
 * Also update the stream with any special data it needs to know from these headers.
 */
static int s_stream_scan_outgoing_headers(
    struct aws_http_stream *stream,
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

                if (!stream->user_cb_outgoing_body_sender) {
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

static bool s_stream_buffer_outgoing_headers(
    struct aws_byte_buf *buf,
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
        wrote_all &= aws_byte_buf_write_from_whole_cursor(buf, name_cursor);
        wrote_all &= aws_byte_buf_write_u8(buf, ':');
        wrote_all &= aws_byte_buf_write_u8(buf, ' ');
        wrote_all &= aws_byte_buf_write_from_whole_cursor(buf, header.value);
        wrote_all &= aws_byte_buf_write_u8(buf, '\r');
        wrote_all &= aws_byte_buf_write_u8(buf, '\n');
    }

    return wrote_all;
}

struct aws_http_stream *aws_http_stream_new_client_request(const struct aws_http_request_options *options) {
    if (!options || options->self_size == 0 || !options->client_connection ||
        aws_http_connection_get_version(options->client_connection) != AWS_HTTP_VERSION_1_1 || options->uri.len == 0 ||
        (options->method == AWS_HTTP_METHOD_UNKNOWN && options->method_str.len == 0)) {

        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_stream *stream = aws_mem_acquire(options->client_connection->alloc, sizeof(struct aws_http_stream));
    AWS_ZERO_STRUCT(*stream);

    stream->connection = AWS_CONTAINER_OF(options->client_connection, struct h1_connection, base);
    stream->user_data = options->user_data;
    stream->user_cb_outgoing_body_sender = options->body_sender;
    stream->user_cb_on_incoming_headers = options->on_response_headers;
    stream->user_cb_on_incoming_header_block_done = options->on_response_header_block_done;
    stream->user_cb_on_incoming_body = options->on_response_body;
    stream->user_cb_on_complete = options->on_complete;

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
    err = aws_byte_buf_init(&stream->outgoing_head_buf, stream->connection->base.alloc, head_total_len);
    if (err) {
        goto error;
    }

    bool wrote_all = true;

    /* Write request-line */
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, method_cursor);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, options->uri);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, ' ');
    wrote_all &= aws_byte_buf_write_from_whole_cursor(&stream->outgoing_head_buf, version_cursor);
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\n');

    /* Write header-lines */
    wrote_all &=
        s_stream_buffer_outgoing_headers(&stream->outgoing_head_buf, options->header_array, options->num_headers);

    /* Write CRLF for head-end */
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\r');
    wrote_all &= aws_byte_buf_write_u8(&stream->outgoing_head_buf, '\n');

    if (!wrote_all) {
        goto error;
    }

    /**
     * Insert new stream into pending list, and schedule outgoing_stream_task if it's not already running.
     */
    bool should_schedule_task = false;
    { /* BEGIN CRITICAL SECTION */
        err = aws_mutex_lock(&stream->connection->synced_data.lock);
        if (err) {
            goto error;
        }

        aws_linked_list_push_back(&stream->connection->synced_data.pending_stream_list, &stream->node);
        if (!stream->connection->synced_data.is_outgoing_stream_task_active) {
            stream->connection->synced_data.is_outgoing_stream_task_active = true;
            should_schedule_task = true;
        }

        aws_mutex_unlock(&stream->connection->synced_data.lock);
    } /* END CRITICAL SECTION */

    if (should_schedule_task) {
        aws_channel_schedule_task_now(
            stream->connection->base.channel_slot->channel, &stream->connection->outgoing_stream_task);
    }

    return stream;

error:
    aws_byte_buf_clean_up(&stream->outgoing_head_buf);
    aws_mem_release(options->client_connection->alloc, stream);
    return NULL;
}

/**
 * Write as much data to msg as possible.
 * The stream's state is updated as necessary to track progress.
 */
static void s_stream_write_outgoing_data(struct aws_http_stream *stream, struct aws_io_message *msg) {
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
            stream->outgoing_state++;
        }
    }

    if (stream->outgoing_state == STREAM_OUTGOING_STATE_BODY) {
        if (!stream->has_outgoing_body) {
            stream->outgoing_state++;
        } else {
            while (true) {
                size_t dst_available = dst->capacity - dst->len;
                if (dst_available == 0) {
                    /* Can't write anymore */
                    return;
                }

                /* Invoke user's body_sender() until 0 bytes are transferred, indicating that the body is done */
                size_t transferred = stream->user_cb_outgoing_body_sender(
                    stream, dst->buffer + dst->len, dst_available, stream->user_data);

                /* It would be super bad for user to write past end of buffer */
                AWS_FATAL_ASSERT(transferred <= dst_available);

                if (transferred == 0) {
                    stream->outgoing_state++;
                    break;
                }
            }
        }
    }
}

static void s_stream_complete(struct aws_http_stream *stream, int error_code) {
    if (stream->user_cb_on_complete) {
        stream->user_cb_on_complete(stream, error_code, stream->user_data);
    }

    // TODO: wtf is the lifetime of these things.
    aws_mem_release(stream->connection->base.alloc, stream);
}

/**
 * If necessary, update `current_outgoing_stream` so it is pointing at a stream
 * with data to send, or NULL if all streams are done sending data.
 *
 * Called from event-loop thread.
 * This function has lots of side effects.
 */
static struct aws_http_stream *s_acquire_current_outgoing_stream(struct h1_connection *impl) {
    struct aws_http_stream *current_stream = impl->el_thread_data.current_outgoing_stream;

    /* If current stream is done sending data... */
    if (current_stream && (current_stream->outgoing_state == STREAM_OUTGOING_STATE_DONE)) {
        struct aws_linked_list_node *next_node = aws_linked_list_next(&current_stream->node);

        /* If it's also done receiving data, then it's complete! */
        if (current_stream->is_incoming_message_done) {
            assert(&current_stream->node == aws_linked_list_begin(&impl->el_thread_data.stream_list));

            aws_linked_list_remove(&current_stream->node);
            s_stream_complete(current_stream, AWS_ERROR_SUCCESS);
        }

        /* Iterate current_stream to the next item in stream_list. */
        if (next_node == aws_linked_list_end(&impl->el_thread_data.stream_list)) {
            current_stream = NULL;
        } else {
            current_stream = AWS_CONTAINER_OF(next_node, struct aws_http_stream, node);
        }
    }

    if (!current_stream) {
        /* Look in synced_data.pending_stream_list for more streams to work on. */
        int err = aws_mutex_lock(&impl->synced_data.lock);
        AWS_FATAL_ASSERT(!err);

        if (aws_linked_list_empty(&impl->synced_data.pending_stream_list)) {
            /* No more work to do. Set this false while we're holding the lock. */
            impl->synced_data.is_outgoing_stream_task_active = false;

        } else {
            /* Front of pending_stream_list becomes new current_stream */
            current_stream = AWS_CONTAINER_OF(
                aws_linked_list_front(&impl->synced_data.pending_stream_list), struct aws_http_stream, node);

            /* Move contents from pending_stream_list to stream_list. */
            do {
                aws_linked_list_push_back(
                    &impl->el_thread_data.stream_list,
                    aws_linked_list_pop_front(&impl->synced_data.pending_stream_list));

            } while (!aws_linked_list_empty(&impl->synced_data.pending_stream_list));
        }

        err = aws_mutex_unlock(&impl->synced_data.lock);
        AWS_FATAL_ASSERT(!err);
    }

    impl->el_thread_data.current_outgoing_stream = current_stream;
    return current_stream;
}

static void s_outgoing_stream_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct h1_connection *impl = arg;
    struct aws_channel *channel = impl->base.channel_slot->channel;
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
     * OR until a stream has written all it can to the msg but still has more data to send.
     */
    struct aws_http_stream *outgoing_stream;
    while (true) {
        outgoing_stream = s_acquire_current_outgoing_stream(impl);
        if (!outgoing_stream) {
            break;
        }

        s_stream_write_outgoing_data(outgoing_stream, msg);

        if (outgoing_stream->outgoing_state != STREAM_OUTGOING_STATE_DONE) {
            break;
        }
    }

    err = aws_channel_slot_send_message(impl->base.channel_slot, msg, AWS_CHANNEL_DIR_WRITE);
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
    if (msg) {
        aws_mem_release(msg->allocator, msg);
    }

    aws_channel_shutdown(channel, aws_last_error());
}

/* Common new() logic for server & client */
static struct h1_connection *s_connection_new(struct aws_allocator *alloc) {
    struct h1_connection *impl = aws_mem_acquire(alloc, sizeof(struct h1_connection));
    if (!impl) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*impl);

    impl->base.vtable = &s_vtable;
    impl->base.alloc = alloc;
    impl->base.channel_handler.vtable = &s_vtable.channel_handler_vtable;
    impl->base.channel_handler.impl = impl;
    impl->base.http_version = AWS_HTTP_VERSION_1_1;

    aws_channel_task_init(&impl->outgoing_stream_task, s_outgoing_stream_task, impl);
    aws_linked_list_init(&impl->el_thread_data.stream_list);

    aws_mutex_init(&impl->synced_data.lock);
    aws_linked_list_init(&impl->synced_data.pending_stream_list);

    return impl;
}

struct aws_http_connection *aws_http_connection_new_http1_1_server(
    const struct aws_http_server_connection_impl_options *options) {

    struct h1_connection *impl = s_connection_new(options->alloc);
    if (!impl) {
        return NULL;
    }

    impl->base.initial_window_size = options->initial_window_size;
    impl->base.server_data = &impl->base.client_or_server_data.server;

    return &impl->base;
}

struct aws_http_connection *aws_http_connection_new_http1_1_client(
    const struct aws_http_client_connection_impl_options *options) {

    struct h1_connection *impl = s_connection_new(options->alloc);
    if (!impl) {
        return NULL;
    }

    impl->base.initial_window_size = options->initial_window_size;
    impl->base.user_data = options->user_data;
    impl->base.client_data = &impl->base.client_or_server_data.client;
    impl->base.client_data->user_cb_on_shutdown = options->user_cb_on_shutdown;

    return &impl->base;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct h1_connection *impl = handler->impl;

    // TODO: cleanup new data types

    aws_mem_release(impl->base.alloc, impl);
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

    struct h1_connection *impl = handler->impl;

    /* Invoke user shutdown callback */
    if (dir == AWS_CHANNEL_DIR_WRITE) {
        if (impl->base.server_data && impl->base.server_data->user_cb_on_shutdown) {
            impl->base.server_data->user_cb_on_shutdown(&impl->base, error_code, impl->base.user_data);
        } else if (impl->base.client_data && impl->base.client_data->user_cb_on_shutdown) {
            impl->base.client_data->user_cb_on_shutdown(&impl->base, error_code, impl->base.user_data);
        }
    }

    aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
    return AWS_OP_SUCCESS;
}

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    struct h1_connection *impl = handler->impl;
    return impl->base.initial_window_size;
}

static size_t s_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}
