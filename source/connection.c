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

#include <aws/common/byte_buf.h>

#include <aws/io/channel.h>
#include <aws/io/message_pool.h>

#include <aws/http/connection.h>
#include <aws/http/decode.h>

#include <stdio.h>

struct aws_http_connection {
    struct aws_http_connection_callbacks callbacks;
    struct aws_byte_buf decoder_scratch_space;
    struct aws_memory_pool message_pool;
    struct aws_channel_handler handler;
    struct aws_channel *channel;
    struct aws_channel_slot *slot;
    struct aws_http_decoder *decoder;
    size_t bytes_unreleased;
    struct aws_array_list backpressure_messages;
    struct aws_socket_endpoint *endpoint;
    struct aws_socket *listener;
    size_t initial_window_size;
    void *user_data;
};

struct aws_http_body_segment {
    struct aws_byte_cursor data;
    bool final_segment;
};

struct aws_http_header_batch {
    struct aws_array_list headers;
    bool final_headers;
};

struct aws_http_task_args {
    struct aws_http_connection *connection;
    struct aws_io_message *msg;
    bool chunked;
    struct aws_task task;
    void *user_data;
    aws_http_promise_fn *promise;
    union {
        enum aws_http_method method;
        const struct aws_byte_cursor *uri;
        enum aws_http_code code;
        struct aws_http_body_segment body_segment;
        struct aws_http_header_batch header_batch;
    } u;
};

struct aws_http_backpressure_message {
    struct aws_io_message *msg;
    size_t bytes_unreleased;
};

static bool s_decoder_on_header(const struct aws_http_decoded_header *header, void *user_data) {
    struct aws_http_connection *connection = (struct aws_http_connection *)user_data;
    struct aws_http_header h;
    h.name = header->name_data;
    h.value = header->value_data;
    connection->callbacks.on_header(&h, connection->user_data);
    return true;
}

static bool s_decoder_on_body(const struct aws_byte_cursor *data, bool last_segment, void *user_data) {
    struct aws_http_connection *connection = (struct aws_http_connection *)user_data;
    bool can_release;
    bool dont_terminate = connection->callbacks.on_body(data, last_segment, &can_release, connection->user_data);
    if (!can_release) {
        connection->bytes_unreleased += data->len;
    }
    return dont_terminate;
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)handler;
    (void)slot;
    (void)message;

    if (message->message_type != AWS_IO_MESSAGE_APPLICATION_DATA || message->message_data.len < 1) {
        return AWS_OP_ERR;
    }

    /* Feed channel message to decoder, which reports signifant events to user callbacks. */
    struct aws_http_connection *connection = (struct aws_http_connection *)handler->impl;
    struct aws_http_decoder *decoder = connection->decoder;

    struct aws_byte_cursor data = aws_byte_cursor_from_buf(&message->message_data);
    size_t total = 0;
    while (total < data.len) {
        size_t bytes_read;
        int ret = aws_http_decode(decoder, (const void *)data.ptr, data.len, &bytes_read);
        total += bytes_read;
        if (ret != AWS_OP_SUCCESS) {
            return ret;
        }
    }

    /* Cleanup channel message. */
    if (connection->bytes_unreleased == 0) {
        aws_channel_slot_increment_read_window(slot, message->message_data.len);
        aws_channel_release_message_to_pool(slot->channel, message);
    } else {
        /* Queue message up until the user calls `aws_http_release_body_data`. */
        struct aws_http_backpressure_message backpressure_message;
        backpressure_message.msg = message;
        backpressure_message.bytes_unreleased = connection->bytes_unreleased;
        aws_array_list_push_back(&connection->backpressure_messages, &backpressure_message);
    }

    connection->bytes_unreleased = 0;

    return AWS_OP_SUCCESS;
}

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)handler;
    (void)slot;
    (void)message;
    assert(false); /* Should not be called until websocket stuff comes along. */
    return AWS_OP_ERR;
}

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {
    (void)handler;
    (void)slot;
    (void)size;
    assert(false); /* Should not be called until websocket stuff comes along. */
    return AWS_OP_ERR;
}

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    struct aws_http_connection *connection = (struct aws_http_connection *)handler->impl;
    return connection->initial_window_size;
}

/* TODO (randgaul): Implement this. */
static void s_handler_destroy(struct aws_channel_handler *handler) {
    (void)handler;
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {
    (void)handler;
    (void)slot;
    (void)dir;
    (void)error_code;
    (void)free_scarce_resources_immediately;
    return AWS_OP_SUCCESS;
}

static struct aws_channel_handler_vtable s_channel_handler = {s_handler_process_read_message,
                                                              s_handler_process_write_message,
                                                              s_handler_increment_read_window,
                                                              s_handler_shutdown,
                                                              s_handler_initial_window_size,
                                                              s_handler_destroy};

static int s_channel_setup(int error_code, struct aws_channel *channel, void *user_data) {
    if (error_code != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    struct aws_http_connection *connection = (struct aws_http_connection *)user_data;

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    if (!slot) {
        return AWS_OP_ERR;
    }
    connection->slot = slot;
    connection->channel = slot->channel;

    aws_channel_slot_insert_end(channel, connection->slot);
    aws_channel_slot_set_handler(connection->slot, &connection->handler);

    return AWS_OP_SUCCESS;
}

static int s_client_channel_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    return s_channel_setup(error_code, channel, user_data);
}

/* TODO (randgaul): Implement this. */
static int s_client_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

static int s_server_channel_setup(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    return s_channel_setup(error_code, channel, user_data);
}

/* TODO (randgaul): Implement this. */
static int s_server_channel_shutdown(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

static struct aws_http_connection *s_connection_new(
    struct aws_allocator *alloc,
    struct aws_http_connection_callbacks *user_callbacks,
    size_t initial_window_size,
    void *user_data) {
    struct aws_http_connection *connection =
        (struct aws_http_connection *)aws_mem_acquire(alloc, sizeof(struct aws_http_connection));
    if (!connection) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*connection);
    connection->callbacks = *user_callbacks;
    connection->initial_window_size = initial_window_size;
    struct aws_http_decoder *decoder = NULL;

    /* Scratch space for the streaming decoder. */
    if (aws_byte_buf_init(alloc, &connection->decoder_scratch_space, 1024) != AWS_OP_SUCCESS) {
        goto error_and_cleanup;
    }

    if (aws_memory_pool_init(&connection->message_pool, alloc, 32, sizeof(struct aws_http_task_args)) !=
        AWS_OP_SUCCESS) {
        goto error_and_cleanup;
    }

    if (aws_array_list_init_dynamic(
            &connection->backpressure_messages, alloc, 16, sizeof(struct aws_http_backpressure_message)) !=
        AWS_OP_SUCCESS) {
        goto error_and_cleanup;
    }

    /* Setup channel handler. */
    struct aws_channel_handler handler;
    handler.vtable = s_channel_handler;
    handler.alloc = alloc;
    handler.impl = (void *)connection;
    connection->handler = handler;

    /* Create http streaming decoder. */
    struct aws_http_decoder_params params;
    params.alloc = alloc;
    params.scratch_space = connection->decoder_scratch_space;
    params.on_header = s_decoder_on_header;
    params.on_body = s_decoder_on_body;
    params.true_for_request_false_for_response = true;
    params.user_data = (void *)connection;
    decoder = aws_http_decoder_new(&params);
    if (!decoder) {
        goto error_and_cleanup;
    }
    connection->decoder = decoder;
    connection->user_data = user_data;
    connection->listener = NULL;

    return connection;

error_and_cleanup:
    if (decoder) {
        aws_http_decoder_destroy(decoder);
    }
    aws_byte_buf_clean_up(&connection->decoder_scratch_space);
    aws_memory_pool_clean_up(&connection->message_pool);
    aws_array_list_clean_up(&connection->backpressure_messages);
    aws_mem_release(alloc, connection);
    return NULL;
}

struct aws_http_connection *aws_http_client_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_client_bootstrap *bootstrap,
    struct aws_http_connection_callbacks *user_callbacks,
    size_t initial_window_size,
    void *user_data) {

    struct aws_http_connection *connection = s_connection_new(alloc, user_callbacks, initial_window_size, user_data);
    if (!connection) {
        return NULL;
    }

    if (tls_options) {
        if (aws_client_bootstrap_new_tls_socket_channel(
                bootstrap,
                endpoint,
                socket_options,
                tls_options,
                s_client_channel_setup,
                s_client_channel_shutdown,
                (void *)connection) != AWS_OP_SUCCESS) {
            goto cleanup;
        }
    } else {
        if (aws_client_bootstrap_new_socket_channel(
                bootstrap,
                endpoint,
                socket_options,
                s_client_channel_setup,
                s_client_channel_shutdown,
                (void *)connection) != AWS_OP_SUCCESS) {
            goto cleanup;
        }
    }

    return connection;

cleanup:
    aws_byte_buf_clean_up(&connection->decoder_scratch_space);
    aws_mem_release(alloc, connection);
    return NULL;
}

struct aws_http_connection *aws_http_server_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_server_bootstrap *bootstrap,
    struct aws_http_connection_callbacks *user_callbacks,
    size_t initial_window_size,
    void *user_data) {

    struct aws_http_connection *connection = s_connection_new(alloc, user_callbacks, initial_window_size, user_data);
    if (!connection) {
        return NULL;
    }

    struct aws_socket *listener;
    if (tls_options) {
        listener = aws_server_bootstrap_add_tls_socket_listener(
            bootstrap,
            endpoint,
            socket_options,
            tls_options,
            s_server_channel_setup,
            s_server_channel_shutdown,
            (void *)connection);
    } else {
        listener = aws_server_bootstrap_add_socket_listener(
            bootstrap, endpoint, socket_options, s_server_channel_setup, s_server_channel_shutdown, (void *)connection);
    }

    if (!listener) {
        goto cleanup;
    }
    connection->listener = listener;

    return connection;

cleanup:
    aws_byte_buf_clean_up(&connection->decoder_scratch_space);
    aws_memory_pool_clean_up(&connection->message_pool);
    aws_mem_release(alloc, connection);
    return NULL;
}

/* TODO (randgaul): Implement this. */
void aws_http_connection_destroy(struct aws_http_connection *connection) {
    (void)connection;
}

/* TODO (randgaul): What should this be? */
#define AWS_HTTP_MESSAGE_SIZE_HINT 1024

static int s_write_to_msg(struct aws_http_task_args *args, struct aws_byte_cursor *data) {
    struct aws_http_connection *connection = args->connection;
    struct aws_io_message *msg = args->msg;
    int ret = aws_byte_buf_append(&msg->message_data, data);
    if (ret == AWS_ERROR_DEST_COPY_TOO_SMALL) {
        aws_channel_slot_send_message(connection->slot, msg, AWS_CHANNEL_DIR_WRITE);
        msg = aws_channel_acquire_message_from_pool(
            connection->channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_HTTP_MESSAGE_SIZE_HINT);
        args->msg = msg;
        ret = aws_byte_buf_append(&msg->message_data, data);
        if (ret != AWS_OP_SUCCESS) {
            /* TODO (randgaul): Figure out what to do here. */
            return ret;
        }
        return AWS_OP_SUCCESS;
    } else {
        /* TODO (randgaul): Figure out what to do here. */
        return ret;
    }
}

static void s_send_request_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_task_args *args = (struct aws_http_task_args *)arg;
    struct aws_http_connection *connection = args->connection;

    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        connection->channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_HTTP_MESSAGE_SIZE_HINT);
    args->msg = msg;

    const char *method_str = aws_http_method_to_str(args->u.method);
    struct aws_byte_cursor method = aws_byte_cursor_from_array(method_str, strlen(method_str));
    s_write_to_msg(args, &method);
}

static void s_send_response_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_task_args *args = (struct aws_http_task_args *)arg;
    struct aws_http_connection *connection = args->connection;

    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        connection->channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_HTTP_MESSAGE_SIZE_HINT);
    args->msg = msg;

    const char *code_str = aws_http_version_to_str(args->u.code);
    struct aws_byte_cursor code = aws_byte_cursor_from_array(code_str, strlen(code_str));
    s_write_to_msg(args, &code);
}

static void s_send_uri_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_task_args *args = (struct aws_http_task_args *)arg;
    struct aws_byte_cursor *uri = (struct aws_byte_cursor *)args->u.uri;
    s_write_to_msg(args, uri);
    args->promise(args->user_data);
}

static void s_send_headers_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_task_args *args = (struct aws_http_task_args *)arg;
    struct aws_http_header *headers = (struct aws_http_header *)args->u.header_batch.headers.data;
    int header_count = (int)(args->u.header_batch.headers.length / args->u.header_batch.headers.item_size);
    struct aws_byte_cursor colon = aws_byte_cursor_from_array(": ", 2);
    struct aws_byte_cursor newline = aws_byte_cursor_from_array("\r\n", 2);
    for (int i = 0; i < header_count; ++i) {
        struct aws_byte_cursor name = headers->name;
        struct aws_byte_cursor value = headers->value;
        s_write_to_msg(args, &name);
        s_write_to_msg(args, &colon);
        s_write_to_msg(args, &value);
        s_write_to_msg(args, &newline);
    }

    if (args->u.header_batch.final_headers) {
        s_write_to_msg(args, &newline);
    }

    args->promise(args->user_data);
}

static void s_send_body_segment_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_task_args *args = (struct aws_http_task_args *)arg;
    struct aws_byte_cursor data = args->u.body_segment.data;
    bool final_segment = args->u.body_segment.final_segment;
    struct aws_byte_cursor newline = aws_byte_cursor_from_array("\r\n", 2);
    if (args->chunked) {
        char buf[128];
        unsigned len = (unsigned)data.len;
        snprintf(buf, AWS_ARRAY_SIZE(buf), "%x", len);
        struct aws_byte_cursor hex_len = aws_byte_cursor_from_array(buf, AWS_ARRAY_SIZE(buf));
        s_write_to_msg(args, &hex_len);
        s_write_to_msg(args, &newline);
        s_write_to_msg(args, &data);
        s_write_to_msg(args, &newline);
    } else {
        s_write_to_msg(args, &data);
    }

    if (final_segment) {
        aws_http_flush(args->connection);
    }

    args->promise(args->user_data);
}

int aws_http_send_request(struct aws_http_connection *connection, enum aws_http_method method, bool chunked) {
    struct aws_http_task_args *args = (struct aws_http_task_args *)aws_memory_pool_acquire(&connection->message_pool);
    if (!args) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(args);
    args->connection = connection;
    args->chunked = chunked;
    args->u.method = method;
    args->user_data = connection->user_data;
    aws_task_init(&args->task, s_send_request_task, (void *)args);

    if (!aws_channel_thread_is_callers_thread(connection->channel)) {
        aws_channel_schedule_task_now(connection->channel, &args->task);
    } else {
        s_send_request_task(&args->task, (void *)args, AWS_TASK_STATUS_RUN_READY);
    }

    return AWS_OP_SUCCESS;
}

int aws_http_send_response(struct aws_http_connection *connection, enum aws_http_code code, bool chunked) {
    struct aws_http_task_args *args = (struct aws_http_task_args *)aws_memory_pool_acquire(&connection->message_pool);
    if (!args) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*args);
    args->connection = connection;
    args->chunked = chunked;
    args->u.code = code;
    args->user_data = connection->user_data;
    aws_task_init(&args->task, s_send_response_task, (void *)args);

    if (!aws_channel_thread_is_callers_thread(connection->channel)) {
        aws_channel_schedule_task_now(connection->channel, &args->task);
    } else {
        s_send_response_task(&args->task, (void *)args, AWS_TASK_STATUS_RUN_READY);
    }

    return AWS_OP_SUCCESS;
}

int aws_http_send_uri(
    struct aws_http_connection *connection,
    const struct aws_byte_cursor *uri,
    aws_http_promise_fn *on_uri_written) {
    struct aws_http_task_args *args = (struct aws_http_task_args *)aws_memory_pool_acquire(&connection->message_pool);
    if (!args) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*args);
    args->connection = connection;
    args->u.uri = uri;
    args->user_data = connection->user_data;
    args->promise = on_uri_written;
    aws_task_init(&args->task, s_send_uri_task, (void *)args);

    if (!aws_channel_thread_is_callers_thread(connection->channel)) {
        aws_channel_schedule_task_now(connection->channel, &args->task);
    } else {
        s_send_uri_task(&args->task, (void *)args, AWS_TASK_STATUS_RUN_READY);
    }

    return AWS_OP_SUCCESS;
}

int aws_http_send_headers(
    struct aws_http_connection *connection,
    const struct aws_http_header *headers,
    int header_count,
    bool final_headers,
    aws_http_promise_fn *on_headers_written) {
    struct aws_http_task_args *args = (struct aws_http_task_args *)aws_memory_pool_acquire(&connection->message_pool);
    if (!args) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*args);
    args->connection = connection;
    args->user_data = connection->user_data;
    args->promise = on_headers_written;
    aws_array_list_init_static(
        &args->u.header_batch.headers, (void *)headers, header_count, sizeof(struct aws_http_header));
    args->u.header_batch.final_headers = final_headers;
    aws_task_init(&args->task, s_send_headers_task, (void *)args);

    if (!aws_channel_thread_is_callers_thread(connection->channel)) {
        aws_channel_schedule_task_now(connection->channel, &args->task);
    } else {
        s_send_headers_task(&args->task, (void *)args, AWS_TASK_STATUS_RUN_READY);
    }

    return AWS_OP_SUCCESS;
}

int aws_http_send_body_segment(
    struct aws_http_connection *connection,
    struct aws_byte_cursor *segment,
    bool final_segment,
    aws_http_promise_fn *on_segment_written) {
    struct aws_http_task_args *args = (struct aws_http_task_args *)aws_memory_pool_acquire(&connection->message_pool);
    if (!args) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*args);
    args->connection = connection;
    args->user_data = connection->user_data;
    args->promise = on_segment_written;
    args->u.body_segment.data = *segment;
    args->u.body_segment.final_segment = final_segment;
    aws_task_init(&args->task, s_send_body_segment_task, (void *)args);

    if (!aws_channel_thread_is_callers_thread(connection->channel)) {
        aws_channel_schedule_task_now(connection->channel, &args->task);
    } else {
        s_send_body_segment_task(&args->task, (void *)args, AWS_TASK_STATUS_RUN_READY);
    }

    return AWS_OP_SUCCESS;
}

int aws_http_release_body_data(struct aws_http_connection *connection, size_t bytes) {
    while (bytes) {
        if (aws_array_list_length(&connection->backpressure_messages)) {
            struct aws_http_backpressure_message msg;
            aws_array_list_front(&connection->backpressure_messages, &msg);

            if (msg.bytes_unreleased < bytes) {
                bytes -= msg.bytes_unreleased;
                aws_channel_slot_increment_read_window(connection->slot, msg.msg->message_data.len);
                aws_channel_release_message_to_pool(connection->slot->channel, msg.msg);
                aws_array_list_pop_front(&connection->backpressure_messages);
            } else {
                msg.bytes_unreleased -= bytes;
                aws_array_list_set_at(&connection->backpressure_messages, &msg, 0);
            }
        } else {
            return aws_raise_error(AWS_ERROR_HTTP_NO_BODY_DATA_BUFFERED);
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_http_flush(struct aws_http_connection *connection) {
    (void)connection;
    return AWS_OP_SUCCESS;
}
