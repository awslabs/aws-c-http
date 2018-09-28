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

struct aws_http_connection_data {
    struct aws_allocator *alloc;
    struct aws_channel_handler handler;
    struct aws_channel *channel;
    struct aws_channel_slot *slot;
    struct aws_byte_buf decoder_scratch_space;
    struct aws_http_decoder *decoder;
    size_t initial_window_size;
    size_t bytes_unreleased;
    void *user_data;
};

struct aws_http_server_connection {
    struct aws_http_connection_data data;
    struct aws_http_server_callbacks callbacks;
    struct aws_http_listener *listener;
};

struct aws_http_client_connection {
    struct aws_http_connection_data data;
    struct aws_http_client_callbacks callbacks;
};

struct aws_http_listener {
    struct aws_allocator *alloc;
    size_t initial_window_size;
    struct aws_http_server_callbacks callbacks;
    struct aws_socket *listener_socket;
    void *user_data;
};

struct aws_http_request {
    struct aws_http_client_connection *connection;
    enum aws_http_method method;
    const struct aws_byte_cursor *uri;
    bool chunked;
    struct aws_http_header *headers;
    int header_count;
    struct aws_http_request_callbacks callbacks;
    struct aws_task task;
    void *user_data;
};

struct aws_http_response {
    struct aws_http_server_connection *connection;
    enum aws_http_code code;
    bool chunked;
    struct aws_http_header *headers;
    int header_count;
    struct aws_http_response_callbacks callbacks;
    struct aws_task task;
    void *user_data;
};

static bool s_response_decoder_on_header(const struct aws_http_decoded_header *header, void *user_data) {
    struct aws_http_request *request = (struct aws_http_request *)user_data;
    struct aws_http_header h;
    h.name = header->name_data;
    h.value = header->value_data;
    request->callbacks.on_response_header(request, header->name, &h, request->user_data);
    return true;
}

static bool s_response_decoder_on_body(const struct aws_byte_cursor *data, bool last_segment, void *user_data) {
    struct aws_http_request *request = (struct aws_http_request *)user_data;
    bool can_release;
            request->callbacks.on_response_body_segment(request, data, last_segment, &can_release, request->user_data);
    if (!can_release) {
        request->connection->data.bytes_unreleased += data->len;
    }
    if (last_segment) {
        request->callbacks.on_request_completed(request, request->user_data);
    }
    return true;
}

static void s_response_decoder_on_version(enum aws_http_version version, void *user_data) {
    struct aws_http_request *request = (struct aws_http_request *)user_data;
    (void)request;
    (void)version;
    (void)user_data;
}

static void s_response_decoder_on_uri(struct aws_byte_cursor *uri, void *user_data) {
    struct aws_http_request *request = (struct aws_http_request *)user_data;
    (void)request;
    (void)uri;
    (void)user_data;
}

static void s_response_decoder_on_response_code(enum aws_http_code code, void *user_data) {
    struct aws_http_request *request = (struct aws_http_request *)user_data;
    request->callbacks.on_response(request, code, request->user_data);
}

static void s_response_decoder_on_method(enum aws_http_method method, void *user_data) {
    struct aws_http_request *request = (struct aws_http_request *)user_data;
    (void)request;
    (void)method;
    (void)user_data;
}

static bool s_request_decoder_on_header(const struct aws_http_decoded_header *header, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    struct aws_http_header h;
    h.name = header->name_data;
    h.value = header->value_data;
    connection->callbacks.on_request_header(connection, header->name, &h, connection->data.user_data);
    return true;
}

static bool s_request_decoder_on_body(const struct aws_byte_cursor *data, bool last_segment, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    bool can_release;
            connection->callbacks.on_request_body_segment(connection, data, last_segment, &can_release, connection->data.user_data);
    if (!can_release) {
        connection->data.bytes_unreleased += data->len;
    }
    return true;
}

static void s_request_decoder_on_version(enum aws_http_version version, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    (void)connection;
    (void)version;
    (void)user_data;
}

static void s_request_decoder_on_uri(struct aws_byte_cursor *uri, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    connection->callbacks.on_uri(connection, uri, connection->data.user_data);
}

static void s_request_decoder_on_response_code(enum aws_http_code code, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    (void)connection;
    (void)code;
}

static void s_request_decoder_on_method(enum aws_http_method method, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    connection->callbacks.on_request(connection, method, connection->data.user_data);
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

    /* Feed channel message to decoder, which reports significant events to user callbacks. */
    struct aws_http_connection_data *data = (struct aws_http_connection_data *)handler->impl;
    struct aws_http_decoder *decoder = data->decoder;

    struct aws_byte_cursor msg_data = aws_byte_cursor_from_buf(&message->message_data);
    size_t total = 0;
    while (total < msg_data.len) {
        size_t bytes_read;
        int ret = aws_http_decode(decoder, (const void *)msg_data.ptr, msg_data.len, &bytes_read);
        total += bytes_read;
        if (ret != AWS_OP_SUCCESS) {
            return ret;
        }
    }

    assert(total == message->message_data.len);

    /* Cleanup channel message. */
    if (data->bytes_unreleased == 0) {
        /* Only release headers, and body data the user did not specify as released. */
        aws_channel_slot_increment_read_window(slot, total - data->bytes_unreleased);
    }
    aws_channel_release_message_to_pool(slot->channel, message);

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
    struct aws_http_connection_data *data = (struct aws_http_connection_data *)handler->impl;
    return data->initial_window_size;
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

static int s_add_backchannel_slot_and_handler(struct aws_channel *channel, struct aws_http_connection_data *data) {

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    if (!slot) {
        return AWS_OP_ERR;
    }
    data->slot = slot;
    data->channel = slot->channel;

    aws_channel_slot_insert_end(channel, data->slot);
    aws_channel_slot_set_handler(data->slot, &data->handler);

    return AWS_OP_SUCCESS;
}

/* New client connection is ready to go. */
static int s_client_channel_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;

    if (error_code != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    int ret = s_add_backchannel_slot_and_handler(channel, &connection->data);
    connection->callbacks.on_connected(connection, connection->data.user_data);

    return ret;
}

/* Client channel was forcefully or otherwise shutdown. */
static int s_client_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)channel;

    if (error_code != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    connection->callbacks.on_disconnected(connection, connection->data.user_data);

    return AWS_OP_SUCCESS;
}

static struct aws_http_connection_data *s_connection_data_init(
    struct aws_http_connection_data *data,
    struct aws_allocator *alloc,
    size_t initial_window_size,
    bool true_for_client_false_for_server,
    void *user_data) {

    AWS_ZERO_STRUCT(*data);
    data->alloc = alloc;
    data->initial_window_size = initial_window_size;
    struct aws_http_decoder *decoder = NULL;

    /* Scratch space for the streaming decoder. */
    if (aws_byte_buf_init(alloc, &data->decoder_scratch_space, 1024) != AWS_OP_SUCCESS) {
        goto error_and_cleanup;
    }

    /* Setup channel handler. */
    struct aws_channel_handler handler;
    handler.vtable = s_channel_handler;
    handler.alloc = alloc;
    handler.impl = (void *)data;
    data->handler = handler;

    /* Create http streaming decoder. */
    struct aws_http_decoder_params params;
    params.alloc = alloc;
    params.scratch_space = data->decoder_scratch_space;
    params.true_for_request_false_for_response = true;
    params.user_data = (void *)data;
    if (true_for_client_false_for_server) {
        params.on_header = s_response_decoder_on_header;
        params.on_body = s_response_decoder_on_body;
        params.on_version = s_response_decoder_on_version;
        params.on_uri = s_response_decoder_on_uri;
        params.on_method = s_response_decoder_on_method;
        params.on_code = s_response_decoder_on_response_code;
    } else {
        params.on_header = s_request_decoder_on_header;
        params.on_body = s_request_decoder_on_body;
        params.on_version = s_request_decoder_on_version;
        params.on_uri = s_request_decoder_on_uri;
        params.on_method = s_request_decoder_on_method;
        params.on_code = s_request_decoder_on_response_code;
    }
    decoder = aws_http_decoder_new(&params);
    if (!decoder) {
        goto error_and_cleanup;
    }
    data->decoder = decoder;
    data->user_data = user_data;

    return data;

error_and_cleanup:
    if (decoder) {
        aws_http_decoder_destroy(decoder);
    }
    aws_byte_buf_clean_up(&data->decoder_scratch_space);
    aws_mem_release(alloc, data);
    return NULL;
}

static int s_on_incoming_channel(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;

    if (error_code != AWS_OP_SUCCESS) {
        return error_code;
    }

    struct aws_http_listener *listener = (struct aws_http_listener *)user_data;
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)aws_mem_acquire(
        listener->alloc, sizeof(struct aws_http_server_connection));
    if (!connection) {
        return AWS_OP_ERR;
    }

    if (s_connection_data_init(
            &connection->data, listener->alloc, listener->initial_window_size, false, (void *)listener->user_data) !=
        AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }
    s_add_backchannel_slot_and_handler(channel, &connection->data);
    connection->callbacks = listener->callbacks;
    connection->listener = listener;
    listener->callbacks.on_connection_created(connection, listener->user_data);

    return AWS_OP_SUCCESS;
}

static int s_on_shutdown_incoming_channel(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)channel;

    if (error_code != AWS_OP_SUCCESS) {
        return error_code;
    }

    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    struct aws_http_listener *listener = (struct aws_http_listener *)connection->data.user_data;
    listener->callbacks.on_connection_closed(connection, listener->user_data);

    return AWS_OP_SUCCESS;
}

int aws_http_client_connect(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_client_bootstrap *bootstrap,
    size_t initial_window_size,
    struct aws_http_client_callbacks *callbacks,
    void *user_data) {

    struct aws_http_client_connection *connection =
        (struct aws_http_client_connection *)aws_mem_acquire(alloc, sizeof(struct aws_http_client_connection));
    if (!connection) {
        return AWS_OP_ERR;
    }

    if (s_connection_data_init(&connection->data, alloc, initial_window_size, true, user_data) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }
    connection->callbacks = *callbacks;

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

    return AWS_OP_SUCCESS;

cleanup:
    /* TODO (randgaul): Implement proper cleanup. */
    aws_mem_release(alloc, connection);
    return AWS_OP_ERR;
}

void aws_http_client_connection_release_bytes(struct aws_http_client_connection *connection, size_t bytes) {
    aws_channel_handler_increment_read_window(&connection->data.handler, connection->data.slot, bytes);
}

/* TODO (randgaul): Implement this. */
void aws_http_client_connection_destroy(struct aws_http_client_connection *connection) {
    (void)connection;
}

struct aws_http_listener *aws_http_listener_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_server_bootstrap *bootstrap,
    size_t initial_window_size,
    struct aws_http_server_callbacks *callbacks,
    void *user_data) {

    struct aws_http_listener *listener =
        (struct aws_http_listener *)aws_mem_acquire(alloc, sizeof(struct aws_http_listener));
    if (!listener) {
        goto cleanup;
    }
    AWS_ZERO_STRUCT(*listener);

    listener->alloc = alloc;
    listener->initial_window_size = initial_window_size;
    listener->callbacks = *callbacks;
    listener->user_data = user_data;

    struct aws_socket *listener_socket;
    if (tls_options) {
        listener_socket = aws_server_bootstrap_add_tls_socket_listener(
            bootstrap,
            endpoint,
            socket_options,
            tls_options,
            s_on_incoming_channel,
            s_on_shutdown_incoming_channel,
            (void *)listener);
    } else {
        listener_socket = aws_server_bootstrap_add_socket_listener(
            bootstrap,
            endpoint,
            socket_options,
            s_on_incoming_channel,
            s_on_shutdown_incoming_channel,
            (void *)listener);
    }

    if (!listener_socket) {
        goto cleanup;
    }

    listener->listener_socket = listener_socket;

    return listener;

cleanup:
    /* TODO (randgaul): Implement this. */
    return NULL;
}

/* TODO (randgaul): Implement this. */
void aws_http_server_connection_destroy(struct aws_http_server_connection *connection) {
    (void)connection;
}

/* TODO (randgaul): Implement this. */
void aws_http_listener_destroy(struct aws_http_listener *listener) {
    (void)listener;
}

struct aws_http_request *aws_http_request_new(
    struct aws_http_client_connection *connection,
    enum aws_http_method method,
    const struct aws_byte_cursor *uri,
    bool chunked,
    struct aws_http_header *headers,
    int header_count,
    struct aws_http_request_callbacks *callbacks,
    void *user_data) {

    struct aws_http_request *request =
        (struct aws_http_request *)aws_mem_acquire(connection->data.alloc, sizeof(struct aws_http_request));
    if (!request) {
        return NULL;
    }

    request->connection = connection;
    request->method = method;
    request->uri = uri;
    request->chunked = chunked;
    request->headers = headers;
    request->header_count = header_count;
    request->callbacks = *callbacks;
    request->user_data = user_data;

    return request;
}

/* TODO (randgaul): What should this be? */
#define AWS_HTTP_MESSAGE_SIZE_HINT 1024

static int s_write_to_msg(
    struct aws_io_message **msg_ptr,
    struct aws_channel *channel,
    struct aws_channel_slot *slot,
    struct aws_byte_cursor *data) {

    struct aws_io_message *msg = *msg_ptr;
    int ret = aws_byte_buf_append(&msg->message_data, data);
    if (ret == AWS_ERROR_DEST_COPY_TOO_SMALL) {
        aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
        msg =
            aws_channel_acquire_message_from_pool(channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_HTTP_MESSAGE_SIZE_HINT);
        *msg_ptr = msg;
        /* TODO (randgaul): What about when AWS_HTTP_MESSAGE_SIZE_HINT is too small? Think about error handling. */
        return aws_byte_buf_append(&msg->message_data, data);
    }

    return AWS_OP_SUCCESS;
}

static inline void s_send_headers(
    struct aws_io_message **msg_ptr,
    struct aws_http_header *headers,
    int header_count,
    struct aws_channel *channel,
    struct aws_channel_slot *slot) {
    struct aws_byte_cursor colon_space = aws_byte_cursor_from_array(": ", 2);
    struct aws_byte_cursor newline = aws_byte_cursor_from_array("\r\n", 2);

    for (int i = 0; i < header_count; ++i) {
        struct aws_http_header *header = headers + i;
        s_write_to_msg(msg_ptr, channel, slot, &header->name);
        s_write_to_msg(msg_ptr, channel, slot, &colon_space);
        s_write_to_msg(msg_ptr, channel, slot, &header->value);
        s_write_to_msg(msg_ptr, channel, slot, &newline);
    }
    s_write_to_msg(msg_ptr, channel, slot, &newline);
}

static void s_send_request_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_request *request = (struct aws_http_request *)arg;
    struct aws_channel *channel = request->connection->data.channel;
    struct aws_channel_slot *slot = request->connection->data.slot;

    struct aws_io_message *msg =
        aws_channel_acquire_message_from_pool(channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_HTTP_MESSAGE_SIZE_HINT);

    const char *method_str = aws_http_method_to_str(request->method);
    struct aws_byte_cursor method = aws_byte_cursor_from_array(method_str, strlen(method_str));
    struct aws_byte_cursor uri = *request->uri;
    struct aws_byte_cursor version = aws_byte_cursor_from_array("HTTP/1.1 ", 9);
    struct aws_byte_cursor space = aws_byte_cursor_from_array(" ", 1);
    struct aws_byte_cursor newline = aws_byte_cursor_from_array("\r\n", 2);

    s_write_to_msg(&msg, channel, slot, &method);
    s_write_to_msg(&msg, channel, slot, &space);
    s_write_to_msg(&msg, channel, slot, &uri);
    s_write_to_msg(&msg, channel, slot, &space);
    s_write_to_msg(&msg, channel, slot, &version);
    s_write_to_msg(&msg, channel, slot, &newline);

    s_send_headers(&msg, request->headers, request->header_count, channel, slot);

    bool done = false;
    if (request->chunked) {
        while (!done) {
            struct aws_byte_cursor *segment;
            request->callbacks.on_write_body_segment(request, &segment, &done, request->user_data);

            char buf[128];
            unsigned len = (unsigned)segment->len;
            snprintf(buf, AWS_ARRAY_SIZE(buf), "%x", len);
            struct aws_byte_cursor hex_len = aws_byte_cursor_from_array(buf, AWS_ARRAY_SIZE(buf));

            s_write_to_msg(&msg, channel, slot, &hex_len);
            s_write_to_msg(&msg, channel, slot, &newline);
            s_write_to_msg(&msg, channel, slot, segment);
            s_write_to_msg(&msg, channel, slot, &newline);
        }
    } else {
        while (!done) {
            struct aws_byte_cursor *segment;
            request->callbacks.on_write_body_segment(request, &segment, &done, request->user_data);
            s_write_to_msg(&msg, channel, slot, segment);
        }
    }

    aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
}

int aws_http_request_send(struct aws_http_request *request) {
    aws_task_init(&request->task, s_send_request_task, (void *)request);

    struct aws_channel *channel = request->connection->data.channel;
    if (!aws_channel_thread_is_callers_thread(channel)) {
        aws_channel_schedule_task_now(channel, &request->task);
    } else {
        s_send_request_task(&request->task, (void *)request, AWS_TASK_STATUS_RUN_READY);
    }

    return AWS_OP_SUCCESS;
}

/* TODO (randgaul): Implement this. */
void aws_http_request_destroy(struct aws_http_request *request) {
    (void)request;
}

struct aws_http_response *aws_http_response_new(
    struct aws_http_server_connection *connection,
    enum aws_http_code code,
    bool chunked,
    struct aws_http_header *headers,
    int header_count,
    struct aws_http_response_callbacks *callbacks,
    void *user_data) {

    struct aws_http_response *response =
        (struct aws_http_response *)aws_mem_acquire(connection->data.alloc, sizeof(struct aws_http_response));
    if (!response) {
        return NULL;
    }

    response->connection = connection;
    response->code = code;
    response->chunked = chunked;
    response->headers = headers;
    response->header_count = header_count;
    response->callbacks = *callbacks;
    response->user_data = user_data;

    return response;
}

static void s_send_response_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_response *response = (struct aws_http_response *)arg;
    struct aws_channel *channel = response->connection->data.channel;
    struct aws_channel_slot *slot = response->connection->data.slot;

    struct aws_io_message *msg =
        aws_channel_acquire_message_from_pool(channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_HTTP_MESSAGE_SIZE_HINT);

    const char *code_str = aws_http_version_to_str(response->code);
    struct aws_byte_cursor code = aws_byte_cursor_from_array(code_str, strlen(code_str));
    struct aws_byte_cursor version = aws_byte_cursor_from_array("HTTP/1.1 ", 9);
    struct aws_byte_cursor space = aws_byte_cursor_from_array(" ", 1);
    char buf[128];
    snprintf(buf, 128, "%d", (int)response->code);
    struct aws_byte_cursor code_num = aws_byte_cursor_from_array(buf, strlen(buf));
    struct aws_byte_cursor newline = aws_byte_cursor_from_array("\r\n", 2);

    s_write_to_msg(&msg, channel, slot, &version);
    s_write_to_msg(&msg, channel, slot, &code_num);
    s_write_to_msg(&msg, channel, slot, &space);
    s_write_to_msg(&msg, channel, slot, &code);
    s_write_to_msg(&msg, channel, slot, &newline);

    s_send_headers(&msg, response->headers, response->header_count, channel, slot);

    bool done = false;
    if (response->chunked) {
        while (!done) {
            struct aws_byte_cursor *segment;
            response->callbacks.on_write_body_segment(response, &segment, &done, response->user_data);

            char buf[128];
            unsigned len = (unsigned)segment->len;
            snprintf(buf, AWS_ARRAY_SIZE(buf), "%x", len);
            struct aws_byte_cursor hex_len = aws_byte_cursor_from_array(buf, AWS_ARRAY_SIZE(buf));

            s_write_to_msg(&msg, channel, slot, &hex_len);
            s_write_to_msg(&msg, channel, slot, &newline);
            s_write_to_msg(&msg, channel, slot, segment);
            s_write_to_msg(&msg, channel, slot, &newline);
        }
    } else {
        while (!done) {
            struct aws_byte_cursor *segment;
            response->callbacks.on_write_body_segment(response, &segment, &done, response->user_data);
            s_write_to_msg(&msg, channel, slot, segment);
        }
    }

    aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);

    if (response->callbacks.on_response_sent) {
        response->callbacks.on_response_sent(response, response->user_data);
    }
}

int aws_http_response_send(struct aws_http_response *response) {
    aws_task_init(&response->task, s_send_response_task, (void *)response);

    struct aws_channel *channel = response->connection->data.channel;
    if (!aws_channel_thread_is_callers_thread(channel)) {
        aws_channel_schedule_task_now(channel, &response->task);
    } else {
        s_send_response_task(&response->task, (void *)response, AWS_TASK_STATUS_RUN_READY);
    }

    return AWS_OP_SUCCESS;
}

/* TODO (randgaul): Implement this. */
void aws_http_response_destroy(struct aws_http_response *response) {
    (void)response;
}
