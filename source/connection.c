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

#include <aws/http/connection.h>
#include <aws/http/decode.h>

struct aws_http_connection {
    struct aws_byte_buf scratch_space;
    struct aws_channel_handler handler;
    struct aws_channel_slot *slot;
    struct aws_http_decoder *decoder;
    aws_http_on_response_fn *on_response;
    aws_http_on_header_fn *on_header;
    aws_http_on_body_fn *on_body;
    struct aws_socket_endpoint *endpoint;
    struct aws_socket *listener;
    void *user_data;
};

bool s_decoder_on_header(const struct aws_http_header *header, void *user_data) {
    struct aws_http_connection *connection = (struct aws_http_connection *)user_data;
    return connection->on_header(header->name, &header->name_data, &header->value_data, connection->user_data);
}

bool s_decoder_on_body(struct aws_byte_cursor data, bool finished, void *user_data) {
    struct aws_http_connection *connection = (struct aws_http_connection *)user_data;
    return connection->on_body(data, finished, connection->user_data);
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
    int ret;
    size_t total = 0;
    while (total < data.len) {
        size_t bytes_read;
        ret = aws_http_decode(decoder, (const void *)data.ptr, data.len, &bytes_read);
        total += bytes_read;
        if (ret != AWS_OP_SUCCESS) {
            /* TODO (randgaul): Figure out what to do here on decode error. */
            break;
        }
    }

    /* Cleanup channel message. */
    aws_channel_slot_increment_read_window(slot, message->message_data.len);
    if (ret == AWS_OP_SUCCESS) {
        aws_channel_release_message_to_pool(slot->channel, message);
    }

    return AWS_OP_SUCCESS;
}

int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)handler;
    (void)slot;
    (void)message;
    return AWS_OP_SUCCESS;
}

int s_handler_increment_read_window(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    (void)handler;
    (void)slot;
    (void)size;
    return AWS_OP_SUCCESS;
}

size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;
    return SIZE_MAX;
}

void s_handler_destroy(struct aws_channel_handler *handler) {
    (void)handler;
}

int s_handler_shutdown(
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

struct aws_channel_handler_vtable s_channel_handler = {s_handler_process_read_message,
                                                       s_handler_process_write_message,
                                                       s_handler_increment_read_window,
                                                       s_handler_shutdown,
                                                       s_handler_initial_window_size,
                                                       s_handler_destroy};

int s_client_channel_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;

    struct aws_http_connection *connection = (struct aws_http_connection *)user_data;

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    if (!slot) {
        /* TODO (randgaul): Report error somehow. */
        return AWS_OP_ERR;
    }
    connection->slot = slot;

    aws_channel_slot_insert_end(channel, connection->slot);
    aws_channel_slot_set_handler(connection->slot, &connection->handler);

    return AWS_OP_SUCCESS;
}

int s_client_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;
    return 0;
}

int s_server_channel_setup(
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

int s_server_channel_shutdown(
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
    aws_http_on_header_fn *on_header,
    aws_http_on_body_fn *on_body,
    void *user_data) {
    struct aws_http_connection *connection =
        (struct aws_http_connection *)aws_mem_acquire(alloc, sizeof(struct aws_http_connection));
    if (!connection) {
        return NULL;
    }

    connection->on_header = on_header;
    connection->on_body = on_body;

    /* Scratch space for the streaming decoder. */
    if (aws_byte_buf_init(alloc, &connection->scratch_space, 1024) != AWS_OP_SUCCESS) {
        return NULL;
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
    params.scratch_space = connection->scratch_space;
    params.on_header = NULL;
    params.on_body = NULL;
    params.true_for_request_false_for_response = true;
    params.user_data = (void *)connection;
    struct aws_http_decoder *decoder = aws_http_decoder_new(&params);
    if (!decoder) {
        aws_byte_buf_clean_up(&connection->scratch_space);
        return NULL;
    }
    connection->decoder = decoder;
    connection->user_data = user_data;
    connection->listener = NULL;

    return connection;
}

struct aws_http_connection *aws_http_client_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_client_bootstrap *bootstrap,
    aws_http_on_header_fn *on_header,
    aws_http_on_body_fn *on_body,
    void *user_data) {

    struct aws_http_connection *connection = s_connection_new(alloc, on_header, on_body, user_data);
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
    aws_byte_buf_clean_up(&connection->scratch_space);
    aws_mem_release(alloc, connection);
    return NULL;
}

struct aws_http_connection *aws_http_server_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_server_bootstrap *bootstrap,
    aws_http_on_header_fn *on_header,
    aws_http_on_body_fn *on_body,
    void *user_data) {

    struct aws_http_connection *connection = s_connection_new(alloc, on_header, on_body, user_data);
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
    aws_byte_buf_clean_up(&connection->scratch_space);
    aws_mem_release(alloc, connection);
    return NULL;
}

void aws_http_connection_destroy(struct aws_http_connection *connection) {
    (void)connection;
}
