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
#include <aws/io/channel_bootstrap.h>
#include <aws/io/message_pool.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/http/connection.h>
#include <aws/http/decode.h>
#include <aws/http/queue.h>

#include <stdio.h>

struct aws_coroutine {
    int line;
};

#define AWS_COROUTINE_START(c)                                                                                         \
    do {                                                                                                               \
        struct aws_coroutine *__co = (c);                                                                              \
        switch (__co->line) {                                                                                          \
            case 0:

#define AWS_COROUTINE_CASE()                                                                                           \
    __co->line = __LINE__;                                                                                             \
    case __LINE__:;                                                                                                    \
        do {

#define AWS_COROUTINE_CASE_END()                                                                                       \
    }                                                                                                                  \
    while (0)

#define AWS_COROUTINE_YIELD() goto __end

#define AWS_COROUTINE_END()                                                                                            \
    default:;                                                                                                          \
        }                                                                                                              \
    __end:;                                                                                                            \
        }                                                                                                              \
        while (0)

#define AWS_COROUTINE_INIT(co)                                                                                         \
    do {                                                                                                               \
        (co)->line = 0;                                                                                                \
    } while (0)

struct aws_http_connection_data {
    struct aws_allocator *alloc;
    struct aws_channel_handler handler;
    struct aws_channel *channel;
    struct aws_channel_slot *slot;
    struct aws_byte_buf decoder_scratch_space;
    struct aws_http_decoder *decoder;
    size_t initial_window_size;
    size_t bytes_unreleased;
    bool is_server;
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
    struct aws_http_request *request;
    struct aws_queue request_queue;
};

struct aws_http_listener {
    struct aws_allocator *alloc;
    struct aws_server_bootstrap *bootstrap;
    size_t initial_window_size;
    struct aws_http_server_callbacks callbacks;
    struct aws_socket *listener_socket;
    void *user_data;
};

struct aws_http_request {
    struct aws_allocator *alloc;
    struct aws_http_client_connection *connection;
    enum aws_http_method method;
    const struct aws_byte_cursor *uri;
    bool chunked;
    struct aws_http_header *headers;
    int header_count;
    struct aws_http_request_callbacks callbacks;
    struct aws_task task;
    struct aws_coroutine co;
    bool has_body;
    int header_index;
    char segment_len_buffer[128];
    struct aws_byte_cursor hex_len;
    struct aws_byte_cursor segment;
    bool has_cached_segment;
    struct aws_byte_buf cached_segment;
    bool last_segment;
    volatile bool expect_100_continue;
    bool got_100_continue;
    void *user_data;
};

struct aws_http_response {
    struct aws_allocator *alloc;
    struct aws_http_server_connection *connection;
    enum aws_http_code code;
    bool chunked;
    struct aws_http_header *headers;
    int header_count;
    struct aws_http_response_callbacks callbacks;
    struct aws_task task;
    struct aws_coroutine co;
    char code_buffer[128];
    char segment_len_buffer[128];
    struct aws_byte_cursor hex_len;
    bool has_body;
    int header_index;
    struct aws_byte_cursor segment;
    bool has_cached_segment;
    struct aws_byte_buf cached_segment;
    bool last_segment;
    void *user_data;
};

static struct aws_http_decoder_vtable s_get_client_decoder_vtable(void);
static struct aws_http_decoder_vtable s_get_client_decoder_vtable_100_continue(void);
static struct aws_http_decoder_vtable s_get_server_decoder_vtable(void);

static bool s_response_decoder_stub(const struct aws_http_decoded_header *header, void *user_data) {
    (void)header;
    (void)user_data;
    return true;
}

static bool s_response_decoder_on_header(const struct aws_http_decoded_header *header, void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;

    struct aws_http_header h;
    h.name = header->name_data;
    h.value = header->value_data;
    request->callbacks.on_response_header(request, header->name, &h, request->user_data);
    return true;
}

static void s_complete_request(struct aws_http_request *request) {
    struct aws_http_client_connection *connection = request->connection;
    request->callbacks.on_request_completed(request, request->user_data);
    if (!aws_queue_is_empty(&connection->request_queue)) {
        aws_queue_pull(&connection->request_queue, &connection->request, sizeof(struct aws_request *));
    } else {
        connection->request = NULL;
    }
    aws_http_decoder_reset(connection->data.decoder, NULL);
}

static bool s_response_decoder_on_body_stub(const struct aws_byte_cursor *data, bool last_segment, void *user_data) {
    (void)data;
    (void)last_segment;
    (void)user_data;
    return true;
}

static bool s_response_decoder_on_body(const struct aws_byte_cursor *data, bool last_segment, void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;
    bool can_release;
    request->callbacks.on_response_body_segment(request, data, last_segment, &can_release, request->user_data);
    if (!can_release) {
        request->connection->data.bytes_unreleased += data->len;
    }
    return true;
}

static void s_response_decoder_on_version_stub(enum aws_http_version version, void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;
    (void)request;
    (void)version;
    (void)user_data;
}

static void s_response_decoder_on_uri_stub(struct aws_byte_cursor *uri, void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;
    (void)request;
    (void)uri;
    (void)user_data;
}

static void s_response_decoder_on_response_code(enum aws_http_code code, void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;
    request->callbacks.on_response(request, code, request->user_data);
}

static void s_response_decoder_on_response_code_100_continue(enum aws_http_code code, void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;
    if (code == AWS_HTTP_CODE_CONTINUE) {
        request->got_100_continue = true;
    }
}

static void s_response_decoder_on_method_stub(enum aws_http_method method, void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;
    (void)request;
    (void)method;
    (void)user_data;
}

static void s_response_decoder_on_done_100_continue(void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;

    /* Got continue, reschedule task to send the rest of the body data. */
    if (request->got_100_continue) {
        request->expect_100_continue = false;
        request->got_100_continue = false;
        struct aws_http_decoder_vtable vtable = s_get_client_decoder_vtable();
        aws_http_decoder_set_vtable(connection->data.decoder, &vtable);
        aws_channel_schedule_task_now(connection->data.channel, &request->task);
        aws_http_decoder_reset(connection->data.decoder, NULL);
    } else {
        s_complete_request(request);
    }
}

static void s_response_decoder_on_done(void *user_data) {
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;
    struct aws_http_request *request = connection->request;
    s_complete_request(request);
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
    connection->callbacks.on_request_body_segment(
        connection, data, last_segment, &can_release, connection->data.user_data);
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

static void s_request_decoder_on_done(void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    connection->callbacks.on_request_end(connection->data.user_data);
    aws_http_decoder_reset(connection->data.decoder, NULL);
}

static struct aws_http_decoder_vtable s_get_client_decoder_vtable(void) {
    struct aws_http_decoder_vtable vtable;
    vtable.on_header = s_response_decoder_on_header;
    vtable.on_body = s_response_decoder_on_body;
    vtable.on_version = s_response_decoder_on_version_stub;
    vtable.on_uri = s_response_decoder_on_uri_stub;
    vtable.on_method = s_response_decoder_on_method_stub;
    vtable.on_code = s_response_decoder_on_response_code;
    vtable.on_done = s_response_decoder_on_done;
    return vtable;
}

static struct aws_http_decoder_vtable s_get_client_decoder_vtable_100_continue(void) {
    struct aws_http_decoder_vtable vtable;
    vtable.on_header = s_response_decoder_stub;
    vtable.on_body = s_response_decoder_on_body_stub;
    vtable.on_version = s_response_decoder_on_version_stub;
    vtable.on_uri = s_response_decoder_on_uri_stub;
    vtable.on_method = s_response_decoder_on_method_stub;
    vtable.on_code = s_response_decoder_on_response_code_100_continue;
    vtable.on_done = s_response_decoder_on_done_100_continue;
    return vtable;
}

static struct aws_http_decoder_vtable s_get_server_decoder_vtable(void) {
    struct aws_http_decoder_vtable vtable;
    vtable.on_header = s_request_decoder_on_header;
    vtable.on_body = s_request_decoder_on_body;
    vtable.on_version = s_request_decoder_on_version;
    vtable.on_uri = s_request_decoder_on_uri;
    vtable.on_method = s_request_decoder_on_method;
    vtable.on_code = s_request_decoder_on_response_code;
    vtable.on_done = s_request_decoder_on_done;
    return vtable;
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
    int ret = AWS_OP_SUCCESS;
    while (total < msg_data.len) {
        size_t bytes_read;
        ret = aws_http_decode(decoder, (const void *)msg_data.ptr, msg_data.len, &bytes_read);
        total += bytes_read;

        if (ret != AWS_OP_SUCCESS) {
            /* Any additional error handling needed here? Returning AWS_OP_ERR from
             * this function doesn't seem to do much. */
            break;
        }
    }

    /* Cleanup channel message. */
    if (data->bytes_unreleased == 0) {
        /* Only release headers, and body data the user did not specify as released. */
        aws_channel_slot_increment_read_window(slot, total - data->bytes_unreleased);
    }
    aws_channel_release_message_to_pool(slot->channel, message);

    return ret;
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

static void s_connection_data_clean_up(struct aws_http_connection_data *data) {
    aws_http_decoder_destroy(data->decoder);
    aws_byte_buf_clean_up(&data->decoder_scratch_space);
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_http_connection_data *data = (struct aws_http_connection_data *)handler->impl;
    s_connection_data_clean_up(data);

    if (data->is_server) {
        struct aws_http_server_connection *connection = (struct aws_http_server_connection *)data;
        aws_mem_release(connection->data.alloc, connection);
    } else {
        struct aws_http_client_connection *connection = (struct aws_http_client_connection *)data;
        aws_queue_clean_up(&connection->request_queue);
        aws_mem_release(connection->data.alloc, connection);
    }
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {
    struct aws_http_connection_data *data = (struct aws_http_connection_data *)handler->impl;

    if (dir == AWS_CHANNEL_DIR_WRITE) {
        if (data->is_server) {
            struct aws_http_server_connection *connection = (struct aws_http_server_connection *)data;
            connection->callbacks.on_connection_closed(connection, connection->listener->user_data);
        } else {
            struct aws_http_client_connection *connection = (struct aws_http_client_connection *)data;
            connection->callbacks.on_disconnected(connection, connection->data.user_data);
        }
    }
    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
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

static int s_client_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)channel;
    (void)user_data;

    if (error_code != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_connection_data_init(
    struct aws_http_connection_data *data,
    struct aws_allocator *alloc,
    size_t initial_window_size,
    bool true_for_client_false_for_server,
    void *user_data) {

    AWS_ZERO_STRUCT(*data);
    data->alloc = alloc;
    data->initial_window_size = initial_window_size;
    data->is_server = !true_for_client_false_for_server;
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
    params.true_for_request_false_for_response = !true_for_client_false_for_server;
    params.user_data = (void *)data;
    if (true_for_client_false_for_server) {
        params.vtable = s_get_client_decoder_vtable();
    } else {
        params.vtable = s_get_server_decoder_vtable();
    }
    decoder = aws_http_decoder_new(&params);
    if (!decoder) {
        goto error_and_cleanup;
    }
    data->decoder = decoder;
    data->user_data = user_data;

    return AWS_OP_SUCCESS;

error_and_cleanup:
    if (decoder) {
        aws_http_decoder_destroy(decoder);
    }
    aws_byte_buf_clean_up(&data->decoder_scratch_space);
    return AWS_OP_ERR;
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
    (void)user_data;

    if (error_code != AWS_OP_SUCCESS) {
        return error_code;
    }

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
    connection->request = NULL;

    if (aws_queue_init(&connection->request_queue, sizeof(struct aws_http_request *) * 8, alloc) != AWS_OP_SUCCESS) {
        aws_mem_release(alloc, connection);
        return AWS_OP_ERR;
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

    return AWS_OP_SUCCESS;

cleanup:
    s_connection_data_clean_up(&connection->data);
    aws_queue_clean_up(&connection->request_queue);
    aws_mem_release(alloc, connection);
    return AWS_OP_ERR;
}

void aws_http_client_connection_release_bytes(struct aws_http_client_connection *connection, size_t bytes) {
    aws_channel_handler_increment_read_window(&connection->data.handler, connection->data.slot, bytes);
}

void aws_http_client_connection_disconnect(struct aws_http_client_connection *connection) {
    aws_channel_shutdown(connection->data.channel, AWS_OP_SUCCESS);
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
    listener->bootstrap = bootstrap;
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
    aws_mem_release(alloc, listener);
    return NULL;
}

void aws_http_server_connection_release_bytes(struct aws_http_server_connection *connection, size_t bytes) {
    aws_channel_handler_increment_read_window(&connection->data.handler, connection->data.slot, bytes);
}

void aws_http_server_connection_disconnect(struct aws_http_server_connection *connection) {
    aws_channel_shutdown(connection->data.channel, AWS_OP_SUCCESS);
}

void aws_http_listener_destroy(struct aws_http_listener *listener) {
    aws_server_bootstrap_remove_socket_listener(listener->bootstrap, listener->listener_socket);
    aws_mem_release(listener->alloc, listener);
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

    request->alloc = connection->data.alloc;
    request->connection = connection;
    request->method = method;
    request->uri = uri;
    request->chunked = chunked;
    request->headers = headers;
    request->header_count = header_count;
    request->callbacks = *callbacks;
    AWS_COROUTINE_INIT(&request->co);
    request->has_body = false;
    request->header_index = 0;
    request->has_cached_segment = false;
    request->last_segment = false;
    request->user_data = user_data;

    return request;
}

#define AWS_HTTP_MESSAGE_SIZE_HINT (16 * 1024)

static inline int s_write_to_msg_implementation(struct aws_io_message *msg, struct aws_byte_cursor *data) {

    if (data->len == 0) {
        return AWS_OP_SUCCESS;
    }

    return aws_byte_buf_append(&msg->message_data, data);
}

#define s_write_to_msg(msg, data)                                                                                      \
    AWS_COROUTINE_CASE();                                                                                              \
    if (s_write_to_msg_implementation(msg, data) != AWS_OP_SUCCESS) {                                                  \
        AWS_COROUTINE_YIELD();                                                                                         \
    }                                                                                                                  \
    AWS_COROUTINE_CASE_END()

static inline char s_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        c -= ('A' - 'a');
    }
    return c;
}

/* Works like memcmp or strcmp, except is case-agnostic. */
static inline int s_strcmp_case_insensitive(const char *a, size_t len_a, const char *b, size_t len_b) {
    if (len_a != len_b) {
        return 1;
    }

    for (size_t i = 0; i < len_a; ++i) {
        int d = s_lower(a[i]) - s_lower(b[i]);
        if (d) {
            return d;
        }
    }
    return 0;
}

static void s_send_request_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_request *request = (struct aws_http_request *)arg;
    struct aws_channel *channel = request->connection->data.channel;
    struct aws_channel_slot *slot = request->connection->data.slot;

    const char *method_str = aws_http_method_to_str(request->method);
    struct aws_byte_cursor method = aws_byte_cursor_from_array(method_str, strlen(method_str));
    struct aws_byte_cursor uri = *request->uri;
    struct aws_byte_cursor version = aws_byte_cursor_from_array("HTTP/1.1 ", 9);
    struct aws_byte_cursor space = aws_byte_cursor_from_array(" ", 1);
    struct aws_byte_cursor newline = aws_byte_cursor_from_array("\r\n", 2);
    struct aws_byte_cursor colon_space = aws_byte_cursor_from_array(": ", 2);
    struct aws_byte_cursor zero = aws_byte_cursor_from_array("0", 1);

    struct aws_io_message *msg =
        aws_channel_acquire_message_from_pool(channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_HTTP_MESSAGE_SIZE_HINT);
    if (!msg) {
        aws_http_client_connection_disconnect(request->connection);
    }

    AWS_COROUTINE_START(&request->co);

    /* Occurs only once. */
    if (request->connection->request) {
        aws_queue_push(&request->connection->request_queue, &request, sizeof(struct aws_http_request *));
    } else {
        request->connection->request = request;
    }

    s_write_to_msg(msg, &method);
    s_write_to_msg(msg, &space);
    s_write_to_msg(msg, &uri);
    s_write_to_msg(msg, &space);
    s_write_to_msg(msg, &version);
    s_write_to_msg(msg, &newline);

    /* Write headers. Detect content presence. Detect expect 100-continue. */
    while (request->header_index < request->header_count) {
        enum aws_http_header_name name = aws_http_str_to_header_name(request->headers[request->header_index].name);
        if (name == AWS_HTTP_HEADER_CONTENT_LENGTH || name == AWS_HTTP_HEADER_TRANSFER_ENCODING) {
            request->has_body = true;
        } else if (name == AWS_HTTP_HEADER_EXPECT) {
            struct aws_byte_cursor cursor = request->headers[request->header_index].value;
            if (!s_strcmp_case_insensitive("100-continue", 12, (const char *)cursor.ptr, cursor.len)) {
                struct aws_http_decoder_vtable vtable = s_get_client_decoder_vtable_100_continue();
                aws_http_decoder_set_vtable(request->connection->data.decoder, &vtable);
                request->expect_100_continue = true;
            }
        }
        s_write_to_msg(msg, &request->headers[request->header_index].name);
        s_write_to_msg(msg, &colon_space);
        s_write_to_msg(msg, &request->headers[request->header_index].value);
        s_write_to_msg(msg, &newline);
        request->header_index++;
    }
    s_write_to_msg(msg, &newline);

    if (request->has_body) {
        /* Wait here for a 100-continue response. */
        AWS_COROUTINE_CASE();
        if (request->expect_100_continue) {
            AWS_COROUTINE_YIELD();
        }
        AWS_COROUTINE_CASE_END();

        while (!request->last_segment) {
            request->segment.ptr = NULL;
            request->segment.len = msg->message_data.capacity - msg->message_data.len;
            request->callbacks.on_write_body_segment(
                request, &request->segment, &request->last_segment, request->user_data);

            if (request->chunked) {
                unsigned len = (unsigned)request->segment.len;
                snprintf(request->segment_len_buffer, AWS_ARRAY_SIZE(request->segment_len_buffer), "%x", len);
                request->hex_len = aws_byte_cursor_from_array(
                    request->segment_len_buffer, AWS_ARRAY_SIZE(request->segment_len_buffer));

                s_write_to_msg(msg, &request->hex_len);
                s_write_to_msg(msg, &newline);
                s_write_to_msg(msg, &request->segment);
                s_write_to_msg(msg, &newline);

                if (request->last_segment) {
                    s_write_to_msg(msg, &zero);
                    s_write_to_msg(msg, &newline);
                    s_write_to_msg(msg, &newline);
                }
            } else {
                s_write_to_msg(msg, &request->segment);
            }
        }
    }

    AWS_COROUTINE_END();

    /* Buffer up the segment memory if needed and schedule a followup task. */
    /* Don't queue up a task when waiting for 100-continue -- will be rescheduled upon server response. */
    if (request->has_body && !request->last_segment && !request->expect_100_continue) {
        if (request->has_cached_segment) {
            aws_byte_buf_clean_up(&request->cached_segment);
        }

        struct aws_byte_buf segment;
        segment.len = request->segment.len;
        segment.capacity = segment.len;
        segment.allocator = NULL;
        segment.buffer = request->segment.ptr;
        aws_byte_buf_init_copy(request->alloc, &request->cached_segment, &segment);

        request->segment = aws_byte_cursor_from_buf(&request->cached_segment);

        aws_channel_schedule_task_now(channel, &request->task);
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

void aws_http_request_destroy(struct aws_http_request *request) {
    if (request->has_cached_segment) {
        aws_byte_buf_clean_up(&request->cached_segment);
    }
    aws_mem_release(request->connection->data.alloc, request);
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

    response->alloc = connection->data.alloc;
    response->connection = connection;
    response->code = code;
    response->chunked = chunked;
    response->headers = headers;
    response->header_count = header_count;
    response->callbacks = *callbacks;
    AWS_COROUTINE_INIT(&response->co);
    response->has_body = false;
    response->header_index = 0;
    response->has_cached_segment = false;
    response->last_segment = false;
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
    if (!msg) {
        aws_http_server_connection_disconnect(response->connection);
    }

    const char *code_str = aws_http_code_to_str(response->code);
    struct aws_byte_cursor code = aws_byte_cursor_from_array(code_str, strlen(code_str));
    struct aws_byte_cursor version = aws_byte_cursor_from_array("HTTP/1.1 ", 9);
    struct aws_byte_cursor space = aws_byte_cursor_from_array(" ", 1);
    struct aws_byte_cursor colon_space = aws_byte_cursor_from_array(": ", 2);
    struct aws_byte_cursor zero = aws_byte_cursor_from_array("0", 1);
    snprintf(response->code_buffer, 128, "%d", (int)response->code);
    struct aws_byte_cursor code_num = aws_byte_cursor_from_array(response->code_buffer, strlen(response->code_buffer));
    struct aws_byte_cursor newline = aws_byte_cursor_from_array("\r\n", 2);

    AWS_COROUTINE_START(&response->co);

    s_write_to_msg(msg, &version);
    s_write_to_msg(msg, &code_num);
    s_write_to_msg(msg, &space);
    s_write_to_msg(msg, &code);
    s_write_to_msg(msg, &newline);

    while (response->header_index < response->header_count) {
        enum aws_http_header_name name = aws_http_str_to_header_name(response->headers[response->header_index].name);
        if (name == AWS_HTTP_HEADER_CONTENT_LENGTH || name == AWS_HTTP_HEADER_TRANSFER_ENCODING) {
            response->has_body = true;
        }
        s_write_to_msg(msg, &response->headers[response->header_index].name);
        s_write_to_msg(msg, &colon_space);
        s_write_to_msg(msg, &response->headers[response->header_index].value);
        s_write_to_msg(msg, &newline);
        response->header_index++;
    }
    s_write_to_msg(msg, &newline);

    if (response->has_body) {
        while (!response->last_segment) {
            response->segment.ptr = NULL;
            response->segment.len = msg->message_data.capacity - msg->message_data.len;
            response->callbacks.on_write_body_segment(
                response, &response->segment, &response->last_segment, response->user_data);

            if (response->chunked) {
                unsigned len = (unsigned)response->segment.len;
                snprintf(response->segment_len_buffer, AWS_ARRAY_SIZE(response->segment_len_buffer), "%x", len);
                response->hex_len = aws_byte_cursor_from_array(
                    response->segment_len_buffer, AWS_ARRAY_SIZE(response->segment_len_buffer));

                s_write_to_msg(msg, &response->hex_len);
                s_write_to_msg(msg, &newline);
                s_write_to_msg(msg, &response->segment);
                s_write_to_msg(msg, &newline);

                if (response->last_segment) {
                    s_write_to_msg(msg, &zero);
                    s_write_to_msg(msg, &newline);
                    s_write_to_msg(msg, &newline);
                }

            } else {
                s_write_to_msg(msg, &response->segment);
            }
        }
    }

    AWS_COROUTINE_END();

    aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);

    /* Buffer up the segment memory if needed and schedule a followup task. */
    if (response->has_body && !response->last_segment) {
        if (response->has_cached_segment) {
            aws_byte_buf_clean_up(&response->cached_segment);
        }

        struct aws_byte_buf segment;
        segment.len = response->segment.len;
        segment.capacity = segment.len;
        segment.allocator = NULL;
        segment.buffer = response->segment.ptr;
        aws_byte_buf_init_copy(response->alloc, &response->cached_segment, &segment);

        response->segment = aws_byte_cursor_from_buf(&response->cached_segment);

        aws_channel_schedule_task_now(channel, &response->task);
    } else {
        if (response->callbacks.on_response_sent) {
            response->callbacks.on_response_sent(response, response->user_data);
        }
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

void aws_http_response_destroy(struct aws_http_response *response) {
    if (response->has_cached_segment) {
        aws_byte_buf_clean_up(&response->cached_segment);
    }
    aws_mem_release(response->connection->data.alloc, response);
}
