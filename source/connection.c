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
#include <aws/common/linked_list.h>

#include <aws/io/channel_bootstrap.h>
#include <aws/io/message_pool.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/http/connection.h>
#include <aws/http/decode.h>

#include <stdio.h>

struct aws_coroutine {
    int line;
};

/* Coroutine for implementing state machines in a linear and simple way. */
/* https://www.chiark.greenend.org.uk/~sgtatham/coroutines.html */
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

static void s_co_init(struct aws_coroutine *co) {
    co->line = 0;
}

struct aws_http_connection_data {
    struct aws_allocator *alloc;
    struct aws_channel_handler handler;
    struct aws_channel *channel;
    struct aws_channel_slot *slot;
    struct aws_byte_buf decoder_scratch_space;
    struct aws_http_decoder *decoder;
    size_t initial_window_size;
    size_t bytes_unreleased;
    struct aws_linked_list msg_list;
    bool is_server;
    bool connection_closed;
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
    struct aws_linked_list_node node;
    struct aws_allocator *alloc;
    struct aws_http_client_connection *connection;
    enum aws_http_method method;
    const struct aws_byte_cursor *uri;
    struct aws_http_header *headers;
    int header_count;
    struct aws_channel_task task;
    struct aws_coroutine co;
    int header_index;
    char segment_len_buffer[128];
    struct aws_byte_cursor hex_len;
    struct aws_byte_buf segment;
    struct aws_byte_buf cached_segment;
    void *user_data;
    bool chunked;
    bool has_body;
    bool has_cached_segment;
    bool last_segment;
    bool expect_100_continue;
    bool got_100_continue;
};

struct aws_http_response {
    struct aws_allocator *alloc;
    struct aws_http_server_connection *connection;
    enum aws_http_code code;
    struct aws_http_header *headers;
    int header_count;
    struct aws_channel_task task;
    struct aws_coroutine co;
    char code_buffer[128];
    char segment_len_buffer[128];
    struct aws_byte_cursor hex_len;
    int header_index;
    struct aws_byte_buf segment;
    struct aws_byte_buf cached_segment;
    void *user_data;
    bool has_cached_segment;
    bool has_body;
    bool chunked;
    bool last_segment;
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
    connection->callbacks.on_response_callbacks.on_message_callbacks.on_header(header->name, &h, request->user_data);
    return true;
}

static void s_complete_request(struct aws_http_request *request) {
    struct aws_http_client_connection *connection = request->connection;
    connection->callbacks.on_response_callbacks.on_message_callbacks.on_completed(AWS_OP_SUCCESS, request->user_data);

    /* Unhook request from client request queue, and clean it up. */
    if (!aws_linked_list_empty(&connection->data.msg_list)) {
        aws_linked_list_pop_front(&connection->data.msg_list);
        if (!aws_linked_list_empty(&connection->data.msg_list)) {
            connection->request =
                AWS_CONTAINER_OF(aws_linked_list_back(&connection->data.msg_list), struct aws_http_request, node);
        } else {
            connection->request = NULL;
        }
    } else {
        connection->request = NULL;
    }

    if (request->has_cached_segment) {
        aws_byte_buf_clean_up(&request->cached_segment);
    }
    aws_mem_release(request->connection->data.alloc, request);

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
    connection->callbacks.on_response_callbacks.on_message_callbacks.on_body_segment(
        data, last_segment, &can_release, request->user_data);
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
    connection->callbacks.on_response_callbacks.on_response(connection, code, request->user_data);
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
    connection->callbacks.on_request_callbacks.on_message_callbacks.on_header(
        header->name, &h, connection->data.user_data);
    return true;
}

static bool s_request_decoder_on_body(const struct aws_byte_cursor *data, bool last_segment, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    bool can_release;
    connection->callbacks.on_request_callbacks.on_message_callbacks.on_body_segment(
        data, last_segment, &can_release, connection->data.user_data);
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
    connection->callbacks.on_request_callbacks.on_uri(uri, connection->data.user_data);
}

static void s_request_decoder_on_response_code(enum aws_http_code code, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    (void)connection;
    (void)code;
}

static void s_request_decoder_on_method(enum aws_http_method method, void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    connection->callbacks.on_request_callbacks.on_request(connection, method, connection->data.user_data);
}

static void s_request_decoder_on_done(void *user_data) {
    struct aws_http_server_connection *connection = (struct aws_http_server_connection *)user_data;
    connection->callbacks.on_request_callbacks.on_message_callbacks.on_completed(
        AWS_OP_SUCCESS, connection->data.user_data);
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
            /* TODO: Disconnect, but don't clean up. */
            break;
        }

        aws_byte_cursor_advance(&msg_data, bytes_read);
    }

    /* Cleanup channel message. */
    if (data->bytes_unreleased == 0) {
        /* Only release headers, and body data the user did not specify as released. */
        aws_channel_slot_increment_read_window(slot, total - data->bytes_unreleased);
    }
    aws_mem_release(message->allocator, message);

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

static size_t s_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}

static void s_connection_data_clean_up(struct aws_http_connection_data *data) {
    aws_http_decoder_destroy(data->decoder);
    aws_byte_buf_clean_up(&data->decoder_scratch_space);
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    (void)handler;
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {
    struct aws_http_connection_data *data = (struct aws_http_connection_data *)handler->impl;
    data->connection_closed = true;

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

static struct aws_channel_handler_vtable s_channel_handler = {
    s_handler_process_read_message,
    s_handler_process_write_message,
    s_handler_increment_read_window,
    s_handler_shutdown,
    s_handler_initial_window_size,
    s_handler_message_overhead,
    s_handler_destroy,
};

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
static void s_client_channel_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    struct aws_http_client_connection *connection = (struct aws_http_client_connection *)user_data;

    if (error_code != AWS_OP_SUCCESS) {
        // TODO: inform user
        return;
    }

    if (s_add_backchannel_slot_and_handler(channel, &connection->data)) {
        goto error;
    }

    connection->callbacks.on_connected(connection, connection->data.user_data);
    return;

error:
    // TODO: inform user
    aws_channel_shutdown(channel, aws_last_error());
}

static void s_client_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;
}

static int s_connection_data_init(
    struct aws_http_connection_data *data,
    struct aws_allocator *alloc,
    size_t initial_window_size,
    bool true_for_client_false_for_server,
    void *user_data) {

    data->alloc = alloc;
    data->initial_window_size = initial_window_size ? initial_window_size : SIZE_MAX;
    data->is_server = !true_for_client_false_for_server;
    struct aws_http_decoder *decoder = NULL;

    /* Scratch space for the streaming decoder. */
    if (aws_byte_buf_init(&data->decoder_scratch_space, alloc, 1024) != AWS_OP_SUCCESS) {
        goto error_and_cleanup;
    }

    /* Setup channel handler. */
    struct aws_channel_handler handler;
    handler.vtable = &s_channel_handler;
    handler.alloc = alloc;
    handler.impl = data;
    data->handler = handler;

    /* Create http streaming decoder. */
    struct aws_http_decoder_params params;
    params.alloc = alloc;
    params.scratch_space = data->decoder_scratch_space;
    params.true_for_request_false_for_response = !true_for_client_false_for_server;
    params.user_data = data;
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
    data->connection_closed = false;

    aws_linked_list_init(&data->msg_list);

    return AWS_OP_SUCCESS;

error_and_cleanup:
    if (decoder) {
        aws_http_decoder_destroy(decoder);
    }
    aws_byte_buf_clean_up(&data->decoder_scratch_space);
    return AWS_OP_ERR;
}

static void s_on_incoming_channel(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    struct aws_http_listener *listener = (struct aws_http_listener *)user_data;

    if (error_code != AWS_OP_SUCCESS) {
        // TODO: inform user
        return;
    }

    struct aws_http_server_connection *connection = NULL;
    bool connection_inited = false;

    connection = aws_mem_acquire(listener->alloc, sizeof(struct aws_http_server_connection));
    if (!connection) {
        goto error;
    }
    AWS_ZERO_STRUCT(*connection);

    int err = s_connection_data_init(
        &connection->data, listener->alloc, listener->initial_window_size, false, listener->user_data);
    if (err) {
        goto error;
    }
    connection_inited = true;

    err = s_add_backchannel_slot_and_handler(channel, &connection->data);
    if (err) {
        goto error;
    }

    connection->callbacks = listener->callbacks;
    connection->listener = listener;
    listener->callbacks.on_connection_created(connection, listener->user_data);
    return;

error:
    if (connection) {
        if (connection_inited) {
            s_connection_data_clean_up(&connection->data);
        }
        aws_mem_release(listener->alloc, connection);
    }

    // TODO: inform user
}

static void s_on_shutdown_incoming_channel(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;
}

void aws_http_request_def_set_method(struct aws_http_request_def *def, enum aws_http_method method) {
    def->method = method;
}

void aws_http_request_def_set_uri(struct aws_http_request_def *def, const struct aws_byte_cursor *uri) {
    def->uri = uri;
}

void aws_http_request_def_set_headers(
    struct aws_http_request_def *def,
    const struct aws_http_header *headers,
    int count) {
    def->headers = headers;
    def->header_count = count;
}

void aws_http_request_def_set_chunked(struct aws_http_request_def *def, bool is_chunked) {
    def->is_chunked = is_chunked;
}

void aws_http_request_def_set_userdata(struct aws_http_request_def *def, void *userdata) {
    def->userdata = userdata;
}

void aws_http_response_def_set_code(struct aws_http_response_def *def, enum aws_http_code code) {
    def->code = code;
}

void aws_http_response_def_set_headers(
    struct aws_http_response_def *def,
    const struct aws_http_header *headers,
    int count) {
    def->headers = headers;
    def->header_count = count;
}

void aws_http_response_def_set_chunked(struct aws_http_response_def *def, bool is_chunked) {
    def->is_chunked = is_chunked;
}

void aws_http_response_def_set_userdata(struct aws_http_response_def *def, void *userdata) {
    def->userdata = userdata;
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

    struct aws_http_client_connection *connection = NULL;
    bool data_inited = false;

    connection = aws_mem_acquire(alloc, sizeof(struct aws_http_client_connection));
    if (!connection) {
        return AWS_OP_ERR;
    }
    AWS_ZERO_STRUCT(*connection);

    int err = s_connection_data_init(&connection->data, alloc, initial_window_size, true, user_data);
    if (err) {
        goto error;
    }
    data_inited = true;

    connection->callbacks = *callbacks;
    connection->request = NULL;

    if (tls_options) {
        err = aws_client_bootstrap_new_tls_socket_channel(
            bootstrap,
            endpoint->address,
            endpoint->port,
            socket_options,
            tls_options,
            s_client_channel_setup,
            s_client_channel_shutdown,
            connection);
        if (err) {
            goto error;
        }
    } else {
        err = aws_client_bootstrap_new_socket_channel(
            bootstrap,
            endpoint->address,
            endpoint->port,
            socket_options,
            s_client_channel_setup,
            s_client_channel_shutdown,
            connection);
        if (err) {
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    if (data_inited) {
        s_connection_data_clean_up(&connection->data);
    }
    aws_mem_release(alloc, connection);
    return AWS_OP_ERR;
}

void aws_http_client_connection_release_bytes(struct aws_http_client_connection *connection, size_t bytes) {
    aws_channel_handler_increment_read_window(&connection->data.handler, connection->data.slot, bytes);
}

void aws_http_client_connection_disconnect(struct aws_http_client_connection *connection) {
    aws_channel_shutdown(connection->data.channel, AWS_OP_SUCCESS);
}

void aws_http_client_connection_destroy(struct aws_http_client_connection *connection) {
    s_connection_data_clean_up(&connection->data);
    aws_mem_release(connection->data.alloc, connection);
    // WORKING HERE
    // Gotta do a task for proper shutdown
    // bleh
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

    struct aws_http_listener *listener = aws_mem_acquire(alloc, sizeof(struct aws_http_listener));
    if (!listener) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*listener);

    listener->alloc = alloc;
    listener->bootstrap = bootstrap;
    listener->initial_window_size = initial_window_size;
    listener->callbacks = *callbacks;
    listener->user_data = user_data;

    struct aws_socket *listener_socket;
    if (tls_options) {
        listener_socket = aws_server_bootstrap_new_tls_socket_listener(
            bootstrap,
            endpoint,
            socket_options,
            tls_options,
            s_on_incoming_channel,
            s_on_shutdown_incoming_channel,
            listener);
    } else {
        listener_socket = aws_server_bootstrap_new_socket_listener(
            bootstrap, endpoint, socket_options, s_on_incoming_channel, s_on_shutdown_incoming_channel, listener);
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

void aws_http_server_connection_destroy(struct aws_http_server_connection *connection) {
    s_connection_data_clean_up(&connection->data);
    aws_mem_release(connection->data.alloc, connection);
}

void aws_http_listener_destroy(struct aws_http_listener *listener) {
    aws_server_bootstrap_destroy_socket_listener(listener->bootstrap, listener->listener_socket);
    aws_mem_release(listener->alloc, listener);
}

#define AWS_HTTP_MESSAGE_SIZE_HINT (16 * 1024)

static int s_write_to_msg_implementation(struct aws_io_message *msg, struct aws_byte_cursor *data) {

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

static char s_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        c -= ('A' - 'a');
    }
    return c;
}

/* Works like memcmp or strcmp, except is case-agnostic. */
static int s_strcmp_case_insensitive(const char *a, size_t len_a, const char *b, size_t len_b) {
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

static void s_send_request_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_request *request = (struct aws_http_request *)arg;
    struct aws_http_client_connection *connection = request->connection;
    assert(connection);

    if (connection->data.connection_closed) {
        connection->callbacks.write_request_callbacks.on_sent(AWS_ERROR_HTTP_CONNECTION_CLOSED, request->user_data);
        return;
    }

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
    aws_linked_list_push_back(&connection->data.msg_list, &request->node);
    if (!connection->request) {
        connection->request = request;
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
        if (!!request->expect_100_continue) {
            AWS_COROUTINE_YIELD();
        }
        AWS_COROUTINE_CASE_END();

        while (!request->last_segment) {
            request->segment.buffer = NULL;
            request->segment.capacity = msg->message_data.capacity - msg->message_data.len;
            size_t capacity = request->segment.capacity;
            (void)capacity;
            request->segment.allocator = NULL;
            request->segment.len = 0;
            connection->callbacks.write_request_callbacks.on_write_body_segment(
                &request->segment, &request->last_segment, request->user_data);
            assert(request->segment.len <= request->segment.capacity);
            assert(capacity == request->segment.capacity);

            if (request->chunked) {
                unsigned len = (unsigned)request->segment.len;
                snprintf(request->segment_len_buffer, AWS_ARRAY_SIZE(request->segment_len_buffer), "%x", len);
                request->hex_len = aws_byte_cursor_from_array(
                    request->segment_len_buffer, AWS_ARRAY_SIZE(request->segment_len_buffer));

                s_write_to_msg(msg, &request->hex_len);
                s_write_to_msg(msg, &newline);

                AWS_COROUTINE_CASE();
                struct aws_byte_cursor segment = aws_byte_cursor_from_buf(&request->segment);
                if (s_write_to_msg_implementation(msg, &segment) != AWS_OP_SUCCESS) {
                    AWS_COROUTINE_YIELD();
                }
                AWS_COROUTINE_CASE_END();

                s_write_to_msg(msg, &newline);

                if (request->last_segment) {
                    s_write_to_msg(msg, &zero);
                    s_write_to_msg(msg, &newline);
                    s_write_to_msg(msg, &newline);
                }
            } else {
                AWS_COROUTINE_CASE();
                struct aws_byte_cursor segment = aws_byte_cursor_from_buf(&request->segment);
                if (s_write_to_msg_implementation(msg, &segment) != AWS_OP_SUCCESS) {
                    AWS_COROUTINE_YIELD();
                }
                AWS_COROUTINE_CASE_END();
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
        segment.buffer = request->segment.buffer;
        aws_byte_buf_init_copy(&request->cached_segment, request->alloc, &segment);
        request->has_cached_segment = true;

        request->segment = request->cached_segment;

        aws_channel_schedule_task_now(channel, &request->task);
    } else {
        /* Finished encoding the request. Notify user. Cleanup happens upon response receival. */
        connection->callbacks.write_request_callbacks.on_sent(AWS_OP_SUCCESS, request->user_data);
    }

    aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
}

int aws_http_request_send(struct aws_http_client_connection *connection, const struct aws_http_request_def *def) {

    if (connection->data.connection_closed) {
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    struct aws_http_request *request = aws_mem_acquire(connection->data.alloc, sizeof(struct aws_http_request));
    if (!request) {
        return AWS_OP_ERR;
    }

    request->alloc = connection->data.alloc;
    request->connection = connection;
    request->method = def->method;
    request->uri = def->uri;
    request->chunked = def->is_chunked;
    request->headers = (struct aws_http_header *)def->headers;
    request->header_count = def->header_count;
    s_co_init(&request->co);
    request->has_body = false;
    request->header_index = 0;
    request->has_cached_segment = false;
    request->last_segment = false;
    request->user_data = def->userdata;

    aws_channel_task_init(&request->task, s_send_request_task, request);

    struct aws_channel *channel = request->connection->data.channel;
    if (!connection->data.connection_closed) {
        if (!aws_channel_thread_is_callers_thread(channel)) {
            aws_channel_schedule_task_now(channel, &request->task);
        } else {
            s_send_request_task(&request->task, request, AWS_TASK_STATUS_RUN_READY);
        }

        return AWS_OP_SUCCESS;
    } else {
        return AWS_OP_ERR;
    }
}

static void s_send_response_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_http_response *response = (struct aws_http_response *)arg;
    struct aws_http_server_connection *connection = response->connection;
    assert(connection);

    if (response->connection->data.connection_closed) {
        connection->callbacks.write_response_callbacks.on_sent(AWS_ERROR_HTTP_CONNECTION_CLOSED, response->user_data);
        return;
    }

    struct aws_channel *channel = connection->data.channel;
    struct aws_channel_slot *slot = connection->data.slot;

    struct aws_io_message *msg =
        aws_channel_acquire_message_from_pool(channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_HTTP_MESSAGE_SIZE_HINT);
    if (!msg) {
        aws_http_server_connection_disconnect(connection);
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
            response->segment.buffer = NULL;
            response->segment.len = 0;
            response->segment.allocator = NULL;
            response->segment.capacity = msg->message_data.capacity - msg->message_data.len;
            size_t capacity = response->segment.capacity;
            (void)capacity;
            connection->callbacks.write_response_callbacks.on_write_body_segment(
                &response->segment, &response->last_segment, response->user_data);
            assert(response->segment.len <= response->segment.capacity);
            assert(capacity == response->segment.capacity);

            if (response->chunked) {
                unsigned len = (unsigned)response->segment.len;
                snprintf(response->segment_len_buffer, AWS_ARRAY_SIZE(response->segment_len_buffer), "%x", len);
                response->hex_len = aws_byte_cursor_from_array(
                    response->segment_len_buffer, AWS_ARRAY_SIZE(response->segment_len_buffer));

                s_write_to_msg(msg, &response->hex_len);
                s_write_to_msg(msg, &newline);

                AWS_COROUTINE_CASE();
                struct aws_byte_cursor segment = aws_byte_cursor_from_buf(&response->segment);
                if (s_write_to_msg_implementation(msg, &segment) != AWS_OP_SUCCESS) {
                    AWS_COROUTINE_YIELD();
                }
                AWS_COROUTINE_CASE_END();

                s_write_to_msg(msg, &newline);

                if (response->last_segment) {
                    s_write_to_msg(msg, &zero);
                    s_write_to_msg(msg, &newline);
                    s_write_to_msg(msg, &newline);
                }

            } else {
                AWS_COROUTINE_CASE();
                struct aws_byte_cursor segment = aws_byte_cursor_from_buf(&response->segment);
                if (s_write_to_msg_implementation(msg, &segment) != AWS_OP_SUCCESS) {
                    AWS_COROUTINE_YIELD();
                }
                AWS_COROUTINE_CASE_END();
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
        segment.buffer = response->segment.buffer;
        aws_byte_buf_init_copy(&response->cached_segment, response->alloc, &segment);
        response->has_cached_segment = true;

        response->segment = response->cached_segment;

        aws_channel_schedule_task_now(channel, &response->task);
    } else {
        /* Finished encoding the response. Notify user and cleanup the response object. */
        connection->callbacks.write_response_callbacks.on_sent(AWS_OP_SUCCESS, response->user_data);

        if (response->has_cached_segment) {
            aws_byte_buf_clean_up(&response->cached_segment);
        }
        aws_mem_release(response->connection->data.alloc, response);
    }
}

int aws_http_response_send(struct aws_http_server_connection *connection, const struct aws_http_response_def *def) {

    if (connection->data.connection_closed) {
        return aws_raise_error(AWS_ERROR_HTTP_CONNECTION_CLOSED);
    }

    struct aws_http_response *response = aws_mem_acquire(connection->data.alloc, sizeof(struct aws_http_response));
    if (!response) {
        return AWS_OP_ERR;
    }

    response->alloc = connection->data.alloc;
    response->connection = connection;
    response->code = def->code;
    response->chunked = def->is_chunked;
    response->headers = (struct aws_http_header *)def->headers;
    response->header_count = def->header_count;
    s_co_init(&response->co);
    response->has_body = false;
    response->header_index = 0;
    response->has_cached_segment = false;
    response->last_segment = false;
    response->user_data = def->userdata;

    aws_channel_task_init(&response->task, s_send_response_task, response);

    struct aws_channel *channel = response->connection->data.channel;
    if (!connection->data.connection_closed) {
        /* This is not an atomic op, and state can change here at any moment. */
        if (!aws_channel_thread_is_callers_thread(channel)) {
            aws_channel_schedule_task_now(channel, &response->task);
        } else {
            s_send_response_task(&response->task, response, AWS_TASK_STATUS_RUN_READY);
        }

        return AWS_OP_SUCCESS;
    } else {
        return AWS_OP_ERR;
    }
}
