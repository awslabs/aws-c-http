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

#include <aws/http/private/h2_connection.h>
#include <aws/http/private/h2_decoder.h>

#include <aws/common/logging.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define CONNECTION_LOGF(level, connection, text, ...)                                                                  \
    AWS_LOGF_##level(AWS_LS_HTTP_CONNECTION, "id=%p: " text, (void *)(connection), __VA_ARGS__)
#define CONNECTION_LOG(level, connection, text) CONNECTION_LOGF(level, connection, "%s", text)

/* Stream IDs are only 31 bits [5.1.1] */
static const uint32_t MAX_STREAM_ID = UINT32_MAX >> 1;

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

static struct aws_http_connection_vtable s_h2_connection_vtable = {
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

    .make_request = NULL,
    .new_server_request_handler_stream = NULL,
    .stream_send_response = NULL,
    .close = NULL,
    .is_open = NULL,
    .update_window = NULL,
};

static const struct aws_h2_decoder_vtable s_h2_decoder_vtable = {
    .on_data = NULL,
};

/* Common new() logic for server & client */
static struct aws_h2_connection *s_connection_new(
    struct aws_allocator *alloc,
    size_t initial_window_size,
    bool server) {

    (void)server;

    struct aws_h2_connection *connection = aws_mem_calloc(alloc, 1, sizeof(struct aws_h2_connection));
    if (!connection) {
        return NULL;
    }

    /* Init mutex first, because its error handling is different than every other init failure */
    if (aws_mutex_init(&connection->synced_data.lock)) {
        CONNECTION_LOGF(
            ERROR, connection, "Mutex init error %d (%s).", aws_last_error(), aws_error_name(aws_last_error()));
        goto error_mutex;
    }

    connection->base.vtable = &s_h2_connection_vtable;
    connection->base.alloc = alloc;
    connection->base.channel_handler.vtable = &s_h2_connection_vtable.channel_handler_vtable;
    connection->base.channel_handler.alloc = alloc;
    connection->base.channel_handler.impl = connection;
    connection->base.http_version = AWS_HTTP_VERSION_2;
    connection->base.initial_window_size = initial_window_size;

    /* 1 refcount for user */
    aws_atomic_init_int(&connection->base.refcount, 1);

    /* Init the next stream id (server must use odd ids, client even [RFC 7540 5.1.1])*/
    connection->synced_data.next_stream_id = (server ? 2 : 1);

    /* Create a new decoder */
    struct aws_h2_decoder_params params = {
        .alloc = alloc,
        .vtable = s_h2_decoder_vtable,
        .userdata = connection,
        .logging_id = connection,
    };
    connection->thread_data.decoder = aws_h2_decoder_new(&params);
    if (!connection->thread_data.decoder) {
        CONNECTION_LOGF(
            ERROR, connection, "Decoder init error %d (%s)", aws_last_error(), aws_error_name(aws_last_error()));
        goto error;
    }

    if (aws_h2_frame_encoder_init(&connection->thread_data.encoder, alloc)) {
        CONNECTION_LOGF(
            ERROR, connection, "Encoder init error %d (%s)", aws_last_error(), aws_error_name(aws_last_error()));
        goto error;
    }

    return connection;

error_mutex:
    /* If mutex fails, don't invoke its clean_up() */
    aws_mem_release(alloc, connection);
    return NULL;
error:
    /* Everything else has idempotent clean_up()/destroy() functions, so we can naively call our own destroy() */
    s_handler_destroy(&connection->base.channel_handler);
    return NULL;
}

struct aws_http_connection *aws_http_connection_new_http2_server(
    struct aws_allocator *allocator,
    size_t initial_window_size) {

    struct aws_h2_connection *connection = s_connection_new(allocator, initial_window_size, true);
    if (!connection) {
        return NULL;
    }

    connection->base.server_data = &connection->base.client_or_server_data.server;

    return &connection->base;
}

struct aws_http_connection *aws_http_connection_new_http2_client(
    struct aws_allocator *allocator,
    size_t initial_window_size) {

    struct aws_h2_connection *connection = s_connection_new(allocator, initial_window_size, false);
    if (!connection) {
        return NULL;
    }

    connection->base.client_data = &connection->base.client_or_server_data.client;

    return &connection->base;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_h2_connection *connection = handler->impl;
    CONNECTION_LOG(TRACE, connection, "Destroying connection");

    aws_h2_decoder_destroy(connection->thread_data.decoder);
    aws_h2_frame_encoder_clean_up(&connection->thread_data.encoder);
    aws_mutex_clean_up(&connection->synced_data.lock);
    aws_mem_release(connection->base.alloc, connection);
}

uint32_t aws_h2_connection_get_next_stream_id(struct aws_h2_connection *connection) {

    uint32_t next_id = 0;

    { /* BEGIN CRITICAL SECTION */
        int err = aws_mutex_lock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);

        next_id = connection->synced_data.next_stream_id;
        connection->synced_data.next_stream_id += 2;

        /* If next fetch would overflow next_stream_id, set it to 0 */
        if (AWS_UNLIKELY(next_id > MAX_STREAM_ID)) {
            CONNECTION_LOG(INFO, connection, "All available stream ids are gone, closing the connection");

            next_id = 0;
            aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
        }

        err = aws_mutex_unlock(&connection->synced_data.lock);
        AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);
    } /* END CRITICAL SECTION */

    return next_id;
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    (void)handler;
    (void)slot;
    (void)size;
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    struct aws_h2_connection *connection = handler->impl;
    CONNECTION_LOGF(
        TRACE,
        connection,
        "Channel shutting down in %s direction with error code %d (%s).",
        (dir == AWS_CHANNEL_DIR_READ) ? "read" : "write",
        error_code,
        aws_error_name(error_code));

    aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
    return AWS_OP_SUCCESS;
}

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    struct aws_h2_connection *connection = handler->impl;
    return connection->base.initial_window_size;
}

static size_t s_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    /* "All frames begin with a fixed 9-octet header followed by a variable-length payload" (RFC-7540 4.1) */
    return 9;
}
