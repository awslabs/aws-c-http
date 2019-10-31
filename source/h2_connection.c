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

static struct aws_http_connection_vtable s_h2_connection_vtable = {
    .channel_handler_vtable =
        {
            .process_read_message = NULL,
            .process_write_message = NULL,
            .increment_read_window = NULL,
            .shutdown = NULL,
            .initial_window_size = NULL,
            .message_overhead = NULL,
            .destroy = NULL,
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
        goto error_connection_alloc;
    }

    connection->base.vtable = &s_h2_connection_vtable;
    connection->base.alloc = alloc;
    connection->base.channel_handler.vtable = &s_h2_connection_vtable.channel_handler_vtable;
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
        .user_data = connection,
        .vtable = s_h2_decoder_vtable,
    };
    connection->thread_data.decoder = aws_h2_decoder_new(&params);

    int err = aws_mutex_init(&connection->synced_data.lock);
    if (err) {
        CONNECTION_LOGF(
            ERROR, connection, "static: Failed to initialize mutex, error %d (%s).", err, aws_error_name(err));

        goto error_mutex;
    }

    return connection;

error_mutex:
    aws_mem_release(alloc, connection);
error_connection_alloc:
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
