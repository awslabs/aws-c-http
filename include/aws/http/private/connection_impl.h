#ifndef AWS_HTTP_CONNECTION_IMPL_H
#define AWS_HTTP_CONNECTION_IMPL_H

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

#include <aws/http/connection.h>

#include <aws/http/private/http_impl.h>
#include <aws/http/server.h>

#include <aws/common/atomics.h>
#include <aws/io/channel.h>

struct aws_http_message;
struct aws_http_request_options;
struct aws_http_request_handler_options;
struct aws_http_stream;

struct aws_http_connection_vtable {
    struct aws_channel_handler_vtable channel_handler_vtable;

    struct aws_http_stream *(*new_client_request_stream)(const struct aws_http_request_options *options);
    int (*stream_send_response)(struct aws_http_stream *stream, struct aws_http_message *response);
    void (*close)(struct aws_http_connection *connection);
    bool (*is_open)(const struct aws_http_connection *connection);
    void (*update_window)(struct aws_http_connection *connection, size_t increment_size);
};
/**
 * Base class for connections.
 * There are specific implementations for each HTTP version.
 */
struct aws_http_connection {
    const struct aws_http_connection_vtable *vtable;
    struct aws_channel_handler channel_handler;
    struct aws_channel_slot *channel_slot;
    struct aws_allocator *alloc;
    enum aws_http_version http_version;
    size_t initial_window_size;

    /* Connection starts with 1 hold for the user.
     * aws_http_streams will also acquire holds on their connection for the duration of their lifetime */
    struct aws_atomic_var refcount;

    union {
        struct aws_http_connection_client_data {
            uint8_t delete_me; /* exists to prevent "empty struct" errors */
        } client;

        struct aws_http_connection_server_data {
            void *connection_user_data;
            aws_http_on_incoming_request_fn *on_incoming_request;
            aws_http_on_server_connection_shutdown_fn *on_shutdown;
        } server;
    } client_or_server_data;

    /* On client connections, `client_data` points to client_or_server_data.client and `server_data` is null.
     * Opposite is true on server connections */
    struct aws_http_connection_client_data *client_data;
    struct aws_http_connection_server_data *server_data;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http1_1_server(
    struct aws_allocator *allocator,
    size_t initial_window_size);

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http1_1_client(
    struct aws_allocator *allocator,
    size_t initial_window_size);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_IMPL_H */
