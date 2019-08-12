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
#include <aws/io/channel_bootstrap.h>

struct aws_http_message;
struct aws_http_make_request_options;
struct aws_http_request_handler_options;
struct aws_http_stream;

typedef int(aws_client_bootstrap_new_socket_channel_fn)(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data);

typedef int(aws_client_bootstrap_new_tls_socket_channel_fn)(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data);

struct aws_http_connection_system_vtable {
    aws_client_bootstrap_new_socket_channel_fn *new_socket_channel;
    aws_client_bootstrap_new_tls_socket_channel_fn *new_tls_socket_channel;
};

struct aws_http_connection_vtable {
    struct aws_channel_handler_vtable channel_handler_vtable;

    struct aws_http_stream *(*make_request)(
        struct aws_http_connection *client_connection,
        const struct aws_http_make_request_options *options);

    struct aws_http_stream *(*new_server_request_handler_stream)(
        const struct aws_http_request_handler_options *options);
    int (*stream_send_response)(struct aws_http_stream *stream, struct aws_http_message *response);
    void (*close)(struct aws_http_connection *connection);
    bool (*is_open)(const struct aws_http_connection *connection);
    void (*update_window)(struct aws_http_connection *connection, size_t increment_size);
};

typedef int(aws_http_proxy_request_transform_fn)(struct aws_http_message *request, void *user_data);

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

    aws_http_proxy_request_transform_fn *proxy_request_transform;
    void *user_data;

    /* Connection starts with 1 hold for the user.
     * aws_http_streams will also acquire holds on their connection for the duration of their lifetime */
    struct aws_atomic_var refcount;

    union {
        struct aws_http_connection_client_data {
            uint8_t delete_me; /* exists to prevent "empty struct" errors */
        } client;

        struct aws_http_connection_server_data {
            aws_http_on_incoming_request_fn *on_incoming_request;
            aws_http_on_server_connection_shutdown_fn *on_shutdown;
        } server;
    } client_or_server_data;

    /* On client connections, `client_data` points to client_or_server_data.client and `server_data` is null.
     * Opposite is true on server connections */
    struct aws_http_connection_client_data *client_data;
    struct aws_http_connection_server_data *server_data;
};

/* Gets a client connection up and running.
 * Responsible for firing on_setup and on_shutdown callbacks. */
struct aws_http_client_bootstrap {
    struct aws_allocator *alloc;
    bool is_using_tls;
    size_t initial_window_size;
    void *user_data;
    aws_http_on_client_connection_setup_fn *on_setup;
    aws_http_on_client_connection_shutdown_fn *on_shutdown;
    aws_http_proxy_request_transform_fn *proxy_request_transform;

    struct aws_http_connection *connection;
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

AWS_HTTP_API
void aws_http_connection_set_system_vtable(const struct aws_http_connection_system_vtable *system_vtable);

AWS_HTTP_API
int aws_http_client_connect_internal(
    const struct aws_http_client_connection_options *options,
    aws_http_proxy_request_transform_fn *proxy_request_transform);

/**
 * Internal API for adding a reference to a connection
 */
AWS_HTTP_API
void aws_http_connection_acquire(struct aws_http_connection *connection);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_IMPL_H */
