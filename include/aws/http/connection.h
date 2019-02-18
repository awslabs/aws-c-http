#ifndef AWS_HTTP_CONNECTION_H
#define AWS_HTTP_CONNECTION_H

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

#include <aws/http/http.h>

struct aws_client_bootstrap;
struct aws_http_connection;
struct aws_http_server;
struct aws_server_bootstrap;
struct aws_socket_options;
struct aws_tls_connection_options;

typedef void(
    aws_http_on_client_connection_setup_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

typedef void(
    aws_http_on_client_connection_shutdown_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

/**
 * Options for creating an HTTP client connection.
 */
struct aws_http_client_connection_options {
    /**
     * Set to sizeof() this struct, used for versioning.
     */
    size_t self_size;

    /**
     * Required.
     * Must outlive the connection.
     */
    struct aws_allocator *allocator;

    /**
     * Required.
     * Must outlive the connection.
     */
    struct aws_client_bootstrap *bootstrap;

    /**
     * Required.
     * aws_http_client_connect() makes a copy.
     */
    const char *host_name;

    /**
     * Required.
     */
    uint16_t port;

    /**
     * Required.
     * aws_http_client_connect() makes a copy.
     */
    struct aws_socket_options *socket_options;

    /**
     * Optional.
     * aws_http_client_connect() deep-copies all contents except the `aws_tls_ctx`,
     * which must outlive the the connection.
     */
    struct aws_tls_connection_options *tls_options;

    /**
     * Optional.
     * A default size is used if nothing is set.
     */
    size_t initial_window_size;

    /**
     * User data for callbacks
     * Optional.
     */
    void *user_data;

    /**
     * Invoked when connect completes.
     * Required.
     * If unsuccessful, error_code will be set, connection will be NULL,
     * and the on_shutdown callback will never be invoked.
     */
    aws_http_on_client_connection_setup_fn *on_setup;

    /**
     * Invoked when the connection is closed.
     * Optional.
     * Never invoked if on_setup failed.
     */
    aws_http_on_client_connection_shutdown_fn *on_shutdown;
};

typedef void(aws_http_connection_result_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

typedef void(aws_http_server_on_incoming_connection_fn)(
    struct aws_http_server *server,
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);

/**
 * Options for creating an HTTP server.
 */
struct aws_http_server_options {
    /**
     * Set to sizeof() this struct, used for versioning.
     */
    size_t self_size;

    /**
     * Required.
     * Must outlive server.
     */
    struct aws_allocator *allocator;

    /**
     * Required.
     * Must outlive server.
     */
    struct aws_server_bootstrap *bootstrap;

    /**
     * Required.
     * Server makes copy.
     */
    struct aws_socket_endpoint *endpoint;

    /**
     * Required.
     * Server makes a copy.
     */
    struct aws_socket_options *socket_options;

    /**
     * Optional.
     * Server copies all contents except the `aws_tls_ctx`, which must outlive the server.
     */
    struct aws_tls_connection_options *tls_options;

    /**
     * User data passed to callbacks.
     * Optional.
     */
    void *server_user_data;

    /**
     * Invoked when an incoming connection has been set up, or when setup has failed.
     * Required.
     * If setup succeeds, the user must call aws_http_connection_configure_server().
     */
    aws_http_server_on_incoming_connection_fn *on_incoming_connection;
};

typedef void(aws_http_on_incoming_request_fn)(struct aws_http_connection *connection, void *user_data);

typedef void(aws_http_on_server_connection_shutdown_fn)(
    struct aws_http_connection *connection,
    int error_code,
    void *connection_user_data);

struct aws_http_server_connection_options {
    /**
     * Set to sizeof() this struct, used for versioning.
     */
    size_t self_size;

    /**
     * Optional.
     * A default size is used if nothing is set.
     */
    size_t initial_window_size;

    /**
     * User data specific to this connection.
     * Optional.
     */
    void *connection_user_data;

    /**
     * Invoked at the start of an incoming request.
     * Required.
     * From this callback, user must call aws_http_create_request_handler().
     */
    aws_http_on_incoming_request_fn *on_incoming_request;

    /**
     * Invoked when the connection is shut down.
     * Optional.
     */
    aws_http_on_server_connection_shutdown_fn *on_shutdown;
};

AWS_EXTERN_C_BEGIN

/**
 * Create server, a listening socket that accepts incoming connections.
 */
AWS_HTTP_API
struct aws_http_server *aws_http_server_new(const struct aws_http_server_options *options);

/**
 * Destroy server.
 *
 * Note: this function should be called by either a user thread (like the main entry point, or from the event-loop the
 * server is assigned to. Otherwise a deadlock is possible. If you call this function from outside the assigned
 * event-loop, this function will block waiting on the assigned event-loop runs the close sequence in its thread.
 */
AWS_HTTP_API
void aws_http_server_destroy(struct aws_http_server *server);

/**
 * Asynchronously establish a client connection.
 */
AWS_HTTP_API
int aws_http_client_connect(const struct aws_http_client_connection_options *options);

/**
 * Users must release the connection when they are done with it.
 * The connection's memory cannot be reclaimed until this is done.
 * If the connection was not already shutting down, it will be shut down
 * with the provided error_code.
 */
AWS_HTTP_API
void aws_http_connection_release(struct aws_http_connection *connection, int error_code);

AWS_HTTP_API
enum aws_http_version aws_http_connection_get_version(const struct aws_http_connection *connection);

/**
 * Configure a server connection.
 * This must be called from the server's on_incoming_connection callback.
 */
AWS_HTTP_API
int aws_http_connection_configure_server(
    struct aws_http_connection *connection,
    const struct aws_http_server_connection_options *options);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_H */
