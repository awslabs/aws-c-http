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

#ifndef AWS_HTTP_CONNECTION_H
#define AWS_HTTP_CONNECTION_H

#include <aws/http/http.h>

struct aws_client_bootstrap;
struct aws_http_connection;
struct aws_http_server;
struct aws_server_bootstrap;
struct aws_socket_options;
struct aws_tls_connection_options;

typedef void(aws_http_on_client_connection_setup_fn)(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);

typedef void(aws_http_on_client_connection_shutdown_fn)(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);

struct aws_http_client_connection_def {
    /* Set to sizeof() this struct, used for versioning. */
    size_t self_size;

    struct aws_allocator *allocator;
    struct aws_client_bootstrap *bootstrap;
    struct aws_byte_cursor host_name;
    uint16_t port;
    struct aws_socket_options *socket_options;
    struct aws_tls_connection_options *tls_options;
    size_t initial_window_size;

    /* supported versions, in preference order. 1.1 is used if nothing is set */
    enum aws_http_version supported_http_versions[AWS_HTTP_VERSION_COUNT];

    /* User data for callbacks */
    void *user_data;

    /* Invoked when connect completes. If unsuccessful, connection will be NULL */
    aws_http_on_client_connection_setup_fn *on_setup;

    /* Invoked when connection is closed. Never invoked if on_setup failed. */
    aws_http_on_client_connection_shutdown_fn *on_shutdown;
};

typedef void(aws_http_connection_result_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

typedef void(aws_http_server_on_incoming_connection_fn)(
    struct aws_http_server *server,
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);

struct aws_http_server_def {
    /* Set to sizeof() this struct, used for versioning. */
    size_t self_size;

    struct aws_allocator *allocator;
    struct aws_server_bootstrap *bootstrap;
    struct aws_byte_cursor host_name;
    uint16_t port;
    struct aws_socket_options *socket_options;
    struct aws_tls_connection_options *tls_options;

    void *server_user_data;

    /* From this callback, user must call aws_http_connection_configure_server() */
    aws_http_server_on_incoming_connection_fn *on_incoming_connection;
};

typedef void(aws_http_on_incoming_request_fn)(struct aws_http_connection *connection, void *user_data);

typedef void(aws_http_on_server_connection_shutdown_fn)(
    struct aws_http_connection *connection,
    int error_code,
    void *connection_user_data);

struct aws_server_connection_def {
    /* Set to sizeof() this struct, used for versioning. */
    size_t self_size;

    size_t initial_window_size;

    void *connection_user_data;

    /* From this callback, user must call aws_http_create_request_handler() */
    aws_http_on_incoming_request_fn *on_incoming_request;

    aws_http_on_server_connection_shutdown_fn *on_shutdown;
};

AWS_EXTERN_C_BEGIN

/**
 * Create server, a listening socket that accepts incoming connections.
 */
AWS_HTTP_API
struct aws_http_server *aws_http_server_new(struct aws_http_server_def *def);

/**
 * Destroy server.
 */
AWS_HTTP_API
void aws_http_server_destroy(struct aws_http_server *server);

/**
 * Asynchronously establish a client connection.
 */
AWS_HTTP_API
int aws_http_client_connect(struct aws_http_client_connection_def *def);

/**
 * Initiate shutdown of a connection.
 * Note that other factors, such as connectin loss, may cause a shutdown at any time.
 */
AWS_HTTP_API
int aws_http_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    aws_http_connection_result_fn *on_complete,
    void *user_data);

/**
 * Configure a server connection.
 * This must be called from the server's on_incoming_connection callback.
 */
AWS_HTTP_API
int aws_http_connection_configure_server(
    struct aws_http_connection *connection,
    struct aws_server_connection_def *config);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_H */
