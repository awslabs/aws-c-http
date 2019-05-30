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
struct aws_socket_options;
struct aws_tls_connection_options;

/**
 * An HTTP connection.
 * This type is used by both server-side and client-side connections.
 * This type is also used by all supported versions of HTTP.
 */
struct aws_http_connection;

typedef void(
    aws_http_on_client_connection_setup_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

typedef void(
    aws_http_on_client_connection_shutdown_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

/**
 * Options for creating an HTTP client connection.
 * Initialize with AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT to set default values.
 */
struct aws_http_client_connection_options {
    /**
     * The sizeof() this struct, used for versioning.
     * Set by AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT.
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
    struct aws_byte_cursor host_name;

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
     * A default size is set by AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT.
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

/**
 * Initializes aws_http_client_connection_options with default values.
 */
#define AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT                                                                        \
    { .self_size = sizeof(struct aws_http_client_connection_options), .initial_window_size = SIZE_MAX, }

typedef void(aws_http_connection_result_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

AWS_EXTERN_C_BEGIN

/**
 * Asynchronously establish a client connection.
 * The on_setup callback is invoked when the operation has created a connection or failed.
 */
AWS_HTTP_API
int aws_http_client_connect(const struct aws_http_client_connection_options *options);

/**
 * Users must release the connection when they are done with it.
 * The connection's memory cannot be reclaimed until this is done.
 * If the connection was not already shutting down, it will be shut down.
 *
 * Users should always wait for the on_shutdown() callback to be called before releasing any data passed to the
 * http_connection (Eg aws_tls_connection_options, aws_socket_options) otherwise there will be race conditions between
 * http_connection shutdown tasks and memory release tasks, causing Segfaults.
 *
 * A language binding will likely invoke this from the wrapper class's finalizer/destructor.
 */
AWS_HTTP_API
void aws_http_connection_release(struct aws_http_connection *connection);

/**
 * Begin shutdown sequence of the connection if it hasn't already started. This will schedule shutdown tasks on the
 * EventLoop that may send HTTP/TLS/TCP shutdown messages to peers if necessary, and will eventually cause internal
 * connection memory to stop being accessed and on_shutdown() callback to be called.
 *
 * It's safe to call this function regardless of the connection state as long as you hold a reference to the connection.
 */
AWS_HTTP_API
void aws_http_connection_close(struct aws_http_connection *connection);

/**
 * Returns true unless the connection is closed or closing.
 */
AWS_HTTP_API
bool aws_http_connection_is_open(const struct aws_http_connection *connection);

AWS_HTTP_API
enum aws_http_version aws_http_connection_get_version(const struct aws_http_connection *connection);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_H */
