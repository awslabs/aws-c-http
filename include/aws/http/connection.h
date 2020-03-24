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

/**
 * Invoked when connect completes.
 *
 * If unsuccessful, error_code will be set, connection will be NULL,
 * and the on_shutdown callback will never be invoked.
 *
 * If successful, error_code will be 0 and connection will be valid.
 * The user is now responsible for the connection and must
 * call aws_http_connection_release() when they are done with it.
 *
 * The connection uses one event-loop thread to do all its work.
 * The thread invoking this callback will be the same thread that invokes all
 * future callbacks for this connection and its streams.
 */
typedef void(
    aws_http_on_client_connection_setup_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

/**
 * Invoked when the connection has finished shutting down.
 * Never invoked if on_setup failed.
 * This is always invoked on connection's event-loop thread.
 * Note that the connection is not completely done until on_shutdown has been invoked
 * AND aws_http_connection_release() has been called.
 */
typedef void(
    aws_http_on_client_connection_shutdown_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

/**
 * Configuration options for connection monitoring
 */
struct aws_http_connection_monitoring_options {

    /**
     * minimum required throughput of the connection.  Throughput is only measured against the interval of time where
     * there is actual io to perform.  Read and write throughput are measured and checked independently of one another.
     */
    uint64_t minimum_throughput_bytes_per_second;

    /*
     * amount of time, in seconds, throughput is allowed to drop below the minimum before the connection is shut down
     * as unhealthy.
     */
    uint32_t allowable_throughput_failure_interval_seconds;
};

/**
 * Supported proxy authentication modes
 */
enum aws_http_proxy_authentication_type {
    AWS_HPAT_NONE = 0,
    AWS_HPAT_BASIC,
};

/**
 * Options for http proxy server usage
 */
struct aws_http_proxy_options {

    /**
     * Proxy host to connect to, in lieu of actual target
     */
    struct aws_byte_cursor host;

    /**
     * Port to make the proxy connection to
     */
    uint16_t port;

    /**
     * Optional.
     * TLS configuration for the Local <-> Proxy connection
     * Must be distinct from the the TLS options in the parent aws_http_connection_options struct
     */
    struct aws_tls_connection_options *tls_options;

    /**
     * What type of proxy authentication to use, if any
     */
    enum aws_http_proxy_authentication_type auth_type;

    /**
     * Optional
     * User name to use for authentication, basic only
     */
    struct aws_byte_cursor auth_username;

    /**
     * Optional
     * Password to use for authentication, basic only
     */
    struct aws_byte_cursor auth_password;
};

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
    const struct aws_socket_options *socket_options;

    /**
     * Optional.
     * aws_http_client_connect() deep-copies all contents except the `aws_tls_ctx`,
     * which must outlive the the connection.
     */
    const struct aws_tls_connection_options *tls_options;

    /**
     * Optional
     * Configuration options related to http proxy usage.
     * Relevant fields are copied internally.
     */
    const struct aws_http_proxy_options *proxy_options;

    /**
     * Optional
     * Configuration options related to connection health monitoring
     */
    const struct aws_http_connection_monitoring_options *monitoring_options;

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
     * See `aws_http_on_client_connection_setup_fn`.
     */
    aws_http_on_client_connection_setup_fn *on_setup;

    /**
     * Invoked when the connection has finished shutting down.
     * Never invoked if setup failed.
     * Optional.
     * See `aws_http_on_client_connection_shutdown_fn`.
     */
    aws_http_on_client_connection_shutdown_fn *on_shutdown;

    /**
     * Set to true to manually manage the read window size.
     *
     * If this is false, the connection will maintain a constant window size.
     *
     * If this is true, the caller must manually increment the window size using aws_http_stream_update_window().
     * If the window is not incremented, it will shrink by the amount of body data received. If the window size
     * reaches 0, no further data will be received.
     **/
    bool manual_window_management;
};

/**
 * Initializes aws_http_client_connection_options with default values.
 */
#define AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT                                                                        \
    { .self_size = sizeof(struct aws_http_client_connection_options), .initial_window_size = SIZE_MAX, }

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

/**
 * Returns true if this is a client connection.
 */
AWS_HTTP_API
bool aws_http_connection_is_client(const struct aws_http_connection *connection);

/**
 * Increments the connection-wide read window by the value specified.
 */
AWS_HTTP_API
void aws_http_connection_update_window(struct aws_http_connection *connection, size_t increment_size);

AWS_HTTP_API
enum aws_http_version aws_http_connection_get_version(const struct aws_http_connection *connection);

/**
 * Returns the channel hosting the HTTP connection.
 * Do not expose this function to language bindings.
 */
AWS_HTTP_API
struct aws_channel *aws_http_connection_get_channel(struct aws_http_connection *connection);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_H */
