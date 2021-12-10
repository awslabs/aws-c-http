#ifndef AWS_HTTP2_STREAM_MANAGER_H
#define AWS_HTTP2_STREAM_MANAGER_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/http.h>

typedef void(aws_http2_stream_manager_on_connection_setup_fn)(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);

typedef void(aws_http2_stream_manager_shutdown_complete_fn)(void *user_data);

/*
 * HTTP/2 stream manager configuration struct.
 *
 * Contains all of the configuration needed to create an http2 connection as well as
 * connection manager under the hood.
 */
struct aws_http2_stream_manager_options {
    /**
     * basic http connection configuration
     * TODO: Refact this part to struct aws_http_connection_config and share between different level of options?
     */
    struct aws_client_bootstrap *bootstrap;
    const struct aws_socket_options *socket_options;
    /**
     * If TLS options is set, you also need to handle ALPN, otherwise, may not able to get HTTP/2 connection and fail
     * the stream manager.
     * If TLS options not set, prior knowledge will be used.
     */
    const struct aws_tls_connection_options *tls_connection_options;
    struct aws_byte_cursor host;
    uint16_t port;

    /* Connection monitor for the underlying connections made */
    const struct aws_http_connection_monitoring_options *monitoring_options;

    /**
     * Scaling options, an enum choice?
     */

    /**
     *
     */
    void *shutdown_complete_user_data;
    aws_http2_stream_manager_shutdown_complete_fn *shutdown_complete_callback;

    /*
     * Maximum number of connections this manager is allowed to contain. (???)
     */
    size_t max_connections;

    /**
     * If set to true, the read back pressure mechanism will be enabled.
     */
    bool enable_read_back_pressure;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
void aws_http2_stream_manager_acquire(struct aws_http2_stream_manager *manager);

AWS_HTTP_API
void aws_http2_stream_manager_release(struct aws_http2_stream_manager *manager);

AWS_HTTP_API
struct aws_http2_stream_manager *aws_http2_stream_manager_new(
    struct aws_allocator *allocator,
    struct aws_http2_stream_manager_options *options);

AWS_HTTP_API
struct aws_http_stream *aws_http2_stream_manager_make_request(
    struct aws_http2_stream_manager *http2_stream_manager,
    const struct aws_http_make_request_options *options);

AWS_HTTP_API
void aws_http2_stream_manager_stream_release(struct aws_http_stream *stream);

AWS_EXTERN_C_END
#endif /* AWS_HTTP2_STREAM_MANAGER_H */
