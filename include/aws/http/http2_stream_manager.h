#ifndef AWS_HTTP2_STREAM_MANAGER_H
#define AWS_HTTP2_STREAM_MANAGER_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/http.h>

/*
 * HTTP/2 stream manager configuration struct.
 *
 * Contains all of the configuration needed to create an http2 connection as well as
 * connection manager under the hood.
 */
struct aws_http2_stream_manager_options {
    /**
     * Required.
     * Configure the connection pool under the hood.
     */
    const struct aws_http_connection_manager_options *connection_manager_options;

    /**
     * Options specific to HTTP/2 connections.
     * Optional.
     * Ignored if connection is not HTTP/2.
     * If connection is HTTP/2 and options were not specified, default values are used.
     */
    const struct aws_http2_connection_options *http2_options;

    /**
     * Optional.
     * When true, use prior knowledge to set up an HTTP/2 connection on a cleartext
     * connection.
     * When TLS is set and this is true, the connection will failed to be established,
     * as prior knowledge only works for cleartext TLS.
     * Refer to RFC7540 3.4
     */
    bool prior_knowledge_http2;
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
