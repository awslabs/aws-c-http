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

/**
 * SUMMARY
 *
 *     This header implements a connection API for HTTP1.1 over TCP, with or without Transport Layer Security (TLS).
 *     Clients can make attempts to connect to an endpoint, and when successful an `aws_http_client_connection` is
 *     handed to the user via callback. This connection can be used to send HTTP requests and receive responses back
 *     from the endpoint.
 *
 *     Servers can spawn TCP socket listeners to accept incoming connections from clients. Once an incoming connection
 *     is established a `aws_http_server_connection` is handed to the user with a callback. This connection is used to
 *     receive incoming requests from clients, and send off responses back to the clients.
 *
 *     The API in this header is HTTP2 compatible. HTTP2 support must be opted-into by setting up appropriate callbacks
 *     for HTTP2 push-promises and push-responses. Note: for a more seamless HTTP2 support the API in the header
 *     aws/http/connection_buffered.h is recommended, as it supports HTTP1.1 and HTTP2 out-of-the-box with no need for
 *     setting up any HTTP2 specific callbacks.
 *
 * HTTP2
 *
 *     HTTP2 extends the HTTP1.1 spec by adding in another layer by encapsulating HTTP1.1. HTTP2 adds in push-promises
 *     (synthesized requests sent from the server to the client), and push-responses (responses sent from the server to
 *     the client, without a prior associated request from the client).
 *
 *     To accept push-promises and push-responses, a client can setup the
 *     `aws_http_client_callbacks::on_push_promise_callbacks` callbacks, along with the
 *     `aws_http_client_callbacks::on_push_response_callbacks` callbacks. Setting these callbacks to NULL means HTTP2
 *     support is *not* opted-into. Setting these callbacks up means opting-into HTTP2 support.
 *
 *     Servers can enable sending push-promises and push-responses by setting up the callbacks
 *     `aws_http_server_callbacks::write_push_response_callbacks`, and
 *     `aws_http_server_callbacks::write_push_promise_callbacks`. Setting these callbacks to NULL means HTTP2 support
 *     is *not* opted-into. Setting these callbacks up means opting-into HTTP2 support.
 *
 *     A server can send a push-promise with the `aws_http_push_promise_send` function. A server can also send a
 *     push-response with the `aws_http_push_response_send` function.
 *
 * NO BUFFERING
 *
 *     This API minimizes all buffering and copying of intermediate data around. As a result there are callbacks for
 *     nearly everything involving HTTP messages. This is a rather low-level asynchronous API. If a slightly higher
 *     level API is desired, one that performs some minimal buffering of headers/URI, the aws/http/connection_buffered.h
 *     header might be a better option. The connection_buffered.h header is an optional wrapper around the asynchronous
 *     API implemented by this header.
 */

struct aws_socket_endpoint;
struct aws_socket_options;
struct aws_tls_connection_options;
struct aws_client_bootstrap;
struct aws_server_bootstrap;

struct aws_http_client_connection;
struct aws_http_listener;
struct aws_http_server_connection;

struct aws_http_request;

typedef void aws_http_on_body_segment_fn(
    const struct aws_byte_cursor *data,
    bool last_segment,
    bool *release_segment,
    void *user_data);

typedef void aws_http_on_header_fn(
    enum aws_http_header_name header_name,
    const struct aws_http_header *header,
    void *user_data);

typedef void aws_http_on_message_completed_fn(int error_code, void *user_data);

typedef void aws_http_on_write_body_fn(struct aws_byte_buf *segment_to_write, bool *is_last_segment, void *user_data);

struct aws_http_on_message_callbacks {
    /**
     * Called once for each header. The memory at `header` is not valid after this function returns,
     * so be sure to store a copy of it as necessary.
     */
    aws_http_on_header_fn *on_header;

    /**
     * Called once for each contiguous segment of body data received. The `last_segment` bool is set
     * to true whenever the last segment of data comes along, and false otherwise. The data stored in
     * `data` is not valid after this function returns, so be sure to store a copy of it as necessary.
     * `release_segment` should be set to true to relieve backpressure. Setting this to false will
     * invoke read back-pressure on the io, for example if the data needs to be moved over to a new
     * thread before queueing. A future call to `aws_http_client_connection_release_bytes` is needed
     * to relieve backpressure by setting `release_segment` to false.
     */
    aws_http_on_body_segment_fn *on_body_segment;

    /**
     * Notification sent when the final byte of the response has been received.
     */
    aws_http_on_message_completed_fn *on_completed;
};

/**
 * The callbacks needed to receive responses. All callbacks are called from the channel's
 * event loop thread.
 */
struct aws_http_on_response_callbacks {
    /**
     * Called when a response has been received from the underlying io, and parsing has begun.
     * `code` is the HTTP response code.
     */
    void (*on_response)(struct aws_http_client_connection *connection, enum aws_http_code code, void *user_data);

    /**
     * All callbacks needed for handling incoming responses.
     */
    struct aws_http_on_message_callbacks on_message_callbacks;
};

struct aws_http_on_request_callbacks {
    /**
     * Called when a request has been received from the underlying io, and parsing has begun.
     * `method` is the request method.
     */
    void (*on_request)(struct aws_http_server_connection *connection, enum aws_http_method method, void *user_data);

    /**
     * Called the URI has been parsed. `uri` memory is not valid after this function returns, so be sure
     * to make a copy of it as necessary.
     */
    void (*on_uri)(const struct aws_byte_cursor *uri, void *user_data);

    /**
     * All callbacks needed for handling incoming requests.
     */
    struct aws_http_on_message_callbacks on_message_callbacks;
};

/**
 * The callbacks needed to send an http message. All callbacks are called from the channel's
 * event loop thread.
 */
struct aws_http_write_message_callbacks {
    /**
     * Called when the message is being written to the underlying io, and needs to write
     * out the segments of the body data. Specify if a segment is the final one by assigning
     * `is_last_segment` to true, and false otherwise. `segment_to_write` needs to have the `buffer`,
     * and the `len` parameters filled out. `len` must not be set as larger than `capacity`.
     */
    aws_http_on_write_body_fn *on_write_body_segment;

    /**
     * Notification sent when the final byte of the message has been sent to the underlying io.
     */
    aws_http_on_message_completed_fn *on_sent;
};

/**
 * The callbacks needed to create a client connection. All callbacks are called from the channel's
 * event loop thread.
 */
struct aws_http_client_callbacks {
    /**
     * Notification for when the client connection has been successfully constructed and ready for use.
     * The connection will be cleaned up automatically upon disconnect.
     */
    void (*on_connected)(struct aws_http_client_connection *connection, void *user_data);

    /**
     * Notification for when the client connection has been disconnected and invalid for future use.
     */
    void (*on_disconnected)(struct aws_http_client_connection *connection, void *user_data);

    /* All callbacks needed for sending requests. */
    struct aws_http_write_message_callbacks write_request_callbacks;

    /* All callbacks needed to handle incoming responses. */
    struct aws_http_on_response_callbacks on_response_callbacks;

    /* All callbacks needed to handle incoming HTTP2 push promises. */
    /* Not implemented yet -- Needed for HTTP2. */
    struct aws_http_on_request_callbacks on_push_promise_callbacks;

    /* All callbacks needed to handle incoming HTTP2 push responses. */
    /* Not implemented yet -- Needed for HTTP2. */
    struct aws_http_on_response_callbacks on_push_response_callbacks;
};

/**
 * The callbacks needed for a server connection to run. All callbacks are called from the channel's
 * event loop thread.
 */
struct aws_http_server_callbacks {

    /**
     * Notification for when the server connection has been successfully constructed and ready for use.
     * The connection will be cleaned up automatically upon disconnect.
     */
    void (*on_connection_created)(struct aws_http_server_connection *connection, void *user_data);

    /**
     * Notification for when the server connection has been disconnected and invalid for future use.
     */
    void (*on_connection_closed)(struct aws_http_server_connection *connection, void *user_data);

    /**
     * All callbacks needed for receiving requests.
     * These callbacks are used per-spawned connection with a client.
     */
    struct aws_http_on_request_callbacks on_request_callbacks;

    /**
     * All callbacks needed for sending responses.
     * These callbacks are used per-spawned connection with a client.
     */
    struct aws_http_write_message_callbacks write_response_callbacks;

    /**
     * All callbacks needed for sending push responses.
     * These callbacks are used per-spawned connection with a client.
     * Not implemented yet -- for HTTP2 only.
     */
    struct aws_http_write_message_callbacks write_push_response_callbacks;

    /**
     * All callbacks needed for sending push responses.
     * These callbacks are used per-spawned connection with a client.
     * Not implemented yet -- for HTTP2 only.
     */
    struct aws_http_write_message_callbacks write_push_promise_callbacks;
};

struct aws_http_request_def {
    enum aws_http_method method;
    const struct aws_byte_cursor *uri;
    int header_count;
    const struct aws_http_header *headers;
    void *userdata;
    bool is_chunked;
};

struct aws_http_response_def {
    enum aws_http_code code;
    int header_count;
    const struct aws_http_header *headers;
    void *userdata;
    bool is_chunked;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API void aws_http_request_def_set_method(struct aws_http_request_def *def, enum aws_http_method method);
AWS_HTTP_API void aws_http_request_def_set_uri(struct aws_http_request_def *def, const struct aws_byte_cursor *uri);
AWS_HTTP_API void aws_http_request_def_set_headers(
    struct aws_http_request_def *def,
    const struct aws_http_header *headers,
    int count);
AWS_HTTP_API void aws_http_request_def_set_chunked(struct aws_http_request_def *def, bool is_chunked);
AWS_HTTP_API void aws_http_request_def_set_userdata(struct aws_http_request_def *def, void *userdata);

AWS_HTTP_API void aws_http_response_def_set_code(struct aws_http_response_def *def, enum aws_http_code code);
AWS_HTTP_API void aws_http_response_def_set_headers(
    struct aws_http_response_def *def,
    const struct aws_http_header *headers,
    int count);
AWS_HTTP_API void aws_http_response_def_set_chunked(struct aws_http_response_def *def, bool is_chunked);
AWS_HTTP_API void aws_http_response_def_set_userdata(struct aws_http_response_def *def, void *userdata);

/**
 * Queues up a task to create a client connection. `callbacks` is copied by value internally. The `on_connected`
 * callback of `aws_http_client_callbacks` is called when the connection has been successfully setup with the
 * server at `endpoint`. The `on_connected` callback hands the user an `aws_http_client_connection`, used for
 * constructing and sending requests. `initial_window_size` is optional -- zero stands for unspecified. Non-zero
 * will limit the api to a certain data window size for io reads/writes.
 */
AWS_HTTP_API int aws_http_client_connect(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_client_bootstrap *bootstrap,
    size_t initial_window_size,
    struct aws_http_client_callbacks *callbacks,
    void *user_data);

/**
 * Used to release bytes held in `aws_http_request_callbacks::on_write_body_segment`, and avoid invoking
 * read back-pressure.
 */
AWS_HTTP_API void aws_http_client_connection_release_bytes(struct aws_http_client_connection *connection, size_t bytes);

/**
 * Signals to the underlying io to disconnect the client connection. Will invoke
 * `aws_http_client_callbacks::on_disconnected` once the client has been disconnected.
 */
AWS_HTTP_API void aws_http_client_connection_destroy(struct aws_http_client_connection *connection);

/**
 * Constructs a new listener socket for the server. `aws_http_server_callbacks::on_connection_created` will be invoked
 * as clients successfully connect to the server with new HTTP connections.  `initial_window_size` is optional -- zero
 * stands for unspecified. Non-zero will limit the api to a certain data window size for io reads/writes. The
 * initial_window_size` parameter is per-connection spawned from the listener.
 */
AWS_HTTP_API struct aws_http_listener *aws_http_listener_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_server_bootstrap *bootstrap,
    size_t initial_window_size,
    struct aws_http_server_callbacks *callbacks,
    void *user_data);

/**
 * Used to release bytes held in `aws_http_response_callbacks::on_write_body_segment`, and avoid invoking
 * read back-pressure.
 */
AWS_HTTP_API void aws_http_server_connection_release_bytes(struct aws_http_server_connection *connection, size_t bytes);

/**
 * Signals to the underlying io to disconnect the server connection. Will invoke
 * `aws_http_server_callbacks::on_connection_closed` once the server has been disconnected.
 */
AWS_HTTP_API void aws_http_server_connection_destroy(struct aws_http_server_connection *connection);

/**
 * Destroys the listener socket created by `aws_http_listener_new`.
 */
AWS_HTTP_API void aws_http_listener_destroy(struct aws_http_listener *listener);

/**
 * Initiates the send processes for a request. All parameters required to setup the request are in the `def` structure.
 * The `def` structure itself, and the pointers within, *must* remain valid until the final byte of the request is
 * written to the underlying IO. `aws_http_write_message_callbacks::on_sent` will be called when the final byte is
 * written.
 */
AWS_HTTP_API int aws_http_request_send(
    struct aws_http_client_connection *connection,
    const struct aws_http_request_def *def);

/**
 * Initiates the send processes for a response. All parameters required to setup the response are in the `def`
 * structure. The `def` structure itself, and the pointers within, *must* remain valid until the final byte of the
 * response is written to the underlying IO. `aws_http_write_message_callbacks::on_sent` will be called when the final
 * byte is written.
 */
AWS_HTTP_API int aws_http_response_send(
    struct aws_http_server_connection *connection,
    const struct aws_http_response_def *def);

/* Not implemented yet -- for HTTP2 only. */
AWS_HTTP_API int aws_http_push_promise_send(
    struct aws_http_server_connection *connection,
    enum aws_http_method method,
    const struct aws_byte_cursor *uri,
    const struct aws_http_header *headers,
    int header_count,
    void *user_data);

/* Not implemented yet -- for HTTP2 only. */
AWS_HTTP_API int aws_http_push_response_send(
    struct aws_http_server_connection *connection,
    enum aws_http_code code,
    const struct aws_http_header *headers,
    int header_count,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_H */
