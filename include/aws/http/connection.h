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

struct aws_socket_endpoint;
struct aws_socket_options;
struct aws_tls_connection_options;
struct aws_client_bootstrap;
struct aws_server_bootstrap;

struct aws_http_client_connection;
struct aws_http_listener;
struct aws_http_server_connection;
struct aws_http_request;
struct aws_http_response;

/**
 * The callbacks needed to create and send a request. All callbacks are called from the channel's
 * event loop thread.
 */
struct aws_http_request_callbacks {
    /**
     * Called when the request is being written to the underlying io, and needs to write
     * out the segments of the body data. Specify if a segment is the final one by assigning
     * `is_last_segment` to true, and false otherwise. The initial value of `segment_to_write->len` specifies
     * the length of the internal buffer; the number of bytes that will be written is equal to
     * the min of `segment_to_write->len`'s initial value, and the value set by the user.
     */
    void (*on_write_body_segment)(
        struct aws_http_request *request,
        struct aws_byte_cursor *segment_to_write,
        bool *is_last_segment,
        void *user_data);

    /**
     * Called when a response has been received from the underlying io, and parsing has begun.
     * `code` is the HTTP response code.
     */
    void (*on_response)(struct aws_http_request *request, enum aws_http_code code, void *user_data);

    /**
     * Called once for each header. The memory at `header` is not valid after this function returns,
     * so be sure to store a copy of it as necessary.
     */
    void (*on_response_header)(
        struct aws_http_request *request,
        enum aws_http_header_name header_name,
        const struct aws_http_header *header,
        void *user_data);

    /**
     * Called once for each contiguous segment of body data received. The `last_segment` bool is set
     * to true whenever the last segment of data comes along, and false otherwise. The data stored in
     * `data` is not valid after this function returns, to be sure to store a copy of it as necessary.
     * `release_segment` should be set to true to inform the underlying io the bytes have been
     * received by the user. Setting this to false will invoke read back-pressure on the io. A future
     * call to `aws_http_client_connection_release_bytes` is needed to release any bytes held by setting
     * `release_segment` to false.
     */
    void (*on_response_body_segment)(
        struct aws_http_request *request,
        const struct aws_byte_cursor *data,
        bool last_segment,
        bool *release_segment,
        void *user_data);

    /**
     * Notification sent when the final byte of the response has been received.
     */
    void (*on_request_completed)(struct aws_http_request *request, void *user_data);
};

/**
 * The callbacks needed to send a response. All callbacks are called from the channel's
 * event loop thread.
 */
struct aws_http_response_callbacks {
    /**
     * Called when the response is being written to the underlying io, and needs to write
     * out the segments of the body data. Specify if a segment is the final one by assigning
     * `is_last_segment` to true, and false otherwise. The initial value of `segment_to_write->len` specifies
     * the length of the internal buffer; the number of bytes that will be written is equal to
     * the min of `segment_to_write->len`'s initial value, and the value set by the user.
     */
    void (*on_write_body_segment)(
        struct aws_http_response *response,
        struct aws_byte_cursor *segment_to_write,
        bool *is_last_segment,
        void *user_data);

    /**
     * Notification sent when the final byte of the response has been sent to the underlying io.
     */
    void (*on_response_sent)(struct aws_http_response *response, void *user_data);
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

    /* HTTP2 Only -- Not implemented yet. */
    void (*on_push_response)(
        struct aws_http_client_connection *connection,
        struct aws_http_response *response,
        void *user_data);
};

/**
 * The callbacks needed for a server connection to run. All callbacks are called from the channel's
 * event loop thread.
 */
struct aws_http_server_callbacks {
    /**
     * Called when a request has been received from the underlying io, and parsing has begun.
     * `method` is the request method.
     */
    void (*on_request)(struct aws_http_server_connection *connection, enum aws_http_method method, void *user_data);

    /**
     * Called the URI has been parsed. `uri` memory is not valid after this function returns, so be sure
     * to make a copy of it as necessary.
     */
    void (*on_uri)(struct aws_http_server_connection *connection, const struct aws_byte_cursor *uri, void *user_data);

    /**
     * Called once for each header. The memory at `header` is not valid after this function returns,
     * so be sure to store a copy of it as necessary.
     */
    void (*on_request_header)(
        struct aws_http_server_connection *connection,
        enum aws_http_header_name header_name,
        const struct aws_http_header *header,
        void *user_data);

    /**
     * Called once for each contiguous segment of body data received. The `last_segment` bool is set
     * to true whenever the last segment of data comes along, and false otherwise. The data stored in
     * `data` is not valid after this function returns, to be sure to store a copy of it as necessary.
     * `release_segment` should be set to true to inform the underlying io the bytes have been
     * received by the user. Setting this to false will invoke read back-pressure on the io. A future
     * call to `aws_http_server_connection_release_bytes` is needed to release any bytes held by setting
     * `release_segment` to false.
     */
    void (*on_request_body_segment)(
        struct aws_http_server_connection *connection,
        const struct aws_byte_cursor *data,
        bool last_segment,
        bool *release_segment,
        void *user_data);

    /**
     * Called when the last byte of the request has been received and parsed.
     */
    void (*on_request_end)(void *user_data);

    /**
     * Notification for when the server connection has been successfully constructed and ready for use.
     * The connection will be cleaned up automatically upon disconnect.
     */
    void (*on_connection_created)(struct aws_http_server_connection *connection, void *user_data);

    /**
     * Notification for when the server connection has been disconnected and invalid for future use.
     */
    void (*on_connection_closed)(struct aws_http_server_connection *connection, void *user_data);
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Queues up a task to create a client connection. `callbacks` is copied by value internally. The `on_connected`
 * callback of `aws_http_client_callbacks` is called when the connection has been successfully setup with the
 * server at `endpoint`. The `on_connected` callback hands the user an `aws_http_client_connection`, used for
 * constructing and sending requests.
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
AWS_HTTP_API void aws_http_client_connection_disconnect(struct aws_http_client_connection *connection);

/**
 * Constructs a new listener socket for the server. `aws_http_server_callbacks::on_connection_created` will be invoked
 * as clients successfully connect to the server with new HTTP connections. This listener lives for the lifetime of
 * your application.
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
AWS_HTTP_API void aws_http_server_connection_disconnect(struct aws_http_server_connection *connection);

/**
 * Destroys the listener socket created by `aws_http_listener_new`.
 */
AWS_HTTP_API void aws_http_listener_destroy(struct aws_http_listener *listener);

/**
 * Constructs a new request object. The `callbacks` will not be invoked until `aws_http_request_send` is called.
 */
AWS_HTTP_API struct aws_http_request *aws_http_request_new(
    struct aws_http_client_connection *connection,
    enum aws_http_method method,
    const struct aws_byte_cursor *uri,
    bool chunked,
    struct aws_http_header *headers,
    int header_count,
    struct aws_http_request_callbacks *callbacks,
    void *user_data);

/**
 * Sends the request to the underlying io.
 */
AWS_HTTP_API int aws_http_request_send(struct aws_http_request *request);

/**
 * Frees up the memory of the `request` object. After `aws_http_request_send` is called, this function should not be
 * called until `aws_http_request_callbacks::on_request_completed` is called.
 */
AWS_HTTP_API void aws_http_request_destroy(struct aws_http_request *request);

/**
 * Constructs a new request object. The `callbacks` will not be invoked until `aws_http_response_send` is invoked.
 */
AWS_HTTP_API struct aws_http_response *aws_http_response_new(
    struct aws_http_server_connection *connection,
    enum aws_http_code code,
    bool chunked,
    struct aws_http_header *headers,
    int header_count,
    struct aws_http_response_callbacks *callbacks,
    void *user_data);

/**
 * Sends the response to the underlying io.
 */
AWS_HTTP_API int aws_http_response_send(struct aws_http_response *response);

/**
 * Frees up the memory of the `response` object. After `aws_http_response_send` is called, this function should not be
 * called until `aws_http_response_callbacks::on_response_sent` is called.
 */
AWS_HTTP_API void aws_http_response_destroy(struct aws_http_response *response);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_CONNECTION_H */
