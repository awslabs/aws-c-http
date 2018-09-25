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

#include <aws/http/decode.h>
#include <aws/http/http.h>

#include <aws/io/channel_bootstrap.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

struct aws_http_message;

/* Automatically handle 100-continue? */
/* Detect expect-continue header, stop writing the body to socket, wait for the 100-continue response. */

struct aws_http_connection_callbacks {
    /**
     * Called when a request is received and the method + uri have been parsed and are ready to read.
     * The `uri` pointer is not valid after this callback returns.
     */
    void (*on_request)(enum aws_http_method method, const struct aws_byte_cursor *uri, void *user_data);

    /**
     * Called when a response is received and parsed.
     */
    void (*on_response)(enum aws_http_code code, void *user_data);

    /**
     * Called when a header is available for reading from the connection.
     * The `headers` pointer is not valid after this callback returns.
     */
    void (*on_header)(const struct aws_http_header *headers, void *user_data);

    /**
     * Called when body data is ready for reading. Set `release_message` to true to let the connection know you are done
     * reading from the `data` pointer, and false for the connection to hold onto the buffered data until
     * `aws_http_release_body_data` is called. `last_segment` is true if this is the final chunk of the body data for
     * the http message. Return false to immediately terminate and place the connection in an invalid state, ready for
     * `aws_http_connection_destroy`.
     */
    bool (*on_body)(const struct aws_byte_cursor *data, bool last_segment, bool *release_message, void *user_data);
};

struct aws_http_connection;
struct aws_http_message;

typedef void(aws_http_promise_fn)(void *user_data);

#ifdef __cplusplus
extern "C" {
#endif

AWS_HTTP_API struct aws_http_connection *aws_http_client_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_client_bootstrap *bootstrap,
    struct aws_http_connection_callbacks *user_callbacks,
    size_t initial_window_size,
    void *user_data);
AWS_HTTP_API struct aws_http_connection *aws_http_server_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_server_bootstrap *bootstrap,
    struct aws_http_connection_callbacks *user_callbacks,
    size_t initial_window_size,
    void *user_data);
AWS_HTTP_API void aws_http_connection_destroy(struct aws_http_connection *connection);

AWS_HTTP_API int aws_http_send_request(
    struct aws_http_connection *connection,
    enum aws_http_method method,
    bool chunked);
AWS_HTTP_API int aws_http_send_response(struct aws_http_connection *connection, enum aws_http_code code, bool chunked);

AWS_HTTP_API int aws_http_send_uri(
    struct aws_http_connection *connection,
    const struct aws_byte_cursor *uri,
    aws_http_promise_fn *on_uri_written);

AWS_HTTP_API int aws_http_send_headers(
    struct aws_http_connection *connection,
    const struct aws_http_header *headers,
    int header_count,
    bool final_headers,
    aws_http_promise_fn *on_headers_written);

AWS_HTTP_API int aws_http_send_body_segment(
    struct aws_http_connection *connection,
    struct aws_byte_cursor *segment,
    bool final_segment,
    aws_http_promise_fn *on_segment_written);

AWS_HTTP_API int aws_http_release_body_data(struct aws_http_connection *connection, size_t bytes);

AWS_HTTP_API int aws_http_flush(struct aws_http_connection *connection);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_CONNECTION_H */
