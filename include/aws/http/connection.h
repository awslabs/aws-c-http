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

/* TODO (randgaul): Some forward declares to lower header dependencies here. */
#include <aws/io/channel_bootstrap.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

/* Automatically handle 100-continue? */
/* Detect expect-continue header, stop writing the body to socket, wait for the 100-continue response. */

struct aws_http_client_connection;
struct aws_http_listener;
struct aws_http_server_connection;
struct aws_http_request;
struct aws_http_response;

struct aws_http_request_callbacks {
    void (*on_write_body_segment)(
        struct aws_http_request *request,
        struct aws_byte_cursor **segment,
        bool *last_segment,
        void *user_data);

    void (*on_response)(struct aws_http_request *request, enum aws_http_code code, void *user_data);
    void (*on_response_header)(
        struct aws_http_request *request,
        enum aws_http_header_name header_name,
        const struct aws_http_header *header,
        void *user_data);
    void (*on_response_body_segment)(
        struct aws_http_request *request,
        const struct aws_byte_cursor *data,
        bool last_segment,
        bool *release_segment,
        void *user_data);

    void (*on_request_completed)(struct aws_http_request *request, void *user_data);
};

struct aws_http_response_callbacks {
    void (*on_write_body_segment)(
        struct aws_http_response *response,
        struct aws_byte_cursor **segment,
        bool *last_segment,
        void *user_data);

    // done when sent to io
    void (*on_response_sent)(struct aws_http_response *response, void *user_data);
};

struct aws_http_client_callbacks {
    void (*on_connected)(struct aws_http_client_connection *connection, void *user_data);
    void (*on_disconnected)(struct aws_http_client_connection *connection, void *user_data);

    /* HTTP2 Only -- Not implemented yet. */
    void (*on_push_response)(
        struct aws_http_client_connection *connection,
        struct aws_http_response *response,
        void *user_data);
};

struct aws_http_server_callbacks {
    void (*on_request)(
        struct aws_http_server_connection *connection,
        enum aws_http_method method,
        void *user_data);
    void (*on_uri)(struct aws_http_server_connection *connection, const struct aws_byte_cursor *uri, void *user_data);
    void (*on_request_header)(
        struct aws_http_server_connection *connection,
        enum aws_http_header_name header_name,
        const struct aws_http_header *header,
        void *user_data);
    void (*on_request_body_segment)(
        struct aws_http_server_connection *connection,
        const struct aws_byte_cursor *data,
        bool last_segment,
        bool *release_segment,
        void *user_data);

    void (*on_connection_created)(struct aws_http_server_connection *connection, void *user_data);
    void (*on_connection_closed)(struct aws_http_server_connection *connection, void *user_data);
};

#ifdef __cplusplus
extern "C" {
#endif

AWS_HTTP_API int aws_http_client_connect(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_client_bootstrap *bootstrap,
    size_t initial_window_size,
    struct aws_http_client_callbacks *callbacks,
    void *user_data);
AWS_HTTP_API void aws_http_client_connection_release_bytes(struct aws_http_client_connection *connection, size_t bytes);
AWS_HTTP_API void aws_http_client_connection_destroy(struct aws_http_client_connection *connection);

AWS_HTTP_API struct aws_http_listener *aws_http_listener_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_server_bootstrap *bootstrap,
    size_t initial_window_size,
    struct aws_http_server_callbacks *callbacks,
    void *user_data);
AWS_HTTP_API void aws_http_server_connection_destroy(struct aws_http_server_connection *connection);
AWS_HTTP_API void aws_http_listener_destroy(struct aws_http_listener *listener);

AWS_HTTP_API struct aws_http_request *aws_http_request_new(
    struct aws_http_client_connection *connection,
    enum aws_http_method method,
    const struct aws_byte_cursor *uri,
    bool chunked,
    struct aws_http_header *headers,
    int header_count,
    struct aws_http_request_callbacks *callbacks,
    void *user_data);
AWS_HTTP_API int aws_http_request_send(struct aws_http_request *request);
AWS_HTTP_API void aws_http_request_destroy(struct aws_http_request *request);

AWS_HTTP_API struct aws_http_response *aws_http_response_new(
    struct aws_http_server_connection *connection,
    enum aws_http_code code,
    bool chunked,
    struct aws_http_header *headers,
    int header_count,
    struct aws_http_response_callbacks *callbacks,
    void *user_data);
AWS_HTTP_API int aws_http_response_send(struct aws_http_response *response);
AWS_HTTP_API void aws_http_response_destroy(struct aws_http_response *response);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_CONNECTION_H */
