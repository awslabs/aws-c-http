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
#include <aws/http/http_decode.h>

#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

struct aws_http_message;

/* Automatically handle 100-continue? */
/* Detect expect-continue header, stop writing the body to socket, wait for the 100-continue response. */

typedef void(aws_http_on_response_fn)(enum aws_http_code code, void *user_data);
typedef void(aws_http_on_header_fn)(enum aws_http_header_name name, struct aws_byte_cursor *name_str, struct aws_byte_cursor *value_str, void *user_data);
typedef void(aws_http_on_body_fn)(struct aws_byte_cursor data, bool finished, void *user_data);

typedef bool(aws_http_get_body_bytes_fn)(void *buffer, int requested_bytes, int *bytes_written, void *user_data);
typedef int(aws_http_on_sent_fn)(struct aws_http_message *msg, void *ctx);

struct aws_http_connection;

#ifdef __cplusplus
extern "C" {
#endif

AWS_HTTP_API struct aws_http_connection *aws_http_client_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_client_bootstrap *bootstrap,
    aws_http_on_header_fn *on_header,
    aws_http_on_body_fn *on_body,
    void *user_data);
AWS_HTTP_API struct aws_http_connection *aws_http_server_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_server_bootstrap *bootstrap,
    aws_http_on_header_fn *on_header,
    aws_http_on_body_fn *on_body,
    void *user_data);
AWS_HTTP_API void aws_http_connection_destroy(struct aws_http_connection *connection);

AWS_HTTP_API struct aws_http_message *aws_http_create_message(
    struct aws_http_connection *connection,
    aws_http_get_body_bytes_fn *get_body,
    aws_http_on_sent_fn *on_sent,
    void *ctx);
AWS_HTTP_API int aws_http_message_set_response_code(struct aws_http_message *msg, enum aws_http_code code);
AWS_HTTP_API int aws_http_message_set_method(struct aws_http_message *msg, enum aws_http_method method);
AWS_HTTP_API int aws_http_message_set_uri(struct aws_http_message *msg, struct aws_byte_cursor uri);
AWS_HTTP_API int aws_http_message_add_header(
    struct aws_http_message *msg,
    struct aws_byte_cursor name,
    struct aws_byte_cursor value);
AWS_HTTP_API int aws_http_message_send(struct aws_http_message *msg, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_CONNECTION_H */
