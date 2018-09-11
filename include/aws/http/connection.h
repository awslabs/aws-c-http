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

#ifndef AWS_HTTP_HANDLER_H
#define AWS_HTTP_HANDLER_H

#include <aws/http/http.h>
#include <aws/http/http_decode.h>

#include <aws/io/channel.h>

struct aws_http_message;

/* Automatically handle 100-continue? */

/* Async callbacks??? Is that OK? If not, what should be our sync and memory strategy? */
typedef void(aws_http_on_response_fn)(enum aws_http_code code, void *user_data);
typedef void(aws_http_on_header_fn)(struct aws_byte_cursor *name, struct aws_byte_cursor *value, void *user_data);
typedef void(aws_http_on_body_fn)(struct aws_byte_cursor data, bool finished, void *user_data);

struct aws_http_connection;

struct aws_http_connection aws_http_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_tls_connection_options *tls_options,
    aws_http_on_header_fn *on_header,
    aws_http_on_body_fn *on_body,
    void *user_data);
void aws_http_connection_destroy(struct aws_http_connection *connection);

typedef bool(aws_http_get_body_bytes_fn)(void *buffer, int requested_bytes, int *bytes_written, void *user_data);
typedef int(aws_http_on_sent_fn)(struct aws_http_message *msg, void *ctx);

struct aws_http_message *aws_http_create_message(
    struct aws_http_connection *connection,
    aws_http_get_body_bytes_fn *get_body,
    aws_http_on_sent_fn *on_sent,
    void *ctx);
int aws_http_message_set_response_code(struct aws_http_message *msg, enum aws_http_code code);
int aws_http_message_set_method(struct aws_http_message *msg, enum aws_http_method method);
int aws_http_message_set_uri(struct aws_http_message *msg, struct aws_byte_cursor uri);
int aws_http_message_add_header(
    struct aws_http_message *msg,
    struct aws_byte_cursor name,
    struct aws_byte_cursor value);
int aws_http_message_send(struct aws_http_message *msg, void *user_data);

#endif /* AWS_HTTP_HANDLER_H */
