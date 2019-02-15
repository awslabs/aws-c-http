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

#ifndef AWS_HTTP_CONNECTION_IMPL_H
#define AWS_HTTP_CONNECTION_IMPL_H

#include <aws/http/connection.h>

#include <aws/io/channel.h>

struct aws_http_server_connection_impl_options {
    struct aws_allocator *alloc;
};

struct aws_http_client_connection_impl_options {
    struct aws_allocator *alloc;
    bool is_using_tls;
    size_t initial_window_size;
    void *user_data;
    aws_http_on_client_connection_setup_fn *user_cb_on_setup;
    aws_http_on_client_connection_shutdown_fn *user_cb_on_shutdown;
};

struct aws_http_connection_vtable {
    struct aws_channel_handler_vtable channel_handler_vtable;

    /* TODO: more functions for aws_http_connection */
};

struct aws_http_connection {
    const struct aws_http_connection_vtable *vtable;
    struct aws_channel_handler channel_handler;
    struct aws_channel_slot *channel_slot;
    struct aws_allocator *alloc;
    enum aws_http_version http_version;
    void *user_data;
    size_t initial_window_size;

    bool is_server;

    /* Union for data specific to client or server */
    union {
        struct {
            aws_http_on_incoming_request_fn *user_cb_on_incoming_request;
            aws_http_on_server_connection_shutdown_fn *user_cb_on_shutdown;
        } server;

        struct {
            aws_http_on_client_connection_shutdown_fn *user_cb_on_shutdown;
        } client;
    } data;
};

struct aws_http_connection *aws_http_connection_new_http1_1_server(
    const struct aws_http_server_connection_impl_options *options);

struct aws_http_connection *aws_http_connection_new_http1_1_client(
    const struct aws_http_client_connection_impl_options *options);

#endif /* AWS_HTTP_CONNECTION_IMPL_H */
