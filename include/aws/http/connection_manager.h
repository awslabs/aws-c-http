#ifndef AWS_HTTP_CONNECTION_MANAGER_H
#define AWS_HTTP_CONNECTION_MANAGER_H

/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/common/byte_buf.h>

struct aws_client_bootstrap;
struct aws_http_connection;
struct aws_http_connection_manager;
struct aws_socket_options;
struct aws_tls_connection_options;

struct aws_http_connection_manager_options {
    struct aws_client_bootstrap *bootstrap;
    size_t initial_window_size;
    struct aws_socket_options *socket_options;
    struct aws_tls_connection_options *tls_connection_options;
    struct aws_byte_cursor host;
    uint16_t port;
    size_t max_connections;
};

typedef int (acquire_connection_callback_fn)(struct aws_http_connection *connection, void *user_data, int result);


AWS_EXTERN_C_BEGIN

AWS_HTTP_API
void aws_http_connection_manager_release(struct aws_http_connection_manager *manager);

AWS_HTTP_API
void aws_http_connection_manager_acquire(struct aws_http_connection_manager *manager);

AWS_HTTP_API
struct aws_http_connection_manager *aws_http_connection_manager_new(struct aws_allocator *allocator, struct aws_http_connection_manager_options *options);

AWS_HTTP_API
int aws_http_connection_manager_acquire_connection(struct aws_http_connection_manager *connection_manager, acquire_connection_callback_fn *callback, void *user_data);

AWS_HTTP_API
int aws_http_connection_manager_release_connection(struct aws_http_connection_manager *connection_manager, struct aws_http_connection *connection);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_MANAGER_H */

