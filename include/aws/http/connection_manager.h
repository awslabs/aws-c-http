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
#include <aws/http/connection.h>

struct aws_client_bootstrap;
struct aws_http_connection_manager;
struct aws_socket_options;
struct aws_tls_connection_options;
struct aws_http_connection_manager_mocks;

/*
 * Connection manager configuration struct.
 *
 * Contains all of the configuration needed to create an http connection as well as
 * the maximum number of connections to ever have in existence.
 */
struct aws_http_connection_manager_options {
    struct aws_client_bootstrap *bootstrap;
    size_t initial_window_size;
    struct aws_socket_options *socket_options;
    struct aws_tls_connection_options *tls_connection_options;
    struct aws_byte_cursor host;
    uint16_t port;
    size_t max_connections;
    const struct aws_http_connection_manager_function_table *mocks;
};

AWS_EXTERN_C_BEGIN

/*
 * Connection managers are ref counted.  Adds one external ref to the manager.
 */
AWS_HTTP_API
void aws_http_connection_manager_acquire(struct aws_http_connection_manager *manager);

/*
 * Connection managers are ref counted.  Removes one external ref from the manager.
 */
AWS_HTTP_API
void aws_http_connection_manager_release(struct aws_http_connection_manager *manager);

/*
 * Creates a new connection manager with the supplied configuration options.
 */
AWS_HTTP_API
struct aws_http_connection_manager *aws_http_connection_manager_new(struct aws_allocator *allocator, struct aws_http_connection_manager_options *options);

/*
 * Requests a connection from the manager
 */
AWS_HTTP_API
int aws_http_connection_manager_acquire_connection(struct aws_http_connection_manager *connection_manager, aws_http_on_client_connection_setup_fn *callback, void *user_data);

/*
 * Returns a connection back to the manager
 */
AWS_HTTP_API
int aws_http_connection_manager_release_connection(struct aws_http_connection_manager *connection_manager, struct aws_http_connection *connection);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_MANAGER_H */

