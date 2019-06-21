#ifndef AWS_HTTP_CONNECTION_MANAGER_SYSTEM_VTABLE_H
#define AWS_HTTP_CONNECTION_MANAGER_SYSTEM_VTABLE_H

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

#include <aws/http/connection.h>

typedef int(aws_http_connection_manager_create_connection_fn)(const struct aws_http_client_connection_options *options);
typedef void(aws_http_connection_manager_close_connection_fn)(struct aws_http_connection *connection);
typedef void(aws_http_connection_manager_release_connection_fn)(struct aws_http_connection *connection);
typedef bool(aws_http_connection_manager_is_connection_open_fn)(const struct aws_http_connection *connection);

struct aws_http_connection_manager_system_vtable {
    /*
     * Downstream http functions
     */
    aws_http_connection_manager_create_connection_fn *create_connection;
    aws_http_connection_manager_close_connection_fn *close_connection;
    aws_http_connection_manager_release_connection_fn *release_connection;
    aws_http_connection_manager_is_connection_open_fn *is_connection_open;
};

AWS_HTTP_API
bool aws_http_connection_manager_system_vtable_is_valid(const struct aws_http_connection_manager_system_vtable *table);

AWS_HTTP_API
void aws_http_connection_manager_set_system_vtable(
    struct aws_http_connection_manager *manager,
    const struct aws_http_connection_manager_system_vtable *system_vtable);

AWS_HTTP_API
extern const struct aws_http_connection_manager_system_vtable *g_aws_http_connection_manager_default_system_vtable_ptr;

#endif /* AWS_HTTP_CONNECTION_MANAGER_SYSTEM_VTABLE_H */
