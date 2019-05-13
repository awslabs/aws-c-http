#ifndef AWS_HTTP_CONNECTION_MANAGER_FUNCTION_TABLE_H
#define AWS_HTTP_CONNECTION_MANAGER_FUNCTION_TABLE_H

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

struct aws_http_connection_manager_function_table {
    /*
     * Downstream http functions
     */
    aws_http_connection_manager_create_connection_fn *create_connection;
    aws_http_connection_manager_close_connection_fn *close_connection;
    aws_http_connection_manager_release_connection_fn *release_connection;
    aws_http_connection_manager_is_connection_open_fn *is_connection_open;
};

AWS_STATIC_IMPL
bool aws_http_connection_manager_function_table_is_valid(
    const struct aws_http_connection_manager_function_table *table) {
    return table->create_connection && table->close_connection && table->release_connection &&
           table->is_connection_open;
}

AWS_HTTP_API
extern const struct aws_http_connection_manager_function_table
    *g_aws_http_connection_manager_default_function_table_ptr;

#endif /* AWS_HTTP_CONNECTION_MANAGER_FUNCTION_TABLE_H */
