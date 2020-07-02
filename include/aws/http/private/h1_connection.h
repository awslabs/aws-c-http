#ifndef AWS_HTTP_H1_CONNECTION_H
#define AWS_HTTP_H1_CONNECTION_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/connection_impl.h>

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http1_1_server(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size);

AWS_HTTP_API
struct aws_http_connection *aws_http_connection_new_http1_1_client(
    struct aws_allocator *allocator,
    bool manual_window_management,
    size_t initial_window_size);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H1_CONNECTION_H */
