#ifndef AWS_HTTP_PROXY_IMPL_H
#define AWS_HTTP_PROXY_IMPL_H

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

struct aws_string;

/*
 * When a proxy connection is made, we wrap the user-supplied user data with this
 * proxy user data.  Callbacks are passed properly to the user.  By having this data
 * available, the proxy request transform that was attached to the connection can extract
 * the proxy settings it needs in order to properly transform the requests.
 *
 * Another possibility would be to fold this data into the connection itself.
 */
struct aws_http_proxy_user_data {
    struct aws_allocator *allocator;

    struct aws_string *original_host;
    uint16_t original_port;
    aws_http_on_client_connection_setup_fn *original_on_setup;
    aws_http_on_client_connection_shutdown_fn *original_on_shutdown;
    void *original_user_data;

    enum aws_http_proxy_authentication_type auth_type;
    struct aws_string *username;
    struct aws_string *password;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
void aws_http_proxy_user_data_destroy(struct aws_http_proxy_user_data *user_data);

AWS_HTTP_API
int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_PROXY_IMPL_H */
