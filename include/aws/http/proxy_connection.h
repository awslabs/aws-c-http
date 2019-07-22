#ifndef AWS_HTTP_PROXY_CONNECTION_H
#define AWS_HTTP_PROXY_CONNECTION_H

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

#include <aws/http/http.h>

#include <aws/http/connection.h>

enum aws_http_proxy_authentication_type {
    AWS_HPAT_NONE,
    AWS_HPAT_BASIC
};

struct aws_http_proxy_authentication_basic_options {
    struct aws_byte_cursor user;
    struct aws_byte_cursor password;
};

struct aws_http_proxy_authentication_options {
    enum aws_http_proxy_authentication_type type;

    union {
        struct aws_http_proxy_authentication_basic_options basic_options;
    } type_options;
};

struct aws_http_proxy_options {

    struct aws_byte_cursor host;

    uint16_t port;

    struct aws_http_proxy_authentication_options auth;

};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options,
                                      const struct aws_http_proxy_options *proxy_options);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_PROXY_CONNECTION_H */
