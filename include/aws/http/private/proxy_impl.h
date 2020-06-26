#ifndef AWS_HTTP_PROXY_IMPL_H
#define AWS_HTTP_PROXY_IMPL_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/http.h>

#include <aws/http/connection.h>

struct aws_http_message;
struct aws_channel_slot;
struct aws_string;
struct aws_tls_connection_options;

/*
 * (Successful) State transitions for proxy connections
 *
 * Http : None -> Socket Connect -> Success
 * Https: None -> Socket Connect -> Http Connect -> Tls Negotiation -> Success
 */
enum aws_proxy_bootstrap_state {
    AWS_PBS_NONE = 0,
    AWS_PBS_SOCKET_CONNECT,
    AWS_PBS_HTTP_CONNECT,
    AWS_PBS_TLS_NEGOTIATION,
    AWS_PBS_SUCCESS,
    AWS_PBS_FAILURE,
};

/**
 * A persistent copy of the aws_http_proxy_options struct.  Clones everything appropriate.
 */
struct aws_http_proxy_config {

    struct aws_allocator *allocator;

    struct aws_byte_buf host;

    uint16_t port;

    struct aws_tls_connection_options *tls_options;

    enum aws_http_proxy_authentication_type auth_type;

    struct aws_byte_buf auth_username;

    struct aws_byte_buf auth_password;
};

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

    enum aws_proxy_bootstrap_state state;
    int error_code;
    struct aws_http_connection *connection;
    struct aws_http_message *connect_request;
    struct aws_http_stream *connect_stream;

    struct aws_string *original_host;
    uint16_t original_port;
    aws_http_on_client_connection_setup_fn *original_on_setup;
    aws_http_on_client_connection_shutdown_fn *original_on_shutdown;
    void *original_user_data;

    struct aws_tls_connection_options *tls_options;

    struct aws_http_proxy_config *proxy_config;
};

struct aws_http_proxy_system_vtable {
    int (*setup_client_tls)(struct aws_channel_slot *right_of_slot, struct aws_tls_connection_options *tls_options);
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
struct aws_http_proxy_user_data *aws_http_proxy_user_data_new(
    struct aws_allocator *allocator,
    const struct aws_http_client_connection_options *options);

AWS_HTTP_API
void aws_http_proxy_user_data_destroy(struct aws_http_proxy_user_data *user_data);

AWS_HTTP_API
int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options);

AWS_HTTP_API
int aws_http_rewrite_uri_for_proxy_request(
    struct aws_http_message *request,
    struct aws_http_proxy_user_data *proxy_user_data);

AWS_HTTP_API
void aws_http_proxy_system_set_vtable(struct aws_http_proxy_system_vtable *vtable);

AWS_HTTP_API
struct aws_http_proxy_config *aws_http_proxy_config_new(
    struct aws_allocator *allocator,
    const struct aws_http_proxy_options *options);

AWS_HTTP_API
void aws_http_proxy_config_destroy(struct aws_http_proxy_config *config);

AWS_HTTP_API
void aws_http_proxy_options_init_from_config(
    struct aws_http_proxy_options *options,
    const struct aws_http_proxy_config *config);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_PROXY_IMPL_H */
