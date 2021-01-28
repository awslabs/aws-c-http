#ifndef AWS_HTTP_PROXY_IMPL_H
#define AWS_HTTP_PROXY_IMPL_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/http.h>

#include <aws/http/connection.h>
#include <aws/http/status_code.h>
#include <aws/io/socket.h>

struct aws_http_connection_manager_options;
struct aws_http_message;
struct aws_channel_slot;
struct aws_string;
struct aws_tls_connection_options;
struct aws_http_proxy_strategy;
struct aws_http_proxy_strategy_tunneling_sequence_options;
struct aws_http_proxy_strategy_tunneling_kerberos_options;
struct aws_http_proxy_strategy_tunneling_ntlm_options;

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

    enum aws_http_proxy_connection_type connection_type;

    struct aws_byte_buf host;

    uint16_t port;

    struct aws_tls_connection_options *tls_options;

    struct aws_http_proxy_strategy *proxy_strategy;
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

    /*
     * dynamic proxy connection resolution state
     */
    enum aws_proxy_bootstrap_state state;
    int error_code;
    enum aws_http_status_code connect_status_code;
    struct aws_http_connection *connection;
    struct aws_http_message *connect_request;
    struct aws_http_stream *connect_stream;
    struct aws_http_proxy_negotiator *proxy_negotiator;

    /*
     * Cached original connect options
     */
    struct aws_string *original_host;
    uint16_t original_port;
    aws_http_on_client_connection_setup_fn *original_on_setup;
    aws_http_on_client_connection_shutdown_fn *original_on_shutdown;
    void *original_user_data;

    struct aws_tls_connection_options *tls_options;
    struct aws_client_bootstrap *bootstrap;
    struct aws_socket_options socket_options;
    bool manual_window_management;
    size_t initial_window_size;

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
struct aws_http_proxy_config *aws_http_proxy_config_new_from_connection_options(
    struct aws_allocator *allocator,
    const struct aws_http_client_connection_options *options);

AWS_HTTP_API
struct aws_http_proxy_config *aws_http_proxy_config_new_from_manager_options(
    struct aws_allocator *allocator,
    const struct aws_http_connection_manager_options *options);

AWS_HTTP_API
struct aws_http_proxy_config *aws_http_proxy_config_new_clone(
    struct aws_allocator *allocator,
    const struct aws_http_proxy_config *proxy_config);

AWS_HTTP_API
void aws_http_proxy_config_destroy(struct aws_http_proxy_config *config);

AWS_HTTP_API
void aws_http_proxy_options_init_from_config(
    struct aws_http_proxy_options *options,
    const struct aws_http_proxy_config *config);

/**
 * Checks if tunneling proxy negotiation should continue to try and connect
 * @param proxy_negotiator negotiator to query
 * @return true if another connect request should be attempted, false otherwise
 */
AWS_HTTP_API
bool aws_http_proxy_negotiator_should_retry(struct aws_http_proxy_negotiator *proxy_negotiator);

/**
 * Constructor for a tunnel-only proxy strategy that applies no changes to outbound CONNECT requests.  Intended to be
 * the first link in an adaptive sequence for a tunneling proxy: first try a basic CONNECT, then based on the response,
 * later links are allowed to make attempts.
 *
 * @param allocator memory allocator to use
 * @return a new proxy strategy if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_new_tunneling_one_time_identity(
    struct aws_allocator *allocator);

/**
 * Constructor for a forwarding-only proxy strategy that does nothing. Exists so that all proxy logic uses a
 * strategy.
 *
 * @param allocator memory allocator to use
 * @return a new proxy strategy if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_new_forwarding_identity(struct aws_allocator *allocator);

/**
 * Constructor for a tunneling proxy strategy that contains a set of sub-strategies which are tried
 * sequentially in order.  Each strategy is tried against a new, fresh connection.
 *
 * @param allocator memory allocator to use
 * @param config sequence configuration options
 * @return a new proxy strategy if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_new_tunneling_sequence(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_tunneling_sequence_options *config);

/**
 * A constructor for a proxy strategy that performs kerberos authentication by adding the appropriate
 * header and header value to CONNECT requests.
 *
 * @param allocator memory allocator to use
 * @param config kerberos authentication configuration info
 * @return a new proxy strategy if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_new_tunneling_kerberos(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_tunneling_kerberos_options *config);

/**
 * Constructor for an NTLM proxy strategy.  Because ntlm is a challenge-response authentication protocol, this
 * strategy will only succeed in a chain in a non-leading position.  The strategy extracts the challenge from the
 * proxy's response to a previous CONNECT request in the chain.
 *
 * @param allocator memory allocator to use
 * @param config configuration options for the strategy
 * @return a new proxy strategy if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_new_tunneling_ntlm(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_tunneling_ntlm_options *config);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_PROXY_IMPL_H */
