#ifndef AWS_PROXY_STRATEGY_H
#define AWS_PROXY_STRATEGY_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/ref_count.h>
#include <aws/http/connection.h>
#include <aws/http/http.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>

struct aws_http_message;
struct aws_http_header;

struct aws_http_proxy_strategy;
struct aws_http_proxy_strategy_factory;

/**
 * Proxy strategy logic must call this function to indicate an unsuccessful outcome
 */
typedef void(aws_http_proxy_strategy_terminate_fn)(
    struct aws_http_message *message,
    int error_code,
    void *internal_proxy_user_data);

/**
 * Proxy strategy logic must call this function to forward the potentially-mutated request back to the proxy
 * strategy coordination logic.
 */
typedef void(
    aws_http_proxy_strategy_http_request_forward_fn)(struct aws_http_message *message, void *internal_proxy_user_data);

/**
 * User-supplied transform callback which implements the proxy request flow and ultimately, across all execution
 * pathways, invokes either the terminate function or the forward function appropriately.
 *
 * For tunneling proxy connections, this request flow transform only applies to the CONNECT stage of proxy
 * connection establishment.
 *
 * For forwarding proxy connections, this request flow transform applies to every single http request that goes
 * out on the connection.
 *
 * Forwarding proxy connections cannot yet support a truly async request transform without major surgery on http
 * stream creation, so for now, we split into an async version (for tunneling proxies) and a separate
 * synchronous version for forwarding proxies.
 *
 */
typedef void(aws_http_proxy_strategy_http_request_transform_async_fn)(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_http_message *message,
    aws_http_proxy_strategy_terminate_fn *strategy_termination_callback,
    aws_http_proxy_strategy_http_request_forward_fn *strategy_http_request_forward_callback,
    void *internal_proxy_user_data);

typedef int(aws_http_proxy_strategy_http_request_transform_fn)(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_http_message *message);

/**
 * Tunneling proxy connections only.  A callback that lets the strategy examine the headers in the
 * response to the most recent CONNECT request as they arrive.
 */
typedef int(aws_http_proxy_strategy_connect_on_incoming_headers_fn)(
    struct aws_http_proxy_strategy *proxy_strategy,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers);

/**
 * Tunneling proxy connections only.  A callback that lets the strategy examine the status code of the
 * response to the most recent CONNECT request.
 */
typedef int(aws_http_proxy_strategy_connect_status_fn)(
    struct aws_http_proxy_strategy *proxy_strategy,
    enum aws_http_status_code status_code);

/**
 * Tunneling proxy connections only.  A callback that lets the strategy examine the body of the response
 * to the most recent CONNECT request.
 */
typedef int(aws_http_proxy_strategy_connect_on_incoming_body_fn)(
    struct aws_http_proxy_strategy *proxy_strategy,
    const struct aws_byte_cursor *data);

/**
 * Destructor for a proxy strategy.  A standard pattern is to
 * make the user data a structure that also embeds the aws_proxy_strategy as a member, letting the destructor
 * clean up everything in a single shot.
 */
typedef void(aws_http_proxy_strategy_destroy_fn)(struct aws_http_proxy_strategy *proxy_strategy);

struct aws_http_proxy_strategy_forwarding_vtable {
    aws_http_proxy_strategy_http_request_transform_fn *forward_request_transform;
};

struct aws_http_proxy_strategy_tunnelling_vtable {
    aws_http_proxy_strategy_http_request_transform_async_fn *connect_request_transform;

    aws_http_proxy_strategy_connect_on_incoming_headers_fn *on_incoming_headers_callback;
    aws_http_proxy_strategy_connect_status_fn *on_status_callback;
    aws_http_proxy_strategy_connect_on_incoming_body_fn *on_incoming_body_callback;
};

/*
 * Configuration definition of a proxy stategy.  Contains a proxy-type-specific vtable, user_data (usually a
 * strategy-specific struct that embeds the aws_proxy_strategy), and a destructor.
 *
 * A strategy works differently based on what kind of proxy connection is being asked for:
 *
 * (1) Tunneling - In a tunneling proxy connection, the connect_request_transform is invoked on every CONNECT request.
 * The connect_request_transform implementation *MUST*, in turn, eventually call one of the terminate or forward
 * functions it gets supplied with.
 *
 *  Every CONNECT request, if a response is obtained, will properly invoke the response handling callbacks supplied
 *  in the tunneling vtable.
 *
 * (2) Forwarding - In a forwarding proxy connection, the forward_request_transform is invoked on every request sent out
 * on the connection.
 *
 * (3) Socks5 - not yet supported
 */
struct aws_http_proxy_strategy {
    struct aws_ref_count ref_count;

    void *impl;

    union {
        struct aws_http_proxy_strategy_forwarding_vtable *forwarding_vtable;
        struct aws_http_proxy_strategy_tunnelling_vtable *tunnelling_vtable;
    } strategy_vtable;
};

/*********************************************************************************************/

typedef struct aws_http_proxy_strategy *(aws_http_proxy_strategy_factory_create_strategy_fn)(
    struct aws_http_proxy_strategy_factory *proxy_strategy_factory,
    struct aws_allocator *allocator);

struct aws_http_proxy_strategy_factory_vtable {
    aws_http_proxy_strategy_factory_create_strategy_fn *create_strategy;
};

struct aws_http_proxy_strategy_factory {
    struct aws_ref_count ref_count;
    struct aws_http_proxy_strategy_factory_vtable *vtable;
    void *impl;
    enum aws_http_proxy_connection_type proxy_connection_type;
};


struct aws_http_proxy_strategy_factory_kerberos_auth_config {

    /* type of proxy connection being established, must be forwarding or tunnel */
    enum aws_http_proxy_connection_type proxy_connection_type;

    /* user token to use in kerberos authentication */
    struct aws_byte_cursor user_token;

};

struct aws_http_proxy_strategy_factory_basic_auth_config {

    /* type of proxy connection being established, must be forwarding or tunnel */
    enum aws_http_proxy_connection_type proxy_connection_type;

    /* user name to use in basic authentication */
    struct aws_byte_cursor user_name;

    /* password to use in basic authentication */
    struct aws_byte_cursor password;
};

struct aws_http_proxy_strategy_factory_tunneling_chain_options {
    struct aws_http_proxy_strategy_factory **factories;

    uint32_t factory_count;
};

/*
 * The adaptive test strategy attempts a bad basic CONNECT and if that fails it attempts a regular basic auth
 * CONNECT.
 */
struct aws_http_proxy_strategy_factory_tunneling_adaptive_test_options {
    /* user name to use in basic authentication */
    struct aws_byte_cursor user_name;

    /* password to use in basic authentication */
    struct aws_byte_cursor password;
};

/*
 * SA-TBI: add any configuration needed for kerberos auth negotiation here
 */
struct aws_http_proxy_strategy_factory_tunneling_kerberos_options {
    bool placeholder;
};

struct aws_http_proxy_strategy_factory_tunneling_adaptive_kerberos_options {
    struct aws_http_proxy_strategy_factory_tunneling_kerberos_options kerberos_options;
    

};

AWS_EXTERN_C_BEGIN

/**
 * Take a reference to an http proxy strategy
 * @param proxy_strategy strategy to take a reference to
 * @return the strategy
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_acquire(struct aws_http_proxy_strategy *proxy_strategy);

/**
 * Release a reference to an http proxy strategy
 * @param proxy_strategy strategy to release a reference to
 */
AWS_HTTP_API
void aws_http_proxy_strategy_release(struct aws_http_proxy_strategy *proxy_strategy);

/**
 * Creates a new proxy strategy from the factory according to the factory's configuration
 * @param allocator memory allocator to use
 * @return a new proxy strategy if successful, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_factory_create_strategy(
    struct aws_http_proxy_strategy_factory *factory,
    struct aws_allocator *allocator);

/**
 * Take a reference to an http proxy strategy factory
 * @param proxy_strategy_factory factory to take a reference to
 * @return the factory
 */
AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_acquire(
    struct aws_http_proxy_strategy_factory *proxy_strategy_factory);

/**
 * Release a reference to an http proxy strategy factory
 * @param proxy_strategy_factory factory to release a reference to
 */
AWS_HTTP_API
void aws_http_proxy_strategy_factory_release(struct aws_http_proxy_strategy_factory *proxy_strategy_factory);



/**
 * A constructor for a proxy strategy factory that performs kerberos authentication by adding the appropriate
 * header and header value to requests or CONNECT requests.
 *
 * @param allocator memory allocator to use
 * @param config kerberos authentication configuration info
 * @return a new proxy strategy factory if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_kerberos_auth(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_kerberos_auth_config *config);



/**
 * A constructor for a proxy strategy factory that performs basic authentication by adding the appropriate
 * header and header value to requests or CONNECT requests.
 *
 * @param allocator memory allocator to use
 * @param config basic authentication configuration info
 * @return a new proxy strategy factory if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_basic_auth(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_basic_auth_config *config);

/**
 * Factory constructor for a tunnel-only proxy request flow that does nothing.  Intended to be the first link in an
 * adaptive chain for a tunneling proxy: first try a basic CONNECT, then based on the response, later links are allowed
 * to make attempts.
 *
 * @param allocator memory allocator to use
 * @return a new proxy strategy factory if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_tunneling_one_time_identity(
    struct aws_allocator *allocator);

/**
 * Factory constructor for a tunneling proxy strategy that contains a chain of sub-strategies which are tried
 * sequentially in order.
 *
 * @param allocator memory allocator to use
 * @param config chain configuration info
 * @return a new proxy strategy factory if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_tunneling_chain(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_tunneling_chain_options *config);

/**
 * Factory constructor for a forwarding-only proxy strategy that does nothing. Exists so that all proxy logic uses a
 * strategy.
 *
 * @param allocator memory allocator to use
 * @return a new proxy strategy factory if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_forwarding_identity(
    struct aws_allocator *allocator);

/**
 * This is an experimental API.
 *
 * Constructor for a WIP adaptive tunneling proxy strategy.  This strategy attempts a bad basic auth CONNECT and if that
 * fails it attempts a configurable basic auth CONNECT.
 *
 * @param allocator memory allocator to use
 * @param config configuration options for the strategy factory
 * @return a new proxy strategy factory if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_tunneling_adaptive_test(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_tunneling_adaptive_test_options *config);

/**
 * This is an experimental API.
 *
 * Constructor for a WIP adaptive tunneling proxy strategy.  This strategy attempts a vanilla CONNECT and if that
 * fails it attempts a kerberos-oriented CONNECT (if applicable).
 *
 * @param allocator memory allocator to use
 * @param config configuration options for the strategy factory
 * @return a new proxy strategy factory if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_tunneling_adaptive_kerberos(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_tunneling_adaptive_kerberos_options *config);

AWS_EXTERN_C_END

#endif /* AWS_PROXY_STRATEGY_H */
