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

struct aws_http_proxy_negotiator;
struct aws_http_proxy_strategy;

/**
 * Synchronous (for now) callback function to fetch a token used in modifying CONNECT requests
 */
typedef struct aws_string *(aws_http_proxy_negotiation_get_token_sync_fn)(void *user_data, int *out_error_code);

/**
 * Synchronous (for now) callback function to fetch a token used in modifying CONNECT request.  Includes a (byte string)
 * context intended to be used as part of a challenge-response flow.
 */
typedef struct aws_string *(aws_http_proxy_negotiation_get_challenge_token_sync_fn)(
    void *user_data,
    const struct aws_byte_cursor *challenge_context,
    int *out_error_code);

/**
 * Proxy negotiation logic must call this function to indicate an unsuccessful outcome
 */
typedef void(aws_http_proxy_negotiation_terminate_fn)(
    struct aws_http_message *message,
    int error_code,
    void *internal_proxy_user_data);

/**
 * Proxy negotiation logic must call this function to forward the potentially-mutated request back to the proxy
 * connection logic.
 */
typedef void(aws_http_proxy_negotiation_http_request_forward_fn)(
    struct aws_http_message *message,
    void *internal_proxy_user_data);

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
 * synchronous version for forwarding proxies.  Also forwarding proxies are a kind of legacy dead-end in some
 * sense.
 *
 */
typedef void(aws_http_proxy_negotiation_http_request_transform_async_fn)(
    struct aws_http_proxy_negotiator *proxy_negotiator,
    struct aws_http_message *message,
    aws_http_proxy_negotiation_terminate_fn *negotiation_termination_callback,
    aws_http_proxy_negotiation_http_request_forward_fn *negotiation_http_request_forward_callback,
    void *internal_proxy_user_data);

typedef int(aws_http_proxy_negotiation_http_request_transform_fn)(
    struct aws_http_proxy_negotiator *proxy_negotiator,
    struct aws_http_message *message);

/**
 * Tunneling proxy connections only.  A callback that lets the negotiator examine the headers in the
 * response to the most recent CONNECT request as they arrive.
 */
typedef int(aws_http_proxy_negotiation_connect_on_incoming_headers_fn)(
    struct aws_http_proxy_negotiator *proxy_negotiator,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers);

/**
 * Tunneling proxy connections only.  A callback that lets the negotiator examine the status code of the
 * response to the most recent CONNECT request.
 */
typedef int(aws_http_proxy_negotiator_connect_status_fn)(
    struct aws_http_proxy_negotiator *proxy_negotiator,
    enum aws_http_status_code status_code);

/**
 * Tunneling proxy connections only.  A callback that lets the negotiator examine the body of the response
 * to the most recent CONNECT request.
 */
typedef int(aws_http_proxy_negotiator_connect_on_incoming_body_fn)(
    struct aws_http_proxy_negotiator *proxy_negotiator,
    const struct aws_byte_cursor *data);

enum aws_http_proxy_negotiation_retry_directive {
    AWS_HPNRD_STOP,
    AWS_HPNRD_NEW_CONNECTION,
    AWS_HPNRD_CURRENT_CONNECTION,
};

typedef enum aws_http_proxy_negotiation_retry_directive(aws_http_proxy_negotiator_get_retry_directive_fn)(struct aws_http_proxy_negotiator *proxy_negotiator);

/**
 * Vtable for forwarding-based proxy negotiators
 */
struct aws_http_proxy_negotiator_forwarding_vtable {
    aws_http_proxy_negotiation_http_request_transform_fn *forward_request_transform;
};

/**
 * Vtable for tunneling-based proxy negotiators
 */
struct aws_http_proxy_negotiator_tunnelling_vtable {
    aws_http_proxy_negotiation_http_request_transform_async_fn *connect_request_transform;

    aws_http_proxy_negotiation_connect_on_incoming_headers_fn *on_incoming_headers_callback;
    aws_http_proxy_negotiator_connect_status_fn *on_status_callback;
    aws_http_proxy_negotiator_connect_on_incoming_body_fn *on_incoming_body_callback;

    aws_http_proxy_negotiator_get_retry_directive_fn *get_retry_directive;
};

/*
 * Base definition of a proxy negotiator.
 *
 * A negotiator works differently based on what kind of proxy connection is being asked for:
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
struct aws_http_proxy_negotiator {
    struct aws_ref_count ref_count;

    void *impl;

    union {
        struct aws_http_proxy_negotiator_forwarding_vtable *forwarding_vtable;
        struct aws_http_proxy_negotiator_tunnelling_vtable *tunnelling_vtable;
    } strategy_vtable;
};

/*********************************************************************************************/

typedef struct aws_http_proxy_negotiator *(aws_http_proxy_strategy_create_negotiator_fn)(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_allocator *allocator);

struct aws_http_proxy_strategy_vtable {
    aws_http_proxy_strategy_create_negotiator_fn *create_negotiator;
};

struct aws_http_proxy_strategy {
    struct aws_ref_count ref_count;
    struct aws_http_proxy_strategy_vtable *vtable;
    void *impl;
    enum aws_http_proxy_connection_type proxy_connection_type;
};

struct aws_http_proxy_strategy_basic_auth_options {

    /* type of proxy connection being established, must be forwarding or tunnel */
    enum aws_http_proxy_connection_type proxy_connection_type;

    /* user name to use in basic authentication */
    struct aws_byte_cursor user_name;

    /* password to use in basic authentication */
    struct aws_byte_cursor password;
};

struct aws_http_proxy_strategy_tunneling_kerberos_options {

    aws_http_proxy_negotiation_get_token_sync_fn *get_token;

    void *get_token_user_data;
};

struct aws_http_proxy_strategy_tunneling_ntlm_options {

    aws_http_proxy_negotiation_get_token_sync_fn *get_token;

    aws_http_proxy_negotiation_get_challenge_token_sync_fn *get_challenge_token;

    void *get_challenge_token_user_data;
};

struct aws_http_proxy_strategy_tunneling_adaptive_options {
    /*
     * If non-null, will insert a kerberos proxy strategy into the adaptive sequence
     */
    struct aws_http_proxy_strategy_tunneling_kerberos_options *kerberos_options;

    /*
     * If non-null will insert an ntlm proxy strategy into the adaptive sequence
     */
    struct aws_http_proxy_strategy_tunneling_ntlm_options *ntlm_options;
};

struct aws_http_proxy_strategy_tunneling_sequence_options {
    struct aws_http_proxy_strategy **strategies;

    uint32_t strategy_count;
};

AWS_EXTERN_C_BEGIN

/**
 * Take a reference to an http proxy negotiator
 * @param proxy_negotiator negotiator to take a reference to
 * @return the strategy
 */
AWS_HTTP_API
struct aws_http_proxy_negotiator *aws_http_proxy_negotiator_acquire(struct aws_http_proxy_negotiator *proxy_negotiator);

/**
 * Release a reference to an http proxy negotiator
 * @param proxy_negotiator negotiator to release a reference to
 */
AWS_HTTP_API
void aws_http_proxy_negotiator_release(struct aws_http_proxy_negotiator *proxy_negotiator);

/**
 * Creates a new proxy negotiator from a proxy strategy
 * @param allocator memory allocator to use
 * @param strategy strategy to creation a new negotiator for
 * @return a new proxy negotiator if successful, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_negotiator *aws_http_proxy_strategy_create_negotiator(
    struct aws_http_proxy_strategy *strategy,
    struct aws_allocator *allocator);

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
 * A constructor for a proxy strategy that performs basic authentication by adding the appropriate
 * header and header value to requests or CONNECT requests.
 *
 * @param allocator memory allocator to use
 * @param config basic authentication configuration info
 * @return a new proxy strategy if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_new_basic_auth(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_basic_auth_options *config);

/**
 * Constructor for an adaptive tunneling proxy strategy.  This strategy attempts a vanilla CONNECT and if that
 * fails it may make followup CONNECT attempts using kerberos or ntlm tokens, based on configuration and proxy
 * response properties.
 *
 * @param allocator memory allocator to use
 * @param config configuration options for the strategy
 * @return a new proxy strategy if successfully constructed, otherwise NULL
 */
AWS_HTTP_API
struct aws_http_proxy_strategy *aws_http_proxy_strategy_new_tunneling_adaptive(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_tunneling_adaptive_options *config);
AWS_EXTERN_C_END

#endif /* AWS_PROXY_STRATEGY_H */
