#ifndef AWS_PROXY_REQUEST_FLOW_H
#define AWS_PROXY_REQUEST_FLOW_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/http.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>

struct aws_http_message;
struct aws_http_header;

/**
 * The proxy request transform callback implementation *MUST* call one of these two functions for every possible
 * (async) execution pathway.
 */

/**
 * Custom request flow logic must call this function to indicate an unsuccessful outcome
 */
typedef void(aws_proxy_request_flow_terminate_fn)(int error_code, void *internal_proxy_user_data);

/**
 * Custom request flow logic must call this function to forward the potentially-mutated request back to the proxy
 * flow coordination logic.
 */
typedef void(aws_proxy_request_flow_forward_fn)(struct aws_http_message *message, void *internal_proxy_user_data);

/**
 * Wrapper for the proxy flow callback functions that the user must use to continue or terminate the proxy
 * request flow.
 */
struct aws_proxy_flow_callback_function_table {
    aws_proxy_request_flow_terminate_fn *terminate_fn;
    aws_proxy_request_flow_forward_fn *forward_fn;
};

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
 */
typedef void(aws_proxy_request_transform_fn)(
    struct aws_http_message *message,
    struct aws_proxy_flow_callback_function_table flow_callback_table,
    void *flow_user_data,
    void *internal_proxy_user_data);

/**
 * Tunneling proxy connections only.  A callback that lets the custom request flow examine the headers in the
 * response to the most recent CONNECT request as they arrive.
 */
typedef int(aws_http_proxy_connect_on_incoming_headers_fn)(
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data);

/**
 * Tunneling proxy connections only.  A callback that lets the custom request flow examine the status code of the
 * response to the CONNECT request.
 */
typedef int(aws_http_proxy_connect_status_fn)(enum aws_http_status_code status_code, void *user_data);

/**
 * Tunneling proxy connections only.  A callback that lets the custom request flow examine the body of the response
 * to the CONNECT request.
 */
typedef int(aws_http_proxy_connect_on_incoming_body_fn)(const struct aws_byte_cursor *data, void *user_data);

/**
 * User-supplied destructor for the user_data associated with this custom request flow.  A standard pattern is to
 * make the user data a structure that also embeds the aws_proxy_request_flow as a member, letting the destructor
 * clean up everything in a single shot.
 */
typedef void(aws_http_proxy_request_flow_user_data_destroy_fn)(void *user_data);

/*
 * Configuration definition of a custom proxy request flow, containing a transform for requests (CONNECT-only for
 * tunneling proxy connections) and CONNECT response handling callbacks.
 *
 * A custom request flow works differently based on what kind of proxy connection is being asked for:
 *
 * (1) Tunneling - In a tunneling proxy connection, the request_transform is invoked on every CONNECT request, and
 *  nothing more.  The request_transform implementation *MUST*, in turn, call one of terminate or forward functions
 *  from the supplied flow_callback_table.
 *
 *  Every CONNECT request, if a response is obtained, will properly invoke the response handling callbacks supplied
 *  in the proxy request flow.
 *
 * (2) Forwarding - In a tunneling proxy connection, the request_transform is invoked on every request sent out
 * on the connection.  The response handling callbacks are unused.
 */
struct aws_proxy_request_flow {

    /*
     * Required.  A custom proxy request flow is nonsensical without doing something here.
     */
    aws_proxy_request_transform_fn *request_transform;

    /*
     * Tunnel-only response handling callbacks that let the request flow process the response to a CONNECT request.
     */
    aws_http_proxy_connect_on_incoming_headers_fn *on_incoming_headers_callback;
    aws_http_proxy_connect_status_fn *on_status_callback;
    aws_http_proxy_connect_on_incoming_body_fn *on_incoming_body_callback;

    aws_http_proxy_request_flow_user_data_destroy_fn *destroy_fn;
    void *user_data;
};

AWS_EXTERN_C_BEGIN

struct aws_proxy_request_flow *aws_proxy_request_flow_new_basic_auth(
    struct aws_byte_cursor user_name,
    struct aws_byte_cursor password);

AWS_EXTERN_C_END

#endif /* AWS_PROXY_REQUEST_FLOW_H */
