#ifndef AWS_HTTP_PROXY_TEST_HELPER_H
#define AWS_HTTP_PROXY_TEST_HELPER_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/http/proxy.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/tls_channel_handler.h>

struct aws_http_client_bootstrap;
struct testing_channel;

typedef void(aws_http_release_connection_fn)(struct aws_http_connection *connection);

enum proxy_tester_test_mode {
    PTTM_HTTP_FORWARD = 0,
    PTTM_HTTP_TUNNEL,
    PTTM_HTTPS_TUNNEL,
};

enum proxy_tester_failure_type {
    PTFT_NONE = 0,
    PTFT_CONNECT_REQUEST,
    PTFT_TLS_NEGOTIATION,
    PTFT_CHANNEL,
    PTFT_CONNECTION,
    PTFT_PROXY_STRATEGY,
};

struct proxy_tester_options {
    struct aws_allocator *alloc;
    struct aws_http_proxy_options *proxy_options;
    struct aws_byte_cursor host;
    uint16_t port;
    enum proxy_tester_test_mode test_mode;
    enum proxy_tester_failure_type failure_type;

    uint32_t desired_connect_response_count;
    struct aws_byte_cursor *desired_connect_responses;
};

struct proxy_tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;
    struct aws_client_bootstrap *client_bootstrap;

    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_connection_options tls_connection_options;

    struct aws_http_proxy_options proxy_options;
    struct aws_byte_cursor host;
    uint16_t port;

    enum proxy_tester_test_mode test_mode;
    enum proxy_tester_failure_type failure_type;

    struct aws_http_connection *client_connection;
    struct aws_array_list testing_channels;

    bool client_connection_is_setup;
    bool client_connection_is_shutdown;

    /* If we need to wait for some async process*/
    struct aws_mutex wait_lock;
    struct aws_condition_variable wait_cvar;
    int wait_result;
    bool request_successful;
    bool request_complete;

    bool tls_finished;
    bool tls_successful;

    struct aws_byte_buf connection_host_name;
    uint16_t connection_port;

    struct aws_array_list connect_requests;

    uint32_t current_response_index;
    struct aws_array_list desired_connect_responses;
};

int proxy_tester_wait(struct proxy_tester *tester, bool (*pred)(void *user_data));

bool proxy_tester_connection_setup_pred(void *user_data);
bool proxy_tester_connection_complete_pred(void *user_data);
bool proxy_tester_connection_shutdown_pred(void *user_data);
bool proxy_tester_request_complete_pred_fn(void *user_data);

int proxy_tester_init(struct proxy_tester *tester, const struct proxy_tester_options *options);

int proxy_tester_clean_up(struct proxy_tester *tester);

void proxy_tester_on_client_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data);

void proxy_tester_on_client_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);

void proxy_tester_on_client_bootstrap_shutdown(void *user_data);

int proxy_tester_create_testing_channel_connection(
    struct proxy_tester *tester,
    struct aws_http_client_bootstrap *http_bootstrap);

int proxy_tester_verify_connect_request(struct proxy_tester *tester);

int proxy_tester_send_connect_response(struct proxy_tester *tester);

int proxy_tester_verify_connection_attempt_was_to_proxy(
    struct proxy_tester *tester,
    struct aws_byte_cursor expected_host,
    uint16_t expected_port);

struct testing_channel *proxy_tester_get_current_channel(struct proxy_tester *tester);

#endif /* AWS_HTTP_PROXY_TEST_HELPER_H */
