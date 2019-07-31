#ifndef AWS_HTTP_PROXY_TEST_HELPER_H
#define AWS_HTTP_PROXY_TEST_HELPER_H

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

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/tls_channel_handler.h>

struct aws_http_client_bootstrap;

typedef void(aws_http_release_connection_fn)(struct aws_http_connection *connection);

struct proxy_tester_options {
    struct aws_allocator *alloc;
    struct aws_http_proxy_options *proxy_options;
    struct aws_byte_cursor host;
    uint16_t port;
    bool use_tls;

    aws_http_release_connection_fn *release_connection;
};

struct proxy_tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;
    struct aws_event_loop_group event_loop_group;
    struct aws_host_resolver host_resolver;
    struct aws_client_bootstrap *client_bootstrap;

    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_connection_options tls_connection_options;

    struct aws_http_proxy_options *proxy_options;
    struct aws_byte_cursor host;
    uint16_t port;
    struct aws_http_connection *client_connection;
    aws_http_release_connection_fn *release_connection;
    struct aws_http_client_bootstrap *http_bootstrap;

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
};

int proxy_tester_wait(struct proxy_tester *tester, bool (*pred)(void *user_data));

bool proxy_tester_connection_setup_pred(void *user_data);
bool proxy_tester_connection_shutdown_pred(void *user_data);
bool proxy_tester_request_complete_pred_fn(void *user_data);

int proxy_tester_init(struct proxy_tester *tester, const struct proxy_tester_options *options);

int proxy_tester_clean_up(struct proxy_tester *tester);

void proxy_tester_on_client_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data);

void proxy_tester_on_client_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);

#endif /* AWS_HTTP_PROXY_TEST_HELPER_H */
