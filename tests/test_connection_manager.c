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

#include <aws/testing/aws_test_harness.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/uuid.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/server.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

struct cm_tester_options {
    struct aws_allocator *allocator;
    size_t max_connections;
};

struct cm_tester {
    struct aws_allocator *allocator;
    struct aws_event_loop_group event_loop_group;
    struct aws_host_resolver host_resolver;

    struct aws_client_bootstrap *client_bootstrap;

    struct aws_http_connection_manager *connection_manager;

    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_connection_options tls_connection_options;

    struct aws_mutex wait_lock;
    struct aws_condition_variable wait_cvar;

    int wait_result;
};

#ifdef NEVER
static void s_tester_on_client_connection_setup(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    if (error_code) {
        tester->wait_result = error_code;
        goto done;
    }

    tester->client_connection = connection;
    done:
    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static void s_tester_on_client_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    (void)connection;
    (void)error_code;
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->client_connection_is_shutdown = true;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}
#endif

int s_cm_tester_init(struct cm_tester *tester, struct cm_tester_options *options) {
    AWS_ZERO_STRUCT(*tester);

    aws_tls_init_static_state(options->allocator);
    aws_http_library_init(options->allocator);
    aws_load_error_strings();
    aws_io_load_error_strings();

    tester->allocator = options->allocator;

    if (aws_mutex_init(&tester->wait_lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&tester->wait_cvar)) {
        return AWS_OP_ERR;
    }

    ASSERT_SUCCESS(aws_event_loop_group_default_init(&tester->event_loop_group, tester->allocator, 1));
    ASSERT_SUCCESS(aws_host_resolver_init_default(&tester->host_resolver, tester->allocator, 8, &tester->event_loop_group));
    tester->client_bootstrap =
            aws_client_bootstrap_new(tester->allocator, &tester->event_loop_group, &tester->host_resolver, NULL);
    ASSERT_NOT_NULL(tester->client_bootstrap);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms =
        (uint32_t)aws_timestamp_convert(60, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    aws_tls_ctx_options_init_default_client(&tester->tls_ctx_options, options->allocator);

    tester->tls_ctx = aws_tls_client_ctx_new(options->allocator, &tester->tls_ctx_options);
    ASSERT_NOT_NULL(tester->tls_ctx);

    aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);

    struct aws_http_connection_manager_options cm_options = {
        .bootstrap = tester->client_bootstrap,
        .initial_window_size = SIZE_MAX,
        .socket_options = &socket_options,
        .tls_connection_options = &tester->tls_connection_options,
        .host = aws_byte_cursor_from_c_str("https://s3.amazonaws.com/"),
        .port = 443,
        .max_connections = options->max_connections
    };

    tester->connection_manager = aws_http_connection_manager_new(tester->allocator, &cm_options);
    ASSERT_NOT_NULL(tester->connection_manager);

    return AWS_OP_SUCCESS;
}

void s_cm_tester_clean_up(struct cm_tester *tester) {
    if (tester == NULL) {
        return;
    }

    aws_http_connection_manager_release(tester->connection_manager);

    aws_client_bootstrap_release(tester->client_bootstrap);

    aws_host_resolver_clean_up(&tester->host_resolver);
    aws_event_loop_group_clean_up(&tester->event_loop_group);

    aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    aws_tls_connection_options_clean_up(&tester->tls_connection_options);
    aws_tls_ctx_destroy(tester->tls_ctx);

    aws_mutex_clean_up(&tester->wait_lock);
    aws_condition_variable_clean_up(&tester->wait_cvar);

    aws_http_library_clean_up();
    aws_tls_clean_up_static_state();
}

static int s_test_connection_manager_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 5
    };

    struct cm_tester tester;
    ASSERT_SUCCESS(s_cm_tester_init(&tester, &options));

    s_cm_tester_clean_up(&tester);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_setup_shutdown, s_test_connection_manager_setup_shutdown);