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

#include <aws/http/connection.h>
#include <aws/http/private/connection_impl.h>
#include <aws/http/private/proxy_impl.h>
#include <aws/http/server.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/log_writer.h>
#include <aws/common/uuid.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

#include "proxy_test_helper.h"

enum {
    TESTER_TIMEOUT_SEC = 60, /* Give enough time for non-sudo users to enter password */
};

void proxy_tester_on_client_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {

    struct proxy_tester *tester = user_data;
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

void proxy_tester_on_client_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    (void)connection;
    (void)error_code;
    struct proxy_tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->client_connection_is_shutdown = true;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

int proxy_tester_wait(struct proxy_tester *tester, bool (*pred)(void *user_data)) {
    ASSERT_SUCCESS(aws_mutex_lock(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&tester->wait_cvar, &tester->wait_lock, pred, tester));
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->wait_lock));

    return AWS_OP_SUCCESS;
}

bool proxy_tester_connection_setup_pred(void *user_data) {
    struct proxy_tester *tester = user_data;
    return tester->wait_result || tester->client_connection;
}

bool proxy_tester_connection_shutdown_pred(void *user_data) {
    struct proxy_tester *tester = user_data;
    return tester->wait_result || tester->client_connection_is_shutdown;
}

bool proxy_tester_request_complete_pred_fn(void *user_data) {
    struct proxy_tester *tester = user_data;
    return tester->request_complete || tester->client_connection_is_shutdown;
}

int proxy_tester_init(struct proxy_tester *tester, const struct proxy_tester_options *options) {
    AWS_ZERO_STRUCT(*tester);

    tester->alloc = options->alloc;

    aws_load_error_strings();
    aws_common_load_log_subject_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();

    aws_http_library_init(options->alloc);

    tester->host = options->host;
    tester->port = options->port;
    tester->release_connection = options->release_connection;
    tester->proxy_options = options->proxy_options;

    ASSERT_SUCCESS(aws_byte_buf_init(&tester->connection_host_name, tester->alloc, 128));

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    ASSERT_SUCCESS(aws_mutex_init(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&tester->wait_cvar));

    ASSERT_SUCCESS(aws_event_loop_group_default_init(&tester->event_loop_group, tester->alloc, 1));
    ASSERT_SUCCESS(aws_host_resolver_init_default(&tester->host_resolver, tester->alloc, 8, &tester->event_loop_group));

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    tester->client_bootstrap =
        aws_client_bootstrap_new(tester->alloc, &tester->event_loop_group, &tester->host_resolver, NULL);
    ASSERT_NOT_NULL(tester->client_bootstrap);

    if (options->use_tls) {
        aws_tls_init_static_state(tester->alloc);

        aws_tls_ctx_options_init_default_client(&tester->tls_ctx_options, tester->alloc);
        aws_tls_ctx_options_set_alpn_list(&tester->tls_ctx_options, "http/1.1");
        tester->tls_ctx_options.verify_peer = false;

        tester->tls_ctx = aws_tls_client_ctx_new(tester->alloc, &tester->tls_ctx_options);

        aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);
        aws_tls_connection_options_set_server_name(&tester->tls_connection_options, tester->alloc, &tester->host);
    }

    /* Connect */
    struct aws_http_client_connection_options client_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    client_options.allocator = tester->alloc;
    client_options.bootstrap = tester->client_bootstrap;
    client_options.host_name = tester->host;
    client_options.port = tester->port;
    client_options.socket_options = &socket_options;
    client_options.tls_options = options->use_tls ? &tester->tls_connection_options : NULL;
    client_options.user_data = tester;
    client_options.on_setup = proxy_tester_on_client_connection_setup;
    client_options.on_shutdown = proxy_tester_on_client_connection_shutdown;
    if (options->proxy_options) {
        client_options.proxy_options = options->proxy_options;
    }

    aws_http_client_connect(&client_options);

    /* Wait for server & client connections to finish setup */
    ASSERT_SUCCESS(proxy_tester_wait(tester, proxy_tester_connection_setup_pred));

    return AWS_OP_SUCCESS;
}

int proxy_tester_clean_up(struct proxy_tester *tester) {
    if (tester->client_connection) {
        if (tester->release_connection) {
            tester->release_connection(tester->client_connection);
        } else {
            aws_http_connection_release(tester->client_connection);
        }

        ASSERT_SUCCESS(proxy_tester_wait(tester, proxy_tester_connection_shutdown_pred));

        if (tester->http_bootstrap != NULL) {
            if (tester->proxy_options != NULL) {
                aws_http_proxy_user_data_destroy(tester->http_bootstrap->user_data);
            }
            aws_mem_release(tester->alloc, tester->http_bootstrap);
        }
    }

    aws_client_bootstrap_release(tester->client_bootstrap);

    aws_host_resolver_clean_up(&tester->host_resolver);
    aws_event_loop_group_clean_up(&tester->event_loop_group);

    if (tester->tls_ctx) {
        aws_tls_connection_options_clean_up(&tester->tls_connection_options);
        aws_tls_ctx_destroy(tester->tls_ctx);
        aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    }

    aws_tls_clean_up_static_state();

    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);

    aws_byte_buf_clean_up(&tester->connection_host_name);

    return AWS_OP_SUCCESS;
}
