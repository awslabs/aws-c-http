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

#include <aws/common/array_list.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/common/uuid.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/private/connection_manager_function_table.h>
#include <aws/http/server.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

enum new_connection_result_type { AWS_NCRT_SUCCESS, AWS_NCRT_ERROR_VIA_CALLBACK, AWS_NCRT_ERROR_FROM_CREATE };

struct mock_connection_proxy {
    enum new_connection_result_type result;
    bool is_closed_on_release;
};

struct cm_tester_options {
    struct aws_allocator *allocator;
    struct aws_http_connection_manager_function_table *mock_table;
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

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_array_list connections;
    size_t connection_errors;
    size_t connection_releases;

    size_t wait_for_connection_count;

    struct aws_http_connection_manager_function_table *mock_table;

    struct aws_atomic_var next_connection_id;
    struct aws_array_list mock_connections;
    struct aws_atomic_var release_connection_fn;
};

static struct cm_tester s_tester;

int s_cm_tester_init(struct cm_tester_options *options) {
    struct cm_tester *tester = &s_tester;

    AWS_ZERO_STRUCT(*tester);

    aws_tls_init_static_state(options->allocator);
    aws_http_library_init(options->allocator);
    aws_load_error_strings();
    aws_io_load_error_strings();

    tester->allocator = options->allocator;

    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&tester->connections, tester->allocator, 10, sizeof(struct aws_http_connection *)));

    ASSERT_SUCCESS(aws_event_loop_group_default_init(&tester->event_loop_group, tester->allocator, 1));
    ASSERT_SUCCESS(
        aws_host_resolver_init_default(&tester->host_resolver, tester->allocator, 8, &tester->event_loop_group));
    tester->client_bootstrap =
        aws_client_bootstrap_new(tester->allocator, &tester->event_loop_group, &tester->host_resolver, NULL);
    ASSERT_NOT_NULL(tester->client_bootstrap);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms = (uint32_t)aws_timestamp_convert(60, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    aws_tls_ctx_options_init_default_client(&tester->tls_ctx_options, options->allocator);

    tester->tls_ctx = aws_tls_client_ctx_new(options->allocator, &tester->tls_ctx_options);
    ASSERT_NOT_NULL(tester->tls_ctx);

    aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);

    struct aws_http_connection_manager_options cm_options = {.bootstrap = tester->client_bootstrap,
                                                             .initial_window_size = SIZE_MAX,
                                                             .socket_options = &socket_options,
                                                             .tls_connection_options =
                                                                 NULL, //&tester->tls_connection_options,
                                                             .host = aws_byte_cursor_from_c_str("www.google.com"),
                                                             .port = 80,
                                                             .max_connections = options->max_connections,
                                                             .function_table = options->mock_table};

    tester->connection_manager = aws_http_connection_manager_new(tester->allocator, &cm_options);
    ASSERT_NOT_NULL(tester->connection_manager);

    tester->mock_table = options->mock_table;

    aws_atomic_store_int(&tester->next_connection_id, 0);
    aws_atomic_store_ptr(&tester->release_connection_fn, NULL);

    ASSERT_SUCCESS(aws_array_list_init_dynamic(
        &tester->mock_connections, tester->allocator, 10, sizeof(struct mock_connection_proxy *)));

    return AWS_OP_SUCCESS;
}

void s_add_mock_connections(size_t count, enum new_connection_result_type result, bool closed_on_release) {
    struct cm_tester *tester = &s_tester;

    for (size_t i = 0; i < count; ++i) {
        struct mock_connection_proxy *mock = aws_mem_acquire(tester->allocator, sizeof(struct mock_connection_proxy));
        AWS_ZERO_STRUCT(*mock);

        mock->result = result;
        mock->is_closed_on_release = closed_on_release;

        aws_array_list_push_back(&tester->mock_connections, &mock);
    }
}

void s_release_connections(size_t count, bool close_first) {

    struct cm_tester *tester = &s_tester;

    aws_mutex_lock(&tester->lock);

    size_t release_count = aws_array_list_length(&tester->connections);
    if (release_count > count) {
        release_count = count;
    }

    struct aws_array_list to_release;
    aws_array_list_init_dynamic(&to_release, tester->allocator, release_count, sizeof(struct aws_http_connection *));

    for (size_t i = 0; i < release_count; ++i) {
        struct aws_http_connection *connection = NULL;
        if (aws_array_list_back(&tester->connections, &connection)) {
            continue;
        }

        aws_array_list_pop_back(&tester->connections);

        aws_array_list_push_back(&to_release, &connection);
    }

    aws_mutex_unlock(&tester->lock);

    for (size_t i = 0; i < aws_array_list_length(&to_release); ++i) {
        struct aws_http_connection *connection = NULL;
        if (aws_array_list_get_at(&to_release, &connection, i)) {
            continue;
        }

        if (close_first) {
            if (tester->mock_table) {
                tester->mock_table->close_connection(connection);
            } else {
                aws_http_connection_close(connection);
            }
        }

        aws_http_connection_manager_release_connection(tester->connection_manager, connection);

        aws_mutex_lock(&tester->lock);
        ++tester->connection_releases;
        aws_condition_variable_notify_one(&tester->signal);
        aws_mutex_unlock(&tester->lock);
    }

    aws_array_list_clean_up(&to_release);
}

void s_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct cm_tester *tester = &s_tester;

    aws_mutex_lock(&tester->lock);

    if (connection == NULL) {
        ++tester->connection_errors;
    } else {
        aws_array_list_push_back(&tester->connections, &connection);
    }

    aws_condition_variable_notify_one(&tester->signal);

    aws_mutex_unlock(&tester->lock);
}

static void s_acquire_connections(size_t count) {
    struct cm_tester *tester = &s_tester;

    for (size_t i = 0; i < count; ++i) {
        aws_http_connection_manager_acquire_connection(tester->connection_manager, s_on_acquire_connection, tester);
    }
}

static bool s_is_connection_reply_count_at_least(void *context) {
    struct cm_tester *tester = &s_tester;

    return tester->wait_for_connection_count <=
           aws_array_list_length(&tester->connections) + tester->connection_errors + tester->connection_releases;
}

static void s_wait_on_connection_reply_count(size_t count) {
    struct cm_tester *tester = &s_tester;

    aws_mutex_lock(&tester->lock);

    tester->wait_for_connection_count = count;
    aws_condition_variable_wait_pred(&tester->signal, &tester->lock, s_is_connection_reply_count_at_least, tester);

    aws_mutex_unlock(&tester->lock);
}

void s_cm_tester_clean_up(void) {
    struct cm_tester *tester = &s_tester;

    s_release_connections(aws_array_list_length(&tester->connections), false);

    aws_array_list_clean_up(&tester->connections);

    for (size_t i = 0; i < aws_array_list_length(&tester->mock_connections); ++i) {
        struct mock_connection_proxy *mock = NULL;

        if (aws_array_list_get_at(&tester->mock_connections, &mock, i)) {
            continue;
        }

        aws_mem_release(tester->allocator, mock);
    }
    aws_array_list_clean_up(&tester->mock_connections);

    aws_http_connection_manager_release(tester->connection_manager);

    aws_client_bootstrap_release(tester->client_bootstrap);

    aws_host_resolver_clean_up(&tester->host_resolver);
    aws_event_loop_group_clean_up(&tester->event_loop_group);

    aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    aws_tls_connection_options_clean_up(&tester->tls_connection_options);
    aws_tls_ctx_destroy(tester->tls_ctx);

    aws_http_library_clean_up();
    aws_tls_clean_up_static_state();
}

static int s_test_connection_manager_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {.allocator = allocator, .max_connections = 5};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_setup_shutdown, s_test_connection_manager_setup_shutdown);

static int s_test_connection_manager_single_connection(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {.allocator = allocator, .max_connections = 5};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_acquire_connections(1);

    s_wait_on_connection_reply_count(1);

    s_release_connections(1, false);

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_single_connection, s_test_connection_manager_single_connection);

static int s_test_connection_manager_many_connections(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {.allocator = allocator, .max_connections = 20};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_acquire_connections(20);

    s_wait_on_connection_reply_count(20);

    s_release_connections(20, false);

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_many_connections, s_test_connection_manager_many_connections);

static int s_test_connection_manager_acquire_release(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {.allocator = allocator, .max_connections = 4};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_acquire_connections(20);

    s_wait_on_connection_reply_count(4);

    for (size_t i = 4; i < 20; ++i) {
        s_release_connections(1, false);

        s_wait_on_connection_reply_count(i + 1);
    }

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_acquire_release, s_test_connection_manager_acquire_release);

static int s_test_connection_manager_close_and_release(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {.allocator = allocator, .max_connections = 4};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_acquire_connections(20);

    s_wait_on_connection_reply_count(4);

    for (size_t i = 4; i < 20; ++i) {
        s_release_connections(1, i % 1 == 0);

        s_wait_on_connection_reply_count(i + 1);
    }

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_close_and_release, s_test_connection_manager_close_and_release);

static int s_test_connection_manager_acquire_release_mix(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {.allocator = allocator, .max_connections = 5};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    for (size_t i = 0; i < 10; ++i) {
        s_acquire_connections(2);

        s_wait_on_connection_reply_count(i + 1);

        s_release_connections(1, i % 1 == 0);
    }

    s_wait_on_connection_reply_count(15);

    for (size_t i = 15; i < 20; ++i) {
        s_release_connections(1, i % 1 == 0);

        s_wait_on_connection_reply_count(i + 1);
    }

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_acquire_release_mix, s_test_connection_manager_acquire_release_mix);

static int s_aws_http_connection_manager_create_connection_sync_mock(
    const struct aws_http_client_connection_options *options) {
    struct cm_tester *tester = &s_tester;

    size_t next_connection_id = aws_atomic_fetch_add(&tester->next_connection_id, 1);
    aws_atomic_store_ptr(&tester->release_connection_fn, options->on_shutdown);

    struct mock_connection_proxy *connection = NULL;

    if (next_connection_id < aws_array_list_length(&tester->mock_connections)) {
        aws_array_list_get_at(&tester->mock_connections, &connection, next_connection_id);
    }

    if (connection->result == AWS_NCRT_SUCCESS) {
        options->on_setup((struct aws_http_connection *)connection, AWS_ERROR_SUCCESS, options->user_data);
    } else if (connection->result == AWS_NCRT_ERROR_VIA_CALLBACK) {
        options->on_setup(NULL, AWS_ERROR_HTTP_UNKNOWN, options->user_data);
    }

    return connection->result != AWS_NCRT_ERROR_FROM_CREATE ? AWS_ERROR_SUCCESS : AWS_ERROR_HTTP_UNKNOWN;
}

static void s_aws_http_connection_manager_release_connection_sync_mock(struct aws_http_connection *connection) {
    (void)connection;

    struct cm_tester *tester = &s_tester;

    aws_http_on_client_connection_shutdown_fn *release_callback = aws_atomic_load_ptr(&tester->release_connection_fn);

    release_callback(connection, AWS_ERROR_SUCCESS, tester->connection_manager);
}

static void s_aws_http_connection_manager_close_connection_sync_mock(struct aws_http_connection *connection) {
    (void)connection;
}

static bool s_aws_http_connection_manager_is_connection_open_sync_mock(const struct aws_http_connection *connection) {
    (void)connection;

    struct mock_connection_proxy *proxy = (struct mock_connection_proxy *)(void *)connection;

    return !proxy->is_closed_on_release;
}

static struct aws_http_connection_manager_function_table s_synchronous_mocks = {
    .create_connection = s_aws_http_connection_manager_create_connection_sync_mock,
    .release_connection = s_aws_http_connection_manager_release_connection_sync_mock,
    .close_connection = s_aws_http_connection_manager_close_connection_sync_mock,
    .is_connection_open = s_aws_http_connection_manager_is_connection_open_sync_mock};

static int s_test_connection_manager_acquire_release_mix_synchronous(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator, .max_connections = 5, .mock_table = &s_synchronous_mocks};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    for (size_t i = 0; i < 20; ++i) {
        s_add_mock_connections(1, AWS_NCRT_SUCCESS, i % 1 == 0);
    }

    for (size_t i = 0; i < 10; ++i) {
        s_acquire_connections(2);

        s_wait_on_connection_reply_count(i + 1);

        s_release_connections(1, false);
    }

    s_wait_on_connection_reply_count(15);

    for (size_t i = 15; i < 20; ++i) {
        s_release_connections(1, false);

        s_wait_on_connection_reply_count(i + 1);
    }

    ASSERT_TRUE(s_tester.connection_errors == 0);

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    test_connection_manager_acquire_release_mix_synchronous,
    s_test_connection_manager_acquire_release_mix_synchronous);

static int s_test_connection_manager_connect_callback_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator, .max_connections = 5, .mock_table = &s_synchronous_mocks};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_add_mock_connections(5, AWS_NCRT_ERROR_VIA_CALLBACK, false);

    s_acquire_connections(5);

    s_wait_on_connection_reply_count(5);

    ASSERT_TRUE(s_tester.connection_errors == 5);

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_connect_callback_failure, s_test_connection_manager_connect_callback_failure);

static int s_test_connection_manager_connect_immediate_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator, .max_connections = 5, .mock_table = &s_synchronous_mocks};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_add_mock_connections(5, AWS_NCRT_ERROR_FROM_CREATE, false);

    s_acquire_connections(5);

    s_wait_on_connection_reply_count(5);

    ASSERT_TRUE(s_tester.connection_errors == 5);

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_connect_immediate_failure, s_test_connection_manager_connect_immediate_failure);

static int s_test_connection_manager_success_then_cancel_pending_from_failure(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator, .max_connections = 1, .mock_table = &s_synchronous_mocks};

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_add_mock_connections(1, AWS_NCRT_SUCCESS, true);
    s_add_mock_connections(1, AWS_NCRT_ERROR_FROM_CREATE, false);

    s_acquire_connections(5);

    s_wait_on_connection_reply_count(1);

    ASSERT_TRUE(s_tester.connection_errors == 0);

    s_release_connections(1, true);

    s_wait_on_connection_reply_count(5);

    ASSERT_TRUE(s_tester.connection_errors == 4);

    s_cm_tester_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    test_connection_manager_success_then_cancel_pending_from_failure,
    s_test_connection_manager_success_then_cancel_pending_from_failure);