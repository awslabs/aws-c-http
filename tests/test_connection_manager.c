/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/common/array_list.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/logging.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/common/uuid.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/private/connection_manager_system_vtable.h>
#include <aws/http/proxy.h>
#include <aws/http/server.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4232) /* function pointer to dll symbol */
#endif

enum new_connection_result_type {
    AWS_NCRT_SUCCESS,
    AWS_NCRT_ERROR_VIA_CALLBACK,
    AWS_NCRT_ERROR_FROM_CREATE,
};

struct mock_connection {
    enum new_connection_result_type result;
    bool is_closed_on_release;
};

struct cm_tester_options {
    struct aws_allocator *allocator;
    struct aws_http_connection_manager_system_vtable *mock_table;
    struct aws_http_proxy_options *proxy_options;
    size_t max_connections;
    uint64_t max_connection_idle_in_ms;
    uint64_t starting_mock_time;
};

struct cm_tester {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;

    struct aws_client_bootstrap *client_bootstrap;

    struct aws_http_connection_manager *connection_manager;

    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_http_proxy_options *proxy_options;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_array_list connections;
    size_t connection_errors;
    size_t connection_releases;

    size_t wait_for_connection_count;
    bool is_shutdown_complete;

    struct aws_http_connection_manager_system_vtable *mock_table;

    struct aws_atomic_var next_connection_id;
    struct aws_array_list mock_connections;
    aws_http_on_client_connection_shutdown_fn *release_connection_fn;

    struct aws_mutex mock_time_lock;
    uint64_t mock_time;
};

static struct cm_tester s_tester;

static int s_tester_get_mock_time(uint64_t *current_time) {
    aws_mutex_lock(&s_tester.mock_time_lock);
    *current_time = s_tester.mock_time;
    aws_mutex_unlock(&s_tester.mock_time_lock);

    return AWS_OP_SUCCESS;
}

static void s_tester_set_mock_time(uint64_t current_time) {
    aws_mutex_lock(&s_tester.mock_time_lock);
    s_tester.mock_time = current_time;
    aws_mutex_unlock(&s_tester.mock_time_lock);
}

static void s_cm_tester_on_cm_shutdown_complete(void *user_data) {
    struct cm_tester *tester = user_data;
    AWS_FATAL_ASSERT(tester == &s_tester);

    aws_mutex_lock(&tester->lock);
    tester->is_shutdown_complete = true;
    aws_mutex_unlock(&tester->lock);
    aws_condition_variable_notify_one(&tester->signal);
}

static struct aws_event_loop *s_new_event_loop(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options,
    void *new_loop_user_data) {
    (void)new_loop_user_data;

    return aws_event_loop_new_default(alloc, options->clock);
}

static int s_cm_tester_init(struct cm_tester_options *options) {
    struct cm_tester *tester = &s_tester;

    AWS_ZERO_STRUCT(*tester);

    aws_http_library_init(options->allocator);

    tester->allocator = options->allocator;

    ASSERT_SUCCESS(aws_mutex_init(&tester->lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&tester->signal));

    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&tester->connections, tester->allocator, 10, sizeof(struct aws_http_connection *)));

    aws_mutex_init(&tester->mock_time_lock);
    s_tester_set_mock_time(options->starting_mock_time);

    aws_io_clock_fn *clock_fn = &aws_high_res_clock_get_ticks;
    if (options->mock_table) {
        clock_fn = options->mock_table->get_monotonic_time;
    }

    tester->event_loop_group = aws_event_loop_group_new(tester->allocator, clock_fn, 1, s_new_event_loop, NULL, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = tester->event_loop_group,
        .max_entries = 8,
    };

    tester->host_resolver = aws_host_resolver_new_default(tester->allocator, &resolver_options);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = tester->event_loop_group,
        .host_resolver = tester->host_resolver,
    };
    tester->client_bootstrap = aws_client_bootstrap_new(tester->allocator, &bootstrap_options);
    ASSERT_NOT_NULL(tester->client_bootstrap);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms = (uint32_t)aws_timestamp_convert(10, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    aws_tls_ctx_options_init_default_client(&tester->tls_ctx_options, options->allocator);

    tester->tls_ctx = aws_tls_client_ctx_new(options->allocator, &tester->tls_ctx_options);
    ASSERT_NOT_NULL(tester->tls_ctx);

    aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);

    tester->proxy_options = options->proxy_options;

    struct aws_http_connection_manager_options cm_options = {
        .bootstrap = tester->client_bootstrap,
        .initial_window_size = SIZE_MAX,
        .socket_options = &socket_options,
        .tls_connection_options = NULL,
        .proxy_options = tester->proxy_options,
        .host = aws_byte_cursor_from_c_str("www.google.com"),
        .port = 80,
        .max_connections = options->max_connections,
        .shutdown_complete_user_data = tester,
        .shutdown_complete_callback = s_cm_tester_on_cm_shutdown_complete,
        .max_connection_idle_in_milliseconds = options->max_connection_idle_in_ms,
    };

    if (options->mock_table) {
        g_aws_http_connection_manager_default_system_vtable_ptr = options->mock_table;
    }

    tester->connection_manager = aws_http_connection_manager_new(tester->allocator, &cm_options);
    ASSERT_NOT_NULL(tester->connection_manager);

    if (options->mock_table) {
        aws_http_connection_manager_set_system_vtable(tester->connection_manager, options->mock_table);
    }

    tester->mock_table = options->mock_table;

    aws_atomic_store_int(&tester->next_connection_id, 0);

    ASSERT_SUCCESS(aws_array_list_init_dynamic(
        &tester->mock_connections, tester->allocator, 10, sizeof(struct mock_connection *)));

    return AWS_OP_SUCCESS;
}

static void s_add_mock_connections(size_t count, enum new_connection_result_type result, bool closed_on_release) {
    struct cm_tester *tester = &s_tester;

    for (size_t i = 0; i < count; ++i) {
        struct mock_connection *mock = aws_mem_acquire(tester->allocator, sizeof(struct mock_connection));
        AWS_ZERO_STRUCT(*mock);

        mock->result = result;
        mock->is_closed_on_release = closed_on_release;

        aws_array_list_push_back(&tester->mock_connections, &mock);
    }
}

static int s_release_connections(size_t count, bool close_first) {

    struct cm_tester *tester = &s_tester;

    struct aws_array_list to_release;
    AWS_ZERO_STRUCT(to_release);

    ASSERT_SUCCESS(aws_mutex_lock(&tester->lock));

    size_t release_count = aws_array_list_length(&tester->connections);
    if (release_count > count) {
        release_count = count;
    }

    if (release_count == 0) {
        goto release;
    }

    if (aws_array_list_init_dynamic(
            &to_release, tester->allocator, release_count, sizeof(struct aws_http_connection *))) {
        goto release;
    }

    for (size_t i = 0; i < release_count; ++i) {
        struct aws_http_connection *connection = NULL;
        if (aws_array_list_back(&tester->connections, &connection)) {
            continue;
        }

        aws_array_list_pop_back(&tester->connections);

        aws_array_list_push_back(&to_release, &connection);
    }

release:

    ASSERT_SUCCESS(aws_mutex_unlock(&tester->lock));

    if (aws_array_list_is_valid(&to_release)) {
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

            ASSERT_SUCCESS(aws_mutex_lock(&tester->lock));
            ++tester->connection_releases;
            aws_condition_variable_notify_one(&tester->signal);
            ASSERT_SUCCESS(aws_mutex_unlock(&tester->lock));
        }

        aws_array_list_clean_up(&to_release);
    } else {
        ASSERT_UINT_EQUALS(0, release_count);
    }

    return AWS_OP_SUCCESS;
}

static void s_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;

    struct cm_tester *tester = &s_tester;

    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->lock) == AWS_OP_SUCCESS);

    if (connection == NULL) {
        ++tester->connection_errors;
    } else {
        aws_array_list_push_back(&tester->connections, &connection);
    }

    aws_condition_variable_notify_one(&tester->signal);

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->lock) == AWS_OP_SUCCESS);
}

static void s_acquire_connections(size_t count) {
    struct cm_tester *tester = &s_tester;

    for (size_t i = 0; i < count; ++i) {
        aws_http_connection_manager_acquire_connection(tester->connection_manager, s_on_acquire_connection, tester);
    }
}

static bool s_is_connection_reply_count_at_least(void *context) {
    (void)context;

    struct cm_tester *tester = &s_tester;

    return tester->wait_for_connection_count <=
           aws_array_list_length(&tester->connections) + tester->connection_errors + tester->connection_releases;
}

static int s_wait_on_connection_reply_count(size_t count) {
    struct cm_tester *tester = &s_tester;

    ASSERT_SUCCESS(aws_mutex_lock(&tester->lock));

    tester->wait_for_connection_count = count;
    int signal_error =
        aws_condition_variable_wait_pred(&tester->signal, &tester->lock, s_is_connection_reply_count_at_least, tester);

    ASSERT_SUCCESS(aws_mutex_unlock(&tester->lock));
    return signal_error;
}

static bool s_is_shutdown_complete(void *context) {
    (void)context;

    struct cm_tester *tester = &s_tester;

    return tester->is_shutdown_complete;
}

static int s_wait_on_shutdown_complete(void) {
    struct cm_tester *tester = &s_tester;

    ASSERT_SUCCESS(aws_mutex_lock(&tester->lock));

    int signal_error = aws_condition_variable_wait_pred(&tester->signal, &tester->lock, s_is_shutdown_complete, tester);

    ASSERT_SUCCESS(aws_mutex_unlock(&tester->lock));
    return signal_error;
}

static int s_cm_tester_clean_up(void) {
    struct cm_tester *tester = &s_tester;

    ASSERT_SUCCESS(s_release_connections(aws_array_list_length(&tester->connections), false));

    aws_array_list_clean_up(&tester->connections);

    for (size_t i = 0; i < aws_array_list_length(&tester->mock_connections); ++i) {
        struct mock_connection *mock = NULL;

        if (aws_array_list_get_at(&tester->mock_connections, &mock, i)) {
            continue;
        }

        aws_mem_release(tester->allocator, mock);
    }
    aws_array_list_clean_up(&tester->mock_connections);

    aws_http_connection_manager_release(tester->connection_manager);

    s_wait_on_shutdown_complete();

    aws_client_bootstrap_release(tester->client_bootstrap);

    aws_host_resolver_release(tester->host_resolver);
    aws_event_loop_group_release(tester->event_loop_group);

    aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    aws_tls_connection_options_clean_up(&tester->tls_connection_options);
    aws_tls_ctx_release(tester->tls_ctx);

    aws_http_library_clean_up();

    aws_mutex_clean_up(&tester->lock);
    aws_condition_variable_clean_up(&tester->signal);

    aws_mutex_clean_up(&tester->mock_time_lock);

    return AWS_OP_SUCCESS;
}

static int s_test_connection_manager_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 5,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_setup_shutdown, s_test_connection_manager_setup_shutdown);

static int s_test_connection_manager_single_connection(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 5,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_acquire_connections(1);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(1));

    ASSERT_SUCCESS(s_release_connections(1, false));

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_single_connection, s_test_connection_manager_single_connection);

static int s_test_connection_manager_many_connections(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 20,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_acquire_connections(20);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(20));

    ASSERT_SUCCESS(s_release_connections(20, false));

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_many_connections, s_test_connection_manager_many_connections);

static int s_test_connection_manager_acquire_release(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 4,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_acquire_connections(20);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(4));

    for (size_t i = 4; i < 20; ++i) {
        ASSERT_SUCCESS(s_release_connections(1, false));

        ASSERT_SUCCESS(s_wait_on_connection_reply_count(i + 1));
    }

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_acquire_release, s_test_connection_manager_acquire_release);

static int s_test_connection_manager_close_and_release(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 4,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_acquire_connections(20);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(4));

    for (size_t i = 4; i < 20; ++i) {
        ASSERT_SUCCESS(s_release_connections(1, i % 1 == 0));

        ASSERT_SUCCESS(s_wait_on_connection_reply_count(i + 1));
    }

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_close_and_release, s_test_connection_manager_close_and_release);

static int s_test_connection_manager_acquire_release_mix(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 5,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    for (size_t i = 0; i < 10; ++i) {
        s_acquire_connections(2);

        ASSERT_SUCCESS(s_wait_on_connection_reply_count(i + 1));

        ASSERT_SUCCESS(s_release_connections(1, i % 1 == 0));
    }

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(15));

    for (size_t i = 15; i < 20; ++i) {
        ASSERT_SUCCESS(s_release_connections(1, i % 1 == 0));

        ASSERT_SUCCESS(s_wait_on_connection_reply_count(i + 1));
    }

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_acquire_release_mix, s_test_connection_manager_acquire_release_mix);

static int s_aws_http_connection_manager_create_connection_sync_mock(
    const struct aws_http_client_connection_options *options) {
    struct cm_tester *tester = &s_tester;

    size_t next_connection_id = aws_atomic_fetch_add(&tester->next_connection_id, 1);

    ASSERT_SUCCESS(aws_mutex_lock(&tester->lock));
    tester->release_connection_fn = options->on_shutdown;
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->lock));

    /* Verify that any proxy options have been propagated to the connection attempt */
    if (tester->proxy_options) {
        ASSERT_BIN_ARRAYS_EQUALS(
            tester->proxy_options->host.ptr,
            tester->proxy_options->host.len,
            options->proxy_options->host.ptr,
            options->proxy_options->host.len);
        ASSERT_TRUE(options->proxy_options->port == tester->proxy_options->port);
    }

    struct mock_connection *connection = NULL;

    if (next_connection_id < aws_array_list_length(&tester->mock_connections)) {
        aws_array_list_get_at(&tester->mock_connections, &connection, next_connection_id);
    }

    if (connection) {
        if (connection->result == AWS_NCRT_SUCCESS) {
            options->on_setup((struct aws_http_connection *)connection, AWS_ERROR_SUCCESS, options->user_data);
        } else if (connection->result == AWS_NCRT_ERROR_VIA_CALLBACK) {
            options->on_setup(NULL, AWS_ERROR_HTTP_UNKNOWN, options->user_data);
        }

        if (connection->result != AWS_NCRT_ERROR_FROM_CREATE) {
            return AWS_OP_SUCCESS;
        }
    }

    return aws_raise_error(AWS_ERROR_HTTP_UNKNOWN);
}

static void s_aws_http_connection_manager_release_connection_sync_mock(struct aws_http_connection *connection) {
    (void)connection;

    struct cm_tester *tester = &s_tester;

    tester->release_connection_fn(connection, AWS_ERROR_SUCCESS, tester->connection_manager);
}

static void s_aws_http_connection_manager_close_connection_sync_mock(struct aws_http_connection *connection) {
    (void)connection;
}

static bool s_aws_http_connection_manager_is_connection_available_sync_mock(
    const struct aws_http_connection *connection) {
    (void)connection;

    struct mock_connection *proxy = (struct mock_connection *)(void *)connection;

    return !proxy->is_closed_on_release;
}

static bool s_aws_http_connection_manager_is_callers_thread_sync_mock(struct aws_channel *channel) {
    (void)channel;

    return true;
}

static struct aws_channel *s_aws_http_connection_manager_connection_get_channel_sync_mock(
    struct aws_http_connection *connection) {
    (void)connection;

    return (struct aws_channel *)1;
}

static struct aws_http_connection_manager_system_vtable s_synchronous_mocks = {
    .create_connection = s_aws_http_connection_manager_create_connection_sync_mock,
    .release_connection = s_aws_http_connection_manager_release_connection_sync_mock,
    .close_connection = s_aws_http_connection_manager_close_connection_sync_mock,
    .is_connection_available = s_aws_http_connection_manager_is_connection_available_sync_mock,
    .get_monotonic_time = aws_high_res_clock_get_ticks,
    .connection_get_channel = s_aws_http_connection_manager_connection_get_channel_sync_mock,
    .is_callers_thread = s_aws_http_connection_manager_is_callers_thread_sync_mock,
};

static int s_test_connection_manager_acquire_release_mix_synchronous(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 5,
        .mock_table = &s_synchronous_mocks,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    for (size_t i = 0; i < 20; ++i) {
        s_add_mock_connections(1, AWS_NCRT_SUCCESS, i % 1 == 0);
    }

    for (size_t i = 0; i < 10; ++i) {
        s_acquire_connections(2);

        ASSERT_SUCCESS(s_wait_on_connection_reply_count(i + 1));

        ASSERT_SUCCESS(s_release_connections(1, false));
    }

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(15));

    for (size_t i = 15; i < 20; ++i) {
        ASSERT_SUCCESS(s_release_connections(1, false));

        ASSERT_SUCCESS(s_wait_on_connection_reply_count(i + 1));
    }

    ASSERT_TRUE(s_tester.connection_errors == 0);

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    test_connection_manager_acquire_release_mix_synchronous,
    s_test_connection_manager_acquire_release_mix_synchronous);

static int s_test_connection_manager_connect_callback_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 5,
        .mock_table = &s_synchronous_mocks,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_add_mock_connections(5, AWS_NCRT_ERROR_VIA_CALLBACK, false);

    s_acquire_connections(5);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(5));

    ASSERT_TRUE(s_tester.connection_errors == 5);

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_connect_callback_failure, s_test_connection_manager_connect_callback_failure);

static int s_test_connection_manager_connect_immediate_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 5,
        .mock_table = &s_synchronous_mocks,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    s_add_mock_connections(5, AWS_NCRT_ERROR_FROM_CREATE, false);

    s_acquire_connections(5);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(5));

    ASSERT_TRUE(s_tester.connection_errors == 5);

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_connect_immediate_failure, s_test_connection_manager_connect_immediate_failure);

static int s_test_connection_manager_proxy_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .port = 8080,
    };

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 1,
        .mock_table = &s_synchronous_mocks,
        .proxy_options = &proxy_options,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_proxy_setup_shutdown, s_test_connection_manager_proxy_setup_shutdown);

static struct aws_http_connection_manager_system_vtable s_idle_mocks = {
    .create_connection = s_aws_http_connection_manager_create_connection_sync_mock,
    .release_connection = s_aws_http_connection_manager_release_connection_sync_mock,
    .close_connection = s_aws_http_connection_manager_close_connection_sync_mock,
    .is_connection_available = s_aws_http_connection_manager_is_connection_available_sync_mock,
    .get_monotonic_time = s_tester_get_mock_time,
    .connection_get_channel = s_aws_http_connection_manager_connection_get_channel_sync_mock,
    .is_callers_thread = s_aws_http_connection_manager_is_callers_thread_sync_mock,
};

static int s_register_acquired_connections(struct aws_array_list *seen_connections) {
    aws_mutex_lock(&s_tester.lock);

    size_t acquired_count = aws_array_list_length(&s_tester.connections);
    for (size_t i = 0; i < acquired_count; ++i) {
        struct aws_http_connection *connection = NULL;
        aws_array_list_get_at(&s_tester.connections, &connection, i);
        aws_array_list_push_back(seen_connections, &connection);
    }

    aws_mutex_unlock(&s_tester.lock);

    return AWS_OP_SUCCESS;
}

static size_t s_get_acquired_connections_seen_count(struct aws_array_list *seen_connections) {
    size_t actual_seen_count = 0;
    aws_mutex_lock(&s_tester.lock);

    size_t seen_count = aws_array_list_length(seen_connections);
    size_t acquired_count = aws_array_list_length(&s_tester.connections);
    for (size_t i = 0; i < acquired_count; ++i) {
        struct aws_http_connection *acquired_connection = NULL;
        aws_array_list_get_at(&s_tester.connections, &acquired_connection, i);

        for (size_t j = 0; j < seen_count; ++j) {
            struct aws_http_connection *seen_connection = NULL;
            aws_array_list_get_at(seen_connections, &seen_connection, j);

            if (seen_connection == acquired_connection) {
                actual_seen_count++;
            }
        }
    }

    aws_mutex_unlock(&s_tester.lock);

    return actual_seen_count;
}

static int s_test_connection_manager_idle_culling_single(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_array_list seen_connections;
    AWS_ZERO_STRUCT(seen_connections);
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&seen_connections, allocator, 10, sizeof(struct aws_http_connection *)));

    uint64_t now = 0;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 1,
        .mock_table = &s_idle_mocks,
        .max_connection_idle_in_ms = 1000,
        .starting_mock_time = now,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    /* add enough fake connections to cover all the acquires */
    s_add_mock_connections(2, AWS_NCRT_SUCCESS, false);

    /* acquire some connections */
    s_acquire_connections(1);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(1));

    /* remember what connections we acquired */
    s_register_acquired_connections(&seen_connections);

    /* release the connections */
    s_release_connections(1, false);

    /* advance fake time enough to cause the connections to be culled, also sleep for real to give the cull task
     * a chance to run in the real event loop
     */
    uint64_t one_sec_in_nanos = aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    s_tester_set_mock_time(now + one_sec_in_nanos);
    aws_thread_current_sleep(2 * one_sec_in_nanos);

    /* acquire some connections */
    s_acquire_connections(1);
    ASSERT_SUCCESS(s_wait_on_connection_reply_count(2));

    /* make sure the connections acquired were not ones that we expected to cull */
    ASSERT_INT_EQUALS(s_get_acquired_connections_seen_count(&seen_connections), 0);

    /* release everything and clean up */
    s_release_connections(1, false);

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    aws_array_list_clean_up(&seen_connections);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_idle_culling_single, s_test_connection_manager_idle_culling_single);

static int s_test_connection_manager_idle_culling_many(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_array_list seen_connections;
    AWS_ZERO_STRUCT(seen_connections);
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&seen_connections, allocator, 10, sizeof(struct aws_http_connection *)));

    uint64_t now = 0;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 5,
        .mock_table = &s_idle_mocks,
        .max_connection_idle_in_ms = 1000,
        .starting_mock_time = now,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    /* add enough fake connections to cover all the acquires */
    s_add_mock_connections(10, AWS_NCRT_SUCCESS, false);

    /* acquire some connections */
    s_acquire_connections(5);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(5));

    /* remember what connections we acquired */
    s_register_acquired_connections(&seen_connections);

    /* release the connections */
    s_release_connections(5, false);

    /* advance fake time enough to cause the connections to be culled, also sleep for real to give the cull task
     * a chance to run in the real event loop
     */
    uint64_t one_sec_in_nanos = aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    s_tester_set_mock_time(now + one_sec_in_nanos);
    aws_thread_current_sleep(2 * one_sec_in_nanos);

    /* acquire some connections */
    s_acquire_connections(5);
    ASSERT_SUCCESS(s_wait_on_connection_reply_count(10));

    /* make sure the connections acquired were not ones that we expected to cull */
    ASSERT_INT_EQUALS(s_get_acquired_connections_seen_count(&seen_connections), 0);

    /* release everything and clean up */
    s_release_connections(5, false);

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    aws_array_list_clean_up(&seen_connections);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_idle_culling_many, s_test_connection_manager_idle_culling_many);

static int s_test_connection_manager_idle_culling_mixture(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_array_list seen_connections;
    AWS_ZERO_STRUCT(seen_connections);
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&seen_connections, allocator, 10, sizeof(struct aws_http_connection *)));

    uint64_t now = 0;

    struct cm_tester_options options = {
        .allocator = allocator,
        .max_connections = 10,
        .mock_table = &s_idle_mocks,
        .max_connection_idle_in_ms = 1000,
        .starting_mock_time = now,
    };

    ASSERT_SUCCESS(s_cm_tester_init(&options));

    /* add enough fake connections to cover all the acquires */
    s_add_mock_connections(15, AWS_NCRT_SUCCESS, false);

    /* acquire some connections */
    s_acquire_connections(10);

    ASSERT_SUCCESS(s_wait_on_connection_reply_count(10));

    /* remember what connections we acquired */
    s_register_acquired_connections(&seen_connections);

    /*
     * release the connections
     * Previous tests created situations where the entire block of idle connections end up getting culled.  We also
     * want to create a situation where just some of the connections get culled.
     */
    s_release_connections(5, false);
    s_tester_set_mock_time(now + 1);
    s_release_connections(5, false);
    s_tester_set_mock_time(now);
    uint64_t one_sec_in_nanos = aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

    /*
     * advance fake time enough to cause half of the connections to be culled, also sleep for real to give the cull task
     * a chance to run in the real event loop.
     */
    s_tester_set_mock_time(now + one_sec_in_nanos);
    aws_thread_current_sleep(2 * one_sec_in_nanos);

    /* acquire some connections */
    s_acquire_connections(10);
    ASSERT_SUCCESS(s_wait_on_connection_reply_count(20));

    /* make sure the connections acquired are half old and half new */
    ASSERT_INT_EQUALS(s_get_acquired_connections_seen_count(&seen_connections), 5);

    /* release everything and clean up */
    s_release_connections(10, false);

    ASSERT_SUCCESS(s_cm_tester_clean_up());

    aws_array_list_clean_up(&seen_connections);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_connection_manager_idle_culling_mixture, s_test_connection_manager_idle_culling_mixture);
