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

#include <aws/common/thread.h>
#include <aws/http/connection.h>
#include <aws/http/private/connection_impl.h>
#include <aws/http/private/connection_monitor.h>
#include <aws/http/statistics.h>
#include <aws/io/channel.h>
#include <aws/io/statistics.h>

#include <aws/testing/aws_test_harness.h>
#include <aws/testing/io_testing_channel.h>

static int s_test_http_connection_monitor_options_is_valid(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_http_connection_monitoring_options options;
    AWS_ZERO_STRUCT(options);

    ASSERT_FALSE(aws_http_connection_monitoring_options_is_valid(NULL));
    ASSERT_FALSE(aws_http_connection_monitoring_options_is_valid(&options));

    options.minimum_throughput_failure_threshold_in_seconds = 5;
    ASSERT_FALSE(aws_http_connection_monitoring_options_is_valid(&options));

    options.minimum_throughput_failure_threshold_in_seconds = 1;
    options.minimum_throughput_bytes_per_second = 1000;
    ASSERT_FALSE(aws_http_connection_monitoring_options_is_valid(&options));

    options.minimum_throughput_failure_threshold_in_seconds = 2;
    ASSERT_TRUE(aws_http_connection_monitoring_options_is_valid(&options));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_options_is_valid, s_test_http_connection_monitor_options_is_valid);

/*

     if (tester->client_connection) {
        if (tester->client_connection) {
            aws_http_connection_release(tester->client_connection);
        }
    }

    if (tester->testing_channel) {
        ASSERT_SUCCESS(testing_channel_clean_up(tester->testing_channel));
        while (!testing_channel_is_shutdown_completed(tester->testing_channel)) {
            aws_thread_current_sleep(1000000000);
        }

        aws_mem_release(tester->alloc, tester->testing_channel);
    }

    ASSERT_SUCCESS(proxy_tester_wait(tester, proxy_tester_connection_shutdown_pred));

    if (tester->http_bootstrap != NULL) {
        if (tester->testing_channel == NULL && tester->http_bootstrap->user_data) {
            aws_http_proxy_user_data_destroy(tester->http_bootstrap->user_data);
        }
        aws_mem_release(tester->alloc, tester->http_bootstrap);
    }

    aws_client_bootstrap_release(tester->client_bootstrap);

    aws_host_resolver_clean_up(&tester->host_resolver);
    aws_event_loop_group_clean_up(&tester->event_loop_group);

    if (tester->tls_ctx) {
        aws_tls_connection_options_clean_up(&tester->tls_connection_options);
        aws_tls_ctx_destroy(tester->tls_ctx);
        aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    }

    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);

    aws_byte_buf_clean_up(&tester->connection_host_name);

    return AWS_OP_SUCCESS;
}

static void s_testing_channel_shutdown_callback(int error_code, void *user_data) {
    struct proxy_tester *tester = user_data;

    if (tester->wait_result == AWS_ERROR_SUCCESS) {
        tester->wait_result = error_code;
    }

    tester->http_bootstrap->on_shutdown(
        tester->client_connection, tester->wait_result, tester->http_bootstrap->user_data);
}

int proxy_tester_create_testing_channel_connection(struct proxy_tester *tester) {
    tester->testing_channel = aws_mem_calloc(tester->alloc, 1, sizeof(struct testing_channel));
    ASSERT_SUCCESS(testing_channel_init(tester->testing_channel, tester->alloc));
    tester->testing_channel->channel_shutdown = s_testing_channel_shutdown_callback;
    tester->testing_channel->channel_shutdown_user_data = tester;

    struct aws_http_connection *connection = aws_http_connection_new_http1_1_client(tester->alloc, SIZE_MAX);
    ASSERT_NOT_NULL(connection);

    connection->user_data = tester->http_bootstrap->user_data;
    connection->client_data = &connection->client_or_server_data.client;
    connection->proxy_request_transform = tester->http_bootstrap->proxy_request_transform;

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel->channel);
    ASSERT_NOT_NULL(slot);
    connection->channel_slot = slot;
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel->channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &connection->channel_handler));

    aws_channel_acquire_hold(tester->testing_channel->channel);

    tester->client_connection = connection;
    testing_channel_drain_queued_tasks(tester->testing_channel);

    return AWS_OP_SUCCESS;
}
 */

static void s_testing_channel_shutdown_callback(int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
}

enum monitor_test_event_type {
    MTET_EMPTY,
    MTET_STATS
};

struct http_monitor_test_stats_event {
    uint64_t timestamp;
    enum monitor_test_event_type event_type;
    struct aws_crt_statistics_socket socket_stats;
    struct aws_crt_statistics_http1 http_stats;
};

struct monitor_test_context {
    struct aws_allocator *allocator;
    struct testing_channel test_channel;
    struct aws_http_connection *connection;
};

static struct monitor_test_context s_test_context;

static int s_init_monitor_test(struct aws_allocator *allocator) {

    aws_http_library_init(allocator);

    AWS_ZERO_STRUCT(s_test_context);
    s_test_context.allocator = allocator;

    testing_channel_init(&s_test_context.test_channel, allocator);

    s_test_context.test_channel.channel_shutdown = s_testing_channel_shutdown_callback;
    s_test_context.test_channel.channel_shutdown_user_data = &s_test_context;

    struct aws_http_connection *connection = aws_http_connection_new_http1_1_client(allocator, SIZE_MAX);
    ASSERT_NOT_NULL(connection);

    struct aws_channel_slot *slot = aws_channel_slot_new(s_test_context.test_channel.channel);
    ASSERT_NOT_NULL(slot);
    connection->channel_slot = slot;
    ASSERT_SUCCESS(aws_channel_slot_insert_end(s_test_context.test_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &connection->channel_handler));

    aws_channel_acquire_hold(s_test_context.test_channel.channel);

    s_test_context.connection = connection;
    testing_channel_drain_queued_tasks(&s_test_context.test_channel);

    return AWS_OP_SUCCESS;

}

static void s_clean_up_monitor_test() {

    testing_channel_clean_up(&s_test_context.test_channel);
    while (!testing_channel_is_shutdown_completed(&s_test_context.test_channel)) {
        aws_thread_current_sleep(1000000000);
    }

    aws_http_library_clean_up();
}

static int s_do_http_monitoring_test(struct aws_allocator *allocator, struct aws_http_connection_monitoring_options *monitoring_options, struct http_monitor_test_stats_event *events, size_t event_count, uint32_t expected_consecutive_failures) {
    (void)monitoring_options;
    (void)events;
    (void)event_count;
    (void)expected_consecutive_failures;

    s_init_monitor_test(allocator);


    s_clean_up_monitor_test();

    return AWS_OP_SUCCESS;
}

static struct aws_http_connection_monitoring_options s_test_options = {
    .minimum_throughput_failure_threshold_in_seconds = 3,
    .minimum_throughput_bytes_per_second = 1000
};

static struct http_monitor_test_stats_event s_test_1_above_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats = {
            .category = AWSCRT_STAT_CAT_SOCKET,
            .bytes_read = 1000,
            .bytes_written = 1000
        },
        .http_stats = {
            .category = AWSCRT_STAT_CAT_HTTP1,
            .pending_incoming_stream_ns = AWS_TIMESTAMP_NANOS,
            .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS
        }
    }
};
static int s_test_http_connection_monitor_1_above(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;


    int result = s_do_http_monitoring_test(allocator, &s_test_options, s_test_1_above_events, AWS_ARRAY_SIZE(s_test_1_above_events), 0);
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_1_above, s_test_http_connection_monitor_1_above);

/*

 Pattern 1 (monitor calculations and side affect)

 Create a dummy channel with no handlers
 Create and attach a (X,Y) connection monitor
 Loop over [(t_i, stats_i)]
   SetCurrentChannelTime(t_i)
   ProcessStatistics(stats_i)

 if ShutdownTest
     flush tasks and wait on channel shutdown
 else
     inspect monitor state



 Pattern 2 (http statistics verification)

 Create an io testing channel (test_handler <-> http_handler)
 Create and attach a mock stats handler
 Loop over events [(t_i, ??)]
    SetCurrentChannelTime
    ApplyEvent(??)

 Inspect ProcessStatistics captures of http statistics

 */