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

static void s_testing_channel_shutdown_callback(int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
}

enum monitor_test_event_type { MTET_EMPTY, MTET_STATS };

struct http_monitor_test_stats_event {
    uint64_t timestamp;
    enum monitor_test_event_type event_type;
    struct aws_crt_statistics_socket socket_stats;
    struct aws_crt_statistics_http1 http_stats;
    uint32_t expected_consecutive_failure_count;
};

struct http_request_info {
    struct aws_http_request *request;
    struct aws_http_stream *stream;
};

struct monitor_test_context {
    struct aws_allocator *allocator;
    struct testing_channel test_channel;
    struct aws_http_connection *connection;
    struct aws_crt_statistics_handler *monitor;

    struct aws_array_list requests;
};

static struct monitor_test_context s_test_context;

static struct aws_atomic_var s_clock_value;

static int s_mock_clock(uint64_t *timestamp) {
    *timestamp = aws_atomic_load_int(&s_clock_value);

    return AWS_OP_SUCCESS;
}

static int s_init_monitor_test(
    struct aws_allocator *allocator,
    struct aws_crt_statistics_handler *monitor) {

    aws_http_library_init(allocator);

    aws_atomic_init_int(&s_clock_value, 0);

    AWS_ZERO_STRUCT(s_test_context);
    s_test_context.allocator = allocator;

    struct aws_testing_channel_options test_channel_options = {.clock_fn = s_mock_clock};

    testing_channel_init(&s_test_context.test_channel, allocator, &test_channel_options);

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

    s_test_context.monitor = monitor;

    aws_channel_set_statistics_handler(s_test_context.test_channel.channel, s_test_context.monitor);

    ASSERT_SUCCESS(aws_array_list_init_dynamic(&s_test_context.requests, allocator, 1, sizeof(struct http_request_info)));

    return AWS_OP_SUCCESS;
}

static void s_clean_up_monitor_test(void) {

    aws_http_connection_release(s_test_context.connection);

    testing_channel_clean_up(&s_test_context.test_channel);

    aws_array_list_clean_up(&s_test_context.requests);

    aws_http_library_clean_up();
}

static void s_apply_stats_event_to_testing_channel(struct http_monitor_test_stats_event *event) {
    (void)event;

    struct aws_channel *channel = s_test_context.test_channel.channel;
    struct aws_channel_slot *first_slot = aws_channel_get_first_slot(channel);
    struct aws_channel_handler *first_handler = first_slot->handler;
    struct testing_channel_handler *testing_handler = first_handler->impl;
    testing_handler->stats = event->socket_stats;

    struct aws_channel_handler *second_handler = first_slot->adj_right->handler;
    struct aws_http_connection *connection = second_handler->impl;
    struct aws_crt_statistics_http1 *h1_stats = aws_h1_connection_get_statistics(connection);
    *h1_stats = event->http_stats;
}

/*

 Test Pattern 1 (monitor calculations and side affect)

 Create a testing channel
 Create and attach a (X,Y) http connection monitor
 Loop over test-specific event list: [(t_i, stats_i)]
   Inject socket and http statistics
   SetCurrentChannelTime(t_i)
   cause ProcessStatistics() to be invoked by running channel tasks
   verify monitor's state is as expected
   if met the monitoring failure condition
      verify the channel was shutdown

 */
static int s_do_http_monitoring_test(
    struct aws_allocator *allocator,
    struct aws_http_connection_monitoring_options *monitoring_options,
    struct http_monitor_test_stats_event *events,
    size_t event_count) {

    s_init_monitor_test(allocator, aws_crt_statistics_handler_new_http_connection_monitor(allocator, monitoring_options));

    struct aws_statistics_handler_http_connection_monitor_impl *monitor_impl = s_test_context.monitor->impl;

    for (size_t i = 0; i < event_count; ++i) {
        struct http_monitor_test_stats_event *event = events + i;
        aws_atomic_store_int(&s_clock_value, event->timestamp);
        switch (event->event_type) {
            case MTET_EMPTY:
                break;

            case MTET_STATS:
                s_apply_stats_event_to_testing_channel(event);
                break;
        }

        testing_channel_drain_queued_tasks(&s_test_context.test_channel);
        ASSERT_TRUE(monitor_impl->consecutive_throughput_failures == event->expected_consecutive_failure_count);
        if (monitor_impl->consecutive_throughput_failures ==
            monitoring_options->minimum_throughput_failure_threshold_in_seconds) {
            ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_test_context.test_channel));
        }
    }

    s_clean_up_monitor_test();

    return AWS_OP_SUCCESS;
}

static struct aws_http_connection_monitoring_options s_test_options = {
    .minimum_throughput_failure_threshold_in_seconds = 2,
    .minimum_throughput_bytes_per_second = 1000};

static struct http_monitor_test_stats_event s_test_above_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 1000,
                .bytes_written = 1000,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = AWS_TIMESTAMP_NANOS,
                .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS,
            },
        .expected_consecutive_failure_count = 0,
    },
};
static int s_test_http_connection_monitor_above(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result =
        s_do_http_monitoring_test(allocator, &s_test_options, s_test_above_events, AWS_ARRAY_SIZE(s_test_above_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_above, s_test_http_connection_monitor_above);

static struct http_monitor_test_stats_event s_test_below_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 999,
                .bytes_written = 1000,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = AWS_TIMESTAMP_NANOS,
                .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS,
            },
        .expected_consecutive_failure_count = 1,
    },
};
static int s_test_http_connection_monitor_below(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result =
        s_do_http_monitoring_test(allocator, &s_test_options, s_test_below_events, AWS_ARRAY_SIZE(s_test_below_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_below, s_test_http_connection_monitor_below);

static struct http_monitor_test_stats_event s_test_below_then_above_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 999,
                .bytes_written = 1000,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = AWS_TIMESTAMP_NANOS,
                .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS,
            },
        .expected_consecutive_failure_count = 1,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = 2 * AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 1500,
                .bytes_written = 500,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = AWS_TIMESTAMP_NANOS,
                .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS,
            },
        .expected_consecutive_failure_count = 0,
    },
};
static int s_test_http_connection_monitor_below_then_above(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_monitoring_test(
        allocator, &s_test_options, s_test_below_then_above_events, AWS_ARRAY_SIZE(s_test_below_then_above_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_below_then_above, s_test_http_connection_monitor_below_then_above);

static struct http_monitor_test_stats_event s_test_zero_bytes_positive_time_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 0,
                .bytes_written = 0,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = 1,
                .pending_outgoing_stream_ns = 0,
            },
        .expected_consecutive_failure_count = 1,
    },
};
static int s_test_http_connection_monitor_zero_bytes_positive_time(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_monitoring_test(
        allocator,
        &s_test_options,
        s_test_zero_bytes_positive_time_events,
        AWS_ARRAY_SIZE(s_test_zero_bytes_positive_time_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    test_http_connection_monitor_zero_bytes_positive_time,
    s_test_http_connection_monitor_zero_bytes_positive_time);

static struct http_monitor_test_stats_event s_test_zero_bytes_zero_time_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 0,
                .bytes_written = 0,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = 0,
                .pending_outgoing_stream_ns = 0,
            },
        .expected_consecutive_failure_count = 0,
    },
};
static int s_test_http_connection_monitor_zero_bytes_zero_time(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_monitoring_test(
        allocator,
        &s_test_options,
        s_test_zero_bytes_zero_time_events,
        AWS_ARRAY_SIZE(s_test_zero_bytes_zero_time_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_zero_bytes_zero_time, s_test_http_connection_monitor_zero_bytes_zero_time);

static struct http_monitor_test_stats_event s_test_tiny_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 1,
                .bytes_written = 0,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = 1,
                .pending_outgoing_stream_ns = 0,
            },
        .expected_consecutive_failure_count = 0,
    },
};
static int s_test_http_connection_monitor_tiny(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result =
        s_do_http_monitoring_test(allocator, &s_test_options, s_test_tiny_events, AWS_ARRAY_SIZE(s_test_tiny_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_tiny, s_test_http_connection_monitor_tiny);

static struct http_monitor_test_stats_event s_test_bytes_overflow_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = UINT64_MAX / 2 + 2,
                .bytes_written = UINT64_MAX / 2 + 2,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = AWS_TIMESTAMP_NANOS,
                .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS,
            },
        .expected_consecutive_failure_count = 0,
    },
};
static int s_test_http_connection_monitor_bytes_overflow(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_monitoring_test(
        allocator, &s_test_options, s_test_bytes_overflow_events, AWS_ARRAY_SIZE(s_test_bytes_overflow_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_bytes_overflow, s_test_http_connection_monitor_bytes_overflow);

static struct http_monitor_test_stats_event s_test_time_overflow_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 1000,
                .bytes_written = 1000,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = UINT64_MAX,
                .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS,
            },
        .expected_consecutive_failure_count = 0,
    },
};
static int s_test_http_connection_monitor_time_overflow(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_monitoring_test(
        allocator, &s_test_options, s_test_time_overflow_events, AWS_ARRAY_SIZE(s_test_time_overflow_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_time_overflow, s_test_http_connection_monitor_time_overflow);

static struct http_monitor_test_stats_event s_test_shutdown_events[] = {
    {
        .event_type = MTET_EMPTY,
        .timestamp = 0,
        .expected_consecutive_failure_count = 0,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 0,
                .bytes_written = 0,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = AWS_TIMESTAMP_NANOS,
                .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS,
            },
        .expected_consecutive_failure_count = 1,
    },
    {
        .event_type = MTET_STATS,
        .timestamp = 2 * AWS_TIMESTAMP_NANOS,
        .socket_stats =
            {
                .category = AWSCRT_STAT_CAT_SOCKET,
                .bytes_read = 0,
                .bytes_written = 0,
            },
        .http_stats =
            {
                .category = AWSCRT_STAT_CAT_HTTP1,
                .pending_incoming_stream_ns = AWS_TIMESTAMP_NANOS,
                .pending_outgoing_stream_ns = AWS_TIMESTAMP_NANOS,
            },
        .expected_consecutive_failure_count = 2,
    },
};
static int s_test_http_connection_monitor_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_monitoring_test(
        allocator, &s_test_options, s_test_shutdown_events, AWS_ARRAY_SIZE(s_test_shutdown_events));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_connection_monitor_shutdown, s_test_http_connection_monitor_shutdown);

/*

 Pattern 2 (http statistics verification)

 Create an io testing channel (test_handler <-> http_handler)
 Create and attach a mock stats handler
 Loop over http events [(t_i, http_event)]
    SetCurrentChannelTime(t_i)
    ApplyEvent(http_event)

 Inspect mock capture of http statistics: are pending_read_interval_ns and pending_write_interval_ns what we expect?

 */

enum monitor_test_http_stats_event_type { MTHSET_TIME, MTHSET_ADD_OUTGOING_STREAM, MTHSET_ADD_INCOMING_STREAM, MTHSET_FLUSH, MTHSET_TICK };

struct test_http_stats_event {
    uint64_t timestamp;
    enum monitor_test_http_stats_event_type event_type;
    const char *stream_data;
};

struct mock_http_connection_monitor_impl {
    struct aws_http_connection_monitoring_options options;

    uint64_t pending_read_interval_ns;
    uint64_t pending_write_interval_ns;
};

static void s_mock_process_statistics(
    struct aws_crt_statistics_handler *handler,
    struct aws_crt_statistics_sample_interval *interval,
    struct aws_array_list *stats_list,
    void *context) {

    (void)interval;

    struct mock_http_connection_monitor_impl *impl = handler->impl;

    size_t stats_count = aws_array_list_length(stats_list);
    for (size_t i = 0; i < stats_count; ++i) {
        struct aws_crt_statistics_base *stats_base = NULL;
        if (aws_array_list_get_at(stats_list, &stats_base, i)) {
            continue;
        }

        switch (stats_base->category) {

            case AWSCRT_STAT_CAT_HTTP1: {
                struct aws_crt_statistics_http1 *http1_stats = (struct aws_crt_statistics_http1 *)stats_base;
                impl->pending_read_interval_ns = http1_stats->pending_incoming_stream_ns;
                impl->pending_write_interval_ns = http1_stats->pending_outgoing_stream_ns;
                break;
            }

            default:
                break;
        }
    }
}

static void s_mock_destroy(struct aws_crt_statistics_handler *handler) {
    if (handler == NULL) {
        return;
    }

    aws_mem_release(handler->allocator, handler);
}

static uint64_t s_mock_get_report_interval_ms(struct aws_crt_statistics_handler *handler) {
    (void)handler;

    return 1000;
}

static struct aws_crt_statistics_handler_vtable s_http_mock_monitor_vtable = {
    .process_statistics = s_mock_process_statistics,
    .destroy = s_mock_destroy,
    .get_report_interval_ms = s_mock_get_report_interval_ms,
};

static struct aws_crt_statistics_handler *s_aws_crt_statistics_handler_new_http_mock(
        struct aws_allocator *allocator) {
    struct aws_crt_statistics_handler *handler = NULL;
    struct mock_http_connection_monitor_impl *impl = NULL;

    if (!aws_mem_acquire_many(
            allocator,
            2,
            &handler,
            sizeof(struct aws_crt_statistics_handler),
            &impl,
            sizeof(struct mock_http_connection_monitor_impl))) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*handler);
    AWS_ZERO_STRUCT(*impl);

    handler->vtable = &s_http_mock_monitor_vtable;
    handler->allocator = allocator;
    handler->impl = impl;

    return handler;
}

/*
static int s_response_tester_init_ex(
    struct response_tester *response,
    struct tester *master_tester,
    struct aws_http_message *request,
    struct aws_http_make_request_options *custom_opt,
    void *specific_test_data) {

    AWS_ZERO_STRUCT(*response);
    response->master_tester = master_tester;
    ASSERT_SUCCESS(aws_byte_buf_init(&response->storage, master_tester->alloc, 1024 * 1024 * 1));

struct aws_http_make_request_options opt;
if (custom_opt) {
opt = *custom_opt;
} else {
AWS_ZERO_STRUCT(opt);
}

opt.self_size = sizeof(struct aws_http_make_request_options);
opt.request = request;
opt.user_data = response;
opt.on_response_headers = s_response_tester_on_headers;
opt.on_response_header_block_done = s_response_tester_on_header_block_done;
opt.on_response_body = s_response_tester_on_body;
opt.on_complete = s_response_tester_on_complete;

response->specific_test_data = specific_test_data;
response->stream = aws_http_connection_make_request(master_tester->connection, &opt);
if (!response->stream) {
return AWS_OP_ERR;
}

return AWS_OP_SUCCESS;
}
 */

/*
 *
struct http_request_info {
    struct aws_http_request *request;
    struct aws_http_stream *stream;
};

 * Make a request, configure options, submit request
 */
static void s_add_outgoing_stream(struct test_http_stats_event *event) {
    (void)event;
}

static void s_add_incoming_stream(struct test_http_stats_event *event) {
    (void)event;
}

static int s_do_http_statistics_test(
    struct aws_allocator *allocator,
    struct test_http_stats_event *events,
    size_t event_count,
    uint64_t expected_pending_read_interval_ns,
    uint64_t expected_pending_write_interval_ns) {

    s_init_monitor_test(allocator, s_aws_crt_statistics_handler_new_http_mock(allocator));

    for (size_t i = 0; i < event_count; ++i) {
        struct test_http_stats_event *event = events + i;

        switch (event->event_type) {
            case MTHSET_TIME:
                aws_atomic_store_int(&s_clock_value, event->timestamp);
                break;

            case MTHSET_FLUSH:
                testing_channel_drain_queued_tasks(&s_test_context.test_channel);
                break;

            case MTHSET_ADD_OUTGOING_STREAM:
                s_add_outgoing_stream(event);
                break;

            case MTHSET_ADD_INCOMING_STREAM:
                s_add_incoming_stream(event);
                break;

            case MTHSET_TICK:
                break;
        }
    }

    struct mock_http_connection_monitor_impl *monitor_impl = s_test_context.monitor->impl;

    ASSERT_TRUE(expected_pending_read_interval_ns == monitor_impl->pending_read_interval_ns);
    ASSERT_TRUE(expected_pending_write_interval_ns == monitor_impl->pending_write_interval_ns);

    s_clean_up_monitor_test();

    return AWS_OP_SUCCESS;
}

static struct test_http_stats_event s_test_events[] = {
        {
                .event_type = MTHSET_TIME,
                .timestamp = 0,
        },
};
static int s_test_http_stats_simple(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_statistics_test(allocator, s_test_events, AWS_ARRAY_SIZE(s_test_events), 0, 0);
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_stats_simple, s_test_http_stats_simple);