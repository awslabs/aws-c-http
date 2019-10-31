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
#include <aws/http/private/connection_monitor.h>
#include <aws/http/private/h1_connection.h>
#include <aws/http/request_response.h>
#include <aws/http/statistics.h>
#include <aws/io/channel.h>
#include <aws/io/statistics.h>
#include <aws/io/stream.h>

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
    struct aws_http_message *request;
    struct aws_http_stream *stream;
    struct aws_input_stream *body;
    bool response_completed;
};

struct monitor_test_context {
    struct aws_allocator *allocator;
    struct testing_channel test_channel;
    struct aws_http_connection *connection;
    struct aws_crt_statistics_handler *monitor;

    struct aws_array_list requests;
    struct aws_byte_buf large_body_buf;
};

static struct monitor_test_context s_test_context;

static struct aws_atomic_var s_clock_value;

static int s_mock_clock(uint64_t *timestamp) {
    *timestamp = aws_atomic_load_int(&s_clock_value);

    return AWS_OP_SUCCESS;
}

/* big enough to spill into a second io message when headers/method included */
#define TICK_BODY_SIZE 16384
#define MAX_BODY_SIZE (1024 * 1024)

static int s_init_monitor_test(struct aws_allocator *allocator, struct aws_crt_statistics_handler *monitor) {

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

    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&s_test_context.requests, allocator, 1, sizeof(struct http_request_info)));

    aws_byte_buf_init(&s_test_context.large_body_buf, allocator, MAX_BODY_SIZE);
    memset(s_test_context.large_body_buf.buffer, '0', MAX_BODY_SIZE);
    s_test_context.large_body_buf.len = MAX_BODY_SIZE;

    return AWS_OP_SUCCESS;
}

static void s_clean_up_monitor_test(void) {

    size_t request_count = aws_array_list_length(&s_test_context.requests);
    for (size_t i = 0; i < request_count; ++i) {
        struct http_request_info *request_info = NULL;
        aws_array_list_get_at_ptr(&s_test_context.requests, (void **)&request_info, i);

        aws_http_message_destroy(request_info->request);
        aws_http_stream_release(request_info->stream);
        aws_input_stream_destroy(request_info->body);
    }

    aws_http_connection_release(s_test_context.connection);

    testing_channel_clean_up(&s_test_context.test_channel);

    aws_array_list_clean_up(&s_test_context.requests);
    aws_byte_buf_clean_up(&s_test_context.large_body_buf);

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

 Test Pattern 1 (monitor calculations and side affect):

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

    s_init_monitor_test(
        allocator, aws_crt_statistics_handler_new_http_connection_monitor(allocator, monitoring_options));

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
 Loop over h1 connection events [(t_i, http_event)]
    SetCurrentChannelTime(t_i)
    ApplyEvent(http_event)

where events include instances of verification of mock-captured http stat state

 */

enum monitor_test_http_stats_event_type {
    MTHSET_ADD_OUTGOING_STREAM,
    MTHSET_ADD_RESPONSE_DATA,
    MTHSET_FLUSH,
    MTHSET_TICK,
    MTHSET_VERIFY
};

struct test_http_stats_event {
    uint64_t timestamp;
    enum monitor_test_http_stats_event_type event_type;
    const char *response_stream_data;
    uint64_t request_body_size;
    uint64_t verify_pending_read_interval_ns;
    uint64_t verify_pending_write_interval_ns;
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

static struct aws_crt_statistics_handler *s_aws_crt_statistics_handler_new_http_mock(struct aws_allocator *allocator) {
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

int s_aws_http_on_incoming_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;
    (void)data;
    (void)user_data;

    return AWS_OP_SUCCESS;
}

void s_aws_http_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    (void)error_code;

    size_t request_index = (size_t)user_data;

    struct http_request_info *request_info;
    aws_array_list_get_at_ptr(&s_test_context.requests, (void **)&request_info, request_index);

    request_info->response_completed = true;
}

static void s_add_outgoing_stream(struct test_http_stats_event *event) {
    (void)event;

    struct http_request_info request_info;
    AWS_ZERO_STRUCT(request_info);

    request_info.request = aws_http_message_new_request(s_test_context.allocator);
    aws_http_message_set_request_method(request_info.request, aws_byte_cursor_from_c_str("GET"));
    struct aws_http_header host_header = {
        .name = aws_byte_cursor_from_c_str("host"),
        .value = aws_byte_cursor_from_c_str("www.derp.com"),
    };
    aws_http_message_add_header(request_info.request, host_header);
    aws_http_message_set_request_path(request_info.request, aws_byte_cursor_from_c_str("/index.html?queryparam=value"));

    AWS_FATAL_ASSERT(event->request_body_size <= MAX_BODY_SIZE);
    if (event->request_body_size > 0) {
        char cl_buffer[256];
        sprintf(cl_buffer, "%zu", s_test_context.large_body_buf.len);

        struct aws_http_header content_length_header = {
            .name = aws_byte_cursor_from_c_str("content-length"),
            .value = aws_byte_cursor_from_c_str(cl_buffer),
        };
        aws_http_message_add_header(request_info.request, content_length_header);

        struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&s_test_context.large_body_buf);
        body_cursor.len = event->request_body_size;
        request_info.body = aws_input_stream_new_from_cursor(s_test_context.allocator, &body_cursor);

        aws_http_message_set_body_stream(request_info.request, request_info.body);
    }

    struct aws_http_make_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.request = request_info.request;
    request_options.on_complete = s_aws_http_on_stream_complete;
    request_options.on_response_body = s_aws_http_on_incoming_body;
    request_options.self_size = sizeof(struct aws_http_make_request_options);
    request_options.user_data = (void *)aws_array_list_length(&s_test_context.requests);

    request_info.stream = aws_http_connection_make_request(s_test_context.connection, &request_options);

    aws_array_list_push_back(&s_test_context.requests, &request_info);
}

static void s_add_response_data(struct test_http_stats_event *event) {
    testing_channel_send_response_str(&s_test_context.test_channel, event->response_stream_data);
}

static int s_do_http_statistics_test(
    struct aws_allocator *allocator,
    struct test_http_stats_event *events,
    size_t event_count) {

    s_init_monitor_test(allocator, s_aws_crt_statistics_handler_new_http_mock(allocator));
    struct mock_http_connection_monitor_impl *monitor_impl = s_test_context.monitor->impl;

    for (size_t i = 0; i < event_count; ++i) {
        struct test_http_stats_event *event = events + i;
        aws_atomic_store_int(&s_clock_value, event->timestamp);

        switch (event->event_type) {
            case MTHSET_FLUSH:
                testing_channel_drain_queued_tasks(&s_test_context.test_channel);
                break;

            case MTHSET_ADD_OUTGOING_STREAM:
                s_add_outgoing_stream(event);
                break;

            case MTHSET_ADD_RESPONSE_DATA:
                s_add_response_data(event);
                break;

            case MTHSET_TICK:
                testing_channel_run_currently_queued_tasks(&s_test_context.test_channel);
                break;

            case MTHSET_VERIFY:
                ASSERT_TRUE(event->verify_pending_read_interval_ns == monitor_impl->pending_read_interval_ns);
                ASSERT_TRUE(event->verify_pending_write_interval_ns == monitor_impl->pending_write_interval_ns);
                break;
        }
    }

    size_t request_count = aws_array_list_length(&s_test_context.requests);
    for (size_t i = 0; i < request_count; ++i) {
        struct http_request_info *request_info = NULL;
        aws_array_list_get_at_ptr(&s_test_context.requests, (void **)&request_info, i);

        ASSERT_TRUE(request_info->response_completed);
    }

    s_clean_up_monitor_test();

    return AWS_OP_SUCCESS;
}

static struct test_http_stats_event s_http_stats_test_trivial[] = {
    {
        .event_type = MTHSET_VERIFY,
        .timestamp = 0,
        .verify_pending_read_interval_ns = 0,
        .verify_pending_write_interval_ns = 0,
    },
};
static int s_test_http_stats_trivial(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result =
        s_do_http_statistics_test(allocator, s_http_stats_test_trivial, AWS_ARRAY_SIZE(s_http_stats_test_trivial));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_stats_trivial, s_test_http_stats_trivial);

static struct test_http_stats_event s_http_stats_test_basic_request[] = {
    {
        .event_type = MTHSET_ADD_OUTGOING_STREAM,
        .timestamp = 100,
        .request_body_size = TICK_BODY_SIZE,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = 100,
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = 200,
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 500,
        .response_stream_data = "HTTP/1.1 200 OK\r\n",
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 700,
        .response_stream_data = "Content-Length: 9\r\n\r\nSomething",
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = 700,
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = AWS_TIMESTAMP_NANOS,
    },
    {
        .event_type = MTHSET_VERIFY,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .verify_pending_read_interval_ns = 600,  /* [100, 700] */
        .verify_pending_write_interval_ns = 100, /* [100, 200] */
    },
};
static int s_test_http_stats_basic_request(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_statistics_test(
        allocator, s_http_stats_test_basic_request, AWS_ARRAY_SIZE(s_http_stats_test_basic_request));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_stats_basic_request, s_test_http_stats_basic_request);

static struct test_http_stats_event s_http_stats_test_split_across_gather_boundary[] = {
    {
        .event_type = MTHSET_ADD_OUTGOING_STREAM,
        .timestamp = AWS_TIMESTAMP_NANOS - 100,
        .request_body_size = 2 * TICK_BODY_SIZE,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = AWS_TIMESTAMP_NANOS - 100,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = AWS_TIMESTAMP_NANOS,
    },
    {
        .event_type = MTHSET_VERIFY,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .verify_pending_read_interval_ns = 100,  /* [NANOS - 100, NANOS] */
        .verify_pending_write_interval_ns = 100, /* [NANOS - 100, NANOS] */
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = AWS_TIMESTAMP_NANOS + 100,
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = AWS_TIMESTAMP_NANOS + 500,
        .response_stream_data = "HTTP/1.1 200 OK\r\n",
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = AWS_TIMESTAMP_NANOS + 700,
        .response_stream_data = "Content-Length: 9\r\n\r\nSomething",
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = AWS_TIMESTAMP_NANOS + 700,
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = 2 * AWS_TIMESTAMP_NANOS,
    },
    {
        .event_type = MTHSET_VERIFY,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .verify_pending_read_interval_ns = 700,  /* [NANOS, NANOS + 700] */
        .verify_pending_write_interval_ns = 100, /* [NANOS, NANOS + 100] */
    },
};
static int s_test_http_stats_split_across_gather_boundary(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_statistics_test(
        allocator,
        s_http_stats_test_split_across_gather_boundary,
        AWS_ARRAY_SIZE(s_http_stats_test_split_across_gather_boundary));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_stats_split_across_gather_boundary, s_test_http_stats_split_across_gather_boundary);

/*
 * Pipeline 3 requests before beginning response data.
 *
 * The request body sizes have a total length of 4 * TICK_BODY_SIZE which means it will take 5 ticks
 * to completely "write" them.
 */
static struct test_http_stats_event s_http_stats_test_pipelined[] = {
    {
        .event_type = MTHSET_ADD_OUTGOING_STREAM,
        .timestamp = 100,
        .request_body_size = 2 * TICK_BODY_SIZE,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = 100,
    },
    {
        .event_type = MTHSET_ADD_OUTGOING_STREAM,
        .timestamp = 300,
        .request_body_size = 1 * TICK_BODY_SIZE,
    },
    {
        .event_type = MTHSET_ADD_OUTGOING_STREAM,
        .timestamp = 500,
        .request_body_size = 1 * TICK_BODY_SIZE,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = 600,
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 700,
        .response_stream_data = "HTTP/1.1 200 OK\r\n",
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 800,
        .response_stream_data = "Content-Length: 9\r\n\r\nSomething",
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = 900,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = 1000,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = 1100,
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 1200,
        .response_stream_data = "HTTP/1.1 200 OK\r\n",
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 1300,
        .response_stream_data = "Content-Length: 9\r\n\r\nSomethingHTTP/1.1 200 OK\r\n",
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 1400,
        .response_stream_data = "Content-Length: 9\r\n\r\nSomething",
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = AWS_TIMESTAMP_NANOS,
    },
    {
        .event_type = MTHSET_VERIFY,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .verify_pending_read_interval_ns = 1300,  /* [100, 800] U [300, 1300] U [500, 1400] = [100, 1400] */
        .verify_pending_write_interval_ns = 1000, /* [100, 600] U [300, 900] U [500, 1100] = [100, 1100] */
    },
};
static int s_test_http_stats_pipelined(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result =
        s_do_http_statistics_test(allocator, s_http_stats_test_pipelined, AWS_ARRAY_SIZE(s_http_stats_test_pipelined));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_stats_pipelined, s_test_http_stats_pipelined);

static struct test_http_stats_event s_http_stats_test_multiple_requests_with_gap[] = {
    {
        .event_type = MTHSET_ADD_OUTGOING_STREAM,
        .timestamp = 100,
        .request_body_size = TICK_BODY_SIZE,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = 100,
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = 200,
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 500,
        .response_stream_data = "HTTP/1.1 200 OK\r\n",
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 700,
        .response_stream_data = "Content-Length: 9\r\n\r\nSomething",
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = 700,
    },
    {
        .event_type = MTHSET_ADD_OUTGOING_STREAM,
        .timestamp = 2000,
        .request_body_size = TICK_BODY_SIZE,
    },
    {
        .event_type = MTHSET_TICK,
        .timestamp = 2000,
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = 2200,
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 2500,
        .response_stream_data = "HTTP/1.1 200 OK\r\n",
    },
    {
        .event_type = MTHSET_ADD_RESPONSE_DATA,
        .timestamp = 2700,
        .response_stream_data = "Content-Length: 9\r\n\r\nSomething",
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = 2700,
    },
    {
        .event_type = MTHSET_FLUSH,
        .timestamp = AWS_TIMESTAMP_NANOS,
    },
    {
        .event_type = MTHSET_VERIFY,
        .timestamp = AWS_TIMESTAMP_NANOS,
        .verify_pending_read_interval_ns = 1300, /* [100, 700] + [2000, 2700]*/
        .verify_pending_write_interval_ns = 300, /* [100, 200] + [2000, 2200] */
    },
};
static int s_test_http_stats_multiple_requests_with_gap(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int result = s_do_http_statistics_test(
        allocator,
        s_http_stats_test_multiple_requests_with_gap,
        AWS_ARRAY_SIZE(s_http_stats_test_multiple_requests_with_gap));
    ASSERT_TRUE(result == AWS_OP_SUCCESS);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_stats_multiple_requests_with_gap, s_test_http_stats_multiple_requests_with_gap);
