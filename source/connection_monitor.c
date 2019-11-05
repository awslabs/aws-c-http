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

#include <aws/http/private/connection_monitor.h>

#include <aws/http/connection.h>
#include <aws/http/statistics.h>
#include <aws/io/channel.h>
#include <aws/io/logging.h>
#include <aws/io/statistics.h>

#include <aws/common/clock.h>

#include <inttypes.h>

static void s_process_statistics(
    struct aws_crt_statistics_handler *handler,
    struct aws_crt_statistics_sample_interval *interval,
    struct aws_array_list *stats_list,
    void *context) {

    (void)interval;

    struct aws_statistics_handler_http_connection_monitor_impl *impl = handler->impl;
    if (!aws_http_connection_monitoring_options_is_valid(&impl->options)) {
        return;
    }

    uint64_t pending_read_interval_ns = 0;
    uint64_t pending_write_interval_ns = 0;
    uint64_t bytes_read = 0;
    uint64_t bytes_written = 0;

    /*
     * Pull out the data needed to perform the throughput calculation
     */
    size_t stats_count = aws_array_list_length(stats_list);
    for (size_t i = 0; i < stats_count; ++i) {
        struct aws_crt_statistics_base *stats_base = NULL;
        if (aws_array_list_get_at(stats_list, &stats_base, i)) {
            continue;
        }

        switch (stats_base->category) {
            case AWSCRT_STAT_CAT_SOCKET: {
                struct aws_crt_statistics_socket *socket_stats = (struct aws_crt_statistics_socket *)stats_base;
                bytes_read = socket_stats->bytes_read;
                bytes_written = socket_stats->bytes_written;
                break;
            }

            case AWSCRT_STAT_CAT_HTTP1_CHANNEL: {
                struct aws_crt_statistics_http1 *http1_stats = (struct aws_crt_statistics_http1 *)stats_base;
                pending_read_interval_ns = http1_stats->pending_incoming_stream_ns;
                pending_write_interval_ns = http1_stats->pending_outgoing_stream_ns;
                break;
            }

            default:
                break;
        }
    }

    struct aws_channel *channel = context;

    /*
     * All early-out/negative execution paths reset the failure count to zero.  Keep a copy of the current count for the
     * remaining path.
     */
    uint32_t current_failure_count = impl->consecutive_throughput_failures;
    impl->consecutive_throughput_failures = 0;

    if (pending_read_interval_ns == 0 && pending_write_interval_ns == 0) {
        return;
    }

    uint64_t bytes_read_per_second = 0;
    if (pending_read_interval_ns > 0) {
        double fractional_bytes_read_per_second =
            (double)bytes_read * (double)AWS_TIMESTAMP_NANOS / (double)pending_read_interval_ns;
        if (fractional_bytes_read_per_second >= (double)UINT64_MAX) {
            bytes_read_per_second = UINT64_MAX;
        } else {
            bytes_read_per_second = (uint64_t)fractional_bytes_read_per_second;
        }
    }

    uint64_t bytes_written_per_second = 0;
    if (pending_write_interval_ns) {
        double fractional_bytes_written_per_second =
            (double)bytes_written * (double)AWS_TIMESTAMP_NANOS / (double)pending_write_interval_ns;
        if (fractional_bytes_written_per_second >= (double)UINT64_MAX) {
            bytes_written_per_second = UINT64_MAX;
        } else {
            bytes_written_per_second = (uint64_t)fractional_bytes_written_per_second;
        }
    }

    uint64_t bytes_per_second = 0;
    if (aws_add_u64_checked(bytes_written_per_second, bytes_read_per_second, &bytes_per_second)) {
        AWS_LOGF_INFO(AWS_LS_IO_CHANNEL, "id=%p: io throughput overflow calculation", (void *)channel);
        return;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_CHANNEL,
        "id=%p: channel throughput - %" PRIu64 " bytes per second",
        (void *)channel,
        bytes_per_second);

    if (bytes_per_second >= impl->options.minimum_throughput_bytes_per_second) {
        return;
    }

    /*
     * We failed the throughput check.  Restore and increment the failure count and then check if the failure threshold
     * has been crossed.
     */
    impl->consecutive_throughput_failures = current_failure_count + 1;
    AWS_LOGF_INFO(
        AWS_LS_IO_CHANNEL,
        "id=%p: Channel low throughput warning.  Currently %u consecutive failures",
        (void *)channel,
        impl->consecutive_throughput_failures);

    if (impl->consecutive_throughput_failures <= impl->options.allowable_consecutive_throughput_failures) {
        return;
    }

    AWS_LOGF_INFO(
        AWS_LS_IO_CHANNEL,
        "id=%p: Channel low throughput threshold exceeded (< %" PRIu64
        " bytes per second for more than %u checks).  Shutting down.",
        (void *)channel,
        impl->options.minimum_throughput_bytes_per_second,
        impl->options.allowable_consecutive_throughput_failures);

    aws_channel_shutdown(channel, AWS_ERROR_HTTP_CHANNEL_THROUGHPUT_FAILURE);
}

static void s_destroy(struct aws_crt_statistics_handler *handler) {
    if (handler == NULL) {
        return;
    }

    aws_mem_release(handler->allocator, handler);
}

static uint64_t s_get_report_interval_ms(struct aws_crt_statistics_handler *handler) {
    (void)handler;

    return 1000;
}

static struct aws_crt_statistics_handler_vtable s_http_connection_monitor_vtable = {
    .process_statistics = s_process_statistics,
    .destroy = s_destroy,
    .get_report_interval_ms = s_get_report_interval_ms,
};

struct aws_crt_statistics_handler *aws_crt_statistics_handler_new_http_connection_monitor(
    struct aws_allocator *allocator,
    struct aws_http_connection_monitoring_options *options) {
    struct aws_crt_statistics_handler *handler = NULL;
    struct aws_statistics_handler_http_connection_monitor_impl *impl = NULL;

    if (!aws_mem_acquire_many(
            allocator,
            2,
            &handler,
            sizeof(struct aws_crt_statistics_handler),
            &impl,
            sizeof(struct aws_statistics_handler_http_connection_monitor_impl))) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*handler);
    AWS_ZERO_STRUCT(*impl);
    impl->options = *options;

    handler->vtable = &s_http_connection_monitor_vtable;
    handler->allocator = allocator;
    handler->impl = impl;

    return handler;
}

bool aws_http_connection_monitoring_options_is_valid(const struct aws_http_connection_monitoring_options *options) {
    if (options == NULL) {
        return false;
    }

    return options->allowable_consecutive_throughput_failures > 0 && options->minimum_throughput_bytes_per_second > 0;
}
