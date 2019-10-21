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

#include <aws/http/private/h1_monitor.h>

#include <aws/http/statistics.h>
#include <aws/io/channel.h>
#include <aws/io/logging.h>
#include <aws/io/statistics.h>


#include <aws/common/clock.h>

struct aws_statistics_handler_http_connection_monitor_impl {
    struct aws_crt_http_connection_monitor_options options;

    uint64_t tls_start_time_ms;

    uint32_t consecutive_throughput_failures;
};

struct aws_h1_monitor_stats_process_context {
    struct aws_channel *channel;
    struct aws_crt_statistics_sample_interval interval;
    uint64_t pending_read_interval_ms;
    uint64_t pending_write_interval_ms;
    uint64_t bytes_read;
    uint64_t bytes_written;
    enum aws_tls_negotiation_status tls_status;
};

static void s_check_for_tls_timeout(struct aws_statistics_handler_http_connection_monitor_impl *monitor_impl, struct aws_h1_monitor_stats_process_context *context) {
    if (monitor_impl->options.tls_timeout_ms == 0 || context->tls_status != AWS_MTLS_STATUS_ONGOING) {
        return;
    }

    AWS_FATAL_ASSERT(context->interval.end_time_ms >= monitor_impl->tls_start_time_ms);

    if (context->interval.end_time_ms - monitor_impl->tls_start_time_ms < monitor_impl->options.tls_timeout_ms) {
        return;
    }

    AWS_LOGF_INFO(AWS_LS_IO_CHANNEL, "id=%p: Channel tls timeout (%u ms) hit.  Shutting down.", (void *)(context->channel), monitor_impl->options.tls_timeout_ms);

    aws_channel_shutdown(context->channel, AWS_ERROR_HTTP_CHANNEL_MONITOR_SHUTDOWN);
}

static void s_check_for_throughput_failure(struct aws_statistics_handler_http_connection_monitor_impl *monitor_impl, struct aws_h1_monitor_stats_process_context *context) {
    if (monitor_impl->options.minimum_throughput_bytes_per_second == 0 || monitor_impl->options.minimum_throughput_failure_threshold_in_seconds == 0) {
        return;
    }

    uint64_t pending_time_ms = 0;
    if (aws_add_u64_checked(context->pending_read_interval_ms, context->pending_write_interval_ms, &pending_time_ms) != AWS_OP_SUCCESS) {
        AWS_LOGF_ERROR(AWS_LS_IO_CHANNEL, "id=%p: io interval summation overflow", (void *)context->channel);
        return;
    }

    if (pending_time_ms == 0) {
        monitor_impl->consecutive_throughput_failures = 0;
    }

    uint64_t total_bytes = 0;
    if (aws_add_u64_checked(context->bytes_read, context->bytes_written, &total_bytes) != AWS_OP_SUCCESS) {
        AWS_LOGF_ERROR(AWS_LS_IO_CHANNEL, "id=%p: io bytes summation overflow", (void *)context->channel);
        return;
    }

    uint64_t throughput = ??;
    AWS_LOGF_DEBUG(AWS_LS_IO_CHANNEL, "id=%p: channel throughput %zu", (void *)context->channel, throughput);

    if (throughput < monitor_impl->options.minimum_throughput_bytes_per_second) {
        ++monitor_impl->consecutive_throughput_failures;
    } else {
        monitor_impl->consecutive_throughput_failures = 0;
    }

    if (monitor_impl->consecutive_throughput_failures < monitor_impl->options.minimum_throughput_failure_threshold_in_seconds) {
        return;
    }

    AWS_LOGF_INFO(AWS_LS_IO_CHANNEL, "id=%p: Channel low throughput threshold hit (< %zu bytes per second for %u seconds).  Shutting down.", (void *)(context->channel), monitor_impl->options.minimum_throughput_bytes_per_second, monitor_impl->options.minimum_throughput_failure_threshold_in_seconds);

    aws_channel_shutdown(context->channel, AWS_ERROR_HTTP_CHANNEL_MONITOR_SHUTDOWN);
}


static void s_process_statistics(
    struct aws_crt_statistics_handler *handler,
    struct aws_crt_statistics_sample_interval *interval,
    struct aws_array_list *stats_list,
    void *context) {

    (void)interval;

    struct aws_statistics_handler_http_connection_monitor_impl *impl = handler->impl;

    struct aws_h1_monitor_stats_process_context stats_context;
    AWS_ZERO_STRUCT(context);
    stats_context.channel = (struct aws_channel *)context;
    stats_context.interval = *interval;

    size_t stats_count = aws_array_list_length(stats_list);
    for (size_t i = 0; i < stats_count; ++i) {
        struct aws_crt_statistics_base *stats_base = NULL;
        if (aws_array_list_get_at(stats_list, &stats_base, i)) {
            continue;
        }

        switch (stats_base->category) {
            case AWSCRT_STAT_CAT_SOCKET: {
                struct aws_crt_statistics_socket *socket_stats = (struct aws_crt_statistics_socket *)stats_base;
                stats_context.bytes_read = socket_stats->bytes_read;
                stats_context.bytes_written = socket_stats->bytes_written;
                break;
            }

            case AWSCRT_STAT_CAT_TLS: {
                struct aws_crt_statistics_tls *tls_stats = (struct aws_crt_statistics_tls *)stats_base;
                stats_context.tls_status = tls_stats->handshake_status;
                if (stats_context.tls_status != AWS_MTLS_STATUS_NONE && impl->tls_start_time_ms == 0) {
                    impl->tls_start_time_ms = interval->end_time_ms;
                }
                break;
            }

            case AWSCRT_STAT_CAT_HTTP1: {
                struct aws_crt_statistics_http1 *http1_stats = (struct aws_crt_statistics_http1 *)stats_base;
                stats_context.pending_read_interval_ms = http1_stats->pending_read_ms;
                stats_context.pending_write_interval_ms = http1_stats->pending_write_ms;
                break;
            }

            default:
                break;
        }
    }

    s_check_for_tls_timeout(impl, &stats_context);

    s_check_for_throughput_failure(impl, &stats_context);
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

static struct aws_crt_statistics_handler_vtable s_statistics_handler_http_default_vtable = {
    .process_statistics = s_process_statistics,
    .destroy = s_destroy,
    .get_report_interval_ms = s_get_report_interval_ms,
};

struct aws_crt_statistics_handler *aws_crt_statistics_handler_new_http_default(struct aws_allocator *allocator, struct aws_crt_http_connection_monitor_options *options) {
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

    handler->vtable = &s_statistics_handler_http_default_vtable;
    handler->allocator = allocator;
    handler->impl = impl;

    return handler;
}
