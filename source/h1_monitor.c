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

#include <aws/io/statistics.h>


#include <aws/common/clock.h>

struct aws_statistics_handler_http_default_impl {
    ??;
};

static void s_process_statistics(
    struct aws_crt_statistics_handler *handler,
    struct aws_crt_statistics_sample_interval *interval,
    struct aws_array_list *stats_list) {

    (void)interval;

    struct aws_statistics_handler_test_impl *impl = handler->impl;

    if (impl->start_time_ns == 0) {
        impl->start_time_ns =
                aws_timestamp_convert(interval->begin_time_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    }

    size_t stats_count = aws_array_list_length(stats_list);
    for (size_t i = 0; i < stats_count; ++i) {
        struct aws_crt_statistics_base *stats_base = NULL;
        if (aws_array_list_get_at(stats_list, &stats_base, i)) {
            continue;
        }

        switch (stats_base->category) {
            case AWSCRT_STAT_CAT_SOCKET: {
                struct aws_crt_statistics_socket *socket_stats = (struct aws_crt_statistics_socket *)stats_base;
                impl->total_bytes_read += socket_stats->bytes_read;
                impl->total_bytes_written += socket_stats->bytes_written;
                break;
            }

            case AWSCRT_STAT_CAT_TLS: {
                struct aws_crt_statistics_tls *tls_stats = (struct aws_crt_statistics_tls *)stats_base;
                impl->tls_status = tls_stats->handshake_status;
                break;
            }

            default:
                break;
        }
    }
}

static void s_cleanup_handler(struct aws_crt_statistics_handler *handler) {
    struct aws_statistics_handler_http_default_impl *impl = handler->impl;
    (void)impl;
}

static uint64_t s_get_report_interval_ms(struct aws_crt_statistics_handler *handler) {
    (void)handler;

    return 1000;
}

static struct aws_crt_statistics_handler_vtable s_statistics_handler_http_default_vtable = {
    .process_statistics = s_process_statistics,
    .cleanup = s_cleanup_handler,
    .get_report_interval_ms = s_get_report_interval_ms};

struct aws_crt_statistics_handler *aws_crt_statistics_handler_new_http_default(struct aws_allocator *allocator, struct aws_crt_statistics_handler_http_default_options *options) {
    struct aws_crt_statistics_handler *handler = NULL;
    struct aws_statistics_handler_http_default_impl *impl = NULL;

    if (!aws_mem_acquire_many(
            allocator,
            2,
            &handler,
            sizeof(struct aws_crt_statistics_handler),
            &impl,
            sizeof(struct aws_statistics_handler_http_default_impl))) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*handler);
    AWS_ZERO_STRUCT(*impl);

    handler->vtable = &s_statistics_handler_http_default_vtable;
    handler->allocator = allocator;
    handler->impl = impl;

    return handler;
}
