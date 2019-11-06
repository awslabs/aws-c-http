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

#include <aws/http/statistics.h>

int aws_crt_statistics_http1_channel_init(struct aws_crt_statistics_http1_channel *stats) {
    AWS_ZERO_STRUCT(*stats);
    stats->category = AWSCRT_STAT_CAT_HTTP1_CHANNEL;

    return AWS_OP_SUCCESS;
}

void aws_crt_statistics_http1_channel_cleanup(struct aws_crt_statistics_http1_channel *stats) {
    (void)stats;
}

void aws_crt_statistics_http1_channel_reset(struct aws_crt_statistics_http1_channel *stats) {
    stats->pending_outgoing_stream_ms = 0;
    stats->pending_incoming_stream_ms = 0;
    stats->current_outgoing_stream_id = 0;
    stats->current_incoming_stream_id = 0;
}
