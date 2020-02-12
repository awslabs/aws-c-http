#ifndef AWS_HTTP_H2_STREAM_H
#define AWS_HTTP_H2_STREAM_H

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

#include <aws/http/private/h2_frames.h>
#include <aws/http/private/request_response_impl.h>

#include <aws/common/mutex.h>

#include <inttypes.h>

#define AWS_H2_STREAM_LOGF(level, stream, text, ...)                                                                   \
    AWS_LOGF_##level(                                                                                                  \
        AWS_LS_HTTP_STREAM,                                                                                            \
        "id=%" PRIu32 " connection=%p state=%s: " text,                                                                \
        (stream)->base.id,                                                                                             \
        (void *)(stream)->base.owning_connection,                                                                      \
        aws_h2_stream_state_to_str((stream)->thread_data.state),                                                       \
        __VA_ARGS__)
#define AWS_H2_STREAM_LOG(level, stream, text) AWS_H2_STREAM_LOGF(level, (stream), "%s", (text))

enum aws_h2_stream_state {
    AWS_H2_STREAM_STATE_IDLE,
    AWS_H2_STREAM_STATE_RESERVED_LOCAL,
    AWS_H2_STREAM_STATE_RESERVED_REMOTE,
    AWS_H2_STREAM_STATE_OPEN,
    AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL,
    AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE,
    AWS_H2_STREAM_STATE_CLOSED,

    AWS_H2_STREAM_STATE_COUNT,
};

struct aws_h2_stream {
    struct aws_http_stream base;

    struct aws_linked_list_node node;

    /* Only the event-loop thread may touch this data */
    struct {
        bool expects_continuation;
        enum aws_h2_stream_state state;
        uint64_t window_size; /* #TODO try to figure out how this actually works, and then implement it */
    } thread_data;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

    } synced_data;
};

struct aws_h2_stream;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
const char *aws_h2_stream_state_to_str(enum aws_h2_stream_state state);

AWS_HTTP_API
struct aws_h2_stream *aws_h2_stream_new_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H2_STREAM_H */
