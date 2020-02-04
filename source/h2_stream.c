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

#include <aws/http/private/h2_stream.h>

#include <aws/http/private/h2_connection.h>

#include <aws/io/channel.h>
#include <aws/io/logging.h>

static void s_stream_destroy(struct aws_http_stream *stream_base);

struct aws_http_stream_vtable s_h2_stream_vtable = {
    .destroy = s_stream_destroy,
    .update_window = NULL,
};

const char *aws_h2_stream_state_to_str(enum aws_h2_stream_state state) {
    switch (state) {
        case AWS_H2_STREAM_STATE_IDLE:
            return "IDLE";
        case AWS_H2_STREAM_STATE_RESERVED_LOCAL:
            return "RESERVED_LOCAL";
        case AWS_H2_STREAM_STATE_RESERVED_REMOTE:
            return "RESERVED_REMOTE";
        case AWS_H2_STREAM_STATE_OPEN:
            return "OPEN";
        case AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL:
            return "HALF_CLOSED_LOCAL";
        case AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE:
            return "HALF_CLOSED_REMOTE";
        case AWS_H2_STREAM_STATE_CLOSED:
            return "CLOSED";
        default:
            /* unreachable */
            AWS_ASSERT(0);
            return "*** UNKNOWN ***";
    }
}

/***********************************************************************************************************************
 * Public API
 **********************************************************************************************************************/

struct aws_h2_stream *aws_h2_stream_new_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {
    AWS_PRECONDITION(client_connection);
    AWS_PRECONDITION(options);

    uint32_t stream_id = aws_http_connection_get_next_stream_id(client_connection);
    if (stream_id == 0) {
        return NULL;
    }

    struct aws_h2_stream *stream = aws_mem_calloc(client_connection->alloc, 1, sizeof(struct aws_h2_stream));
    if (!stream) {
        /* stream id exhausted error was already raised*/
        return NULL;
    }

    /* Initialize base stream */
    stream->base.vtable = &s_h2_stream_vtable;
    stream->base.alloc = client_connection->alloc;
    stream->base.owning_connection = client_connection;
    stream->base.user_data = options->user_data;
    stream->base.on_incoming_headers = options->on_response_headers;
    stream->base.on_incoming_header_block_done = options->on_response_header_block_done;
    stream->base.on_incoming_body = options->on_response_body;
    stream->base.on_complete = options->on_complete;
    stream->base.id = stream_id;

    /* Stream refcount starts at 2. 1 for user and 1 for connection to release when it's done with the stream */
    aws_atomic_init_int(&stream->base.refcount, 2);

    /* Init H2 specific stuff */
    stream->thread_data.state = AWS_H2_STREAM_STATE_IDLE;
    aws_linked_list_node_reset(&stream->node);

    return stream;
}
static void s_stream_destroy(struct aws_http_stream *stream_base) {
    AWS_PRECONDITION(stream_base);
    struct aws_h2_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h2_stream, base);

    AWS_H2_STREAM_LOG(DEBUG, stream, "Destroying stream");

    aws_mem_release(stream->base.alloc, stream);
}
