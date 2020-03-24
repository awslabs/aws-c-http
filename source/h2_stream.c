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
    .activate = aws_h2_stream_activate,
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

static struct aws_h2_connection *s_get_h2_connection(const struct aws_h2_stream *stream) {
    return AWS_CONTAINER_OF(stream->base.owning_connection, struct aws_h2_connection, base);
}

#define AWS_PRECONDITION_ON_CHANNEL_THREAD(STREAM)                                                                     \
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(s_get_h2_connection(STREAM)->base.channel_slot->channel))

struct aws_h2_stream *aws_h2_stream_new_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {
    AWS_PRECONDITION(client_connection);
    AWS_PRECONDITION(options);

    struct aws_h2_stream *stream = aws_mem_calloc(client_connection->alloc, 1, sizeof(struct aws_h2_stream));
    if (!stream) {
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

    /* Stream refcount starts at 1, and gets incremented again for the connection upon a call to activate() */
    aws_atomic_init_int(&stream->base.refcount, 1);

    /* Init H2 specific stuff */
    stream->thread_data.state = AWS_H2_STREAM_STATE_IDLE;
    stream->thread_data.outgoing_message = options->request;
    aws_http_message_acquire(stream->thread_data.outgoing_message);

    return stream;
}

static void s_stream_destroy(struct aws_http_stream *stream_base) {
    AWS_PRECONDITION(stream_base);
    struct aws_h2_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h2_stream, base);

    AWS_H2_STREAM_LOG(DEBUG, stream, "Destroying stream");

    aws_http_message_release(stream->thread_data.outgoing_message);

    aws_mem_release(stream->base.alloc, stream);
}

enum aws_h2_stream_state aws_h2_stream_get_state(const struct aws_h2_stream *stream) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);
    return stream->thread_data.state;
}

int aws_h2_stream_on_activated(struct aws_h2_stream *stream, bool *out_has_outgoing_data) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    struct aws_h2_connection *connection = s_get_h2_connection(stream);

    /* Create HEADERS frame */
    const struct aws_http_message *msg = stream->thread_data.outgoing_message;
    bool has_body_stream = aws_http_message_get_body_stream(msg) != NULL;
    struct aws_h2_frame *headers_frame = aws_h2_frame_new_headers(
        stream->base.alloc,
        stream->base.id,
        aws_http_message_get_const_headers(msg),
        !has_body_stream /* end_stream */,
        0 /* padding - not currently configurable via public API */,
        NULL /* priority - not currently configurable via public API */);

    if (!headers_frame) {
        AWS_H2_STREAM_LOGF(ERROR, stream, "Failed to create HEADERS frame: %s", aws_error_name(aws_last_error()));
        goto error;
    }

    if (has_body_stream) {
        /* If stream has DATA to send, put it in the outgoing_streams_list, and we'll send data later */
        stream->thread_data.state = AWS_H2_STREAM_STATE_OPEN;
        *out_has_outgoing_data = has_body_stream;
    } else {
        /* If stream has no body, then HEADERS frame marks the end of outgoing data */
        stream->thread_data.state = AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL;
        *out_has_outgoing_data = has_body_stream;
    }

    aws_h2_connection_enqueue_outgoing_frame(connection, headers_frame);
    return AWS_OP_SUCCESS;

error:
    return AWS_OP_ERR;
}
