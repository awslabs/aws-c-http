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

struct aws_h2_stream {
    struct aws_allocator *allocator;

    uint32_t id;
    enum aws_h2_stream_state state;
    bool expects_continuation;

    uint64_t window_size; /* If anyone has any idea how the fuck this works I'm all ears */

    aws_http_on_incoming_headers_fn *on_headers;
    void *on_headers_ud;

    aws_http_on_incoming_body_fn *on_body;
    void *on_body_ud;

    aws_http_on_stream_complete_fn *on_close;
    void *on_close_ud;
};

/***********************************************************************************************************************
 * Frame Handling
 **********************************************************************************************************************/
static int s_h2_stream_handle_data(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_DATA);

    struct aws_h2_frame_data frame;
    if (aws_h2_frame_data_decode(&frame, decoder)) {
        return AWS_OP_ERR;
    }

    /* Call user callback */
    size_t window_size_increment = 0;
    stream->on_body(NULL, &frame.data, &window_size_increment, stream->on_body_ud);

    /* Send window increment packet */
    struct aws_h2_frame_window_update window_update;
    if (aws_h2_frame_window_update_init(&window_update, stream->allocator)) {
        return AWS_OP_ERR;
    }
    window_update.window_size_increment = window_size_increment;
    aws_h2_frame_window_update_encode(&window_update, NULL, NULL); /* #TODO uh, this should do something */

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_headers(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_HEADERS);

    struct aws_h2_frame_headers frame;
    if (aws_h2_frame_headers_decode(&frame, decoder)) {
        return AWS_OP_ERR;
    }

    if (!frame.end_headers) {
        stream->expects_continuation = true;
    }

    stream->on_headers(NULL, frame.header_block.header_fields.data, frame.header_block.header_fields.length, stream->on_headers_ud);

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_priority(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_PRIORITY);

    struct aws_h2_frame_priority frame;
    if (aws_h2_frame_priority_decode(&frame, decoder)) {
        return AWS_OP_ERR;
    }

    /* No idea yet. */
    (void)stream;

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_rst_stream(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_RST_STREAM);

    struct aws_h2_frame_rst_stream frame;
    if (aws_h2_frame_rst_stream_decode(&frame, decoder)) {
        return AWS_OP_ERR;
    }

    stream->state = AWS_H2_STREAM_STATE_CLOSED;

    /* Call user callback stating frame was reset */
    stream->on_close(NULL, frame.error_code, stream->on_close_ud);

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_push_promise(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_PUSH_PROMISE);

    struct aws_h2_frame_push_promise frame;
    if (aws_h2_frame_push_promise_decode(&frame, decoder)) {
        return AWS_OP_ERR;
    }

    if (!frame.end_headers) {
        stream->expects_continuation = true;
    }

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_window_update(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_WINDOW_UPDATE);

    struct aws_h2_frame_window_update frame;
    if (aws_h2_frame_window_update_decode(&frame, decoder)) {
        return AWS_OP_ERR;
    }

    /* Increment the window size, I suppose */
    stream->window_size += frame.window_size_increment;

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_continuation(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_CONTINUATION);

    if (!stream->expects_continuation) {
        return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
    }

    struct aws_h2_frame_continuation frame;
    if (aws_h2_frame_continuation_decode(&frame, decoder)) {
        return AWS_OP_ERR;
    }

    if (!frame.end_headers) {
        stream->expects_continuation = true;
    }

    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * State Machine
 **********************************************************************************************************************/

static int s_h2_stream_state_idle(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    switch (decoder->header.type) {
        case AWS_H2_FRAME_T_HEADERS:
            stream->state = AWS_H2_STREAM_STATE_OPEN;
            return s_h2_stream_handle_headers(stream, decoder);

        case AWS_H2_FRAME_T_PUSH_PROMISE:
            stream->state = AWS_H2_STREAM_STATE_RESERVED_REMOTE;
            return s_h2_stream_handle_push_promise(stream, decoder);

        default:
            return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
    }
}

static int s_h2_stream_state_reserved_local(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    switch (decoder->header.type) {
        case AWS_H2_FRAME_T_HEADERS:
            stream->state = AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
            return s_h2_stream_handle_headers(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        default:
            return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
    }
}

static int s_h2_stream_state_reserved_remote(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    switch (decoder->header.type) {
        case AWS_H2_FRAME_T_HEADERS:
            stream->state = AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL;
            return s_h2_stream_handle_headers(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        default:
            return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
    }
}

static int s_h2_stream_state_open(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    switch (decoder->header.type) {
        case AWS_H2_FRAME_T_DATA:
            return s_h2_stream_handle_data(stream, decoder);

        case AWS_H2_FRAME_T_HEADERS:
            return s_h2_stream_handle_headers(stream, decoder);

        case AWS_H2_FRAME_T_PRIORITY:
            return s_h2_stream_handle_priority(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        case AWS_H2_FRAME_T_PUSH_PROMISE:
            return s_h2_stream_handle_push_promise(stream, decoder);

        case AWS_H2_FRAME_T_WINDOW_UPDATE:
            return s_h2_stream_handle_window_update(stream, decoder);

        case AWS_H2_FRAME_T_CONTINUATION:
            return s_h2_stream_handle_continuation(stream, decoder);

        default:
            return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
    }
}

static int s_h2_stream_state_half_closed_local(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    switch (decoder->header.type) {
        /* #TODO Handle basically every other frame type */

        case AWS_H2_FRAME_T_WINDOW_UPDATE:
            return s_h2_stream_handle_window_update(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        default:
            return aws_raise_error(AWS_H2_ERR_STREAM_CLOSED);
    }
}

static int s_h2_stream_state_half_closed_remote(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    switch (decoder->header.type) {
        case AWS_H2_FRAME_T_WINDOW_UPDATE:
            return s_h2_stream_handle_window_update(stream, decoder);

        case AWS_H2_FRAME_T_PRIORITY:
            return s_h2_stream_handle_priority(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        default:
            return aws_raise_error(AWS_H2_ERR_STREAM_CLOSED);
    }
}

static int s_h2_stream_state_closed(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    (void)stream;

    switch (decoder->header.type) {
        case AWS_H2_FRAME_T_PRIORITY:
            return s_h2_stream_handle_priority(stream, decoder);

        case AWS_H2_FRAME_T_WINDOW_UPDATE:
        case AWS_H2_FRAME_T_RST_STREAM:
            return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);

        default:
            return aws_raise_error(AWS_H2_ERR_STREAM_CLOSED);
    }
}

/* State machine to handle each frame */
static int (*s_state_handlers[])(struct aws_h2_stream *, struct aws_h2_frame_decoder *) = {
    [AWS_H2_STREAM_STATE_IDLE] = s_h2_stream_state_idle,
    [AWS_H2_STREAM_STATE_RESERVED_LOCAL] = s_h2_stream_state_reserved_local,
    [AWS_H2_STREAM_STATE_RESERVED_REMOTE] = s_h2_stream_state_reserved_remote,
    [AWS_H2_STREAM_STATE_OPEN] = s_h2_stream_state_open,
    [AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL] = s_h2_stream_state_half_closed_local,
    [AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE] = s_h2_stream_state_half_closed_remote,
    [AWS_H2_STREAM_STATE_CLOSED] = s_h2_stream_state_closed,
};

/***********************************************************************************************************************
 * Public API
 **********************************************************************************************************************/

struct aws_h2_stream *aws_h2_stream_new(struct aws_allocator *allocator, uint32_t stream_id) {
    AWS_PRECONDITION(allocator);

    struct aws_h2_stream *stream = aws_mem_calloc(allocator, 0, sizeof(struct aws_h2_stream));
    if (!stream) {
        return NULL;
    }

    stream->allocator = allocator;
    stream->id = stream_id;
    stream->state = AWS_H2_STREAM_STATE_IDLE;

    return stream;
}
void aws_h2_stream_destroy(struct aws_h2_stream *stream) {
    AWS_PRECONDITION(stream);

    aws_mem_release(stream->allocator, stream);
}

int aws_h2_stream_handle_frame(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(stream);
    AWS_PRECONDITION(decoder);

    return s_state_handlers[stream->state](stream, decoder);
}
