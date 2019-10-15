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

#include <inttypes.h>

#define STREAM_LOGF(level, stream, text, ...)                                                                          \
    AWS_LOGF_##level(                                                                                                  \
        AWS_LS_HTTP_STREAM,                                                                                            \
        "id=%" PRIu32 "(%p) state=%s: " text,                                                                          \
        (stream)->id,                                                                                                  \
        (void *)(stream),                                                                                              \
        aws_h2_stream_state_to_str((stream)->thread_data.state),                                                       \
        __VA_ARGS__)
#define STREAM_LOG(level, stream, text) STREAM_LOGF(level, stream, "%s", text)

static void s_stream_destroy(struct aws_http_stream *stream_base);

struct aws_http_stream_vtable s_h2_stream_vtable = {
    .destroy = s_stream_destroy,
    .update_window = NULL,
};

/* Shortcut for logging invalid stream and raising an error */
static int s_h2_stream_raise_invalid_frame(struct aws_h2_stream *stream, enum aws_h2_frame_type type, int error_code) {
    STREAM_LOGF(
        ERROR,
        stream,
        "Not allowed to receive frame of type %s when in %s state, raising %s",
        aws_h2_frame_type_to_str(type),
        aws_h2_stream_state_to_str(stream->thread_data.state),
        aws_error_name(error_code));
    return aws_raise_error(error_code);
}

static void s_h2_stream_set_state(struct aws_h2_stream *stream, enum aws_h2_stream_state new_state) {
    STREAM_LOGF(
        DEBUG,
        stream,
        "Stream moving from state %s to %s",
        aws_h2_stream_state_to_str(stream->thread_data.state),
        aws_h2_stream_state_to_str(new_state));

    stream->thread_data.state = new_state;
}

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
            return "*** UNKNOWN ***";
    }
}

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
    stream->base.on_incoming_body(&stream->base, &frame.data, stream->base.user_data);

    if (!stream->base.manual_window_management) {
        /* Increment read window */
    }

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_headers(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_HEADERS);

    struct aws_h2_frame_headers frame;
    if (aws_h2_frame_headers_decode(&frame, decoder)) {
        STREAM_LOG(ERROR, stream, "Failed to decode HEADERS frame");
        return AWS_OP_ERR;
    }

    stream->base.on_incoming_headers(
        &stream->base,
        AWS_HTTP_HEADER_BLOCK_MAIN,
        frame.header_block.header_fields.data,
        frame.header_block.header_fields.length,
        stream->base.user_data);

    if (frame.end_headers) {
        STREAM_LOG(DEBUG, stream, "HEADERS frame is self-containing, calling header_block_done");
        stream->base.on_incoming_header_block_done(&stream->base, false, stream->base.user_data);
    } else {
        STREAM_LOG(DEBUG, stream, "HEADERS frame does not have END_HEADERS set, expecting following CONTINUATION");
        stream->thread_data.expects_continuation = true;
    }

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_priority(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_PRIORITY);

    struct aws_h2_frame_priority frame;
    if (aws_h2_frame_priority_decode(&frame, decoder)) {
        STREAM_LOG(ERROR, stream, "Failed to decode PRIORITY frame");
        return AWS_OP_ERR;
    }

    /* Happy Birthday to the GROUND */
    (void)stream;

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_rst_stream(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_RST_STREAM);

    struct aws_h2_frame_rst_stream frame;
    if (aws_h2_frame_rst_stream_decode(&frame, decoder)) {
        STREAM_LOG(ERROR, stream, "Failed to decode RST_STREAM frame");
        return AWS_OP_ERR;
    }

    s_h2_stream_set_state(stream, AWS_H2_STREAM_STATE_CLOSED);

    /* Call user callback stating frame was reset */
    stream->base.on_complete(&stream->base, frame.error_code, stream->base.user_data);

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_push_promise(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_PUSH_PROMISE);

    struct aws_h2_frame_push_promise frame;
    if (aws_h2_frame_push_promise_decode(&frame, decoder)) {
        STREAM_LOG(ERROR, stream, "Failed to decode PUSH_PROMISE frame");
        return AWS_OP_ERR;
    }

    if (!frame.end_headers) {
        STREAM_LOG(TRACE, stream, "PUSH_PROMISE END_HEADERS not set, expecting CONTINUATION frame next");
        stream->thread_data.expects_continuation = true;
    }

    /* #TODO Handle whatever this means */

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_window_update(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_WINDOW_UPDATE);

    struct aws_h2_frame_window_update frame;
    if (aws_h2_frame_window_update_decode(&frame, decoder)) {
        STREAM_LOG(ERROR, stream, "Failed to decode WINDOW_UPDATE frame");
        return AWS_OP_ERR;
    }

    /* Increment the window size, I suppose */
    stream->thread_data.window_size += frame.window_size_increment;

    return AWS_OP_SUCCESS;
}
static int s_h2_stream_handle_continuation(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder->header.type == AWS_H2_FRAME_T_CONTINUATION);

    if (!stream->thread_data.expects_continuation) {
        STREAM_LOG(
            ERROR,
            stream,
            "Received CONTINUATION frame following a frame with END_HEADERS set, raising PROTOCOL_ERROR");
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    struct aws_h2_frame_continuation frame;
    if (aws_h2_frame_continuation_decode(&frame, decoder)) {
        STREAM_LOG(ERROR, stream, "Failed to decode CONTINUATION frame");
        return AWS_OP_ERR;
    }

    if (frame.end_headers) {
        STREAM_LOG(TRACE, stream, "CONTINUATION frames complete, calling header_block_done");
        stream->thread_data.expects_continuation = false;
        stream->base.on_incoming_header_block_done(&stream->base, false, stream->base.user_data);
    } else {
        STREAM_LOG(TRACE, stream, "CONTINUATION END_HEADERS not set, expecting CONTINUATION frame next");
        stream->thread_data.expects_continuation = true;
    }

    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * State Machine
 **********************************************************************************************************************/

static int s_h2_stream_state_idle(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    const enum aws_h2_frame_type frame_type = decoder->header.type;
    switch (frame_type) {
        case AWS_H2_FRAME_T_HEADERS:
            s_h2_stream_set_state(stream, AWS_H2_STREAM_STATE_OPEN);
            return s_h2_stream_handle_headers(stream, decoder);

        case AWS_H2_FRAME_T_PUSH_PROMISE:
            s_h2_stream_set_state(stream, AWS_H2_STREAM_STATE_RESERVED_REMOTE);
            return s_h2_stream_handle_push_promise(stream, decoder);

        default:
            return s_h2_stream_raise_invalid_frame(stream, frame_type, AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }
}

static int s_h2_stream_state_reserved_local(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    const enum aws_h2_frame_type frame_type = decoder->header.type;
    switch (frame_type) {
        case AWS_H2_FRAME_T_HEADERS:
            s_h2_stream_set_state(stream, AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE);
            return s_h2_stream_handle_headers(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        default:
            return s_h2_stream_raise_invalid_frame(stream, frame_type, AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }
}

static int s_h2_stream_state_reserved_remote(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    const enum aws_h2_frame_type frame_type = decoder->header.type;
    switch (frame_type) {
        case AWS_H2_FRAME_T_HEADERS:
            s_h2_stream_set_state(stream, AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL);
            return s_h2_stream_handle_headers(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        default:
            return s_h2_stream_raise_invalid_frame(stream, frame_type, AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }
}

static int s_h2_stream_state_open(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    const enum aws_h2_frame_type frame_type = decoder->header.type;
    switch (frame_type) {
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
            return s_h2_stream_raise_invalid_frame(stream, frame_type, AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }
}

static int s_h2_stream_state_half_closed_local(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    const enum aws_h2_frame_type frame_type = decoder->header.type;
    switch (frame_type) {
            /* #TODO Handle basically every other frame type */

        case AWS_H2_FRAME_T_WINDOW_UPDATE:
            return s_h2_stream_handle_window_update(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        default:
            return s_h2_stream_raise_invalid_frame(stream, frame_type, AWS_ERROR_HTTP_STREAM_CLOSED);
    }
}

static int s_h2_stream_state_half_closed_remote(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    const enum aws_h2_frame_type frame_type = decoder->header.type;
    switch (frame_type) {
        case AWS_H2_FRAME_T_WINDOW_UPDATE:
            return s_h2_stream_handle_window_update(stream, decoder);

        case AWS_H2_FRAME_T_PRIORITY:
            return s_h2_stream_handle_priority(stream, decoder);

        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_handle_rst_stream(stream, decoder);

        default:
            return s_h2_stream_raise_invalid_frame(stream, frame_type, AWS_ERROR_HTTP_STREAM_CLOSED);
    }
}

static int s_h2_stream_state_closed(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {

    (void)stream;

    const enum aws_h2_frame_type frame_type = decoder->header.type;
    switch (frame_type) {
        case AWS_H2_FRAME_T_PRIORITY:
            return s_h2_stream_handle_priority(stream, decoder);

        case AWS_H2_FRAME_T_WINDOW_UPDATE:
        case AWS_H2_FRAME_T_RST_STREAM:
            return s_h2_stream_raise_invalid_frame(stream, frame_type, AWS_ERROR_HTTP_PROTOCOL_ERROR);

        default:
            return s_h2_stream_raise_invalid_frame(stream, frame_type, AWS_ERROR_HTTP_STREAM_CLOSED);
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

struct aws_h2_stream *aws_h2_stream_new(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {
    AWS_PRECONDITION(client_connection);
    AWS_PRECONDITION(options);

    struct aws_h2_connection *connection = AWS_CONTAINER_OF(client_connection, struct aws_h2_connection, base);

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

    /* Stream refcount starts at 2. 1 for user and 1 for connection to release it's done with the stream */
    aws_atomic_init_int(&stream->base.refcount, 2);

    /* Init H2 specific stuff */
    *((uint32_t *)&stream->id) = aws_h2_connection_get_next_stream_id(connection);
    s_h2_stream_set_state(stream, AWS_H2_STREAM_STATE_IDLE);

    STREAM_LOG(DEBUG, stream, "Created stream");

    return stream;
}
static void s_stream_destroy(struct aws_http_stream *stream_base) {
    AWS_PRECONDITION(stream_base);
    struct aws_h2_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h2_stream, base);

    STREAM_LOG(DEBUG, stream, "Destroying stream");

    aws_mem_release(stream->base.alloc, stream);
}

int aws_h2_stream_handle_frame(struct aws_h2_stream *stream, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(stream);
    AWS_PRECONDITION(decoder);

    STREAM_LOGF(DEBUG, stream, "Received frame of type %s", aws_h2_frame_type_to_str(decoder->header.type));

    return s_state_handlers[stream->thread_data.state](stream, decoder);
}
