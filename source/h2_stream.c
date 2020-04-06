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
#include <aws/http/private/strutil.h>
#include <aws/http/status_code.h>
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

static bool s_client_state_allows_frame_type[AWS_H2_STREAM_STATE_COUNT][AWS_H2_FRAME_TYPE_COUNT] = {
    /* State before anything is sent or received */
    [AWS_H2_STREAM_STATE_IDLE] = {0},
    /* Client streams are never in reserved (local) state */
    [AWS_H2_STREAM_STATE_RESERVED_LOCAL] = {0},
    /* Client received push-request via PUSH_PROMISE on another stream.
     * Waiting for push-response to start arriving on this server-initiated stream. */
    [AWS_H2_STREAM_STATE_RESERVED_REMOTE] =
        {
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
        },
    /* Client is sending request and has not received full response yet. */
    [AWS_H2_STREAM_STATE_OPEN] =
        {
            [AWS_H2_FRAME_T_DATA] = true,
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_PUSH_PROMISE] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Client has sent full request (END_STREAM), but has not received full response yet. */
    [AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL] =
        {
            [AWS_H2_FRAME_T_DATA] = true,
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_PUSH_PROMISE] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Client has received full response (END_STREAM), but is still sending request (uncommon). */
    [AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE] =
        {
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Full request sent (END_STREAM) and full response received (END_STREAM).
     * OR sent RST_STREAM. OR received RST_STREAM. */
    [AWS_H2_STREAM_STATE_CLOSED] = {0},
};

static bool s_server_state_allows_frame_type[AWS_H2_STREAM_STATE_COUNT][AWS_H2_FRAME_TYPE_COUNT] = {
    /* State before anything is sent or received, waiting for request headers to arrives and start things off */
    [AWS_H2_STREAM_STATE_IDLE] =
        {
            [AWS_H2_FRAME_T_HEADERS] = true,
        },
    /* Server sent push-request via PUSH_PROMISE on a client-initiated stream,
     * but hasn't started sending the push-response on this server-initiated stream yet. */
    [AWS_H2_STREAM_STATE_RESERVED_LOCAL] =
        {
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Server streams are never in reserved (remote) state */
    [AWS_H2_STREAM_STATE_RESERVED_REMOTE] = {0},
    /* Server is receiving request, and has sent full response yet. */
    [AWS_H2_STREAM_STATE_OPEN] =
        {
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_DATA] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Server has sent full response (END_STREAM), but has not received full response yet (uncommon). */
    [AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL] =
        {
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_DATA] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Server has received full request (END_STREAM), and is still sending response. */
    [AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE] =
        {
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Full request received (END_STREAM) and full response sent (END_STREAM).
     * OR sent RST_STREAM. OR received RST_STREAM. */
    [AWS_H2_STREAM_STATE_CLOSED] = {0},
};

static int s_check_state_allows_frame_type(const struct aws_h2_stream *stream, enum aws_h2_frame_type frame_type) {
    AWS_PRECONDITION(frame_type < AWS_H2_FRAME_T_UNKNOWN); /* Decoder won't invoke callbacks for unknown frame types */
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    const enum aws_h2_stream_state state = stream->thread_data.state;

    bool allowed;
    if (stream->base.server_data) {
        allowed = s_server_state_allows_frame_type[state][frame_type];
    } else {
        allowed = s_client_state_allows_frame_type[state][frame_type];
    }

    if (allowed) {
        return AWS_OP_SUCCESS;
    }

    /* Determine specifice error code */
    int aws_error_code = AWS_ERROR_HTTP_PROTOCOL_ERROR;

    /* If peer knows the state is closed, then it's a STREAM_CLOSED error */
    if (state == AWS_H2_STREAM_STATE_CLOSED || state == AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        aws_error_code = AWS_ERROR_HTTP_STREAM_CLOSED;
    }

    AWS_H2_STREAM_LOGF(
        ERROR,
        stream,
        "Malformed message, cannot receive %s frame in %s state",
        aws_h2_frame_type_to_str(frame_type),
        aws_error_name(aws_error_code));

    return aws_raise_error(aws_error_code);
}

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
    stream->base.client_data = &stream->base.client_or_server_data.client;
    stream->base.client_data->response_status = AWS_HTTP_STATUS_CODE_UNKNOWN;

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

/* Send RST_STREAM frame and close stream */
static int s_send_rst_and_close_stream(struct aws_h2_stream *stream, int aws_error_code) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);
    AWS_PRECONDITION(stream->thread_data.state != AWS_H2_STREAM_STATE_CLOSED);
    AWS_PRECONDITION(aws_error_code != 0);

    struct aws_h2_connection *connection = s_get_h2_connection(stream);

    enum aws_h2_error_code h2_error_code = aws_error_to_h2_error_code(aws_error_code);

    stream->thread_data.state = AWS_H2_STREAM_STATE_CLOSED;
    AWS_H2_STREAM_LOGF(
        DEBUG,
        stream,
        "Sending RST_STREAM with error code %s (0x%x). State -> CLOSED",
        aws_h2_error_code_to_str(h2_error_code),
        h2_error_code);

    /* Send RST_STREAM */
    struct aws_h2_frame *rst_stream_frame =
        aws_h2_frame_new_rst_stream(stream->base.alloc, stream->base.id, h2_error_code);
    if (!rst_stream_frame) {
        AWS_H2_STREAM_LOGF(ERROR, stream, "Error creating RST_STREAM frame, %s", aws_error_name(aws_last_error()));
        return AWS_OP_ERR;
    }
    aws_h2_connection_enqueue_outgoing_frame(connection, rst_stream_frame); /* connection takes ownership of frame */

    /* Tell connection that stream is now closed */
    if (aws_h2_connection_on_stream_closed(
            connection, stream, AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_SENT, aws_error_code)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
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
        AWS_H2_STREAM_LOG(TRACE, stream, "Sending HEADERS. State -> OPEN");

        *out_has_outgoing_data = has_body_stream;
    } else {
        /* If stream has no body, then HEADERS frame marks the end of outgoing data */
        stream->thread_data.state = AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL;
        AWS_H2_STREAM_LOG(TRACE, stream, "Sending HEADERS with END_STREAM. State -> HALF_CLOSED_LOCAL");

        *out_has_outgoing_data = has_body_stream;
    }

    aws_h2_connection_enqueue_outgoing_frame(connection, headers_frame);
    return AWS_OP_SUCCESS;

error:
    return AWS_OP_ERR;
}

int aws_h2_stream_on_decoder_headers_begin(struct aws_h2_stream *stream) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    if (s_check_state_allows_frame_type(stream, AWS_H2_FRAME_T_HEADERS)) {
        return s_send_rst_and_close_stream(stream, aws_last_error());
    }

    return AWS_OP_SUCCESS;
}

int aws_h2_stream_on_decoder_headers_i(
    struct aws_h2_stream *stream,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type) {

    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    /* Not calling s_check_state_allows_frame_type() here because we already checked
     * at start of HEADERS frame in aws_h2_stream_on_decoder_headers_begin() */

    bool is_server = stream->base.server_data;

    /* RFC-7540 8.1 - Message consists of:
     * - 0+ Informational 1xx headers (response-only, decoder validates that this only occurs in responses)
     * - 1 main headers with normal request or response.
     * - 0 or 1 trailing headers with no pseudo-headers */
    switch (block_type) {
        case AWS_HTTP_HEADER_BLOCK_INFORMATIONAL:
            if (stream->thread_data.received_main_headers) {
                AWS_H2_STREAM_LOG(
                    ERROR, stream, "Malformed message, received informational (1xx) response after main response");
                goto malformed;
            }
            break;
        case AWS_HTTP_HEADER_BLOCK_MAIN:
            if (stream->thread_data.received_main_headers) {
                AWS_H2_STREAM_LOG(ERROR, stream, "Malformed message, received second set of headers");
                goto malformed;
            }
            break;
        case AWS_HTTP_HEADER_BLOCK_TRAILING:
            if (!stream->thread_data.received_main_headers) {
                /* A HEADERS frame without any pseudo-headers looks like trailing headers to the decoder */
                AWS_H2_STREAM_LOG(ERROR, stream, "Malformed headers lack required pseudo-header fields.");
                goto malformed;
            }
            break;
        default:
            AWS_ASSERT(0);
    }

    if (is_server) {
        return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);

    } else {
        /* Client */
        if (name_enum == AWS_HTTP_HEADER_STATUS) {
            uint64_t status_code;
            int err = aws_strutil_read_unsigned_num(header->value, &status_code);
            AWS_ASSERT(!err && "Invalid :status value. Decoder should have already validated this");
            (void)err;

            stream->base.client_data->response_status = (int)status_code;
        }
    }

    if (stream->base.on_incoming_headers) {
        if (stream->base.on_incoming_headers(&stream->base, block_type, header, 1, stream->base.user_data)) {
            AWS_H2_STREAM_LOGF(
                ERROR, stream, "Incoming header callback raised error, %s", aws_error_name(aws_last_error()));
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;

malformed:
    return s_send_rst_and_close_stream(stream, AWS_ERROR_HTTP_PROTOCOL_ERROR);
}

int aws_h2_stream_on_decoder_headers_end(
    struct aws_h2_stream *stream,
    bool malformed,
    enum aws_http_header_block block_type) {

    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    /* Not calling s_check_state_allows_frame_type() here because we already checked
     * at start of HEADERS frame in aws_h2_stream_on_decoder_headers_begin() */

    if (malformed) {
        AWS_H2_STREAM_LOG(ERROR, stream, "Headers are malformed");
        return s_send_rst_and_close_stream(stream, AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    switch (block_type) {
        case AWS_HTTP_HEADER_BLOCK_INFORMATIONAL:
            AWS_H2_STREAM_LOG(TRACE, stream, "Informational 1xx header-block done.");
            break;
        case AWS_HTTP_HEADER_BLOCK_MAIN:
            AWS_H2_STREAM_LOG(TRACE, stream, "Main header-block done.");
            stream->thread_data.received_main_headers = true;
            break;
        case AWS_HTTP_HEADER_BLOCK_TRAILING:
            AWS_H2_STREAM_LOG(TRACE, stream, "Trailing 1xx header-block done.");
            break;
        default:
            AWS_ASSERT(0);
    }

    if (stream->base.on_incoming_header_block_done) {
        if (stream->base.on_incoming_header_block_done(&stream->base, block_type, stream->base.user_data)) {
            AWS_H2_STREAM_LOGF(
                ERROR,
                stream,
                "Incoming-header-block-done callback raised error, %s",
                aws_error_name(aws_last_error()));
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_h2_stream_on_decoder_data(struct aws_h2_stream *stream, struct aws_byte_cursor data) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    if (s_check_state_allows_frame_type(stream, AWS_H2_FRAME_T_DATA)) {
        return s_send_rst_and_close_stream(stream, aws_last_error());
    }

    if (!stream->thread_data.received_main_headers) {
        /* #TODO Not 100% sure whether this is Stream Error or Connection Error. */
        AWS_H2_STREAM_LOG(ERROR, stream, "Malformed message, received DATA before main HEADERS");
        return s_send_rst_and_close_stream(stream, AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    /* #TODO Update connection's flow-control window */

    if (stream->base.on_incoming_body) {
        if (stream->base.on_incoming_body(&stream->base, &data, stream->base.user_data)) {
            AWS_H2_STREAM_LOGF(
                ERROR, stream, "Incoming body callback raised error, %s", aws_error_name(aws_last_error()));
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_h2_stream_on_decoder_end_stream(struct aws_h2_stream *stream) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    /* Not calling s_check_state_allows_frame_type() here because END_STREAM isn't
     * an actual frame type. It's a flag on DATA or HEADERS frames, and we
     * already checked the legality of those frames in their respective callbacks. */

    if (stream->thread_data.state == AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL) {
        /* Both sides have sent END_STREAM */
        stream->thread_data.state = AWS_H2_STREAM_STATE_CLOSED;
        AWS_H2_STREAM_LOG(TRACE, stream, "Received END_STREAM. State -> CLOSED");

        /* Tell connection that stream is now closed */
        if (aws_h2_connection_on_stream_closed(
                s_get_h2_connection(stream),
                stream,
                AWS_H2_STREAM_CLOSED_WHEN_BOTH_SIDES_END_STREAM,
                AWS_ERROR_SUCCESS)) {
            return AWS_OP_ERR;
        }

    } else {
        /* Else can't close until our side sends END_STREAM */
        stream->thread_data.state = AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
        AWS_H2_STREAM_LOG(TRACE, stream, "Received END_STREAM. State -> HALF_CLOSED_REMOTE");
    }

    return AWS_OP_SUCCESS;
}
