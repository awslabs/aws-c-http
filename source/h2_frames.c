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
#include <aws/http/private/hpack.h>

#include <aws/compression/huffman.h>

#include <aws/common/logging.h>

#include <aws/io/stream.h>

#include <inttypes.h>

#define ENCODER_LOGF(level, encoder, text, ...)                                                                        \
    AWS_LOGF_##level(AWS_LS_HTTP_ENCODER, "id=%p " text, (encoder)->logging_id, __VA_ARGS__)

#define ENCODER_LOG(level, encoder, text) ENCODER_LOGF(level, encoder, "%s", text)

const struct aws_byte_cursor aws_h2_connection_preface_client_string =
    AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

/* Initial values and bounds are from RFC-7540 6.5.2 */
const uint32_t aws_h2_settings_initial[AWS_H2_SETTINGS_END_RANGE] = {
    [AWS_H2_SETTINGS_HEADER_TABLE_SIZE] = 4096,
    [AWS_H2_SETTINGS_ENABLE_PUSH] = 1,
    [AWS_H2_SETTINGS_MAX_CONCURRENT_STREAMS] = UINT32_MAX, /* "Initially there is no limit to this value" */
    [AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE] = 65535,
    [AWS_H2_SETTINGS_MAX_FRAME_SIZE] = 16384,
    [AWS_H2_SETTINGS_MAX_HEADER_LIST_SIZE] = UINT32_MAX, /* "The initial value of this setting is unlimited" */
};

const uint32_t aws_h2_settings_bounds[AWS_H2_SETTINGS_END_RANGE][2] = {
    [AWS_H2_SETTINGS_HEADER_TABLE_SIZE][0] = 0,
    [AWS_H2_SETTINGS_HEADER_TABLE_SIZE][1] = UINT32_MAX,

    [AWS_H2_SETTINGS_ENABLE_PUSH][0] = 0,
    [AWS_H2_SETTINGS_ENABLE_PUSH][1] = 1,

    [AWS_H2_SETTINGS_MAX_CONCURRENT_STREAMS][0] = 0,
    [AWS_H2_SETTINGS_MAX_CONCURRENT_STREAMS][1] = UINT32_MAX,

    [AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE][0] = 0,
    [AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE][1] = AWS_H2_WINDOW_UPDATE_MAX,

    [AWS_H2_SETTINGS_MAX_FRAME_SIZE][0] = 16384,
    [AWS_H2_SETTINGS_MAX_FRAME_SIZE][1] = AWS_H2_PAYLOAD_MAX,

    [AWS_H2_SETTINGS_MAX_HEADER_LIST_SIZE][0] = 0,
    [AWS_H2_SETTINGS_MAX_HEADER_LIST_SIZE][1] = UINT32_MAX,
};

/* Put constraints on frames that could get very large given crazy inputs.
 * This isn't dictated by the spec, it's here to avoid edge cases where
 * we'd never have a big enough output buffer to encode the frame. */
static const size_t s_settings_and_goaway_payload_limit = 8192;

/* Stream ids & dependencies should only write the bottom 31 bits */
static const uint32_t s_31_bit_mask = UINT32_MAX >> 1;
static const uint32_t s_u32_top_bit_mask = UINT32_MAX << 31;

/* All frames begin with a fixed 9-octet prefix */
static const size_t s_frame_prefix_length = 9;

/* Bytes to initially reserve for encoding of an entire header block. Buffer will grow if necessary. */
static const size_t s_encoded_header_block_reserve = 128; /* Value pulled from thin air */

#define DEFINE_FRAME_VTABLE(NAME)                                                                                      \
    static aws_h2_frame_destroy_fn s_frame_##NAME##_destroy;                                                           \
    static aws_h2_frame_encode_fn s_frame_##NAME##_encode;                                                             \
    static const struct aws_h2_frame_vtable s_frame_##NAME##_vtable = {                                                \
        .destroy = s_frame_##NAME##_destroy,                                                                           \
        .encode = s_frame_##NAME##_encode,                                                                             \
    }

const char *aws_h2_frame_type_to_str(enum aws_h2_frame_type type) {
    switch (type) {
        case AWS_H2_FRAME_T_DATA:
            return "DATA";
        case AWS_H2_FRAME_T_HEADERS:
            return "HEADERS";
        case AWS_H2_FRAME_T_PRIORITY:
            return "PRIORITY";
        case AWS_H2_FRAME_T_RST_STREAM:
            return "RST_STREAM";
        case AWS_H2_FRAME_T_SETTINGS:
            return "SETTINGS";
        case AWS_H2_FRAME_T_PUSH_PROMISE:
            return "PUSH_PROMISE";
        case AWS_H2_FRAME_T_PING:
            return "PING";
        case AWS_H2_FRAME_T_GOAWAY:
            return "GOAWAY";
        case AWS_H2_FRAME_T_WINDOW_UPDATE:
            return "WINDOW_UPDATE";
        case AWS_H2_FRAME_T_CONTINUATION:
            return "CONTINUATION";
        default:
            return "**UNKNOWN**";
    }
}

int aws_h2_validate_stream_id(uint32_t stream_id) {
    if (stream_id == 0 || stream_id > AWS_H2_STREAM_ID_MAX) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    return AWS_OP_SUCCESS;
}

/**
 * Determine max frame payload length that will:
 * 1) fit in output's available space
 * 2) obey encoders current MAX_FRAME_SIZE
 *
 * Assumes no part of the frame has been written yet to output.
 * The total length of the frame would be: returned-payload-len + s_frame_prefix_length
 *
 * Raises error if there is not enough space available for even a frame prefix.
 */
static int s_get_max_contiguous_payload_length(
    const struct aws_h2_frame_encoder *encoder,
    const struct aws_byte_buf *output,
    size_t *max_payload_length) {

    const size_t space_available = output->capacity - output->len;

    size_t max_payload_given_space_available;
    if (aws_sub_size_checked(space_available, s_frame_prefix_length, &max_payload_given_space_available)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    /* #TODO actually check against encoder's current MAX_FRAME_SIZE */
    (void)encoder;
    const size_t max_payload_given_settings = AWS_H2_PAYLOAD_MAX;

    *max_payload_length = aws_min_size(max_payload_given_space_available, max_payload_given_settings);
    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * Priority
 **********************************************************************************************************************/
static size_t s_frame_priority_settings_size = 5;

static int s_frame_priority_settings_encode(
    const struct aws_h2_frame_priority_settings *priority,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(priority);
    AWS_PRECONDITION(output);

    if (priority->stream_dependency & s_u32_top_bit_mask) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Write the top 4 bytes */
    uint32_t top_bytes = priority->stream_dependency | ((uint32_t)priority->stream_dependency_exclusive << 31);
    if (!aws_byte_buf_write_be32(output, top_bytes)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    /* Write the priority weight */
    if (!aws_byte_buf_write_u8(output, priority->weight)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * Common Frame Prefix
 **********************************************************************************************************************/
static void s_init_frame_base(
    struct aws_h2_frame *frame_base,
    struct aws_allocator *alloc,
    enum aws_h2_frame_type type,
    const struct aws_h2_frame_vtable *vtable,
    uint32_t stream_id) {

    frame_base->vtable = vtable;
    frame_base->alloc = alloc;
    frame_base->type = type;
    frame_base->stream_id = stream_id;
}

static int s_frame_prefix_encode(
    struct aws_h2_frame_encoder *encoder,
    enum aws_h2_frame_type type,
    uint32_t stream_id,
    size_t length,
    uint8_t flags,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);
    AWS_PRECONDITION(!(stream_id & s_u32_top_bit_mask), "Invalid stream ID");

    ENCODER_LOGF(
        TRACE,
        encoder,
        "Encoding frame: type=%s stream_id=%" PRIu32 " payload_length=%zu flags=0x%02X",
        aws_h2_frame_type_to_str(type),
        stream_id,
        length,
        flags);

    /* Length must fit in 24 bits */
    if (length > AWS_H2_PAYLOAD_MAX) {
        ENCODER_LOGF(ERROR, encoder, "Payload size %zu exceeds max for HTTP/2", length);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Write length */
    if (!aws_byte_buf_write_be24(output, (uint32_t)length)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write type */
    if (!aws_byte_buf_write_u8(output, type)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write flags */
    if (!aws_byte_buf_write_u8(output, flags)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write stream id (with reserved first bit) */
    if (!aws_byte_buf_write_be32(output, stream_id & s_31_bit_mask)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * Encoder
 **********************************************************************************************************************/
int aws_h2_frame_encoder_init(struct aws_h2_frame_encoder *encoder, struct aws_allocator *allocator, void *logging_id) {

    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(allocator);

    AWS_ZERO_STRUCT(*encoder);
    encoder->allocator = allocator;
    encoder->logging_id = logging_id;

    encoder->hpack = aws_hpack_context_new(allocator, AWS_LS_HTTP_ENCODER, logging_id);
    if (!encoder->hpack) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_encoder_clean_up(struct aws_h2_frame_encoder *encoder) {
    AWS_PRECONDITION(encoder);

    aws_hpack_context_destroy(encoder->hpack);
}

/***********************************************************************************************************************
 * DATA
 **********************************************************************************************************************/
int aws_h2_encode_data_frame(
    struct aws_h2_frame_encoder *encoder,
    uint32_t stream_id,
    struct aws_input_stream *body_stream,
    bool body_ends_stream,
    uint8_t pad_length,
    struct aws_byte_buf *output,
    bool *body_complete) {

    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(body_stream);
    AWS_PRECONDITION(output);
    AWS_PRECONDITION(body_complete);

    if (aws_h2_validate_stream_id(stream_id)) {
        return AWS_OP_ERR;
    }

    *body_complete = false;
    uint8_t flags = 0;

    /*
     * Payload-length is the first thing encoded in a frame, but we don't know how
     * much data we'll get from the body-stream until we actually read it.
     * Therefore, we determine the exact location that the body data should go,
     * then stream the body directly into that part of the output buffer.
     * Then we will go and write the other parts of the frame in around it.
     */

    size_t bytes_preceding_body = s_frame_prefix_length;
    size_t payload_overhead = 0; /* Amount of "payload" that will not contain body (padding) */
    if (pad_length > 0) {
        flags |= AWS_H2_FRAME_F_PADDED;

        /* Padding len is 1st byte of payload (padding itself goes at end of payload) */
        bytes_preceding_body += 1;
        payload_overhead = 1 + pad_length;
    }

    /* Max amount of payload we can do right now */
    size_t max_payload;
    if (s_get_max_contiguous_payload_length(encoder, output, &max_payload)) {
        goto handle_waiting_for_more_space;
    }

    /* Max amount of body we can fit in the payload*/
    size_t max_body;
    if (aws_sub_size_checked(max_payload, payload_overhead, &max_body) || max_body == 0) {
        goto handle_waiting_for_more_space;
    }

    /* Use a sub-buffer to limit where body can go */
    struct aws_byte_buf body_sub_buf =
        aws_byte_buf_from_empty_array(output->buffer + output->len + bytes_preceding_body, max_body);

    /* Read body into sub-buffer */
    if (aws_input_stream_read(body_stream, &body_sub_buf)) {
        goto error;
    }

    /* Check if we've reached the end of the body */
    struct aws_stream_status body_status;
    if (aws_input_stream_get_status(body_stream, &body_status)) {
        goto error;
    }

    if (body_status.is_end_of_stream) {
        *body_complete = true;
        if (body_ends_stream) {
            flags |= AWS_H2_FRAME_F_END_STREAM;
        }
    } else {
        if (body_sub_buf.len == 0) {
            /* This frame would have no useful information, don't even bother sending it */
            goto handle_nothing_to_send_right_now;
        }
    }

    /*
     * Write in the other parts of the frame.
     */

    /* Write the frame prefix */
    const size_t payload_len = body_sub_buf.len + payload_overhead;
    if (s_frame_prefix_encode(encoder, AWS_H2_FRAME_T_DATA, stream_id, payload_len, flags, output)) {
        goto error;
    }

    /* Write pad length */
    if (flags & AWS_H2_FRAME_F_PADDED) {
        if (!aws_byte_buf_write_u8(output, pad_length)) {
            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto error;
        }
    }

    /* Increment output->len to jump over the body that we already wrote in */
    AWS_ASSERT(output->buffer + output->len == body_sub_buf.buffer && "Streamed DATA to wrong position");
    output->len += body_sub_buf.len;

    /* Write padding */
    if (flags & AWS_H2_FRAME_F_PADDED) {
        if (!aws_byte_buf_write_u8_n(output, 0, pad_length)) {
            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

handle_waiting_for_more_space:
    ENCODER_LOGF(TRACE, encoder, "Insufficient space to encode DATA for stream %" PRIu32 " right now", stream_id);
    return AWS_OP_SUCCESS;

handle_nothing_to_send_right_now:
    ENCODER_LOGF(INFO, encoder, "Stream %" PRIu32 " produced 0 bytes of body data", stream_id);
    return AWS_OP_SUCCESS;

error:
    return AWS_OP_ERR;
}

/***********************************************************************************************************************
 * HEADERS / PUSH_PROMISE
 **********************************************************************************************************************/
DEFINE_FRAME_VTABLE(headers);

static struct aws_h2_frame *s_frame_new_headers_or_push_promise(
    struct aws_allocator *allocator,
    enum aws_h2_frame_type frame_type,
    uint32_t stream_id,
    const struct aws_http_headers *headers,
    uint8_t pad_length,
    bool end_stream,
    const struct aws_h2_frame_priority_settings *optional_priority,
    uint32_t promised_stream_id) {

    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(frame_type == AWS_H2_FRAME_T_HEADERS || frame_type == AWS_H2_FRAME_T_PUSH_PROMISE);
    AWS_PRECONDITION(headers);

    /* Validate args */

    if (aws_h2_validate_stream_id(stream_id)) {
        return NULL;
    }

    if (frame_type == AWS_H2_FRAME_T_PUSH_PROMISE) {
        if (aws_h2_validate_stream_id(promised_stream_id)) {
            return NULL;
        }
    }

    if (optional_priority && aws_h2_validate_stream_id(optional_priority->stream_dependency)) {
        return NULL;
    }

    /* Create */

    struct aws_h2_frame_headers *frame = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_frame_headers));
    if (!frame) {
        return NULL;
    }

    if (aws_byte_buf_init(&frame->whole_encoded_header_block, allocator, s_encoded_header_block_reserve)) {
        goto error;
    }

    if (frame_type == AWS_H2_FRAME_T_HEADERS) {
        frame->end_stream = end_stream;
        if (optional_priority) {
            frame->has_priority = true;
            frame->priority = *optional_priority;
        }
    } else {
        frame->promised_stream_id = promised_stream_id;
    }

    s_init_frame_base(&frame->base, allocator, frame_type, &s_frame_headers_vtable, stream_id);

    aws_http_headers_acquire((struct aws_http_headers *)headers);
    frame->headers = headers;
    frame->pad_length = pad_length;

    return &frame->base;

error:
    s_frame_headers_destroy(&frame->base);
    return NULL;
}

struct aws_h2_frame *aws_h2_frame_new_headers(
    struct aws_allocator *allocator,
    uint32_t stream_id,
    const struct aws_http_headers *headers,
    bool end_stream,
    uint8_t pad_length,
    const struct aws_h2_frame_priority_settings *optional_priority) {

    return s_frame_new_headers_or_push_promise(
        allocator,
        AWS_H2_FRAME_T_HEADERS,
        stream_id,
        headers,
        pad_length,
        end_stream,
        optional_priority,
        0 /* HEADERS doesn't have promised_stream_id */);
}

struct aws_h2_frame *aws_h2_frame_new_push_promise(
    struct aws_allocator *allocator,
    uint32_t stream_id,
    uint32_t promised_stream_id,
    const struct aws_http_headers *headers,
    uint8_t pad_length) {

    return s_frame_new_headers_or_push_promise(
        allocator,
        AWS_H2_FRAME_T_PUSH_PROMISE,
        stream_id,
        headers,
        pad_length,
        false /* PUSH_PROMISE doesn't have end_stream flag */,
        NULL /* PUSH_PROMISE doesn't have priority_settings */,
        promised_stream_id);
}

static void s_frame_headers_destroy(struct aws_h2_frame *frame_base) {
    struct aws_h2_frame_headers *frame = AWS_CONTAINER_OF(frame_base, struct aws_h2_frame_headers, base);
    aws_http_headers_release((struct aws_http_headers *)frame->headers);
    aws_byte_buf_clean_up(&frame->whole_encoded_header_block);
    aws_mem_release(frame->base.alloc, frame);
}

/* Encode the next frame for this header-block (or encode nothing if output buffer is too small). */
int s_encode_single_header_block_frame(
    struct aws_h2_frame_headers *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    bool *waiting_for_more_space) {

    /*
     * Figure out the details of the next frame to encode.
     * The first frame will be either HEADERS or PUSH_PROMISE.
     * All subsequent frames will be CONTINUATION
     */

    enum aws_h2_frame_type frame_type;
    uint8_t flags = 0;
    uint8_t pad_length = 0;
    const struct aws_h2_frame_priority_settings *priority_settings = NULL;
    const uint32_t *promised_stream_id = NULL;
    size_t payload_overhead = 0; /* Amount of payload holding things other than header-block (padding, etc) */

    if (frame->state == AWS_H2_HEADERS_STATE_FIRST_FRAME) {
        frame_type = frame->base.type;

        if (frame->pad_length > 0) {
            flags |= AWS_H2_FRAME_F_PADDED;
            pad_length = frame->pad_length;
            payload_overhead += 1 + pad_length;
        }

        if (frame->has_priority) {
            priority_settings = &frame->priority;
            flags |= AWS_H2_FRAME_F_PRIORITY;
            payload_overhead += s_frame_priority_settings_size;
        }

        if (frame->end_stream) {
            flags |= AWS_H2_FRAME_F_END_STREAM;
        }

        if (frame_type == AWS_H2_FRAME_T_PUSH_PROMISE) {
            promised_stream_id = &frame->promised_stream_id;
            payload_overhead += 4;
        }

    } else /* CONTINUATION */ {
        frame_type = AWS_H2_FRAME_T_CONTINUATION;
    }

    /*
     * Figure out what size header-block fragment should go in this frame.
     */

    size_t max_payload;
    if (s_get_max_contiguous_payload_length(encoder, output, &max_payload)) {
        goto handle_waiting_for_more_space;
    }

    size_t max_fragment;
    if (aws_sub_size_checked(max_payload, payload_overhead, &max_fragment)) {
        goto handle_waiting_for_more_space;
    }

    const size_t fragment_len = aws_min_size(max_fragment, frame->header_block_cursor.len);
    if (fragment_len == frame->header_block_cursor.len) {
        /* This will finish the header-block */
        flags |= AWS_H2_FRAME_F_END_HEADERS;
    } else {
        /* If we're not finishing the header-block, is it even worth trying to send this frame now? */
        const size_t even_worth_sending_threshold = s_frame_prefix_length + payload_overhead;
        if (fragment_len < even_worth_sending_threshold) {
            goto handle_waiting_for_more_space;
        }
    }

    /*
     * Ok, it fits! Write the frame
     */

    /* Write the frame prefix */
    const size_t payload_len = fragment_len + payload_overhead;
    if (s_frame_prefix_encode(encoder, frame_type, frame->base.stream_id, payload_len, flags, output)) {
        goto error;
    }

    /* Write pad length */
    if (flags & AWS_H2_FRAME_F_PADDED) {
        AWS_ASSERT(frame_type != AWS_H2_FRAME_T_CONTINUATION);
        if (!aws_byte_buf_write_u8(output, pad_length)) {
            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto error;
        }
    }

    /* Write priority */
    if (flags & AWS_H2_FRAME_F_PRIORITY) {
        AWS_ASSERT(frame_type == AWS_H2_FRAME_T_HEADERS);
        if (s_frame_priority_settings_encode(priority_settings, output)) {
            goto error;
        }
    }

    /* Write promised stream ID */
    if (promised_stream_id) {
        AWS_ASSERT(frame_type == AWS_H2_FRAME_T_PUSH_PROMISE);
        if (!aws_byte_buf_write_be32(output, *promised_stream_id & s_31_bit_mask)) {
            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto error;
        }
    }

    /* Write header-block fragment */
    if (fragment_len > 0) {
        struct aws_byte_cursor fragment = aws_byte_cursor_advance(&frame->header_block_cursor, fragment_len);
        if (!aws_byte_buf_write_from_whole_cursor(output, fragment)) {
            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto error;
        }
    }

    /* Write padding */
    if (flags & AWS_H2_FRAME_F_PADDED) {
        if (!aws_byte_buf_write_u8_n(output, 0, pad_length)) {
            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto error;
        }
    }

    /* Success! Wrote entire frame. It's safe to change state now */
    frame->state =
        flags & AWS_H2_FRAME_F_END_HEADERS ? AWS_H2_HEADERS_STATE_COMPLETE : AWS_H2_HEADERS_STATE_CONTINUATION;
    *waiting_for_more_space = false;
    return AWS_OP_SUCCESS;

handle_waiting_for_more_space:
    ENCODER_LOGF(
        TRACE,
        encoder,
        "Insufficient space to encode %s for stream %" PRIu32 " right now",
        aws_h2_frame_type_to_str(frame->base.type),
        frame->base.stream_id);
    *waiting_for_more_space = true;
    return AWS_OP_SUCCESS;

error:
    frame->state = AWS_H2_HEADERS_STATE_ERROR;
    return AWS_OP_ERR;
}

static int s_frame_headers_encode(
    struct aws_h2_frame *frame_base,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    bool *complete) {

    struct aws_h2_frame_headers *frame = AWS_CONTAINER_OF(frame_base, struct aws_h2_frame_headers, base);

    if (frame->state >= AWS_H2_HEADERS_STATE_COMPLETE) {
        aws_raise_error(AWS_ERROR_INVALID_STATE);
        goto error;
    }

    /* Pre-encode the entire header-block into another buffer
     * the first time we're called. */
    if (frame->state == AWS_H2_HEADERS_STATE_INIT) {
        if (aws_hpack_encode_header_block(encoder->hpack, frame->headers, &frame->whole_encoded_header_block)) {
            ENCODER_LOGF(
                ERROR,
                encoder,
                "Error doing HPACK encoding on %s of stream %" PRIu32 ": %s",
                aws_h2_frame_type_to_str(frame->base.type),
                frame->base.stream_id,
                aws_error_name(aws_last_error()));
            goto error;
        }

        frame->header_block_cursor = aws_byte_cursor_from_buf(&frame->whole_encoded_header_block);
        frame->state = AWS_H2_HEADERS_STATE_FIRST_FRAME;
    }

    /* Write frames (HEADER or PUSH_PROMISE, followed by N CONTINUATION frames)
     * until we're done writing header-block or the buffer is too full to continue */
    bool waiting_for_more_space = false;
    while (frame->state < AWS_H2_HEADERS_STATE_COMPLETE && !waiting_for_more_space) {
        if (s_encode_single_header_block_frame(frame, encoder, output, &waiting_for_more_space)) {
            goto error;
        }
    }

    if (waiting_for_more_space) {
        ENCODER_LOGF(
            TRACE,
            encoder,
            "Insufficient space to finish encoding %s header-block for stream %" PRIu32 " right now",
            aws_h2_frame_type_to_str(frame->base.type),
            frame->base.stream_id);
    }

    *complete = frame->state == AWS_H2_HEADERS_STATE_COMPLETE;
    return AWS_OP_SUCCESS;

error:
    frame->state = AWS_H2_HEADERS_STATE_ERROR;
    return AWS_OP_ERR;
}

/***********************************************************************************************************************
 * PRIORITY
 **********************************************************************************************************************/
DEFINE_FRAME_VTABLE(priority);
static const size_t s_frame_priority_length = 5;

struct aws_h2_frame *aws_h2_frame_new_priority(
    struct aws_allocator *allocator,
    uint32_t stream_id,
    const struct aws_h2_frame_priority_settings *priority) {

    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(priority);

    if (aws_h2_validate_stream_id(stream_id) || aws_h2_validate_stream_id(priority->stream_dependency)) {
        return NULL;
    }

    struct aws_h2_frame_priority *frame = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_frame_priority));
    if (!frame) {
        return NULL;
    }

    s_init_frame_base(&frame->base, allocator, AWS_H2_FRAME_T_PRIORITY, &s_frame_priority_vtable, stream_id);
    frame->priority = *priority;

    return &frame->base;
}

static void s_frame_priority_destroy(struct aws_h2_frame *frame_base) {
    aws_mem_release(frame_base->alloc, frame_base);
}

static int s_frame_priority_encode(
    struct aws_h2_frame *frame_base,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    bool *complete) {

    (void)encoder;
    struct aws_h2_frame_priority *frame = AWS_CONTAINER_OF(frame_base, struct aws_h2_frame_priority, base);

    const size_t total_len = s_frame_prefix_length + s_frame_priority_length;
    const size_t space_available = output->capacity - output->len;

    /* If we can't encode the whole frame at once, try again later */
    if (total_len > space_available) {
        ENCODER_LOGF(
            TRACE,
            encoder,
            "Insufficient space to encode PRIORITY for stream %" PRIu32 " right now",
            frame->base.stream_id);

        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    if (s_frame_prefix_encode(encoder, frame->base.type, frame->base.stream_id, s_frame_priority_length, 0, output)) {
        return AWS_OP_ERR;
    }

    /* Write the priority settings */
    if (s_frame_priority_settings_encode(&frame->priority, output)) {
        return AWS_OP_ERR;
    }

    *complete = true;
    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * RST_STREAM
 **********************************************************************************************************************/
DEFINE_FRAME_VTABLE(rst_stream);
static const size_t s_frame_rst_stream_length = 4;

struct aws_h2_frame *aws_h2_frame_new_rst_stream(
    struct aws_allocator *allocator,
    uint32_t stream_id,
    uint32_t error_code) {

    if (aws_h2_validate_stream_id(stream_id)) {
        return NULL;
    }

    struct aws_h2_frame_rst_stream *frame = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_frame_rst_stream));
    if (!frame) {
        return NULL;
    }

    s_init_frame_base(&frame->base, allocator, AWS_H2_FRAME_T_RST_STREAM, &s_frame_rst_stream_vtable, stream_id);
    frame->error_code = error_code;

    return &frame->base;
}

static void s_frame_rst_stream_destroy(struct aws_h2_frame *frame_base) {
    aws_mem_release(frame_base->alloc, frame_base);
}

static int s_frame_rst_stream_encode(
    struct aws_h2_frame *frame_base,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    bool *complete) {

    (void)encoder;
    struct aws_h2_frame_rst_stream *frame = AWS_CONTAINER_OF(frame_base, struct aws_h2_frame_rst_stream, base);

    const size_t total_len = s_frame_prefix_length + s_frame_rst_stream_length;
    const size_t space_available = output->capacity - output->len;

    /* If we can't encode the whole frame at once, try again later */
    if (total_len > space_available) {
        ENCODER_LOGF(
            TRACE,
            encoder,
            "Insufficient space to encode RST_STREAM for stream %" PRIu32 " right now",
            frame->base.stream_id);
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    if (s_frame_prefix_encode(encoder, frame->base.type, frame->base.stream_id, s_frame_rst_stream_length, 0, output)) {
        return AWS_OP_ERR;
    }

    /* Write the error_code */
    if (!aws_byte_buf_write_be32(output, frame->error_code)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    *complete = true;
    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * SETTINGS
 **********************************************************************************************************************/
DEFINE_FRAME_VTABLE(settings);
static const size_t s_frame_setting_length = 6;

struct aws_h2_frame *aws_h2_frame_new_settings(
    struct aws_allocator *allocator,
    const struct aws_h2_frame_setting *settings_array,
    size_t num_settings,
    bool ack) {

    AWS_PRECONDITION(settings_array || num_settings == 0);

    /* Cannot send settings in an ACK frame */
    if (ack && num_settings > 0) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    /* Check against insane edge case of too many settings to fit in a frame. */
    size_t max_settings = s_settings_and_goaway_payload_limit / s_frame_setting_length;
    if (num_settings > max_settings) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_ENCODER,
            "Cannot create SETTINGS frame with %zu settings, this exceeds internal limit of %zu",
            num_settings,
            max_settings);

        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_h2_frame_settings *frame;
    struct aws_h2_frame_setting *array_alloc;
    const size_t sizeof_settings_array = sizeof(struct aws_h2_frame_setting) * num_settings;
    if (!aws_mem_acquire_many(
            allocator, 2, &frame, sizeof(struct aws_h2_frame_settings), &array_alloc, sizeof_settings_array)) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*frame);
    s_init_frame_base(&frame->base, allocator, AWS_H2_FRAME_T_SETTINGS, &s_frame_settings_vtable, 0);
    frame->ack = ack;
    frame->settings_count = num_settings;
    if (num_settings) {
        frame->settings_array = memcpy(array_alloc, settings_array, sizeof_settings_array);
    }

    return &frame->base;
}

static void s_frame_settings_destroy(struct aws_h2_frame *frame_base) {
    aws_mem_release(frame_base->alloc, frame_base);
}

static int s_frame_settings_encode(
    struct aws_h2_frame *frame_base,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    bool *complete) {

    (void)encoder;
    struct aws_h2_frame_settings *frame = AWS_CONTAINER_OF(frame_base, struct aws_h2_frame_settings, base);

    const size_t payload_len = frame->settings_count * s_frame_setting_length;

    /* If we can't encode the whole frame at once, try again later */
    size_t max_payload;
    if (s_get_max_contiguous_payload_length(encoder, output, &max_payload) || max_payload < payload_len) {
        ENCODER_LOG(TRACE, encoder, "Insufficient space to encode SETTINGS right now");
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    uint8_t flags = 0;
    if (frame->ack) {
        flags |= AWS_H2_FRAME_F_ACK;
    }

    if (s_frame_prefix_encode(encoder, frame->base.type, frame->base.stream_id, payload_len, flags, output)) {
        return AWS_OP_ERR;
    }

    /* Write the payload */
    for (size_t i = 0; i < frame->settings_count; ++i) {
        if (!aws_byte_buf_write_be16(output, frame->settings_array[i].id) ||
            !aws_byte_buf_write_be32(output, frame->settings_array[i].value)) {

            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    *complete = true;
    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * PING
 **********************************************************************************************************************/
DEFINE_FRAME_VTABLE(ping);

struct aws_h2_frame *aws_h2_frame_new_ping(
    struct aws_allocator *allocator,
    bool ack,
    const uint8_t opaque_data[AWS_H2_PING_DATA_SIZE]) {

    struct aws_h2_frame_ping *frame = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_frame_ping));
    if (!frame) {
        return NULL;
    }

    s_init_frame_base(&frame->base, allocator, AWS_H2_FRAME_T_PING, &s_frame_ping_vtable, 0);
    frame->ack = ack;
    memcpy(frame->opaque_data, opaque_data, AWS_H2_PING_DATA_SIZE);

    return &frame->base;
}

static void s_frame_ping_destroy(struct aws_h2_frame *frame_base) {
    aws_mem_release(frame_base->alloc, frame_base);
}

static int s_frame_ping_encode(
    struct aws_h2_frame *frame_base,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    bool *complete) {

    (void)encoder;
    struct aws_h2_frame_ping *frame = AWS_CONTAINER_OF(frame_base, struct aws_h2_frame_ping, base);

    const size_t total_len = s_frame_prefix_length + AWS_H2_PING_DATA_SIZE;
    const size_t space_available = output->capacity - output->len;

    /* If we can't encode the whole frame at once, try again later */
    if (total_len > space_available) {
        ENCODER_LOG(TRACE, encoder, "Insufficient space to encode PING right now");
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    uint8_t flags = 0;
    if (frame->ack) {
        flags |= AWS_H2_FRAME_F_ACK;
    }

    if (s_frame_prefix_encode(encoder, frame->base.type, frame->base.stream_id, AWS_H2_PING_DATA_SIZE, flags, output)) {
        return AWS_OP_ERR;
    }

    /* Write the opaque_data */
    if (!aws_byte_buf_write(output, frame->opaque_data, AWS_H2_PING_DATA_SIZE)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    *complete = true;
    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * GOAWAY
 **********************************************************************************************************************/
DEFINE_FRAME_VTABLE(goaway);

struct aws_h2_frame *aws_h2_frame_new_goaway(
    struct aws_allocator *allocator,
    uint32_t last_stream_id,
    uint32_t error_code,
    struct aws_byte_cursor debug_data) {

    /* If debug_data is too long, don't sent it.
     * It's more important that the GOAWAY frame gets sent. */
    if (debug_data.len > s_settings_and_goaway_payload_limit) {
        AWS_LOGF_WARN(
            AWS_LS_HTTP_ENCODER,
            "Sending GOAWAY without debug-data. Debug-data size %zu exceeds internal limit of %zu",
            debug_data.len,
            s_settings_and_goaway_payload_limit);

        debug_data.len = 0;
    }

    struct aws_h2_frame_goaway *frame = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_frame_goaway));
    if (!frame) {
        return NULL;
    }

    s_init_frame_base(&frame->base, allocator, AWS_H2_FRAME_T_GOAWAY, &s_frame_goaway_vtable, 0);
    frame->last_stream_id = last_stream_id;
    frame->error_code = error_code;
    frame->debug_data = debug_data;

    return &frame->base;
}

static void s_frame_goaway_destroy(struct aws_h2_frame *frame_base) {
    aws_mem_release(frame_base->alloc, frame_base);
}

static int s_frame_goaway_encode(
    struct aws_h2_frame *frame_base,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    bool *complete) {

    (void)encoder;
    struct aws_h2_frame_goaway *frame = AWS_CONTAINER_OF(frame_base, struct aws_h2_frame_goaway, base);

    const size_t payload_len = 8 + frame->debug_data.len;
    const size_t total_len = s_frame_prefix_length + payload_len;
    const size_t space_available = output->capacity - output->len;

    /* If we can't encode the whole frame at once, try again later */
    if (total_len > space_available) {
        ENCODER_LOG(TRACE, encoder, "Insufficient space to encode GOAWAY right now");
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    if (s_frame_prefix_encode(encoder, frame->base.type, frame->base.stream_id, payload_len, 0, output)) {
        return AWS_OP_ERR;
    }

    /* Write the payload */
    if (!aws_byte_buf_write_be32(output, frame->last_stream_id & s_31_bit_mask) ||
        !aws_byte_buf_write_be32(output, frame->error_code) ||
        !aws_byte_buf_write_from_whole_cursor(output, frame->debug_data)) {

        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    *complete = true;
    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * WINDOW_UPDATE
 **********************************************************************************************************************/
DEFINE_FRAME_VTABLE(window_update);
static const size_t s_frame_window_update_length = 4;

struct aws_h2_frame *aws_h2_frame_new_window_update(
    struct aws_allocator *allocator,
    uint32_t stream_id,
    uint32_t window_size_increment) {

    /* Note: stream_id may be zero or non-zero */
    if (stream_id > AWS_H2_STREAM_ID_MAX) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    if (window_size_increment > AWS_H2_WINDOW_UPDATE_MAX) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_h2_frame_window_update *frame = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_frame_window_update));
    if (!frame) {
        return NULL;
    }

    s_init_frame_base(&frame->base, allocator, AWS_H2_FRAME_T_WINDOW_UPDATE, &s_frame_window_update_vtable, stream_id);
    frame->window_size_increment = window_size_increment;

    return &frame->base;
}

static void s_frame_window_update_destroy(struct aws_h2_frame *frame_base) {
    aws_mem_release(frame_base->alloc, frame_base);
}

static int s_frame_window_update_encode(
    struct aws_h2_frame *frame_base,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    bool *complete) {

    (void)encoder;
    struct aws_h2_frame_window_update *frame = AWS_CONTAINER_OF(frame_base, struct aws_h2_frame_window_update, base);

    const size_t total_len = s_frame_prefix_length + s_frame_window_update_length;
    const size_t space_available = output->capacity - output->len;

    /* If we can't encode the whole frame at once, try again later */
    if (total_len > space_available) {
        ENCODER_LOG(TRACE, encoder, "Insufficient space to encode WINDOW_UPDATE right now");
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    if (s_frame_prefix_encode(
            encoder, frame->base.type, frame->base.stream_id, s_frame_window_update_length, 0, output)) {
        return AWS_OP_ERR;
    }

    /* Write the error_code */
    if (!aws_byte_buf_write_be32(output, frame->window_size_increment)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    *complete = true;
    return AWS_OP_SUCCESS;
}

void aws_h2_frame_destroy(struct aws_h2_frame *frame) {
    if (frame) {
        frame->vtable->destroy(frame);
    }
}

int aws_h2_encode_frame(
    struct aws_h2_frame_encoder *encoder,
    struct aws_h2_frame *frame,
    struct aws_byte_buf *output,
    bool *frame_complete) {

    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(output);
    AWS_PRECONDITION(frame_complete);

    if (encoder->has_errored) {
        ENCODER_LOG(ERROR, encoder, "Encoder cannot be used again after an error");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    if (encoder->current_frame && (encoder->current_frame != frame)) {
        ENCODER_LOG(ERROR, encoder, "Cannot encode new frame until previous frame completes");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    *frame_complete = false;

    if (frame->vtable->encode(frame, encoder, output, frame_complete)) {
        ENCODER_LOGF(
            ERROR,
            encoder,
            "Failed to encode frame type=%s stream_id=%" PRIu32 ", %s",
            aws_h2_frame_type_to_str(frame->type),
            frame->stream_id,
            aws_error_name(aws_last_error()));
        encoder->has_errored = true;
        return AWS_OP_ERR;
    }

    encoder->current_frame = *frame_complete ? NULL : frame;
    return AWS_OP_SUCCESS;
}
