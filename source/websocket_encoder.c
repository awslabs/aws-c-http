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

#include <aws/http/private/websocket_encoder.h>

/* TODO: encoder logging */
/* TODO: make common masking algorithm in aws-c-common */
/* TODO: validate fragmentation of outgoing frames? */
/* TODO: use nospec advance? */
/* TODO: whyyyy does advance break after SIZE_MAX/2 */
/* TODO: aws_byte_buf_write_from_advancing_cursor() ?*/

typedef int(state_fn)(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf);

/* STATE_INIT: Outputs no data */
static int s_state_init(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {
    (void)out_buf;

    if (!encoder->is_frame_in_progress) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    encoder->state = AWS_WEBSOCKET_ENCODER_STATE_OPCODE_BYTE;
    return AWS_OP_SUCCESS;
}

/* STATE_OPCODE_BYTE: Outputs 1st byte of frame, which is packed with goodies. */
static int s_state_opcode_byte(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {
    /* First 4 bits are fin|rsv1|rsv2|rsv3, next 4 bits are opcode */
    uint8_t byte = 0;
    byte |= (encoder->frame.fin << 7);
    byte |= (encoder->frame.rsv[0] << 6);
    byte |= (encoder->frame.rsv[1] << 5);
    byte |= (encoder->frame.rsv[2] << 4);
    byte |= (encoder->frame.opcode & 0x0F);

    /* If buffer has room to write, proceed to next state */
    if (aws_byte_buf_write_u8(out_buf, byte)) {
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_LENGTH_BYTE;
    }

    return AWS_OP_SUCCESS;
}

/* STATE_LENGTH_BYTE: Output 2nd byte of frame, which indicates payload length */
static int s_state_length_byte(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {
    /* First bit is masking bool */
    uint8_t byte = (uint8_t)(encoder->frame.masked << 7);

    /* Next 7bits are length, if length is small.
     * Otherwise next 7bits are a magic number indicating how many bytes will be required to encode actual length */
    bool extended_length_required;

    if (encoder->frame.payload_length < AWS_WEBSOCKET_2BYTE_EXTENDED_LENGTH_MIN_VALUE) {
        byte |= (uint8_t)encoder->frame.payload_length;
        extended_length_required = false;
    } else if (encoder->frame.payload_length <= AWS_WEBSOCKET_2BYTE_EXTENDED_LENGTH_MAX_VALUE) {
        byte |= AWS_WEBSOCKET_7BIT_VALUE_FOR_2BYTE_EXTENDED_LENGTH;
        extended_length_required = true;
    } else {
        assert(encoder->frame.payload_length <= AWS_WEBSOCKET_8BYTE_EXTENDED_LENGTH_MAX_VALUE);
        byte |= AWS_WEBSOCKET_7BIT_VALUE_FOR_8BYTE_EXTENDED_LENGTH;
        extended_length_required = true;
    }

    /* If buffer has room to write, proceed to next appropriate state */
    if (aws_byte_buf_write_u8(out_buf, byte)) {
        if (extended_length_required) {
            encoder->state = AWS_WEBSOCKET_ENCODER_STATE_EXTENDED_LENGTH;
            encoder->state_bytes_processed = 0;
        } else {
            encoder->state = AWS_WEBSOCKET_ENCODER_STATE_MASKING_KEY_CHECK;
        }
    }

    return AWS_OP_SUCCESS;
}

/* STATE_EXTENDED_LENGTH: Output extended length (state skipped if not using extended length). */
static int s_state_extended_length(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {
    /* Fill tmp buffer with extended-length in network byte order */
    uint8_t network_bytes_array[8];
    struct aws_byte_buf network_bytes_buf =
        aws_byte_buf_from_empty_array(network_bytes_array, sizeof(network_bytes_array));
    if (encoder->frame.payload_length <= AWS_WEBSOCKET_2BYTE_EXTENDED_LENGTH_MAX_VALUE) {
        aws_byte_buf_write_be16(&network_bytes_buf, (uint16_t)encoder->frame.payload_length);
    } else {
        aws_byte_buf_write_be64(&network_bytes_buf, encoder->frame.payload_length);
    }

    /* Use cursor to iterate over tmp buffer */
    struct aws_byte_cursor network_bytes_cursor = aws_byte_cursor_from_buf(&network_bytes_buf);

    /* Advance cursor if some bytes already written */
    aws_byte_cursor_advance(&network_bytes_cursor, encoder->state_bytes_processed);

    /* Shorten cursor if it won't all fit in out_buf */
    bool all_data_written = true;
    size_t space_available = out_buf->capacity - out_buf->len;
    if (network_bytes_cursor.len > space_available) {
        network_bytes_cursor.len = space_available;
        all_data_written = false;
    }

    aws_byte_buf_write_from_whole_cursor(out_buf, network_bytes_cursor);

    /* If all bytes written, advance to next state */
    if (all_data_written) {
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_MASKING_KEY_CHECK;
    }

    return AWS_OP_SUCCESS;
}

/* MASKING_KEY_CHECK: Outputs no data. Gets things ready for (or decides to skip) the STATE_MASKING_KEY */
static int s_state_masking_key_check(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {
    (void)out_buf;

    if (encoder->frame.masked) {
        encoder->state_bytes_processed = 0;
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_MASKING_KEY;
    } else {
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_PAYLOAD_CHECK;
    }

    return AWS_OP_SUCCESS;
}

/* MASKING_KEY: Output masking-key (state skipped if no masking key). */
static int s_state_masking_key(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {
    /* Prepare cursor to iterate over masking-key bytes */
    struct aws_byte_cursor cursor =
        aws_byte_cursor_from_array(encoder->frame.masking_key, sizeof(encoder->frame.masking_key));

    /* Advance cursor if some bytes already written */
    aws_byte_cursor_advance(&cursor, encoder->state_bytes_processed);

    /* Shorten cursor if it won't all fit in out_buf */
    bool all_data_written = true;
    size_t space_available = out_buf->capacity - out_buf->len;
    if (cursor.len > space_available) {
        cursor.len = space_available;
        all_data_written = false;
    }

    aws_byte_buf_write_from_whole_cursor(out_buf, cursor);

    /* If all bytes written, advance to next state */
    if (all_data_written) {
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_PAYLOAD_CHECK;
    }

    return AWS_OP_SUCCESS;
}

/* MASKING_KEY_CHECK: Outputs no data. Gets things ready for (or decides to skip) STATE_PAYLOAD */
static int s_state_payload_check(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {
    (void)out_buf;

    if (encoder->frame.payload_length > 0) {
        encoder->state_bytes_processed = 0;
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_PAYLOAD;
    } else {
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_DONE;
    }

    return AWS_OP_SUCCESS;
}

/* PAYLOAD: Output payload until we're done (state skipped if no payload). */
static int s_state_payload(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {

    /* Bail early if out_buf has no space for writing */
    if (out_buf->len >= out_buf->capacity) {
        return AWS_OP_SUCCESS;
    }

    const uint64_t prev_bytes_processed = encoder->state_bytes_processed;
    const struct aws_byte_buf prev_buf = *out_buf;

    /* Invoke callback which will write to buffer */
    int err = encoder->stream_outgoing_payload(out_buf, encoder->user_data);
    if (err) {
        return AWS_OP_ERR;
    }

    /* Ensure that user did not commit forbidden acts with the out_buf */
    AWS_FATAL_ASSERT(
        (out_buf->buffer == prev_buf.buffer) && (out_buf->capacity == prev_buf.capacity) &&
        (out_buf->len >= prev_buf.len));

    size_t bytes_written = out_buf->len - prev_buf.len;

    err = aws_add_u64_checked(encoder->state_bytes_processed, bytes_written, &encoder->state_bytes_processed);
    if (err) {
        return AWS_OP_ERR;
    }

    if (encoder->state_bytes_processed > encoder->frame.payload_length) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    /* Mask data, if necessary.
     * RFC-6455 Section 5.3 Client-to-Server Masking
     * Each byte of payload is XOR against a byte of the masking-key */
    if (encoder->frame.masked) {
        uint64_t mask_index = prev_bytes_processed;

        /* Optimization idea: don't do this 1 byte at a time */
        uint8_t *current_byte = out_buf->buffer + prev_buf.len;
        uint8_t *end_byte = out_buf->buffer + out_buf->len;
        while (current_byte != end_byte) {
            *current_byte++ ^= encoder->frame.masking_key[mask_index++ % 4];
        }
    }

    /* If done writing payload, proceed to next state */
    if (encoder->state_bytes_processed == encoder->frame.payload_length) {
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_DONE;
    }

    return AWS_OP_SUCCESS;
}

static state_fn *s_state_functions[AWS_WEBSOCKET_ENCODER_STATE_DONE] = {
    s_state_init,
    s_state_opcode_byte,
    s_state_length_byte,
    s_state_extended_length,
    s_state_masking_key_check,
    s_state_masking_key,
    s_state_payload_check,
    s_state_payload,
};

int aws_websocket_encoder_process(struct aws_websocket_encoder *encoder, struct aws_byte_buf *out_buf) {

    while (encoder->state != AWS_WEBSOCKET_ENCODER_STATE_DONE) {
        const enum aws_websocket_encoder_state prev_state = encoder->state;

        int err = s_state_functions[encoder->state](encoder, out_buf);
        if (err) {
            return AWS_OP_ERR;
        }

        if (prev_state == encoder->state) {
            assert(out_buf->len == out_buf->capacity); /* Assert that a state isn't giving up without filling buffer */
            break;
        }
    }

    if (encoder->state == AWS_WEBSOCKET_ENCODER_STATE_DONE) {
        encoder->state = AWS_WEBSOCKET_ENCODER_STATE_INIT;
        encoder->is_frame_in_progress = false;
    }

    return AWS_OP_SUCCESS;
}

int aws_websocket_encoder_start_frame(struct aws_websocket_encoder *encoder, const struct aws_websocket_frame *frame) {
    if (encoder->is_frame_in_progress) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    /* Validate frame */
    if (frame->opcode != (frame->opcode & 0x0F)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (frame->payload_length > AWS_WEBSOCKET_8BYTE_EXTENDED_LENGTH_MAX_VALUE) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    encoder->frame = *frame;
    encoder->is_frame_in_progress = true;

    return AWS_OP_SUCCESS;
}

bool aws_websocket_encoder_is_frame_in_progress(const struct aws_websocket_encoder *encoder) {
    return encoder->is_frame_in_progress;
}

void aws_websocket_encoder_init(
    struct aws_websocket_encoder *encoder,
    aws_websocket_encoder_payload_fn *stream_outgoing_payload,
    void *user_data) {

    AWS_ZERO_STRUCT(*encoder);
    encoder->user_data = user_data;
    encoder->stream_outgoing_payload = stream_outgoing_payload;
}
