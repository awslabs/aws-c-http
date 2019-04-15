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

#include <aws/http/private/websocket_decoder.h>

/* If 7bit payload length has these values, then the next few bytes contain the real payload length */
#define VALUE_FOR_2BYTE_EXTENDED_LENGTH 126
#define VALUE_FOR_8BYTE_EXTENDED_LENGTH 127

typedef int(state_fn)(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data);

/* STATE_INIT: Resets things, consumes no data */
static int s_state_init(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data) {
    (void)data;
    AWS_ZERO_STRUCT(decoder->current_frame);
    decoder->state++;
    return AWS_OP_SUCCESS;
}

/* STATE_OPCODE_BYTE: Decode first byte of frame, which has all kinds of goodies in it. */
static int s_state_opcode_byte(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data) {
    if (data->len == 0) {
        return AWS_OP_SUCCESS;
    }

    uint8_t byte = data->ptr[0];
    aws_byte_cursor_advance(data, 1);

    /* first 4 bits are all bools */
    decoder->current_frame.fin = byte & 0x80;
    decoder->current_frame.rsv[0] = byte & 0x40;
    decoder->current_frame.rsv[1] = byte & 0x20;
    decoder->current_frame.rsv[2] = byte & 0x10;

    /* next 4 bits are opcode */
    decoder->current_frame.opcode = byte & 0x0F;

    /* RFC-6455 Section 5.2 Fragmentation
     *
     * Data frames with the FIN bit clear are considered fragmented and must be followed by
     * 1+ CONTINUATION frames, where only the final CONTINUATION frame's FIN bit is set.
     *
     * Control frames may be injected in the middle of a fragmented message,
     * but control frames may not be fragmented themselves.
     */
    if (aws_websocket_is_data_frame(decoder->current_frame.opcode)) {
        bool is_continuation_frame = AWS_WEBSOCKET_OPCODE_CONTINUATION == decoder->current_frame.opcode;

        if (decoder->expecting_continuation_data_frames != is_continuation_frame) {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }

        decoder->expecting_continuation_data_frames = !decoder->current_frame.fin;

    } else {
        /* Control frames themselves MUST NOT be fragmented. */
        if (!decoder->current_frame.fin) {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }
    }

    decoder->state++;
    return AWS_OP_SUCCESS;
}

/* STATE_LENGTH_BEGIN: Decode byte containing length, determine if we need to decode extended length. */
static int s_state_length_begin(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data) {
    if (data->len == 0) {
        return AWS_OP_SUCCESS;
    }

    uint8_t byte = data->ptr[0];
    aws_byte_cursor_advance(data, 1);

    /* first bit is a bool */
    decoder->current_frame.masked = byte & 0x80;

    /* remaining 7 bits are payload length */
    decoder->current_frame.payload_length = byte & 0x7F;

    /* If 7bit payload length has a high value, then the next few bytes contain the real payload length */
    if (decoder->current_frame.payload_length < VALUE_FOR_2BYTE_EXTENDED_LENGTH) {
        decoder->state += 2; /* Skip next state, which would have processed extended length */
    } else {
        decoder->state_bytes_processed = 0;
        decoder->state++;
    }

    return AWS_OP_SUCCESS;
}

/* STATE_LENGTH_CONTINUE: Decode extended length (skipped if no extended length) . */
static int s_state_length_continue(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data) {
    if (data->len == 0) {
        return AWS_OP_SUCCESS;
    }

    /* RFC-6455 Section 5.2 Base Framing Protocol - Payload length
     * 1) It is a crime to use more bytes than necessary to encode length.
     *      > in all cases, the minimal number of bytes MUST be used to encode
     *      > the length, for example, the length of a 124-byte-long string
     *      > can't be encoded as the sequence 126, 0, 124
     * 2) It is a crime to use most-significant bit on 8 byte payloads.
     *      > If 127, the following 8 bytes interpreted as a 64-bit unsigned integer
     *      > (the most significant bit MUST be 0) are the payload length */
    uint8_t total_bytes_extended_length;
    uint64_t min_acceptable_value;
    uint64_t max_acceptable_value;
    if (decoder->current_frame.payload_length == VALUE_FOR_2BYTE_EXTENDED_LENGTH) {
        total_bytes_extended_length = 2;
        min_acceptable_value = VALUE_FOR_2BYTE_EXTENDED_LENGTH;
        max_acceptable_value = UINT16_MAX;
    } else {
        assert(decoder->current_frame.payload_length == VALUE_FOR_8BYTE_EXTENDED_LENGTH);

        total_bytes_extended_length = 8;
        min_acceptable_value = UINT16_MAX + 1;
        max_acceptable_value = 0x8000000000000000ULL - 1;
    }

    /* Copy bytes of extended-length to state_cache, we'll process them later.*/
    assert(total_bytes_extended_length > decoder->state_bytes_processed);

    size_t remaining_bytes = (size_t)(total_bytes_extended_length - decoder->state_bytes_processed);
    size_t bytes_to_consume = remaining_bytes <= data->len ? remaining_bytes : data->len;

    assert(bytes_to_consume + decoder->state_bytes_processed <= sizeof(decoder->state_cache));

    memcpy(decoder->state_cache + decoder->state_bytes_processed, data->ptr, bytes_to_consume);

    aws_byte_cursor_advance(data, bytes_to_consume);
    decoder->state_bytes_processed += bytes_to_consume;

    /* Return, still waiting on more bytes */
    if (decoder->state_bytes_processed < total_bytes_extended_length) {
        return AWS_OP_SUCCESS;
    }

    /* All bytes have been copied into state_cache, now read them together as one number,
     * transforming from network byte order (big endian) to native endianness. */
    struct aws_byte_cursor cache_cursor = aws_byte_cursor_from_array(decoder->state_cache, total_bytes_extended_length);
    if (total_bytes_extended_length == 2) {
        uint16_t val;
        if (!aws_byte_cursor_read_be16(&cache_cursor, &val)) {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }

        decoder->current_frame.payload_length = val;
    } else {
        if (!aws_byte_cursor_read_be64(&cache_cursor, &decoder->current_frame.payload_length)) {
            return aws_raise_error(AWS_ERROR_HTTP_PARSE);
        }
    }

    if (decoder->current_frame.payload_length < min_acceptable_value ||
        decoder->current_frame.payload_length > max_acceptable_value) {

        return aws_raise_error(AWS_ERROR_HTTP_PARSE);
    }

    decoder->state++;
    return AWS_OP_SUCCESS;
}

/* MASKING_KEY_BEGIN: Determine if we need to decode masking-key. Consumes no data. */
static int s_state_masking_key_begin(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data) {
    (void)data;

    /* If mask bit was set, move to next state to process 4 bytes of masking key.
     * Otherwise skip next step, there is no masking key. */
    if (decoder->current_frame.masked) {
        decoder->state++;
        decoder->state_bytes_processed = 0;
    } else {
        decoder->state += 2;
    }

    return AWS_OP_SUCCESS;
}

/* MASKING_KEY_CONTINUE: Decode masking-key. */
static int s_state_masking_key_continue(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data) {
    if (data->len == 0) {
        return AWS_OP_SUCCESS;
    }

    assert(4 > decoder->state_bytes_processed);
    size_t bytes_remaining = 4 - (size_t)decoder->state_bytes_processed;
    size_t bytes_to_consume = bytes_remaining < data->len ? bytes_remaining : data->len;

    memcpy(decoder->current_frame.masking_key + decoder->state_bytes_processed, data->ptr, bytes_to_consume);

    aws_byte_cursor_advance(data, bytes_to_consume);
    decoder->state_bytes_processed += bytes_to_consume;

    /* If all bytes consumed, proceed to next state */
    if (decoder->state_bytes_processed == 4) {
        decoder->state++;
    }

    return AWS_OP_SUCCESS;
}

/* PAYLOAD_BEGIN: Determine if we need to decode a payload. Consumes no data. */
static int s_state_payload_begin(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data) {
    (void)data;

    /* Invoke on_frame() callback to inform user of non-payload data. */
    int err = decoder->on_frame(&decoder->current_frame, decoder->user_data);
    if (err) {
        return AWS_OP_ERR;
    }

    /* Choose next state: either we have payload to process or we don't. */
    if (decoder->current_frame.payload_length > 0) {
        decoder->state_bytes_processed = 0;
        decoder->state++;
    } else {
        decoder->state += 2;
    }

    return AWS_OP_SUCCESS;
}

/* PAYLOAD_CONTINUE: Decode payload until we're done. */
static int s_state_payload_continue(struct aws_websocket_decoder *decoder, struct aws_byte_cursor *data) {
    if (data->len == 0) {
        return AWS_OP_SUCCESS;
    }

    assert(decoder->current_frame.payload_length > decoder->state_bytes_processed);
    uint64_t bytes_remaining = decoder->current_frame.payload_length - decoder->state_bytes_processed;
    size_t bytes_to_consume = bytes_remaining < data->len ? (size_t)bytes_remaining : data->len;

    struct aws_byte_cursor payload = aws_byte_cursor_advance(data, bytes_to_consume);

    /* Unmask data, if necessary.
     * RFC-6455 Section 5.3 Client-to-Server Masking
     * Each byte of payload is XOR against a byte of the masking-key */
    if (decoder->current_frame.masked) {
        uint64_t mask_index = decoder->state_bytes_processed;

        /* Optimization idea: don't do this 1 byte at a time */
        uint8_t *current_byte = payload.ptr;
        uint8_t *end_byte = payload.ptr + payload.len;
        while (current_byte != end_byte) {
            *current_byte++ ^= decoder->current_frame.masking_key[mask_index++ % 4];
        }
    }

    /* TODO: validate utf-8 */

    /* Invoke on_payload() callback to inform user of payload data */
    int err = decoder->on_payload(payload, decoder->user_data);
    if (err) {
        return AWS_OP_ERR;
    }

    decoder->state_bytes_processed += payload.len;
    assert(decoder->state_bytes_processed <= decoder->current_frame.payload_length);

    /* If all data consumed, proceed to next state. */
    if (decoder->state_bytes_processed == decoder->current_frame.payload_length) {
        decoder->state++;
    }

    return AWS_OP_SUCCESS;
}

static state_fn *s_state_vtable[AWS_WEBSOCKET_DECODER_STATE_DONE] = {
    s_state_init,
    s_state_opcode_byte,
    s_state_length_begin,
    s_state_length_continue,
    s_state_masking_key_begin,
    s_state_masking_key_continue,
    s_state_payload_begin,
    s_state_payload_continue,
};

int aws_websocket_decoder_process(
    struct aws_websocket_decoder *decoder,
    struct aws_byte_cursor *data,
    bool *frame_complete) {

    while (decoder->state != AWS_WEBSOCKET_DECODER_STATE_DONE) {
        enum aws_websocket_decoder_state prev_state = decoder->state;

        int err = s_state_vtable[decoder->state](decoder, data);
        if (err) {
            return AWS_OP_ERR;
        }

        if (decoder->state == prev_state) {
            break;
        }
    }

    if (decoder->state == AWS_WEBSOCKET_DECODER_STATE_DONE) {
        decoder->state = AWS_WEBSOCKET_DECODER_STATE_INIT;
        *frame_complete = true;
        return AWS_OP_SUCCESS;
    }

    *frame_complete = false;
    return AWS_OP_SUCCESS;
}

void aws_websocket_decoder_init(
    struct aws_websocket_decoder *decoder,
    aws_websocket_decoder_frame_fn *on_frame,
    aws_websocket_decoder_payload_fn *on_payload,
    void *user_data) {

    AWS_ZERO_STRUCT(*decoder);
    decoder->user_data = user_data;
    decoder->on_frame = on_frame;
    decoder->on_payload = on_payload;
}
