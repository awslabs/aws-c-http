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

#include <inttypes.h>

/* #TODO: Don't raise AWS_H2_ERR_* enums, raise AWS_ERROR_* .
 *        Also, if encoder raises error corresponding to AWS_H2_ERR, should
 *        we send that code in the GOAWAY, or always treat encoder errors as AWS_H2_ERR_INTERNAL?
 *        Like, you're only supposed to inform peer of errors that were their fault, right? */

/* Stream ids & dependencies should only write the bottom 31 bits */
static const uint32_t s_31_bit_mask = UINT32_MAX >> 1;
static const uint32_t s_u32_top_bit_mask = UINT32_MAX << 31;

static const uint8_t s_indexed_header_field_mask = 1 << 7;
static const uint8_t s_literal_save_field_mask = 1 << 6;
static const uint8_t s_literal_no_forward_save_mask = 1 << 4;

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
 * Header Block
 **********************************************************************************************************************/
int aws_h2_frame_header_block_init(struct aws_h2_frame_header_block *header_block, struct aws_allocator *allocator) {
    AWS_PRECONDITION(header_block);
    AWS_PRECONDITION(allocator);

    return aws_array_list_init_dynamic(
        &header_block->header_fields, allocator, 0, sizeof(struct aws_h2_frame_header_field));
}
void aws_h2_frame_header_block_clean_up(struct aws_h2_frame_header_block *header_block) {
    AWS_PRECONDITION(header_block);

    aws_array_list_clean_up(&header_block->header_fields);
}

int aws_h2_frame_header_block_get_encoded_length(
    const struct aws_h2_frame_header_block *header_block,
    const struct aws_h2_frame_encoder *encoder,
    size_t *length) {
    AWS_PRECONDITION(header_block);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(length);

    *length = 0;

    AWS_PRECONDITION(header_block);
    AWS_PRECONDITION(length);

    const size_t num_headers = aws_array_list_length(&header_block->header_fields);
    for (size_t i = 0; i < num_headers; ++i) {

        const struct aws_h2_frame_header_field *field = NULL;
        aws_array_list_get_at_ptr(&header_block->header_fields, (void **)&field, i);
        AWS_ASSERT(field);

        bool found_value = false;
        const size_t index = aws_hpack_find_index(encoder->hpack, &field->header, &found_value);

        uint8_t prefix_size;
        /* If a value was found, this is an indexed header */
        if (found_value) {
            prefix_size = 7;
        } else {
            /* If not indexed, determine the appropriate flags and prefixes */
            switch (field->hpack_behavior) {
                case AWS_H2_HEADER_BEHAVIOR_SAVE:
                    prefix_size = 6;
                    break;
                case AWS_H2_HEADER_BEHAVIOR_NO_SAVE:
                    prefix_size = 4;
                    break;
                case AWS_H2_HEADER_BEHAVIOR_NO_FORWARD_SAVE:
                    prefix_size = 5;
                    break;
                default:
                    /* Unreachable */
                    AWS_FATAL_ASSERT(false);
            }
        }

        /* Write the index if indexed, or 0 to signal literal name */
        *length += aws_hpack_get_encoded_length_integer(index, prefix_size);

        if (!found_value) {
            /* If not an indexed header, check if the name needs to be written */
            if (!index) {
                *length +=
                    aws_hpack_get_encoded_length_string(encoder->hpack, field->header.name, encoder->use_huffman);
            }

            /* Value must be written if the field isn't pure indexed */
            *length += aws_hpack_get_encoded_length_string(encoder->hpack, field->header.value, encoder->use_huffman);
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_h2_frame_header_block_encode(
    const struct aws_h2_frame_header_block *header_block,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(header_block);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    const size_t num_headers = aws_array_list_length(&header_block->header_fields);
    AWS_LOGF(AWS_LL_TRACE, AWS_LS_HTTP_FRAMES, "Encoding header block with %zu headers", num_headers);

    for (size_t i = 0; i < num_headers; ++i) {

        const struct aws_h2_frame_header_field *field = NULL;
        aws_array_list_get_at_ptr(&header_block->header_fields, (void **)&field, i);
        AWS_ASSERT(field);

        bool found_value = true;
        const size_t index = aws_hpack_find_index(encoder->hpack, &field->header, &found_value);

        uint8_t mask;
        uint8_t prefix_size;
        /* If a value was found, this is an indexed header */
        if (found_value) {
            mask = s_indexed_header_field_mask;
            prefix_size = 7;
        } else {
            /* If not indexed, determine the appropriate flags and prefixes */
            switch (field->hpack_behavior) {
                case AWS_H2_HEADER_BEHAVIOR_SAVE:
                    mask = s_literal_save_field_mask;
                    prefix_size = 6;
                    break;
                case AWS_H2_HEADER_BEHAVIOR_NO_SAVE:
                    mask = 0; /* No bits set, just 4 bit prefix */
                    prefix_size = 4;
                    break;
                case AWS_H2_HEADER_BEHAVIOR_NO_FORWARD_SAVE:
                    mask = s_literal_no_forward_save_mask;
                    prefix_size = 4;
                    break;
                default:
                    /* Unreachable */
                    AWS_FATAL_ASSERT(false);
            }
        }

        const size_t before_len = output->len;

        /* Write the top bits to signal representation */
        output->buffer[output->len] = mask;

        /* Write the index if indexed, or 0 to signal literal name */
        if (aws_hpack_encode_integer(index, prefix_size, output)) {
            return AWS_OP_ERR;
        }

        /* Names and values must be copied to avoid modifying the original struct */
        struct aws_byte_cursor scratch;

        if (!found_value) {
            /* If not an indexed header, check if the name needs to be written */
            if (!index) {
                scratch = field->header.name;
                if (aws_hpack_encode_string(encoder->hpack, &scratch, encoder->use_huffman, output)) {
                    return AWS_OP_ERR;
                }
                AWS_ASSERT(scratch.len == 0);
            }

            /* Value must be written if the field isn't pure indexed */
            scratch = field->header.value;
            if (aws_hpack_encode_string(encoder->hpack, &scratch, encoder->use_huffman, output)) {
                return AWS_OP_ERR;
            }
            AWS_ASSERT(scratch.len == 0);

            if (field->hpack_behavior == AWS_H2_HEADER_BEHAVIOR_SAVE) {
                /* Save for next time */
                aws_hpack_insert_header(encoder->hpack, &field->header);
            }
        }

        const size_t encoded_bytes = output->len - before_len;
        AWS_LOGF(AWS_LL_TRACE, AWS_LS_HTTP_FRAMES, "Encoded header %zu as %zu bytes", i, encoded_bytes);
    }

    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * Common Header
 **********************************************************************************************************************/
static int s_frame_header_encode(
    struct aws_h2_frame_header *header,
    size_t length,
    uint8_t flags,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(header);
    AWS_PRECONDITION(output);

    AWS_LOGF(
        AWS_LL_TRACE,
        AWS_LS_HTTP_FRAMES,
        "Beginning encode of frame %s: stream: %" PRIu32 " payload length: %zu flags: %" PRIu8,
        aws_h2_frame_type_to_str(header->type),
        header->stream_id,
        length,
        flags);

    /* Length must fit in 24 bits */
    if (length > 0x00FFFFFF) {
        return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);
    }

    /* Write length */
    if (!aws_byte_buf_write_be24(output, (uint32_t)length)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write type */
    if (!aws_byte_buf_write_u8(output, header->type)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write flags */
    if (!aws_byte_buf_write_u8(output, flags)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write stream id (with reserved first bit) */
    if (!aws_byte_buf_write_be32(output, header->stream_id & s_31_bit_mask)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    return AWS_OP_SUCCESS;
}

/***********************************************************************************************************************
 * Encoder
 **********************************************************************************************************************/
int aws_h2_frame_encoder_init(struct aws_h2_frame_encoder *encoder, struct aws_allocator *allocator) {
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(allocator);

    AWS_ZERO_STRUCT(*encoder);
    encoder->allocator = allocator;

    encoder->hpack = aws_hpack_context_new(allocator, AWS_LS_HTTP_ENCODER, encoder);
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
int aws_h2_frame_data_init(struct aws_h2_frame_data *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_DATA;

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_data_clean_up(struct aws_h2_frame_data *frame) {
    AWS_PRECONDITION(frame);
    (void)frame;
}

int aws_h2_frame_data_encode(
    struct aws_h2_frame_data *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    (void)encoder;

    const size_t output_init_len = output->len;

    /* Calculate length & flags */
    size_t length = frame->data.len;

    uint8_t flags = 0;
    if (frame->end_stream) {
        flags |= AWS_H2_FRAME_F_END_STREAM;
    }
    if (frame->pad_length) {
        flags |= AWS_H2_FRAME_F_PADDED;
        length += 1 + frame->pad_length;
    }

    /* Write the header data */
    if (s_frame_header_encode(&frame->header, length, flags, output)) {
        goto write_error;
    }

    /* Write pad length */
    if (frame->pad_length) {
        if (!aws_byte_buf_write_u8(output, frame->pad_length)) {
            goto write_error;
        }
    }
    /* Write data */
    if (!aws_byte_buf_write_from_whole_cursor(output, frame->data)) {
        goto write_error;
    }
    /* Write padding */
    for (size_t i = 0; i < frame->pad_length; ++i) {
        if (!aws_byte_buf_write_u8(output, 0)) {
            goto write_error;
        }
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);
}

/***********************************************************************************************************************
 * HEADERS
 **********************************************************************************************************************/
int aws_h2_frame_headers_init(struct aws_h2_frame_headers *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_HEADERS;

    return aws_h2_frame_header_block_init(&frame->header_block, allocator);
}
void aws_h2_frame_headers_clean_up(struct aws_h2_frame_headers *frame) {
    AWS_PRECONDITION(frame);

    aws_h2_frame_header_block_clean_up(&frame->header_block);
}

int aws_h2_frame_headers_encode(
    struct aws_h2_frame_headers *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    const size_t output_init_len = output->len;

    /* Calculate length & flags */
    size_t length = 0;
    if (aws_h2_frame_header_block_get_encoded_length(&frame->header_block, encoder, &length)) {
        goto compression_error;
    }

    uint8_t flags = 0;
    if (frame->end_stream) {
        flags |= AWS_H2_FRAME_F_END_STREAM;
    }
    if (frame->end_headers) {
        flags |= AWS_H2_FRAME_F_END_HEADERS;
    }
    if (frame->pad_length) {
        flags |= AWS_H2_FRAME_F_PADDED;
        length += 1 + frame->pad_length;
    }
    if (frame->has_priority) {
        flags |= AWS_H2_FRAME_F_PRIORITY;
        length += s_frame_priority_settings_size;
    }

    /* Write the header data */
    if (s_frame_header_encode(&frame->header, length, flags, output)) {
        goto write_error;
    }

    /* Write pad length */
    if (frame->pad_length) {
        if (!aws_byte_buf_write_u8(output, frame->pad_length)) {
            goto write_error;
        }
    }
    /* Write priority */
    if (frame->has_priority) {
        if (s_frame_priority_settings_encode(&frame->priority, output)) {
            goto write_error;
        }
    }
    /* Write data */
    if (aws_h2_frame_header_block_encode(&frame->header_block, encoder, output)) {
        goto compression_error;
    }
    /* Write padding */
    for (size_t i = 0; i < frame->pad_length; ++i) {
        if (!aws_byte_buf_write_u8(output, 0)) {
            goto write_error;
        }
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);

compression_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
}

/***********************************************************************************************************************
 * PRIORITY
 **********************************************************************************************************************/
static const size_t s_frame_priority_length = 5;

int aws_h2_frame_priority_init(struct aws_h2_frame_priority *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_PRIORITY;

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_priority_clean_up(struct aws_h2_frame_priority *frame) {
    AWS_PRECONDITION(frame);

    (void)frame;
}

int aws_h2_frame_priority_encode(
    struct aws_h2_frame_priority *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    (void)encoder;

    const size_t output_init_len = output->len;

    /* Write the header data */
    if (s_frame_header_encode(&frame->header, s_frame_priority_length, 0, output)) {
        goto write_error;
    }

    /* Write the priority settings */
    if (s_frame_priority_settings_encode(&frame->priority, output)) {
        goto write_error;
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
}

/***********************************************************************************************************************
 * RST_STREAM
 **********************************************************************************************************************/
static const size_t s_frame_rst_stream_length = 4;

int aws_h2_frame_rst_stream_init(struct aws_h2_frame_rst_stream *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_RST_STREAM;

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_rst_stream_clean_up(struct aws_h2_frame_rst_stream *frame) {
    AWS_PRECONDITION(frame);

    (void)frame;
}

int aws_h2_frame_rst_stream_encode(
    struct aws_h2_frame_rst_stream *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    (void)encoder;

    const size_t output_init_len = output->len;

    /* Write the header data */
    if (s_frame_header_encode(&frame->header, s_frame_rst_stream_length, 0, output)) {
        goto write_error;
    }

    /* Write the error_code */
    if (!aws_byte_buf_write_be32(output, frame->error_code)) {
        goto write_error;
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
}

/***********************************************************************************************************************
 * SETTINGS
 **********************************************************************************************************************/
int aws_h2_frame_settings_init(struct aws_h2_frame_settings *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_SETTINGS;

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_settings_clean_up(struct aws_h2_frame_settings *frame) {
    AWS_PRECONDITION(frame);

    (void)frame;
}

int aws_h2_frame_settings_encode(
    struct aws_h2_frame_settings *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);
    AWS_PRECONDITION(!frame->settings_count || frame->settings_array);

    (void)encoder;

    const size_t output_init_len = output->len;

    /* Write the header data */
    uint8_t flags = 0;
    if (frame->ack) {
        if (frame->settings_count != 0) {
            aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
            goto write_error;
        }
        flags |= AWS_H2_FRAME_F_ACK;
    }

    if (s_frame_header_encode(&frame->header, frame->settings_count * 6, flags, output)) {
        goto write_error;
    }

    /* Write the payload */
    for (size_t i = 0; i < frame->settings_count; ++i) {
        if (!aws_byte_buf_write_be16(output, frame->settings_array[i].id) ||
            !aws_byte_buf_write_be32(output, frame->settings_array[i].value)) {

            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto write_error;
        }
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return AWS_OP_ERR;
}

/***********************************************************************************************************************
 * PUSH_PROMISE
 **********************************************************************************************************************/
int aws_h2_frame_push_promise_init(struct aws_h2_frame_push_promise *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_PUSH_PROMISE;

    return aws_h2_frame_header_block_init(&frame->header_block, allocator);
}
void aws_h2_frame_push_promise_clean_up(struct aws_h2_frame_push_promise *frame) {
    AWS_PRECONDITION(frame);

    aws_h2_frame_header_block_clean_up(&frame->header_block);
}

int aws_h2_frame_push_promise_encode(
    struct aws_h2_frame_push_promise *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    if (frame->promised_stream_id & s_u32_top_bit_mask) {
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    const size_t output_init_len = output->len;

    /* Write header */
    uint8_t flags = 0;
    size_t length = 0;
    if (aws_h2_frame_header_block_get_encoded_length(&frame->header_block, encoder, &length)) {
        goto compression_error;
    }
    length += 4; /* Account for promised stream id */
    if (frame->pad_length) {
        flags |= AWS_H2_FRAME_F_PADDED;
        length += frame->pad_length + 1;
    }
    if (frame->end_headers) {
        flags |= AWS_H2_FRAME_F_END_HEADERS;
    }
    if (s_frame_header_encode(&frame->header, length, flags, output)) {
        goto write_error;
    }

    /* Write pad length */
    if (frame->pad_length) {
        aws_byte_buf_write_u8(output, frame->pad_length);
    }

    /* Write new stream id */
    const uint32_t stream_id_bytes = frame->promised_stream_id & s_31_bit_mask;
    aws_byte_buf_write_be32(output, stream_id_bytes);

    /* Write header block fragment */
    if (aws_h2_frame_header_block_encode(&frame->header_block, encoder, output)) {
        goto compression_error;
    }

    /* Write padding */
    for (size_t i = 0; i < frame->pad_length; ++i) {
        if (!aws_byte_buf_write_u8(output, 0)) {
            goto write_error;
        }
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

compression_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
}

/***********************************************************************************************************************
 * PING
 **********************************************************************************************************************/
int aws_h2_frame_ping_init(struct aws_h2_frame_ping *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_PING;

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_ping_clean_up(struct aws_h2_frame_ping *frame) {
    AWS_PRECONDITION(frame);

    (void)frame;
}

int aws_h2_frame_ping_encode(
    struct aws_h2_frame_ping *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    (void)encoder;

    if (frame->header.stream_id != 0) {
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    const size_t output_init_len = output->len;

    /* Write the header data */
    uint8_t flags = 0;
    if (frame->ack) {
        flags |= AWS_H2_FRAME_F_ACK;
    }

    if (s_frame_header_encode(&frame->header, AWS_H2_PING_DATA_SIZE, flags, output)) {
        goto write_error;
    }

    /* Write the opaque_data */
    if (!aws_byte_buf_write(output, frame->opaque_data, AWS_H2_PING_DATA_SIZE)) {
        goto write_error;
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);
}

/***********************************************************************************************************************
 * GOAWAY
 **********************************************************************************************************************/
int aws_h2_frame_goaway_init(struct aws_h2_frame_goaway *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_GOAWAY;

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_goaway_clean_up(struct aws_h2_frame_goaway *frame) {
    AWS_PRECONDITION(frame);

    (void)frame;
}

int aws_h2_frame_goaway_encode(
    struct aws_h2_frame_goaway *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    (void)encoder;

    if (frame->header.stream_id != 0) {
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    const size_t output_init_len = output->len;

    /* Write the header data */
    size_t length = 8 + frame->debug_data.len;
    if (s_frame_header_encode(&frame->header, length, 0, output)) {
        goto write_error;
    }

    /* Write the payload */
    if (!aws_byte_buf_write_be32(output, frame->last_stream_id & s_31_bit_mask)) {
        goto write_error;
    }
    if (!aws_byte_buf_write_be32(output, frame->error_code)) {
        goto write_error;
    }
    if (!aws_byte_buf_write_from_whole_cursor(output, frame->debug_data)) {
        goto write_error;
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
}

/***********************************************************************************************************************
 * WINDOW_UPDATE
 **********************************************************************************************************************/
static const size_t s_frame_window_update_length = 4;

int aws_h2_frame_window_update_init(struct aws_h2_frame_window_update *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_WINDOW_UPDATE;

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_window_update_clean_up(struct aws_h2_frame_window_update *frame) {
    AWS_PRECONDITION(frame);

    (void)frame;
}

int aws_h2_frame_window_update_encode(
    struct aws_h2_frame_window_update *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    (void)encoder;

    const size_t output_init_len = output->len;

    if (frame->window_size_increment & s_u32_top_bit_mask) {
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    /* Write the header data */
    if (s_frame_header_encode(&frame->header, s_frame_window_update_length, 0, output)) {
        goto write_error;
    }

    /* Write the error_code */
    if (!aws_byte_buf_write_be32(output, frame->window_size_increment)) {
        goto write_error;
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
}

/***********************************************************************************************************************
 * CONTINUATION
 **********************************************************************************************************************/
int aws_h2_frame_continuation_init(struct aws_h2_frame_continuation *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_CONTINUATION;

    return aws_h2_frame_header_block_init(&frame->header_block, allocator);
}
void aws_h2_frame_continuation_clean_up(struct aws_h2_frame_continuation *frame) {
    AWS_PRECONDITION(frame);

    aws_h2_frame_header_block_clean_up(&frame->header_block);
}

int aws_h2_frame_continuation_encode(
    struct aws_h2_frame_continuation *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    const size_t output_init_len = output->len;

    /* Calculate length & flags */
    size_t length = 0;
    if (aws_h2_frame_header_block_get_encoded_length(&frame->header_block, encoder, &length)) {
        goto compression_error;
    }

    uint8_t flags = 0;
    if (frame->end_headers) {
        flags |= AWS_H2_FRAME_F_END_HEADERS;
    }

    /* Write the header data */
    if (s_frame_header_encode(&frame->header, length, flags, output)) {
        goto write_error;
    }

    /* Write the header block */
    if (aws_h2_frame_header_block_encode(&frame->header_block, encoder, output)) {
        goto compression_error;
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);

compression_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
}

int aws_h2_encode_frame(
    struct aws_h2_frame_encoder *encoder,
    struct aws_h2_frame_header *frame_header,
    struct aws_byte_buf *output) {

    switch (frame_header->type) {
        case AWS_H2_FRAME_T_DATA:
            return aws_h2_frame_data_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_data, header), encoder, output);

        case AWS_H2_FRAME_T_HEADERS:
            return aws_h2_frame_headers_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_headers, header), encoder, output);

        case AWS_H2_FRAME_T_PRIORITY:
            return aws_h2_frame_priority_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_priority, header), encoder, output);

        case AWS_H2_FRAME_T_RST_STREAM:
            return aws_h2_frame_rst_stream_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_rst_stream, header), encoder, output);

        case AWS_H2_FRAME_T_SETTINGS:
            return aws_h2_frame_settings_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_settings, header), encoder, output);

        case AWS_H2_FRAME_T_PUSH_PROMISE:
            return aws_h2_frame_push_promise_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_push_promise, header), encoder, output);

        case AWS_H2_FRAME_T_PING:
            return aws_h2_frame_ping_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_ping, header), encoder, output);

        case AWS_H2_FRAME_T_GOAWAY:
            return aws_h2_frame_goaway_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_goaway, header), encoder, output);

        case AWS_H2_FRAME_T_WINDOW_UPDATE:
            return aws_h2_frame_window_update_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_window_update, header), encoder, output);

        case AWS_H2_FRAME_T_CONTINUATION:
            return aws_h2_frame_continuation_encode(
                AWS_CONTAINER_OF(frame_header, struct aws_h2_frame_continuation, header), encoder, output);

        default:
            AWS_ASSERT(0);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
}
