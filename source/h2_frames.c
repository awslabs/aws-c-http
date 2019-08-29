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

#include <aws/http/request_response.h>

#include <aws/compression/huffman.h>

/* Stream ids & dependencies should only write the bottom 31 bits */
static const uint32_t s_31_bit_mask = UINT32_MAX >> 1;
static const uint32_t s_u32_top_bit_mask = UINT32_MAX << 31;

static const uint8_t s_indexed_header_field_mask = 1 << 7;
static const uint8_t s_literal_save_field_mask = 1 << 6;
static const uint8_t s_dynamic_table_size_update_mask = 1 << 5;
static const uint8_t s_literal_no_forward_save_mask = 1 << 4;

/* RFC-7540 6.5.2 */
static const size_t s_hpack_dynamic_table_initial_size = 4096;
/* TBD */
static const size_t s_hpack_dynamic_table_max_size = 4096;

/***********************************************************************************************************************
 * Priority
 **********************************************************************************************************************/
static size_t s_frame_priority_settings_size = 5;

static int s_frame_priority_settings_encode(
    const struct aws_h2_frame_priority_settings *priority,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(priority);
    AWS_PRECONDITION(output);
    AWS_FATAL_ASSERT((priority->stream_dependency & s_u32_top_bit_mask) == 0);

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

static int s_frame_priority_settings_decode(
    struct aws_h2_frame_priority_settings *priority,
    struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(priority);
    AWS_PRECONDITION(decoder);

    /* Read the top 4 bytes */
    uint32_t top_bytes = 0;
    if (!aws_byte_cursor_read_be32(&decoder->payload, &top_bytes)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    priority->stream_dependency = top_bytes & s_31_bit_mask;
    priority->stream_dependency_exclusive = top_bytes >> 31;

    /* Write the priority weight */
    if (!aws_byte_cursor_read_u8(&decoder->payload, &priority->weight)) {
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
        }

        if (field->hpack_behavior == AWS_H2_HEADER_BEHAVIOR_SAVE) {
            /* Save for next time */
            aws_hpack_insert_header(encoder->hpack, &field->header);
        }
    }

    return AWS_OP_SUCCESS;
}
int aws_h2_frame_header_block_decode(
    struct aws_h2_frame_header_block *header_block,
    struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(header_block);
    AWS_PRECONDITION(decoder);

    /* Don't need to call init, frames will have done that */

    struct aws_h2_frame_header_field field;

    while (decoder->payload.len) {
        AWS_ZERO_STRUCT(field);

        uint8_t first_byte = *decoder->payload.ptr;

        if (first_byte & s_indexed_header_field_mask) {
            /* Indexed header, fetch from hpack */
            field.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_SAVE;

            uint64_t index = 0;
            if (aws_hpack_decode_integer(&decoder->payload, 7, &index)) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }

            if (index > SIZE_MAX) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }

            const struct aws_http_header *header = aws_hpack_get_header(decoder->hpack, (size_t)index);
            if (!header) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }
            field.header = *header;

            if (aws_array_list_push_back(&header_block->header_fields, &field)) {
                return AWS_OP_ERR;
            }
        } else if (first_byte & s_literal_save_field_mask || (first_byte & s_dynamic_table_size_update_mask) == 0) {

            uint8_t payload_len_prefix;
            if (first_byte & s_literal_save_field_mask) {
                field.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_SAVE;
                payload_len_prefix = 6;
            } else if (first_byte & s_literal_no_forward_save_mask) {
                field.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_NO_FORWARD_SAVE;
                payload_len_prefix = 4;
            } else {
                field.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_NO_SAVE;
                payload_len_prefix = 5;
            }

            uint64_t index = 0;
            if (aws_hpack_decode_integer(&decoder->payload, payload_len_prefix, &index)) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }

            if (index > SIZE_MAX) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }

            /* Read the name */
            if (index) {
                /* Name is indexed, so just read it */
                const struct aws_http_header *header = aws_hpack_get_header(decoder->hpack, (size_t)index);
                if (!header) {
                    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
                }
                field.header.name = header->name;
            } else {
                const size_t scratch_len = decoder->header_scratch.len;
                /* New name, decode as string */
                if (aws_hpack_decode_string(decoder->hpack, &decoder->payload, &decoder->header_scratch)) {
                    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
                }
                /* Get a cursor to the string we just decoded */
                field.header.name = aws_byte_cursor_from_array(
                    decoder->header_scratch.buffer + scratch_len, decoder->header_scratch.len - scratch_len);
            }

            const size_t scratch_len = decoder->header_scratch.len;
            /* Read the value */
            if (aws_hpack_decode_string(decoder->hpack, &decoder->payload, &decoder->header_scratch)) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }
            field.header.value = aws_byte_cursor_from_array(
                decoder->header_scratch.buffer + scratch_len, decoder->header_scratch.len - scratch_len);

            /* Save if necessary */
            if (field.hpack_behavior == AWS_H2_HEADER_BEHAVIOR_SAVE) {
                if (aws_hpack_insert_header(decoder->hpack, &field.header)) {
                    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
                }
            }

            /* Save the field */
            aws_array_list_push_back(&header_block->header_fields, &field);
        } else {
            /* This header is *actually* a dynamic table size update */
            uint64_t new_size = 0;
            if (aws_hpack_decode_integer(&decoder->payload, 5, &new_size)) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }

            if (new_size > s_hpack_dynamic_table_max_size) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }

            if (aws_hpack_resize_dynamic_table(decoder->hpack, (size_t)new_size)) {
                return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
            }
        }
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

    /* Length must fit in 24 bits */
    if (length > 0x00FFFFFF) {
        return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);
    }

    /* Write length */
    uint32_t u32_len = (uint32_t)length;
    u32_len = aws_hton24(u32_len);
    if (!aws_byte_buf_write(output, (uint8_t *)&u32_len, 3)) {
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

    encoder->hpack = aws_hpack_context_new(allocator, s_hpack_dynamic_table_initial_size);
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
 * Decoder
 **********************************************************************************************************************/
int aws_h2_frame_decoder_init(struct aws_h2_frame_decoder *decoder, struct aws_allocator *allocator) {
    AWS_PRECONDITION(decoder);
    AWS_PRECONDITION(allocator);

    AWS_ZERO_STRUCT(*decoder);
    decoder->allocator = allocator;

    decoder->hpack = aws_hpack_context_new(allocator, s_hpack_dynamic_table_initial_size);
    if (!decoder->hpack) {
        goto failed_create_hpack;
    }

    if (aws_byte_buf_init(&decoder->header_scratch, allocator, 512)) {
        goto failed_init_header_scratch;
    }

    return AWS_OP_SUCCESS;

failed_init_header_scratch:
    aws_hpack_context_destroy(decoder->hpack);

failed_create_hpack:
    return AWS_OP_ERR;
}
void aws_h2_frame_decoder_clean_up(struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(decoder);

    aws_byte_buf_clean_up(&decoder->header_scratch);

    aws_hpack_context_destroy(decoder->hpack);
}

int aws_h2_frame_decoder_begin(struct aws_h2_frame_decoder *decoder, struct aws_byte_cursor *data) {

    AWS_PRECONDITION(decoder);
    AWS_PRECONDITION(data);

    const struct aws_byte_cursor data_init = *data;

    /* Reset the scratch buffer */
    decoder->header_scratch.len = 0;

    /* Read length */
    uint32_t payload_len = 0;
    uint8_t *length_ptr = ((uint8_t *)&payload_len);
    if (!aws_byte_cursor_read(data, length_ptr, 3)) {
        goto read_error;
    }
    payload_len = aws_ntoh24(payload_len);
    /* Assert top byte isn't set */
    AWS_FATAL_ASSERT((payload_len & 0xFF000000) == 0);

    /* Read type */
    if (!aws_byte_cursor_read_u8(data, &decoder->header.type)) {
        goto read_error;
    }

    /* Read flags */
    if (!aws_byte_cursor_read_u8(data, &decoder->flags)) {
        goto read_error;
    }

    /* Read stream id */
    uint32_t stream_id = 0;
    if (!aws_byte_cursor_read_be32(data, &stream_id)) {
        goto read_error;
    }
    /* Discard top bit */
    decoder->header.stream_id = stream_id & s_31_bit_mask;

    /* Capture the payload */
    decoder->payload = aws_byte_cursor_advance(data, payload_len);
    if (!decoder->payload.ptr) {
        goto read_error;
    }

    return AWS_OP_SUCCESS;

read_error:
    *data = data_init;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);
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
    size_t length = frame->data.len + frame->pad_length;

    uint8_t flags = 0;
    if (frame->end_stream) {
        flags |= AWS_H2_FRAME_F_END_STREAM;
    }
    if (frame->pad_length) {
        flags |= AWS_H2_FRAME_F_PADDED;
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
int aws_h2_frame_data_decode(struct aws_h2_frame_data *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_data_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_DATA);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    /* Initialize the frame */
    frame->header = decoder->header;

    /* Read flags */
    if (decoder->flags & AWS_H2_FRAME_F_END_STREAM) {
        frame->end_stream = true;
    }

    /* Read padding if present */
    if (decoder->flags & AWS_H2_FRAME_F_PADDED) {
        if (!aws_byte_cursor_read_u8(&decoder->payload, &frame->pad_length)) {
            goto read_error;
        }
    }
    /* Read the data */
    frame->data = aws_byte_cursor_advance(&decoder->payload, decoder->payload.len - frame->pad_length);
    if (!frame->data.ptr) {
        goto read_error;
    }

    if (decoder->payload.len != frame->pad_length) {
        goto read_error;
    }
    aws_byte_cursor_advance(&decoder->payload, frame->pad_length);

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
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
    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
}
int aws_h2_frame_headers_decode(struct aws_h2_frame_headers *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_headers_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_HEADERS);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    /* Initialize the frame */
    frame->header = decoder->header;

    /* Read flags */
    if (decoder->flags & AWS_H2_FRAME_F_END_STREAM) {
        frame->end_stream = true;
    }
    if (decoder->flags & AWS_H2_FRAME_F_END_HEADERS) {
        frame->end_headers = true;
    }

    /* Read padding if present */
    if (decoder->flags & AWS_H2_FRAME_F_PADDED) {
        if (!aws_byte_cursor_read_u8(&decoder->payload, &frame->pad_length)) {
            goto read_error;
        }

        if (frame->pad_length > decoder->payload.len) {
            goto protocol_error;
        }

        /* Remove padding from payload */
        decoder->payload.len -= frame->pad_length;
    }

    /* Check for priority settings */
    if (decoder->flags & AWS_H2_FRAME_F_PRIORITY) {
        frame->has_priority = true;
        if (s_frame_priority_settings_decode(&frame->priority, decoder)) {
            goto protocol_error;
        }
    }

    /* Read header block */
    if (aws_h2_frame_header_block_decode(&frame->header_block, decoder)) {
        goto compression_error;
    }

    /* Validate length length */
    if (decoder->payload.len != 0) {
        goto read_error;
    }

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);

protocol_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);

compression_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
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
int aws_h2_frame_priority_decode(struct aws_h2_frame_priority *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_priority_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_PRIORITY);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    if (decoder->payload.len != s_frame_priority_length) {
        goto read_error;
    }

    if (decoder->flags) {
        goto protocol_error;
    }

    /* Initialize the frame */
    frame->header = decoder->header;

    /* Decode the priority settings */
    if (s_frame_priority_settings_decode(&frame->priority, decoder)) {
        goto read_error;
    }
    AWS_FATAL_ASSERT(decoder->payload.len == 0);

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);

protocol_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
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
int aws_h2_frame_rst_stream_decode(struct aws_h2_frame_rst_stream *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_rst_stream_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_RST_STREAM);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    if (decoder->payload.len != s_frame_rst_stream_length) {
        goto read_error;
    }

    if (decoder->flags) {
        goto protocol_error;
    }

    /* Initialize the frame */
    frame->header = decoder->header;

    /* Decode the priority settings */
    uint32_t error_code = 0;
    if (!aws_byte_cursor_read_be32(&decoder->payload, &error_code)) {
        goto read_error;
    }
    frame->error_code = (enum aws_h2_error_codes)error_code;
    AWS_FATAL_ASSERT(decoder->payload.len == 0);

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);

protocol_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
}

/***********************************************************************************************************************
 * SETTINGS
 **********************************************************************************************************************/
/* Settings hash table */
static uint64_t s_hash_uint16_t(const void *item) {
    return (uint16_t)(size_t)item;
}
static bool s_uint16_t_eq(const void *a, const void *b) {
    return (uint16_t)(size_t)a == (uint16_t)(size_t)b;
}

int aws_h2_frame_settings_init(struct aws_h2_frame_settings *frame, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*frame);
    frame->header.type = AWS_H2_FRAME_T_SETTINGS;

    if (aws_hash_table_init(&frame->settings, allocator, 0, s_hash_uint16_t, s_uint16_t_eq, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}
void aws_h2_frame_settings_clean_up(struct aws_h2_frame_settings *frame) {
    AWS_PRECONDITION(frame);

    aws_hash_table_clean_up(&frame->settings);
}

int aws_h2_frame_settings_set(struct aws_h2_frame_settings *frame, uint16_t identifier, uint32_t value) {
    return aws_hash_table_put(&frame->settings, (void *)(size_t)identifier, (void *)(size_t)value, NULL);
}
int aws_h2_frame_settings_remove(struct aws_h2_frame_settings *frame, uint16_t identifier) {
    return aws_hash_table_remove(&frame->settings, (void *)(size_t)identifier, NULL, NULL);
}

int aws_h2_frame_settings_encode(
    struct aws_h2_frame_settings *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(encoder);
    AWS_PRECONDITION(output);

    (void)encoder;

    const size_t output_init_len = output->len;

    /* Write the header data */
    size_t num_settings = aws_hash_table_get_entry_count(&frame->settings);

    uint8_t flags = 0;
    if (frame->ack) {
        if (num_settings != 0) {
            aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
            goto write_error;
        }
        flags |= AWS_H2_FRAME_F_ACK;
    }

    if (s_frame_header_encode(&frame->header, num_settings * 6, flags, output)) {
        goto write_error;
    }

    /* Write the payload */
    struct aws_hash_iter i = aws_hash_iter_begin(&frame->settings);
    while (!aws_hash_iter_done(&i)) {

        uint8_t id = (uint8_t)(size_t)i.element.key;
        uint32_t value = (uint32_t)(size_t)i.element.value;

        if (!aws_byte_buf_write_be16(output, id) || !aws_byte_buf_write_be32(output, value)) {
            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto write_error;
        }

        aws_hash_iter_next(&i);
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return AWS_OP_ERR;
}
int aws_h2_frame_settings_decode(struct aws_h2_frame_settings *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_settings_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_SETTINGS);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    if (decoder->header.stream_id != 0x0) {
        return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
    }

    /* Initialize the frame */
    frame->header = decoder->header;

    if (decoder->flags & AWS_H2_FRAME_F_ACK) {
        frame->ack = true;
        if (decoder->payload.len) {
            goto read_error;
        }
    } else {
        frame->ack = false;
        if ((decoder->payload.len % 6) != 0) {
            goto read_error;
        }

        /* Read over the rest of the bytes */
        while (decoder->payload.len) {
            uint16_t id = 0;
            uint32_t value = 0;
            if (!aws_byte_cursor_read_be16(&decoder->payload, &id) ||
                !aws_byte_cursor_read_be32(&decoder->payload, &value)) {

                goto read_error;
            }

            if (aws_h2_frame_settings_set(frame, id, value)) {
                goto read_error;
            }
        }
    }

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);
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
        return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
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
    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
}
int aws_h2_frame_push_promise_decode(struct aws_h2_frame_push_promise *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_push_promise_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_PUSH_PROMISE);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    /* Initialize the frame */
    frame->header = decoder->header;

    /* Check for padding */
    if (decoder->flags & AWS_H2_FRAME_F_PADDED) {
        if (!aws_byte_cursor_read_u8(&decoder->payload, &frame->pad_length)) {
            goto read_error;
        }

        if (frame->pad_length > decoder->payload.len) {
            goto protocol_error;
        }

        /* Remove padding from payload */
        decoder->payload.len -= frame->pad_length;
    }

    /* Read new stream id */
    if (!aws_byte_cursor_read_be32(&decoder->payload, &frame->promised_stream_id)) {
        goto read_error;
    }
    if (frame->promised_stream_id & s_u32_top_bit_mask) {
        goto protocol_error;
    }

    /* Read header block */
    if (aws_h2_frame_header_block_decode(&frame->header_block, decoder)) {
        goto compression_error;
    }

    /* Check length */
    if (decoder->payload.len != 0) {
        goto read_error;
    }

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);

protocol_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);

compression_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
}

/***********************************************************************************************************************
 * PING
 **********************************************************************************************************************/
static const size_t s_frame_ping_length = 8;

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
        return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
    }
    if (frame->opaque_data.len != s_frame_ping_length) {
        return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);
    }

    const size_t output_init_len = output->len;

    /* Write the header data */
    uint8_t flags = 0;
    if (frame->ack) {
        flags |= AWS_H2_FRAME_F_ACK;
    }

    if (s_frame_header_encode(&frame->header, s_frame_ping_length, flags, output)) {
        goto write_error;
    }

    /* Write the error_code */
    if (!aws_byte_buf_write_from_whole_cursor(output, frame->opaque_data)) {
        goto write_error;
    }

    return AWS_OP_SUCCESS;

write_error:
    output->len = output_init_len;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);
}
int aws_h2_frame_ping_decode(struct aws_h2_frame_ping *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_ping_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_PING);

    struct aws_h2_frame_decoder decoder_init = *decoder;

    if (decoder->payload.len != s_frame_ping_length) {
        goto read_error;
    }
    if (decoder->header.stream_id != 0) {
        goto protocol_error;
    }

    /* Initialize the frame */
    frame->header = decoder->header;

    if (decoder->flags & AWS_H2_FRAME_F_ACK) {
        frame->ack = true;
    }

    /* Read the opaque data */
    frame->opaque_data = aws_byte_cursor_advance(&decoder->payload, s_frame_ping_length);
    AWS_ASSERT(frame->opaque_data.ptr && frame->opaque_data.len == s_frame_ping_length);

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);

protocol_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
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
        return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
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
int aws_h2_frame_goaway_decode(struct aws_h2_frame_goaway *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_goaway_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_GOAWAY);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    if (decoder->flags) {
        goto protocol_error;
    }
    if (decoder->header.stream_id != 0) {
        goto protocol_error;
    }

    if (decoder->payload.len < 8) {
        goto read_error;
    }

    /* Initialize the frame */
    frame->header = decoder->header;

    /* Read last_stream_id */
    uint32_t first_byte = 0;
    if (!aws_byte_cursor_read_be32(&decoder->payload, &first_byte)) {
        goto read_error;
    }
    /* Top bit is reserved */
    if (first_byte & s_u32_top_bit_mask) {
        goto protocol_error;
    }
    frame->last_stream_id = first_byte & s_31_bit_mask;

    /* Read error_code */
    uint32_t error_code = 0;
    if (!aws_byte_cursor_read_be32(&decoder->payload, &error_code)) {
        goto read_error;
    }
    frame->error_code = (enum aws_h2_error_codes)error_code;

    /* Read debug data */
    frame->debug_data = aws_byte_cursor_advance(&decoder->payload, decoder->payload.len);

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_FRAME_SIZE_ERROR);

protocol_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
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
        return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
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
int aws_h2_frame_window_update_decode(struct aws_h2_frame_window_update *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_window_update_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_WINDOW_UPDATE);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    if (decoder->flags) {
        goto protocol_error;
    }
    if (decoder->payload.len != s_frame_window_update_length) {
        goto read_error;
    }

    /* Initialize the frame */
    frame->header = decoder->header;

    /* Read the window increment */
    if (!aws_byte_cursor_read_be32(&decoder->payload, &frame->window_size_increment)) {
        goto read_error;
    }
    if (frame->window_size_increment & s_u32_top_bit_mask) {
        goto protocol_error;
    }

    return AWS_OP_SUCCESS;

read_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

protocol_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_PROTOCOL_ERROR);
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
    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
}

int aws_h2_frame_continuation_decode(struct aws_h2_frame_continuation *frame, struct aws_h2_frame_decoder *decoder) {
    AWS_PRECONDITION(frame);
    AWS_PRECONDITION(decoder);

    if (aws_h2_frame_continuation_init(frame, decoder->allocator)) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(decoder->header.type == AWS_H2_FRAME_T_CONTINUATION);

    const struct aws_h2_frame_decoder decoder_init = *decoder;

    /* Initialize the frame */
    frame->header = decoder->header;

    /* Read flags */
    if (decoder->flags & AWS_H2_FRAME_F_END_HEADERS) {
        frame->end_headers = true;
    }

    /* Read the header block */
    if (aws_h2_frame_header_block_decode(&frame->header_block, decoder)) {
        goto compression_error;
    }

    return AWS_OP_SUCCESS;

compression_error:
    *decoder = decoder_init;
    return aws_raise_error(AWS_H2_ERR_COMPRESSION_ERROR);
}
