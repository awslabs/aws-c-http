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
 *        Actually, maybe do NOT raise H2-specific errors, because those are for *receiving* bad data,
 *        and errors from the encoder are user error???
 *        Also, if encoder raises error corresponding to AWS_H2_ERR, should
 *        we send that code in the GOAWAY, or always treat encoder errors as AWS_H2_ERR_INTERNAL?
 *        Like, you're only supposed to inform peer of errors that were their fault, right? */

/* #TODO: when is the right time to validate every possible input?
 *        while encoding? while making new frame? in actual user-facing API? */

/* #TODO: use add_checked and mul_checked */

const struct aws_byte_cursor aws_h2_connection_preface_client_string =
    AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

/* Stream ids & dependencies should only write the bottom 31 bits */
static const uint32_t s_31_bit_mask = UINT32_MAX >> 1;
static const uint32_t s_u32_top_bit_mask = UINT32_MAX << 31;

static const uint8_t s_indexed_header_field_mask = 1 << 7;
static const uint8_t s_literal_save_field_mask = 1 << 6;
static const uint8_t s_literal_no_forward_save_mask = 1 << 4;

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

#if 0
/***********************************************************************************************************************
 * Header Block
 **********************************************************************************************************************/
int aws_h2_frame_header_block_init(struct aws_h2_frame_header_block *header_block, struct aws_allocator *allocator) {
    AWS_PRECONDITION(header_block);
    AWS_PRECONDITION(allocator);

    return aws_array_list_init_dynamic(&header_block->header_fields, allocator, 0, sizeof(struct aws_http_header));
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

        const struct aws_http_header *field = NULL;
        aws_array_list_get_at_ptr(&header_block->header_fields, (void **)&field, i);
        AWS_ASSERT(field);

        bool found_value = false;
        const size_t index = aws_hpack_find_index(encoder->hpack, field, &found_value);

        uint8_t prefix_size;
        /* If a value was found, this is an indexed header */
        if (found_value) {
            prefix_size = 7;
        } else {
            /* If not indexed, determine the appropriate flags and prefixes */
            switch (field->compression) {
                case AWS_HTTP_HEADER_COMPRESSION_USE_CACHE:
                    prefix_size = 6;
                    break;
                case AWS_HTTP_HEADER_COMPRESSION_NO_CACHE:
                    prefix_size = 4;
                    break;
                case AWS_HTTP_HEADER_COMPRESSION_NO_FORWARD_CACHE:
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
                *length += aws_hpack_get_encoded_length_string(encoder->hpack, field->name, encoder->use_huffman);
            }

            /* Value must be written if the field isn't pure indexed */
            *length += aws_hpack_get_encoded_length_string(encoder->hpack, field->value, encoder->use_huffman);
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

        const struct aws_http_header *field = NULL;
        aws_array_list_get_at_ptr(&header_block->header_fields, (void **)&field, i);
        AWS_ASSERT(field);

        /* #TODO don't use index unless header is USE_CACHE */
        /* #TODO need to update hpack as we go or we'll be using wrong indices */
        bool found_value = true;
        const size_t index = aws_hpack_find_index(encoder->hpack, field, &found_value);

        uint8_t mask;
        uint8_t prefix_size;
        /* If a value was found, this is an indexed header */
        if (found_value) {
            mask = s_indexed_header_field_mask;
            prefix_size = 7;
        } else {
            /* If not indexed, determine the appropriate flags and prefixes */
            switch (field->compression) {
                case AWS_HTTP_HEADER_COMPRESSION_USE_CACHE:
                    mask = s_literal_save_field_mask;
                    prefix_size = 6;
                    break;
                case AWS_HTTP_HEADER_COMPRESSION_NO_CACHE:
                    mask = 0; /* No bits set, just 4 bit prefix */
                    prefix_size = 4;
                    break;
                case AWS_HTTP_HEADER_COMPRESSION_NO_FORWARD_CACHE:
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
                scratch = field->name;
                if (aws_hpack_encode_string(encoder->hpack, &scratch, encoder->use_huffman, output)) {
                    return AWS_OP_ERR;
                }
                AWS_ASSERT(scratch.len == 0);
            }

            /* Value must be written if the field isn't pure indexed */
            scratch = field->value;
            if (aws_hpack_encode_string(encoder->hpack, &scratch, encoder->use_huffman, output)) {
                return AWS_OP_ERR;
            }
            AWS_ASSERT(scratch.len == 0);

            if (field->compression == AWS_HTTP_HEADER_COMPRESSION_USE_CACHE) {
                /* Save for next time */
                aws_hpack_insert_header(encoder->hpack, field);
            }
        }

        const size_t encoded_bytes = output->len - before_len;
        AWS_LOGF(AWS_LL_TRACE, AWS_LS_HTTP_FRAMES, "Encoded header %zu as %zu bytes", i, encoded_bytes);
    }

    return AWS_OP_SUCCESS;
}
#endif // 0
/***********************************************************************************************************************
 * Common Frame Prefix
 **********************************************************************************************************************/
static const size_t s_frame_prefix_length = 24;

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
    struct aws_h2_frame *frame_base,
    size_t length,
    uint8_t flags,
    struct aws_byte_buf *output) {
    AWS_PRECONDITION(frame_base);
    AWS_PRECONDITION(output);
    AWS_PRECONDITION(!(frame_base->stream_id & s_u32_top_bit_mask), "Invalid stream ID");

    AWS_LOGF(
        AWS_LL_TRACE,
        AWS_LS_HTTP_FRAMES,
        "Beginning encode of frame %s: stream: %" PRIu32 " payload length: %zu flags: %" PRIu8,
        aws_h2_frame_type_to_str(frame_base->type),
        frame_base->stream_id,
        length,
        flags);

    /* Length must fit in 24 bits */
    /* #TODO Check against SETTINGS_MAX_FRAME_SIZE */
    if (length > AWS_H2_PAYLOAD_MAX) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Write length */
    if (!aws_byte_buf_write_be24(output, (uint32_t)length)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write type */
    if (!aws_byte_buf_write_u8(output, frame_base->type)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write flags */
    if (!aws_byte_buf_write_u8(output, flags)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    /* Write stream id (with reserved first bit) */
    if (!aws_byte_buf_write_be32(output, frame_base->stream_id & s_31_bit_mask)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    return AWS_OP_SUCCESS;
}
#if 0
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
    frame->base.type = AWS_H2_FRAME_T_DATA;

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

    /* Write the frame prefix */
    if (s_frame_prefix_encode(&frame->base, length, flags, output)) {
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
    frame->base.type = AWS_H2_FRAME_T_HEADERS;

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

    /* Write the frame prefix */
    if (s_frame_prefix_encode(&frame->base, length, flags, output)) {
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
#endif // 0
/***********************************************************************************************************************
 * PRIORITY
 **********************************************************************************************************************/
DEFINE_FRAME_VTABLE(priority);
static const size_t s_frame_priority_length = 5;

struct aws_h2_frame *aws_h2_frame_new_priority(
    struct aws_allocator *allocator,
    uint32_t stream_id,
    const struct aws_h2_frame_priority_settings *priority) {

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
    if (total_len < space_available) {
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    if (s_frame_prefix_encode(&frame->base, s_frame_priority_length, 0, output)) {
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
    enum aws_h2_error_codes error_code) {

    struct aws_h2_frame_rst_stream *frame = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_frame_rst_stream));
    if (!frame) {
        return NULL;
    }

    s_init_frame_base(&frame->base, allocator, AWS_H2_FRAME_T_RST_STREAM, &s_frame_rst_stream_vtable, stream_id);
    frame->error_code = error_code;

    return AWS_OP_SUCCESS;
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
    if (total_len < space_available) {
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    if (s_frame_prefix_encode(&frame->base, s_frame_rst_stream_length, 0, output)) {
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

    AWS_PRECONDITION(!ack || num_settings == 0, "Settings ACK must be empty");
    AWS_PRECONDITION(settings_array || num_settings == 0);

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
    const size_t total_len = s_frame_prefix_length + payload_len;
    const size_t space_available = output->capacity - output->len;

    /* If we can't encode the whole frame at once, try again later */
    if (total_len < space_available) {
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    uint8_t flags = 0;
    if (frame->ack) {
        flags |= AWS_H2_FRAME_F_ACK;
    }

    if (s_frame_prefix_encode(&frame->base, payload_len, flags, output)) {
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

#if 0
/***********************************************************************************************************************
 * PUSH_PROMISE
 **********************************************************************************************************************/
int aws_h2_frame_push_promise_init(struct aws_h2_frame_push_promise *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->base.type = AWS_H2_FRAME_T_PUSH_PROMISE;

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
    if (s_frame_prefix_encode(&frame->base, length, flags, output)) {
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
#endif // 0
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
    if (total_len < space_available) {
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    uint8_t flags = 0;
    if (frame->ack) {
        flags |= AWS_H2_FRAME_F_ACK;
    }

    if (s_frame_prefix_encode(&frame->base, AWS_H2_PING_DATA_SIZE, flags, output)) {
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
    enum aws_h2_error_codes error_code,
    struct aws_byte_cursor debug_data) {

    struct aws_h2_frame_goaway *frame = aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_frame_goaway));
    if (!frame) {
        return NULL;
    }

    s_init_frame_base(&frame->base, allocator, AWS_H2_FRAME_T_GOAWAY, &s_frame_goaway_vtable, 0);
    frame->last_stream_id = last_stream_id;
    frame->error_code = error_code, frame->debug_data = debug_data;

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

    /* # TODO: handle max payload len. simply truncate debug data?  */
    const size_t payload_len = 8 + frame->debug_data.len;
    const size_t total_len = s_frame_prefix_length + payload_len;
    const size_t space_available = output->capacity - output->len;

    /* If we can't encode the whole frame at once, try again later */
    if (total_len < space_available) {
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    if (s_frame_prefix_encode(&frame->base, payload_len, 0, output)) {
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
    if (total_len < space_available) {
        *complete = false;
        return AWS_OP_SUCCESS;
    }

    /* Write the frame prefix */
    if (s_frame_prefix_encode(&frame->base, s_frame_window_update_length, 0, output)) {
        return AWS_OP_ERR;
    }

    /* Write the error_code */
    if (!aws_byte_buf_write_be32(output, frame->window_size_increment)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    *complete = true;
    return AWS_OP_SUCCESS;
}

#if 0
/***********************************************************************************************************************
 * CONTINUATION
 **********************************************************************************************************************/
int aws_h2_frame_continuation_init(struct aws_h2_frame_continuation *frame, struct aws_allocator *allocator) {
    (void)allocator;

    AWS_ZERO_STRUCT(*frame);
    frame->base.type = AWS_H2_FRAME_T_CONTINUATION;

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

    /* Write the frame prefix */
    if (s_frame_prefix_encode(&frame->base, length, flags, output)) {
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
#endif
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
    AWS_PRECONDITION(!encoder->has_errored && "Cannot encode after error");
    AWS_PRECONDITION(!encoder->current_frame || (encoder->current_frame == frame) && "Must resume current frame");

    *frame_complete = false;

    if (frame->vtable->encode(frame, encoder, output, frame_complete)) {
        encoder->has_errored = true;
        return AWS_OP_ERR;
    }

    encoder->current_frame = *frame_complete ? NULL : frame;
    return AWS_OP_SUCCESS;
}
