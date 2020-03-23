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
#include <aws/testing/aws_test_harness.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/logging.h>

#include <aws/http/private/h2_decoder.h>
#include <aws/http/private/h2_frames.h>
#include <aws/http/private/hpack.h>

#include <aws/io/stream.h>

#include <inttypes.h>

static const uint32_t FRAME_PREFIX_SIZE = 3 + 1 + 1 + 4;
static const uint32_t MAX_PAYLOAD_SIZE = 16384;

static struct aws_http_headers *s_generate_headers(struct aws_allocator *allocator, struct aws_byte_cursor *input) {

    struct aws_http_headers *headers = aws_http_headers_new(allocator);

    /* Requires 4 bytes: type, size, and then 1 each for name & value */
    while (input->len >= 4) {
        struct aws_http_header header;
        AWS_ZERO_STRUCT(header);

        uint8_t type = 0;
        aws_byte_cursor_read_u8(input, &type);
        switch (type % 3) {
            case 0:
                header.compression = AWS_HTTP_HEADER_COMPRESSION_USE_CACHE;
                break;
            case 1:
                header.compression = AWS_HTTP_HEADER_COMPRESSION_NO_CACHE;
                break;
            case 2:
                header.compression = AWS_HTTP_HEADER_COMPRESSION_NO_FORWARD_CACHE;
                break;
        }

        uint8_t lengths = 0;
        aws_byte_cursor_read_u8(input, &lengths);

        /* Pull a byte, split it in half, and use the top for name length, and bottom for value length */
        uint8_t name_len = lengths >> 4;
        uint8_t value_len = lengths & (UINT8_MAX >> 4);

        /* Handle the 0 length cases */
        if ((name_len == 0 && value_len == 0) || (name_len + value_len < 2)) {
            continue;
        } else if (name_len == 0) {
            name_len = value_len / 2;
            value_len -= name_len;
        } else if (value_len == 0) {
            value_len = name_len / 2;
            name_len -= value_len;
        }

        /* If there's less than enough bytes left, just split the data in half */
        if (input->len < name_len + value_len) {
            name_len = input->len / 2;
            value_len = input->len - name_len;
        }
        header.name = aws_byte_cursor_advance(input, name_len);
        header.value = aws_byte_cursor_advance(input, value_len);

        aws_http_headers_add_header(headers, &header);
    }

    return headers;
}

static uint32_t s_generate_stream_id(struct aws_byte_cursor *input) {
    uint32_t stream_id = 0;
    aws_byte_cursor_read_be32(input, &stream_id);
    return aws_min_u32(AWS_H2_STREAM_ID_MAX, aws_max_u32(1, stream_id));
}

/* Server-initiated stream-IDs must be even */
static uint32_t s_generate_even_stream_id(struct aws_byte_cursor *input) {
    uint32_t stream_id = 0;
    aws_byte_cursor_read_be32(input, &stream_id);
    stream_id = aws_min_u32(AWS_H2_STREAM_ID_MAX, aws_max_u32(2, stream_id));

    if (stream_id % 2 != 0) {
        stream_id -= 1;
    }

    return stream_id;
}

static struct aws_h2_frame_priority_settings s_generate_priority(struct aws_byte_cursor *input) {
    struct aws_h2_frame_priority_settings priority;
    priority.stream_dependency = s_generate_stream_id(input);

    uint8_t exclusive = 0;
    aws_byte_cursor_read_u8(input, &exclusive);
    priority.stream_dependency_exclusive = (bool)exclusive;

    aws_byte_cursor_read_u8(input, &priority.weight);

    return priority;
}

AWS_EXTERN_C_BEGIN

/**
 * This test generates valid frames from the random input.
 * It feeds these frames through the encoder and ensures that they're output without error.
 * Then it feeds the encoder's output to the decoder and ensures that it does not report an error.
 * It does not currently investigate the outputs to see if they line up with they inputs,
 * it just checks for errors from the encoder & decoder.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Setup allocator and parameters */
    struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_BYTES, 0);
    struct aws_byte_cursor input = aws_byte_cursor_from_array(data, size);

    /* Enable logging */
    struct aws_logger logger;
    struct aws_logger_standard_options log_options = {
        .level = AWS_LL_TRACE,
        .file = stdout,
    };
    aws_logger_init_standard(&logger, allocator, &log_options);
    aws_logger_set(&logger);

    /* Init HTTP (s2n init is weird, so don't do this under the tracer) */
    aws_http_library_init(aws_default_allocator());

    /* Create the encoder */
    struct aws_h2_frame_encoder encoder;
    aws_h2_frame_encoder_init(&encoder, allocator, NULL /*logging_id*/);

    /* Create the decoder */
    const struct aws_h2_decoder_vtable decoder_vtable = {0};
    struct aws_h2_decoder_params decoder_params = {
        .alloc = allocator,
        .vtable = &decoder_vtable,
        .skip_connection_preface = true,
    };
    struct aws_h2_decoder *decoder = aws_h2_decoder_new(&decoder_params);

    /* Init the buffer */
    struct aws_byte_buf frame_data;
    aws_byte_buf_init(&frame_data, allocator, FRAME_PREFIX_SIZE + MAX_PAYLOAD_SIZE);

    /*
     * Generate the frame to decode
     */

    uint8_t frame_type = 0;
    aws_byte_cursor_read_u8(&input, &frame_type);

    /* figure out if we should use huffman encoding */
    uint8_t huffman_choice = 0;
    aws_byte_cursor_read_u8(&input, &huffman_choice);
    aws_hpack_set_huffman_mode(encoder.hpack, huffman_choice % 3);

    switch (frame_type % (AWS_H2_FRAME_T_UNKNOWN + 1)) {
        case AWS_H2_FRAME_T_DATA: {
            uint32_t stream_id = s_generate_stream_id(&input);

            uint8_t flags = 0;
            aws_byte_cursor_read_u8(&input, &flags);
            bool body_ends_stream = flags & AWS_H2_FRAME_F_END_STREAM;

            uint8_t pad_length = 0;
            aws_byte_cursor_read_u8(&input, &pad_length);

            /* Allow body to exceed available space. Data encoder should just write what it can fit */
            struct aws_input_stream *body = aws_input_stream_new_from_cursor(allocator, &input);

            bool body_complete;
            AWS_FATAL_ASSERT(
                aws_h2_encode_data_frame(
                    &encoder, stream_id, body, (bool)body_ends_stream, pad_length, &frame_data, &body_complete) ==
                AWS_OP_SUCCESS);

            struct aws_stream_status body_status;
            aws_input_stream_get_status(body, &body_status);
            AWS_FATAL_ASSERT(body_complete == body_status.is_end_of_stream)
            aws_input_stream_destroy(body);
            break;
        }
        case AWS_H2_FRAME_T_HEADERS: {
            uint32_t stream_id = s_generate_stream_id(&input);

            uint8_t flags = 0;
            aws_byte_cursor_read_u8(&input, &flags);
            bool end_stream = flags & AWS_H2_FRAME_F_END_STREAM;
            bool use_priority = flags & AWS_H2_FRAME_F_PRIORITY;

            uint8_t pad_length = 0;
            aws_byte_cursor_read_u8(&input, &pad_length);

            struct aws_h2_frame_priority_settings priority = s_generate_priority(&input);
            struct aws_h2_frame_priority_settings *priority_ptr = use_priority ? &priority : NULL;

            /* generate headers last since it uses up the rest of input */
            struct aws_http_headers *headers = s_generate_headers(allocator, &input);

            struct aws_h2_frame *frame =
                aws_h2_frame_new_headers(allocator, stream_id, headers, end_stream, pad_length, priority_ptr);
            AWS_FATAL_ASSERT(frame);

            bool frame_complete;
            AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
            AWS_FATAL_ASSERT(frame_complete == true);

            aws_h2_frame_destroy(frame);
            aws_http_headers_release(headers);
            break;
        }
        case AWS_H2_FRAME_T_PRIORITY: {
            uint32_t stream_id = s_generate_stream_id(&input);
            struct aws_h2_frame_priority_settings priority = s_generate_priority(&input);

            struct aws_h2_frame *frame = aws_h2_frame_new_priority(allocator, stream_id, &priority);
            AWS_FATAL_ASSERT(frame);

            bool frame_complete;
            AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
            AWS_FATAL_ASSERT(frame_complete == true);

            aws_h2_frame_destroy(frame);
            break;
        }
        case AWS_H2_FRAME_T_RST_STREAM: {
            uint32_t stream_id = s_generate_stream_id(&input);

            uint32_t error_code = 0;
            aws_byte_cursor_read_be32(&input, &error_code);

            struct aws_h2_frame *frame = aws_h2_frame_new_rst_stream(allocator, stream_id, error_code);
            AWS_FATAL_ASSERT(frame);

            bool frame_complete;
            AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
            AWS_FATAL_ASSERT(frame_complete == true);

            aws_h2_frame_destroy(frame);
            break;
        }
        case AWS_H2_FRAME_T_SETTINGS: {
            uint8_t flags = 0;
            aws_byte_cursor_read_u8(&input, &flags);

            bool ack = flags & AWS_H2_FRAME_F_ACK;

            size_t settings_count = 0;
            struct aws_h2_frame_setting *settings_array = NULL;

            if (!ack) {
                settings_count = aws_min_size(input.len / 6, MAX_PAYLOAD_SIZE);
                if (settings_count > 0) {
                    settings_array = aws_mem_calloc(allocator, settings_count, sizeof(struct aws_h2_frame_setting));
                    for (size_t i = 0; i < settings_count; ++i) {
                        aws_byte_cursor_read_be16(&input, &settings_array[i].id);
                        aws_byte_cursor_read_be32(&input, &settings_array[i].value);
                    }
                }
            }

            struct aws_h2_frame *frame = aws_h2_frame_new_settings(allocator, settings_array, settings_count, ack);
            AWS_FATAL_ASSERT(frame);

            bool frame_complete;
            AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
            AWS_FATAL_ASSERT(frame_complete == true);

            aws_h2_frame_destroy(frame);
            aws_mem_release(allocator, settings_array);
            break;
        }
        case AWS_H2_FRAME_T_PUSH_PROMISE: {
            uint32_t stream_id = s_generate_stream_id(&input);
            uint32_t promised_stream_id = s_generate_even_stream_id(&input);

            uint8_t pad_length = 0;
            aws_byte_cursor_read_u8(&input, &pad_length);

            /* generate headers last since it uses up the rest of input */
            struct aws_http_headers *headers = s_generate_headers(allocator, &input);

            struct aws_h2_frame *frame =
                aws_h2_frame_new_push_promise(allocator, stream_id, promised_stream_id, headers, pad_length);
            AWS_FATAL_ASSERT(frame);

            bool frame_complete;
            AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
            AWS_FATAL_ASSERT(frame_complete == true);

            aws_h2_frame_destroy(frame);
            aws_http_headers_release(headers);
            break;
        }
        case AWS_H2_FRAME_T_PING: {
            uint8_t flags;
            aws_byte_cursor_read_u8(&input, &flags);
            bool ack = flags & AWS_H2_FRAME_F_ACK;

            uint8_t opaque_data[AWS_H2_PING_DATA_SIZE] = {0};
            size_t copy_len = aws_min_size(input.len, AWS_H2_PING_DATA_SIZE);
            if (copy_len > 0) {
                struct aws_byte_cursor copy = aws_byte_cursor_advance(&input, copy_len);
                memcpy(opaque_data, copy.ptr, copy.len);
            }

            struct aws_h2_frame *frame = aws_h2_frame_new_ping(allocator, ack, opaque_data);
            AWS_FATAL_ASSERT(frame);

            bool frame_complete;
            AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
            AWS_FATAL_ASSERT(frame_complete == true);

            aws_h2_frame_destroy(frame);
            break;
        }
        case AWS_H2_FRAME_T_GOAWAY: {
            uint32_t last_stream_id = s_generate_stream_id(&input);

            uint32_t error_code = 0;
            aws_byte_cursor_read_be32(&input, &error_code);

            /* Pass debug_data that might be too large (it will get truncated if necessary) */
            struct aws_byte_cursor debug_data = aws_byte_cursor_advance(&input, input.len);

            struct aws_h2_frame *frame = aws_h2_frame_new_goaway(allocator, last_stream_id, error_code, debug_data);
            AWS_FATAL_ASSERT(frame);

            bool frame_complete;
            AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
            AWS_FATAL_ASSERT(frame_complete == true);

            aws_h2_frame_destroy(frame);
            break;
        }
        case AWS_H2_FRAME_T_WINDOW_UPDATE: {
            /* WINDOW_UPDATE's stream-id can be zero or non-zero */
            uint32_t stream_id = 0;
            aws_byte_cursor_read_be32(&input, &stream_id);
            stream_id = aws_min_u32(stream_id, AWS_H2_STREAM_ID_MAX);

            uint32_t window_size_increment = 0;
            aws_byte_cursor_read_be32(&input, &window_size_increment);
            window_size_increment = aws_min_u32(window_size_increment, AWS_H2_WINDOW_UPDATE_MAX);

            struct aws_h2_frame *frame = aws_h2_frame_new_window_update(allocator, stream_id, window_size_increment);
            AWS_FATAL_ASSERT(frame);

            bool frame_complete;
            AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
            AWS_FATAL_ASSERT(frame_complete == true);

            aws_h2_frame_destroy(frame);
            break;
        }
        case AWS_H2_FRAME_T_CONTINUATION:
            /* We don't directly create CONTINUATION frames (they occur when HEADERS or PUSH_PROMISE gets too big) */
            frame_type = AWS_H2_FRAME_T_UNKNOWN;
            /* fallthrough */
        case AWS_H2_FRAME_T_UNKNOWN: {
            /* #YOLO roll our own frame */
            uint32_t payload_length = aws_min_u32(input.len, MAX_PAYLOAD_SIZE - FRAME_PREFIX_SIZE);

            /* Write payload length */
            aws_byte_buf_write_be24(&frame_data, payload_length);

            /* Write type */
            aws_byte_buf_write_u8(&frame_data, frame_type);

            /* Write flags */
            uint8_t flags = 0;
            aws_byte_cursor_read_u8(&input, &flags);
            aws_byte_buf_write_u8(&frame_data, flags);

            /* Write stream-id */
            uint32_t stream_id = 0;
            aws_byte_cursor_read_be32(&input, &stream_id);
            aws_byte_buf_write_be32(&frame_data, stream_id);

            /* Write payload */
            aws_byte_buf_write_from_whole_cursor(&frame_data, aws_byte_cursor_advance(&input, payload_length));
            break;
        }
        default: {
            AWS_FATAL_ASSERT(false);
        }
    }

    /* Decode whatever we got */
    AWS_FATAL_ASSERT(frame_data.len > 0);
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_buf(&frame_data);
    int err = aws_h2_decode(decoder, &to_decode);
    AWS_FATAL_ASSERT(err == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(to_decode.len == 0);

    /* Clean up */
    aws_byte_buf_clean_up(&frame_data);
    aws_h2_decoder_destroy(decoder);
    aws_h2_frame_encoder_clean_up(&encoder);
    aws_logger_set(NULL);
    aws_logger_clean_up(&logger);

    atexit(aws_http_library_clean_up);

    /* Check for leaks */
    AWS_FATAL_ASSERT(aws_mem_tracer_count(allocator) == 0);
    allocator = aws_mem_tracer_destroy(allocator);

    return 0;
}

AWS_EXTERN_C_END
