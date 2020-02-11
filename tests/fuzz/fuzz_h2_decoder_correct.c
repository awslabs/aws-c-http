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

#include <inttypes.h>

static const uint32_t FRAME_HEADER_SIZE = 3 + 1 + 1 + 4;
static const uint32_t MAX_PAYLOAD_SIZE = 16384;

static struct { uint64_t headers_decoded; } fuzz_state;

static int s_on_header(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_h2_header_field_hpack_behavior hpack_behavior,
    void *userdata) {
    (void)stream_id;
    (void)header;
    (void)hpack_behavior;
    (void)userdata;

    AWS_LOGF_INFO(AWS_LS_HTTP_GENERAL, "Decoded header %" PRIu64, fuzz_state.headers_decoded++);

    return AWS_OP_SUCCESS;
}

static void s_generate_header_block(struct aws_byte_cursor *input, struct aws_h2_frame_header_block *header_block) {

    /* Requires 4 bytes: type, size, and then 1 each for name & value */
    while (input->len >= 4) {
        struct aws_h2_frame_header_field header;
        AWS_ZERO_STRUCT(header);

        uint8_t type = 0;
        aws_byte_cursor_read_u8(input, &type);
        switch (type % 3) {
            case 0:
                header.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_SAVE;
                break;
            case 1:
                header.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_NO_SAVE;
                break;
            case 2:
                header.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_NO_FORWARD_SAVE;
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
        header.header.name = aws_byte_cursor_advance(input, name_len);
        header.header.value = aws_byte_cursor_advance(input, value_len);

        aws_array_list_push_back(&header_block->header_fields, &header);
    }
}

/* Generate non-zero stream id */
static void s_generate_stream_id(struct aws_byte_cursor *input, uint32_t *stream_id) {
    aws_byte_cursor_read_be32(input, stream_id);
    /* Top bit of stream-id is ignored by decoder */
    if ((*stream_id & (UINT32_MAX >> 1)) == 0) {
        *stream_id = 1;
    }
}

AWS_EXTERN_C_BEGIN

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if (size < FRAME_HEADER_SIZE) {
        return 0;
    }

    AWS_ZERO_STRUCT(fuzz_state);

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
    aws_h2_frame_encoder_init(&encoder, allocator);

    /* Create the decoder */
    struct aws_h2_decoder_params decoder_params = {
        .alloc = allocator,
        .vtable =
            {
                .on_header = s_on_header,
            },
    };
    struct aws_h2_decoder *decoder = aws_h2_decoder_new(&decoder_params);

    /* Init the buffer */
    struct aws_byte_buf frame_data;
    aws_byte_buf_init(&frame_data, allocator, FRAME_HEADER_SIZE + MAX_PAYLOAD_SIZE);

    /* Generate the frame to decode */
    {
        uint8_t frame_type = 0;
        aws_byte_cursor_read_u8(&input, &frame_type);

        /* Hijack the top bit of the type to figure out if we should use huffman encoding */
        encoder.use_huffman = (frame_type >> 7) == 1;

        switch (frame_type % (AWS_H2_FRAME_T_UNKNOWN + 1)) {
            case AWS_H2_FRAME_T_DATA: {
                struct aws_h2_frame_data frame;
                aws_h2_frame_data_init(&frame, allocator);

                s_generate_stream_id(&input, &frame.header.stream_id);
                aws_byte_cursor_read_u8(&input, &frame.pad_length);

                uint32_t payload_len = input.len;
                if (payload_len > MAX_PAYLOAD_SIZE - frame.pad_length) {
                    payload_len = MAX_PAYLOAD_SIZE - frame.pad_length;
                }

                frame.data = aws_byte_cursor_advance(&input, payload_len);

                aws_h2_frame_data_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_data_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_HEADERS: {
                struct aws_h2_frame_headers frame;
                aws_h2_frame_headers_init(&frame, allocator);

                s_generate_stream_id(&input, &frame.header.stream_id);

                s_generate_header_block(&input, &frame.header_block);

                aws_h2_frame_headers_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_headers_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_PRIORITY: {
                struct aws_h2_frame_priority frame;
                aws_h2_frame_priority_init(&frame, allocator);

                s_generate_stream_id(&input, &frame.header.stream_id);

                uint32_t stream_dependency = 0;
                aws_byte_cursor_read_be32(&input, &stream_dependency);

                frame.priority.stream_dependency = stream_dependency & (UINT32_MAX >> 1);
                frame.priority.stream_dependency_exclusive = stream_dependency & (1ULL << 31);

                aws_byte_cursor_read_u8(&input, &frame.priority.weight);

                aws_h2_frame_priority_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_priority_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_RST_STREAM: {
                struct aws_h2_frame_rst_stream frame;
                aws_h2_frame_rst_stream_init(&frame, allocator);

                s_generate_stream_id(&input, &frame.header.stream_id);

                aws_byte_cursor_read_be32(&input, &frame.error_code);

                aws_h2_frame_rst_stream_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_rst_stream_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_SETTINGS: {
                struct aws_h2_frame_settings frame;
                aws_h2_frame_settings_init(&frame, allocator);
                frame.settings_count = input.len / 6;
                frame.settings_array =
                    aws_mem_calloc(allocator, frame.settings_count, sizeof(struct aws_h2_frame_settings));

                for (size_t i = 0; i < frame.settings_count; ++i) {
                    aws_byte_cursor_read_be16(&input, &frame.settings_array[i].id);
                    aws_byte_cursor_read_be32(&input, &frame.settings_array[i].value);
                }

                aws_h2_frame_settings_encode(&frame, &encoder, &frame_data);
                aws_mem_release(allocator, frame.settings_array);
                aws_h2_frame_settings_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_PUSH_PROMISE: {
                struct aws_h2_frame_push_promise frame;
                aws_h2_frame_push_promise_init(&frame, allocator);

                s_generate_stream_id(&input, &frame.header.stream_id);

                s_generate_header_block(&input, &frame.header_block);

                aws_h2_frame_push_promise_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_push_promise_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_PING: {
                struct aws_h2_frame_ping frame;
                aws_h2_frame_ping_init(&frame, allocator);

                if (input.len >= AWS_H2_PING_DATA_SIZE) {
                    memcpy(frame.opaque_data, input.ptr, AWS_H2_PING_DATA_SIZE);
                    aws_byte_cursor_advance(&input, AWS_H2_PING_DATA_SIZE);
                    frame.ack = frame.opaque_data[0] != 0;
                } else if (input.len >= 1) {
                    frame.ack = *input.ptr != 0;
                }

                aws_h2_frame_ping_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_ping_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_GOAWAY: {
                struct aws_h2_frame_goaway frame;
                aws_h2_frame_goaway_init(&frame, allocator);

                aws_byte_cursor_read_be32(&input, &frame.last_stream_id);
                aws_byte_cursor_read_be32(&input, &frame.error_code);

                uint32_t debug_data_size = input.len;
                if (debug_data_size > MAX_PAYLOAD_SIZE - 8) {
                    debug_data_size = MAX_PAYLOAD_SIZE - 8;
                }
                frame.debug_data = aws_byte_cursor_advance(&input, debug_data_size);

                aws_h2_frame_goaway_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_goaway_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_WINDOW_UPDATE: {
                struct aws_h2_frame_window_update frame;
                aws_h2_frame_window_update_init(&frame, allocator);

                /* WINDOW_UPDATE's stream-id can be zero or non-zero */
                aws_byte_cursor_read_be32(&input, &frame.header.stream_id);

                aws_byte_cursor_read_be32(&input, &frame.window_size_increment);

                aws_h2_frame_window_update_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_window_update_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_CONTINUATION: {
                struct aws_h2_frame_continuation frame;
                aws_h2_frame_continuation_init(&frame, allocator);

                s_generate_stream_id(&input, &frame.header.stream_id);

                s_generate_header_block(&input, &frame.header_block);

                aws_h2_frame_continuation_encode(&frame, &encoder, &frame_data);
                aws_h2_frame_continuation_clean_up(&frame);
                break;
            }
            case AWS_H2_FRAME_T_UNKNOWN: {
                /* #YOLO roll our own frame */
                uint32_t payload_length = input.len - (FRAME_HEADER_SIZE - 1);
                if (payload_length > MAX_PAYLOAD_SIZE) {
                    payload_length = MAX_PAYLOAD_SIZE;
                }

                /* Write payload length */
                aws_byte_buf_write_be24(&frame_data, payload_length);

                /* Write type */
                aws_byte_buf_write_u8(&frame_data, frame_type);

                /* Write flags & stream id */
                aws_byte_buf_write_from_whole_cursor(&frame_data, aws_byte_cursor_advance(&input, 5));

                /* Write payload */
                aws_byte_buf_write_from_whole_cursor(&frame_data, aws_byte_cursor_advance(&input, payload_length));
                break;
            }
            default: {
                AWS_FATAL_ASSERT(false);
            }
        }
    }

    /* Decode whatever we got */
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
    ASSERT_UINT_EQUALS(0, aws_mem_tracer_count(allocator));
    allocator = aws_mem_tracer_destroy(allocator);

    return 0;
}

AWS_EXTERN_C_END
