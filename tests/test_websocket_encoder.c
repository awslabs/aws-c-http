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

#include <aws/io/logging.h>
#include <aws/testing/aws_test_harness.h>

#define ENCODER_TEST_CASE(NAME)                                                                                        \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct encoder_tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;

    struct aws_websocket_encoder encoder;

    /* payload to encode */
    struct aws_byte_cursor payload;
    size_t on_payload_count;
    size_t fail_on_nth_payload;
    bool never_say_payload_is_done;

    struct aws_byte_buf out_buf;
};

static int s_on_payload(struct aws_byte_buf *out_buf, bool *out_done, void *user_data) {
    struct encoder_tester *tester = user_data;

    tester->on_payload_count++;
    if (tester->fail_on_nth_payload == tester->on_payload_count) {
        return aws_raise_error(AWS_ERROR_UNKNOWN);
    }

    size_t space_available = out_buf->capacity - out_buf->len;
    size_t bytes_to_write = space_available < tester->payload.len ? space_available : tester->payload.len;
    struct aws_byte_cursor cursor_to_write = aws_byte_cursor_advance(&tester->payload, bytes_to_write);
    if (!aws_byte_buf_write_from_whole_cursor(out_buf, cursor_to_write)) {
        return aws_raise_error(AWS_ERROR_UNKNOWN); /* write shouldn't fail, but just in case */
    }

    if (tester->payload.len == 0) {
        if (!tester->never_say_payload_is_done) {
            *out_done = true;
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_encoder_tester_reset(struct encoder_tester *tester) {
    aws_websocket_encoder_init(&tester->encoder, s_on_payload, tester);
    tester->out_buf.len = 0;
}

static int s_encoder_tester_init(struct encoder_tester *tester, struct aws_allocator *alloc) {
    aws_load_error_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();
    aws_http_library_init(alloc);

    AWS_ZERO_STRUCT(*tester);
    tester->alloc = alloc;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    ASSERT_SUCCESS(aws_byte_buf_init(&tester->out_buf, alloc, 1024));

    s_encoder_tester_reset(tester);

    return AWS_OP_SUCCESS;
}

static int s_encoder_tester_clean_up(struct encoder_tester *tester) {
    aws_byte_buf_clean_up(&tester->out_buf);
    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);
    return AWS_OP_SUCCESS;
}

static bool aws_byte_buf_eq_array(const struct aws_byte_buf *buf, void *array, size_t array_len) {
    return aws_array_eq(buf->buffer, buf->len, array, array_len);
}

ENCODER_TEST_CASE(websocket_encoder_sanity_check) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test encoding a frame with no payload or mask */
ENCODER_TEST_CASE(websocket_encoder_simplest_frame) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 9,
    };

    uint8_t expected_output[] = {
        0x89, // fin | rsv1 | rsv2 | rsv3 | 4bit opcode
        0x00, // mask | 7bit payload len
    };

    ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
    ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));

    ASSERT_FALSE(aws_websocket_encoder_is_frame_in_progress(&tester.encoder));
    ASSERT_TRUE(aws_byte_buf_eq_array(&tester.out_buf, expected_output, sizeof(expected_output)));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test the 3 RSV bools */
ENCODER_TEST_CASE(websocket_encoder_rsv) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    for (int rsv = 0; rsv < 3; ++rsv) {

        struct aws_websocket_frame input_frame = {
            .fin = true,
            .opcode = 9,
        };
        input_frame.rsv[rsv] = true;

        uint8_t expected_output[] = {
            0x89, // fin | rsv1 | rsv2 | rsv3 | 4bit opcode
            0x00, // mask | 7bit payload len
        };
        expected_output[0] |= (1 << (6 - rsv));

        tester.out_buf.len = 0; /* reset output buffer */
        ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
        ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));

        ASSERT_FALSE(aws_websocket_encoder_is_frame_in_progress(&tester.encoder));
        ASSERT_TRUE(aws_byte_buf_eq_array(&tester.out_buf, expected_output, sizeof(expected_output)));
    }

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

ENCODER_TEST_CASE(websocket_encoder_data_frame) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    uint8_t input_payload[] = {0x00, 0x0F, 0xF0, 0xFF};
    tester.payload = aws_byte_cursor_from_array(input_payload, sizeof(input_payload));

    struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 2,
        .payload_length = sizeof(input_payload),
    };

    uint8_t expected_output[] = {
        0x82, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x04, /* mask | 7bit payload len */
        /* payload */
        0x00,
        0x0F,
        0xF0,
        0xFF,
    };

    ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
    ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));

    ASSERT_FALSE(aws_websocket_encoder_is_frame_in_progress(&tester.encoder));
    ASSERT_TRUE(aws_byte_buf_eq_array(&tester.out_buf, expected_output, sizeof(expected_output)));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

ENCODER_TEST_CASE(websocket_encoder_fail_if_payload_exceeds_stated_length) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 2,
        .payload_length = 4,
    };

    const uint8_t input_payload[5];
    tester.payload = aws_byte_cursor_from_array(input_payload, sizeof(input_payload));

    ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
    ASSERT_FAILS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT, aws_last_error());

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

ENCODER_TEST_CASE(websocket_encoder_fail_if_payload_less_than_stated_length) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 2,
        .payload_length = 4,
    };

    const uint8_t input_payload[3];
    tester.payload = aws_byte_cursor_from_array(input_payload, sizeof(input_payload));

    ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
    ASSERT_FAILS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT, aws_last_error());

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

ENCODER_TEST_CASE(websocket_encoder_fail_if_payload_never_marked_done) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 2,
        .payload_length = 4,
    };

    const uint8_t input_payload[4];
    tester.payload = aws_byte_cursor_from_array(input_payload, sizeof(input_payload));
    tester.never_say_payload_is_done = true;

    ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
    ASSERT_FAILS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT, aws_last_error());

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

ENCODER_TEST_CASE(websocket_encoder_masking) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    /* Test from RFC-6545 Section 5.7 - Examples - A single-frame masked text message */
    const char *input_payload = "Hello";
    tester.payload = aws_byte_cursor_from_c_str(input_payload);

    struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 1,
        .masked = true,
        .masking_key = {0x37, 0xfa, 0x21, 0x3d},
        .payload_length = strlen(input_payload),
    };

    uint8_t expected_output[] = {
        0x81, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x85, /* mask | 7bit payload len */
        /* masking key */
        0x37,
        0xfa,
        0x21,
        0x3d,
        /* payload */
        0x7f,
        0x9f,
        0x4d,
        0x51,
        0x58,
    };

    ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
    ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));

    ASSERT_FALSE(aws_websocket_encoder_is_frame_in_progress(&tester.encoder));
    ASSERT_TRUE(aws_byte_buf_eq_array(&tester.out_buf, expected_output, sizeof(expected_output)));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

ENCODER_TEST_CASE(websocket_encoder_extended_length) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    enum length_type {
        LENGTH_IN_7BITS,
        LENGTH_IN_2BYTES,
        LENGTH_IN_8BYTES,
        LENGTH_ILLEGAL,
    };

    struct actual_length_type_pair {
        uint64_t len;
        enum length_type type;
    };

    struct actual_length_type_pair test_pairs[] = {
        {0, LENGTH_IN_7BITS},
        {1, LENGTH_IN_7BITS},
        {125, LENGTH_IN_7BITS}, /* highest number for 7bit length encoding */
        {126, LENGTH_IN_2BYTES},
        {127, LENGTH_IN_2BYTES},
        {0x00FF, LENGTH_IN_2BYTES},
        {0x0100, LENGTH_IN_2BYTES},
        {0xFFFF, LENGTH_IN_2BYTES}, /* highest number for 2byte extended length */
        {0x0000000000010000, LENGTH_IN_8BYTES},
        {0x7FFFFFFFFFFFFFFF, LENGTH_IN_8BYTES},
        {0x123456789ABCDEF0, LENGTH_IN_8BYTES},
        {0x8000000000000000, LENGTH_ILLEGAL}, /* illegal to use high bit in 8byte extended length */
        {0xFFFFFFFFFFFFFFFF, LENGTH_ILLEGAL},
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(test_pairs); ++i) {
        struct actual_length_type_pair pair_i = test_pairs[i];

        /* Reset encoder for each pair. */
        s_encoder_tester_reset(&tester);

        /* Don't actually encode the payload, we're just testing the non-payload portion of the frame here */
        tester.payload.len = 0;
        tester.never_say_payload_is_done = true;

        struct aws_websocket_frame input_frame = {
            .fin = true,
            .opcode = 2,
            .payload_length = pair_i.len,
        };

        if (pair_i.type == LENGTH_ILLEGAL) {
            ASSERT_FAILS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
            ASSERT_INT_EQUALS(AWS_ERROR_INVALID_ARGUMENT, aws_last_error());
        } else {
            uint8_t extended_length_bytes;
            uint8_t expected_output[10];
            expected_output[0] = 0x82; /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */

            switch (pair_i.type) {
                case LENGTH_IN_7BITS:
                    expected_output[1] = (uint8_t)pair_i.len;
                    extended_length_bytes = 0;
                    break;
                case LENGTH_IN_2BYTES:
                    expected_output[1] = 126;
                    extended_length_bytes = 2;
                    break;
                default:
                    expected_output[1] = 127;
                    extended_length_bytes = 8;
                    break;
            }

            ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
            ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));

            size_t expected_output_len = 2 + extended_length_bytes;
            ASSERT_UINT_EQUALS(expected_output_len, tester.out_buf.len);

            if (pair_i.type == LENGTH_IN_7BITS) {
                ASSERT_UINT_EQUALS(pair_i.len, tester.out_buf.buffer[1]);
            } else if (pair_i.type == LENGTH_IN_2BYTES) {
                uint16_t *u16_ptr = (uint16_t *)&tester.out_buf.buffer[2];
                ASSERT_UINT_EQUALS(pair_i.len, aws_ntoh16(*u16_ptr));
            } else { /* LENGTH_IN_8BYTES */
                uint64_t *u64_ptr = (uint64_t *)&tester.out_buf.buffer[2];
                ASSERT_UINT_EQUALS(pair_i.len, aws_ntoh64(*u64_ptr));
            }
        }
    }

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
