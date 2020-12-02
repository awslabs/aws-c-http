/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
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
    bool payload_length_is_wrong_on_purpose;

    uint8_t out_buf_storage[1024];
    struct aws_byte_buf out_buf;
};

static int s_on_payload(struct aws_byte_buf *out_buf, void *user_data) {
    struct encoder_tester *tester = user_data;

    tester->on_payload_count++;
    if (tester->fail_on_nth_payload == tester->on_payload_count) {
        return aws_raise_error(AWS_ERROR_UNKNOWN);
    }

    if (tester->payload.len > 0) {
        size_t space_available = out_buf->capacity - out_buf->len;
        size_t bytes_to_write = space_available < tester->payload.len ? space_available : tester->payload.len;
        if (!aws_byte_buf_write(out_buf, tester->payload.ptr, bytes_to_write)) {
            return aws_raise_error(AWS_ERROR_UNKNOWN); /* write shouldn't fail, but just in case */
        }
        aws_byte_cursor_advance(&tester->payload, bytes_to_write);
    } else {
        if (!tester->payload_length_is_wrong_on_purpose) {
            return aws_raise_error(AWS_ERROR_UNKNOWN); /* encoder should have stopped asking for more payload */
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_encoder_tester_reset(struct encoder_tester *tester) {
    aws_websocket_encoder_init(&tester->encoder, s_on_payload, tester);
    tester->out_buf.len = 0;
}

static int s_encoder_tester_init(struct encoder_tester *tester, struct aws_allocator *alloc) {
    aws_http_library_init(alloc);

    AWS_ZERO_STRUCT(*tester);
    tester->alloc = alloc;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    tester->out_buf = aws_byte_buf_from_empty_array(tester->out_buf_storage, sizeof(tester->out_buf_storage));

    s_encoder_tester_reset(tester);

    return AWS_OP_SUCCESS;
}

static int s_encoder_tester_clean_up(struct encoder_tester *tester) {
    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);
    return AWS_OP_SUCCESS;
}

static bool aws_byte_buf_eq_array(const struct aws_byte_buf *buf, const void *array, size_t array_len) {
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

    const struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 2,
        .payload_length = 4,
    };

    const uint8_t input_payload[5] = {0};
    tester.payload = aws_byte_cursor_from_array(input_payload, sizeof(input_payload));

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
        tester.payload_length_is_wrong_on_purpose = true;

        struct aws_websocket_frame input_frame = {
            .fin = true,
            .opcode = 2,
            .payload_length = pair_i.len,
        };

        if (pair_i.type == LENGTH_ILLEGAL) {
            ASSERT_FAILS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
            ASSERT_INT_EQUALS(AWS_ERROR_INVALID_ARGUMENT, aws_last_error());
        } else {
            uint8_t expected_output_array[10];
            struct aws_byte_buf expected_output =
                aws_byte_buf_from_empty_array(expected_output_array, sizeof(expected_output_array));
            aws_byte_buf_write_u8(&expected_output, 0x82); /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */

            switch (pair_i.type) {
                case LENGTH_IN_7BITS:
                    aws_byte_buf_write_u8(&expected_output, (uint8_t)pair_i.len); /* 7bit length */
                    break;
                case LENGTH_IN_2BYTES:
                    aws_byte_buf_write_u8(&expected_output, AWS_WEBSOCKET_7BIT_VALUE_FOR_2BYTE_EXTENDED_LENGTH);
                    aws_byte_buf_write_be16(&expected_output, (uint16_t)pair_i.len); /* extended length */
                    break;
                default:
                    aws_byte_buf_write_u8(&expected_output, AWS_WEBSOCKET_7BIT_VALUE_FOR_8BYTE_EXTENDED_LENGTH);
                    aws_byte_buf_write_be64(&expected_output, pair_i.len); /* extended length */
                    break;
            }

            ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
            ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));

            ASSERT_TRUE(aws_byte_buf_eq(&tester.out_buf, &expected_output));
        }
    }

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Ensure the encoder can handle outputing data across split buffers.
 * Best way I know is to output 1 byte at a time, that covers EVERY possible splitting point. */
ENCODER_TEST_CASE(websocket_encoder_1_byte_at_a_time) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    /* Use all optional frame features in this test (8byte extended payload length and masking-key).
     * Even though we say the payload is long, we're only going to send a portion of it in this test */
    const char *input_payload = "Hello";
    tester.payload = aws_byte_cursor_from_c_str(input_payload);
    tester.payload_length_is_wrong_on_purpose = true;

    const struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 1,
        .masked = true,
        .masking_key = {0x37, 0xfa, 0x21, 0x3d},
        .payload_length = 0x0102030405060708,
    };

    const uint8_t expected_output[] = {
        0x81, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0xFF, /* mask | 7bit payload len */
        /* 8byte extended payload len */
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
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

    for (size_t i = 0; i < sizeof(expected_output); ++i) {
        uint8_t one_sad_byte;
        struct aws_byte_buf one_sad_byte_buf = aws_byte_buf_from_empty_array(&one_sad_byte, 1);

        ASSERT_TRUE(aws_websocket_encoder_is_frame_in_progress(&tester.encoder));
        ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &one_sad_byte_buf));

        aws_byte_buf_write_from_whole_buffer(&tester.out_buf, one_sad_byte_buf);
    }

    ASSERT_TRUE(aws_byte_buf_eq_array(&tester.out_buf, expected_output, sizeof(expected_output)));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test fragmented messages, which are sent via multiple frames whose FIN bit is cleared */
ENCODER_TEST_CASE(websocket_encoder_fragmented_message) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    struct frame_payload_pair {
        struct aws_websocket_frame frame;
        const char *payload;
    };

    const struct frame_payload_pair input_pairs[] = {
        /* TEXT FRAME */
        {
            {
                .fin = false,
                .opcode = 1,
                .payload_length = 3,
            },
            "hot",
        },
        {
            /* CONTINUATION FRAME */
            {
                .fin = false,
                .opcode = 0,
                .payload_length = 2,
            },
            "do",
        },
        /* PING FRAME - Control frames may be injected in the middle of a fragmented message. */
        {
            {
                .fin = true,
                .opcode = 9,
            },
            "",
        },
        /* CONTINUATION FRAME */
        {
            {
                .fin = true,
                .opcode = 0,
                .payload_length = 1,
            },
            "g",
        },
    };

    const uint8_t expected_output[] = {
        /* TEXT FRAME */
        0x01, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x03, /* mask | 7bit payload len */
        'h',
        'o',
        't',

        /* CONTINUATION FRAME */
        0x00, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x02, /* mask | 7bit payload len */
        'd',
        'o',

        /* PING FRAME */
        0x89, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x00, /* mask | 7bit payload len */

        /* CONTINUATION FRAME */
        0x80, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        'g',
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(input_pairs); ++i) {
        const struct frame_payload_pair *pair_i = &input_pairs[i];

        tester.payload = aws_byte_cursor_from_c_str(pair_i->payload);

        ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &pair_i->frame));
        ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));
        ASSERT_FALSE(aws_websocket_encoder_is_frame_in_progress(&tester.encoder));
    }

    ASSERT_TRUE(aws_byte_buf_eq_array(&tester.out_buf, expected_output, sizeof(expected_output)));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test illegal sequences of fragmented (FIN bit is clear) frames */
ENCODER_TEST_CASE(websocket_encoder_fragmentation_failure_checks) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    struct aws_websocket_frame fragmented_control_frames[] = {
        {
            .fin = false,
            .opcode = AWS_WEBSOCKET_OPCODE_PING,
        },
    };

    struct aws_websocket_frame no_fin_bit_between_messages[] = {
        {
            .fin = false,
            .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
        },
        {
            .fin = true,
            .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
        },
    };

    struct aws_websocket_frame no_fin_bit_between_messages2[] = {
        {
            .fin = false,
            .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
        },
        {
            .fin = false,
            .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
        },
        {
            .fin = true,
            .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
        },
    };

    struct aws_websocket_frame continuation_frame_without_preceding_data_frame[] = {
        {
            .fin = false,
            .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
        },
    };

    struct aws_websocket_frame continuation_frame_without_preceding_data_frame2[] = {
        {
            .fin = true,
            .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
        },
    };

    struct test_def {
        struct aws_websocket_frame *frames;
        size_t num_frames;
        int error_code;
    };

    struct test_def test_defs[] = {
        {
            .frames = fragmented_control_frames,
            .num_frames = AWS_ARRAY_SIZE(fragmented_control_frames),
            .error_code = AWS_ERROR_INVALID_ARGUMENT,
        },
        {
            .frames = no_fin_bit_between_messages,
            .num_frames = AWS_ARRAY_SIZE(no_fin_bit_between_messages),
            .error_code = AWS_ERROR_INVALID_STATE,
        },
        {
            .frames = no_fin_bit_between_messages2,
            .num_frames = AWS_ARRAY_SIZE(no_fin_bit_between_messages2),
            .error_code = AWS_ERROR_INVALID_STATE,
        },
        {
            .frames = continuation_frame_without_preceding_data_frame,
            .num_frames = AWS_ARRAY_SIZE(continuation_frame_without_preceding_data_frame),
            .error_code = AWS_ERROR_INVALID_STATE,
        },
        {
            .frames = continuation_frame_without_preceding_data_frame2,
            .num_frames = AWS_ARRAY_SIZE(continuation_frame_without_preceding_data_frame2),
            .error_code = AWS_ERROR_INVALID_STATE,
        },
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(test_defs); ++i) {
        struct test_def *test_i = &test_defs[i];

        s_encoder_tester_reset(&tester);

        int err = 0;

        for (size_t frame_i = 0; frame_i < test_i->num_frames; ++frame_i) {
            /* We expect the encoder to fail at some point in this test.
             * Currently, fragmentation errors are detected in the frame_start() call */
            err = aws_websocket_encoder_start_frame(&tester.encoder, &test_i->frames[frame_i]);
            if (err) {
                ASSERT_INT_EQUALS(test_i->error_code, aws_last_error()); /* Error code */
                break;
            }

            ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));
            ASSERT_FALSE(aws_websocket_encoder_is_frame_in_progress(&tester.encoder));
        }

        /* Assert that test did fail at some point */
        ASSERT_INT_EQUALS(AWS_OP_ERR, err);
    }

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

ENCODER_TEST_CASE(websocket_encoder_payload_callback_can_fail_encoder) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    const struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 2,
        .payload_length = 4,
    };

    tester.fail_on_nth_payload = 1;

    ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
    ASSERT_FAILS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));

    /* Check that error returned by callback bubbles up.
     * UNKNOWN error just happens to be what our test callback throws */
    ASSERT_INT_EQUALS(AWS_ERROR_UNKNOWN, aws_last_error());

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
