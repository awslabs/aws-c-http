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

    struct aws_byte_buf out_buf;
};

static int s_on_payload(struct aws_byte_buf *out_buf, void *user_data) {
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

    return AWS_OP_SUCCESS;
}

static void s_encoder_tester_reset(struct encoder_tester *tester) {
    aws_websocket_encoder_init(&tester->encoder, s_on_payload, tester);
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
        .payload_length = sizeof(input_payload)
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

    ASSERT_TRUE(aws_byte_buf_eq_array(&tester.out_buf, expected_output, sizeof(expected_output)));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

ENCODER_TEST_CASE(websocket_encoder_stops_at_frame_end) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    uint8_t input_payload[] = "ThisNotThat";
    tester.payload = aws_byte_cursor_from_array(input_payload, 4);

    struct aws_websocket_frame input_frame = {
        .fin = true,
        .opcode = 1,
        .payload_length = 4,
    };

    uint8_t expected_output[] = {
        0x81, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x04, /* mask | 7bit payload len */
        /* payload */
        'T',
        'h',
        'i',
        's',
    };

    ASSERT_SUCCESS(aws_websocket_encoder_start_frame(&tester.encoder, &input_frame));
    ASSERT_SUCCESS(aws_websocket_encoder_process(&tester.encoder, &tester.out_buf));

    ASSERT_TRUE(aws_byte_buf_eq_array(&tester.out_buf, expected_output, sizeof(expected_output)));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}