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

    if (tester->fail_on_nth_payload == tester->on_payload_count) {
        return aws_raise_error(AWS_ERROR_UNKNOWN);
    }

    tester->on_payload_count++;

    size_t space_available = out_buf->capacity - out_buf->len;
    size_t bytes_to_write = space_available < tester->payload.len ? space_available : tester->payload.len;
    struct aws_byte_cursor cursor_to_write = aws_byte_cursor_advance(&tester->payload, bytes_to_write);
    aws_byte_buf_write_from_whole_cursor(out_buf, cursor_to_write);

    return AWS_OP_SUCCESS;
}

static void s_encoder_tester_reset(struct encoder_tester *tester) {
    aws_websocket_encoder_init(&tester->encoder, s_on_payload, &tester);
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

ENCODER_TEST_CASE(websocket_encoder_sanity_check) {
    (void)ctx;
    struct encoder_tester tester;
    ASSERT_SUCCESS(s_encoder_tester_init(&tester, allocator));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

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

    ASSERT_TRUE(aws_array_eq(expected_output, sizeof(expected_output), tester.out_buf.buffer, tester.out_buf.len));

    ASSERT_SUCCESS(s_encoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
