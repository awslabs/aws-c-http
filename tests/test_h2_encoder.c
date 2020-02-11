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

#include <aws/http/private/h2_frames.h>

static int s_fixture_init(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_http_library_init(allocator);
    return AWS_OP_SUCCESS;
}

static int s_fixture_clean_up(struct aws_allocator *allocator, int setup_res, void *ctx) {
    (void)allocator;
    (void)ctx;
    (void)setup_res;
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE_FIXTURE(NAME, s_fixture_init, s_test_##NAME, s_fixture_clean_up, NULL);                              \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

/* Run the given frame's encoder and check that it outputs the expected bytes */
static int s_encode(
    struct aws_allocator *allocator,
    struct aws_h2_frame_header *frame_header,
    const uint8_t *expected,
    size_t expected_size) {

    struct aws_h2_frame_encoder encoder;
    ASSERT_SUCCESS(aws_h2_frame_encoder_init(&encoder, allocator));

    struct aws_byte_buf buffer;
    /* Allocate more room than necessary, easier to debug the full output than a failed aws_h2_encode_frame() call */
    ASSERT_SUCCESS(aws_byte_buf_init(&buffer, allocator, expected_size * 2));

    ASSERT_SUCCESS(aws_h2_encode_frame(&encoder, frame_header, &buffer));
    ASSERT_BIN_ARRAYS_EQUALS(expected, expected_size, buffer.buffer, buffer.len);

    aws_byte_buf_clean_up(&buffer);
    aws_h2_frame_encoder_clean_up(&encoder);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_data) {
    (void)ctx;

    struct aws_h2_frame_data frame;
    ASSERT_SUCCESS(aws_h2_frame_data_init(&frame, allocator));
    frame.header.stream_id = 0x76543210;
    frame.end_stream = true;
    frame.pad_length = 2;
    frame.data = aws_byte_cursor_from_c_str("hello");

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM | AWS_H2_FRAME_F_PADDED, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        'h', 'e', 'l', 'l', 'o',    /* Data (*) */
        0x00, 0x00                  /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_data_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_headers) {
    (void)ctx;

    struct aws_h2_frame_headers frame;
    ASSERT_SUCCESS(aws_h2_frame_headers_init(&frame, allocator));
    frame.header.stream_id = 0x76543210;
    frame.end_headers = true;
    frame.end_stream = true;
    frame.pad_length = 2;
    frame.has_priority = true;
    frame.priority.stream_dependency_exclusive = true;
    frame.priority.stream_dependency = 0x01234567;
    frame.priority.weight = 9;

    /* Intentionally leaving header block fragment empty. Header block encoding is tested elsewhere */

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM | AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PADDED | AWS_H2_FRAME_F_PRIORITY, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31)   - F_PRIORITY*/
        0x09,                       /* Weight (8)                               - F_PRIORITY */
                                    /* Header Block Fragment (*) */
        0x00, 0x00                  /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_headers_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_priority) {
    (void)ctx;

    struct aws_h2_frame_priority frame;
    ASSERT_SUCCESS(aws_h2_frame_priority_init(&frame, allocator));
    frame.header.stream_id = 0x76543210;
    frame.priority.stream_dependency_exclusive = true;
    frame.priority.stream_dependency = 0x01234567;
    frame.priority.weight = 9;

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_PRIORITY,    /* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PRIORITY */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31) */
        0x09,                       /* Weight (8) */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));

    aws_h2_frame_priority_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_rst_stream) {
    (void)ctx;

    struct aws_h2_frame_rst_stream frame;
    ASSERT_SUCCESS(aws_h2_frame_rst_stream_init(&frame, allocator));
    frame.header.stream_id = 0x76543210;
    frame.error_code = 0xFEEDBEEF;

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_RST_STREAM,  /* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* RST_STREAM */
        0xFE, 0xED, 0xBE, 0xEF,     /* Error Code (32) */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_rst_stream_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_settings) {
    (void)ctx;

    struct aws_h2_frame_setting settings[] = {
        {.id = AWS_H2_SETTINGS_ENABLE_PUSH, .value = 1}, /* real world value */
        {.id = 0x0000, .value = 0x00000000},             /* min value */
        {.id = 0xFFFF, .value = 0xFFFFFFFF},             /* max value */
    };

    struct aws_h2_frame_settings frame;
    ASSERT_SUCCESS(aws_h2_frame_settings_init(&frame, allocator));
    frame.settings_array = settings;
    frame.settings_count = AWS_ARRAY_SIZE(settings);

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 18,             /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x02,                 /* Identifier (16) */
        0x00, 0x00, 0x00, 0x01,     /* Value (32) */
        0x00, 0x00,                 /* Identifier (16) */
        0x00, 0x00, 0x00, 0x00,     /* Value (32) */
        0xFF, 0xFF,                 /* Identifier (16) */
        0xFF, 0xFF, 0xFF, 0xFF,     /* Value (32) */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_settings_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_settings_ack) {
    (void)ctx;

    struct aws_h2_frame_settings frame;
    ASSERT_SUCCESS(aws_h2_frame_settings_init(&frame, allocator));
    frame.ack = true;

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        AWS_H2_FRAME_F_ACK,         /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_settings_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_push_promise) {
    (void)ctx;

    struct aws_h2_frame_push_promise frame;
    ASSERT_SUCCESS(aws_h2_frame_push_promise_init(&frame, allocator));
    frame.header.stream_id = 0x00000001;
    frame.promised_stream_id = 0x76543210;
    frame.end_headers = true;
    frame.pad_length = 2;

    /* Intentionally leaving header block fragment empty. Header block encoding is tested elsewhere */

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x07,           /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PADDED, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE */
        0x02,                       /* Pad Length (8)                           | F_PADDED */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Promised Stream ID (31) */
                                    /* Header Block Fragment (*) */
        0x00, 0x00,                 /* Padding (*)                              | F_PADDED*/
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_push_promise_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_ping) {
    (void)ctx;

    struct aws_h2_frame_ping frame;
    ASSERT_SUCCESS(aws_h2_frame_ping_init(&frame, allocator));
    frame.ack = true;
    for (uint8_t i = 0; i < AWS_H2_PING_DATA_SIZE; ++i) {
        frame.opaque_data[i] = i;
    }

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        AWS_H2_FRAME_F_ACK,         /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* PING */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* Opaque Data (64) */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_ping_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_goaway) {
    (void)ctx;

    struct aws_h2_frame_goaway frame;
    ASSERT_SUCCESS(aws_h2_frame_goaway_init(&frame, allocator));
    frame.last_stream_id = 0x77665544;
    frame.error_code = 0xFFEEDDCC;
    frame.debug_data = aws_byte_cursor_from_c_str("goodbye");

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 15,             /* Length (24) */
        AWS_H2_FRAME_T_GOAWAY,      /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* GOAWAY */
        0x77, 0x66, 0x55, 0x44,     /* Reserved (1) | Last-Stream-ID (31) */
        0xFF, 0xEE, 0xDD, 0xCC,     /* Error Code (32) */
        'g','o','o','d','b','y','e',/* Additional Debug Data (*) */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_goaway_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_window_update) {
    (void)ctx;

    struct aws_h2_frame_window_update frame;
    ASSERT_SUCCESS(aws_h2_frame_window_update_init(&frame, allocator));
    frame.header.stream_id = 0x76543210;
    frame.window_size_increment = 0x7FFFFFFF;

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_WINDOW_UPDATE,/* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* WINDOW_UPDATE */
        0x7F, 0xFF, 0xFF, 0xFF,     /* Window Size Increment (31) */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_window_update_clean_up(&frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_continuation) {
    (void)ctx;

    struct aws_h2_frame_continuation frame;
    ASSERT_SUCCESS(aws_h2_frame_continuation_init(&frame, allocator));
    frame.header.stream_id = 0x76543210;
    frame.end_headers = true;

    /* Intentionally leaving header block fragment empty. Header block encoding is tested elsewhere */

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* CONTINUATION */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode(allocator, &frame.header, expected, sizeof(expected)));
    aws_h2_frame_continuation_clean_up(&frame);
    return AWS_OP_SUCCESS;
}
