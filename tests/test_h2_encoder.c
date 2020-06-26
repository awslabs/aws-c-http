/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "h2_test_helper.h"
#include <aws/testing/aws_test_harness.h>

#include <aws/http/private/h2_frames.h>
#include <aws/io/stream.h>

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

#define DEFINE_STATIC_HEADER(_key, _value, _behavior)                                                                  \
    {                                                                                                                  \
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_key), .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_value),   \
        .compression = AWS_HTTP_HEADER_COMPRESSION_##_behavior,                                                        \
    }

/* Run the given frame's encoder and check that it outputs the expected bytes */
static int s_encode_frame(
    struct aws_allocator *allocator,
    struct aws_h2_frame *frame,
    const uint8_t *expected,
    size_t expected_size) {

    struct aws_h2_frame_encoder encoder;
    ASSERT_SUCCESS(aws_h2_frame_encoder_init(&encoder, allocator, NULL /*logging_id*/));

    struct aws_byte_buf buffer;

    /* Allocate more room than necessary, easier to debug the full output than a failed aws_h2_encode_frame() call */
    ASSERT_SUCCESS(aws_byte_buf_init(&buffer, allocator, expected_size * 2));

    bool frame_complete;
    ASSERT_SUCCESS(aws_h2_encode_frame(&encoder, frame, &buffer, &frame_complete));
    ASSERT_BIN_ARRAYS_EQUALS(expected, expected_size, buffer.buffer, buffer.len);
    ASSERT_UINT_EQUALS(true, frame_complete);

    aws_byte_buf_clean_up(&buffer);
    aws_h2_frame_encoder_clean_up(&encoder);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_data) {
    (void)ctx;

    struct aws_h2_frame_encoder encoder;
    ASSERT_SUCCESS(aws_h2_frame_encoder_init(&encoder, allocator, NULL /*logging_id*/));

    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 1024));

    struct aws_byte_cursor body_src = aws_byte_cursor_from_c_str("hello");
    struct aws_input_stream *body = aws_input_stream_new_from_cursor(allocator, &body_src);
    ASSERT_NOT_NULL(body);

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

    bool body_complete;
    bool body_stalled;
    int32_t stream_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    size_t connection_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    ASSERT_SUCCESS(aws_h2_encode_data_frame(
        &encoder,
        0x76543210 /*stream_id*/,
        body,
        true /*body_ends_stream*/,
        2 /*pad_length*/,
        &stream_window_size_peer,
        &connection_window_size_peer,
        &output,
        &body_complete,
        &body_stalled));

    ASSERT_BIN_ARRAYS_EQUALS(expected, sizeof(expected), output.buffer, output.len);
    ASSERT_TRUE(body_complete);
    ASSERT_FALSE(body_stalled);

    aws_byte_buf_clean_up(&output);
    aws_input_stream_destroy(body);
    aws_h2_frame_encoder_clean_up(&encoder);
    return AWS_OP_SUCCESS;
}

/* Test that we set body_stalled to true if the aws_input_stream is unable to fill the available space */
TEST_CASE(h2_encoder_data_stalled) {
    (void)ctx;

    struct aws_h2_frame_encoder encoder;
    ASSERT_SUCCESS(aws_h2_frame_encoder_init(&encoder, allocator, NULL /*logging_id*/));

    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 1024));

    struct aws_byte_cursor body_src = aws_byte_cursor_from_c_str("hello");
    struct aws_input_stream *body = aws_input_stream_new_tester(allocator, body_src);
    ASSERT_NOT_NULL(body);

    /* Run encoder where body produces only 1 byte */
    aws_input_stream_tester_set_max_bytes_per_read(body, 1);

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x01,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        'h',                        /* Data (*) */
    };
    /* clang-format on */

    bool body_complete;
    bool body_stalled;
    int32_t stream_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    size_t connection_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    ASSERT_SUCCESS(aws_h2_encode_data_frame(
        &encoder,
        0x76543210 /*stream_id*/,
        body,
        true /*body_ends_stream*/,
        0 /*pad_length*/,
        &stream_window_size_peer,
        &connection_window_size_peer,
        &output,
        &body_complete,
        &body_stalled));

    ASSERT_BIN_ARRAYS_EQUALS(expected, sizeof(expected), output.buffer, output.len);
    ASSERT_FALSE(body_complete);
    ASSERT_TRUE(body_stalled);

    aws_byte_buf_clean_up(&output);
    aws_input_stream_destroy(body);
    aws_h2_frame_encoder_clean_up(&encoder);
    return AWS_OP_SUCCESS;
}

/* Run encoder where body produces zero bytes. The encoder should not even bother writing a frame. */
TEST_CASE(h2_encoder_data_stalled_completely) {
    (void)ctx;

    struct aws_h2_frame_encoder encoder;
    ASSERT_SUCCESS(aws_h2_frame_encoder_init(&encoder, allocator, NULL /*logging_id*/));

    struct aws_byte_buf output;
    ASSERT_SUCCESS(aws_byte_buf_init(&output, allocator, 1024));

    struct aws_byte_cursor body_src = aws_byte_cursor_from_c_str("hello");
    struct aws_input_stream *body = aws_input_stream_new_tester(allocator, body_src);
    ASSERT_NOT_NULL(body);

    aws_input_stream_tester_set_max_bytes_per_read(body, 0);

    bool body_complete;
    bool body_stalled;
    int32_t stream_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    size_t connection_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    ASSERT_SUCCESS(aws_h2_encode_data_frame(
        &encoder,
        0x76543210 /*stream_id*/,
        body,
        true /*body_ends_stream*/,
        0 /*pad_length*/,
        &stream_window_size_peer,
        &connection_window_size_peer,
        &output,
        &body_complete,
        &body_stalled));

    ASSERT_FALSE(body_complete);
    ASSERT_TRUE(body_stalled);
    ASSERT_UINT_EQUALS(0, output.len);

    /* clean up */
    aws_byte_buf_clean_up(&output);
    aws_input_stream_destroy(body);
    aws_h2_frame_encoder_clean_up(&encoder);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_headers) {
    (void)ctx;

    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    struct aws_http_header h = DEFINE_STATIC_HEADER(":status", "302", USE_CACHE);

    ASSERT_SUCCESS(aws_http_headers_add_header(headers, &h));

    struct aws_h2_frame_priority_settings priority = {
        .stream_dependency_exclusive = true,
        .stream_dependency = 0x01234567,
        .weight = 9,
    };

    struct aws_h2_frame *frame = aws_h2_frame_new_headers(
        allocator, 0x76543210 /*stream_id*/, headers, true /*end_stream*/, 2 /*pad_length*/, &priority);
    ASSERT_NOT_NULL(frame);

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 12,             /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM | AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PADDED | AWS_H2_FRAME_F_PRIORITY, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31)   - F_PRIORITY*/
        0x09,                       /* Weight (8)                               - F_PRIORITY */
        0x48, 0x82, 0x64, 0x02,     /* ":status: 302" - indexed name, huffman-compressed value */
        0x00, 0x00                  /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_priority) {
    (void)ctx;

    struct aws_h2_frame_priority_settings priority = {
        .stream_dependency_exclusive = true,
        .stream_dependency = 0x01234567,
        .weight = 9,
    };

    struct aws_h2_frame *frame = aws_h2_frame_new_priority(allocator, 0x76543210 /*stream_id*/, &priority);
    ASSERT_NOT_NULL(frame);

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

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_rst_stream) {
    (void)ctx;

    struct aws_h2_frame *frame =
        aws_h2_frame_new_rst_stream(allocator, 0x76543210 /*stream_id*/, 0xFEEDBEEF /*error_code*/);
    ASSERT_NOT_NULL(frame);

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

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_settings) {
    (void)ctx;

    struct aws_http2_setting settings[] = {
        {.id = AWS_HTTP2_SETTINGS_ENABLE_PUSH, .value = 1}, /* real world value */
        {.id = 0x0000, .value = 0x00000000},                /* min value */
        {.id = 0xFFFF, .value = 0xFFFFFFFF},                /* max value */
    };

    struct aws_h2_frame *frame =
        aws_h2_frame_new_settings(allocator, settings, AWS_ARRAY_SIZE(settings), false /*ack*/);
    ASSERT_NOT_NULL(frame);

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

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_settings_ack) {
    (void)ctx;

    struct aws_h2_frame *frame =
        aws_h2_frame_new_settings(allocator, NULL /*settings_array*/, 0 /*num_settings*/, true /*ack*/);
    ASSERT_NOT_NULL(frame);

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        AWS_H2_FRAME_F_ACK,         /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_push_promise) {
    (void)ctx;

    struct aws_http_header headers_array[] = {
        DEFINE_STATIC_HEADER(":method", "GET", USE_CACHE),
        DEFINE_STATIC_HEADER(":scheme", "http", USE_CACHE),
        DEFINE_STATIC_HEADER(":path", "/", USE_CACHE),
        DEFINE_STATIC_HEADER(":authority", "www.example.com", USE_CACHE),
    };
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);
    ASSERT_SUCCESS(aws_http_headers_add_array(headers, headers_array, AWS_ARRAY_SIZE(headers_array)));

    struct aws_h2_frame *frame = aws_h2_frame_new_push_promise(
        allocator, 0x00000001 /*stream_id*/, 0x76543210 /*promised_stream_id*/, headers, 2 /*pad_length*/);
    ASSERT_NOT_NULL(frame);

    /* clang-format off */
    uint8_t expected[] = {
        0x00, 0x00, 24,             /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PADDED, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE */
        0x02,                       /* Pad Length (8)                           | F_PADDED */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Promised Stream ID (31) */

        /* Header Block Fragment (*) (values from RFC-7541 example C.4.1) */
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,

        0x00, 0x00,                 /* Padding (*)                              | F_PADDED*/
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_ping) {
    (void)ctx;

    uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7};

    struct aws_h2_frame *frame = aws_h2_frame_new_ping(allocator, true /*ack*/, opaque_data);
    ASSERT_NOT_NULL(frame);

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

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_goaway) {
    (void)ctx;

    struct aws_h2_frame *frame = aws_h2_frame_new_goaway(
        allocator,
        0x77665544 /*last_stream_id*/,
        0xFFEEDDCC /*error_code*/,
        aws_byte_cursor_from_c_str("goodbye") /*debug_data*/);
    ASSERT_NOT_NULL(frame);

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

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_encoder_window_update) {
    (void)ctx;

    struct aws_h2_frame *frame =
        aws_h2_frame_new_window_update(allocator, 0x76543210 /*stream_id*/, 0x7FFFFFFF /*window_size_increment*/);
    ASSERT_NOT_NULL(frame);

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

    ASSERT_SUCCESS(s_encode_frame(allocator, frame, expected, sizeof(expected)));
    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}
