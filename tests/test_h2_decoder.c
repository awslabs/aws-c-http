/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "h2_test_helper.h"

#include <aws/http/private/h2_decoder.h>

struct fixture {
    struct aws_allocator *allocator;
    struct h2_decode_tester decode;

    /* If true, run decoder over input one byte at a time */
    bool one_byte_at_a_time;

    bool is_server;
    bool skip_connection_preface;
};

static int s_fixture_init(struct fixture *fixture, struct aws_allocator *allocator) {
    fixture->allocator = allocator;

    struct h2_decode_tester_options options = {
        .alloc = allocator,
        .is_server = fixture->is_server,
        .skip_connection_preface = fixture->skip_connection_preface,
    };
    ASSERT_SUCCESS(h2_decode_tester_init(&fixture->decode, &options));

    return AWS_OP_SUCCESS;
}

static void s_fixture_clean_up(struct fixture *fixture) {
    h2_decode_tester_clean_up(&fixture->decode);
}

static int s_fixture_test_setup(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);

    struct fixture *fixture = ctx;
    ASSERT_SUCCESS(s_fixture_init(fixture, allocator));
    return AWS_OP_SUCCESS;
}

static int s_fixture_test_teardown(struct aws_allocator *allocator, int setup_result, void *ctx) {
    (void)allocator;
    if (setup_result) {
        return AWS_OP_ERR;
    }

    struct fixture *fixture = ctx;
    s_fixture_clean_up(fixture);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* declare 1 test using the fixture */
#define TEST_CASE(NAME)                                                                                                \
    static struct fixture s_fixture_##NAME;                                                                            \
    AWS_TEST_CASE_FIXTURE(NAME, s_fixture_test_setup, s_test_##NAME, s_fixture_test_teardown, &s_fixture_##NAME);      \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

/* declare 2 tests, where:
 * 1) NAME runs the decoder over input all at once
 * 2) NAME_one_byte_at_a_time runs the decoder on one byte of input at a time. */
#define H2_DECODER_TEST_CASE_IMPL(NAME, IS_SERVER, SKIP_PREFACE)                                                       \
    static struct fixture s_fixture_##NAME = {                                                                         \
        .is_server = (IS_SERVER),                                                                                      \
        .skip_connection_preface = (SKIP_PREFACE),                                                                     \
    };                                                                                                                 \
    AWS_TEST_CASE_FIXTURE(NAME, s_fixture_test_setup, s_test_##NAME, s_fixture_test_teardown, &s_fixture_##NAME);      \
    static struct fixture s_fixture_##NAME##_one_byte_at_a_time = {                                                    \
        .one_byte_at_a_time = true,                                                                                    \
        .is_server = (IS_SERVER),                                                                                      \
        .skip_connection_preface = (SKIP_PREFACE),                                                                     \
    };                                                                                                                 \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        NAME##_one_byte_at_a_time,                                                                                     \
        s_fixture_test_setup,                                                                                          \
        s_test_##NAME,                                                                                                 \
        s_fixture_test_teardown,                                                                                       \
        &s_fixture_##NAME##_one_byte_at_a_time)                                                                        \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

#define H2_DECODER_ON_CLIENT_TEST(NAME) H2_DECODER_TEST_CASE_IMPL(NAME, false /*server*/, true /*skip_preface*/)
#define H2_DECODER_ON_SERVER_TEST(NAME) H2_DECODER_TEST_CASE_IMPL(NAME, true /*server*/, true /*skip_preface*/)
#define H2_DECODER_ON_CLIENT_PREFACE_TEST(NAME) H2_DECODER_TEST_CASE_IMPL(NAME, false, false)
#define H2_DECODER_ON_SERVER_PREFACE_TEST(NAME) H2_DECODER_TEST_CASE_IMPL(NAME, true, false)

/* Make sure fixture works */
TEST_CASE(h2_decoder_sanity_check) {
    (void)allocator;
    struct fixture *fixture = ctx;
    ASSERT_NOT_NULL(fixture);
    return AWS_OP_SUCCESS;
}

/* Run aws_h2_decode() on input in special ways determined by the fixture */
static struct aws_h2err s_decode_all(struct fixture *fixture, struct aws_byte_cursor input) {
    if (fixture->one_byte_at_a_time) {
        /* Decode input one byte at a time */
        while (input.len) {
            struct aws_byte_cursor one_byte = aws_byte_cursor_advance(&input, 1);
            struct aws_h2err err = aws_h2_decode(fixture->decode.decoder, &one_byte);
            if (aws_h2err_failed(err)) {
                return err;
            }
            AWS_FATAL_ASSERT(0 == one_byte.len);
        }

    } else {
        /* Decode buffer all at once */
        struct aws_h2err err = aws_h2_decode(fixture->decode.decoder, &input);
        if (aws_h2err_failed(err)) {
            return err;
        }
        AWS_FATAL_ASSERT(0 == input.len);
    }

    return AWS_H2ERR_SUCCESS;
}

/* Test DATA frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_data) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        'h', 'e', 'l', 'l', 'o',    /* Data (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(5, frame->data_payload_len);
    ASSERT_TRUE(frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&frame->data, "hello"));
    return AWS_OP_SUCCESS;
}

/* Test padded DATA frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_data_padded) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_PADDED,      /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        'h', 'e', 'l', 'l', 'o',    /* Data (*) */
        0x00, 0x00,                 /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(8, frame->data_payload_len);
    ASSERT_FALSE(frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&frame->data, "hello"));
    return AWS_OP_SUCCESS;
}

/* OK for PADDED frame to have pad length of zero */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_data_pad_length_zero) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x06,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_PADDED | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        0x00,                       /* Pad Length (8)                           - F_PADDED */
        'h', 'e', 'l', 'l', 'o',    /* Data (*) */
                                    /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(6, frame->data_payload_len);
    ASSERT_TRUE(frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&frame->data, "hello"));
    return AWS_OP_SUCCESS;
}

/* OK for DATA frame to have no data */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_data_empty) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
                                    /* Data (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, h2_decode_tester_frame_count(&fixture->decode));
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_TRUE(frame->data.len == 0);
    ASSERT_TRUE(frame->end_stream);

    return AWS_OP_SUCCESS;
}

/* OK for padded DATA frame to have no data */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_data_empty_padded) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x03,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_PADDED,      /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
                                    /* Data (*) */
        0x00, 0x00,                 /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(3, frame->data_payload_len);
    ASSERT_FALSE(frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&frame->data, ""));
    return AWS_OP_SUCCESS;
}

/* Unexpected flags should be ignored.
 * DATA frames only support END_STREAM and PADDED*/
H2_DECODER_ON_CLIENT_TEST(h2_decoder_data_ignores_unknown_flags) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        0xFF,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        'h', 'e', 'l', 'l', 'o',    /* Data (*) */
        0x00, 0x00,                 /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(8, frame->data_payload_len);
    ASSERT_TRUE(frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&frame->data, "hello"));
    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_data_payload_max_size_update) {
    (void)allocator;
    struct fixture *fixture = ctx;
    /* The initial max size is set as 16384. Let's create a data frame with 16500 bytes data, and update the setting to
     * make it valid */
    aws_h2_decoder_set_setting_max_frame_size(fixture->decode.decoder, 16500);
    /* clang-format off */
    uint8_t input[16509] = {
        0x00, 0x40, 0x74,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
    };
    /* clang-format on */
    /* set the data and expected to 16500 'a' */
    char expected[16500];
    for (int i = 9; i < 16509; i++) {
        input[i] = 'a';
        expected[i - 9] = 'a';
    }
    struct aws_byte_cursor expected_cursor = aws_byte_cursor_from_array(expected, sizeof(expected));

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(16500, frame->data_payload_len);
    ASSERT_TRUE(frame->end_stream);
    ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&expected_cursor, &frame->data));
    return AWS_OP_SUCCESS;
}

/* The size of a frame payload is limited by the maximum size. An endpoint MUST send an error code of FRAME_SIZE_ERROR
 * if a frame exceeds the size */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_data_payload_exceed_max_size) {
    (void)allocator;
    struct fixture *fixture = ctx;
    /* The initial max size is set as 16384. Let's create a data frame with 16500 bytes data, which will be invalid in
     * this case */
    /* clang-format off */
    uint8_t input[16509] = {
        0x00, 0x40, 0x74,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* DATA frames MUST specify a stream-id */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_data_requires_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        'h', 'e', 'l', 'l', 'o',    /* Data (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Error if frame is padded, but not big enough to contain the padding length */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_payload_too_small_for_pad_length) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_PADDED,      /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        /* Pad Length (8)                           - F_PADDED */
        /* Data (*) */
        /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));
    return AWS_OP_SUCCESS;
}

/* The most-significant-bit of the encoded stream ID is reserved, and should be ignored when decoding */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_stream_id_ignores_reserved_bit) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0xFF, 0xFF, 0xFF, 0xFF,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        'h', 'e', 'l', 'l', 'o',    /* Data (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_DATA, 0x7FFFFFFF /*stream_id*/));
    ASSERT_UINT_EQUALS(5, frame->data_payload_len);
    ASSERT_TRUE(frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&frame->data, "hello"));
    return AWS_OP_SUCCESS;
}

static int s_check_header(
    struct h2_decoded_frame *frame,
    size_t header_idx,
    const char *name,
    const char *value,
    enum aws_http_header_compression compression) {

    struct aws_http_header header_field;
    ASSERT_SUCCESS(aws_http_headers_get_index(frame->headers, header_idx, &header_field));

    ASSERT_BIN_ARRAYS_EQUALS(name, strlen(name), header_field.name.ptr, header_field.name.len);
    ASSERT_BIN_ARRAYS_EQUALS(value, strlen(value), header_field.value.ptr, header_field.value.len);
    ASSERT_INT_EQUALS(compression, header_field.compression);
    return AWS_OP_SUCCESS;
}

/* Test a simple HEADERS frame
 * Note that we're not stressing the HPACK decoder here, that's done in other test files */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_headers) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 11,                 /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - indexed name, uncompressed value */
        0x7a, 0x04, 't', 'e', 's', 't'  /* "user-agent: test" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(2, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "user-agent", "test", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Test a HEADERS frame with padding */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_headers_padded) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_PADDED | AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */
        0x00, 0x00,                 /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    return AWS_OP_SUCCESS;
}

/* Test a HEADERS frame with priority information
 * Note that priority information is ignored for now.
 * We're not testing that it was reported properly, just that decoder can properly consume it */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_headers_priority) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 10,             /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PRIORITY, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31)   - F_PRIORITY*/
        0x09,                       /* Weight (8)                               - F_PRIORITY */
        0x48, 0x03, '3', '0', '2'   /* ":status: 302" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    return AWS_OP_SUCCESS;
}

/* Test a HEADERS frame with ALL flags set.
 * Unexpected flags should be ignored, but HEADERS supports: priority and padding and end-headers and end-stream */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_headers_ignores_unknown_flags) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 13,             /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        0xFF,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31)   - F_PRIORITY*/
        0x09,                       /* Weight (8)                               - F_PRIORITY */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */
        0x00, 0x00                  /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_headers_response_informational) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,               /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS,     /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, 0x03, '1', '0', '0',      /* ":status: 100" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "100", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_INFORMATIONAL, frame->header_block_type);
    ASSERT_FALSE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Test decoding a request frame (Note: must use decoder on server) */
H2_DECODER_ON_SERVER_TEST(h2_decoder_headers_request) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 21,                 /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x82,                           /* ":method: GET" - indexed */
        0x86,                           /* ":scheme: http" - indexed */
        0x41, 10, 'a', 'm', 'a', 'z', 'o', 'n', '.', 'c', 'o', 'm', /* ":authority: amazon.com" - indexed name */
        0x84,                           /* ":path: /" - indexed */
        0x7a, 0x04, 't', 'e', 's', 't'  /* "user-agent: test" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 1 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(5, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":method", "GET", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, ":scheme", "http", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 2, ":authority", "amazon.com", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 3, ":path", "/", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 4, "user-agent", "test", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_SERVER_TEST(h2_decoder_headers_cookies) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x06,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x82,                       /* ":method: GET" - indexed */
        0x60, 0x03, 'a', '=', 'b',  /* "cache: a=b" - indexed name, uncompressed value */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 16,             /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x7a, 0x04, 't', 'e', 's', 't',  /* "user-agent: test" - indexed name, uncompressed value */
        0x60, 0x03, 'c', '=', 'd',  /* "cache: c=d" - indexed name, uncompressed value */
        0x60, 0x03, 'e', '=', 'f',  /* "cache: e=f" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    /* two sepaprate cookie headers are concatenated and moved as the last header*/
    ASSERT_UINT_EQUALS(3, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":method", "GET", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "user-agent", "test", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 2, "cookie", "a=b; c=d; e=f", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);

    return AWS_OP_SUCCESS;
}

/* A trailing header has no pseudo-headers, and always ends the stream */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_headers_trailer) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x06,               /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x7a, 0x04, 't', 'e', 's', 't'  /* "user-agent: test" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, "user-agent", "test", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_TRAILING, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* A trailing header can be empty */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_headers_empty_trailer) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,               /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS - none */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(0, aws_http_headers_count(frame->headers));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_TRAILING, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* HEADERS must specify a valid stream-id */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_headers_requires_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, 0x03, '3', '0', '2'   /* ":status: 302" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_headers_payload_too_small_for_padding) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PRIORITY | AWS_H2_FRAME_F_PADDED | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31)   - F_PRIORITY*/
        0x09,                       /* Weight (8)                               - F_PRIORITY */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */
        0x00, 0x00                  /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_headers_payload_too_small_for_priority) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PRIORITY | AWS_H2_FRAME_F_PADDED | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31)   - F_PRIORITY*/
        0x09,                       /* Weight (8)                               - F_PRIORITY */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */
        0x00, 0x00                  /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Message is malformed if a header-name is blank.
 * A malformed message is a Stream Error, not a Connection Error, so the decoder should continue */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_headers_blank_name) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x09,               /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - indexed name, uncompressed value */
        0x40, 0x00, 0x01, 'a',          /* ": a" - literal blank name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_TRUE(frame->headers_malformed);

    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Message is malformed if a header-name has illegal characters.
 * A malformed message is a Stream Error, not a Connection Error, so the decoder should continue */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_headers_illegal_name) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 10,                 /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - indexed name, uncompressed value */
        0x40, 0x01, ',', 0x01, 'a',     /* ",: a" - literal name with illegal character */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_TRUE(frame->headers_malformed);

    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Message is malformed if server receives a response.
 * A malformed message is a Stream Error, not a Connection Error, so the decoder should continue */
H2_DECODER_ON_SERVER_TEST(h2_decoder_malformed_headers_response_to_server) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,               /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_TRUE(frame->headers_malformed);

    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Message is malformed if client cannot receive requests in HEADERS
 * (though they can get requests in PUSH_PROMISE frames).
 * A malformed message is a Stream Error, not a Connection Error, so the decoder should continue */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_headers_request_to_client) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x03,               /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x82,                           /* ":method: GET" - indexed */
        0x86,                           /* ":scheme: http" - indexed */
        0x84,                           /* ":path: /" - indexed */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 1 /*stream_id*/));
    ASSERT_TRUE(frame->headers_malformed);

    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Message is malformed if it contains both request and response pseudo-headers.
 * A malformed message is a Stream Error, not a Connection Error, so the decoder should continue */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_headers_mixed_pseudoheaders) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x06,               /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x82,                           /* ":method: GET" - REQUEST PSEUDO-HEADER */
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - RESPONSE PSEUDO-HEADER */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 1 /*stream_id*/));
    ASSERT_TRUE(frame->headers_malformed);

    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Message is malformed if pseudo-headers come after regular headers.
 * A malformed message is a Stream Error, not a Connection Error, so the decoder should continue */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_headers_late_pseudoheaders) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 11,                 /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x7a, 0x04, 't', 'e', 's', 't', /* "user-agent: test" - REGULAR HEADER */
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - PSEUDO-HEADER after regular header*/
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 1 /*stream_id*/));
    ASSERT_TRUE(frame->headers_malformed);

    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Message is malformed if trailing header does not end stream. */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_headers_trailer_must_end_stream) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,               /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS,     /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS - blank*/
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_TRUE(frame->headers_malformed);
    ASSERT_FALSE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Even if a header-block is malformed, we still process its fields, which may mutate the hpack tables. */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_header_continues_hpack_parsing) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* FRAME 1 - malformed HEADERS */
        0x00, 0x00, 15,                 /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS,     /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - stored to dynamic table */
        0x40, 0x01, ',', 0x01, 'a',     /* ",: a" - INVALID character - stored to dynamic table */
        0x40, 0x01, 'b', 0x01, 'c',     /* "b: c" - stored to dynamic table */

        /* So at this point dynamic table should look like:
         *  INDEX   NAME    VALUE
         *  62      b       c
         *  63      ,       a
         *  64      :status 302
         */

        /* FRAME 2 - valid HEADERS referencing entry from malformed HEADERS */
        0x00, 0x00, 2,                  /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,         /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS,     /* Flags (8) */
        0x00, 0x00, 0x00, 0x03,         /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0xc0,                           /* ":status: 302" - indexed from dynamic table */
        0xbe,                           /* "b: c" - indexed from dynamic table */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    ASSERT_UINT_EQUALS(2, h2_decode_tester_frame_count(&fixture->decode));

    /* frame 1 should be malformed */
    struct h2_decoded_frame *frame = h2_decode_tester_get_frame(&fixture->decode, 0);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 1 /*stream_id*/));
    ASSERT_TRUE(frame->headers_malformed);

    /* frame 2 should be able to index fields stored by previous malformed frame */
    frame = h2_decode_tester_get_frame(&fixture->decode, 1);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 3 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(2, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "b", "c", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);

    return AWS_OP_SUCCESS;
}

/* Test CONTINUATION frame.
 * Decoder requires that a HEADERS or PUSH_PROMISE frame be sent first */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_continuation) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x09,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x58, 0x07, 'p', 'r', 'i', 'v', 'a', 't', 'e', /* "cache-control: private" */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(2, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "cache-control", "private", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Try setting ALL the flags on CONTINUATION frame.
 * Only END_HEADERS and should trigger.
 * Continuation doesn't support PRIORITY and PADDING like HEADERS does, so they should just be ignored */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_continuation_ignores_unknown_flags) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        0x0, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x09,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        0xFF,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x58, 0x07, 'p', 'r', 'i', 'v', 'a', 't', 'e', /* "cache-control: private" */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(2, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "cache-control", "private", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    return AWS_OP_SUCCESS;
}

/* Test that we an handle a header-field whose encoding is spread across multiple frames.
 * Throw some padding in to make it extra complicated */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_continuation_header_field_spans_frames) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x06,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_PADDED,      /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x48, 0x03, '3',            /* ":status: 302" - beginning 3/5 bytes encoded in this frame. */
        0x00, 0x00,                 /* Padding (*)                              - F_PADDED */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x02,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        '0', '2',                   /* :status: 302" - last 2/5 bytes encoded in this frame*/
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    ASSERT_FALSE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Test having multiple CONTINUATION frames in a row */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_continuation_many_frames) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x09,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x58, 0x07, 'p', 'r', 'i', 'v', 'a', 't', 'e', /* "cache-control: private" */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x40, 0x02, 'h', 'i', 0x03, 'm', 'o', 'm', /* "hi: mom" */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(3, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "cache-control", "private", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 2, "hi", "mom", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Test having HEADERS and CONTINUATION frames with empty header-block-fragments */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_continuation_empty_payloads) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(1, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_INT_EQUALS(AWS_HTTP_HEADER_BLOCK_MAIN, frame->header_block_type);
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Once a header-block starts, it's illegal for any frame but a CONTINUATION on that same stream to arrive.
 * This test sends a different frame type next */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_continuation_frame_expected) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */

        /* HEADERS FRAME*/
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x12,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Once a header-block starts, it's illegal for any frame but a CONTINUATION on that same stream to arrive.
 * This test sends a different stream-id next */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_continuation_frame_same_stream_expected) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x09,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x12,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x58, 0x07, 'p', 'r', 'i', 'v', 'a', 't', 'e', /* "cache-control: private" */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* It's an error for a header-block to end with a partially decoded header-field */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_partial_header) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x03,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x48, 0x03, '3',            /* ":status: 302" - Note that final 2 characters are not encoded */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_COMPRESSION_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Ensure that random HPACK decoding errors are reported as ERROR_COMPRESSION */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_bad_hpack_data) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 32,             /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* indexed header field, with index bigger than 64bits */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_COMPRESSION_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test PRIORITY frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_priority) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_PRIORITY,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PRIORITY */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31) */
        0x09,                       /* Weight (8)                             */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Our implementation currently chooses to ignore PRIORITY frames, so no callbacks should have fired */
    ASSERT_UINT_EQUALS(0, h2_decode_tester_frame_count(&fixture->decode));
    return AWS_OP_SUCCESS;
}

/* Unknown flags should be ignored. PRIORITY frames don't have any flags. */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_priority_ignores_unknown_flags) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_PRIORITY,    /* Type (8) */
        0xFF,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PRIORITY */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31) */
        0x09,                       /* Weight (8)                             */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Our implementation currently chooses to ignore PRIORITY frames, so no callbacks should have fired */
    ASSERT_UINT_EQUALS(0, h2_decode_tester_frame_count(&fixture->decode));
    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_priority_requires_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_PRIORITY,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* PRIORITY */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31) */
        0x09,                       /* Weight (8)                             */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test PRIORITY frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_priority_payload_too_small) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_PRIORITY,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PRIORITY */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31) */
                                    /* Weight (8)                             */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test PRIORITY frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_priority_payload_too_large) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x06,           /* Length (24) */
        AWS_H2_FRAME_T_PRIORITY,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* PRIORITY */
        0x81, 0x23, 0x45, 0x67,     /* Exclusive (1) | Stream Dependency (31) */
        0x09,                       /* Weight (8)                             */
        0x00,                       /* TOO MUCH PAYLOAD*/
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test RST_STREAM frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_rst_stream) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_RST_STREAM,  /* Type (8) */
        0x00,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* RST_STREAM */
        0xFF, 0xEE, 0xDD, 0xCC,     /* Error Code (32) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    ASSERT_UINT_EQUALS(1, h2_decode_tester_frame_count(&fixture->decode));
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_RST_STREAM, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(0xFFEEDDCC, frame->error_code);
    return AWS_OP_SUCCESS;
}

/* Unknown flags should be ignored. RST_STREAM frame doesn't support any flags */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_rst_stream_ignores_unknown_flags) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_RST_STREAM,  /* Type (8) */
        0xFF,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* RST_STREAM */
        0xFF, 0xEE, 0xDD, 0xCC,     /* Error Code (32) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    ASSERT_UINT_EQUALS(1, h2_decode_tester_frame_count(&fixture->decode));
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_RST_STREAM, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(0xFFEEDDCC, frame->error_code);
    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_rst_stream_requires_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_RST_STREAM,  /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* RST_STREAM */
        0xFF, 0xEE, 0xDD, 0xCC,     /* Error Code (32) */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Payload must be 4 bytes exactly */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_rst_stream_payload_too_small) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x03,           /* Length (24) */
        AWS_H2_FRAME_T_RST_STREAM,  /* Type (8) */
        0x00,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* RST_STREAM */
        0xFF, 0xEE, 0xDD,           /* Error Code (32) <-- missing one byte */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Payload must be 4 bytes exactly */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_rst_stream_payload_too_large) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_RST_STREAM,  /* Type (8) */
        0x00,                       /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* RST_STREAM */
        0xFF, 0xEE, 0xDD, 0xCC,     /* Error Code (32) */
        0x00,                       /* TOO MUCH PAYLOAD */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test SETTINGS frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_settings) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 12,             /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x05,                 /* Identifier (16) */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) */
        0x00, 0x02,                 /* Identifier (16) */
        0x00, 0x00, 0x00, 0x01,     /* Value (32) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, h2_decode_tester_frame_count(&fixture->decode));
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    ASSERT_FALSE(frame->ack);
    ASSERT_UINT_EQUALS(2, aws_array_list_length(&frame->settings));

    struct aws_http2_setting setting;
    aws_array_list_get_at(&frame->settings, &setting, 0);
    ASSERT_UINT_EQUALS(0x0005, setting.id);
    ASSERT_UINT_EQUALS(0x00FFFFFF, setting.value);

    aws_array_list_get_at(&frame->settings, &setting, 1);
    ASSERT_UINT_EQUALS(0x0002, setting.id);
    ASSERT_UINT_EQUALS(0x00000001, setting.value);

    return AWS_OP_SUCCESS;
}

/* Test SETTINGS frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_settings_empty) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, h2_decode_tester_frame_count(&fixture->decode));
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    ASSERT_FALSE(frame->ack);
    ASSERT_UINT_EQUALS(0, aws_array_list_length(&frame->settings));

    return AWS_OP_SUCCESS;
}

/* SETTINGS frame with ACK flag set */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_settings_ack) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        AWS_H2_FRAME_F_ACK,         /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, h2_decode_tester_frame_count(&fixture->decode));
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    ASSERT_TRUE(frame->ack);
    ASSERT_UINT_EQUALS(0, aws_array_list_length(&frame->settings));

    return AWS_OP_SUCCESS;
}

/* Decoder must ignore settings with unknown IDs */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_settings_ignores_unknown_ids) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 18,             /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x00,                 /* Identifier (16) <-- SHOULD IGNORE. 0 is invalid ID */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) */
        0x00, 0x01,                 /* Identifier (16) <-- This is OK */
        0x00, 0x00, 0x00, 0x01,     /* Value (32) */
        0x00, AWS_HTTP2_SETTINGS_END_RANGE, /* Identifier (16) <-- SHOULD IGNORE */
        0x00, 0x00, 0x00, 0x01,     /* Value (32) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, h2_decode_tester_frame_count(&fixture->decode));
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    ASSERT_FALSE(frame->ack);
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&frame->settings));

    struct aws_http2_setting setting;
    aws_array_list_get_at(&frame->settings, &setting, 0);
    ASSERT_UINT_EQUALS(0x0001, setting.id);
    ASSERT_UINT_EQUALS(0x00000001, setting.value);

    return AWS_OP_SUCCESS;
}

/* Unexpected flags should be ignored.
 * SETTINGS frames only support ACK */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_settings_ignores_unknown_flags) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0xFF,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, h2_decode_tester_frame_count(&fixture->decode));
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    ASSERT_TRUE(frame->ack);
    ASSERT_UINT_EQUALS(0, aws_array_list_length(&frame->settings));

    return AWS_OP_SUCCESS;
}

/* Error if SETTINGS ACK frame has any individual settings in it */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_settings_ack_with_data) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x06,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        AWS_H2_FRAME_F_ACK,         /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x05,                 /* Identifier (16) */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_settings_forbids_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 12,             /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x05,                 /* Identifier (16) */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) */
        0x00, 0x02,                 /* Identifier (16) */
        0x00, 0x00, 0x00, 0x01,     /* Value (32) */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Error if SETTINGS payload is not a multiple of 6 */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_settings_payload_size) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x05,                 /* Identifier (16) */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) */
        0x00, 0x02,                 /* Identifier (16) */
                                    /* Value (32) <-- MISSING */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Error if SETTINGS has invalid values */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_settings_invalid_values_enable_push) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 12,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x05,                 /* Identifier (16) */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) */
        0x00, 0x02,                 /* Identifier (16) */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) <-- INVALID value FOR ENABLE_PUSH */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_settings_invalid_values_initial_window_size) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 12,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x05,                 /* Identifier (16) */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) */
        0x00, 0x04,                 /* Identifier (16) */
        0x80, 0xFF, 0xFF, 0xFF,     /* Value (32) <-- INVALID value FOR INITIAL_WINDOW_SIZE */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FLOW_CONTROL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_settings_invalid_values_max_frame_size) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 12,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* SETTINGS */
        0x00, 0x05,                 /* Identifier (16) */
        0x00, 0xFF, 0xFF, 0xFF,     /* Value (32) */
        0x00, 0x05,                 /* Identifier (16) */
        0x00, 0x00, 0x00, 0x00,     /* Value (32) <-- INVALID value FOR MAX_FRAME_SIZE */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_push_promise) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x07,           /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE */
        0x80, 0x00, 0x00, 0x02,     /* Reserved (1) | Promised Stream ID (31) */
        0x82,                       /* ":method: GET" - indexed header field */
        0x87,                       /* ":scheme: https" - indexed header field */
        0x85,                       /* ":path: /index.html" - indexed header field */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_PUSH_PROMISE, 0x1 /*stream_id*/));
    ASSERT_UINT_EQUALS(2, frame->promised_stream_id);
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(3, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":method", "GET", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, ":scheme", "https", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 2, ":path", "/index.html", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_FALSE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Unknown flags should be ignored.
 * PUSH_PROMISE supports END_HEADERS and PADDED */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_push_promise_ignores_unknown_flags) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 10,             /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        0xFF,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x00, 0x00, 0x00, 0x02,     /* Reserved (1) | Promised Stream ID (31) */
        0x82,                       /* ":method: GET" - indexed header field */
        0x87,                       /* ":scheme: https" - indexed header field */
        0x85,                       /* ":path: /index.html" - indexed header field */
        0x00, 0x00,                 /* Padding (*)                              - F_PADDED */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_PUSH_PROMISE, 0x1 /*stream_id*/));
    ASSERT_UINT_EQUALS(2, frame->promised_stream_id);
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(3, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":method", "GET", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, ":scheme", "https", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 2, ":path", "/index.html", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_FALSE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_push_promise_continuation) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* PUSH_PROMISE FRAME */
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        AWS_H2_FRAME_F_PADDED,      /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x02,                       /* Pad Length (8)                           - F_PADDED */
        0x00, 0x00, 0x00, 0x02,     /* Reserved (1) | Promised Stream ID (31) */
        0x82,                       /* ":method: GET" - indexed header field */
        0x00, 0x00,                 /* Padding (*)                              - F_PADDED */

        /* CONTINUATION FRAME - empty payload just for kicks */
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */


        /* CONTINUATION FRAME */
        0x00, 0x00, 0x02,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x87,                       /* ":scheme: https" - indexed header field */
        0x85,                       /* ":path: /index.html" - indexed header field */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_PUSH_PROMISE, 0x1 /*stream_id*/));
    ASSERT_UINT_EQUALS(2, frame->promised_stream_id);
    ASSERT_FALSE(frame->headers_malformed);
    ASSERT_UINT_EQUALS(3, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":method", "GET", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, ":scheme", "https", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 2, ":path", "/index.html", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_FALSE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Once a header-block starts, it's illegal for any frame but a CONTINUATION on that same stream to arrive.
 * This test sends a different frame type next */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_push_promise_continuation_expected) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* PUSH_PROMISE FRAME */
        0x00, 0x00, 0x07,           /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PAYLOAD */
        0x00, 0x00, 0x00, 0x02,     /* Reserved (1) | Promised Stream ID (31) */
        0x82,                       /* ":method: GET" - indexed header field */
        0x87,                       /* ":scheme: https" - indexed header field */
        0x85,                       /* ":path: /index.html" - indexed header field */

        /* DATA FRAME <-- ERROR should be CONTINUATION because PUSH_PROMISE lacked END_HEADERS flag */
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x00, 0x00, 0x00, 0x02,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
        'h', 'e', 'l', 'l', 'o',    /* Data (*) */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_push_promise_requires_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x07,           /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE */
        0x00, 0x00, 0x00, 0x02,     /* Reserved (1) | Promised Stream ID (31) */
        0x82,                       /* ":method: GET" - indexed header field */
        0x87,                       /* ":scheme: https" - indexed header field */
        0x85,                       /* ":path: /index.html" - indexed header field */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_push_promise_must_be_request_1) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x09,               /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,    /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS,     /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,         /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE */
        0x00, 0x00, 0x00, 0x02,         /* Reserved (1) | Promised Stream ID (31) */
        0x48, 0x03, '3', '0', '2',      /* ":status: 302" - RESPONSE pseudo-header is incorrect */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_PUSH_PROMISE, 1 /*stream_id*/));
    ASSERT_UINT_EQUALS(2, frame->promised_stream_id);
    ASSERT_TRUE(frame->headers_malformed);
    return AWS_OP_SUCCESS;
}

/* Malformed if PUSH_PROMISE missing request pseudo-headers */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_malformed_push_promise_must_be_request_2) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x04,               /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,    /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS,     /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,         /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE  */
        0x00, 0x00, 0x00, 0x02,         /* Reserved (1) | Promised Stream ID (31) */
                                        /* No headers */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_PUSH_PROMISE, 1 /*stream_id*/));
    ASSERT_UINT_EQUALS(2, frame->promised_stream_id);
    ASSERT_TRUE(frame->headers_malformed);
    return AWS_OP_SUCCESS;
}

/* Promised stream ID must be valid */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_push_promise_requires_promised_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x07,           /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Promised Stream ID (31) */
        0x82,                       /* ":method: GET" - indexed header field */
        0x87,                       /* ":scheme: https" - indexed header field */
        0x85,                       /* ":path: /index.html" - indexed header field */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Promised stream will be invalid, if enable_push is set to 0 */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_push_promise_with_enable_push_0) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x07,           /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PUSH_PROMISE */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Promised Stream ID (31) */
        0x82,                       /* ":method: GET" - indexed header field */
        0x87,                       /* ":scheme: https" - indexed header field */
        0x85,                       /* ":path: /index.html" - indexed header field */
    };
    /* clang-format on */
    aws_h2_decoder_set_setting_enable_push(fixture->decode.decoder, (uint32_t)0);
    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test PING frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_ping) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* PING */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g' /* Opaque Data (64) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_PING, 0x0 /*stream_id*/));
    ASSERT_BIN_ARRAYS_EQUALS("pingpong", AWS_HTTP2_PING_DATA_SIZE, frame->ping_opaque_data, AWS_HTTP2_PING_DATA_SIZE);
    ASSERT_FALSE(frame->ack);
    return AWS_OP_SUCCESS;
}

/* Test PING frame with ALL flags set (ACK is only supported flag) */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_ping_ack) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0xFF,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* PING */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g' /* Opaque Data (64) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_PING, 0x0 /*stream_id*/));
    ASSERT_BIN_ARRAYS_EQUALS("pingpong", AWS_HTTP2_PING_DATA_SIZE, frame->ping_opaque_data, AWS_HTTP2_PING_DATA_SIZE);
    ASSERT_TRUE(frame->ack);
    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_ping_forbids_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* PING */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g' /* Opaque Data (64) */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* PING payload MUST be 8 bytes */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_ping_payload_too_small) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* PING */
                                    /* Opaque Data (64) <-- MISSING */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* PING payload MUST be 8 bytes */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_ping_payload_too_large) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x09,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* PING */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g', 0x00 /* Opaque Data (64) <-- ERROR: TOO LARGE */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test GOAWAY frame */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_goaway) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 11,             /* Length (24) */
        AWS_H2_FRAME_T_GOAWAY,      /* Type (8) */
        0xFF,                       /* Flags (8) <-- set all flags, all of which should be ignored */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* GOAWAY */
        0xFF, 0x00, 0x00, 0x01,     /* Reserved (1) | Last Stream ID (31) */
        0xFE, 0xED, 0xBE, 0xEF,     /* Error Code (32) */
        'b', 'y', 'e'               /* Additional Debug Data (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_GOAWAY, 0x0 /*stream_id*/));
    ASSERT_UINT_EQUALS(0x7F000001, frame->goaway_last_stream_id);
    ASSERT_UINT_EQUALS(0xFEEDBEEF, frame->error_code);
    ASSERT_BIN_ARRAYS_EQUALS("bye", 3, frame->data.buffer, frame->data.len);

    return AWS_OP_SUCCESS;
}

/* Test GOAWAY frame with no debug data */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_goaway_empty) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_GOAWAY,      /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* GOAWAY */
        0xFF, 0x00, 0x00, 0x01,     /* Reserved (1) | Last Stream ID (31) */
        0xFE, 0xED, 0xBE, 0xEF,     /* Error Code (32) */
                                    /* Additional Debug Data (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_GOAWAY, 0x0 /*stream_id*/));
    ASSERT_UINT_EQUALS(0x7F000001, frame->goaway_last_stream_id);
    ASSERT_UINT_EQUALS(0xFEEDBEEF, frame->error_code);
    ASSERT_BIN_ARRAYS_EQUALS("", 0, frame->data.buffer, frame->data.len);

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_goaway_forbids_stream_id) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 11,             /* Length (24) */
        AWS_H2_FRAME_T_GOAWAY,      /* Type (8) */
        0xFF,                       /* Flags (8) <-- set all flags, all of which should be ignored */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* GOAWAY */
        0xFF, 0x00, 0x00, 0x01,     /* Reserved (1) | Last Stream ID (31) */
        0xFE, 0xED, 0xBE, 0xEF,     /* Error Code (32) */
        'b', 'y', 'e'               /* Additional Debug Data (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_goaway_payload_too_small) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_GOAWAY,      /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* GOAWAY */
                                    /* Reserved (1) | Last Stream ID (31) <-- MISSING */
                                    /* Error Code (32)                    <-- MISSING */
                                    /* Additional Debug Data (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test WINDOW_UPDATE frame on stream 0 */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_window_update_connection) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_WINDOW_UPDATE,/* Type (8) */
        0xFF,                       /* Flags (8) <-- set all flags, all of which should be ignored */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* WINDOW_UPDATE */
        0xFF, 0x00, 0x00, 0x01,     /* Reserved (1) | Window Size Increment (31) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_WINDOW_UPDATE, 0x0 /*stream_id*/));
    ASSERT_UINT_EQUALS(0x7F000001, frame->window_size_increment);

    return AWS_OP_SUCCESS;
}

/* Test WINDOW_UPDATE frame on a specific stream.
 * This the only frame type whose stream-id can be zero OR non-zero*/
H2_DECODER_ON_CLIENT_TEST(h2_decoder_window_update_stream) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_WINDOW_UPDATE,/* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* WINDOW_UPDATE */
        0xFF, 0x00, 0x00, 0x01,     /* Reserved (1) | Window Size Increment (31) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(&fixture->decode);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(frame, AWS_H2_FRAME_T_WINDOW_UPDATE, 0x1 /*stream_id*/));
    ASSERT_UINT_EQUALS(0x7F000001, frame->window_size_increment);

    return AWS_OP_SUCCESS;
}

/* WINDOW_UPDATE payload must always be 4 bytes */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_window_update_payload_too_small) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_WINDOW_UPDATE,/* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* WINDOW_UPDATE */
                                    /* Reserved (1) | Window Size Increment (31) <-- MISSING */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* WINDOW_UPDATE payload must always be 4 bytes */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_err_window_update_payload_too_large) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_WINDOW_UPDATE,/* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* WINDOW_UPDATE */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Window Size Increment (31) */
        0x00, 0x00, 0x00, 0x02,     /* ERROR TOO BIG */
    };
    /* clang-format on */

    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_FRAME_SIZE_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Frames of unknown type must be ignored */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_unknown_frame_type_ignored) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* UNKNOWN FRAME WITHOUT FLAGS OR STREAM-ID */
        0x00, 0x00, 0x04,           /* Length (24) */
        0xFF,                       /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        0xFF, 0xFF, 0xFF, 0xFF,     /* Payload (*) */

        /* UNKNOWN FRAME WITH FLAGS AND STREAM-ID */
        0x00, 0x00, 0x04,           /* Length (24) */
        0xFF,                       /* Type (8) */
        0xFF,                       /* Flags (8) */
        0xFF, 0xFF, 0xFF, 0xFF,     /* Reserved (1) | Stream Identifier (31) */
        0xFF, 0xFF, 0xFF, 0xFF,     /* Payload (*) */

        /* UNKNOWN FRAME WITH NO PAYLOAD */
        0x00, 0x00, 0x00,           /* Length (24) */
        0xFF,                       /* Type (8) */
        0xFF,                       /* Flags (8) */
        0xFF, 0xFF, 0xFF, 0xFF,     /* Reserved (1) | Stream Identifier (31) */
                                    /* Payload (*) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* No callbacks should have fired about any of these frames */
    ASSERT_UINT_EQUALS(0, h2_decode_tester_frame_count(&fixture->decode));
    return AWS_OP_SUCCESS;
}

static int s_get_finished_frame_i(
    struct fixture *fixture,
    size_t i,
    enum aws_h2_frame_type type,
    uint32_t stream_id,
    struct h2_decoded_frame **out_frame) {

    ASSERT_TRUE(i < h2_decode_tester_frame_count(&fixture->decode));
    *out_frame = h2_decode_tester_get_frame(&fixture->decode, i);
    ASSERT_SUCCESS(h2_decoded_frame_check_finished(*out_frame, type, stream_id));
    return AWS_OP_SUCCESS;
}

/* Test processing many different frame types in a row.
 * (most other tests just operate on 1 frame) */
H2_DECODER_ON_CLIENT_TEST(h2_decoder_many_frames_in_a_row) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* HEADERS FRAME*/
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        0x48, 0x03, '3', '0', '2',  /* ":status: 302" - indexed name, uncompressed value */

        /* CONTINUATION FRAME*/
        0x00, 0x00, 0x09,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        0x58, 0x07, 'p', 'r', 'i', 'v', 'a', 't', 'e', /* "cache-control: private" */

        /* SETTINGS ACK FRAME*/
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        AWS_H2_FRAME_F_ACK,         /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */

        /* PUSH_PROMISE FRAME */
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_PUSH_PROMISE,/* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        0x80, 0x00, 0x00, 0x02,     /* Reserved (1) | Promised Stream ID (31) */
        0x82,                       /* ":method: GET" - indexed header field */

        /* CONTINUATION FRAME */
        0x00, 0x00, 0x02,           /* Length (24) */
        AWS_H2_FRAME_T_CONTINUATION,/* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        0x87,                       /* ":scheme: https" - indexed header field */
        0x85,                       /* ":path: /index.html" - indexed header field */

        /* PRIORITY FRAME */
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_PRIORITY,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        0x00, 0x00, 0x00, 0x02,     /* Exclusive (1) | Stream Dependency (31) */
        0x09,                       /* Weight (8)                             */

        /* WINDOW_UPDATE FRAME */
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_WINDOW_UPDATE,/* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* WINDOW_UPDATE */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Window Size Increment (31) */

        /* DATA FRAME */
        0x00, 0x00, 0x01,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        AWS_H2_FRAME_F_END_STREAM,  /* Flags (8) */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        'h',                        /* Data (*) */

        /* UNKNOWN FRAME */
        0x00, 0x00, 0x01,           /* Length (24) */
        0xFF,                       /* Type (8) */
        0xFF,                       /* Flags (8) */
        0xFF, 0xFF, 0xFF, 0xFF,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload (*) */
        'z',

        /* RST_STREAM FRAME */
        0x00, 0x00, 0x04,           /* Length (24) */
        AWS_H2_FRAME_T_RST_STREAM,  /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x02,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        0xFF, 0xEE, 0xDD, 0xCC,     /* Error Code (32) */

        /* GOAWAY FRAME */
        0x00, 0x00, 11,             /* Length (24) */
        AWS_H2_FRAME_T_GOAWAY,      /* Type (8) */
        0xFF,                       /* Flags (8) <-- set all flags, all of which should be ignored */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        0x00, 0x00, 0x00, 0x01,     /* Reserved (1) | Last Stream ID (31) */
        0xFE, 0xED, 0xBE, 0xEF,     /* Error Code (32) */
        'b', 'y', 'e',              /* Additional Debug Data (*) */

        /* PING ACK FRAME */
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        AWS_H2_FRAME_F_ACK,         /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g', /* Opaque Data (64) */
    };
    /* clang-format on */

    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    size_t frame_i = 0;
    struct h2_decoded_frame *frame;

    /* Validate HEADERS (and its CONTINUATION) */
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, frame_i++, AWS_H2_FRAME_T_HEADERS, 0x1 /*stream-id*/, &frame));
    ASSERT_UINT_EQUALS(2, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "cache-control", "private", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_FALSE(frame->end_stream);

    /* Validate SETTINGS ACK */
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, frame_i++, AWS_H2_FRAME_T_SETTINGS, 0x0 /*stream-id*/, &frame));
    ASSERT_TRUE(frame->ack);

    /* Validate PUSH_PROMISE (and its CONTINUATION) */
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, frame_i++, AWS_H2_FRAME_T_PUSH_PROMISE, 0x1 /*stream-id*/, &frame));
    ASSERT_UINT_EQUALS(2, frame->promised_stream_id);
    ASSERT_UINT_EQUALS(3, aws_http_headers_count(frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":method", "GET", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 1, ":scheme", "https", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_SUCCESS(s_check_header(frame, 2, ":path", "/index.html", AWS_HTTP_HEADER_COMPRESSION_USE_CACHE));
    ASSERT_FALSE(frame->end_stream);

    /* PRIORITY frame is ignored by decoder */

    /* Validate WINDOW_UPDATE */
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, frame_i++, AWS_H2_FRAME_T_WINDOW_UPDATE, 0x0 /*stream-id*/, &frame));
    ASSERT_UINT_EQUALS(0x1, frame->window_size_increment);

    /* Validate DATA */
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, frame_i++, AWS_H2_FRAME_T_DATA, 0x1 /*stream-id*/, &frame));
    ASSERT_BIN_ARRAYS_EQUALS("h", 1, frame->data.buffer, frame->data.len);
    ASSERT_TRUE(frame->end_stream);

    /* UNKNOWN frame is ignored */

    /* Validate RST_STREAM */
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, frame_i++, AWS_H2_FRAME_T_RST_STREAM, 0x2 /*stream-id*/, &frame));
    ASSERT_UINT_EQUALS(0xFFEEDDCC, frame->error_code);

    /* Validate GOAWAY */
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, frame_i++, AWS_H2_FRAME_T_GOAWAY, 0x0 /*stream-id*/, &frame));
    ASSERT_UINT_EQUALS(0x1, frame->goaway_last_stream_id);
    ASSERT_UINT_EQUALS(0xFEEDBEEF, frame->error_code);
    ASSERT_BIN_ARRAYS_EQUALS("bye", 3, frame->data.buffer, frame->data.len);

    /* Validate PING */
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, frame_i++, AWS_H2_FRAME_T_PING, 0x0 /*stream-id*/, &frame));
    ASSERT_TRUE(frame->ack);

    /* Ensure no further frames reported */
    ASSERT_UINT_EQUALS(frame_i, h2_decode_tester_frame_count(&fixture->decode));

    return AWS_OP_SUCCESS;
}

/* Test that client can decode a proper connection preface sent by the server.
 * A server connection preface is just a settings frame */
H2_DECODER_ON_CLIENT_PREFACE_TEST(h2_decoder_preface_from_server) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* SETTINGS FRAME - empty settings frame is acceptable in preface */
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */

        /* PING FRAME - send another frame to be sure decoder is now functioning normally */
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g' /* Opaque Data (64) */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    ASSERT_UINT_EQUALS(2, h2_decode_tester_frame_count(&fixture->decode));

    struct h2_decoded_frame *frame;
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, 0, AWS_H2_FRAME_T_SETTINGS, 0 /*stream-id*/, &frame));
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, 1, AWS_H2_FRAME_T_PING, 0 /*stream-id*/, &frame));

    return AWS_OP_SUCCESS;
}

/* The server must send a SETTINGS frame first.
 * It's an error to send any other frame type */
H2_DECODER_ON_CLIENT_PREFACE_TEST(h2_decoder_err_bad_preface_from_server_1) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* PING FRAME - but should be SETTINGS */
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g' /* Opaque Data (64) */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* The server must send a SETTINGS frame first.
 * It's an error if SETTINGS frame is an ACK */
H2_DECODER_ON_CLIENT_PREFACE_TEST(h2_decoder_err_bad_preface_from_server_2) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* SETTINGS FRAME */
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        AWS_H2_FRAME_F_ACK,         /* Flags (8) <-- Preface SETTINGS should not have ACK */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* The server mustn't send the "client connection preface string" */
H2_DECODER_ON_CLIENT_PREFACE_TEST(h2_decoder_err_bad_preface_from_server_3) {
    (void)allocator;
    struct fixture *fixture = ctx;

    const struct aws_byte_cursor input = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

    /* Decode */
    ASSERT_H2ERR_ERROR(AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, input));

    return AWS_OP_SUCCESS;
}

/* Test that client can decode a proper connection preface sent by the client. */
H2_DECODER_ON_SERVER_PREFACE_TEST(h2_decoder_preface_from_client) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* Client connection preface string */
        'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n','\r','\n','S','M','\r','\n','\r','\n',

        /* SETTINGS FRAME - empty settings frame is acceptable in preface */
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */

        /* PING FRAME - send another frame to be sure decoder is now functioning normally */
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g' /* Opaque Data (64) */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    ASSERT_UINT_EQUALS(2, h2_decode_tester_frame_count(&fixture->decode));

    struct h2_decoded_frame *frame;
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, 0, AWS_H2_FRAME_T_SETTINGS, 0 /*stream-id*/, &frame));
    ASSERT_SUCCESS(s_get_finished_frame_i(fixture, 1, AWS_H2_FRAME_T_PING, 0 /*stream-id*/, &frame));

    return AWS_OP_SUCCESS;
}

/* Should fail because we're not sending the "client connection preface string" */
H2_DECODER_ON_SERVER_PREFACE_TEST(h2_decoder_err_bad_preface_from_client_1) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* SETTINGS FRAME - empty settings frame is acceptable in preface */
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Should fail because we're sending something different from (and shorter than) "client connection preface string" */
H2_DECODER_ON_SERVER_PREFACE_TEST(h2_decoder_err_bad_preface_from_client_2) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* This is the shortest valid HTTP query I can come up with */
    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("GET / HTTP/1.0\r\n\r\n");

    /* Decode */
    ASSERT_H2ERR_ERROR(AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, input));

    return AWS_OP_SUCCESS;
}

/* Should fail because we're not sending SETTINGS as the first frame */
H2_DECODER_ON_SERVER_PREFACE_TEST(h2_decoder_err_bad_preface_from_client_3) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        /* Client connection preface string */
        'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n','\r','\n','S','M','\r','\n','\r','\n',

        /* PING FRAME - but should be SETTINGS */
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* Payload */
        'p', 'i', 'n', 'g', 'p', 'o', 'n', 'g' /* Opaque Data (64) */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_H2ERR_ERROR(
        AWS_HTTP2_ERR_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}
