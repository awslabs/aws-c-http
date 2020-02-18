/*
 * Copyright 2010-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/http/private/h2_decoder.h>

/* Information gathered about a given frame from decoder callbacks.
 * These aren't 1:1 with literal H2 frames:
 * - The decoder hides the existence of CONTINUATION frames,
 *   their data continues the preceding HEADERS or PUSH_PROMISE frame.
 *
 * - A DATA frame could appear as N on_data callbacks.
 *
 * - The on_end_stream callback fires after all other callbacks for that frame,
 *   so we count it as part of the preceding "finished" frame.
 */
struct frame {
    enum aws_h2_frame_type type;
    uint32_t stream_id;

    /* If true, we expect no further callbacks regarding this frame */
    bool finished;

    struct aws_array_list headers;  /* contains aws_h2_frame_header_field */
    struct aws_array_list settings; /* contains aws_h2_frame_setting */
    struct aws_byte_buf data;

    bool end_stream;
    uint32_t error_code;
    uint32_t promised_stream_id;
    bool ack;
    uint32_t goaway_last_stream_id;
    uint32_t goaway_debug_data_remaining;
    uint8_t ping_opaque_data[AWS_H2_PING_DATA_SIZE];
    uint32_t window_size_increment;
};

struct fixture {
    struct aws_allocator *allocator;
    struct aws_h2_decoder *decoder;
    struct aws_array_list frames; /* contains frame */

    bool one_byte_at_a_time;
};

static int s_frame_init(
    struct frame *frame,
    struct aws_allocator *allocator,
    enum aws_h2_frame_type type,
    uint32_t stream_id) {
    AWS_ZERO_STRUCT(*frame);
    frame->type = type;
    frame->stream_id = stream_id;
    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&frame->headers, allocator, 16, sizeof(struct aws_h2_frame_header_field)));
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&frame->settings, allocator, 16, sizeof(struct aws_h2_frame_setting)));
    ASSERT_SUCCESS(aws_byte_buf_init(&frame->data, allocator, 1024));
    return AWS_OP_SUCCESS;
}

static void s_frame_clean_up(struct frame *frame) {
    aws_array_list_clean_up(&frame->headers);
    aws_array_list_clean_up(&frame->settings);
    aws_byte_buf_clean_up(&frame->data);
}

static int s_validate_finished_frame(struct frame *frame, enum aws_h2_frame_type type, uint32_t stream_id) {
    ASSERT_INT_EQUALS(type, frame->type);
    ASSERT_UINT_EQUALS(stream_id, frame->stream_id);
    ASSERT_TRUE(frame->finished);
    return AWS_OP_SUCCESS;
}

static struct frame *s_latest_frame(struct fixture *fixture) {
    AWS_FATAL_ASSERT(aws_array_list_length(&fixture->frames) > 0);
    struct frame *frame = NULL;
    aws_array_list_get_at_ptr(&fixture->frames, (void **)&frame, aws_array_list_length(&fixture->frames) - 1);
    return frame;
}

/* fixture begins recording a new frame's data */
static int s_begin_new_frame(
    struct fixture *fixture,
    enum aws_h2_frame_type type,
    uint32_t stream_id,
    struct frame **out_frame) {

    /* If there's a previous frame, assert that we know it was finished.
     * If this fails, some on_X_begin(), on_X_i(), on_X_end() loop didn't fire correctly.
     * It should be impossible for an unrelated callback to fire during these loops */
    if (aws_array_list_length(&fixture->frames) > 0) {
        struct frame *prev_frame = s_latest_frame(fixture);
        ASSERT_TRUE(prev_frame->finished);
    }

    /* Create new frame */
    struct frame new_frame;
    ASSERT_SUCCESS(s_frame_init(&new_frame, fixture->allocator, type, stream_id));
    ASSERT_SUCCESS(aws_array_list_push_back(&fixture->frames, &new_frame));

    if (out_frame) {
        aws_array_list_get_at_ptr(&fixture->frames, (void **)out_frame, aws_array_list_length(&fixture->frames) - 1);
    }
    return AWS_OP_SUCCESS;
}

/* fixture stops recording the latest frame's data */
static int s_end_current_frame(struct fixture *fixture, enum aws_h2_frame_type type, uint32_t stream_id) {
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_FALSE(frame->finished);
    frame->finished = true;
    ASSERT_SUCCESS(s_validate_finished_frame(frame, type, stream_id));
    return AWS_OP_SUCCESS;
}

/**************************** DECODER CALLBACKS *******************************/

static int s_decoder_on_headers_begin(uint32_t stream_id, void *userdata) {
    struct fixture *fixture = userdata;
    ASSERT_SUCCESS(s_begin_new_frame(fixture, AWS_H2_FRAME_T_HEADERS, stream_id, NULL /*out_frame*/));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_headers_i(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_h2_header_field_hpack_behavior hpack_behavior,
    void *userdata) {

    struct fixture *fixture = userdata;
    struct frame *frame = s_latest_frame(fixture);

    /* validate */
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, frame->type);
    ASSERT_FALSE(frame->finished);
    ASSERT_UINT_EQUALS(frame->stream_id, stream_id);

    /* Stash header strings in frame->data.
     * DO NOT resize buffer or pointers will get messed up */
    struct aws_h2_frame_header_field header_field = {
        .header = *header,
        .hpack_behavior = hpack_behavior,
    };
    ASSERT_SUCCESS(aws_byte_buf_append_and_update(&frame->data, &header_field.header.name));
    ASSERT_SUCCESS(aws_byte_buf_append_and_update(&frame->data, &header_field.header.value));

    ASSERT_SUCCESS(aws_array_list_push_back(&frame->headers, &header_field));

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_headers_end(uint32_t stream_id, void *userdata) {
    struct fixture *fixture = userdata;
    ASSERT_SUCCESS(s_end_current_frame(fixture, AWS_H2_FRAME_T_HEADERS, stream_id));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_data(uint32_t stream_id, struct aws_byte_cursor data, void *userdata) {
    struct fixture *fixture = userdata;
    struct frame *frame;

    /* Pretend each on_data callback is a full DATA frame for the purposes of these tests */
    ASSERT_SUCCESS(s_begin_new_frame(fixture, AWS_H2_FRAME_T_DATA, stream_id, &frame));

    /* Stash data*/
    ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&frame->data, &data));

    ASSERT_SUCCESS(s_end_current_frame(fixture, AWS_H2_FRAME_T_DATA, stream_id));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_end_stream(uint32_t stream_id, void *userdata) {
    struct fixture *fixture = userdata;
    struct frame *frame = s_latest_frame(fixture);

    /* Validate */

    /* on_end_stream should fire IMMEDIATELY after on_data OR after on_headers_end.
     * This timing lets the user close the stream from this callback without waiting for any trailing data/headers */
    ASSERT_TRUE(frame->finished);
    ASSERT_TRUE(frame->type == AWS_H2_FRAME_T_HEADERS || frame->type == AWS_H2_FRAME_T_DATA);

    ASSERT_FALSE(frame->end_stream);

    /* Stash */
    frame->end_stream = true;

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_rst_stream(uint32_t stream_id, uint32_t error_code, void *userdata) {
    struct fixture *fixture = userdata;
    struct frame *frame;

    ASSERT_SUCCESS(s_begin_new_frame(fixture, AWS_H2_FRAME_T_RST_STREAM, stream_id, &frame));

    /* Stash data*/
    frame->error_code = error_code;

    ASSERT_SUCCESS(s_end_current_frame(fixture, AWS_H2_FRAME_T_RST_STREAM, stream_id));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_settings_begin(void *userdata) {
    struct fixture *fixture = userdata;
    struct frame *frame;
    ASSERT_SUCCESS(s_begin_new_frame(fixture, AWS_H2_FRAME_T_SETTINGS, 0, &frame));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_settings_i(uint16_t setting_id, uint32_t value, void *userdata) {
    struct fixture *fixture = userdata;
    struct frame *frame = s_latest_frame(fixture);

    /* Validate */
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_SETTINGS, frame->type);
    ASSERT_FALSE(frame->finished);

    /* Stash setting */
    struct aws_h2_frame_setting setting = {setting_id, value};
    ASSERT_SUCCESS(aws_array_list_push_back(&frame->settings, &setting));

    return AWS_OP_SUCCESS;
}

static int s_decoder_on_settings_end(void *userdata) {
    struct fixture *fixture = userdata;
    ASSERT_SUCCESS(s_end_current_frame(fixture, AWS_H2_FRAME_T_SETTINGS, 0));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_settings_ack(void *userdata) {
    struct fixture *fixture = userdata;
    struct frame *frame;

    ASSERT_SUCCESS(s_begin_new_frame(fixture, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/, &frame));

    /* Stash data*/
    frame->ack = true;

    ASSERT_SUCCESS(s_end_current_frame(fixture, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    return AWS_OP_SUCCESS;
}

static struct aws_h2_decoder_vtable s_decoder_vtable = {
    .on_headers_begin = s_decoder_on_headers_begin,
    .on_headers_i = s_decoder_on_headers_i,
    .on_headers_end = s_decoder_on_headers_end,
    .on_data = s_decoder_on_data,
    .on_end_stream = s_decoder_on_end_stream,
    .on_rst_stream = s_decoder_on_rst_stream,
    .on_settings_begin = s_decoder_on_settings_begin,
    .on_settings_i = s_decoder_on_settings_i,
    .on_settings_end = s_decoder_on_settings_end,
    .on_settings_ack = s_decoder_on_settings_ack,
};

/************************** END DECODER CALLBACKS *****************************/

static int s_fixture_setup(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);

    struct fixture *fixture = ctx;
    fixture->allocator = allocator;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&fixture->frames, allocator, 2, sizeof(struct frame)));

    struct aws_h2_decoder_params options = {
        .alloc = allocator,
        .vtable = &s_decoder_vtable,
        .userdata = fixture,
    };
    fixture->decoder = aws_h2_decoder_new(&options);
    ASSERT_NOT_NULL(fixture->decoder);

    return AWS_OP_SUCCESS;
}

static int s_fixture_teardown(struct aws_allocator *allocator, int setup_result, void *ctx) {
    (void)allocator;
    if (setup_result) {
        return AWS_OP_ERR;
    }

    struct fixture *fixture = ctx;
    for (size_t i = 0; i < aws_array_list_length(&fixture->frames); ++i) {
        struct frame *frame;
        aws_array_list_get_at_ptr(&fixture->frames, (void **)&frame, i);
        s_frame_clean_up(frame);
    }
    aws_array_list_clean_up(&fixture->frames);
    aws_h2_decoder_destroy(fixture->decoder);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* declare 1 test using the fixture */
#define TEST_CASE(NAME)                                                                                                \
    static struct fixture s_fixture_##NAME;                                                                            \
    AWS_TEST_CASE_FIXTURE(NAME, s_fixture_setup, s_test_##NAME, s_fixture_teardown, &s_fixture_##NAME);                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

/* declare 2 tests, where one of them runs the decoder on one byte of input at a time. */
#define TEST_CASE_ONE_BYTE_AT_A_TIME(NAME)                                                                             \
    static struct fixture s_fixture_##NAME;                                                                            \
    AWS_TEST_CASE_FIXTURE(NAME, s_fixture_setup, s_test_##NAME, s_fixture_teardown, &s_fixture_##NAME);                \
    static struct fixture s_fixture_##NAME##_one_byte_at_a_time = {.one_byte_at_a_time = true};                        \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        NAME##_one_byte_at_a_time,                                                                                     \
        s_fixture_setup,                                                                                               \
        s_test_##NAME,                                                                                                 \
        s_fixture_teardown,                                                                                            \
        &s_fixture_##NAME##_one_byte_at_a_time);                                                                       \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

/* Make sure fixture works */
TEST_CASE(h2_decoder_sanity_check) {
    (void)allocator;
    struct fixture *fixture = ctx;
    ASSERT_NOT_NULL(fixture);
    return AWS_OP_SUCCESS;
}

/* Run aws_h2_decode() on input. Decode the whole buffer at once, or decode it one byte at a time */
static int s_decode_all(struct fixture *fixture, struct aws_byte_cursor input) {
    if (fixture->one_byte_at_a_time) {
        while (input.len) {
            struct aws_byte_cursor one_byte = aws_byte_cursor_advance(&input, 1);
            if (aws_h2_decode(fixture->decoder, &one_byte)) {
                return AWS_OP_ERR;
            }
            ASSERT_UINT_EQUALS(0, one_byte.len);
        }

    } else {
        if (aws_h2_decode(fixture->decoder, &input)) {
            return AWS_OP_ERR;
        }
        ASSERT_UINT_EQUALS(0, input.len);
    }

    return AWS_OP_SUCCESS;
}

/* Compare data (which might be split across N frames) to expected string */
static int s_check_data_across_frames(
    struct fixture *fixture,
    uint32_t stream_id,
    const char *expected,
    bool expect_end_stream) {

    struct aws_byte_buf data;
    ASSERT_SUCCESS(aws_byte_buf_init(&data, fixture->allocator, 128));

    bool found_end_stream = false;

    for (size_t frame_i = 0; frame_i < aws_array_list_length(&fixture->frames); ++frame_i) {
        struct frame *frame;
        aws_array_list_get_at_ptr(&fixture->frames, (void **)&frame, frame_i);

        if (frame->type == AWS_H2_FRAME_T_DATA && frame->stream_id == stream_id) {
            struct aws_byte_cursor frame_data = aws_byte_cursor_from_buf(&frame->data);
            ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&data, &frame_data));

            found_end_stream = frame->end_stream;
        }
    }

    ASSERT_BIN_ARRAYS_EQUALS(expected, strlen(expected), data.buffer, data.len);
    ASSERT_UINT_EQUALS(expect_end_stream, found_end_stream);

    aws_byte_buf_clean_up(&data);
    return AWS_OP_SUCCESS;
}

/* Test DATA frame */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_data) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_SUCCESS(s_check_data_across_frames(fixture, 0x76543210 /*stream_id*/, "hello", true /*end_stream*/));
    return AWS_OP_SUCCESS;
}

/* Test padded DATA frame */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_data_padded) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_SUCCESS(s_check_data_across_frames(fixture, 0x76543210 /*stream_id*/, "hello", false /*end_stream*/));
    return AWS_OP_SUCCESS;
}

/* OK for PADDED frame to have pad length of zero */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_data_pad_length_zero) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_SUCCESS(s_check_data_across_frames(fixture, 0x76543210 /*stream_id*/, "hello", true /*end_stream*/));
    return AWS_OP_SUCCESS;
}

/* OK for DATA frame to have no data */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_data_empty) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_DATA,        /* Type (8) */
        0x0,                        /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* DATA */
                                    /* Data (*) */
    };
    /* clang-format on */

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_SUCCESS(s_check_data_across_frames(fixture, 0x76543210 /*stream_id*/, "", false /*end_stream*/));
    return AWS_OP_SUCCESS;
}

/* OK for padded DATA frame to have no data */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_data_empty_padded) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_SUCCESS(s_check_data_across_frames(fixture, 0x76543210 /*stream_id*/, "", false /*end_stream*/));
    return AWS_OP_SUCCESS;
}

/* Unexpected flags should be ignored.
 * DATA frames only support END_STREAM and PADDED*/
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_data_ignores_unknown_flags) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_SUCCESS(s_check_data_across_frames(fixture, 0x76543210 /*stream_id*/, "hello", true /*end_stream*/));
    return AWS_OP_SUCCESS;
}

/* Error if frame is padded, but not big enough to contain the padding length */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_payload_too_small_for_pad_length) {
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

    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_FRAME_SIZE, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));
    return AWS_OP_SUCCESS;
}

/* The most-significant-bit of the encoded stream ID is reserved, and should be ignored when decoding */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_stream_id_ignores_reserved_bit) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_DATA, 0x7FFFFFFF /*stream_id*/));
    ASSERT_SUCCESS(s_check_data_across_frames(fixture, 0x7FFFFFFF /*stream_id*/, "hello", true /*end_stream*/));
    return AWS_OP_SUCCESS;
}

static int s_check_header(
    struct frame *frame,
    size_t header_idx,
    const char *name,
    const char *value,
    enum aws_h2_header_field_hpack_behavior hpack_behavior) {
    ASSERT_TRUE(header_idx < aws_array_list_length(&frame->headers));

    struct aws_h2_frame_header_field *header_field;
    aws_array_list_get_at_ptr(&frame->headers, (void **)&header_field, header_idx);

    ASSERT_BIN_ARRAYS_EQUALS(name, strlen(name), header_field->header.name.ptr, header_field->header.name.len);
    ASSERT_BIN_ARRAYS_EQUALS(value, strlen(value), header_field->header.value.ptr, header_field->header.value.len);
    ASSERT_INT_EQUALS(hpack_behavior, header_field->hpack_behavior);
    return AWS_OP_SUCCESS;
}

/* Test a simple HEADERS frame
 * Note that we're not stressing the HPACK decoder here, that's done in other test files */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_headers) {
    (void)allocator;
    struct fixture *fixture = ctx;

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_END_STREAM, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, 0x03, '3', '0', '2'   /* ":status: 302" - indexed name, uncompressed value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Test a HEADERS frame with padding */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_headers_padded) {
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
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    return AWS_OP_SUCCESS;
}

/* Test a HEADERS frame with priority information
 * Note that priority information is ignored for now.
 * We're not testing that it was reported properly, just that decoder can properly consume it */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_headers_priority) {
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
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    return AWS_OP_SUCCESS;
}

/* Test a HEADERS frame with ALL flags set.
 * Unexpected flags should be ignored, but HEADERS supports: priority and padding and end-headers and end-stream */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_headers_ignores_unknown_flags) {
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
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_headers_payload_too_small_for_padding) {
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
    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_FRAME_SIZE, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_headers_payload_too_small_for_priority) {
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
    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_FRAME_SIZE, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test CONTINUATION frame.
 * Decoder requires that a HEADERS or PUSH_PROMISE frame be sent first */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_continuation) {
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
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(2, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "cache-control", "private", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Try setting ALL the flags on CONTINUATION frame.
 * Only END_HEADERS and should trigger.
 * Continuation doesn't support PRIORITY and PADDING like HEADERS does, so they should just be ignored */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_continuation_ignores_unknown_flags) {
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
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(2, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "cache-control", "private", AWS_H2_HEADER_BEHAVIOR_SAVE));
    return AWS_OP_SUCCESS;
}

/* Test that we an handle a header-field whose encoding is spread across multiple frames.
 * Throw some padding in to make it extra complicated */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_continuation_header_field_spans_frames) {
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
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_FALSE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Test having multiple CONTINUATION frames in a row */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_continuation_many_frames) {
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
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(3, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_SUCCESS(s_check_header(frame, 1, "cache-control", "private", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_SUCCESS(s_check_header(frame, 2, "hi", "mom", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Test having HEADERS and CONTINUATION frames with empty header-block-fragments */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_continuation_empty_payloads) {
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
    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));
    ASSERT_TRUE(frame->end_stream);
    return AWS_OP_SUCCESS;
}

/* Once a header-block starts, it's illegal for any frame but a CONTINUATION on that same stream to arrive.
 * This test sends a different frame type next */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_continuation_frame_expected) {
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
    ASSERT_ERROR(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Once a header-block starts, it's illegal for any frame but a CONTINUATION on that same stream to arrive.
 * This test sends a different stream-id next */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_continuation_frame_same_stream_expected) {
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
    ASSERT_ERROR(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* It's an error for a header-block to end with a partially decoded header-field */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_partial_header) {
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
    ASSERT_ERROR(AWS_ERROR_HTTP_COMPRESSION, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Ensure that random HPACK decoding errors are reported as ERROR_COMPRESSION */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_bad_hpack_data) {
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
    ASSERT_ERROR(AWS_ERROR_HTTP_COMPRESSION, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test PRIORITY frame */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_priority) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Our implementation currently chooses to ignore PRIORITY frames, so no callbacks should have fired */
    ASSERT_UINT_EQUALS(0, aws_array_list_length(&fixture->frames));
    return AWS_OP_SUCCESS;
}

/* Unknown flags should be ignored. PRIORITY frames don't have any flags. */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_priority_ignores_unknown_flags) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Our implementation currently chooses to ignore PRIORITY frames, so no callbacks should have fired */
    ASSERT_UINT_EQUALS(0, aws_array_list_length(&fixture->frames));
    return AWS_OP_SUCCESS;
}

/* Test PRIORITY frame */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_priority_payload_too_small) {
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

    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_FRAME_SIZE, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test PRIORITY frame */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_priority_payload_too_large) {
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

    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_FRAME_SIZE, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test RST_STREAM frame */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_rst_stream) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&fixture->frames));
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_RST_STREAM, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(0xFFEEDDCC, frame->error_code);
    return AWS_OP_SUCCESS;
}

/* Unknown flags should be ignored. RST_STREAM frame doesn't support any flags */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_rst_stream_ignores_unknown_flags) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate */
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&fixture->frames));
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_RST_STREAM, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(0xFFEEDDCC, frame->error_code);
    return AWS_OP_SUCCESS;
}

/* Payload must be 4 bytes exactly */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_rst_stream_payload_too_small) {
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

    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_FRAME_SIZE, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Payload must be 4 bytes exactly */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_err_rst_stream_payload_too_large) {
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

    ASSERT_ERROR(
        AWS_ERROR_HTTP_INVALID_FRAME_SIZE, s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    return AWS_OP_SUCCESS;
}

/* Test SETTINGS frame */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_settings) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&fixture->frames));
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    ASSERT_FALSE(frame->ack);
    ASSERT_UINT_EQUALS(2, aws_array_list_length(&frame->settings));

    struct aws_h2_frame_setting setting;
    aws_array_list_get_at(&frame->settings, &setting, 0);
    ASSERT_UINT_EQUALS(0x00005, setting.id);
    ASSERT_UINT_EQUALS(0x00FFFFFF, setting.value);

    aws_array_list_get_at(&frame->settings, &setting, 1);
    ASSERT_UINT_EQUALS(0x00002, setting.id);
    ASSERT_UINT_EQUALS(0x00000001, setting.value);

    return AWS_OP_SUCCESS;
}

/* Test SETTINGS frame */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_settings_empty) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&fixture->frames));
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    ASSERT_FALSE(frame->ack);
    ASSERT_UINT_EQUALS(0, aws_array_list_length(&frame->settings));

    return AWS_OP_SUCCESS;
}

TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_settings_ack) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* Validate. */
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&fixture->frames));
    struct frame *frame = s_latest_frame(fixture);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/));
    ASSERT_TRUE(frame->ack);
    ASSERT_UINT_EQUALS(0, aws_array_list_length(&frame->settings));

    return AWS_OP_SUCCESS;
}

/* Frames of unknown type must be ignored */
TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_unknown_frame_type_ignored) {
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

    ASSERT_SUCCESS(s_decode_all(fixture, aws_byte_cursor_from_array(input, sizeof(input))));

    /* No callbacks should have fired about the frame*/
    ASSERT_UINT_EQUALS(0, aws_array_list_length(&fixture->frames));
    return AWS_OP_SUCCESS;
}

/* #TODO
 * - verify stream-id required/forbidden
 * - enormous payload
 * - every frame type in a row
 * */