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
    bool ping_ack;
    uint32_t goaway_last_stream_id;
    uint32_t goaway_debug_data_remaining;
    uint8_t ping_opaque_data[AWS_H2_PING_DATA_SIZE];
    uint32_t window_size_increment;
};

struct tester {
    struct aws_allocator *allocator;
    struct aws_h2_decoder *decoder;
    struct aws_array_list frames; /* contains frame */
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

static struct frame *s_latest_frame(struct tester *tester) {
    AWS_FATAL_ASSERT(aws_array_list_length(&tester->frames) > 0);
    struct frame *frame = NULL;
    aws_array_list_get_at_ptr(&tester->frames, (void **)&frame, aws_array_list_length(&tester->frames) - 1);
    return frame;
}

/* tester begins recording a new frame's data */
static int s_begin_new_frame(
    struct tester *tester,
    enum aws_h2_frame_type type,
    uint32_t stream_id,
    struct frame **out_frame) {

    /* If there's a previous frame, assert that we know it was finished.
     * If this fails, some on_X_begin(), on_X_i(), on_X_end() loop didn't fire correctly.
     * It should be impossible for an unrelated callback to fire during these loops */
    if (aws_array_list_length(&tester->frames) > 0) {
        struct frame *prev_frame = s_latest_frame(tester);
        ASSERT_TRUE(prev_frame->finished);
    }

    /* Create new frame */
    struct frame new_frame;
    ASSERT_SUCCESS(s_frame_init(&new_frame, tester->allocator, type, stream_id));
    ASSERT_SUCCESS(aws_array_list_push_back(&tester->frames, &new_frame));

    if (out_frame) {
        aws_array_list_get_at_ptr(&tester->frames, (void **)out_frame, aws_array_list_length(&tester->frames) - 1);
    }
    return AWS_OP_SUCCESS;
}

/* tester stops recording the latest frame's data */
static int s_end_current_frame(struct tester *tester, enum aws_h2_frame_type type, uint32_t stream_id) {
    struct frame *frame = s_latest_frame(tester);
    ASSERT_FALSE(frame->finished);
    frame->finished = true;
    ASSERT_SUCCESS(s_validate_finished_frame(frame, type, stream_id));
    return AWS_OP_SUCCESS;
}

/**************************** DECODER CALLBACKS *******************************/

static int s_decoder_on_headers_begin(uint32_t stream_id, void *userdata) {
    struct tester *tester = userdata;
    ASSERT_SUCCESS(s_begin_new_frame(tester, AWS_H2_FRAME_T_HEADERS, stream_id, NULL /*out_frame*/));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_headers_i(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_h2_header_field_hpack_behavior hpack_behavior,
    void *userdata) {

    struct tester *tester = userdata;
    struct frame *frame = s_latest_frame(tester);

    /* validate */
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, frame->type);
    ASSERT_FALSE(frame->finished);
    ASSERT_INT_EQUALS(frame->stream_id, stream_id);

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
    struct tester *tester = userdata;
    ASSERT_SUCCESS(s_end_current_frame(tester, AWS_H2_FRAME_T_HEADERS, stream_id));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_data(uint32_t stream_id, struct aws_byte_cursor data, void *userdata) {
    struct tester *tester = userdata;
    struct frame *frame;

    /* Pretend each on_data callback is a full DATA frame for the purposes of these tests */
    ASSERT_SUCCESS(s_begin_new_frame(tester, AWS_H2_FRAME_T_DATA, stream_id, &frame));

    /* Stash data*/
    ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&frame->data, &data));

    ASSERT_SUCCESS(s_end_current_frame(tester, AWS_H2_FRAME_T_DATA, stream_id));
    return AWS_OP_SUCCESS;
}

static int s_decoder_on_end_stream(uint32_t stream_id, void *userdata) {
    struct tester *tester = userdata;
    struct frame *frame = s_latest_frame(tester);

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

static struct aws_h2_decoder_vtable s_decoder_vtable = {
    .on_headers_begin = s_decoder_on_headers_begin,
    .on_headers_i = s_decoder_on_headers_i,
    .on_headers_end = s_decoder_on_headers_end,
    .on_data = s_decoder_on_data,
    .on_end_stream = s_decoder_on_end_stream,
};

/************************** END DECODER CALLBACKS *****************************/

static int s_tester_init(struct aws_allocator *allocator, void *ctx, struct tester **tester_out) {
    (void)ctx;
    aws_http_library_init(allocator);

    struct tester *tester = aws_mem_calloc(allocator, 1, sizeof(struct tester));
    ASSERT_NOT_NULL(tester);
    *tester_out = tester;

    tester->allocator = allocator;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&tester->frames, allocator, 2, sizeof(struct frame)));

    struct aws_h2_decoder_params options = {
        .alloc = allocator,
        .vtable = &s_decoder_vtable,
        .userdata = tester,
    };
    tester->decoder = aws_h2_decoder_new(&options);
    ASSERT_NOT_NULL(tester->decoder);

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    for (size_t i = 0; i < aws_array_list_length(&tester->frames); ++i) {
        struct frame *frame;
        aws_array_list_get_at_ptr(&tester->frames, (void **)&frame, i);
        s_frame_clean_up(frame);
    }
    aws_array_list_clean_up(&tester->frames);
    aws_h2_decoder_destroy(tester->decoder);
    aws_mem_release(tester->allocator, tester);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

/* declare 2 tests, where one of them runs the decoder on one byte of input at a time. */
#define TEST_CASE_ONE_BYTE_AT_A_TIME(NAME)                                                                             \
    static int s_test_##NAME##_ex(struct aws_allocator *allocator, void *ctx, bool one_byte_at_a_time);                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx) {                                             \
        return s_test_##NAME##_ex(allocator, ctx, false);                                                              \
    }                                                                                                                  \
    AWS_TEST_CASE(NAME##_one_byte_at_a_time, s_test_##NAME##_one_byte_at_a_time)                                       \
    static int s_test_##NAME##_one_byte_at_a_time(struct aws_allocator *allocator, void *ctx) {                        \
        return s_test_##NAME##_ex(allocator, ctx, true);                                                               \
    }                                                                                                                  \
    static int s_test_##NAME##_ex(struct aws_allocator *allocator, void *ctx, bool one_byte_at_a_time)

TEST_CASE(h2_decoder_sanity_check) {
    struct tester *tester;
    ASSERT_SUCCESS(s_tester_init(allocator, ctx, &tester));

    return s_tester_clean_up(tester);
}

/* run aws_h2_decode() on input. Decode the whole buffer at once, or decode it one byte at a time */
static int s_decode_all(struct tester *tester, struct aws_byte_cursor input, bool one_byte_at_a_time) {
    while (input.len) {
        if (one_byte_at_a_time) {
            struct aws_byte_cursor one_byte = aws_byte_cursor_advance(&input, 1);
            ASSERT_SUCCESS(aws_h2_decode(tester->decoder, &one_byte));
            ASSERT_UINT_EQUALS(0, one_byte.len);
        } else {
            size_t prev_len = input.len;
            ASSERT_SUCCESS(aws_h2_decode(tester->decoder, &input));
            ASSERT_TRUE(input.len < prev_len);
        }
    }
    return AWS_OP_SUCCESS;
}

/* Compare data (which might be split across N frames) to expected string */
static int s_check_data_across_frames(struct tester *tester, uint32_t stream_id, const char *expected) {
    struct aws_byte_buf data;
    ASSERT_SUCCESS(aws_byte_buf_init(&data, tester->allocator, 128));

    for (size_t frame_i = 0; frame_i < aws_array_list_length(&tester->frames); ++frame_i) {
        struct frame *frame;
        aws_array_list_get_at_ptr(&tester->frames, (void **)&frame, frame_i);

        if (frame->type == AWS_H2_FRAME_T_DATA && frame->stream_id == stream_id) {
            struct aws_byte_cursor frame_data = aws_byte_cursor_from_buf(&frame->data);
            ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&data, &frame_data));
        }
    }

    ASSERT_BIN_ARRAYS_EQUALS(expected, strlen(expected), data.buffer, data.len);

    aws_byte_buf_clean_up(&data);
    return AWS_OP_SUCCESS;
}

static int s_test_h2_decoder_data_ex(struct aws_allocator *allocator, void *ctx, bool one_byte_at_a_time) {
    struct tester *tester;
    ASSERT_SUCCESS(s_tester_init(allocator, ctx, &tester));

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

    ASSERT_SUCCESS(s_decode_all(tester, aws_byte_cursor_from_array(input, sizeof(input)), one_byte_at_a_time));

    /* Validate. */
    struct frame *frame = s_latest_frame(tester);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_TRUE(frame->end_stream);
    ASSERT_SUCCESS(s_check_data_across_frames(tester, 0x76543210, "hello"));

    return s_tester_clean_up(tester);
}

TEST_CASE(h2_decoder_data) {
    return s_test_h2_decoder_data_ex(allocator, ctx, false /*one_byte_at_a_time*/);
}

TEST_CASE(h2_decoder_data_one_byte_at_a_time) {
    return s_test_h2_decoder_data_ex(allocator, ctx, true /*one_byte_at_a_time*/);
}

static int s_test_h2_decoder_data_padded_ex(struct aws_allocator *allocator, void *ctx, bool one_byte_at_a_time) {
    struct tester *tester;
    ASSERT_SUCCESS(s_tester_init(allocator, ctx, &tester));

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

    ASSERT_SUCCESS(s_decode_all(tester, aws_byte_cursor_from_array(input, sizeof(input)), one_byte_at_a_time));

    /* Validate. */
    struct frame *frame = s_latest_frame(tester);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_DATA, 0x76543210 /*stream_id*/));
    ASSERT_SUCCESS(s_check_data_across_frames(tester, 0x76543210, "hello"));

    return s_tester_clean_up(tester);
}

TEST_CASE(h2_decoder_data_padded) {
    return s_test_h2_decoder_data_padded_ex(allocator, ctx, false /*one_byte_at_a_time*/);
}

TEST_CASE(h2_decoder_data_padded_one_byte_at_a_time) {
    return s_test_h2_decoder_data_padded_ex(allocator, ctx, true /*one_byte_at_a_time*/);
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

TEST_CASE_ONE_BYTE_AT_A_TIME(h2_decoder_headers) {
    struct tester *tester;
    ASSERT_SUCCESS(s_tester_init(allocator, ctx, &tester));

    /* clang-format off */
    uint8_t input[] = {
        0x00, 0x00, 0x05,           /* Length (24) */
        AWS_H2_FRAME_T_HEADERS,     /* Type (8) */
        AWS_H2_FRAME_F_END_HEADERS, /* Flags (8) */
        0x76, 0x54, 0x32, 0x10,     /* Reserved (1) | Stream Identifier (31) */
        /* HEADERS */
        0x48, /* */
        0x03, '3', '0', '2' /* literal value */
    };
    /* clang-format on */

    /* Decode */
    ASSERT_SUCCESS(s_decode_all(tester, aws_byte_cursor_from_array(input, sizeof(input)), one_byte_at_a_time));

    /* Validate */
    struct frame *frame = s_latest_frame(tester);
    ASSERT_SUCCESS(s_validate_finished_frame(frame, AWS_H2_FRAME_T_HEADERS, 0x76543210 /*stream_id*/));
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&frame->headers));
    ASSERT_SUCCESS(s_check_header(frame, 0, ":status", "302", AWS_H2_HEADER_BEHAVIOR_SAVE));

    return s_tester_clean_up(tester);
}
