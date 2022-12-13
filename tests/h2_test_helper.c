/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "h2_test_helper.h"

#include <aws/http/private/h2_decoder.h>
#include <aws/io/stream.h>
#include <aws/testing/io_testing_channel.h>

/*******************************************************************************
 * h2_decoded_frame
 ******************************************************************************/
static void s_frame_init(
    struct h2_decoded_frame *frame,
    struct aws_allocator *alloc,
    enum aws_h2_frame_type type,
    uint32_t stream_id) {

    AWS_ZERO_STRUCT(*frame);
    frame->type = type;
    frame->stream_id = stream_id;
    frame->headers = aws_http_headers_new(alloc);
    AWS_FATAL_ASSERT(0 == aws_array_list_init_dynamic(&frame->settings, alloc, 16, sizeof(struct aws_http2_setting)));
    AWS_FATAL_ASSERT(0 == aws_byte_buf_init(&frame->data, alloc, 1024));
}

static void s_frame_clean_up(struct h2_decoded_frame *frame) {
    if (!frame) {
        return;
    }
    aws_http_headers_release(frame->headers);
    aws_array_list_clean_up(&frame->settings);
    aws_byte_buf_clean_up(&frame->data);
}

int h2_decoded_frame_check_finished(
    const struct h2_decoded_frame *frame,
    enum aws_h2_frame_type expected_type,
    uint32_t expected_stream_id) {

    ASSERT_INT_EQUALS(expected_type, frame->type);
    ASSERT_UINT_EQUALS(expected_stream_id, frame->stream_id);
    ASSERT_TRUE(frame->finished);
    return AWS_OP_SUCCESS;
}

/*******************************************************************************
 * h2_decode_tester
 ******************************************************************************/

size_t h2_decode_tester_frame_count(const struct h2_decode_tester *decode_tester) {
    return aws_array_list_length(&decode_tester->frames);
}

struct h2_decoded_frame *h2_decode_tester_get_frame(const struct h2_decode_tester *decode_tester, size_t i) {
    AWS_FATAL_ASSERT(h2_decode_tester_frame_count(decode_tester) > i);
    struct h2_decoded_frame *frame = NULL;
    aws_array_list_get_at_ptr(&decode_tester->frames, (void **)&frame, i);
    return frame;
}

struct h2_decoded_frame *h2_decode_tester_latest_frame(const struct h2_decode_tester *decode_tester) {
    size_t frame_count = h2_decode_tester_frame_count(decode_tester);
    AWS_FATAL_ASSERT(frame_count != 0);
    return h2_decode_tester_get_frame(decode_tester, frame_count - 1);
}

struct h2_decoded_frame *h2_decode_tester_find_frame(
    const struct h2_decode_tester *decode_tester,
    enum aws_h2_frame_type type,
    size_t search_start_idx,
    size_t *out_idx) {

    return h2_decode_tester_find_stream_frame(decode_tester, type, UINT32_MAX /*stream_id*/, search_start_idx, out_idx);
}

struct h2_decoded_frame *h2_decode_tester_find_stream_frame_any_type(
    const struct h2_decode_tester *decode_tester,
    uint32_t stream_id,
    size_t search_start_idx,
    size_t *out_idx) {

    return h2_decode_tester_find_stream_frame(
        decode_tester, AWS_H2_FRAME_TYPE_COUNT /*frame_type*/, stream_id, search_start_idx, out_idx);
}

struct h2_decoded_frame *h2_decode_tester_find_stream_frame(
    const struct h2_decode_tester *decode_tester,
    enum aws_h2_frame_type type,
    uint32_t stream_id,
    size_t search_start_idx,
    size_t *out_idx) {

    size_t frame_count = h2_decode_tester_frame_count(decode_tester);
    if (out_idx) {
        *out_idx = frame_count;
    }

    for (size_t i = search_start_idx; i < frame_count; ++i) {
        struct h2_decoded_frame *frame = h2_decode_tester_get_frame(decode_tester, i);
        if (frame->type == type || type == AWS_H2_FRAME_TYPE_COUNT) {
            if (frame->stream_id == stream_id || stream_id == UINT32_MAX) {
                if (out_idx) {
                    *out_idx = i;
                }
                return frame;
            }
        }
    }
    return NULL;
}

int h2_decode_tester_check_data_across_frames(
    const struct h2_decode_tester *decode_tester,
    uint32_t stream_id,
    struct aws_byte_cursor expected,
    bool expect_end_stream) {

    struct aws_byte_buf data;
    ASSERT_SUCCESS(aws_byte_buf_init(&data, decode_tester->alloc, 128));

    bool found_end_stream = false;

    for (size_t frame_i = 0; frame_i < h2_decode_tester_frame_count(decode_tester); ++frame_i) {
        struct h2_decoded_frame *frame = h2_decode_tester_get_frame(decode_tester, frame_i);

        if (frame->type == AWS_H2_FRAME_T_DATA && frame->stream_id == stream_id) {
            struct aws_byte_cursor frame_data = aws_byte_cursor_from_buf(&frame->data);
            ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&data, &frame_data));

            found_end_stream = frame->end_stream;
        }
    }

    ASSERT_BIN_ARRAYS_EQUALS(expected.ptr, expected.len, data.buffer, data.len);
    ASSERT_UINT_EQUALS(expect_end_stream, found_end_stream);

    aws_byte_buf_clean_up(&data);
    return AWS_OP_SUCCESS;
}

int h2_decode_tester_check_data_str_across_frames(
    const struct h2_decode_tester *decode_tester,
    uint32_t stream_id,
    const char *expected,
    bool expect_end_stream) {

    return h2_decode_tester_check_data_across_frames(
        decode_tester, stream_id, aws_byte_cursor_from_c_str(expected), expect_end_stream);
}

/* decode-tester begins recording a new frame's data */
static void s_begin_new_frame(
    struct h2_decode_tester *decode_tester,
    enum aws_h2_frame_type type,
    uint32_t stream_id,
    struct h2_decoded_frame **out_frame) {

    /* If there's a previous frame, assert that we know it was finished.
     * If this fails, some on_X_begin(), on_X_i(), on_X_end() loop didn't fire correctly.
     * It should be impossible for an unrelated callback to fire during these loops */
    if (aws_array_list_length(&decode_tester->frames) > 0) {
        const struct h2_decoded_frame *prev_frame = h2_decode_tester_latest_frame(decode_tester);
        AWS_FATAL_ASSERT(prev_frame->finished);
    }

    /* Create new frame */
    struct h2_decoded_frame new_frame;
    s_frame_init(&new_frame, decode_tester->alloc, type, stream_id);
    AWS_FATAL_ASSERT(0 == aws_array_list_push_back(&decode_tester->frames, &new_frame));

    if (out_frame) {
        aws_array_list_get_at_ptr(
            &decode_tester->frames, (void **)out_frame, aws_array_list_length(&decode_tester->frames) - 1);
    }
}

/* decode-tester stops recording the latest frame's data */
static void s_end_current_frame(
    struct h2_decode_tester *decode_tester,
    enum aws_h2_frame_type type,
    uint32_t stream_id) {
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(decode_tester);
    AWS_FATAL_ASSERT(!frame->finished);
    frame->finished = true;
    AWS_FATAL_ASSERT(0 == h2_decoded_frame_check_finished(frame, type, stream_id));
}

static struct aws_h2err s_decoder_on_headers_begin(uint32_t stream_id, void *userdata) {
    struct h2_decode_tester *decode_tester = userdata;
    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_HEADERS, stream_id, NULL /*out_frame*/);
    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_on_header(
    bool is_push_promise,
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type,
    void *userdata) {

    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(decode_tester);

    /* Validate */
    if (is_push_promise) {
        AWS_FATAL_ASSERT(AWS_H2_FRAME_T_PUSH_PROMISE == frame->type);
    } else {
        AWS_FATAL_ASSERT(AWS_H2_FRAME_T_HEADERS == frame->type);

        /* block-type should be same for each header in block */
        if (aws_http_headers_count(frame->headers) > 0) {
            AWS_FATAL_ASSERT(frame->header_block_type == block_type);
        }
    }

    AWS_FATAL_ASSERT(!frame->finished);
    AWS_FATAL_ASSERT(frame->stream_id == stream_id);
    AWS_FATAL_ASSERT(aws_http_lowercase_str_to_header_name(header->name) == name_enum);

    /* Stash header */
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_headers_add_header(frame->headers, header));
    frame->header_block_type = block_type;

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_headers_i(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type,
    void *userdata) {
    return s_on_header(false /* is_push_promise */, stream_id, header, name_enum, block_type, userdata);
}

static struct aws_h2err s_on_headers_end(
    bool is_push_promise,
    uint32_t stream_id,
    bool malformed,
    enum aws_http_header_block block_type,
    void *userdata) {

    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(decode_tester);

    /* end() should report same block-type as i() calls */
    if (!is_push_promise && aws_http_headers_count(frame->headers) > 0) {
        AWS_FATAL_ASSERT(frame->header_block_type == block_type);
    }
    frame->header_block_type = block_type;

    frame->headers_malformed = malformed;
    s_end_current_frame(
        decode_tester, is_push_promise ? AWS_H2_FRAME_T_PUSH_PROMISE : AWS_H2_FRAME_T_HEADERS, stream_id);
    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_headers_end(
    uint32_t stream_id,
    bool malformed,
    enum aws_http_header_block block_type,
    void *userdata) {
    return s_on_headers_end(false /*is_push_promise*/, stream_id, malformed, block_type, userdata);
}

static struct aws_h2err s_decoder_on_push_promise_begin(
    uint32_t stream_id,
    uint32_t promised_stream_id,
    void *userdata) {

    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;
    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_PUSH_PROMISE, stream_id, &frame /*out_frame*/);

    frame->promised_stream_id = promised_stream_id;

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_push_promise_i(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    void *userdata) {
    return s_on_header(true /* is_push_promise */, stream_id, header, name_enum, AWS_HTTP_HEADER_BLOCK_MAIN, userdata);
}

static struct aws_h2err s_decoder_on_push_promise_end(uint32_t stream_id, bool malformed, void *userdata) {
    return s_on_headers_end(true /*is_push_promise*/, stream_id, malformed, AWS_HTTP_HEADER_BLOCK_MAIN, userdata);
}

static struct aws_h2err s_decoder_on_data_begin(
    uint32_t stream_id,
    uint32_t payload_len,
    uint32_t total_padding_bytes,
    bool end_stream,
    void *userdata) {
    (void)total_padding_bytes;
    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;
    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_DATA, stream_id, &frame);

    frame->data_payload_len = payload_len;
    frame->data_end_stream = end_stream;

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_data_i(uint32_t stream_id, struct aws_byte_cursor data, void *userdata) {
    (void)stream_id;
    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(decode_tester);

    /* Validate */
    AWS_FATAL_ASSERT(AWS_H2_FRAME_T_DATA == frame->type);
    AWS_FATAL_ASSERT(!frame->finished);
    AWS_FATAL_ASSERT(frame->stream_id == stream_id);

    /* Stash data*/
    AWS_FATAL_ASSERT(0 == aws_byte_buf_append_dynamic(&frame->data, &data));

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_data_end(uint32_t stream_id, void *userdata) {
    struct h2_decode_tester *decode_tester = userdata;

    s_end_current_frame(decode_tester, AWS_H2_FRAME_T_DATA, stream_id);
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(decode_tester);
    AWS_FATAL_ASSERT(frame->data.len <= frame->data_payload_len);

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_end_stream(uint32_t stream_id, void *userdata) {
    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame = h2_decode_tester_latest_frame(decode_tester);

    /* Validate */

    /* on_end_stream should fire IMMEDIATELY after on_data OR after on_headers_end.
     * This timing lets the user close the stream from a single callback */
    AWS_FATAL_ASSERT(frame->finished);
    AWS_FATAL_ASSERT(frame->type == AWS_H2_FRAME_T_HEADERS || frame->type == AWS_H2_FRAME_T_DATA);
    AWS_FATAL_ASSERT(frame->stream_id == stream_id);

    if (frame->type == AWS_H2_FRAME_T_DATA) {
        AWS_FATAL_ASSERT(frame->data_end_stream);
    }

    /* Stash */
    frame->end_stream = true;

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_rst_stream(uint32_t stream_id, uint32_t error_code, void *userdata) {
    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;

    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_RST_STREAM, stream_id, &frame);

    /* Stash data*/
    frame->error_code = error_code;

    s_end_current_frame(decode_tester, AWS_H2_FRAME_T_RST_STREAM, stream_id);
    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_settings(
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    void *userdata) {

    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;
    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_SETTINGS, 0, &frame);

    /* Stash setting */
    for (size_t i = 0; i < num_settings; i++) {
        AWS_FATAL_ASSERT(0 == aws_array_list_push_back(&frame->settings, &settings_array[i]));
    }

    s_end_current_frame(decode_tester, AWS_H2_FRAME_T_SETTINGS, 0);
    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_settings_ack(void *userdata) {
    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;

    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/, &frame);

    /* Stash data*/
    frame->ack = true;

    s_end_current_frame(decode_tester, AWS_H2_FRAME_T_SETTINGS, 0 /*stream_id*/);
    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_ping(uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE], void *userdata) {
    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;

    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_PING, 0 /*stream_id*/, &frame);

    /* Stash data*/
    memcpy(frame->ping_opaque_data, opaque_data, AWS_HTTP2_PING_DATA_SIZE);

    s_end_current_frame(decode_tester, AWS_H2_FRAME_T_PING, 0 /*stream_id*/);
    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_ping_ack(uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE], void *userdata) {
    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;

    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_PING, 0 /*stream_id*/, &frame);

    /* Stash data*/
    memcpy(frame->ping_opaque_data, opaque_data, AWS_HTTP2_PING_DATA_SIZE);
    frame->ack = true;

    s_end_current_frame(decode_tester, AWS_H2_FRAME_T_PING, 0 /*stream_id*/);
    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_goaway(
    uint32_t last_stream,
    uint32_t error_code,
    struct aws_byte_cursor debug_data,
    void *userdata) {

    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;
    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_GOAWAY, 0, &frame);

    frame->goaway_last_stream_id = last_stream;
    frame->error_code = error_code;
    /* Stash data */
    AWS_FATAL_ASSERT(0 == aws_byte_buf_append_dynamic(&frame->data, &debug_data));
    s_end_current_frame(decode_tester, AWS_H2_FRAME_T_GOAWAY, 0);

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2err s_decoder_on_window_update(uint32_t stream_id, uint32_t window_size_increment, void *userdata) {
    struct h2_decode_tester *decode_tester = userdata;
    struct h2_decoded_frame *frame;
    s_begin_new_frame(decode_tester, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id, &frame);

    frame->window_size_increment = window_size_increment;

    s_end_current_frame(decode_tester, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id);

    return AWS_H2ERR_SUCCESS;
}

static struct aws_h2_decoder_vtable s_decoder_vtable = {
    .on_headers_begin = s_decoder_on_headers_begin,
    .on_headers_i = s_decoder_on_headers_i,
    .on_headers_end = s_decoder_on_headers_end,
    .on_push_promise_begin = s_decoder_on_push_promise_begin,
    .on_push_promise_i = s_decoder_on_push_promise_i,
    .on_push_promise_end = s_decoder_on_push_promise_end,
    .on_data_begin = s_decoder_on_data_begin,
    .on_data_i = s_decoder_on_data_i,
    .on_data_end = s_decoder_on_data_end,
    .on_end_stream = s_decoder_on_end_stream,
    .on_rst_stream = s_decoder_on_rst_stream,
    .on_settings = s_decoder_on_settings,
    .on_settings_ack = s_decoder_on_settings_ack,
    .on_ping = s_decoder_on_ping,
    .on_ping_ack = s_decoder_on_ping_ack,
    .on_goaway = s_decoder_on_goaway,
    .on_window_update = s_decoder_on_window_update,
};

int h2_decode_tester_init(struct h2_decode_tester *decode_tester, const struct h2_decode_tester_options *options) {
    AWS_ZERO_STRUCT(*decode_tester);
    decode_tester->alloc = options->alloc;

    struct aws_h2_decoder_params decoder_params = {
        .alloc = options->alloc,
        .vtable = &s_decoder_vtable,
        .userdata = decode_tester,
        .is_server = options->is_server,
        .skip_connection_preface = options->skip_connection_preface,
    };
    decode_tester->decoder = aws_h2_decoder_new(&decoder_params);
    ASSERT_NOT_NULL(decode_tester->decoder);

    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&decode_tester->frames, options->alloc, 16, sizeof(struct h2_decoded_frame)));
    return AWS_OP_SUCCESS;
}

void h2_decode_tester_clean_up(struct h2_decode_tester *decode_tester) {
    aws_h2_decoder_destroy(decode_tester->decoder);

    for (size_t i = 0; i < aws_array_list_length(&decode_tester->frames); ++i) {
        struct h2_decoded_frame *frame;
        aws_array_list_get_at_ptr(&decode_tester->frames, (void **)&frame, i);
        s_frame_clean_up(frame);
    }
    aws_array_list_clean_up(&decode_tester->frames);

    AWS_ZERO_STRUCT(*decode_tester);
}

/*******************************************************************************
 * h2_fake_peer
 ******************************************************************************/

int h2_fake_peer_init(struct h2_fake_peer *peer, const struct h2_fake_peer_options *options) {
    AWS_ZERO_STRUCT(*peer);
    peer->alloc = options->alloc;
    peer->testing_channel = options->testing_channel;
    peer->is_server = options->is_server;

    ASSERT_SUCCESS(aws_h2_frame_encoder_init(&peer->encoder, peer->alloc, NULL /*logging_id*/));

    struct h2_decode_tester_options decode_options = {.alloc = options->alloc, .is_server = options->is_server};
    ASSERT_SUCCESS(h2_decode_tester_init(&peer->decode, &decode_options));
    return AWS_OP_SUCCESS;
}

void h2_fake_peer_clean_up(struct h2_fake_peer *peer) {
    if (!peer) {
        return;
    }
    aws_h2_frame_encoder_clean_up(&peer->encoder);
    h2_decode_tester_clean_up(&peer->decode);
    AWS_ZERO_STRUCT(peer);
}

int h2_fake_peer_decode_messages_from_testing_channel(struct h2_fake_peer *peer) {
    struct aws_byte_buf msg_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&msg_buf, peer->alloc, 128));
    ASSERT_SUCCESS(testing_channel_drain_written_messages(peer->testing_channel, &msg_buf));

    struct aws_byte_cursor msg_cursor = aws_byte_cursor_from_buf(&msg_buf);
    ASSERT_H2ERR_SUCCESS(aws_h2_decode(peer->decode.decoder, &msg_cursor));
    ASSERT_UINT_EQUALS(0, msg_cursor.len);

    aws_byte_buf_clean_up(&msg_buf);
    return AWS_OP_SUCCESS;
}

int h2_fake_peer_send_frame(struct h2_fake_peer *peer, struct aws_h2_frame *frame) {
    ASSERT_NOT_NULL(frame);

    bool frame_complete = false;
    while (!frame_complete) {
        struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
            peer->testing_channel->channel, AWS_IO_MESSAGE_APPLICATION_DATA, g_aws_channel_max_fragment_size);
        ASSERT_NOT_NULL(msg);

        ASSERT_SUCCESS(aws_h2_encode_frame(&peer->encoder, frame, &msg->message_data, &frame_complete));
        ASSERT_TRUE(msg->message_data.len != 0);

        ASSERT_SUCCESS(testing_channel_push_read_message(peer->testing_channel, msg));
    }

    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}

int h2_fake_peer_send_data_frame(
    struct h2_fake_peer *peer,
    uint32_t stream_id,
    struct aws_byte_cursor data,
    bool end_stream) {
    return h2_fake_peer_send_data_frame_with_padding_length(peer, stream_id, data, end_stream, 0);
}

int h2_fake_peer_send_data_frame_with_padding_length(
    struct h2_fake_peer *peer,
    uint32_t stream_id,
    struct aws_byte_cursor data,
    bool end_stream,
    uint8_t padding_length) {

    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(peer->alloc, &data);
    ASSERT_NOT_NULL(body_stream);

    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        peer->testing_channel->channel, AWS_IO_MESSAGE_APPLICATION_DATA, g_aws_channel_max_fragment_size);
    ASSERT_NOT_NULL(msg);

    bool body_complete;
    bool body_stalled;
    int32_t stream_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    size_t connection_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    ASSERT_SUCCESS(aws_h2_encode_data_frame(
        &peer->encoder,
        stream_id,
        body_stream,
        end_stream,
        padding_length /*pad_length*/,
        &stream_window_size_peer,
        &connection_window_size_peer,
        &msg->message_data,
        &body_complete,
        &body_stalled));

    ASSERT_TRUE(body_complete);
    ASSERT_FALSE(body_stalled);
    ASSERT_TRUE(msg->message_data.len != 0);

    ASSERT_SUCCESS(testing_channel_push_read_message(peer->testing_channel, msg));
    aws_input_stream_release(body_stream);
    return AWS_OP_SUCCESS;
}

int h2_fake_peer_send_data_frame_str(struct h2_fake_peer *peer, uint32_t stream_id, const char *data, bool end_stream) {
    return h2_fake_peer_send_data_frame(peer, stream_id, aws_byte_cursor_from_c_str(data), end_stream);
}

int h2_fake_peer_send_connection_preface(struct h2_fake_peer *peer, struct aws_h2_frame *settings) {
    if (!peer->is_server) {
        /* Client must first send magic string */
        ASSERT_SUCCESS(testing_channel_push_read_data(peer->testing_channel, aws_h2_connection_preface_client_string));
    }

    /* Both server and client send SETTINGS as first proper frame */
    ASSERT_SUCCESS(h2_fake_peer_send_frame(peer, settings));

    return AWS_OP_SUCCESS;
}

int h2_fake_peer_send_connection_preface_default_settings(struct h2_fake_peer *peer) {
    /* Empty SETTINGS frame means "everything default" */
    struct aws_h2_frame *settings = aws_h2_frame_new_settings(peer->alloc, NULL, 0, false /*ack*/);
    ASSERT_NOT_NULL(settings);

    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface(peer, settings));
    return AWS_OP_SUCCESS;
}

/******************************************************************************/

struct aws_input_stream_tester {
    struct aws_input_stream base;
    struct aws_allocator *allocator;
    /* aws_input_stream_byte_cursor provides our actual functionality  */
    struct aws_input_stream *cursor_stream;

    size_t max_bytes_per_read;
    bool is_reading_broken;
};

static int s_aws_input_stream_tester_seek(
    struct aws_input_stream *stream,
    int64_t offset,
    enum aws_stream_seek_basis basis) {

    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(stream, struct aws_input_stream_tester, base);
    return aws_input_stream_seek(impl->cursor_stream, offset, basis);
}

static int s_aws_input_stream_tester_read(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(stream, struct aws_input_stream_tester, base);

    if (impl->is_reading_broken) {
        return aws_raise_error(AWS_IO_STREAM_READ_FAILED);
    }

    /* prevent more than max_bytes_per_read by temporarily limiting the buffer's capacity */
    size_t prev_capacity = dest->capacity;
    size_t max_capacity = aws_add_size_saturating(dest->len, impl->max_bytes_per_read);
    dest->capacity = aws_min_size(prev_capacity, max_capacity);

    int err = aws_input_stream_read(impl->cursor_stream, dest);

    dest->capacity = prev_capacity;
    return err;
}

static int s_aws_input_stream_tester_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(stream, struct aws_input_stream_tester, base);
    return aws_input_stream_get_status(impl->cursor_stream, status);
}

static int s_aws_input_stream_tester_get_length(struct aws_input_stream *stream, int64_t *out_length) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(stream, struct aws_input_stream_tester, base);
    return aws_input_stream_get_length(impl->cursor_stream, out_length);
}

static void s_aws_input_stream_tester_destroy(struct aws_input_stream_tester *impl) {
    aws_input_stream_release(impl->cursor_stream);
    aws_mem_release(impl->allocator, impl);
}

static struct aws_input_stream_vtable s_aws_input_stream_tester_vtable = {
    .seek = s_aws_input_stream_tester_seek,
    .read = s_aws_input_stream_tester_read,
    .get_status = s_aws_input_stream_tester_get_status,
    .get_length = s_aws_input_stream_tester_get_length,
};

struct aws_input_stream *aws_input_stream_new_tester(struct aws_allocator *alloc, struct aws_byte_cursor cursor) {

    struct aws_input_stream_tester *impl = aws_mem_calloc(alloc, 1, sizeof(struct aws_input_stream_tester));
    AWS_FATAL_ASSERT(impl);

    impl->max_bytes_per_read = SIZE_MAX;

    impl->cursor_stream = aws_input_stream_new_from_cursor(alloc, &cursor);
    AWS_FATAL_ASSERT(impl->cursor_stream);
    impl->allocator = alloc;
    impl->base.vtable = &s_aws_input_stream_tester_vtable;
    aws_ref_count_init(
        &impl->base.ref_count, impl, (aws_simple_completion_callback *)s_aws_input_stream_tester_destroy);
    return &impl->base;
}

void aws_input_stream_tester_set_max_bytes_per_read(struct aws_input_stream *input_stream, size_t max_bytes) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(input_stream, struct aws_input_stream_tester, base);
    impl->max_bytes_per_read = max_bytes;
}

void aws_input_stream_tester_set_reading_broken(struct aws_input_stream *input_stream, bool is_broken) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(input_stream, struct aws_input_stream_tester, base);
    impl->is_reading_broken = is_broken;
}

struct aws_input_stream_tester_upload_impl {
    struct aws_input_stream base;
    size_t position;
    size_t length;
    size_t num_sentence_sent;
    struct aws_allocator *allocator;
};

static int s_aws_input_stream_tester_upload_seek(
    struct aws_input_stream *stream,
    int64_t offset,
    enum aws_stream_seek_basis basis) {
    (void)stream;
    (void)offset;
    (void)basis;

    /* Stream should never be seeked; all reads should be sequential. */
    aws_raise_error(AWS_ERROR_UNKNOWN);
    return AWS_OP_ERR;
}

const struct aws_byte_cursor s_test_string = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("This is CRT HTTP test.");

static int s_aws_input_stream_tester_upload_read(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    (void)stream;
    (void)dest;

    struct aws_input_stream_tester_upload_impl *test_input_stream =
        AWS_CONTAINER_OF(stream, struct aws_input_stream_tester_upload_impl, base);

    while (dest->len < dest->capacity && test_input_stream->length - test_input_stream->position > 0) {
        size_t buffer_pos = test_input_stream->position % s_test_string.len;

        struct aws_byte_cursor source_byte_cursor = {
            .len = s_test_string.len - buffer_pos,
            .ptr = s_test_string.ptr + buffer_pos,
        };

        size_t remaining_in_buffer =
            aws_min_size(dest->capacity - dest->len, test_input_stream->length - test_input_stream->position);

        if (remaining_in_buffer < source_byte_cursor.len) {
            source_byte_cursor.len = remaining_in_buffer;
        }

        aws_byte_buf_append(dest, &source_byte_cursor);
        buffer_pos += source_byte_cursor.len;

        test_input_stream->position += source_byte_cursor.len;
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_input_stream_tester_upload_get_status(
    struct aws_input_stream *stream,
    struct aws_stream_status *status) {
    (void)stream;
    (void)status;

    struct aws_input_stream_tester_upload_impl *test_input_stream =
        AWS_CONTAINER_OF(stream, struct aws_input_stream_tester_upload_impl, base);

    status->is_end_of_stream = test_input_stream->position == test_input_stream->length;
    status->is_valid = true;

    return AWS_OP_SUCCESS;
}

static int s_aws_input_stream_tester_upload_get_length(struct aws_input_stream *stream, int64_t *out_length) {
    AWS_ASSERT(stream != NULL);
    struct aws_input_stream_tester_upload_impl *test_input_stream =
        AWS_CONTAINER_OF(stream, struct aws_input_stream_tester_upload_impl, base);
    *out_length = (int64_t)test_input_stream->length;
    return AWS_OP_SUCCESS;
}

static void s_aws_input_stream_tester_upload_destroy(struct aws_input_stream_tester_upload_impl *test_input_stream) {
    aws_mem_release(test_input_stream->allocator, test_input_stream);
}

static struct aws_input_stream_vtable s_aws_input_stream_tester_upload_vtable = {
    .seek = s_aws_input_stream_tester_upload_seek,
    .read = s_aws_input_stream_tester_upload_read,
    .get_status = s_aws_input_stream_tester_upload_get_status,
    .get_length = s_aws_input_stream_tester_upload_get_length,
};

struct aws_input_stream *aws_input_stream_tester_upload_new(struct aws_allocator *alloc, size_t length) {

    struct aws_input_stream_tester_upload_impl *test_input_stream =
        aws_mem_calloc(alloc, 1, sizeof(struct aws_input_stream_tester_upload_impl));
    test_input_stream->base.vtable = &s_aws_input_stream_tester_upload_vtable;
    aws_ref_count_init(
        &test_input_stream->base.ref_count,
        test_input_stream,
        (aws_simple_completion_callback *)s_aws_input_stream_tester_upload_destroy);

    struct aws_input_stream *input_stream = &test_input_stream->base;

    test_input_stream->position = 0;
    test_input_stream->length = length;
    test_input_stream->allocator = alloc;
    test_input_stream->num_sentence_sent = length / s_test_string.len;

    return input_stream;
}

size_t aws_input_stream_tester_upload_get_num_sentence_sent(struct aws_input_stream *stream) {
    struct aws_input_stream_tester_upload_impl *test_input_stream =
        AWS_CONTAINER_OF(stream, struct aws_input_stream_tester_upload_impl, base);
    return test_input_stream->num_sentence_sent;
}
