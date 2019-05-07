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

#include <aws/http/private/websocket_impl.h>

#include <aws/http/private/websocket_decoder.h>
#include <aws/io/logging.h>
#include <aws/testing/io_testing_channel.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct written_frame {
    struct aws_websocket_frame def;
    struct aws_byte_buf payload;
    bool is_complete;
};

struct tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;
    void *specific_test_data;

    struct testing_channel testing_channel;
    struct aws_websocket *websocket;
    size_t on_shutdown_count;
    int shutdown_error_code;

    size_t on_send_complete_count;

    /* To make the written output of the websocket-handler easier to check,
     * we translate the written bytes back into `written_frames` using a websocket-decoder.
     * We're not testing the decoder here, just using it as a tool (decoder tests go in test_websocket_decoder.c). */
    struct written_frame written_frames[100];
    size_t num_written_frames;
    struct aws_websocket_decoder written_frame_decoder;
};

/* Helps track the progress of a frame being sent. */
struct send_tester {
    struct aws_websocket_outgoing_frame_options def; /* some properties are autoconfigured */
    struct aws_byte_cursor payload;

    size_t delay_ticks;    /* Don't send anything the first N ticks */
    size_t bytes_per_tick; /* Don't send more than N bytes per tick */

    /* Everything below this line is auto-configured */

    struct aws_byte_cursor cursor; /* iterates as payload is written */

    size_t on_complete_count;
    int on_complete_error_code;

    size_t on_complete_order; /* Order that frame sent, amongst all frames sent this test */

    struct tester *owner;
};

static void s_on_connection_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {
    (void)websocket;
    struct tester *tester = user_data;
    tester->on_shutdown_count++;
    tester->shutdown_error_code = error_code;
}

/* Run loop that keeps the websocket-handler chugging. We need this because:
 * 1) The websocket-handler won't write the next aws_io_message until the preceding one is processed.
 * 2) The websocket-handler won't finish shutdown until it can write a CLOSE frame.
 *
 * Repeat until no more work is being done:
 * - Drain task queue.
 * - Decode written aws_io_messages from raw bytes into tester->written_frames[].
 * - Mark aws_io_messages completed.
 */
static int s_drain_written_messages(struct tester *tester) {
    struct aws_linked_list *io_msgs = testing_channel_get_written_message_queue(&tester->testing_channel);
    bool still_draining;
    do {
        still_draining = false;
        testing_channel_drain_queued_tasks(&tester->testing_channel);

        while (!aws_linked_list_empty(io_msgs)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(io_msgs);
            struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

            struct aws_byte_cursor msg_cursor = aws_byte_cursor_from_buf(&msg->message_data);
            while (msg_cursor.len) {
                /* Make sure our arbitrarily sized buffer hasn't overflowed. */
                ASSERT_TRUE(tester->num_written_frames < AWS_ARRAY_SIZE(tester->written_frames));

                bool frame_complete;
                ASSERT_SUCCESS(
                    aws_websocket_decoder_process(&tester->written_frame_decoder, &msg_cursor, &frame_complete));

                if (frame_complete) {
                    tester->written_frames[tester->num_written_frames].is_complete = true;
                    tester->num_written_frames++;
                }
            }

            if (msg->on_completion) {
                msg->on_completion(tester->testing_channel.channel, msg, 0, msg->user_data);
                still_draining = true;
            }

            aws_mem_release(msg->allocator, msg);
        }
    } while (still_draining);

    return AWS_OP_SUCCESS;
}

static int s_on_written_frame(const struct aws_websocket_frame *frame, void *user_data) {
    struct tester *tester = user_data;
    struct written_frame *written = &tester->written_frames[tester->num_written_frames];
    written->def = *frame;
    if (frame->payload_length) {
        ASSERT_SUCCESS(aws_byte_buf_init(&written->payload, tester->alloc, frame->payload_length));
    }
    return AWS_OP_SUCCESS;
}

static int s_on_written_frame_payload(struct aws_byte_cursor data, void *user_data) {
    struct tester *tester = user_data;
    struct written_frame *written = &tester->written_frames[tester->num_written_frames];
    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&written->payload, data));
    return AWS_OP_SUCCESS;
}

static int s_tester_init(struct tester *tester, struct aws_allocator *alloc) {
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

    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc));

    struct aws_channel_slot *channel_slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(channel_slot);

    struct aws_websocket_handler_options ws_options = {
        .allocator = alloc,
        .channel_slot = channel_slot,
        .initial_window_size = SIZE_MAX,
        .user_data = tester,
        .on_connection_shutdown = s_on_connection_shutdown,
    };
    struct aws_channel_handler *channel_handler = aws_websocket_handler_new(&ws_options);
    ASSERT_NOT_NULL(channel_handler);

    tester->websocket = channel_handler->impl;

    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, channel_slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(channel_slot, channel_handler));

    aws_websocket_decoder_init(&tester->written_frame_decoder, s_on_written_frame, s_on_written_frame_payload, tester);

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    aws_channel_shutdown(tester->testing_channel.channel, AWS_ERROR_SUCCESS);
    ASSERT_SUCCESS(s_drain_written_messages(tester));

    ASSERT_SUCCESS(testing_channel_clean_up(&tester->testing_channel));

    for (size_t i = 0; i < AWS_ARRAY_SIZE(tester->written_frames); ++i) {
        aws_byte_buf_clean_up(&tester->written_frames[i].payload);
    }

    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);
    return AWS_OP_SUCCESS;
}

static enum aws_websocket_outgoing_payload_state s_on_stream_outgoing_payload(
    struct aws_websocket *websocket,
    struct aws_byte_buf *out_buf,
    void *user_data) {

    struct send_tester *send_tester = user_data;
    AWS_FATAL_ASSERT(websocket == send_tester->owner->websocket);

    size_t space_available = out_buf->capacity - out_buf->len;

    size_t bytes_max = send_tester->cursor.len;
    if (send_tester->delay_ticks > 0) {
        bytes_max = 0;
        send_tester->delay_ticks--;
    } else if (send_tester->bytes_per_tick > 0) {
        bytes_max = bytes_max < send_tester->bytes_per_tick ? bytes_max : send_tester->bytes_per_tick;
    }

    size_t amount_to_send = bytes_max < space_available ? bytes_max : space_available;
    struct aws_byte_cursor send_cursor = aws_byte_cursor_advance(&send_tester->cursor, amount_to_send);
    aws_byte_buf_write_from_whole_cursor(out_buf, send_cursor);

    return send_tester->cursor.len == 0 ? AWS_WEBSOCKET_OUTGOING_PAYLOAD_DONE
                                        : AWS_WEBSOCKET_OUTGOING_PAYLOAD_IN_PROGRESS;
}

static void s_on_outgoing_frame_complete(struct aws_websocket *websocket, int error_code, void *user_data) {
    struct send_tester *send_tester = user_data;
    AWS_FATAL_ASSERT(websocket == send_tester->owner->websocket);

    send_tester->on_complete_error_code = error_code;
    send_tester->on_complete_count++;
    send_tester->on_complete_order = send_tester->owner->on_send_complete_count;
    send_tester->owner->on_send_complete_count++;
}

static int s_send_frame(struct tester *tester, struct send_tester *send_tester) {
    send_tester->owner = tester;
    send_tester->cursor = send_tester->payload;
    send_tester->def.payload_length = send_tester->payload.len;
    send_tester->def.stream_outgoing_payload = s_on_stream_outgoing_payload;
    send_tester->def.on_complete = s_on_outgoing_frame_complete;
    send_tester->def.user_data = send_tester;

    ASSERT_SUCCESS(aws_websocket_send_frame(tester->websocket, &send_tester->def));
    return AWS_OP_SUCCESS;
}

static int s_check_written_message(struct send_tester *send, size_t expected_order) {
    struct tester *tester = send->owner;

    ASSERT_UINT_EQUALS(1, send->on_complete_count);
    ASSERT_UINT_EQUALS(expected_order, send->on_complete_order);

    ASSERT_TRUE(expected_order < tester->num_written_frames);
    struct written_frame *written = &tester->written_frames[expected_order];

    ASSERT_TRUE(written->is_complete);
    ASSERT_UINT_EQUALS(send->def.opcode, written->def.opcode);
    ASSERT_UINT_EQUALS(send->def.payload_length, written->def.payload_length);
    ASSERT_INT_EQUALS(send->def.fin, written->def.fin);
    for (int i = 0; i < 3; i++) {
        ASSERT_INT_EQUALS(send->def.rsv[i], written->def.rsv[i]);
    }

    /* All payloads sent from client should have been masked (assuming client is being tested here) */
    ASSERT_TRUE(written->def.masked);
    if (written->def.masked) {
        bool valid_masking_key = false;
        for (int i = 0; i < 4; i++) {
            if (written->def.masking_key[i]) {
                valid_masking_key = true;
            }
        }
        ASSERT_TRUE(valid_masking_key);
    }

    /* If payload was masked, decoder already unmasked it for us, so we can directly compare contents here */
    ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&send->payload, &written->payload));

    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_sanity_check) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_send_frame) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    const char *payload = "Crying through the lock";

    struct send_tester send = {
        .payload = aws_byte_cursor_from_c_str(payload),
        .def =
            {
                .opcode = AWS_WEBSOCKET_OPCODE_PING,
                .fin = true,
            },
    };

    ASSERT_SUCCESS(s_send_frame(&tester, &send));
    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    ASSERT_SUCCESS(s_check_written_message(&send, 0));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
