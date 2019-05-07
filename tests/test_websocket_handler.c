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
    size_t on_payload_count;

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

    send_tester->on_payload_count++;

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

static int s_send_frame_ex(struct tester *tester, struct send_tester *send_tester, bool assert_on_error) {
    send_tester->owner = tester;
    send_tester->cursor = send_tester->payload;
    send_tester->def.payload_length = send_tester->payload.len;
    send_tester->def.stream_outgoing_payload = s_on_stream_outgoing_payload;
    send_tester->def.on_complete = s_on_outgoing_frame_complete;
    send_tester->def.user_data = send_tester;

    if (assert_on_error) {
        ASSERT_SUCCESS(aws_websocket_send_frame(tester->websocket, &send_tester->def));
        return AWS_OP_SUCCESS;
    } else {
        return aws_websocket_send_frame(tester->websocket, &send_tester->def);
    }
}

static int s_send_frame(struct tester *tester, struct send_tester *send_tester) {
    return s_send_frame_ex(tester, send_tester, true);
}

static int s_send_frame_no_assert(struct tester *tester, struct send_tester *send_tester) {
    return s_send_frame_ex(tester, send_tester, false);
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

    const char *payload = "Shall I come in to cut off your threads?";

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

TEST_CASE(websocket_handler_send_multiple_frames) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct send_tester sending[] = {
        {
            .payload = aws_byte_cursor_from_c_str("Wee Willie Winkie runs through the town."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("Upstairs and downstairs in his nightgown."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("Rapping at the window, crying through the lock."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = false,
                },
        },
        {
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_PING,
                    .fin = true,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("Are the children all in bed, for now it's eight o'clock?"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = true,
                },
        },

    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_send_frame(&tester, &sending[i]));
    }

    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_check_written_message(&sending[i], i));
    }
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_send_huge_frame) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* transmit giant buffer with random contents */
    struct aws_byte_buf giant_buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&giant_buf, allocator, 100000));
    while (aws_byte_buf_write_u8(&giant_buf, (uint8_t)rand())) {
    }

    struct send_tester sending[] = {
        {
            .payload = aws_byte_cursor_from_c_str("Little frame before big one."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_BINARY,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_buf(&giant_buf),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("Little frame after big one."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = true,
                },
        },
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_send_frame(&tester, &sending[i]));
    }

    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_check_written_message(&sending[i], i));
    }

    /* Ensure this was actually big enough to be split across aws_io_messages */
    ASSERT_TRUE(sending[1].on_payload_count > 1);

    aws_byte_buf_clean_up(&giant_buf);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_send_payload_slowly) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct send_tester sending[] = {
        {
            .payload = aws_byte_cursor_from_c_str("quick A."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("s l o o w w w l l y  B."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = false,
                },
            .bytes_per_tick = 1,
        },
        {
            .payload = aws_byte_cursor_from_c_str("quick C."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = true,
                },
        },
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_send_frame(&tester, &sending[i]));
    }

    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_check_written_message(&sending[i], i));
    }

    /* Ensure this test really did send data over multiple callbacks */
    ASSERT_TRUE(sending[1].on_payload_count > 1);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_send_payload_with_pauses) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct send_tester sending[] = {
        {
            .payload = aws_byte_cursor_from_c_str("immediate A."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("delayed B."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = false,
                },
            .delay_ticks = 5,
        },
        {
            .payload = aws_byte_cursor_from_c_str("immediate C."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = true,
                },
        },
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_send_frame(&tester, &sending[i]));
    }

    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_check_written_message(&sending[i], i));
    }

    /* Ensure this test really did send data over multiple callbacks */
    ASSERT_TRUE(sending[1].on_payload_count > 1);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_send_high_priority_frame) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct send_tester sending[] = {
        {
            .payload = aws_byte_cursor_from_c_str("A"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = false,
                },
        },
        {
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_PING,
                    .fin = true,
                    .high_priority = true,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("C"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = true,
                },
        },
    };

    /* Send from user-thread to ensure that everything is queued.
     * When queued frames are processed, the high-priority one should end up first. */
    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_send_frame(&tester, &sending[i]));
    }

    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);
    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    /* High-priority frame (index 1) should get sent first */
    ASSERT_SUCCESS(s_check_written_message(&sending[1], 0));
    ASSERT_SUCCESS(s_check_written_message(&sending[0], 1));
    ASSERT_SUCCESS(s_check_written_message(&sending[2], 2));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_sends_nothing_after_close_frame) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct send_tester sending[] = {
        {
            .payload = aws_byte_cursor_from_c_str("Last text frame"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
        {
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CLOSE,
                    .fin = true,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("Should not be sent."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
    };

    /* Ensure these frames are queued and processed later */
    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_send_frame(&tester, &sending[i]));
    }

    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);
    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    /* Ensure that only 1st frame and CLOSE frame were written*/
    ASSERT_UINT_EQUALS(2, tester.num_written_frames);
    ASSERT_SUCCESS(s_check_written_message(&sending[0], 0));
    ASSERT_SUCCESS(s_check_written_message(&sending[1], 1));

    /* Ensure no more frames written during shutdown */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    ASSERT_UINT_EQUALS(2, tester.num_written_frames);

    /* Ensure 3rd frame completed with error code */
    ASSERT_UINT_EQUALS(1, sending[2].on_complete_count);
    ASSERT_TRUE(sending[2].on_complete_error_code != AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Send a frame while the handler is in every conceivable state.
 * Ensure that the completion callback always fires. */
TEST_CASE(websocket_handler_send_frames_always_complete) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    enum {
        ON_THREAD_BEFORE_CLOSE,
        OFF_THREAD_BEFORE_CLOSE,
        CLOSE,
        ON_THREAD_AFTER_CLOSE,
        OFF_THREAD_AFTER_CLOSE,
        ON_THREAD_DURING_SHUTDOWN,
        OFF_THREAD_DURING_SHUTDOWN,
        ON_THREAD_AFTER_SHUTDOWN,
        OFF_THREAD_AFTER_SHUTDOWN,
        COUNT,
    };

    struct send_tester sending[COUNT];
    memset(sending, 0, sizeof(sending));
    for (int i = 0; i < COUNT; ++i) {
        struct send_tester *send = &sending[i];
        send->def.opcode = (i == CLOSE) ? AWS_WEBSOCKET_OPCODE_CLOSE : AWS_WEBSOCKET_OPCODE_PING;
        send->def.fin = true;
    }

    int sending_err[AWS_ARRAY_SIZE(sending)];

    /* Start sending frames */
    sending_err[ON_THREAD_BEFORE_CLOSE] = s_send_frame_no_assert(&tester, &sending[ON_THREAD_BEFORE_CLOSE]);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    sending_err[OFF_THREAD_BEFORE_CLOSE] = s_send_frame_no_assert(&tester, &sending[OFF_THREAD_BEFORE_CLOSE]);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);

    /* Send close frame */
    sending_err[CLOSE] = s_send_frame_no_assert(&tester, &sending[CLOSE]);

    sending_err[ON_THREAD_AFTER_CLOSE] = s_send_frame_no_assert(&tester, &sending[ON_THREAD_AFTER_CLOSE]);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    sending_err[OFF_THREAD_AFTER_CLOSE] = s_send_frame_no_assert(&tester, &sending[OFF_THREAD_AFTER_CLOSE]);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);

    /* Issue channel shutdown */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);

    sending_err[ON_THREAD_DURING_SHUTDOWN] = s_send_frame_no_assert(&tester, &sending[ON_THREAD_DURING_SHUTDOWN]);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    sending_err[OFF_THREAD_DURING_SHUTDOWN] = s_send_frame_no_assert(&tester, &sending[OFF_THREAD_DURING_SHUTDOWN]);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);

    /* Wait for shutdown to complete */
    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    /* Try to send even more frames */
    sending_err[ON_THREAD_AFTER_SHUTDOWN] = s_send_frame_no_assert(&tester, &sending[ON_THREAD_AFTER_SHUTDOWN]);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    sending_err[OFF_THREAD_AFTER_SHUTDOWN] = s_send_frame_no_assert(&tester, &sending[OFF_THREAD_AFTER_SHUTDOWN]);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);

    /* Check that each send() failed immediately, or had its completion callback invoked. */
    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    for (int i = 0; i < COUNT; ++i) {
        if (sending_err[i] == AWS_OP_SUCCESS) {
            ASSERT_UINT_EQUALS(1, sending[i].on_complete_count);
        }
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
