/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/websocket_impl.h>

#include <aws/http/private/websocket_decoder.h>
#include <aws/http/private/websocket_encoder.h>
#include <aws/io/logging.h>
#include <aws/testing/io_testing_channel.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

/* Use small window so that we can observe it opening in tests.
 * Channel may wait until the window is small before issuing the increment command. */
static const size_t s_default_initial_window_size = 256;

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct written_frame {
    struct aws_websocket_frame def;
    struct aws_byte_buf payload;
    bool is_complete;
};

struct incoming_frame {
    struct aws_websocket_incoming_frame def;
    struct aws_byte_buf payload;
    size_t on_payload_count;
    int on_complete_error_code;
    bool has_begun;
    bool is_complete;
};

static struct tester_options { bool manual_window_update; } s_tester_options;

struct tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;
    void *specific_test_data;

    struct testing_channel testing_channel;
    struct aws_websocket *websocket;
    bool is_midchannel_handler;

    size_t on_send_complete_count;

    /* To make the written output of the websocket-handler easier to check,
     * we translate the written bytes back into `written_frames` using a websocket-decoder.
     * We're not testing the decoder here, just using it as a tool (decoder tests go in test_websocket_decoder.c). */
    struct written_frame written_frames[100];
    size_t num_written_frames;
    size_t num_written_io_messages;
    struct aws_websocket_decoder written_frame_decoder;

    /* Frames reported via the websocket's on_incoming_frame callbacks are recorded here */
    struct incoming_frame incoming_frames[100];
    size_t num_incoming_frames;
    size_t fail_on_incoming_frame_begin_n;    /* If set, return false on Nth incoming_frame_begin callback */
    size_t fail_on_incoming_frame_payload_n;  /* If set, return false on Nth incoming_frame_payload callback */
    size_t fail_on_incoming_frame_complete_n; /* If set, return false on Nth incoming_frame_complete callback */

    /* For pushing messages downstream, to be read by websocket handler.
     * readpush_frame is for tests to define websocket frames to be pushed downstream.
     * An encoder is used to turn these into proper bits */
    struct readpush_frame *readpush_frames;
    size_t num_readpush_frames;
    size_t readpush_frame_index;
    struct aws_websocket_encoder readpush_encoder;

    /* For pushing messages upstream, to test a websocket that's been converted to midchannel handler. */
    size_t num_writepush_messages;
    struct aws_byte_buf all_writepush_data; /* All data that's been writepushed, concatenated together */
};

/* Helps track the progress of a frame being sent. */
struct send_tester {
    struct aws_websocket_send_frame_options def; /* some properties are autoconfigured */
    struct aws_byte_cursor payload;

    size_t delay_ticks;    /* Don't send anything the first N ticks */
    size_t bytes_per_tick; /* Don't send more than N bytes per tick */
    size_t send_wrong_payload_amount;

    /* Everything below this line is auto-configured */
    struct tester *owner;

    struct aws_byte_cursor cursor; /* iterates as payload is written */
    size_t on_payload_count;
    size_t fail_on_nth_payload; /* If set, returns false on Nth callback (1 is first callback)*/

    size_t on_complete_count;
    size_t on_complete_order; /* Order that frame sent, amongst all frames sent this test */
    int on_complete_error_code;
    bool fail_on_complete; /* If true, return false from on_complete callback */
};

struct readpush_frame {
    struct aws_websocket_frame def;
    struct aws_byte_cursor payload;

    /* Everything below this is auto-configured */
    struct aws_byte_cursor cursor; /* advances as payload is written */
};

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

            tester->num_written_io_messages++;

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
        AWS_FATAL_ASSERT(frame->payload_length <= SIZE_MAX);
        ASSERT_SUCCESS(aws_byte_buf_init(&written->payload, tester->alloc, (size_t)frame->payload_length));
    }
    return AWS_OP_SUCCESS;
}

static int s_on_written_frame_payload(struct aws_byte_cursor data, void *user_data) {
    struct tester *tester = user_data;
    struct written_frame *written = &tester->written_frames[tester->num_written_frames];
    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&written->payload, data));
    return AWS_OP_SUCCESS;
}

static bool s_on_incoming_frame_begin(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    void *user_data) {

    (void)websocket;
    struct tester *tester = user_data;

    /* Make sure our arbitrarily-sized testing buffer hasn't overflowed */
    AWS_FATAL_ASSERT(tester->num_incoming_frames < AWS_ARRAY_SIZE(tester->incoming_frames));

    if (tester->num_incoming_frames > 0) {
        /* Make sure previous frame was marked complete */
        AWS_FATAL_ASSERT(tester->incoming_frames[tester->num_incoming_frames - 1].is_complete);
    }

    struct incoming_frame *incoming_frame = &tester->incoming_frames[tester->num_incoming_frames];

    AWS_FATAL_ASSERT(!incoming_frame->has_begun);
    incoming_frame->has_begun = true;
    incoming_frame->def = *frame;

    AWS_FATAL_ASSERT(frame->payload_length <= SIZE_MAX);
    int err = aws_byte_buf_init(&incoming_frame->payload, tester->alloc, (size_t)frame->payload_length);
    AWS_FATAL_ASSERT(!err);

    if (tester->fail_on_incoming_frame_begin_n) {
        AWS_FATAL_ASSERT(tester->num_incoming_frames < tester->fail_on_incoming_frame_begin_n);

        if ((tester->num_incoming_frames + 1) == tester->fail_on_incoming_frame_begin_n) {
            return false;
        }
    }
    return true;
}

static bool s_on_incoming_frame_payload(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    void *user_data) {

    (void)websocket;
    (void)frame;
    struct tester *tester = user_data;
    struct incoming_frame *incoming_frame = &tester->incoming_frames[tester->num_incoming_frames];
    AWS_FATAL_ASSERT(incoming_frame->has_begun);
    AWS_FATAL_ASSERT(!incoming_frame->is_complete);

    /* buffer was allocated to exact payload length, so write should succeed */
    AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_cursor(&incoming_frame->payload, data));

    incoming_frame->on_payload_count++;

    if (tester->fail_on_incoming_frame_payload_n) {
        AWS_FATAL_ASSERT(incoming_frame->on_payload_count <= tester->fail_on_incoming_frame_payload_n);

        if (incoming_frame->on_payload_count == tester->fail_on_incoming_frame_payload_n) {
            return false;
        }
    }
    return true;
}

static bool s_on_incoming_frame_complete(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    int error_code,
    void *user_data) {

    (void)websocket;
    (void)frame;
    struct tester *tester = user_data;
    struct incoming_frame *incoming_frame = &tester->incoming_frames[tester->num_incoming_frames++];
    AWS_FATAL_ASSERT(incoming_frame->has_begun);
    AWS_FATAL_ASSERT(!incoming_frame->is_complete);

    incoming_frame->is_complete = true;
    incoming_frame->on_complete_error_code = error_code;
    if (error_code == AWS_ERROR_SUCCESS) {
        AWS_FATAL_ASSERT(incoming_frame->payload.len == incoming_frame->def.payload_length);
    }

    if (tester->fail_on_incoming_frame_complete_n) {
        AWS_FATAL_ASSERT(tester->num_incoming_frames <= tester->fail_on_incoming_frame_complete_n);

        if (tester->num_incoming_frames == tester->fail_on_incoming_frame_complete_n) {
            return false;
        }
    }
    return true;
}

static void s_set_readpush_frames(struct tester *tester, struct readpush_frame *frames, size_t num_frames) {
    tester->readpush_frames = frames;
    tester->num_readpush_frames = num_frames;
    for (size_t i = 0; i < num_frames; ++i) {
        struct readpush_frame *frame = &frames[i];
        frame->cursor = frame->payload;
        frame->def.payload_length = frame->payload.len;
    }
}

static int s_stream_readpush_payload(struct aws_byte_buf *out_buf, void *user_data) {
    struct tester *tester = user_data;

    struct readpush_frame *frame = &tester->readpush_frames[tester->readpush_frame_index];
    size_t available_bytes = out_buf->capacity - out_buf->len;
    size_t sending_bytes = available_bytes < frame->cursor.len ? available_bytes : frame->cursor.len;
    struct aws_byte_cursor sending_cursor = aws_byte_cursor_advance(&frame->cursor, sending_bytes);
    AWS_FATAL_ASSERT(sending_cursor.len > 0);

    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(out_buf, sending_cursor));
    return AWS_OP_SUCCESS;
}

/* Options for pushing readpush_frames. Anything set to 0 is treated as "unlimited" */
struct readpush_options {
    size_t num_frames;   /* Stop after pushing this many frames. */
    size_t num_bytes;    /* Stop after pushing this many total bytes of aws_io_messages */
    size_t num_messages; /* Stop after pushing this many aws_io_messages */
    size_t message_size; /* Force fragmentation by limiting amount packed into each aws_io_message */
};

/* Encode readpush_frames into aws_io_messages and push those to websocket-handler. */
static int s_do_readpush(struct tester *tester, struct readpush_options options) {
    const size_t max_frames = options.num_frames ? options.num_frames : SIZE_MAX;
    const size_t max_bytes = options.num_bytes ? options.num_bytes : SIZE_MAX;
    const size_t max_messages = options.num_messages ? options.num_messages : SIZE_MAX;
    const size_t message_size = options.message_size ? options.message_size : (16 * 1024);

    size_t sum_frames = 0;
    size_t sum_bytes = 0;
    size_t sum_messages = 0;

    bool done = tester->readpush_frame_index >= tester->num_readpush_frames;
    while (!done) {
        size_t remaining_bytes = max_bytes - sum_bytes;
        size_t request_bytes = remaining_bytes < message_size ? remaining_bytes : message_size;
        struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
            tester->testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, request_bytes);
        ASSERT_NOT_NULL(msg);

        while (!done && (msg->message_data.len < msg->message_data.capacity)) {

            if (!aws_websocket_encoder_is_frame_in_progress(&tester->readpush_encoder)) {
                ASSERT_SUCCESS(aws_websocket_encoder_start_frame(
                    &tester->readpush_encoder, &tester->readpush_frames[tester->readpush_frame_index].def));
            }

            ASSERT_SUCCESS(aws_websocket_encoder_process(&tester->readpush_encoder, &msg->message_data));

            if (aws_websocket_encoder_is_frame_in_progress(&tester->readpush_encoder)) {
                /* This function doesn't expect encoder to stop until frame is done or buffer is full */
                ASSERT_UINT_EQUALS(msg->message_data.len, msg->message_data.capacity);
            } else {
                /* Frame done */
                if (++tester->readpush_frame_index >= tester->num_readpush_frames) {
                    done = true;
                }

                if (++sum_frames >= max_frames) {
                    done = true;
                }
            }
        }

        sum_bytes += msg->message_data.len;
        if (sum_bytes >= max_bytes) {
            done = true;
        }

        if (++sum_messages >= max_messages) {
            done = true;
        }

        ASSERT_SUCCESS(testing_channel_push_read_message(&tester->testing_channel, msg));
    }

    return AWS_OP_SUCCESS;
}

static int s_do_readpush_all(struct tester *tester) {
    struct readpush_options options;
    AWS_ZERO_STRUCT(options);
    return s_do_readpush(tester, options);
}

/* Check that a readpush_frame was received by websocket */
static int s_readpush_check(struct tester *tester, size_t frame_i, int expected_error_code) {
    ASSERT_TRUE(frame_i < tester->num_readpush_frames);
    struct readpush_frame *pushed = &tester->readpush_frames[frame_i];
    struct incoming_frame *received = &tester->incoming_frames[frame_i];

    ASSERT_TRUE(received->has_begun);
    ASSERT_TRUE(received->is_complete);
    ASSERT_INT_EQUALS(expected_error_code, received->on_complete_error_code);

    ASSERT_UINT_EQUALS(pushed->def.payload_length, received->def.payload_length);
    ASSERT_UINT_EQUALS(pushed->def.opcode, received->def.opcode);
    ASSERT_INT_EQUALS(pushed->def.fin, received->def.fin);
    ASSERT_INT_EQUALS(pushed->def.rsv[0], received->def.rsv[0]);
    ASSERT_INT_EQUALS(pushed->def.rsv[1], received->def.rsv[1]);
    ASSERT_INT_EQUALS(pushed->def.rsv[2], received->def.rsv[2]);

    if (received->on_complete_error_code == AWS_ERROR_SUCCESS) {
        ASSERT_UINT_EQUALS(received->def.payload_length, received->payload.len);
        ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&pushed->payload, &received->payload));
    }

    return AWS_OP_SUCCESS;
}

/* Check that a readpush_frame's payload was passed to the next handler downstream */
static int s_readpush_midchannel_check(struct tester *tester, size_t frame_i) {
    ASSERT_TRUE(frame_i < tester->num_readpush_frames);
    struct readpush_frame *pushed = &tester->readpush_frames[frame_i];
    struct aws_byte_cursor payload = pushed->payload;

    struct aws_linked_list *downstream_messages = testing_channel_get_read_message_queue(&tester->testing_channel);

    while (payload.len > 0) {
        ASSERT_FALSE(aws_linked_list_empty(downstream_messages));
        struct aws_linked_list_node *message_node = aws_linked_list_front(downstream_messages);
        struct aws_io_message *message = AWS_CONTAINER_OF(message_node, struct aws_io_message, queueing_handle);

        /* This function might be called multiple times, the copy_mark is used to track where the last check ended */
        size_t message_remainder = message->message_data.len - message->copy_mark;
        size_t compare_bytes = message_remainder < payload.len ? message_remainder : payload.len;
        struct aws_byte_cursor message_chunk =
            aws_byte_cursor_from_array(message->message_data.buffer + message->copy_mark, compare_bytes);

        struct aws_byte_cursor payload_chunk = aws_byte_cursor_advance(&payload, compare_bytes);
        ASSERT_TRUE(aws_byte_cursor_eq(&message_chunk, &payload_chunk));
        message->copy_mark += compare_bytes;
        if (message->copy_mark == message->message_data.len) {
            aws_linked_list_pop_front(downstream_messages);
            aws_mem_release(message->allocator, message);
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_writepush(struct tester *tester, struct aws_byte_cursor data) {
    if (!tester->all_writepush_data.allocator) {
        ASSERT_SUCCESS(aws_byte_buf_init(&tester->all_writepush_data, tester->alloc, data.len));
    }

    while (data.len) {
        /* Ask for slightly more data than we need so that capacity != length.
         * This is to repro a bug where capacity and length were confused */
        size_t size_hint = data.len + 1;

        struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
            tester->testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, size_hint);
        ASSERT_NOT_NULL(msg);
        size_t chunk_size = msg->message_data.capacity < data.len ? msg->message_data.capacity : data.len;
        struct aws_byte_cursor chunk = aws_byte_cursor_advance(&data, chunk_size);
        ASSERT_NOT_NULL(chunk.ptr);
        ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&msg->message_data, chunk));
        ASSERT_SUCCESS(testing_channel_push_write_message(&tester->testing_channel, msg));

        /* Update tracking data in tester */
        tester->num_writepush_messages++;
        ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&tester->all_writepush_data, &chunk));
    }
    return AWS_OP_SUCCESS;
}

/* Scan all written_frames, and ensure that payloads of the binary frames match data */
static int s_writepush_check(struct tester *tester, size_t ignore_n_written_frames) {
    struct aws_byte_cursor expected_cursor = aws_byte_cursor_from_buf(&tester->all_writepush_data);
    for (size_t i = ignore_n_written_frames; i < tester->num_written_frames; ++i) {
        struct written_frame *frame_i = &tester->written_frames[i];
        if (aws_websocket_is_data_frame(frame_i->def.opcode)) {
            ASSERT_UINT_EQUALS(AWS_WEBSOCKET_OPCODE_BINARY, frame_i->def.opcode);
            struct aws_byte_cursor expected_i =
                aws_byte_cursor_advance(&expected_cursor, (size_t)frame_i->def.payload_length);
            ASSERT_TRUE(expected_i.len > 0);
            ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&expected_i, &frame_i->payload));
        }
    }
    ASSERT_UINT_EQUALS(0, expected_cursor.len);
    return AWS_OP_SUCCESS;
}

static int s_tester_init(struct tester *tester, struct aws_allocator *alloc) {
    aws_http_library_init(alloc);

    AWS_ZERO_STRUCT(*tester);
    tester->alloc = alloc;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    struct aws_testing_channel_options test_channel_options = {.clock_fn = aws_high_res_clock_get_ticks};
    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc, &test_channel_options));

    struct aws_websocket_handler_options ws_options = {
        .allocator = alloc,
        .channel = tester->testing_channel.channel,
        .initial_window_size = s_default_initial_window_size,
        .user_data = tester,
        .on_incoming_frame_begin = s_on_incoming_frame_begin,
        .on_incoming_frame_payload = s_on_incoming_frame_payload,
        .on_incoming_frame_complete = s_on_incoming_frame_complete,
        .manual_window_update = s_tester_options.manual_window_update,
    };
    tester->websocket = aws_websocket_handler_new(&ws_options);
    ASSERT_NOT_NULL(tester->websocket);
    testing_channel_drain_queued_tasks(&tester->testing_channel);

    aws_websocket_decoder_init(&tester->written_frame_decoder, s_on_written_frame, s_on_written_frame_payload, tester);
    aws_websocket_encoder_init(&tester->readpush_encoder, s_stream_readpush_payload, tester);

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    aws_websocket_release(tester->websocket);
    ASSERT_SUCCESS(s_drain_written_messages(tester));

    ASSERT_SUCCESS(testing_channel_clean_up(&tester->testing_channel));

    for (size_t i = 0; i < AWS_ARRAY_SIZE(tester->written_frames); ++i) {
        aws_byte_buf_clean_up(&tester->written_frames[i].payload);
    }

    for (size_t i = 0; i < AWS_ARRAY_SIZE(tester->incoming_frames); ++i) {
        aws_byte_buf_clean_up(&tester->incoming_frames[i].payload);
    }

    aws_byte_buf_clean_up(&tester->all_writepush_data);

    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);
    return AWS_OP_SUCCESS;
}

static int s_install_downstream_handler(struct tester *tester, size_t initial_window) {

    ASSERT_SUCCESS(aws_websocket_convert_to_midchannel_handler(tester->websocket));
    tester->is_midchannel_handler = true;

    ASSERT_SUCCESS(testing_channel_install_downstream_handler(&tester->testing_channel, initial_window));
    testing_channel_drain_queued_tasks(&tester->testing_channel);

    return AWS_OP_SUCCESS;
}

static bool s_on_stream_outgoing_payload(
    struct aws_websocket *websocket,
    struct aws_byte_buf *out_buf,
    void *user_data) {

    struct send_tester *send_tester = user_data;
    AWS_FATAL_ASSERT(websocket == send_tester->owner->websocket);

    /* If user wants frame to break websocket, write an extra byte */
    if (send_tester->send_wrong_payload_amount && (send_tester->on_payload_count == 0)) {
        aws_byte_buf_write_u8(out_buf, 'X');
    }

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
    if (send_cursor.len) {
        aws_byte_buf_write_from_whole_cursor(out_buf, send_cursor);
    }

    if (send_tester->fail_on_nth_payload) {
        AWS_FATAL_ASSERT(send_tester->on_payload_count <= send_tester->fail_on_nth_payload);
        if (send_tester->on_payload_count == send_tester->fail_on_nth_payload) {
            return false;
        }
    }

    return true;
}

static void s_on_outgoing_frame_complete(struct aws_websocket *websocket, int error_code, void *user_data) {
    struct send_tester *send_tester = user_data;
    AWS_FATAL_ASSERT(websocket == send_tester->owner->websocket);

    send_tester->on_complete_error_code = error_code;
    AWS_FATAL_ASSERT(send_tester->on_complete_count == 0);
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

static int s_websocket_handler_send_frame_common(struct aws_allocator *allocator, bool on_thread) {
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

    testing_channel_set_is_on_users_thread(&tester.testing_channel, on_thread);
    ASSERT_SUCCESS(s_send_frame(&tester, &send));

    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);
    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    ASSERT_SUCCESS(s_check_written_message(&send, 0));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_send_frame) {
    (void)ctx;
    return s_websocket_handler_send_frame_common(allocator, true);
}

TEST_CASE(websocket_handler_send_frame_off_thread) {
    (void)ctx;
    return s_websocket_handler_send_frame_common(allocator, false);
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
    while (aws_byte_buf_write_be32(&giant_buf, (uint32_t)rand())) {
    }
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

    struct send_tester sending = {
        .payload = aws_byte_cursor_from_c_str("delayed B."),
        .def =
            {
                .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                .fin = true,
            },
        .delay_ticks = 5,
    };

    ASSERT_SUCCESS(s_send_frame(&tester, &sending));

    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    ASSERT_SUCCESS(s_check_written_message(&sending, 0));

    /* Ensure this test really did send data over multiple callbacks */
    ASSERT_TRUE(sending.on_payload_count > 1);

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
        {
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_PONG,
                    .fin = true,
                    .high_priority = true,
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

    /* High-priority frames (index 1 and 3) should get sent first */
    ASSERT_SUCCESS(s_check_written_message(&sending[1], 0));
    ASSERT_SUCCESS(s_check_written_message(&sending[3], 1));
    ASSERT_SUCCESS(s_check_written_message(&sending[0], 2));
    ASSERT_SUCCESS(s_check_written_message(&sending[2], 3));

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

TEST_CASE(websocket_handler_send_one_io_msg_at_a_time) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct aws_byte_cursor payload = aws_byte_cursor_from_c_str("bitter butter.");

    const size_t count = 10000;
    struct send_tester *sending = aws_mem_acquire(allocator, sizeof(struct send_tester) * count);
    ASSERT_NOT_NULL(sending);
    memset(sending, 0, sizeof(struct send_tester) * count);

    for (size_t i = 0; i < count; ++i) {
        struct send_tester *send = &sending[i];
        send->payload = payload;
        send->def.opcode = AWS_WEBSOCKET_OPCODE_TEXT;
        send->def.fin = true;

        ASSERT_SUCCESS(s_send_frame(&tester, send));
    }

    /* Turn off instant write completion */
    testing_channel_complete_written_messages_immediately(&tester.testing_channel, false, AWS_OP_SUCCESS);

    /* Repeatedly drain event loop and ensure that only 1 aws_io_message is written */
    struct aws_linked_list *io_msgs = testing_channel_get_written_message_queue(&tester.testing_channel);
    size_t total_io_msg_count = 0;
    while (true) {
        testing_channel_drain_queued_tasks(&tester.testing_channel);
        if (aws_linked_list_empty(io_msgs)) {
            break;
        }

        total_io_msg_count++;
        struct aws_linked_list_node *node = aws_linked_list_pop_front(io_msgs);
        struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

        ASSERT_TRUE(aws_linked_list_empty(io_msgs)); /* Only 1 aws_io_message should be in the channel at a time */

        if (msg->on_completion) {
            msg->on_completion(tester.testing_channel.channel, msg, AWS_ERROR_SUCCESS, msg->user_data);
        }
        aws_mem_release(msg->allocator, msg);
    }

    /* Assert that every frame sent */
    ASSERT_UINT_EQUALS(1, sending[count - 1].on_complete_count);

    /* Assert this test actually actually involved several aws_io_messages */
    ASSERT_TRUE(total_io_msg_count >= 3);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    aws_mem_release(allocator, sending);
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_send_halts_if_payload_fn_returns_false) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct send_tester sending[] = {
        {
            /* Sending should halt after 1st frame sends 1byte of payload */
            .payload = aws_byte_cursor_from_c_str("Stop"),
            .fail_on_nth_payload = 1,
            .bytes_per_tick = 1,
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("Should never send"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(sending); ++i) {
        ASSERT_SUCCESS(s_send_frame(&tester, &sending[i]));
    }

    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    /* Check that frame stopped processing */
    ASSERT_UINT_EQUALS(1, sending[0].on_payload_count);
    ASSERT_UINT_EQUALS(1, sending[0].on_complete_count);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CALLBACK_FAILURE, sending[0].on_complete_error_code);

    /* The websocket should close when a callback returns false */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    /* Other send should have been cancelled without it payload callback ever being invoked */
    ASSERT_UINT_EQUALS(0, sending[1].on_payload_count);
    ASSERT_UINT_EQUALS(1, sending[1].on_complete_count);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, sending[1].on_complete_error_code);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_shutdown_automatically_sends_close_frame) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Shutdown channel normally */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    /* Check that CLOSE frame written */
    ASSERT_UINT_EQUALS(AWS_WEBSOCKET_OPCODE_CLOSE, tester.written_frames[0].def.opcode);
    ASSERT_TRUE(tester.written_frames[0].is_complete);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Ensure that, if user had queued their own CLOSE frame before shutdown,
 * The user frame is the only one that gets written. */
TEST_CASE(websocket_handler_shutdown_handles_queued_close_frame) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Try to make it so we issue channel-shutdown while user CLOSE frame is mid-send.
     * We use the "payload delay" feature in the `send_tester` struct */
    uint8_t payload_bytes[] = {0x01, 0x02};
    struct send_tester send = {
        .payload = aws_byte_cursor_from_array(payload_bytes, sizeof(payload_bytes)),
        .def =
            {
                .opcode = AWS_WEBSOCKET_OPCODE_CLOSE,
                .fin = true,
            },
        .delay_ticks = 5,
    };

    ASSERT_SUCCESS(s_send_frame(&tester, &send));

    /* Assert that test has one aws_io_message written, containing a partially sent frame */
    testing_channel_run_currently_queued_tasks(&tester.testing_channel);
    ASSERT_TRUE(send.on_payload_count > 0);
    ASSERT_UINT_EQUALS(0, send.on_complete_count);

    /* Shutdown channel normally */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    /* Check that user's CLOSE frame was written, and nothing further */
    ASSERT_SUCCESS(s_check_written_message(&send, 0));
    ASSERT_UINT_EQUALS(1, tester.num_written_frames);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_shutdown_immediately_in_emergency) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Try to make it so we issue channel-shutdown while a frame is mid-send.
     * We use the "payload delay" feature in the `send_tester` struct */
    struct send_tester send = {
        .payload = aws_byte_cursor_from_c_str("delayed payload"),
        .def =
            {
                .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                .fin = true,
            },
        .delay_ticks = 15,
    };

    ASSERT_SUCCESS(s_send_frame(&tester, &send));

    /* Assert that test is issuing shutdown while frame is partially written */
    testing_channel_run_currently_queued_tasks(&tester.testing_channel);
    ASSERT_TRUE(send.on_payload_count > 0);
    ASSERT_UINT_EQUALS(0, send.on_complete_count);

    /* Shutdown channel with error code, which should result in IMMEDIATE style shutdown */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_IO_SOCKET_CLOSED);
    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    /* Ensure shutdown is complete at this point*/
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    /* Frame should not have sent completely, no CLOSE frame should have been sent either */
    ASSERT_UINT_EQUALS(1, send.on_complete_count);
    ASSERT_TRUE(send.on_complete_error_code != AWS_ERROR_SUCCESS);

    ASSERT_UINT_EQUALS(0, tester.num_written_frames);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* During normal shutdown, the websocket delays until a CLOSE frame can be sent.
 * This test checks that, if unexpected errors occur during that waiting period, shutdown doesn't hang forever */
TEST_CASE(websocket_handler_shutdown_handles_unexpected_write_error) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* Queue a frame that delays a while, and then breaks the websocket entirely. */
    struct send_tester send = {
        .payload = aws_byte_cursor_from_c_str("bad frame"),
        .def =
            {
                .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                .fin = true,
            },
        .delay_ticks = 15,
        .send_wrong_payload_amount = 1,
    };

    ASSERT_SUCCESS(s_send_frame(&tester, &send));

    /* Assert that test is issuing shutdown while frame is partially written */
    testing_channel_run_currently_queued_tasks(&tester.testing_channel);
    ASSERT_TRUE(send.on_payload_count > 0);
    ASSERT_UINT_EQUALS(0, send.on_complete_count);

    /* Shutdown channel normally, which should cause the websocket to queue a CLOSE frame and wait until it's sent. */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_IO_SOCKET_CLOSED);

    /* Wait for shutdown to complete */
    ASSERT_SUCCESS(s_drain_written_messages(&tester));

    /* Assert that test did actually experience a write error */
    ASSERT_UINT_EQUALS(1, send.on_complete_count);
    ASSERT_TRUE(send.on_complete_error_code != AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_close_on_thread) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    aws_websocket_close(tester.websocket, false);

    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_close_off_thread) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    testing_channel_set_is_on_users_thread(&tester.testing_channel, false);
    aws_websocket_close(tester.websocket, false);
    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);

    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_read_frame) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing[] = {
        {
            .payload = aws_byte_cursor_from_c_str("guten morgen"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
    };

    s_set_readpush_frames(&tester, pushing, AWS_ARRAY_SIZE(pushing));
    s_do_readpush_all(&tester);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    for (size_t i = 0; i < AWS_ARRAY_SIZE(pushing); ++i) {
        ASSERT_SUCCESS(s_readpush_check(&tester, i, AWS_ERROR_SUCCESS));
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_read_multiple_frames) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing[] = {
        {
            .payload = aws_byte_cursor_from_c_str("Uno."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("Dos."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("Tres."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = true,
                },
        },
    };

    s_set_readpush_frames(&tester, pushing, AWS_ARRAY_SIZE(pushing));
    ASSERT_SUCCESS(s_do_readpush_all(&tester));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    for (size_t i = 0; i < AWS_ARRAY_SIZE(pushing); ++i) {
        ASSERT_SUCCESS(s_readpush_check(&tester, i, AWS_ERROR_SUCCESS));
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_read_frames_split_across_io_messages) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing[] = {
        {
            .payload = aws_byte_cursor_from_c_str("As dry leaves that before the wild hurricane fly,"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("when they meet with an obstacle,"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = false,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("mount to the sky"),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION,
                    .fin = true,
                },
        },
    };

    s_set_readpush_frames(&tester, pushing, AWS_ARRAY_SIZE(pushing));

    /* Send 1 byte at a time to ensure we can tolerate frames split across multiple aws_io_messages */
    struct readpush_options options = {.message_size = 1};
    ASSERT_SUCCESS(s_do_readpush(&tester, options));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    for (size_t i = 0; i < AWS_ARRAY_SIZE(pushing); ++i) {
        ASSERT_SUCCESS(s_readpush_check(&tester, i, AWS_ERROR_SUCCESS));
    }

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_read_frames_complete_on_shutdown) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing[] = {
        {
            .payload = aws_byte_cursor_from_c_str("This frame will not be completely sent."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
    };

    s_set_readpush_frames(&tester, pushing, AWS_ARRAY_SIZE(pushing));

    /* Push most, but not all, of a frame */
    struct readpush_options options = {
        .num_bytes = (size_t)(aws_websocket_frame_encoded_size(&pushing[0].def) - 1),
    };
    s_do_readpush(&tester, options);

    /* Shut down channel */
    aws_channel_shutdown(tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    s_drain_written_messages(&tester);

    /* Check that completion callbacks fired */
    ASSERT_SUCCESS(s_readpush_check(&tester, 0, AWS_ERROR_HTTP_CONNECTION_CLOSED));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_read_halts_if_begin_fn_returns_false) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing[] = {
        {
            .payload = aws_byte_cursor_from_c_str("Fail on frame begin."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("This frame should never get read."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
    };

    tester.fail_on_incoming_frame_begin_n = 1;

    s_set_readpush_frames(&tester, pushing, AWS_ARRAY_SIZE(pushing));
    ASSERT_SUCCESS(s_do_readpush_all(&tester));

    s_drain_written_messages(&tester);

    /* First frame should have completed immediately with an error */
    ASSERT_SUCCESS(s_readpush_check(&tester, 0, AWS_ERROR_HTTP_CALLBACK_FAILURE));
    ASSERT_UINT_EQUALS(0, tester.incoming_frames[0].on_payload_count);

    /* No further frames should have been read */
    ASSERT_UINT_EQUALS(1, tester.num_incoming_frames);

    /* Callback failure should have caused connection to close */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_read_halts_if_payload_fn_returns_false) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing[] = {
        {
            .payload = aws_byte_cursor_from_c_str("Fail on payload."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("This frame should never get read."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
    };

    /* Return false from 1st on_payload callback. */
    tester.fail_on_incoming_frame_payload_n = 1;

    s_set_readpush_frames(&tester, pushing, AWS_ARRAY_SIZE(pushing));
    ASSERT_SUCCESS(s_do_readpush_all(&tester));

    s_drain_written_messages(&tester);

    /* First frame should complete with error */
    ASSERT_SUCCESS(s_readpush_check(&tester, 0, AWS_ERROR_HTTP_CALLBACK_FAILURE));
    ASSERT_UINT_EQUALS(1, tester.incoming_frames[0].on_payload_count);

    /* No further frames should have been read */
    ASSERT_UINT_EQUALS(1, tester.num_incoming_frames);

    /* Callback failure should have caused connection to close */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_read_halts_if_complete_fn_returns_false) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing[] = {
        {
            .payload = aws_byte_cursor_from_c_str("Fail on completion."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
        {
            .payload = aws_byte_cursor_from_c_str("This frame should never get read."),
            .def =
                {
                    .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                    .fin = true,
                },
        },
    };

    /* Return false when 1st frame's on_complete callback */
    tester.fail_on_incoming_frame_complete_n = 1;

    s_set_readpush_frames(&tester, pushing, AWS_ARRAY_SIZE(pushing));
    ASSERT_SUCCESS(s_do_readpush_all(&tester));

    s_drain_written_messages(&tester);

    /* First frame should have succeeded */
    ASSERT_SUCCESS(s_readpush_check(&tester, 0, AWS_ERROR_SUCCESS));

    /* No further frames should have been read */
    ASSERT_UINT_EQUALS(1, tester.num_incoming_frames);

    /* Callback failure should have caused connection to close */
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&tester.testing_channel));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_window_reopens_by_default) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing = {
        .payload = aws_byte_cursor_from_c_str("Tore open the shutters and threw up the sash."),
        .def =
            {
                .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                .fin = true,
            },
    };

    s_set_readpush_frames(&tester, &pushing, 1);
    ASSERT_SUCCESS(s_do_readpush_all(&tester));

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    uint64_t total_frame_size = aws_websocket_frame_encoded_size(&pushing.def);
    ASSERT_UINT_EQUALS(total_frame_size, testing_channel_last_window_update(&tester.testing_channel));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

static int s_window_manual_increment_common(struct aws_allocator *allocator, bool on_thread) {
    struct tester tester;
    s_tester_options.manual_window_update = true;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    struct readpush_frame pushing = {
        .payload = aws_byte_cursor_from_c_str("Shrink, then open"),
        .def =
            {
                .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
                .fin = true,
            },
    };

    s_set_readpush_frames(&tester, &pushing, 1);
    ASSERT_SUCCESS(s_do_readpush_all(&tester));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Assert that window did not fully re-open*/
    uint64_t frame_minus_payload_size = aws_websocket_frame_encoded_size(&pushing.def) - pushing.def.payload_length;

    ASSERT_UINT_EQUALS(frame_minus_payload_size, testing_channel_last_window_update(&tester.testing_channel));

    /* Manually increment window */
    testing_channel_set_is_on_users_thread(&tester.testing_channel, on_thread);
    aws_websocket_increment_read_window(tester.websocket, (size_t)pushing.def.payload_length);

    /* Assert it re-opened that much */
    testing_channel_set_is_on_users_thread(&tester.testing_channel, true);
    testing_channel_drain_queued_tasks(&tester.testing_channel);
    ASSERT_UINT_EQUALS(pushing.def.payload_length, testing_channel_last_window_update(&tester.testing_channel));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_handler_window_manual_increment) {
    (void)ctx;
    return s_window_manual_increment_common(allocator, true);
}

TEST_CASE(websocket_handler_window_manual_increment_off_thread) {
    (void)ctx;
    return s_window_manual_increment_common(allocator, false);
}

TEST_CASE(websocket_midchannel_sanity_check) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_SUCCESS(s_install_downstream_handler(&tester, s_default_initial_window_size));
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_midchannel_write_message) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_SUCCESS(s_install_downstream_handler(&tester, s_default_initial_window_size));

    /* Write data */
    struct aws_byte_cursor writing = aws_byte_cursor_from_c_str("My hat it has three corners");
    ASSERT_SUCCESS(s_writepush(&tester, writing));

    /* Compare results */
    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    ASSERT_SUCCESS(s_writepush_check(&tester, 0));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_midchannel_write_multiple_messages) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_SUCCESS(s_install_downstream_handler(&tester, s_default_initial_window_size));

    struct aws_byte_cursor writing[] = {
        aws_byte_cursor_from_c_str("My hat it has three corners."),
        aws_byte_cursor_from_c_str("Three corners has my hat."),
        aws_byte_cursor_from_c_str("And had it not three corners, it would not be my hat."),
    };

    /* Write data */
    for (size_t i = 0; i < AWS_ARRAY_SIZE(writing); ++i) {
        ASSERT_SUCCESS(s_writepush(&tester, writing[i]));
    }

    /* Compare results */
    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    ASSERT_SUCCESS(s_writepush_check(&tester, 0));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_midchannel_write_huge_message) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_SUCCESS(s_install_downstream_handler(&tester, s_default_initial_window_size));

    /* Fill big buffer with random data */
    struct aws_byte_buf writing;
    ASSERT_SUCCESS(aws_byte_buf_init(&writing, allocator, 1000000));
    while (aws_byte_buf_write_be32(&writing, (uint32_t)rand())) {
    }
    while (aws_byte_buf_write_u8(&writing, (uint8_t)rand())) {
    }

    /* Send as multiple aws_io_messages that are as full as they can be */
    ASSERT_SUCCESS(s_writepush(&tester, aws_byte_cursor_from_buf(&writing)));

    /* Compare results */
    ASSERT_SUCCESS(s_drain_written_messages(&tester));
    ASSERT_TRUE(tester.num_written_io_messages > 1); /* Assert that message was huge enough to stress limits */
    ASSERT_SUCCESS(s_writepush_check(&tester, 0));

    aws_byte_buf_clean_up(&writing);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_midchannel_read_message) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_SUCCESS(s_install_downstream_handler(&tester, s_default_initial_window_size));

    struct readpush_frame pushing = {
        .payload = aws_byte_cursor_from_c_str("Hello hello can you hear me Joe?"),
        .def = {.opcode = AWS_WEBSOCKET_OPCODE_BINARY, .fin = true},
    };

    s_set_readpush_frames(&tester, &pushing, 1);
    ASSERT_SUCCESS(s_do_readpush_all(&tester));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    ASSERT_SUCCESS(s_readpush_midchannel_check(&tester, 0));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(websocket_midchannel_read_multiple_messages) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));
    ASSERT_SUCCESS(s_install_downstream_handler(&tester, s_default_initial_window_size));

    /* Read a mix of different frame types, most of which shouldn't get passed along to next handler. */
    struct readpush_frame pushing[] = {
        {
            .payload = aws_byte_cursor_from_c_str("Message 1."),
            .def = {.opcode = AWS_WEBSOCKET_OPCODE_BINARY, .fin = true},
        },
        {
            .payload = aws_byte_cursor_from_c_str("Ignore ping frame"),
            .def = {.opcode = AWS_WEBSOCKET_OPCODE_PING, .fin = true},
        },
        {
            .payload = aws_byte_cursor_from_c_str("Ignore text frame"),
            .def = {.opcode = AWS_WEBSOCKET_OPCODE_TEXT, .fin = false},
        },
        {
            .payload = aws_byte_cursor_from_c_str("Ignore continuation of text frame"),
            .def = {.opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION, .fin = true},
        },
        {
            .payload = aws_byte_cursor_from_c_str("Message 2 fragment 1/3."),
            .def = {.opcode = AWS_WEBSOCKET_OPCODE_BINARY, .fin = false},
        },
        {
            .payload = aws_byte_cursor_from_c_str("Message 2 fragment 2/3"),
            .def = {.opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION, .fin = false},
        },
        {
            .payload = aws_byte_cursor_from_c_str("Ignore ping frame"),
            .def = {.opcode = AWS_WEBSOCKET_OPCODE_PING, .fin = true},
        },
        {
            .payload = aws_byte_cursor_from_c_str("Message 2 fragment 3/3."),
            .def = {.opcode = AWS_WEBSOCKET_OPCODE_CONTINUATION, .fin = true},
        },
    };

    s_set_readpush_frames(&tester, pushing, AWS_ARRAY_SIZE(pushing));
    ASSERT_SUCCESS(s_do_readpush_all(&tester));
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    /* Check that only BINARY (and continuation of BINARY) frames passed through */
    ASSERT_SUCCESS(s_readpush_midchannel_check(&tester, 0));
    ASSERT_SUCCESS(s_readpush_midchannel_check(&tester, 4));
    ASSERT_SUCCESS(s_readpush_midchannel_check(&tester, 5));
    ASSERT_SUCCESS(s_readpush_midchannel_check(&tester, 7));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
