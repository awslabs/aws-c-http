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

#include <aws/http/private/h2_connection.h>
#include <aws/http/private/h2_decoder.h>

#include <aws/http/request_response.h>
#include <aws/testing/io_testing_channel.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

#define MAX_FRAME_SIZE 16384

/* Singleton used by tests in this file */
struct tester {
    struct aws_allocator *alloc;
    struct aws_http_connection *connection;
    struct testing_channel testing_channel;

    struct aws_h2_frame_encoder encoder;
    struct aws_array_list frames; /* contains frame */
} s_tester;

static int s_tester_init(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_http_library_init(alloc);

    s_tester.alloc = alloc;

    struct aws_testing_channel_options options = {.clock_fn = aws_high_res_clock_get_ticks};

    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, alloc, &options));

    s_tester.connection = aws_http_connection_new_http2_client(alloc, SIZE_MAX);
    ASSERT_NOT_NULL(s_tester.connection);

    { /* re-enact marriage vows of http-connection and channel (handled by http-bootstrap in real world) */
        struct aws_channel_slot *slot = aws_channel_slot_new(s_tester.testing_channel.channel);
        ASSERT_NOT_NULL(slot);
        ASSERT_SUCCESS(aws_channel_slot_insert_end(s_tester.testing_channel.channel, slot));
        ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &s_tester.connection->channel_handler));
        s_tester.connection->vtable->on_channel_handler_installed(&s_tester.connection->channel_handler, slot);
    }

    ASSERT_SUCCESS(aws_h2_frame_encoder_init(&s_tester.encoder, alloc, NULL /*logging_id*/));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
    aws_http_connection_release(s_tester.connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&s_tester.testing_channel));
    aws_h2_frame_encoder_clean_up(&s_tester.encoder);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* send the frame into the testing channel */
static int s_send_frame(struct aws_h2_frame *frame) {
    ASSERT_NOT_NULL(frame);
    struct aws_byte_buf buffer;

    /* Allocate more room than necessary, easier to debug the full output than a failed aws_h2_encode_frame() call */
    ASSERT_SUCCESS(aws_byte_buf_init(&buffer, s_tester.alloc, MAX_FRAME_SIZE));
    bool frame_complete;
    ASSERT_SUCCESS(aws_h2_encode_frame(&s_tester.encoder, frame, &buffer, &frame_complete));
    ASSERT_UINT_EQUALS(true, frame_complete);
    ASSERT_SUCCESS(testing_channel_push_read_data(&s_tester.testing_channel, aws_byte_cursor_from_buf(&buffer)));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* clean up */
    aws_byte_buf_clean_up(&buffer);
    aws_h2_frame_destroy(frame);
    return AWS_OP_SUCCESS;
}

static int s_tester_send_default_setting(void) {
    struct aws_h2_frame_setting settings[] = {
        {.id = AWS_H2_SETTINGS_ENABLE_PUSH, .value = 1}, /* real world value */
        {.id = 0x0000, .value = 0x00000000},             /* min value */
        {.id = 0xFFFF, .value = 0xFFFFFFFF},             /* max value */
    };

    struct aws_h2_frame *frame =
        aws_h2_frame_new_settings(s_tester.alloc, settings, AWS_ARRAY_SIZE(settings), false /*ack*/);
    ASSERT_SUCCESS(s_send_frame(frame));

    return AWS_OP_SUCCESS;
}

/* Test the common setup/teardown used by all tests in this file */
TEST_CASE(h2_client_sanity_check) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    return s_tester_clean_up();
}

/* Test that a stream can be created and destroyed. */
TEST_CASE(h2_client_request_create) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* create request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header headers[] = {
        {aws_byte_cursor_from_c_str(":method"), aws_byte_cursor_from_c_str("GET")},
        {aws_byte_cursor_from_c_str(":scheme"), aws_byte_cursor_from_c_str("https")},
        {aws_byte_cursor_from_c_str(":path"), aws_byte_cursor_from_c_str("/")},
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(aws_http_message_get_headers(request), headers, AWS_ARRAY_SIZE(headers)));

    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = request,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &options);
    ASSERT_NOT_NULL(stream);

    /* shutdown channel so request can be released */
    aws_channel_shutdown(s_tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));

    /* release request */
    aws_http_stream_release(stream);
    aws_http_message_release(request);

    return s_tester_clean_up();
}

/* Test that client automatically sends the HTTP/2 Connection Preface */
TEST_CASE(h2_client_connection_preface_sent) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    struct aws_byte_buf expected;
    ASSERT_SUCCESS(aws_byte_buf_init(&expected, s_tester.alloc, 1024));

    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&expected, aws_h2_connection_preface_client_string));

    /* clang-format off */
    uint8_t expected_settings[] = {
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
    };
    /* clang-format on */

    ASSERT_TRUE(aws_byte_buf_write(&expected, expected_settings, sizeof(expected_settings)));

    ASSERT_SUCCESS(testing_channel_check_written_messages(
        &s_tester.testing_channel, s_tester.alloc, aws_byte_cursor_from_buf(&expected)));

    aws_byte_buf_clean_up(&expected);

    return s_tester_clean_up();
}

/* Test that client will automatically send the PING ACK frame back, when the PING frame is received */
TEST_CASE(h2_client_ping_ack) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* Connection preface requires that SETTINGS be sent first (RFC-7540 3.5). */
    ASSERT_SUCCESS(s_tester_send_default_setting());

    uint8_t opaque_data[AWS_H2_PING_DATA_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7};

    struct aws_h2_frame *frame = aws_h2_frame_new_ping(allocator, false /*ack*/, opaque_data);
    ASSERT_NOT_NULL(frame);

    ASSERT_SUCCESS(s_send_frame(frame));
    struct aws_byte_buf expected;
    ASSERT_SUCCESS(aws_byte_buf_init(&expected, s_tester.alloc, 1024));

    /* The channel will receive the preface and the ping ACK frame */
    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&expected, aws_h2_connection_preface_client_string));
    /* clang-format off */
    uint8_t expected_settings[] = {
        /* SETTINGS FRAME - empty settings frame is acceptable in preface */
        0x00, 0x00, 0x00,           /* Length (24) */
        AWS_H2_FRAME_T_SETTINGS,    /* Type (8) */
        0x00,                       /* Flags (8) */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */

        /* PING FRAME - send another frame to be sure decoder is now functioning normally */
        0x00, 0x00, 0x08,           /* Length (24) */
        AWS_H2_FRAME_T_PING,        /* Type (8) */
        0x1,                        /* Flags (8) ACK */
        0x00, 0x00, 0x00, 0x00,     /* Reserved (1) | Stream Identifier (31) */
        /* PING */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* Opaque Data (64) */
    };
    /* clang-format on */
    ASSERT_TRUE(aws_byte_buf_write(&expected, expected_settings, sizeof(expected_settings)));
    ASSERT_SUCCESS(testing_channel_check_written_messages(
        &s_tester.testing_channel, s_tester.alloc, aws_byte_cursor_from_buf(&expected)));

    aws_byte_buf_clean_up(&expected);
    return s_tester_clean_up();
}
