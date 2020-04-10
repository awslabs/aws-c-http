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

#include "h2_test_helper.h"
#include "stream_test_helper.h"
#include <aws/http/private/h2_connection.h>
#include <aws/http/request_response.h>
#include <aws/testing/io_testing_channel.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

#define DEFINE_HEADER(NAME, VALUE)                                                                                     \
    { .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(NAME), .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(VALUE), }

/* Singleton used by tests in this file */
struct tester {
    struct aws_allocator *alloc;
    struct aws_http_connection *connection;
    struct testing_channel testing_channel;
    struct h2_fake_peer peer;
} s_tester;

static int s_tester_init(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_http_library_init(alloc);

    s_tester.alloc = alloc;

    struct aws_testing_channel_options options = {.clock_fn = aws_high_res_clock_get_ticks};

    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, alloc, &options));

    s_tester.connection = aws_http_connection_new_http2_client(alloc, true, SIZE_MAX);
    ASSERT_NOT_NULL(s_tester.connection);

    { /* re-enact marriage vows of http-connection and channel (handled by http-bootstrap in real world) */
        struct aws_channel_slot *slot = aws_channel_slot_new(s_tester.testing_channel.channel);
        ASSERT_NOT_NULL(slot);
        ASSERT_SUCCESS(aws_channel_slot_insert_end(s_tester.testing_channel.channel, slot));
        ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &s_tester.connection->channel_handler));
        s_tester.connection->vtable->on_channel_handler_installed(&s_tester.connection->channel_handler, slot);
    }

    struct h2_fake_peer_options peer_options = {
        .alloc = alloc,
        .testing_channel = &s_tester.testing_channel,
        .is_server = true,
    };
    ASSERT_SUCCESS(h2_fake_peer_init(&s_tester.peer, &peer_options));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
    h2_fake_peer_clean_up(&s_tester.peer);
    aws_http_connection_release(s_tester.connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&s_tester.testing_channel));
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* Test the common setup/teardown used by all tests in this file */
TEST_CASE(h2_client_sanity_check) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    return s_tester_clean_up();
}

/* Test that a stream can be created and destroyed. */
TEST_CASE(h2_client_stream_create) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* create request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header headers[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));

    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = request,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &options);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    /* shutdown channel so request can be released */
    aws_channel_shutdown(s_tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));

    /* release request */
    aws_http_stream_release(stream);

    aws_http_message_release(request);

    return s_tester_clean_up();
}

TEST_CASE(h2_client_unactivated_stream_cleans_up) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* create request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header headers[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));

    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = request,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &options);
    ASSERT_NOT_NULL(stream);
    /* do not activate the stream, that's the test. */

    /* shutdown channel so request can be released */
    aws_channel_shutdown(s_tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));

    aws_http_stream_release(stream);
    aws_http_message_release(request);

    return s_tester_clean_up();
}

/* Test that client automatically sends the HTTP/2 Connection Preface (magic string, followed by SETTINGS frame) */
TEST_CASE(h2_client_connection_preface_sent) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* Have the fake peer to run its decoder on what the client has written.
     * The decoder will raise an error if it doesn't receive the "client connection preface string" first. */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* Now check that client sent SETTINGS frame */
    struct h2_decoded_frame *first_written_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, 0);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_SETTINGS, first_written_frame->type);
    ASSERT_FALSE(first_written_frame->ack);

    return s_tester_clean_up();
}

/* Test that client will automatically send the PING ACK frame back, when the PING frame is received */
TEST_CASE(h2_client_ping_ack) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* Connection preface requires that SETTINGS be sent first (RFC-7540 3.5). */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    uint8_t opaque_data[AWS_H2_PING_DATA_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7};

    struct aws_h2_frame *frame = aws_h2_frame_new_ping(allocator, false /*ack*/, opaque_data);
    ASSERT_NOT_NULL(frame);

    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Have the fake peer to run its decoder on what the client has written.
     * The decoder will raise an error if it doesn't receive the "client connection preface string" first. */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* Now check that client sent PING ACK frame, it should be the latest frame received by peer
     * The last frame should be a ping type with ack on, and identical payload */
    struct h2_decoded_frame *latest_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_PING, latest_frame->type);
    ASSERT_TRUE(latest_frame->ack);
    ASSERT_BIN_ARRAYS_EQUALS(opaque_data, AWS_H2_PING_DATA_SIZE, latest_frame->ping_opaque_data, AWS_H2_PING_DATA_SIZE);

    return s_tester_clean_up();
}
/* TODO: test that ping response is sent with higher priority than any other frame */

TEST_CASE(h2_client_setting_ack) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* Connection preface requires that SETTINGS be sent first (RFC-7540 3.5). */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Have the fake peer to run its decoder on what the client has written. */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* The Setting ACK frame should be sent back */
    struct h2_decoded_frame *latest_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_SETTINGS, latest_frame->type);
    ASSERT_TRUE(latest_frame->ack);

    return s_tester_clean_up();
}

static int s_stream_tester_init(struct client_stream_tester *stream_tester, struct aws_http_message *request) {
    struct client_stream_tester_options options = {
        .request = request,
        .connection = s_tester.connection,
    };
    return client_stream_tester_init(stream_tester, s_tester.alloc, &options);
}

static int s_compare_headers(const struct aws_http_headers *expected, const struct aws_http_headers *got) {

    ASSERT_UINT_EQUALS(aws_http_headers_count(expected), aws_http_headers_count(got));
    for (size_t i = 0; i < aws_http_headers_count(expected); ++i) {
        struct aws_http_header expected_field;
        aws_http_headers_get_index(expected, i, &expected_field);

        struct aws_http_header got_field;
        aws_http_headers_get_index(got, i, &got_field);

        ASSERT_TRUE(aws_byte_cursor_eq(&expected_field.name, &got_field.name));
        ASSERT_TRUE(aws_byte_cursor_eq(&expected_field.value, &got_field.value));
        ASSERT_INT_EQUALS(expected_field.compression, got_field.compression);
    }

    return AWS_OP_SUCCESS;
}

/* Test that h2 can split cookie headers from request, if we need to compress it use cache. */
TEST_CASE(h2_client_request_cookie_headers) {
    (void)ctx;
    aws_http_library_init(allocator);

    /* send a request with cookie headers */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
        DEFINE_HEADER("cookie", "a=b; c=d; e=f"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct aws_http_headers *h2_headers = aws_h2_create_headers_from_request(request, allocator);

    /* set expected h2 style headers */
    struct aws_http_header expected_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
        DEFINE_HEADER("cookie", "a=b"),
        DEFINE_HEADER("cookie", "c=d"),
        DEFINE_HEADER("cookie", "e=f"),
    };
    struct aws_http_headers *expected_headers = aws_http_headers_new(allocator);
    ASSERT_SUCCESS(
        aws_http_headers_add_array(expected_headers, expected_headers_src, AWS_ARRAY_SIZE(expected_headers_src)));

    ASSERT_SUCCESS(s_compare_headers(expected_headers, h2_headers));

    /* clean up */
    aws_http_headers_release(h2_headers);
    aws_http_headers_release(expected_headers);
    aws_http_message_release(request);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* Test that a simple request/response can be carried to completion.
 * The request consists of a single HEADERS frame and the response consists of a single HEADERS frame. */
TEST_CASE(h2_client_stream_complete) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));

    /* validate sent request, */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_TRUE(sent_headers_frame->end_stream);
    ASSERT_SUCCESS(s_compare_headers(aws_http_message_get_headers(request), sent_headers_frame->headers));

    /* fake peer sends response  */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame = aws_h2_frame_new_headers(
        allocator, aws_http_stream_get_id(stream_tester.stream), response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* validate that client received complete response */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(404, stream_tester.response_status);
    ASSERT_SUCCESS(s_compare_headers(response_headers, stream_tester.response_headers));

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Test that h2 stream can take a h1 request massega and transfrom it to h2 style to send it. */
TEST_CASE(h2_client_stream_with_h1_request_message) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send an h1 request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_method(request, aws_http_method_get));
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER("Accept", "*/*"),
        DEFINE_HEADER("Host", "example.com"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));

    /* set expected h2 style headers */
    struct aws_http_header expected_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":authority", "example.com"),
        DEFINE_HEADER(":path", "/"),
        DEFINE_HEADER("accept", "*/*"),
    };
    struct aws_http_headers *expected_headers = aws_http_headers_new(allocator);
    ASSERT_SUCCESS(
        aws_http_headers_add_array(expected_headers, expected_headers_src, AWS_ARRAY_SIZE(expected_headers_src)));
    /* validate sent request, */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_TRUE(sent_headers_frame->end_stream);
    ASSERT_SUCCESS(s_compare_headers(expected_headers, sent_headers_frame->headers));

    /* clean up */
    aws_http_headers_release(expected_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Receiving malformed headers should result in a "Stream Error", not a "Connection Error". */
TEST_CASE(h2_client_stream_err_malformed_header) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* fake peer sends response with malformed header */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":STATUS", "404"), /* uppercase name forbidden in h2 */
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame = aws_h2_frame_new_headers(
        allocator, aws_http_stream_get_id(stream_tester.stream), response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* validate that stream completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);

    /* a stream error should not affect the connection */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_RST_STREAM, rst_stream_frame->type);
    ASSERT_UINT_EQUALS(AWS_H2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_conn_err_stream_frames_received_for_idle_stream) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* fake peer sends response to "idle" (aka doesn't exist yet) stream 99 */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "200"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, 99 /*stream_id*/, response_headers, true /* end_stream */, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* validate that connection has closed due to PROTOCOL_ERROR */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));

    /* #TODO client should send GOAWAY */

    /* clean up */
    aws_http_headers_release(response_headers);
    return s_tester_clean_up();
}

/* Peer may have sent certain frames (WINDOW_UPDATE and RST_STREAM) before realizing
 * that we have closed the stream. These frames should be ignored. */
TEST_CASE(h2_client_stream_ignores_some_frames_received_soon_after_closing) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* fake peer sends complete response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* fake peer sends WINDOW_UPDATE */
    peer_frame = aws_h2_frame_new_window_update(allocator, stream_id, 99);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* fake peer sends RST_STREAM */
    peer_frame = aws_h2_frame_new_rst_stream(allocator, stream_id, AWS_H2_ERR_ENHANCE_YOUR_CALM);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* validate that stream completed successfully.
     * the WINDOW_UPDATE and RST_STREAM should be ignored because
     * they arrived soon after the client had sent END_STREAM */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Test receiving a response with DATA frames */
TEST_CASE(h2_client_stream_receive_data) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    /* fake peer sends response headers */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "200"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* fake peer sends response body */
    const char *body_src = "hello";
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(&s_tester.peer, stream_id, body_src, true /*end_stream*/));

    /* validate that client received complete response */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_SUCCESS(s_compare_headers(response_headers, stream_tester.response_headers));
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&stream_tester.response_body, body_src));

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* A message is malformed if DATA is received before HEADERS */
TEST_CASE(h2_client_stream_err_receive_data_before_headers) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    /* fake peer sends response body BEFORE any response headers */
    const char *body_src = "hello";
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(&s_tester.peer, stream_id, body_src, true /*end_stream*/));

    /* validate that stream completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);

    /* a stream error should not affect the connection */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_RST_STREAM, rst_stream_frame->type);
    ASSERT_UINT_EQUALS(AWS_H2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}