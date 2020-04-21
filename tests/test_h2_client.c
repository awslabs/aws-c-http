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
#include <aws/io/stream.h>
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

/* Calling aws_http_connection_close() should cleanly shut down connection */
TEST_CASE(h2_client_close) {
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

    /* close connection */
    aws_http_connection_close(s_tester.connection);

    /* connection should immediately lose "open" status */
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));

    /* finish shutting down */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* validate that pending streams complete with error */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, stream_tester.on_complete_error_code);

    /* validate that GOAWAY sent */
    struct h2_decoded_frame *goaway =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_GOAWAY, 0, NULL);
    ASSERT_NOT_NULL(goaway);
    ASSERT_UINT_EQUALS(AWS_H2_ERR_NO_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Test that client automatically sends the HTTP/2 Connection Preface (magic string, followed by initial SETTINGS frame,
 * which we disabled the push_promise) And it will not be applied until the SETTINGS ack is received */
TEST_CASE(h2_client_connection_init_setting_applied_after_ack_by_peer) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

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

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* fake peer sends push_promise */
    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    /* fake peer sends push request (PUSH_PROMISE) */
    struct aws_http_header push_request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":authority", "veryblackpage.com"),
        DEFINE_HEADER(":path", "/style.css"),
    };
    struct aws_http_headers *push_request_headers = aws_http_headers_new(allocator);
    ASSERT_SUCCESS(aws_http_headers_add_array(
        push_request_headers, push_request_headers_src, AWS_ARRAY_SIZE(push_request_headers_src)));

    uint32_t promised_stream_id = 2;
    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_push_promise(allocator, stream_id, promised_stream_id, push_request_headers, 0);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate the connection is still open */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* fake peer sends setting ack */
    struct aws_h2_frame *settings_ack_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, settings_ack_frame));
    /* fake peer sends another push_promise again, after setting applied, connection will be closed */
    peer_frame = aws_h2_frame_new_push_promise(allocator, stream_id, promised_stream_id + 2, push_request_headers, 0);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate the connection completed with error */
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));
    /* clean up */
    aws_http_headers_release(push_request_headers);
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

    /* validate that client sent GOAWAY */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct h2_decoded_frame *goaway =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_GOAWAY, 0, NULL);
    ASSERT_NOT_NULL(goaway);
    ASSERT_UINT_EQUALS(AWS_H2_ERR_PROTOCOL_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

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

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

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
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_stream_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, stream_id, 0, NULL);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_RST_STREAM, rst_stream_frame->type);
    ASSERT_UINT_EQUALS(AWS_H2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Test sending a request with DATA frames */
TEST_CASE(h2_client_stream_send_data) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* send request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "POST"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    const char *body_src = "hello";
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str(body_src);
    struct aws_input_stream *request_body = aws_input_stream_new_from_cursor(allocator, &body_cursor);
    aws_http_message_set_body_stream(request, request_body);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    /* validate sent request (client should have sent SETTINGS, HEADERS, DATA (END_STREAM) */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_UINT_EQUALS(3, h2_decode_tester_frame_count(&s_tester.peer.decode));

    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, 1);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_SUCCESS(s_compare_headers(aws_http_message_get_headers(request), sent_headers_frame->headers));
    ASSERT_FALSE(sent_headers_frame->end_stream);

    struct h2_decoded_frame *sent_data_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, 2);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_DATA, sent_data_frame->type);
    ASSERT_TRUE(sent_data_frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&sent_data_frame->data, body_src));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));

    /* fake peer sends response headers */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "200"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* validate that request completed successfully */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    aws_input_stream_destroy(request_body);
    return s_tester_clean_up();
}

/* Test sending multiple requests, each with large bodies that must be sent across multiple DATA frames.
 * The connection should not let one stream hog the connection, the streams should take turns sending DATA.
 * Also, the stream should not send more than one aws_io_message full of frames per event-loop-tick */
TEST_CASE(h2_client_stream_send_lots_of_data) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* bodies must be big enough to span multiple H2-frames and multiple aws_io_messages */
    size_t body_size =
        aws_max_size(aws_h2_settings_initial[AWS_H2_SETTINGS_MAX_FRAME_SIZE], g_aws_channel_max_fragment_size) * 5;

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send multiple requests */
    enum { NUM_STREAMS = 3 };
    struct aws_http_message *requests[NUM_STREAMS];
    struct aws_http_header request_headers_src[NUM_STREAMS][3] = {
        {
            DEFINE_HEADER(":method", "POST"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/a.txt"),
        },
        {
            DEFINE_HEADER(":method", "POST"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/b.txt"),
        },
        {
            DEFINE_HEADER(":method", "POST"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/c.txt"),
        },
    };

    struct aws_byte_buf request_body_bufs[NUM_STREAMS];
    struct aws_input_stream *request_bodies[NUM_STREAMS];
    struct client_stream_tester stream_testers[NUM_STREAMS];
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        requests[i] = aws_http_message_new_request(allocator);
        aws_http_message_add_header_array(requests[i], request_headers_src[i], AWS_ARRAY_SIZE(request_headers_src[i]));

        /* fill first body with "aaaa...", second with "bbbb...", etc */
        ASSERT_SUCCESS(aws_byte_buf_init(&request_body_bufs[i], allocator, body_size));
        ASSERT_TRUE(aws_byte_buf_write_u8_n(&request_body_bufs[i], (uint8_t)('a' + i), body_size));
        struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&request_body_bufs[i]);

        request_bodies[i] = aws_input_stream_new_from_cursor(allocator, &body_cursor);
        ASSERT_NOT_NULL(request_bodies[i]);

        aws_http_message_set_body_stream(requests[i], request_bodies[i]);

        ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[i], requests[i]));
    }

    /* now loop until all requests are done sending.
     * 1 aws_io_message should be written with each tick of the event-loop.
     * determine when (based on event-loop tick count) each request sent its END_STREAM. */
    struct aws_linked_list *written_msg_queue = testing_channel_get_written_message_queue(&s_tester.testing_channel);
    size_t tick_i = 0;
    size_t end_stream_count = 0;
    size_t end_stream_tick[NUM_STREAMS];
    while (end_stream_count < NUM_STREAMS) {

        /* check that connection sends exactly 1 aws_io_message per event-loop tick */
        testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);

        size_t written_msg_queue_len = 0;
        for (struct aws_linked_list_node *node = aws_linked_list_begin(written_msg_queue);
             node != aws_linked_list_end(written_msg_queue);
             node = aws_linked_list_next(node)) {
            written_msg_queue_len++;
        }
        ASSERT_UINT_EQUALS(1, written_msg_queue_len);

        /* decode all new frames and examine them to see if any request has finished */
        const size_t prev_frame_count = h2_decode_tester_frame_count(&s_tester.peer.decode);
        ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
        const size_t frame_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

        for (size_t i = prev_frame_count; i < frame_count; ++i) {
            struct h2_decoded_frame *frame = h2_decode_tester_get_frame(&s_tester.peer.decode, i);
            if (frame->type == AWS_H2_FRAME_T_DATA) {
                /* Send a Window update frame back */
                struct aws_h2_frame *connection_window_update =
                    aws_h2_frame_new_window_update(allocator, 0, (uint32_t)frame->data.len);
                ASSERT_NOT_NULL(connection_window_update);
                h2_fake_peer_send_frame(&s_tester.peer, connection_window_update);
                struct aws_h2_frame *stream_window_update =
                    aws_h2_frame_new_window_update(allocator, frame->stream_id, (uint32_t)frame->data.len);
                ASSERT_NOT_NULL(stream_window_update);
                h2_fake_peer_send_frame(&s_tester.peer, stream_window_update);
            }
            if (frame->type == AWS_H2_FRAME_T_DATA && frame->end_stream) {

                end_stream_tick[end_stream_count++] = tick_i;
            }
        }

        tick_i++;
    }

    for (size_t i = 1; i < NUM_STREAMS; ++i) {
        /* as a simple fairness test, check that each of the requests finished within 1 event-loop tick of the last. */
        size_t streams_finished_n_ticks_apart = end_stream_tick[i] - end_stream_tick[i - 1];
        ASSERT_TRUE(streams_finished_n_ticks_apart <= 1);

        /* validate that all data sent successfully */
        ASSERT_SUCCESS(h2_decode_tester_check_data_across_frames(
            &s_tester.peer.decode,
            aws_http_stream_get_id(stream_testers[i].stream),
            aws_byte_cursor_from_buf(&request_body_bufs[i]),
            true /*expect_end_frame*/));
    }

    /* finally, send responses and ensure all streams complete successfully */
    struct aws_http_header response_headers_src[] = {DEFINE_HEADER(":status", "200")};
    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        struct aws_h2_frame *response_frame = aws_h2_frame_new_headers(
            allocator,
            aws_http_stream_get_id(stream_testers[i].stream),
            response_headers,
            true /* end_stream */,
            0,
            NULL);
        ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));
    }

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        ASSERT_TRUE(stream_testers[i].complete);
        ASSERT_INT_EQUALS(200, stream_testers[i].response_status);
    }

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        client_stream_tester_clean_up(&stream_testers[i]);
        aws_http_message_release(requests[i]);
        aws_input_stream_destroy(request_bodies[i]);
        aws_byte_buf_clean_up(&request_body_bufs[i]);
    }
    return s_tester_clean_up();
}

/* Test sending a request whose aws_input_stream is not providing body data all at once */
TEST_CASE(h2_client_stream_send_stalled_data) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* get request ready
     * the body_stream will stall and provide no data when we try to read from it */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "POST"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    const char *body_src = "hello";
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str(body_src);
    struct aws_input_stream *request_body = aws_input_stream_new_tester(allocator, body_cursor);
    aws_input_stream_tester_set_max_bytes_per_read(request_body, 0);

    aws_http_message_set_body_stream(request, request_body);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));

    /* Execute 1 event-loop tick. Validate that no DATA frames were written */
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_NULL(h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_DATA, 0 /*search_start_idx*/, NULL));

    /* Execute a few more event-loop ticks. No more frames should be written */
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(aws_linked_list_empty(testing_channel_get_written_message_queue(&s_tester.testing_channel)));

    /* Let aws_input_stream produce just 1 byte. This should result in 1 DATA frame with 1 byte of payload */
    aws_input_stream_tester_set_max_bytes_per_read(request_body, 1);
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    size_t data_frame_idx;
    struct h2_decoded_frame *data_frame = h2_decode_tester_find_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_DATA, 0 /*search_start_idx*/, &data_frame_idx);
    ASSERT_NOT_NULL(data_frame);
    ASSERT_UINT_EQUALS(1, data_frame->data.len);
    ASSERT_FALSE(data_frame->end_stream);

    ASSERT_NULL(h2_decode_tester_find_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_DATA, data_frame_idx + 1 /*search_start_idx*/, NULL));

    /* finish up. Let aws_input_stream produce the rest of its data */
    aws_input_stream_tester_set_max_bytes_per_read(request_body, SIZE_MAX);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_SUCCESS(
        h2_decode_tester_check_data_str_across_frames(&s_tester.peer.decode, stream_id, body_src, true /*end_stream*/));

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    aws_input_stream_destroy(request_body);
    return s_tester_clean_up();
}

static int s_fake_peer_window_update_check(
    struct aws_allocator *alloc,
    uint32_t stream_id,
    uint32_t window_size_increment,
    const char *expected_data,
    size_t expected_data_len,
    bool end_stream,
    bool skip_check_data) {

    struct aws_h2_frame *stream_window_update = aws_h2_frame_new_window_update(alloc, stream_id, window_size_increment);
    ASSERT_NOT_NULL(stream_window_update);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, stream_window_update));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    if (expected_data) {
        /* DATA should be received now as the last frame, check the result */
        struct h2_decoded_frame *latest_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
        ASSERT_INT_EQUALS(AWS_H2_FRAME_T_DATA, latest_frame->type);
        ASSERT_TRUE(latest_frame->end_stream == end_stream);
        if (!skip_check_data) {
            ASSERT_BIN_ARRAYS_EQUALS(
                latest_frame->data.buffer, latest_frame->data.len, expected_data, expected_data_len);
        }
    } else {
        ASSERT_TRUE(aws_linked_list_empty(testing_channel_get_written_message_queue(&s_tester.testing_channel)));
    }
    return AWS_OP_SUCCESS;
}

/* Test sending DATA frames is blocked by stream window size, and will resume when we receive window update */
TEST_CASE(h2_client_stream_send_data_controlled_by_stream_window_size) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    /* fake peer sends setting with 5 initial window size */
    struct aws_h2_frame_setting settings_array[1];
    settings_array[0].id = AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE;
    settings_array[0].value = 5;
    struct aws_h2_frame *settings = aws_h2_frame_new_settings(allocator, settings_array, 1, false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* send request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    const char *body_src = "hello CRT!";

    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str(body_src);
    struct aws_input_stream *request_body = aws_input_stream_new_from_cursor(allocator, &body_cursor);
    aws_http_message_set_body_stream(request, request_body);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    /* validate sent request (client should only have sent HEADERS) */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    frames_count += 1;
    ASSERT_UINT_EQUALS(frames_count, h2_decode_tester_frame_count(&s_tester.peer.decode));

    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count - 1);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_SUCCESS(s_compare_headers(aws_http_message_get_headers(request), sent_headers_frame->headers));
    ASSERT_FALSE(sent_headers_frame->end_stream);

    /* fake peer sends a WINDOW_UPDATE on stream to unblock the DATA frame. We need to release the min window size */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator, stream_id, 256, "hello CRT!", 10, true /*end_stream*/, false /*skip_check_data*/));

    /* fake peer sends response headers */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "200"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* validate that request completed successfully */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    aws_input_stream_destroy(request_body);
    return s_tester_clean_up();
}

/* Test stream window size becomes negative, and will resume only when it back to positive again. */
TEST_CASE(h2_client_stream_send_data_controlled_by_negative_stream_window_size) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    /* fake peer sends setting with 300 initial window size */
    struct aws_h2_frame_setting settings_array[1];
    settings_array[0].id = AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE;
    settings_array[0].value = 300;
    struct aws_h2_frame *settings = aws_h2_frame_new_settings(allocator, settings_array, 1, false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* send request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    char body_src[400];
    for (int i = 0; i < 400; i++) {
        body_src[i] = 'a';
    }

    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_array(body_src, 400);
    struct aws_input_stream *request_body = aws_input_stream_new_from_cursor(allocator, &body_cursor);
    aws_http_message_set_body_stream(request, request_body);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    /* validate sent request (client should have sent HEADERS, part of DATA(first 300 bytes) */
    frames_count += 2;
    ASSERT_UINT_EQUALS(frames_count, h2_decode_tester_frame_count(&s_tester.peer.decode));

    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count - 2);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_SUCCESS(s_compare_headers(aws_http_message_get_headers(request), sent_headers_frame->headers));
    ASSERT_FALSE(sent_headers_frame->end_stream);
    struct h2_decoded_frame *sent_data_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count - 1);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_DATA, sent_data_frame->type);
    ASSERT_FALSE(sent_data_frame->end_stream);
    ASSERT_BIN_ARRAYS_EQUALS(sent_data_frame->data.buffer, sent_data_frame->data.len, body_src, 300);

    /* fake peer set new INITIAL_WINDOW_SIZE to 0 to make stream window size to be negative,which should be -300 */
    settings_array[0].value = 0;
    settings = aws_h2_frame_new_settings(allocator, settings_array, 1, false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check for setting ACK */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    frames_count += 1;
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_UINT_EQUALS(frames_count, h2_decode_tester_frame_count(&s_tester.peer.decode));
    struct h2_decoded_frame *setting_ack_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count - 1);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_SETTINGS, setting_ack_frame->type);
    ASSERT_TRUE(setting_ack_frame->ack);

    /* fake peer sends a WINDOW_UPDATE on stream to try unblocking the DATA frame. But just release (300+min window
     * size) bytes, it will still be min window size, nothing will be sent */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator, stream_id, 300 + AWS_H2_MIN_WINDOW_SIZE, NULL, 0, false /*end_stream*/, false /*skip_check_data*/));

    /* Release one more bytes, rest of the data will be sent */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator, stream_id, 1, body_src, 100, true /*end_stream*/, false /*skip_check_data*/));

    /* fake peer sends response headers */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "200"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* validate that request completed successfully */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    aws_input_stream_destroy(request_body);
    return s_tester_clean_up();
}

/* Test when connection window size becomes zero, no stream can send data */
TEST_CASE(h2_client_stream_send_data_controlled_by_connection_window_size) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* bodies must be big enough to span multiple H2-frames and multiple aws_io_messages */
    size_t body_size = aws_h2_settings_initial[AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE] - AWS_H2_MIN_WINDOW_SIZE;

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send multiple requests */
    enum { NUM_STREAMS = 2 };
    struct aws_http_message *requests[NUM_STREAMS];
    struct aws_http_header request_headers_src[NUM_STREAMS][3] = {
        {
            DEFINE_HEADER(":method", "GET"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/a.txt"),
        },
        {
            DEFINE_HEADER(":method", "GET"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/b.txt"),
        },
    };

    struct aws_byte_buf request_body_bufs[NUM_STREAMS];
    struct aws_input_stream *request_bodies[NUM_STREAMS];
    struct client_stream_tester stream_testers[NUM_STREAMS];
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        requests[i] = aws_http_message_new_request(allocator);
        aws_http_message_add_header_array(requests[i], request_headers_src[i], AWS_ARRAY_SIZE(request_headers_src[i]));

        /* fill first body with "aaaa...", second with "bbbb...", etc */
        ASSERT_SUCCESS(aws_byte_buf_init(&request_body_bufs[i], allocator, body_size));
        ASSERT_TRUE(aws_byte_buf_write_u8_n(&request_body_bufs[i], (uint8_t)('a' + i), body_size));
        struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&request_body_bufs[i]);

        request_bodies[i] = aws_input_stream_new_from_cursor(allocator, &body_cursor);
        ASSERT_NOT_NULL(request_bodies[i]);

        aws_http_message_set_body_stream(requests[i], request_bodies[i]);
    }
    /* Send the first request, which will make the connection window to the min_window_size and stop connection from
     * sending more data */
    ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[0], requests[0]));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    /* Check the last frame is the end of the stream, if all the data is send. */
    struct h2_decoded_frame *latest_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_DATA, latest_frame->type);
    ASSERT_TRUE(latest_frame->end_stream);
    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* Send the rest requst, which only data frames will be blocked */
    ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[1], requests[1]));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    frames_count += 1;
    /* Check only the HEADERS frame is received */
    ASSERT_UINT_EQUALS(frames_count, h2_decode_tester_frame_count(&s_tester.peer.decode));
    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count - 1);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_SUCCESS(s_compare_headers(aws_http_message_get_headers(requests[1]), sent_headers_frame->headers));
    ASSERT_FALSE(sent_headers_frame->end_stream);

    /* WINDOW UPDATE at the second stream will no help */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator,
        aws_http_stream_get_id(stream_testers[1].stream),
        400,
        NULL,
        0,
        false /*end_stream*/,
        false /*skip_check_data*/));

    char expected[400];
    for (int i = 0; i < 400; i++) {
        expected[i] = 'b';
    }

    /* Connection window update will help, and the rest of the previous request is sent now */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator, 0, 400 - AWS_H2_MIN_WINDOW_SIZE, expected, 400, false /*end_stream*/, false /*skip_check_data*/));

    /* Release all the window */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator, 0, (uint32_t)body_size, "", 0, true /*end_stream*/, true /*skip_check_data*/));

    /* finally, send responses and ensure all streams complete successfully */
    struct aws_http_header response_headers_src[] = {DEFINE_HEADER(":status", "200")};
    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        struct aws_h2_frame *response_frame = aws_h2_frame_new_headers(
            allocator,
            aws_http_stream_get_id(stream_testers[i].stream),
            response_headers,
            true /* end_stream */,
            0,
            NULL);
        ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));
    }

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        ASSERT_TRUE(stream_testers[i].complete);
        ASSERT_INT_EQUALS(200, stream_testers[i].response_status);
    }

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        client_stream_tester_clean_up(&stream_testers[i]);
        aws_http_message_release(requests[i]);
        aws_input_stream_destroy(request_bodies[i]);
        aws_byte_buf_clean_up(&request_body_bufs[i]);
    }
    return s_tester_clean_up();
}

/* Test when connection window size becomes zero, and stream window size is zero, window_update on connection and stream
 * will not affect eachother */
TEST_CASE(h2_client_stream_send_data_controlled_by_connection_and_stream_window_size) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* bodies must be big enough to span multiple H2-frames and multiple aws_io_messages */
    size_t body_size = aws_h2_settings_initial[AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE];

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send multiple requests */
    enum { NUM_STREAMS = 3 };
    struct aws_http_message *requests[NUM_STREAMS];
    struct aws_http_header request_headers_src[NUM_STREAMS][3] = {
        {
            DEFINE_HEADER(":method", "GET"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/a.txt"),
        },
        {
            DEFINE_HEADER(":method", "GET"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/b.txt"),
        },
        {
            DEFINE_HEADER(":method", "GET"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/c.txt"),
        },
    };

    struct aws_byte_buf request_body_bufs[NUM_STREAMS];
    struct aws_input_stream *request_bodies[NUM_STREAMS];
    struct client_stream_tester stream_testers[NUM_STREAMS];
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        requests[i] = aws_http_message_new_request(allocator);
        aws_http_message_add_header_array(requests[i], request_headers_src[i], AWS_ARRAY_SIZE(request_headers_src[i]));

        /* fill first body with "aaaa...", second with "bbbb...", etc */
        ASSERT_SUCCESS(aws_byte_buf_init(&request_body_bufs[i], allocator, body_size));
        ASSERT_TRUE(aws_byte_buf_write_u8_n(&request_body_bufs[i], (uint8_t)('a' + i), body_size));
        struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&request_body_bufs[i]);

        request_bodies[i] = aws_input_stream_new_from_cursor(allocator, &body_cursor);
        ASSERT_NOT_NULL(request_bodies[i]);

        aws_http_message_set_body_stream(requests[i], request_bodies[i]);
    }
    /* Send the first request, which will take all the connection window */
    ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[0], requests[0]));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    /* Check the last frame is the end of the stream, if all the data is send. But it's not true in this test. */
    /* Since we stop sending data when the connection window size is smaller than 256 bytes, we actually cannot receive
     * the end of the stream here. */
    struct h2_decoded_frame *latest_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_DATA, latest_frame->type);
    ASSERT_FALSE(latest_frame->end_stream);
    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* fake peer set new INITIAL_WINDOW_SIZE to 0 to set window size for rest stream to be 0 */
    struct aws_h2_frame_setting settings_array[1];
    settings_array[0].id = AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE;
    settings_array[0].value = 0;
    struct aws_h2_frame *settings = aws_h2_frame_new_settings(allocator, settings_array, 1, false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Get setting ACK */
    frames_count += 1;
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_UINT_EQUALS(frames_count, h2_decode_tester_frame_count(&s_tester.peer.decode));
    struct h2_decoded_frame *setting_ack_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count - 1);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_SETTINGS, setting_ack_frame->type);
    ASSERT_TRUE(setting_ack_frame->ack);

    /* Send the rest requst, which only data frames will be blocked */
    ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[1], requests[1]));
    ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[2], requests[2]));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    /* Check only the HEADERS frames of two streams are received */
    frames_count += 2;
    ASSERT_UINT_EQUALS(frames_count, h2_decode_tester_frame_count(&s_tester.peer.decode));
    /* Header for requests[1] */
    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count - 2);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_SUCCESS(s_compare_headers(aws_http_message_get_headers(requests[1]), sent_headers_frame->headers));
    ASSERT_FALSE(sent_headers_frame->end_stream);
    /* Header for requests[2] */
    sent_headers_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count - 1);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_SUCCESS(s_compare_headers(aws_http_message_get_headers(requests[2]), sent_headers_frame->headers));
    ASSERT_FALSE(sent_headers_frame->end_stream);

    char expected_b[400];
    for (int i = 0; i < 400; i++) {
        expected_b[i] = 'b';
    }
    char expected_c[400];
    for (int i = 0; i < 400; i++) {
        expected_c[i] = 'c';
    }
    /* WINDOW UPDATE at requests[1] will no help */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator,
        aws_http_stream_get_id(stream_testers[1].stream),
        400,
        NULL,
        0,
        false /*end_stream*/,
        false /*skip_check_data*/));

    /* WINDOW UPDATE at the connection to keep connection wide open, but only 10 bytes of requests[1] will be sent */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator, 0, (uint32_t)body_size * 3, expected_b, 400, false /*end_stream*/, false /*skip_check_data*/));

    /* WINDOW UPDATE at requests[1] will help requests[1] to send data now */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator,
        aws_http_stream_get_id(stream_testers[1].stream),
        400,
        expected_b,
        400,
        false /*end_stream*/,
        false /*skip_check_data*/));
    /* WINDOW UPDATE at requests[2] will help requests[2] to send data now */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator,
        aws_http_stream_get_id(stream_testers[2].stream),
        400,
        expected_c,
        400,
        false /*end_stream*/,
        false /*skip_check_data*/));

    /* Release all the window for requests[0] */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator,
        aws_http_stream_get_id(stream_testers[0].stream),
        (uint32_t)body_size + AWS_H2_MIN_WINDOW_SIZE,
        "",
        0,
        true /*end_stream*/,
        true /*skip_check_data*/));
    /* Release all the window for requests[1] */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator,
        aws_http_stream_get_id(stream_testers[1].stream),
        (uint32_t)body_size + AWS_H2_MIN_WINDOW_SIZE,
        "",
        0,
        true /*end_stream*/,
        true /*skip_check_data*/));
    /* Release all the window for requests[2] */
    ASSERT_SUCCESS(s_fake_peer_window_update_check(
        allocator,
        aws_http_stream_get_id(stream_testers[2].stream),
        (uint32_t)body_size + AWS_H2_MIN_WINDOW_SIZE,
        "",
        0,
        true /*end_stream*/,
        true /*skip_check_data*/));

    /* finally, send responses and ensure all streams complete successfully */
    struct aws_http_header response_headers_src[] = {DEFINE_HEADER(":status", "200")};
    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        struct aws_h2_frame *response_frame = aws_h2_frame_new_headers(
            allocator,
            aws_http_stream_get_id(stream_testers[i].stream),
            response_headers,
            true /* end_stream */,
            0,
            NULL);
        ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));
    }

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        ASSERT_TRUE(stream_testers[i].complete);
        ASSERT_INT_EQUALS(200, stream_testers[i].response_status);
    }

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        client_stream_tester_clean_up(&stream_testers[i]);
        aws_http_message_release(requests[i]);
        aws_input_stream_destroy(request_bodies[i]);
        aws_byte_buf_clean_up(&request_body_bufs[i]);
    }
    return s_tester_clean_up();
}

/* Test receiving a response with DATA frames, the window update frame will be sent */
TEST_CASE(h2_client_stream_send_window_update) {
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

    /* fake peer sends 1 DATA frame */
    const char *body_src = "hello";
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(&s_tester.peer, stream_id, body_src, false /*end_stream*/));

    /* check that 2 WINDOW_UPDATE frames have been sent.
     * 1 for the connection, and 1 for the stream */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct h2_decoded_frame *stream_window_update_frame = h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id, 0 /*idx*/, NULL);
    ASSERT_NOT_NULL(stream_window_update_frame);
    ASSERT_UINT_EQUALS(5, stream_window_update_frame->window_size_increment);

    struct h2_decoded_frame *connection_window_update_frame = h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, 0 /*stream_id*/, 0 /*idx*/, NULL);
    ASSERT_NOT_NULL(connection_window_update_frame);
    ASSERT_UINT_EQUALS(5, connection_window_update_frame->window_size_increment);

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Receiving invalid WINDOW_UPDATE frame of stream should result in a "Stream Error", invalid WINDOW_UPDATE frame of
 * connection should result in a "Connection Error". */
static int s_invalid_window_update(
    struct aws_allocator *allocator,
    void *ctx,
    uint32_t window_update_size,
    enum aws_h2_error_code h2_error_code) {
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

    /* Send the largest update on stream, which will cause the flow-control window of stream exceeding the max */
    struct aws_h2_frame *stream_window_update =
        aws_h2_frame_new_window_update(allocator, aws_http_stream_get_id(stream_tester.stream), window_update_size);
    ASSERT_NOT_NULL(stream_window_update);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, stream_window_update));

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
    ASSERT_INT_EQUALS(h2_error_code, rst_stream_frame->error_code);

    /* Send the largest update on stream, which will cause the flow-control window of stream exceeding the max */
    stream_window_update = aws_h2_frame_new_window_update(allocator, 0, window_update_size);
    ASSERT_NOT_NULL(stream_window_update);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, stream_window_update));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate the connection completed with error */
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));

    /* client should send GOAWAY */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *goaway =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_GOAWAY, 0, NULL);
    ASSERT_NOT_NULL(goaway);
    ASSERT_UINT_EQUALS(h2_error_code, goaway->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Window update cause window to exceed max size will lead to FLOW_CONTROL_ERROR */
TEST_CASE(h2_client_conn_err_window_update_exceed_max) {
    return s_invalid_window_update(allocator, ctx, AWS_H2_WINDOW_UPDATE_MAX, AWS_H2_ERR_FLOW_CONTROL_ERROR);
}

/* Window update with zero update size will lead to PROTOCOL_ERROR */
TEST_CASE(h2_client_conn_err_window_update_size_zero) {
    return s_invalid_window_update(allocator, ctx, 0, AWS_H2_ERR_PROTOCOL_ERROR);
}

/* SETTINGS_INITIAL_WINDOW_SIZE cause stream window to exceed the max size is a Connection ERROR... */
TEST_CASE(h2_client_conn_err_initial_window_size_cause_window_exceed_max) {
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

    /* Send a small update on stream */
    struct aws_h2_frame *stream_window_update =
        aws_h2_frame_new_window_update(allocator, aws_http_stream_get_id(stream_tester.stream), 1);
    ASSERT_NOT_NULL(stream_window_update);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, stream_window_update));

    /* Then we set INITIAL_WINDOW_SIZE to largest - 1, which will not lead to any error */
    struct aws_h2_frame_setting settings_array[1];
    settings_array[0].id = AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE;
    settings_array[0].value = AWS_H2_WINDOW_UPDATE_MAX - 1;
    struct aws_h2_frame *settings = aws_h2_frame_new_settings(allocator, settings_array, 1, false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate connection is still open */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* Finally we set INITIAL_WINDOW_SIZE to largest, which cause the stream window size to exceed the max size */
    settings_array[0].id = AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE;
    settings_array[0].value = AWS_H2_WINDOW_UPDATE_MAX;
    settings = aws_h2_frame_new_settings(allocator, settings_array, 1, false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate the connection completed with error */
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));

    /* client should send GOAWAY */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *goaway =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_GOAWAY, 0, NULL);
    ASSERT_NOT_NULL(goaway);
    ASSERT_UINT_EQUALS(AWS_H2_ERR_FLOW_CONTROL_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* A request stream that receives RST_STREAM should terminate */
TEST_CASE(h2_client_stream_err_receive_rst_stream) {
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

    /* fake peer sends RST_STREAM */
    struct aws_h2_frame *rst_stream = aws_h2_frame_new_rst_stream(allocator, stream_id, AWS_H2_ERR_HTTP_1_1_REQUIRED);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, rst_stream));

    /* validate that stream completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_RST_STREAM_RECEIVED, stream_tester.on_complete_error_code);

    /* a stream error should not affect the connection */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that stream did NOT send RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_NULL(h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, 0, NULL));

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* A server MAY request that the client abort transmission of a request without error by sending a
 * RST_STREAM with an error code of NO_ERROR after sending a complete response. */
TEST_CASE(h2_client_stream_receive_rst_stream_after_complete_response_ok) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* get request ready */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "POST"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    /* use a stalled body-stream so our test can send the response before the request is completely sent */
    const char *body_src = "hello";
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str(body_src);
    struct aws_input_stream *request_body = aws_input_stream_new_tester(allocator, body_cursor);
    aws_http_message_set_body_stream(request, request_body);
    aws_input_stream_tester_set_max_bytes_per_read(request_body, 0);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));

    /* execute 1 event-loop tick, the HEADERS should be written
     * (don't drain task queue or we'll infinite loop waiting for stalled body) */
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_NOT_NULL(
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_HEADERS, 0 /*search_start_idx*/, NULL));

    /* fake peer sends complete response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* fake peer sends RST_STREAM with error-code NO_ERROR */
    response_frame = aws_h2_frame_new_rst_stream(allocator, stream_id, AWS_H2_ERR_NO_ERROR);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* validate the client request completes successfully */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(404, stream_tester.response_status);

    /* clean up */
    aws_http_headers_release(response_headers);
    client_stream_tester_clean_up(&stream_tester);
    aws_http_message_release(request);
    aws_input_stream_destroy(request_body);
    return s_tester_clean_up();
}

/* We don't fully support PUSH_PROMISE, so we automatically send RST_STREAM to reject any promised streams.
 * Why, you ask, don't we simply send SETTINGS_ENABLE_PUSH=0 in the initial SETTINGS frame and call it a day?
 * Because it's theoretically possible for a server to start sending PUSH_PROMISE frames in the initial
 * response, before sending the ACK to the initial SETTINGS. */
TEST_CASE(h2_client_push_promise_automatically_rejected) {
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
        DEFINE_HEADER(":authority", "veryblackpage.com"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    /* fake peer sends push request (PUSH_PROMISE) */
    struct aws_http_header push_request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":authority", "veryblackpage.com"),
        DEFINE_HEADER(":path", "/style.css"),
    };
    struct aws_http_headers *push_request_headers = aws_http_headers_new(allocator);
    ASSERT_SUCCESS(aws_http_headers_add_array(
        push_request_headers, push_request_headers_src, AWS_ARRAY_SIZE(push_request_headers_src)));

    uint32_t promised_stream_id = 2;
    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_push_promise(allocator, stream_id, promised_stream_id, push_request_headers, 0);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* fake peer sends push response RIGHT AWAY before there's any possibility of receiving RST_STREAM */
    struct aws_http_header push_response_headers_src[] = {
        DEFINE_HEADER(":status", "200"),
    };
    struct aws_http_headers *push_response_headers = aws_http_headers_new(allocator);
    ASSERT_SUCCESS(aws_http_headers_add_array(
        push_response_headers, push_response_headers_src, AWS_ARRAY_SIZE(push_response_headers_src)));

    peer_frame =
        aws_h2_frame_new_headers(allocator, promised_stream_id, push_response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(
        &s_tester.peer, promised_stream_id, "body {background-color: black;}", true /*end_stream*/));

    /* fake peer sends response to the initial request */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "200"),
    };
    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    peer_frame = aws_h2_frame_new_headers(allocator, stream_id, response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    const char *body_src = "<html><head><link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\"></head></html>";
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(&s_tester.peer, stream_id, body_src, true /*end_stream*/));

    /* validate that stream completed successfully. */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_BIN_ARRAYS_EQUALS(
        body_src, strlen(body_src), stream_tester.response_body.buffer, stream_tester.response_body.len);

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that client automatically sent RST_STREAM to reject the promised stream */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *client_sent_rst_stream = h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, promised_stream_id, 0, NULL);
    ASSERT_NOT_NULL(client_sent_rst_stream);

    /* clean up */
    aws_http_headers_release(push_request_headers);
    aws_http_headers_release(push_response_headers);
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Test client receives the GOAWAY frame, stop creating new stream and complete the streams whose id are higher than the
 * last stream id included in GOAWAY frame */
TEST_CASE(h2_client_conn_receive_goaway) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send multiple requests */
    enum { NUM_STREAMS = 3 };
    struct aws_http_message *requests[NUM_STREAMS];
    struct aws_http_header request_headers_src[NUM_STREAMS][3] = {
        {
            DEFINE_HEADER(":method", "GET"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/a.txt"),
        },
        {
            DEFINE_HEADER(":method", "GET"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/b.txt"),
        },
        {
            DEFINE_HEADER(":method", "GET"),
            DEFINE_HEADER(":scheme", "https"),
            DEFINE_HEADER(":path", "/c.txt"),
        },
    };
    struct client_stream_tester stream_testers[NUM_STREAMS];
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        requests[i] = aws_http_message_new_request(allocator);
        aws_http_message_add_header_array(requests[i], request_headers_src[i], AWS_ARRAY_SIZE(request_headers_src[i]));
    }
    /* Send the first two requests */
    ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[0], requests[0]));
    ASSERT_SUCCESS(s_stream_tester_init(&stream_testers[1], requests[1]));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* fake peer send a GOAWAY frame indicating only the first request will be processed */
    uint32_t stream_id = aws_http_stream_get_id(stream_testers[0].stream);
    struct aws_byte_cursor debug_info;
    AWS_ZERO_STRUCT(debug_info);
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_goaway(allocator, stream_id, AWS_H2_ERR_NO_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate the connection is still open, and the second request finished with GOAWAY_RECEIVED */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_FALSE(stream_testers[0].complete);
    ASSERT_TRUE(stream_testers[1].complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_GOAWAY_RECEIVED, stream_testers[1].on_complete_error_code);

    /* validate the new requst will no be accepted */
    ASSERT_FAILS(s_stream_tester_init(&stream_testers[2], requests[2]));

    /* Try gracefully shutting down the connection */
    struct aws_http_header response_headers_src[] = {DEFINE_HEADER(":status", "200")};
    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));
    struct aws_h2_frame *response_frame = aws_h2_frame_new_headers(
        allocator, aws_http_stream_get_id(stream_testers[0].stream), response_headers, true /* end_stream */, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));
    /* shutdown channel */
    aws_channel_shutdown(s_tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));

    /* validate the first request finishes successfully */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_testers[0].complete);
    ASSERT_INT_EQUALS(200, stream_testers[0].response_status);

    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(response_headers);
    for (size_t i = 0; i < NUM_STREAMS; ++i) {
        client_stream_tester_clean_up(&stream_testers[i]);
        aws_http_message_release(requests[i]);
    }
    return s_tester_clean_up();
}

/* Test client receives the GOAWAY frame, stop creating new stream and complete the streams whose id are higher than the
 * last stream id included in GOAWAY frame */
TEST_CASE(h2_client_conn_err_invalid_last_stream_id_goaway) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* fake peer send multiple GOAWAY frames  */
    struct aws_byte_cursor debug_info;
    AWS_ZERO_STRUCT(debug_info);
    /* First on with last_stream_id as AWS_H2_STREAM_ID_MAX */
    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_goaway(allocator, AWS_H2_STREAM_ID_MAX, AWS_H2_ERR_NO_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    /* Second one with last_stream_id as 1 and some error */
    peer_frame = aws_h2_frame_new_goaway(allocator, 1, AWS_H2_ERR_FLOW_CONTROL_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate the connection is still open, everything is fine */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* Another GOAWAY with higher last stream id will cause connection closed with an error */
    peer_frame = aws_h2_frame_new_goaway(allocator, 3, AWS_H2_ERR_FLOW_CONTROL_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));
    /* clean up */
    return s_tester_clean_up();
}
