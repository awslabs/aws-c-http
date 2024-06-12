/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "h2_test_helper.h"
#include "stream_test_helper.h"
#include <aws/http/private/h2_connection.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/http/request_response.h>
#include <aws/io/stream.h>
#include <aws/testing/io_testing_channel.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

#define DEFINE_HEADER(NAME, VALUE)                                                                                     \
    {                                                                                                                  \
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(NAME),                                                           \
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(VALUE),                                                         \
    }

struct connection_user_data {
    struct aws_allocator *allocator;
    int initial_settings_error_code;
    uint32_t last_stream_id;
    uint32_t http2_error;
    struct aws_http2_setting remote_settings_array[10];
    struct aws_byte_buf debug_data;
    size_t num_settings;
};

static void s_on_initial_settings_completed(
    struct aws_http_connection *http2_connection,
    int error_code,
    void *user_data) {

    (void)http2_connection;
    struct connection_user_data *data = user_data;
    data->initial_settings_error_code = error_code;
}

static void s_on_goaway_received(
    struct aws_http_connection *http2_connection,
    uint32_t last_stream_id,
    uint32_t http2_error,
    const struct aws_byte_cursor debug_data,
    void *user_data) {

    (void)http2_connection;
    struct connection_user_data *data = user_data;
    data->last_stream_id = last_stream_id;
    data->http2_error = http2_error;
    if (data->debug_data.capacity != 0) {
        /* If multiple goaway received, clean up the previous one */
        aws_byte_buf_clean_up(&data->debug_data);
    }
    aws_byte_buf_init_copy_from_cursor(&data->debug_data, data->allocator, debug_data);
}

static void s_on_remote_settings_change(
    struct aws_http_connection *http2_connection,
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    void *user_data) {

    (void)http2_connection;
    struct connection_user_data *data = user_data;
    if (num_settings) {
        memcpy(data->remote_settings_array, settings_array, num_settings * sizeof(struct aws_http2_setting));
    }
    data->num_settings = num_settings;
}

/* Singleton used by tests in this file */
static struct tester {
    struct aws_allocator *alloc;
    struct aws_http_connection *connection;
    struct testing_channel testing_channel;
    struct h2_fake_peer peer;
    struct connection_user_data user_data;

    bool no_conn_manual_win_management;
} s_tester;

static int s_tester_init(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_http_library_init(alloc);

    s_tester.alloc = alloc;
    AWS_ZERO_STRUCT(s_tester.user_data.debug_data);

    struct aws_testing_channel_options options = {.clock_fn = aws_high_res_clock_get_ticks};

    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, alloc, &options));
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_ENABLE_PUSH, .value = 0},
    };

    struct aws_http2_connection_options http2_options = {
        .initial_settings_array = settings_array,
        .num_initial_settings = AWS_ARRAY_SIZE(settings_array),
        .on_initial_settings_completed = s_on_initial_settings_completed,
        .max_closed_streams = AWS_HTTP2_DEFAULT_MAX_CLOSED_STREAMS,
        .on_goaway_received = s_on_goaway_received,
        .on_remote_settings_change = s_on_remote_settings_change,
        .conn_manual_window_management = !s_tester.no_conn_manual_win_management,
    };

    s_tester.connection =
        aws_http_connection_new_http2_client(alloc, false /* manual window management */, &http2_options);
    ASSERT_NOT_NULL(s_tester.connection);

    {
        s_tester.user_data.allocator = s_tester.alloc;
        /* set connection user_data (handled by http-bootstrap in real world) */
        s_tester.connection->user_data = &s_tester.user_data;
        /* re-enact marriage vows of http-connection and channel (handled by http-bootstrap in real world) */
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
    aws_byte_buf_clean_up(&s_tester.user_data.debug_data);
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
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

static void s_stream_cleans_up_on_destroy(void *data) {
    bool *destroyed = data;
    *destroyed = true;
}

TEST_CASE(h2_client_stream_release_after_complete) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* create request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header headers[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));

    bool destroyed = false;
    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = request,
        .on_destroy = s_stream_cleans_up_on_destroy,
        .user_data = &destroyed,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &options);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    /* shutdown channel so request can be released */
    aws_channel_shutdown(s_tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));

    /* release request */
    ASSERT_FALSE(destroyed);
    aws_http_stream_release(stream);
    ASSERT_TRUE(destroyed);

    aws_http_message_release(request);

    return s_tester_clean_up();
}

struct s_callback_invoked {
    bool destroy_invoked;
    bool complete_invoked;
};

static void s_unactivated_stream_cleans_up_on_destroy(void *data) {
    struct s_callback_invoked *callback_data = data;
    callback_data->destroy_invoked = true;
}

static void s_unactivated_stream_complete(struct aws_http_stream *stream, int error_code, void *data) {
    (void)stream;
    (void)error_code;
    struct s_callback_invoked *callback_data = data;
    callback_data->complete_invoked = true;
}

TEST_CASE(h2_client_unactivated_stream_cleans_up) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* create request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header headers[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));
    struct s_callback_invoked callback_data = {0};
    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = request,
        .on_destroy = s_unactivated_stream_cleans_up_on_destroy,
        .on_complete = s_unactivated_stream_complete,
        .user_data = &callback_data,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &options);
    ASSERT_NOT_NULL(stream);
    /* do not activate the stream, that's the test. */

    ASSERT_FALSE(callback_data.destroy_invoked);
    ASSERT_FALSE(callback_data.complete_invoked);
    /* shutdown channel so request can be released */
    aws_channel_shutdown(s_tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));

    aws_http_stream_release(stream);
    ASSERT_TRUE(callback_data.destroy_invoked);
    ASSERT_FALSE(callback_data.complete_invoked);

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

static int s_stream_tester_init(struct client_stream_tester *stream_tester, struct aws_http_message *request) {
    struct client_stream_tester_options options = {
        .request = request,
        .connection = s_tester.connection,
    };
    return client_stream_tester_init(stream_tester, s_tester.alloc, &options);
}

/* Test that client will automatically send the PING ACK frame back, when the PING frame is received */
TEST_CASE(h2_client_auto_ping_ack) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* Connection preface requires that SETTINGS be sent first (RFC-7540 3.5). */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7};

    struct aws_h2_frame *frame = aws_h2_frame_new_ping(allocator, false /*ack*/, opaque_data);
    ASSERT_NOT_NULL(frame);

    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* Now check that client sent PING ACK frame, it should be the latest frame received by peer
     * The last frame should be a ping type with ack on, and identical payload */
    struct h2_decoded_frame *latest_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_PING, latest_frame->type);
    ASSERT_TRUE(latest_frame->ack);
    ASSERT_BIN_ARRAYS_EQUALS(
        opaque_data, AWS_HTTP2_PING_DATA_SIZE, latest_frame->ping_opaque_data, AWS_HTTP2_PING_DATA_SIZE);

    return s_tester_clean_up();
}

TEST_CASE(h2_client_auto_ping_ack_higher_priority) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* Frames for the request are activated. Fake peer send PING frame now */
    uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7};

    struct aws_h2_frame *frame = aws_h2_frame_new_ping(allocator, false /*ack*/, opaque_data);
    ASSERT_NOT_NULL(frame);

    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, frame));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate PING ACK frame has higher priority than the normal request frames, and be received earliest */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct h2_decoded_frame *fastest_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frames_count);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_PING, fastest_frame->type);
    ASSERT_TRUE(fastest_frame->ack);
    ASSERT_BIN_ARRAYS_EQUALS(
        opaque_data, AWS_HTTP2_PING_DATA_SIZE, fastest_frame->ping_opaque_data, AWS_HTTP2_PING_DATA_SIZE);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    aws_input_stream_release(request_body);
    return s_tester_clean_up();
}

/* Test client can automatically send SETTINGs ACK */
TEST_CASE(h2_client_auto_settings_ack) {
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

/* Test that a simple request/response can be carried to completion.
 * The request consists of a single HEADERS frame and the response consists of a single HEADERS frame. */
TEST_CASE(h2_client_stream_complete) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    ASSERT_TRUE(stream_tester.metrics.receive_end_timestamp_ns > 0);
    ASSERT_TRUE(stream_tester.metrics.receive_start_timestamp_ns > 0);
    ASSERT_TRUE(stream_tester.metrics.receive_end_timestamp_ns > stream_tester.metrics.receive_start_timestamp_ns);
    ASSERT_TRUE(
        stream_tester.metrics.receiving_duration_ns ==
        stream_tester.metrics.receive_end_timestamp_ns - stream_tester.metrics.receive_start_timestamp_ns);
    ASSERT_TRUE(stream_tester.metrics.send_start_timestamp_ns > 0);
    ASSERT_TRUE(stream_tester.metrics.send_end_timestamp_ns > 0);
    ASSERT_TRUE(stream_tester.metrics.send_end_timestamp_ns > stream_tester.metrics.send_start_timestamp_ns);
    ASSERT_TRUE(
        stream_tester.metrics.sending_duration_ns ==
        stream_tester.metrics.send_end_timestamp_ns - stream_tester.metrics.send_start_timestamp_ns);
    ASSERT_TRUE(stream_tester.metrics.stream_id == stream_tester.stream->id);

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
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_NO_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Test that client automatically sends the HTTP/2 Connection Preface (magic string, followed by initial SETTINGS frame,
 * which we disabled the push_promise) And it will not be applied until the SETTINGS ack is received. Once SETTINGS ack
 * received, the initial settings will be applied and callback will be invoked */
TEST_CASE(h2_client_connection_init_settings_applied_after_ack_by_peer) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* set initial_settings_error_code as AWS_ERROR_UNKNOWN to make sure callback invoked later */
    s_tester.user_data.initial_settings_error_code = AWS_ERROR_UNKNOWN;
    /* fake peer sends setting ack */
    struct aws_h2_frame *settings_ack_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, settings_ack_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate the callback invoked */
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, s_tester.user_data.initial_settings_error_code);
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
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_method(request, aws_http_method_post));
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER("Accept", "*/*"),
        DEFINE_HEADER("Host", "example.com"),
        DEFINE_HEADER("Content-Length", "5"),
        DEFINE_HEADER("Upgrade", "HTTP/2.0"), /* Connection-specific header should be skiped */
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    /* body */
    const char *body_src = "hello";
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str(body_src);
    struct aws_input_stream *request_body = aws_input_stream_new_from_cursor(allocator, &body_cursor);
    aws_http_message_set_body_stream(request, request_body);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    /* validate sent request (client should have sent SETTINGS, SETTINGS ACK, HEADERS, DATA (END_STREAM) */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_UINT_EQUALS(4, h2_decode_tester_frame_count(&s_tester.peer.decode));

    /* set expected h2 style headers */
    struct aws_http_header expected_headers_src[] = {
        DEFINE_HEADER(":method", "POST"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":authority", "example.com"),
        DEFINE_HEADER(":path", "/"),
        DEFINE_HEADER("accept", "*/*"),
        DEFINE_HEADER("content-length", "5"),
    };
    struct aws_http_headers *expected_headers = aws_http_headers_new(allocator);
    ASSERT_SUCCESS(
        aws_http_headers_add_array(expected_headers, expected_headers_src, AWS_ARRAY_SIZE(expected_headers_src)));

    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, 2);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_SUCCESS(s_compare_headers(expected_headers, sent_headers_frame->headers));

    struct h2_decoded_frame *sent_data_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, 3);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_DATA, sent_data_frame->type);
    ASSERT_TRUE(sent_data_frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&sent_data_frame->data, body_src));

    /* clean up */
    aws_http_headers_release(expected_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    aws_input_stream_destroy(request_body);
    return s_tester_clean_up();
}

/* Test that h2 stream can split the cookies header correctly */
TEST_CASE(h2_client_stream_with_cookies_headers) {
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
        DEFINE_HEADER("cookie", "a=b; c=d; e=f"),
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
        DEFINE_HEADER("cookie", "a=b; c=d; e=f"),
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
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_err_state_forbids_frame) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "PUT"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    const char *body_src = "hello";
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str(body_src);
    struct aws_input_stream *request_body = aws_input_stream_new_tester(allocator, body_cursor);
    /* Prevent END_STREAM from being sent */
    aws_input_stream_tester_set_max_bytes_per_read(request_body, 0);

    aws_http_message_set_body_stream(request, request_body);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    /* Execute 1 event-loop tick. Request is sent, but no end_stream received */
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);

    struct h2_decoded_frame *sent_headers_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_HEADERS, sent_headers_frame->type);
    ASSERT_FALSE(sent_headers_frame->end_stream);
    ASSERT_SUCCESS(s_compare_headers(aws_http_message_get_headers(request), sent_headers_frame->headers));

    /* fake peer sends response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    /* fake peer sends response headers with end_stream set, which cause the stream to be
     * AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE */
    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE will reject body frame */
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(&s_tester.peer, stream_id, body_src, true /*end_stream*/));

    /* validate that stream completed with error */
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);

    /* a stream error should not affect the connection */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_stream_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, stream_id, 0, NULL);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_RST_STREAM, rst_stream_frame->type);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_STREAM_CLOSED, rst_stream_frame->error_code);

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    aws_input_stream_release(request_body);
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
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, goaway->error_code);
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
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    peer_frame = aws_h2_frame_new_rst_stream(allocator, stream_id, AWS_HTTP2_ERR_ENHANCE_YOUR_CALM);
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

TEST_CASE(h2_client_stream_receive_info_headers) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* fake peer sends a info-header-block response */
    struct aws_http_header info_response_headers_src[] = {
        DEFINE_HEADER(":status", "100"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:03:49 GMT"),
    };
    struct aws_http_headers *info_response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(
        info_response_headers, info_response_headers_src, AWS_ARRAY_SIZE(info_response_headers_src));
    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_headers(allocator, stream_id, info_response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* check info response */
    ASSERT_INT_EQUALS(1, stream_tester.num_info_responses);
    ASSERT_SUCCESS(aws_http_message_set_response_status(stream_tester.info_responses[0], 100));
    struct aws_http_headers *rev_info_headers = aws_http_message_get_headers(stream_tester.info_responses[0]);
    ASSERT_SUCCESS(s_compare_headers(info_response_headers, rev_info_headers));

    /* fake peer sends a main-header-block response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };
    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));
    peer_frame = aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* validate that client received complete response */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(404, stream_tester.response_status);
    ASSERT_SUCCESS(s_compare_headers(response_headers, stream_tester.response_headers));

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_headers_release(info_response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_err_receive_info_headers_after_main) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* fake peer sends a main-header-block response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));
    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* fake peer sends a info-header-block response */
    struct aws_http_header info_response_headers_src[] = {
        DEFINE_HEADER(":status", "100"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:03:49 GMT"),
    };

    struct aws_http_headers *info_response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(
        info_response_headers, info_response_headers_src, AWS_ARRAY_SIZE(info_response_headers_src));
    peer_frame = aws_h2_frame_new_headers(allocator, stream_id, info_response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate the stream completed with error */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);
    /* validate the connection is not affected */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_stream_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, stream_id, 0, NULL);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_RST_STREAM, rst_stream_frame->type);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_headers_release(info_response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_receive_trailing_headers) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* fake peer sends a main-header-block response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* fake peer sends a trailing-header-block response */
    struct aws_http_header response_trailer_src[] = {
        DEFINE_HEADER("user-agent", "test"),
    };

    struct aws_http_headers *response_trailer = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_trailer, response_trailer_src, AWS_ARRAY_SIZE(response_trailer_src));

    peer_frame = aws_h2_frame_new_headers(allocator, stream_id, response_trailer, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    /* validate that client received complete response */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(404, stream_tester.response_status);
    ASSERT_SUCCESS(s_compare_headers(response_headers, stream_tester.response_headers));
    ASSERT_SUCCESS(s_compare_headers(response_trailer, stream_tester.response_trailer));

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_headers_release(response_trailer);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_err_receive_trailing_before_main) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* fake peer sends a trailing-header-block response */
    struct aws_http_header response_trailer_src[] = {
        DEFINE_HEADER("user-agent", "test"),
    };

    struct aws_http_headers *response_trailer = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_trailer, response_trailer_src, AWS_ARRAY_SIZE(response_trailer_src));

    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_trailer, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate the stream completed with error */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);
    /* validate the connection is not affected */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_stream_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, stream_id, 0, NULL);
    ASSERT_INT_EQUALS(AWS_H2_FRAME_T_RST_STREAM, rst_stream_frame->type);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_headers_release(response_trailer);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Peer should not send any frames other than WINDOW_UPDATE and RST_STREAM once they send END_STREAM flag, we will treat
 * that as connection error (STREAM_CLOSED) */
TEST_CASE(h2_client_conn_err_stream_frames_received_soon_after_closing) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* fake peer try to send data frame */
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(&s_tester.peer, stream_id, "hello", true /*end_stream*/));

    /* validate that connection has closed. */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));

    /* validate that client sent GOAWAY */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct h2_decoded_frame *goaway =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_GOAWAY, 0, NULL);
    ASSERT_NOT_NULL(goaway);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_STREAM_CLOSED, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_err_stream_frames_received_soon_after_rst_stream_received) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_rst_stream(allocator, stream_id, AWS_HTTP2_ERR_ENHANCE_YOUR_CALM);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    struct aws_http_headers *response_headers;
    /* fake peer try sending complete response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };

    response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    peer_frame = aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate the stream completed with error */
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_RST_STREAM_RECEIVED, stream_tester.on_complete_error_code);
    /* We treat this as a stream error. So, validate the connection is still open and a rst stream is sent by
     * client. */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_stream_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, stream_id, 0, NULL);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_STREAM_CLOSED, rst_stream_frame->error_code);
    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Connection error for frames received on a closed stream we have removed from cache, which may because it closed too
 * long ago */
TEST_CASE(h2_client_conn_err_stream_frames_received_after_removed_from_cache) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    enum { NUM_STREAMS = AWS_HTTP2_DEFAULT_MAX_CLOSED_STREAMS + 2 };
    /* send request */
    struct aws_http_message *requests[NUM_STREAMS];

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    struct client_stream_tester stream_tester[NUM_STREAMS];

    /* fill out the cache */
    for (size_t i = 0; i < NUM_STREAMS; i++) {
        requests[i] = aws_http2_message_new_request(allocator);
        aws_http_message_add_header_array(requests[i], request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
        ASSERT_SUCCESS(s_stream_tester_init(&stream_tester[i], requests[i]));
        testing_channel_drain_queued_tasks(&s_tester.testing_channel);
        /* close the streams immediately */
        struct aws_h2_frame *peer_frame = aws_h2_frame_new_rst_stream(
            allocator, aws_http_stream_get_id(stream_tester[i].stream), AWS_HTTP2_ERR_ENHANCE_YOUR_CALM);
        ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
        testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    }
    uint32_t stream_id = aws_http_stream_get_id(stream_tester[0].stream);

    struct aws_http_headers *response_headers;

    /* fake peer try sending complete response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };

    response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    /* validate the connection completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));

    /* client should send GOAWAY */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *goaway =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_GOAWAY, 0, NULL);
    ASSERT_NOT_NULL(goaway);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, goaway->error_code);

    /* clean up */
    aws_http_headers_release(response_headers);
    for (size_t i = 0; i < NUM_STREAMS; i++) {
        aws_http_message_release(requests[i]);
        client_stream_tester_clean_up(&stream_tester[i]);
    }
    return s_tester_clean_up();
}

/* Test receiving a response with DATA frames */
TEST_CASE(h2_client_stream_receive_data) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* A message is malformed if DATA is received not match the content_length received */
TEST_CASE(h2_client_stream_err_receive_data_not_match_content_length) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
        DEFINE_HEADER("content-length", "200"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* fake peer sends response body */
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
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Test sending a request with DATA frames */
TEST_CASE(h2_client_stream_send_data) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "POST"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
        DEFINE_HEADER("content-length", "5"),
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
    aws_input_stream_release(request_body);
    return s_tester_clean_up();
}

/* Test sending multiple requests, each with large bodies that must be sent across multiple DATA frames.
 * The connection should not let one stream hog the connection, the streams should take turns sending DATA.
 * Also, the stream should not send more than one aws_io_message full of frames per event-loop-tick */
TEST_CASE(h2_client_stream_send_lots_of_data) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* bodies must be big enough to span multiple H2-frames and multiple aws_io_messages */
    size_t body_size =
        aws_max_size(aws_h2_settings_initial[AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE], g_aws_channel_max_fragment_size) * 5;

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
        requests[i] = aws_http2_message_new_request(allocator);
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
        aws_input_stream_release(request_bodies[i]);
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
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    aws_input_stream_release(request_body);
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
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = 5},
    };
    struct aws_h2_frame *settings =
        aws_h2_frame_new_settings(allocator, settings_array, AWS_ARRAY_SIZE(settings_array), false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    aws_input_stream_release(request_body);
    return s_tester_clean_up();
}

/* Test stream window size becomes negative, and will resume only when it back to positive again. */
TEST_CASE(h2_client_stream_send_data_controlled_by_negative_stream_window_size) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    /* fake peer sends setting with 300 initial window size */
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = 300},
    };
    struct aws_h2_frame *settings =
        aws_h2_frame_new_settings(allocator, settings_array, AWS_ARRAY_SIZE(settings_array), false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    settings = aws_h2_frame_new_settings(allocator, settings_array, AWS_ARRAY_SIZE(settings_array), false /*ack*/);
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
    aws_input_stream_release(request_body);
    return s_tester_clean_up();
}

/* Test when connection window size becomes zero, no stream can send data */
TEST_CASE(h2_client_stream_send_data_controlled_by_connection_window_size) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* bodies must be big enough to span multiple H2-frames and multiple aws_io_messages */
    size_t body_size = aws_h2_settings_initial[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE] - AWS_H2_MIN_WINDOW_SIZE;

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
        requests[i] = aws_http2_message_new_request(allocator);
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
        aws_input_stream_release(request_bodies[i]);
        aws_byte_buf_clean_up(&request_body_bufs[i]);
    }
    return s_tester_clean_up();
}

/* Test when connection window size becomes zero, and stream window size is zero, window_update on connection and stream
 * will not affect eachother */
TEST_CASE(h2_client_stream_send_data_controlled_by_connection_and_stream_window_size) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* bodies must be big enough to span multiple H2-frames and multiple aws_io_messages */
    size_t body_size = aws_h2_settings_initial[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE];

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
        requests[i] = aws_http2_message_new_request(allocator);
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
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = 0},
    };
    struct aws_h2_frame *settings =
        aws_h2_frame_new_settings(allocator, settings_array, AWS_ARRAY_SIZE(settings_array), false /*ack*/);
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
        aws_input_stream_release(request_bodies[i]);
        aws_byte_buf_clean_up(&request_body_bufs[i]);
    }
    return s_tester_clean_up();
}

/* Test receiving a response with DATA frames, the window update frame will be sent */
TEST_CASE(h2_client_stream_send_window_update) {
    /* Enable automatic window manager management */
    s_tester.no_conn_manual_win_management = true;
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    /* Check the inital window update frame has been sent to maximize the connection window */
    size_t initial_window_update_index = 0;
    struct h2_decoded_frame *initial_connection_window_update_frame = h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, 0 /*stream_id*/, 0 /*idx*/, &initial_window_update_index);
    ASSERT_NOT_NULL(initial_connection_window_update_frame);
    ASSERT_UINT_EQUALS(
        AWS_H2_WINDOW_UPDATE_MAX - AWS_H2_INIT_WINDOW_SIZE,
        initial_connection_window_update_frame->window_size_increment);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
        &s_tester.peer.decode,
        AWS_H2_FRAME_T_WINDOW_UPDATE,
        0 /*stream_id*/,
        initial_window_update_index + 1 /*idx*/,
        NULL);
    ASSERT_NOT_NULL(connection_window_update_frame);
    ASSERT_UINT_EQUALS(5, connection_window_update_frame->window_size_increment);

    /* clean up */
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Peer sends a frame larger than the window size we had on stream, will result in stream error */
TEST_CASE(h2_client_stream_err_received_data_flow_control) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    size_t window_size = 10;

    /* change the settings of the initial window size for new stream flow-control window */
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = (uint32_t)window_size},
    };

    ASSERT_SUCCESS(aws_http2_connection_change_settings(
        s_tester.connection,
        settings_array,
        AWS_ARRAY_SIZE(settings_array),
        NULL /*callback function*/,
        NULL /*user_data*/));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* fake peer sends two settings ack back, one for the initial settings, one for the user settings we just sent */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    struct aws_byte_buf response_body_bufs;
    /* fake peer sends a DATA frame larger than the window size we have */
    ASSERT_SUCCESS(aws_byte_buf_init(&response_body_bufs, allocator, window_size + 1));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&response_body_bufs, (uint8_t)'a', window_size + 1));
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&response_body_bufs);
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, true /*end_stream*/));

    /* validate that stream completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);

    /* a stream error should not affect the connection */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that stream sent RST_STREAM with AWS_HTTP2_ERR_FLOW_CONTROL_ERROR */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_stream_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, stream_id, 0, NULL);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_byte_buf_clean_up(&response_body_bufs);
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

static int s_manual_window_management_tester_init(struct aws_allocator *alloc, bool conn, bool stream, void *ctx) {
    (void)ctx;
    aws_http_library_init(alloc);

    s_tester.alloc = alloc;

    struct aws_testing_channel_options options = {.clock_fn = aws_high_res_clock_get_ticks};

    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, alloc, &options));
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_ENABLE_PUSH, .value = 0},
    };

    struct aws_http2_connection_options http2_options = {
        .initial_settings_array = settings_array,
        .num_initial_settings = AWS_ARRAY_SIZE(settings_array),
        .max_closed_streams = AWS_HTTP2_DEFAULT_MAX_CLOSED_STREAMS,
        .conn_manual_window_management = conn,
    };

    s_tester.connection =
        aws_http_connection_new_http2_client(alloc, stream /* manual window management */, &http2_options);
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

/* Peer sends a flow-controlled frame when the connection window-size is not enough for it will result in connection
 * flow-control error */
TEST_CASE(h2_client_conn_err_received_data_flow_control) {
    /* disable the connection automatic window update */
    ASSERT_SUCCESS(s_manual_window_management_tester_init(allocator, true /*conn*/, false /*stream*/, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    struct aws_byte_buf response_body_bufs;

    /* The max body size here is limited. So we need to send multiple bodies to get the flow-control error */
    size_t body_size =
        aws_max_size(aws_h2_settings_initial[AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE], g_aws_channel_max_fragment_size) -
        AWS_H2_FRAME_PREFIX_SIZE;
    /* fake peer sends a DATA frame larger than the window size we have */
    ASSERT_SUCCESS(aws_byte_buf_init(&response_body_bufs, allocator, body_size));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&response_body_bufs, (uint8_t)'a', body_size));
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&response_body_bufs);
    for (uint32_t i = 0; i < aws_h2_settings_initial[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE] / body_size; i++) {
        ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, false /*end_stream*/));
        /* manually update the stream flow-control window, ensure that stream window is available all the time */
        aws_http_stream_update_window(stream_tester.stream, body_size);
        testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    }
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    /* the last one will result in the connection flow control error */
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, true /*end_stream*/));
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
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    aws_byte_buf_clean_up(&response_body_bufs);
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
    enum aws_http2_error_code h2_error_code) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    return s_invalid_window_update(allocator, ctx, AWS_H2_WINDOW_UPDATE_MAX, AWS_HTTP2_ERR_FLOW_CONTROL_ERROR);
}

/* Window update with zero update size will lead to PROTOCOL_ERROR */
TEST_CASE(h2_client_conn_err_window_update_size_zero) {
    return s_invalid_window_update(allocator, ctx, 0, AWS_HTTP2_ERR_PROTOCOL_ERROR);
}

static int s_compare_settings_array(
    const struct aws_http2_setting *expected,
    const struct aws_http2_setting *got,
    int num_settings) {

    for (int i = 0; i < num_settings; ++i) {
        struct aws_http2_setting expected_settings = expected[i];
        struct aws_http2_setting got_settings = got[i];

        ASSERT_INT_EQUALS(expected_settings.id, got_settings.id);
        ASSERT_INT_EQUALS(expected_settings.value, got_settings.value);
    }

    return AWS_OP_SUCCESS;
}

/* SETTINGS_INITIAL_WINDOW_SIZE cause stream window to exceed the max size is a Connection ERROR... */
TEST_CASE(h2_client_conn_err_initial_window_size_settings_cause_window_exceed_max) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = AWS_H2_WINDOW_UPDATE_MAX - 1},
    };
    struct aws_h2_frame *settings =
        aws_h2_frame_new_settings(allocator, settings_array, AWS_ARRAY_SIZE(settings_array), false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate connection is still open and callback invoked */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(s_tester.user_data.num_settings, AWS_ARRAY_SIZE(settings_array));
    ASSERT_SUCCESS(s_compare_settings_array(
        settings_array, s_tester.user_data.remote_settings_array, AWS_ARRAY_SIZE(settings_array)));
    s_tester.user_data.num_settings = 0;

    /* Finally we set INITIAL_WINDOW_SIZE to largest, which cause the stream window size to exceed the max size */
    settings_array[0].value = AWS_H2_WINDOW_UPDATE_MAX;
    settings = aws_h2_frame_new_settings(allocator, settings_array, AWS_ARRAY_SIZE(settings_array), false /*ack*/);
    ASSERT_NOT_NULL(settings);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, settings));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate callback is not invoked, num_settings is still 0 */
    ASSERT_INT_EQUALS(0, s_tester.user_data.num_settings);

    /* validate the connection completed with error */
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));

    /* client should send GOAWAY */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *goaway =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_GOAWAY, 0, NULL);
    ASSERT_NOT_NULL(goaway);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* A server MAY finish the response before client done sending, and client just keep sending the rest of request. */
TEST_CASE(h2_client_stream_receive_end_stream_before_done_sending) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* get request ready */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    aws_input_stream_tester_set_max_bytes_per_read(request_body, 1);

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));

    /* execute 1 event-loop tick, 1 byte of the body and header should be written */
    testing_channel_run_currently_queued_tasks(&s_tester.testing_channel);
    uint32_t stream_id = aws_http_stream_get_id(stream_tester.stream);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_NOT_NULL(
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_HEADERS, 0 /*search_start_idx*/, NULL));
    struct h2_decoded_frame *sent_data_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_DATA, 0 /*search_start_idx*/, NULL);
    ASSERT_FALSE(sent_data_frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&sent_data_frame->data, "h"));
    /* fake peer sends complete response */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
    };
    /* stop stalling the input stream */
    aws_input_stream_tester_set_max_bytes_per_read(request_body, 5);
    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* No rst stream sent, we wait until the client finish sending body */
    /* validate the client request completes successfully */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(404, stream_tester.response_status);

    /* Check the rest of the body received by peer */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rest_data_frame = h2_decode_tester_find_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_DATA, frames_count /*search_start_idx*/, NULL);
    ASSERT_TRUE(rest_data_frame->end_stream);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&rest_data_frame->data, "ello"));

    /* clean up */
    aws_http_headers_release(response_headers);
    client_stream_tester_clean_up(&stream_tester);
    aws_http_message_release(request);
    aws_input_stream_release(request_body);
    return s_tester_clean_up();
}

/* A server MAY request that the client abort transmission of a request without error by sending a
 * RST_STREAM with an error code of NO_ERROR after sending a complete response. */
TEST_CASE(h2_client_stream_receive_end_stream_and_rst_before_done_sending) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* get request ready */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    response_frame = aws_h2_frame_new_rst_stream(allocator, stream_id, AWS_HTTP2_ERR_NO_ERROR);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    /* validate the client request completes successfully */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(404, stream_tester.response_status);
    /* Check no data frame received by the peer */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_NULL(h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_DATA, 0 /*search_start_idx*/, NULL));

    /* clean up */
    aws_http_headers_release(response_headers);
    client_stream_tester_clean_up(&stream_tester);
    aws_http_message_release(request);
    aws_input_stream_release(request_body);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_err_input_stream_failure) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* get request ready */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    aws_input_stream_tester_set_reading_broken(request_body, true /*is_broken*/);
    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));

    /* validate that stream completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_IO_STREAM_READ_FAILED, stream_tester.on_complete_error_code);
    /* a stream error should not affect the connection */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_INT_EQUALS(AWS_HTTP2_ERR_INTERNAL_ERROR, rst_stream_frame->error_code);
    /* clean up */
    client_stream_tester_clean_up(&stream_tester);
    aws_http_message_release(request);
    aws_input_stream_release(request_body);
    return s_tester_clean_up();
}

/* A request stream that receives RST_STREAM should terminate */
TEST_CASE(h2_client_stream_err_receive_rst_stream) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    struct aws_h2_frame *rst_stream =
        aws_h2_frame_new_rst_stream(allocator, stream_id, AWS_HTTP2_ERR_HTTP_1_1_REQUIRED);
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
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
 * last stream id included in GOAWAY frame, and callback invoked */
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
        requests[i] = aws_http2_message_new_request(allocator);
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
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_goaway(allocator, stream_id, AWS_HTTP2_ERR_NO_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate the callback invoked and the information recorded during callback */
    ASSERT_INT_EQUALS(s_tester.user_data.http2_error, AWS_HTTP2_ERR_NO_ERROR);
    ASSERT_INT_EQUALS(s_tester.user_data.last_stream_id, stream_id);

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

/* Test client receives the GOAWAY frame with the debug data correctly */
TEST_CASE(h2_client_conn_receive_goaway_debug_data) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* fake peer send a GOAWAY frame indicating only the first request will be processed */
    uint32_t stream_id = 1;
    const char debug_string[] = "Error, Core Dump 0XFFFFFFFF";
    struct aws_byte_cursor debug_info = aws_byte_cursor_from_c_str(debug_string);
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_goaway(allocator, stream_id, AWS_HTTP2_ERR_NO_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate the callback invoked and the information recorded during callback */
    ASSERT_INT_EQUALS(s_tester.user_data.http2_error, AWS_HTTP2_ERR_NO_ERROR);
    ASSERT_INT_EQUALS(s_tester.user_data.last_stream_id, stream_id);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&s_tester.user_data.debug_data, debug_string));

    return s_tester_clean_up();
}

/* Test client receives the GOAWAY frame with invalid last stream id and connection error happened, and callback will
 * not be invoked for the invalid GOAWAY frame */
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
        aws_h2_frame_new_goaway(allocator, AWS_H2_STREAM_ID_MAX, AWS_HTTP2_ERR_NO_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    /* validate the callback invoked and the information recorded during callback */
    ASSERT_INT_EQUALS(s_tester.user_data.http2_error, AWS_HTTP2_ERR_NO_ERROR);
    ASSERT_INT_EQUALS(s_tester.user_data.last_stream_id, AWS_H2_STREAM_ID_MAX);

    int last_stream_id = 1;
    /* Second one with last_stream_id as 1 and some error */
    peer_frame = aws_h2_frame_new_goaway(allocator, last_stream_id, AWS_HTTP2_ERR_FLOW_CONTROL_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_INT_EQUALS(s_tester.user_data.http2_error, AWS_HTTP2_ERR_FLOW_CONTROL_ERROR);
    ASSERT_INT_EQUALS(s_tester.user_data.last_stream_id, last_stream_id);

    /* validate the connection is still open, everything is fine */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* Another GOAWAY with higher last stream id will cause connection closed with an error */
    peer_frame = aws_h2_frame_new_goaway(allocator, last_stream_id + 1, AWS_HTTP2_ERR_FLOW_CONTROL_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate the callback is not invoked and the information is still the same as the second one */
    ASSERT_INT_EQUALS(s_tester.user_data.http2_error, AWS_HTTP2_ERR_FLOW_CONTROL_ERROR);
    ASSERT_INT_EQUALS(s_tester.user_data.last_stream_id, last_stream_id);
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_INT_EQUALS(
        AWS_ERROR_HTTP_PROTOCOL_ERROR, testing_channel_get_shutdown_error_code(&s_tester.testing_channel));
    /* clean up */
    return s_tester_clean_up();
}

static void s_on_completed(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)connection;
    int *callback_error_code = user_data;
    *callback_error_code = error_code;
}

/* Test the user API for changing HTTP/2 connection settings */
TEST_CASE(h2_client_change_settings_succeed) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* client sent the preface and first settings */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *first_written_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, 0);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_SETTINGS, first_written_frame->type);
    ASSERT_FALSE(first_written_frame->ack);

    /* We disabled the push_promise at the initial setting, let's use user API to enable it. */
    /* Use user API to change HTTP/2 connection settings */

    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_ENABLE_PUSH, .value = 1},
    };
    int callback_error_code = INT32_MAX;

    ASSERT_SUCCESS(aws_http2_connection_change_settings(
        s_tester.connection, settings_array, AWS_ARRAY_SIZE(settings_array), s_on_completed, &callback_error_code));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* check the settings frame is sent */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *second_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, 1);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_SETTINGS, second_frame->type);
    ASSERT_FALSE(second_frame->ack);
    ASSERT_INT_EQUALS(1, second_frame->settings.length);
    struct aws_http2_setting setting_received;
    aws_array_list_front(&second_frame->settings, &setting_received);
    ASSERT_INT_EQUALS(AWS_HTTP2_SETTINGS_ENABLE_PUSH, setting_received.id);
    ASSERT_INT_EQUALS(1, setting_received.value);

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    /* fake peer sends two settings ack back, one for the initial settings, one for the user settings we just sent */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check the callback has NOT fired after the first settings ack frame, the user_data has not changed */
    ASSERT_INT_EQUALS(INT32_MAX, callback_error_code);
    peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    /* Check the callback has fired after the second settings ack frame, the error code we got is NO_ERROR(0) */
    ASSERT_INT_EQUALS(0, callback_error_code);

    /* Check empty settings can be sent */
    callback_error_code = INT32_MAX;

    ASSERT_SUCCESS(
        aws_http2_connection_change_settings(s_tester.connection, NULL, 0, s_on_completed, &callback_error_code));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* check the empty settings frame is sent */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *second_settings = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_SETTINGS, second_settings->type);
    ASSERT_FALSE(second_settings->ack);
    ASSERT_INT_EQUALS(0, second_settings->settings.length);
    peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    /* Check the callback has fired after the second settings ack frame, the error code we got is NO_ERROR(0) */
    ASSERT_INT_EQUALS(0, callback_error_code);

    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    peer_frame = aws_h2_frame_new_push_promise(allocator, stream_id, promised_stream_id, push_request_headers, 0);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate the connection is still open */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_http_headers_release(push_request_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

/* Test the user API for changing HTTP/2 connection settings and no settings ACK received from peer */
TEST_CASE(h2_client_change_settings_failed_no_ack_received) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* client sent the preface and first settings */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *first_written_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, 0);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_SETTINGS, first_written_frame->type);
    ASSERT_FALSE(first_written_frame->ack);

    /* request changing setting */
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_ENABLE_PUSH, .value = 1},
    };
    int callback_error_code = INT32_MAX;
    ASSERT_SUCCESS(aws_http2_connection_change_settings(
        s_tester.connection, settings_array, AWS_ARRAY_SIZE(settings_array), s_on_completed, &callback_error_code));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    /* fake peer sends one settings ack back the initial settings */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check the callback has NOT fired after the first settings ack frame, the user_data has not changed */
    ASSERT_INT_EQUALS(INT32_MAX, callback_error_code);

    /* shutdown the connection */
    h2_fake_peer_clean_up(&s_tester.peer);
    aws_http_connection_release(s_tester.connection);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check the callback has fired with error, after connection shutdown */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, callback_error_code);
    ASSERT_SUCCESS(testing_channel_clean_up(&s_tester.testing_channel));
    /* clean up */
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* Test manual window management for stream successfully disabled the automatically window update */
TEST_CASE(h2_client_manual_window_management_disabled_auto_window_update) {
    ASSERT_SUCCESS(s_manual_window_management_tester_init(allocator, false /*conn*/, true /*stream*/, ctx));
    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    size_t window_size = 10;

    /* change the settings of the initial window size for new stream flow-control window */
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = (uint32_t)window_size},
    };

    ASSERT_SUCCESS(aws_http2_connection_change_settings(
        s_tester.connection,
        settings_array,
        AWS_ARRAY_SIZE(settings_array),
        NULL /*callback function*/,
        NULL /*user_data*/));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* fake peer sends two settings ack back, one for the initial settings, one for the user settings we just sent */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    struct aws_byte_buf response_body_bufs;
    /* fake peer sends a DATA frame take all the window size we have */
    ASSERT_SUCCESS(aws_byte_buf_init(&response_body_bufs, allocator, window_size));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&response_body_bufs, (uint8_t)'a', window_size));
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&response_body_bufs);
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, false /*end_stream*/));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate no window_update for stream frame sent automatically */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_NULL(h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id, 0 /*idx*/, NULL));

    /* validate that stream is still open */
    ASSERT_FALSE(stream_tester.complete);
    /* peer send another flow-controlled frame will result in stream flow control error */
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, true /*end_stream*/));

    /* validate that stream completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);

    /* a stream error should not affect the connection */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* validate that stream sent RST_STREAM with AWS_HTTP2_ERR_FLOW_CONTROL_ERROR */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_stream_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, stream_id, 0, NULL);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_byte_buf_clean_up(&response_body_bufs);
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);

    return s_tester_clean_up();
}

TEST_CASE(h2_client_manual_window_management_user_send_stream_window_update) {

    ASSERT_SUCCESS(s_manual_window_management_tester_init(allocator, false /*conn*/, true /*stream*/, ctx));
    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    size_t window_size = 10;

    /* change the settings of the initial window size for new stream flow-control window */
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = (uint32_t)window_size},
    };

    ASSERT_SUCCESS(aws_http2_connection_change_settings(
        s_tester.connection,
        settings_array,
        AWS_ARRAY_SIZE(settings_array),
        NULL /*callback function*/,
        NULL /*user_data*/));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* fake peer sends two settings ack back, one for the initial settings, one for the user settings we just sent */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    struct aws_byte_buf response_body_bufs;
    /* fake peer sends a DATA frame take all the window size we have */
    ASSERT_SUCCESS(aws_byte_buf_init(&response_body_bufs, allocator, window_size));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&response_body_bufs, (uint8_t)'a', window_size));
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&response_body_bufs);
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, false /*end_stream*/));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate no window_update frame for stream sent automatically */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_NULL(h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id, 0 /*idx*/, NULL));

    /* call API to update the stream window */
    aws_http_stream_update_window(stream_tester.stream, window_size);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate stream window_update frame was sent */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *stream_window_update_frame = h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id, 0 /*idx*/, NULL);
    ASSERT_NOT_NULL(stream_window_update_frame);
    ASSERT_UINT_EQUALS(window_size, stream_window_update_frame->window_size_increment);

    /* validate that stream is still open */
    ASSERT_FALSE(stream_tester.complete);
    /* peer send another flow-controlled frame will success */
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, true /*end_stream*/));

    /* validate that stream received complete response */
    struct aws_byte_buf expected_body;
    ASSERT_SUCCESS(aws_byte_buf_init(&expected_body, allocator, 2 * window_size));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&expected_body, (uint8_t)'a', 2 * window_size));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_SUCCESS(s_compare_headers(response_headers, stream_tester.response_headers));
    ASSERT_TRUE(aws_byte_buf_eq(&stream_tester.response_body, &expected_body));

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_byte_buf_clean_up(&response_body_bufs);
    aws_byte_buf_clean_up(&expected_body);
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);

    return s_tester_clean_up();
}

TEST_CASE(h2_client_manual_window_management_user_send_stream_window_update_with_padding) {

    ASSERT_SUCCESS(s_manual_window_management_tester_init(allocator, false /*conn*/, true /*stream*/, ctx));
    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    size_t window_size = 20;
    size_t padding_length = 10;
    size_t data_length = window_size - padding_length - 1;

    /* change the settings of the initial window size for new stream flow-control window */
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = (uint32_t)window_size},
    };

    ASSERT_SUCCESS(aws_http2_connection_change_settings(
        s_tester.connection,
        settings_array,
        AWS_ARRAY_SIZE(settings_array),
        NULL /*callback function*/,
        NULL /*user_data*/));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* fake peer sends two settings ack back, one for the initial settings, one for the user settings we just sent */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    struct aws_byte_buf response_body_bufs;
    /* fake peer sends a DATA frame take all the window size we have */
    ASSERT_SUCCESS(aws_byte_buf_init(&response_body_bufs, allocator, data_length));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&response_body_bufs, (uint8_t)'a', data_length));
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&response_body_bufs);
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_with_padding_length(
        &s_tester.peer, stream_id, body_cursor, false /*end_stream*/, (uint8_t)padding_length));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate no window_update frame for stream sent automatically */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    /* padding and padding length should be updated automatically */
    size_t end_index = 0;
    struct h2_decoded_frame *stream_window_update_frame = h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id, 0 /*idx*/, &end_index);
    ASSERT_NOT_NULL(stream_window_update_frame);
    ASSERT_UINT_EQUALS(
        padding_length + 1 /*one byte for padding length*/, stream_window_update_frame->window_size_increment);

    /* call API to update the stream window */
    aws_http_stream_update_window(stream_tester.stream, data_length);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate stream window_update frame from user was sent */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    stream_window_update_frame = h2_decode_tester_find_stream_frame(
        &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id, end_index + 1, NULL);
    ASSERT_NOT_NULL(stream_window_update_frame);
    ASSERT_UINT_EQUALS(data_length, stream_window_update_frame->window_size_increment);

    /* validate that stream is still open */
    ASSERT_FALSE(stream_tester.complete);
    /* peer send another flow-controlled frame will success */
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, true /*end_stream*/));

    /* validate that stream received complete response */
    struct aws_byte_buf expected_body;
    ASSERT_SUCCESS(aws_byte_buf_init(&expected_body, allocator, 2 * data_length));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&expected_body, (uint8_t)'a', 2 * data_length));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_SUCCESS(s_compare_headers(response_headers, stream_tester.response_headers));
    ASSERT_TRUE(aws_byte_buf_eq(&stream_tester.response_body, &expected_body));

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_byte_buf_clean_up(&response_body_bufs);
    aws_byte_buf_clean_up(&expected_body);
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);

    return s_tester_clean_up();
}

TEST_CASE(h2_client_manual_window_management_user_send_stream_window_update_overflow) {

    ASSERT_SUCCESS(s_manual_window_management_tester_init(allocator, false /*conn*/, true /*stream*/, ctx));
    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* call API to update the stream window and cause a overflow */
    aws_http_stream_update_window(stream_tester.stream, INT32_MAX);
    aws_http_stream_update_window(stream_tester.stream, INT32_MAX);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate that stream completed with error */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_TRUE(stream_tester.complete);
    /* overflow happens */
    ASSERT_INT_EQUALS(AWS_ERROR_OVERFLOW_DETECTED, stream_tester.on_complete_error_code);
    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, 0, NULL);
    /* But the error code is not the same as user was trying to send */
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_INTERNAL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);

    return s_tester_clean_up();
}

/* Peer sends a flow-controlled frame when the connection window-size is not enough for it will result in connection
 * flow-control error */
TEST_CASE(h2_client_manual_window_management_user_send_conn_window_update) {

    ASSERT_SUCCESS(s_manual_window_management_tester_init(allocator, true /*conn*/, false /*stream*/, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    struct aws_byte_buf response_body_bufs;

    /* The max body size here is limited. So we need to send multiple bodies to get the flow-control error */
    size_t body_size =
        aws_max_size(aws_h2_settings_initial[AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE], g_aws_channel_max_fragment_size) -
        AWS_H2_FRAME_PREFIX_SIZE;
    /* fake peer sends a DATA frame larger than the window size we have */
    ASSERT_SUCCESS(aws_byte_buf_init(&response_body_bufs, allocator, body_size));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&response_body_bufs, (uint8_t)'a', body_size));
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&response_body_bufs);
    /* number of bodies peer will send, just to ensure the connection flow-control window will not be blocked when we
     * manually update it */
    size_t body_number = 2 * aws_h2_settings_initial[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE] / body_size;
    for (size_t i = 0; i < body_number; i++) {
        if (i == body_number - 1) {
            ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, true /*end_stream*/));
        } else {
            ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, false /*end_stream*/));
        }
        /* manually update the stream and connection flow-control window. */
        aws_http_stream_update_window(stream_tester.stream, body_size);
        aws_http2_connection_update_window(s_tester.connection, (uint32_t)body_size);
        testing_channel_drain_queued_tasks(&s_tester.testing_channel);
        ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

        struct h2_decoded_frame *stream_window_update_frame = h2_decode_tester_find_stream_frame(
            &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, stream_id, 0 /*idx*/, NULL);
        ASSERT_NOT_NULL(stream_window_update_frame);
        ASSERT_UINT_EQUALS(body_size, stream_window_update_frame->window_size_increment);

        struct h2_decoded_frame *connection_window_update_frame = h2_decode_tester_find_stream_frame(
            &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, 0 /*stream_id*/, 0 /*idx*/, NULL);
        ASSERT_NOT_NULL(connection_window_update_frame);
        ASSERT_UINT_EQUALS(body_size, connection_window_update_frame->window_size_increment);
    }
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    /* validate that stream received complete response */
    struct aws_byte_buf expected_body;
    ASSERT_SUCCESS(aws_byte_buf_init(&expected_body, allocator, body_number * body_size));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&expected_body, (uint8_t)'a', body_number * body_size));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_SUCCESS(s_compare_headers(response_headers, stream_tester.response_headers));
    ASSERT_TRUE(aws_byte_buf_eq(&stream_tester.response_body, &expected_body));

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_byte_buf_clean_up(&response_body_bufs);
    aws_byte_buf_clean_up(&expected_body);
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_manual_window_management_user_send_conn_window_update_with_padding) {

    ASSERT_SUCCESS(s_manual_window_management_tester_init(allocator, true /*conn*/, false /*stream*/, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    struct aws_byte_buf response_body_bufs;

    /* The max body size here is limited. So we need to send multiple bodies to get the flow-control error */
    size_t padding_size = 10;
    size_t body_size =
        aws_max_size(aws_h2_settings_initial[AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE], g_aws_channel_max_fragment_size) -
        AWS_H2_FRAME_PREFIX_SIZE - padding_size - 1;
    /* fake peer sends a DATA frame larger than the window size we have */
    ASSERT_SUCCESS(aws_byte_buf_init(&response_body_bufs, allocator, body_size));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&response_body_bufs, (uint8_t)'a', body_size));
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&response_body_bufs);
    /* number of bodies peer will send, just to ensure the connection flow-control window will not be blocked when we
     * manually update it */
    size_t body_number = 2 * aws_h2_settings_initial[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE] / body_size;
    for (size_t i = 0; i < body_number; i++) {
        if (i == body_number - 1) {
            ASSERT_SUCCESS(h2_fake_peer_send_data_frame_with_padding_length(
                &s_tester.peer, stream_id, body_cursor, true /*end_stream*/, (uint8_t)padding_size));
        } else {
            ASSERT_SUCCESS(h2_fake_peer_send_data_frame_with_padding_length(
                &s_tester.peer, stream_id, body_cursor, false /*end_stream*/, (uint8_t)padding_size));
        }
        testing_channel_drain_queued_tasks(&s_tester.testing_channel);
        ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
        size_t out_index = 0;
        /* The update for padding and padding length should be sent */
        struct h2_decoded_frame *connection_window_update_frame = h2_decode_tester_find_stream_frame(
            &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, 0 /*stream_id*/, 0 /*idx*/, &out_index);
        ASSERT_NOT_NULL(connection_window_update_frame);
        ASSERT_UINT_EQUALS(
            padding_size + 1 /* one byte for padding length */, connection_window_update_frame->window_size_increment);
        /* manually update the stream and connection flow-control window. */
        aws_http_stream_update_window(stream_tester.stream, body_size);
        aws_http2_connection_update_window(s_tester.connection, (uint32_t)body_size);
        testing_channel_drain_queued_tasks(&s_tester.testing_channel);
        ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

        connection_window_update_frame = h2_decode_tester_find_stream_frame(
            &s_tester.peer.decode, AWS_H2_FRAME_T_WINDOW_UPDATE, 0 /*stream_id*/, out_index + 1 /*idx*/, &out_index);
        ASSERT_NOT_NULL(connection_window_update_frame);
        ASSERT_UINT_EQUALS(body_size, connection_window_update_frame->window_size_increment);
    }
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    /* validate that stream received complete response */
    struct aws_byte_buf expected_body;
    ASSERT_SUCCESS(aws_byte_buf_init(&expected_body, allocator, body_number * body_size));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&expected_body, (uint8_t)'a', body_number * body_size));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    ASSERT_INT_EQUALS(200, stream_tester.response_status);
    ASSERT_SUCCESS(s_compare_headers(response_headers, stream_tester.response_headers));
    ASSERT_TRUE(aws_byte_buf_eq(&stream_tester.response_body, &expected_body));

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* clean up */
    aws_byte_buf_clean_up(&response_body_bufs);
    aws_byte_buf_clean_up(&expected_body);
    aws_http_headers_release(response_headers);
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_manual_window_management_user_send_connection_window_update_overflow) {

    ASSERT_SUCCESS(s_manual_window_management_tester_init(allocator, true /*conn*/, false /*stream*/, ctx));
    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* update the connection window to cause an overflow */
    aws_http2_connection_update_window(s_tester.connection, INT32_MAX);
    aws_http2_connection_update_window(s_tester.connection, INT32_MAX);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* validate that connection closed with error */
    ASSERT_FALSE(aws_http_connection_is_open(s_tester.connection));
    /* client should send GOAWAY */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *goaway =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_GOAWAY, 0, NULL);
    ASSERT_NOT_NULL(goaway);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_INTERNAL_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    return s_tester_clean_up();
}

struct ping_user_data {
    uint64_t rtt_ns;
    int error_code;
};

static void on_ping_complete(
    struct aws_http_connection *connection,
    uint64_t round_trip_time_ns,
    int error_code,
    void *user_data) {

    (void)connection;
    struct ping_user_data *data = user_data;
    data->error_code = error_code;
    data->rtt_ns = round_trip_time_ns;
}

/* Test the user API for PING successfully get the round trip time */
TEST_CASE(h2_client_send_ping_successfully_receive_ack) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct aws_byte_cursor opaque_data = aws_byte_cursor_from_c_str("12345678");
    struct ping_user_data data = {.rtt_ns = 0, .error_code = INT32_MAX};
    /* client request a PING */
    ASSERT_SUCCESS(aws_http2_connection_ping(s_tester.connection, &opaque_data, on_ping_complete, &data));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* check ping frame received */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *ping_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_PING, 0, NULL);
    ASSERT_BIN_ARRAYS_EQUALS(
        opaque_data.ptr, AWS_HTTP2_PING_DATA_SIZE, ping_frame->ping_opaque_data, AWS_HTTP2_PING_DATA_SIZE);
    ASSERT_FALSE(ping_frame->ack);

    /* fake peer send PING ACK */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_ping(allocator, true /*ACK*/, ping_frame->ping_opaque_data);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* check callback fired, and succeed */
    ASSERT_INT_EQUALS(0, data.error_code);
    ASSERT_FALSE(data.rtt_ns == 0);
    /* clean up */
    return s_tester_clean_up();
}

/* Test the user request a PING, but peer never sends PING ACK back */
TEST_CASE(h2_client_send_ping_no_ack_received) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct ping_user_data data = {.rtt_ns = 0, .error_code = INT32_MAX};
    /* client request a PING */
    ASSERT_SUCCESS(aws_http2_connection_ping(s_tester.connection, NULL, on_ping_complete, &data));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* check ping frame received */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *ping_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_PING, 0, NULL);
    uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE];
    AWS_ZERO_ARRAY(opaque_data);
    /* Zeroed 8 bytes data received */
    ASSERT_BIN_ARRAYS_EQUALS(
        opaque_data, AWS_HTTP2_PING_DATA_SIZE, ping_frame->ping_opaque_data, AWS_HTTP2_PING_DATA_SIZE);
    ASSERT_FALSE(ping_frame->ack);

    /* shutdown the connection */
    h2_fake_peer_clean_up(&s_tester.peer);
    aws_http_connection_release(s_tester.connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&s_tester.testing_channel));
    /* Check the callback has fired with error */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, data.error_code);
    ASSERT_TRUE(data.rtt_ns == 0);
    /* clean up */
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* Test the user request a PING, but peer sends an extra PING ACK */
TEST_CASE(h2_client_conn_err_extraneous_ping_ack_received) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct aws_byte_cursor opaque_data = aws_byte_cursor_from_c_str("12345678");
    /* client request a PING */
    ASSERT_SUCCESS(aws_http2_connection_ping(s_tester.connection, &opaque_data, NULL, NULL));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    struct aws_h2_frame *peer_frame = aws_h2_frame_new_ping(allocator, true /*ACK*/, opaque_data.ptr);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    /* fake peer send an extra PING ACK */
    peer_frame = aws_h2_frame_new_ping(allocator, true /*ACK*/, opaque_data.ptr);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
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
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    return s_tester_clean_up();
}

/* Test the user request a PING, but peer sends the PING ACK with mismatched opaque_data */
TEST_CASE(h2_client_conn_err_mismatched_ping_ack_received) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct aws_byte_cursor opaque_data = aws_byte_cursor_from_c_str("12345678");
    /* client request a PING with all zero opaque_data */
    ASSERT_SUCCESS(aws_http2_connection_ping(s_tester.connection, NULL, NULL, NULL));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* peer sends PING ACK with numbers in payload */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_ping(allocator, true /*ACK*/, opaque_data.ptr);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
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
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, goaway->error_code);
    ASSERT_UINT_EQUALS(0, goaway->goaway_last_stream_id);

    /* clean up */
    return s_tester_clean_up();
}

TEST_CASE(h2_client_empty_initial_settings) {
    (void)ctx;
    aws_http_library_init(allocator);

    s_tester.alloc = allocator;

    struct aws_testing_channel_options options = {.clock_fn = aws_high_res_clock_get_ticks};

    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, allocator, &options));

    /* empty initial settings */
    struct aws_http2_connection_options http2_options = {
        .on_initial_settings_completed = s_on_initial_settings_completed,
        .max_closed_streams = AWS_HTTP2_DEFAULT_MAX_CLOSED_STREAMS,
        .on_remote_settings_change = s_on_remote_settings_change,
    };

    s_tester.connection =
        aws_http_connection_new_http2_client(allocator, false /* manual window management */, &http2_options);
    ASSERT_NOT_NULL(s_tester.connection);

    {
        /* set connection user_data (handled by http-bootstrap in real world) */
        s_tester.connection->user_data = &s_tester.user_data;
        /* re-enact marriage vows of http-connection and channel (handled by http-bootstrap in real world) */
        struct aws_channel_slot *slot = aws_channel_slot_new(s_tester.testing_channel.channel);
        ASSERT_NOT_NULL(slot);
        ASSERT_SUCCESS(aws_channel_slot_insert_end(s_tester.testing_channel.channel, slot));
        ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &s_tester.connection->channel_handler));
        s_tester.connection->vtable->on_channel_handler_installed(&s_tester.connection->channel_handler, slot);
    }

    struct h2_fake_peer_options peer_options = {
        .alloc = allocator,
        .testing_channel = &s_tester.testing_channel,
        .is_server = true,
    };
    ASSERT_SUCCESS(h2_fake_peer_init(&s_tester.peer, &peer_options));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* shutdown the connection */
    h2_fake_peer_clean_up(&s_tester.peer);
    aws_http_connection_release(s_tester.connection);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check the callback has fired with error, after connection shutdown */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, s_tester.user_data.initial_settings_error_code);
    ASSERT_SUCCESS(testing_channel_clean_up(&s_tester.testing_channel));
    /* clean up */
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_client_conn_failed_initial_settings_completed_not_invoked) {
    (void)ctx;
    aws_http_library_init(allocator);

    s_tester.alloc = allocator;
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_ENABLE_PUSH, .value = 0},
    };

    struct aws_http2_connection_options http2_options = {
        .initial_settings_array = settings_array,
        .num_initial_settings = AWS_ARRAY_SIZE(settings_array),
        .on_initial_settings_completed = s_on_initial_settings_completed,
        .max_closed_streams = AWS_HTTP2_DEFAULT_MAX_CLOSED_STREAMS,
        .on_remote_settings_change = s_on_remote_settings_change,
    };
    s_tester.connection =
        aws_http_connection_new_http2_client(allocator, false /* manual window management */, &http2_options);
    ASSERT_NOT_NULL(s_tester.connection);
    s_tester.user_data.initial_settings_error_code = INT32_MAX;
    {
        /* set connection user_data (handled by http-bootstrap in real world) */
        s_tester.connection->user_data = &s_tester.user_data;
        /* pretent the connection failed, and destroy the handler (handled by http-bootstrap in real world)  */
        aws_channel_handler_destroy(&s_tester.connection->channel_handler);
    }
    /* Check callback has not fired and the error code is still INT32_MAX */
    ASSERT_INT_EQUALS(INT32_MAX, s_tester.user_data.initial_settings_error_code);
    /* clean up */
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_client_stream_reset_stream) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* reset stream with no error */
    ASSERT_SUCCESS(aws_http2_stream_reset(stream_tester.stream, AWS_HTTP2_ERR_NO_ERROR));
    /* stream can only be reset once, the second reset will not fail but will be ignored */
    ASSERT_SUCCESS(aws_http2_stream_reset(stream_tester.stream, AWS_HTTP2_ERR_CANCEL));

    /* validate that stream completed with error. */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_RST_STREAM_SENT, stream_tester.on_complete_error_code);
    /* a stream error should not affect the connection */
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    /* validate that stream sent only the first RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_TRUE(frames_count + 1 == h2_decode_tester_frame_count(&s_tester.peer.decode));
    struct h2_decoded_frame *rst_stream_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_RST_STREAM, rst_stream_frame->type);
    ASSERT_INT_EQUALS(AWS_HTTP2_ERR_NO_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_reset_ignored_stream_closed) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* Request to reset stream after error has happened, still get success back, but the error code will be ignored */
    ASSERT_SUCCESS(aws_http2_stream_reset(stream_tester.stream, AWS_HTTP2_ERR_CANCEL));
    /* Before the async call finishes, an error happens and stream closed because of it */
    /* fake peer sends response body BEFORE any response headers, which leads to a error and stream will close */
    const char *body_src = "hello";
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(&s_tester.peer, stream_id, body_src, true /*end_stream*/));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* A possible race condition between "real error" and user request to reset stream in real life, which will lead to
     * possible different error code in rst_stream. User can aws_http2_stream_get_sent_reset_error_code to query the
     * error code we sent to peer. */

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);
    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, 0, NULL);
    /* But the error code is not the same as user was trying to send */
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_reset_failed_before_activate_called) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);

    /* reset will fail before activate called */
    ASSERT_FAILS(aws_http2_stream_reset(stream, AWS_HTTP2_ERR_NO_ERROR));

    /* Once you activate the stream, you are able to reset it */
    ASSERT_SUCCESS(aws_http_stream_activate(stream));
    ASSERT_SUCCESS(aws_http2_stream_reset(stream, AWS_HTTP2_ERR_ENHANCE_YOUR_CALM));

    /* validate rst_stream is sent */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, 0, NULL);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_ENHANCE_YOUR_CALM, rst_stream_frame->error_code);
    /* clean up */
    aws_http_message_release(request);
    aws_http_stream_release(stream);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_cancel_stream) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
    };

    struct client_stream_tester stream_tester;
    ASSERT_SUCCESS(s_stream_tester_init(&stream_tester, request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Cancel the request */
    aws_http_stream_cancel(stream_tester.stream, AWS_ERROR_COND_VARIABLE_ERROR_UNKNOWN);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_COND_VARIABLE_ERROR_UNKNOWN, stream_tester.on_complete_error_code);
    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, 0, NULL);
    /* But the error code is not the same as user was trying to send */
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_CANCEL, rst_stream_frame->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_keeps_alive_for_cross_thread_task) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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

    /* fake peer sends response  */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "404"),
        DEFINE_HEADER("date", "Wed, 01 Apr 2020 23:02:49 GMT"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));

    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, true /*end_stream*/, 0, NULL);

    /* User reset the stream */
    ASSERT_SUCCESS(aws_http2_stream_reset(stream_tester.stream, AWS_HTTP2_ERR_ENHANCE_YOUR_CALM));
    /* Before the async call finishes, the stream completes */
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));
    /* And user releases the stream */
    aws_http_stream_release(stream_tester.stream);

    /* Task should finish without error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, stream_tester.on_complete_error_code);
    /* validate that no RST_STREAM sent */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_NULL(h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, 0, NULL));

    /* clean up */
    aws_http_message_release(request);
    aws_http_headers_release(response_headers);

    /* clean up stream_tester */
    for (size_t i = 0; i < stream_tester.num_info_responses; ++i) {
        aws_http_message_release(stream_tester.info_responses[i]);
    }

    aws_http_headers_release(stream_tester.current_info_headers);
    aws_http_headers_release(stream_tester.response_headers);
    aws_http_headers_release(stream_tester.response_trailer);
    aws_byte_buf_clean_up(&stream_tester.response_body);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_get_received_reset_error_code) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    uint32_t http2_error;
    /* Before rst_stream received, get function will fail */
    ASSERT_FAILS(aws_http2_stream_get_received_reset_error_code(stream_tester.stream, &http2_error));

    /* fake peer sends RST_STREAM */
    struct aws_h2_frame *rst_stream =
        aws_h2_frame_new_rst_stream(allocator, stream_id, AWS_HTTP2_ERR_ENHANCE_YOUR_CALM);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, rst_stream));
    /* validate that stream completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_RST_STREAM_RECEIVED, stream_tester.on_complete_error_code);

    /* After rst_stream received, and stream completed with RST_STREAM_RECEIVED, get function will get the error_code
     * received in rst_stream */
    ASSERT_SUCCESS(aws_http2_stream_get_received_reset_error_code(stream_tester.stream, &http2_error));
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_ENHANCE_YOUR_CALM, http2_error);
    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_stream_get_sent_reset_error_code) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
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
    uint32_t http2_error;

    /* Before rst_stream sent, get function will fail */
    ASSERT_FAILS(aws_http2_stream_get_sent_reset_error_code(stream_tester.stream, &http2_error));

    /* fake peer sends response body BEFORE any response headers, which leads to a error and stream will close */
    const char *body_src = "hello";
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame_str(&s_tester.peer, stream_id, body_src, true /*end_stream*/));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate that stream completed with protocol error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(stream_tester.complete);
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_PROTOCOL_ERROR, stream_tester.on_complete_error_code);

    /* Stream completed with error code, it's time to get what we sent */
    ASSERT_SUCCESS(aws_http2_stream_get_sent_reset_error_code(stream_tester.stream, &http2_error));
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, http2_error);

    /* validate that stream sent RST_STREAM */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, 0, NULL);
    ASSERT_NOT_NULL(rst_stream_frame);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, rst_stream_frame->error_code);

    /* clean up */
    aws_http_message_release(request);
    client_stream_tester_clean_up(&stream_tester);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_new_request_allowed) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    /* prepare request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header headers[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":authority", "veryblackpage.com"),
        DEFINE_HEADER(":path", "/"),
    };
    ASSERT_SUCCESS(aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers)));

    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = request,
    };

    /* validate the new request is allowed for now */
    ASSERT_TRUE(aws_http_connection_new_requests_allowed(s_tester.connection));

    /* fake peer send a GOAWAY frame */
    uint32_t stream_id = 0;
    struct aws_byte_cursor debug_info;
    AWS_ZERO_STRUCT(debug_info);
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_goaway(allocator, stream_id, AWS_HTTP2_ERR_NO_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* validate the new request is not allowed anymore when goaway received */
    ASSERT_FALSE(aws_http_connection_new_requests_allowed(s_tester.connection));
    /* Make new request will fail */
    ASSERT_NULL(aws_http_connection_make_request(s_tester.connection, &options));
    ASSERT_UINT_EQUALS(AWS_ERROR_HTTP_GOAWAY_RECEIVED, aws_last_error());

    /* close connection */
    aws_http_connection_close(s_tester.connection);
    /* Make new request will fail */
    ASSERT_NULL(aws_http_connection_make_request(s_tester.connection, &options));
    ASSERT_UINT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, aws_last_error());

    /* clean up */
    aws_http_message_release(request);
    return s_tester_clean_up();
}

static void s_default_settings(struct aws_http2_setting settings[AWS_HTTP2_SETTINGS_COUNT]) {
    for (int i = AWS_HTTP2_SETTINGS_BEGIN_RANGE; i < AWS_HTTP2_SETTINGS_END_RANGE; i++) {
        /* settings range begin with 1, store them into 0-based array of aws_http2_setting */
        settings[i - 1].id = i;
        settings[i - 1].value = aws_h2_settings_initial[i];
    }
}

static int s_apply_changed_settings(
    struct aws_http2_setting settings[AWS_HTTP2_SETTINGS_COUNT],
    struct aws_http2_setting *settings_to_change,
    int number_settings_to_change) {

    for (int i = 0; i < number_settings_to_change; i++) {
        struct aws_http2_setting setting = settings_to_change[i];
        ASSERT_UINT_EQUALS(settings[setting.id - 1].id, setting.id);
        settings[setting.id - 1].value = setting.value;
    }
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_client_send_multiple_goaway) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct aws_byte_buf info_buf = aws_byte_buf_from_c_str("this is a debug info");
    struct aws_byte_cursor debug_info = aws_byte_cursor_from_buf(&info_buf);

    /* First graceful shutdown warning */
    aws_http2_connection_send_goaway(
        s_tester.connection, AWS_HTTP2_ERR_NO_ERROR, true /*allow_more_streams*/, &debug_info /*debug_data*/);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check the goaway frame received */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *latest_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_NO_ERROR, latest_frame->error_code);
    ASSERT_UINT_EQUALS(AWS_H2_STREAM_ID_MAX, latest_frame->goaway_last_stream_id);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&latest_frame->data, "this is a debug info"));

    /* Real GOAWAY */
    aws_http2_connection_send_goaway(
        s_tester.connection, AWS_HTTP2_ERR_PROTOCOL_ERROR, false /*allow_more_streams*/, &debug_info);
    /* It is fine to free the buffer right after the call, since we keep it in the connection's memory */
    aws_byte_buf_clean_up(&info_buf);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check the goaway frame received */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    latest_frame = h2_decode_tester_latest_frame(&s_tester.peer.decode);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, latest_frame->error_code);
    ASSERT_UINT_EQUALS(0, latest_frame->goaway_last_stream_id);
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&latest_frame->data, "this is a debug info"));
    size_t frames_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    /* Graceful shutdown warning after real GOAWAY will be ignored */
    aws_http2_connection_send_goaway(
        s_tester.connection, AWS_HTTP2_ERR_NO_ERROR, true /*allow_more_streams*/, NULL /*debug_data*/);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check the goaway frame received */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    ASSERT_UINT_EQUALS(frames_count, h2_decode_tester_frame_count(&s_tester.peer.decode));

    /* clean up */
    return s_tester_clean_up();
}

TEST_CASE(h2_client_get_sent_goaway) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    uint32_t last_stream_id;
    uint32_t http2_error;
    ASSERT_FAILS(aws_http2_connection_get_sent_goaway(s_tester.connection, &http2_error, &last_stream_id));

    /* First graceful shutdown warning */
    aws_http2_connection_send_goaway(
        s_tester.connection, AWS_HTTP2_ERR_NO_ERROR, true /*allow_more_streams*/, NULL /*debug_data*/);
    /* User send goaway asynchronously, you are not able to get the sent goaway right after the call */
    ASSERT_FAILS(aws_http2_connection_get_sent_goaway(s_tester.connection, &http2_error, &last_stream_id));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(aws_http2_connection_get_sent_goaway(s_tester.connection, &http2_error, &last_stream_id));
    ASSERT_UINT_EQUALS(AWS_H2_STREAM_ID_MAX, last_stream_id);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_NO_ERROR, http2_error);

    /* Second graceful shutdown warning, with non-zero error. Well it's not against the law, just do what user wants */
    aws_http2_connection_send_goaway(
        s_tester.connection, AWS_HTTP2_ERR_ENHANCE_YOUR_CALM, true /*allow_more_streams*/, NULL /*debug_data*/);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(aws_http2_connection_get_sent_goaway(s_tester.connection, &http2_error, &last_stream_id));
    ASSERT_UINT_EQUALS(AWS_H2_STREAM_ID_MAX, last_stream_id);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_ENHANCE_YOUR_CALM, http2_error);

    struct aws_byte_cursor opaque_data = aws_byte_cursor_from_c_str("12345678");
    /* peer send extra ping ack will lead to a connection error and goaway will be sent */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_ping(allocator, true /*ACK*/, opaque_data.ptr);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Check the sent goaway */
    ASSERT_SUCCESS(aws_http2_connection_get_sent_goaway(s_tester.connection, &http2_error, &last_stream_id));
    ASSERT_UINT_EQUALS(0, last_stream_id);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_PROTOCOL_ERROR, http2_error);

    /* clean up */
    return s_tester_clean_up();
}

TEST_CASE(h2_client_get_received_goaway) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    uint32_t last_stream_id;
    uint32_t http2_error;

    /* you are not able to get the received goaway if no GOAWAY received */
    ASSERT_FAILS(aws_http2_connection_get_received_goaway(s_tester.connection, &http2_error, &last_stream_id));

    /* fake peer send goaway */
    const char debug_string[] = "Error, Core Dump 0XFFFFFFFF";
    struct aws_byte_cursor debug_info = aws_byte_cursor_from_c_str(debug_string);
    struct aws_h2_frame *peer_frame =
        aws_h2_frame_new_goaway(allocator, AWS_H2_STREAM_ID_MAX, AWS_HTTP2_ERR_NO_ERROR, debug_info);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Try to get the received goaway */
    ASSERT_SUCCESS(aws_http2_connection_get_received_goaway(s_tester.connection, &http2_error, &last_stream_id));
    ASSERT_UINT_EQUALS(AWS_H2_STREAM_ID_MAX, last_stream_id);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_NO_ERROR, http2_error);

    /* clean up */
    return s_tester_clean_up();
}

TEST_CASE(h2_client_get_local_settings) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    struct aws_http2_setting settings_get[AWS_HTTP2_SETTINGS_COUNT];
    struct aws_http2_setting settings_expected[AWS_HTTP2_SETTINGS_COUNT];
    s_default_settings(settings_expected);
    aws_http2_connection_get_local_settings(s_tester.connection, settings_get);
    /* Altough we disabled the push_promise at the initial settings, but without the settings ACK from peer, the
     * settings we are using locally is still the default settings */
    ASSERT_SUCCESS(s_compare_settings_array(settings_expected, settings_get, AWS_HTTP2_SETTINGS_COUNT));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    /* fake peer sends settings ack back for the initial settings. */
    struct aws_h2_frame *peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Set expected setting */
    settings_expected[AWS_HTTP2_SETTINGS_ENABLE_PUSH - 1].value = false;
    /* Initial settings got ACK by peer, know we will get the settings with push_promise disabled */
    aws_http2_connection_get_local_settings(s_tester.connection, settings_get);
    ASSERT_SUCCESS(s_compare_settings_array(settings_expected, settings_get, AWS_HTTP2_SETTINGS_COUNT));

    /* Request to change the local settings */
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_ENABLE_PUSH, .value = 1},
        {.id = AWS_HTTP2_SETTINGS_HEADER_TABLE_SIZE, .value = 0},
        {.id = AWS_HTTP2_SETTINGS_HEADER_TABLE_SIZE, .value = 1000},
        {.id = AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = 1},
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = 1},
        {.id = AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE, .value = AWS_H2_PAYLOAD_MAX},
        {.id = AWS_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, .value = 1},
    };

    ASSERT_SUCCESS(aws_http2_connection_change_settings(
        s_tester.connection, settings_array, AWS_ARRAY_SIZE(settings_array), NULL /*call_back*/, NULL /*user_data*/));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Settings sent, but not ACKed, still the same settings, we will get */
    aws_http2_connection_get_local_settings(s_tester.connection, settings_get);
    ASSERT_SUCCESS(s_compare_settings_array(settings_expected, settings_get, AWS_HTTP2_SETTINGS_COUNT));

    /* Peer ACKed the settings */
    peer_frame = aws_h2_frame_new_settings(allocator, NULL, 0, true);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Set expected setting */
    ASSERT_SUCCESS(s_apply_changed_settings(settings_expected, settings_array, AWS_ARRAY_SIZE(settings_array)));
    aws_http2_connection_get_local_settings(s_tester.connection, settings_get);
    ASSERT_SUCCESS(s_compare_settings_array(settings_expected, settings_get, AWS_HTTP2_SETTINGS_COUNT));
    /* clean up */
    return s_tester_clean_up();
}

TEST_CASE(h2_client_get_remote_settings) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    struct aws_http2_setting settings_get[AWS_HTTP2_SETTINGS_COUNT];
    struct aws_http2_setting settings_expected[AWS_HTTP2_SETTINGS_COUNT];
    s_default_settings(settings_expected);
    /* Once connection setup and no settings from peer, remote settings will be default init settings */
    aws_http2_connection_get_remote_settings(s_tester.connection, settings_get);
    ASSERT_SUCCESS(s_compare_settings_array(settings_expected, settings_get, AWS_HTTP2_SETTINGS_COUNT));

    /* fake peer sends connection preface */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    /* fake peer sends settings and change the remote settings */
    struct aws_http2_setting settings_array[] = {
        {.id = AWS_HTTP2_SETTINGS_ENABLE_PUSH, .value = 1},
        {.id = AWS_HTTP2_SETTINGS_HEADER_TABLE_SIZE, .value = 0},
        {.id = AWS_HTTP2_SETTINGS_HEADER_TABLE_SIZE, .value = 1000},
        {.id = AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = 1},
        {.id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = 1},
        {.id = AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE, .value = AWS_H2_PAYLOAD_MAX},
        {.id = AWS_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, .value = 1},
    };

    struct aws_h2_frame *settings_frame =
        aws_h2_frame_new_settings(allocator, settings_array, AWS_ARRAY_SIZE(settings_array), false /*ack*/);
    ASSERT_NOT_NULL(settings_frame);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, settings_frame));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Set expected setting */
    ASSERT_SUCCESS(s_apply_changed_settings(settings_expected, settings_array, AWS_ARRAY_SIZE(settings_array)));
    aws_http2_connection_get_remote_settings(s_tester.connection, settings_get);
    ASSERT_SUCCESS(s_compare_settings_array(settings_expected, settings_get, AWS_HTTP2_SETTINGS_COUNT));

    /* clean up */
    return s_tester_clean_up();
}

/* User apis that want to add stuff into connection.synced_data will fail after connection shutdown starts */
TEST_CASE(h2_client_request_apis_failed_after_connection_begin_shutdown) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);
    /* close the connection */
    aws_http_connection_close(s_tester.connection);

    /* Send goaway will silently do nothing as the connection already closed */
    aws_http2_connection_send_goaway(
        s_tester.connection, AWS_HTTP2_ERR_NO_ERROR, false /*allow_more_streams*/, NULL /*debug_data*/);
    /* validate all those user apis to add stuff into synced data will fail */
    ASSERT_FAILS(aws_http_stream_activate(stream));
    ASSERT_FAILS(aws_http2_connection_change_settings(
        s_tester.connection, NULL, 0, NULL /*callback function*/, NULL /*user_data*/));
    ASSERT_FAILS(aws_http2_connection_ping(s_tester.connection, NULL, NULL /*callback function*/, NULL /*user_data*/));

    /* clean up */
    aws_http_message_release(request);
    aws_http_stream_release(stream);
    return s_tester_clean_up();
}

enum request_callback {
    REQUEST_CALLBACK_OUTGOING_BODY,
    REQUEST_CALLBACK_INCOMING_HEADERS,
    REQUEST_CALLBACK_INCOMING_HEADERS_DONE,
    REQUEST_CALLBACK_INCOMING_BODY,
    REQUEST_CALLBACK_COMPLETE,
    REQUEST_CALLBACK_COUNT,
};

struct error_from_callback_tester {
    struct aws_input_stream base;
    enum request_callback error_at;
    int callback_counts[REQUEST_CALLBACK_COUNT];
    bool has_errored;
    struct aws_stream_status status;
    int on_complete_error_code;
};

static const int ERROR_FROM_CALLBACK_ERROR_CODE = (int)0xBEEFCAFE;

static int s_error_from_callback_common(
    struct error_from_callback_tester *error_tester,
    enum request_callback current_callback) {

    error_tester->callback_counts[current_callback]++;

    /* After error code returned, no more callbacks should fire (except for on_complete) */
    AWS_FATAL_ASSERT(!error_tester->has_errored);
    AWS_FATAL_ASSERT(current_callback <= error_tester->error_at);
    if (current_callback == error_tester->error_at) {
        error_tester->has_errored = true;
        return aws_raise_error(ERROR_FROM_CALLBACK_ERROR_CODE);
    }

    return AWS_OP_SUCCESS;
}

static int s_error_from_outgoing_body_read(struct aws_input_stream *body, struct aws_byte_buf *dest) {

    (void)dest;

    struct error_from_callback_tester *error_tester = AWS_CONTAINER_OF(body, struct error_from_callback_tester, base);
    if (s_error_from_callback_common(error_tester, REQUEST_CALLBACK_OUTGOING_BODY)) {
        return AWS_OP_ERR;
    }

    /* If the common fn was successful, write out some data and end the stream */
    ASSERT_TRUE(aws_byte_buf_write(dest, (const uint8_t *)"abcd", 4));
    error_tester->status.is_end_of_stream = true;
    return AWS_OP_SUCCESS;
}

static int s_error_from_outgoing_body_get_status(struct aws_input_stream *body, struct aws_stream_status *status) {
    struct error_from_callback_tester *error_tester = AWS_CONTAINER_OF(body, struct error_from_callback_tester, base);
    *status = error_tester->status;
    return AWS_OP_SUCCESS;
}

static void s_error_from_outgoing_body_destroy(void *stream) {
    /* allocated from stack, nothing to do */
    (void)stream;
}
static struct aws_input_stream_vtable s_error_from_outgoing_body_vtable = {
    .seek = NULL,
    .read = s_error_from_outgoing_body_read,
    .get_status = s_error_from_outgoing_body_get_status,
    .get_length = NULL,
};

static int s_error_from_incoming_headers(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)stream;
    (void)header_block;
    (void)header_array;
    (void)num_headers;
    return s_error_from_callback_common(user_data, REQUEST_CALLBACK_INCOMING_HEADERS);
}

static int s_error_from_incoming_headers_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    (void)stream;
    (void)header_block;
    return s_error_from_callback_common(user_data, REQUEST_CALLBACK_INCOMING_HEADERS_DONE);
}

static int s_error_from_incoming_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;
    (void)data;
    return s_error_from_callback_common(user_data, REQUEST_CALLBACK_INCOMING_BODY);
}

static void s_error_tester_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    struct error_from_callback_tester *error_tester = user_data;
    error_tester->callback_counts[REQUEST_CALLBACK_COMPLETE]++;
    error_tester->on_complete_error_code = error_code;
}

static int s_test_error_from_callback(struct aws_allocator *allocator, void *ctx, enum request_callback error_at) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    /* send request */
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct error_from_callback_tester error_tester = {
        .error_at = error_at,
        .status =
            {
                .is_valid = true,
                .is_end_of_stream = false,
            },
    };
    error_tester.base.vtable = &s_error_from_outgoing_body_vtable;
    aws_ref_count_init(&error_tester.base.ref_count, &error_tester, s_error_from_outgoing_body_destroy);

    aws_http_message_set_body_stream(request, &error_tester.base);

    struct aws_http_make_request_options opt = {
        .self_size = sizeof(opt),
        .request = request,
        .on_response_headers = s_error_from_incoming_headers,
        .on_response_header_block_done = s_error_from_incoming_headers_done,
        .on_response_body = s_error_from_incoming_body,
        .on_complete = s_error_tester_on_stream_complete,
        .user_data = &error_tester,
    };
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    ASSERT_SUCCESS(aws_http_stream_activate(stream));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* Ensure the request can be destroyed after request is sent */
    aws_http_message_release(opt.request);

    /* fake peer sends response headers */
    struct aws_http_header response_headers_src[] = {
        DEFINE_HEADER(":status", "200"),
        DEFINE_HEADER("date", "Fri, 01 Mar 2019 17:18:55 GMT"),
    };

    struct aws_http_headers *response_headers = aws_http_headers_new(allocator);
    aws_http_headers_add_array(response_headers, response_headers_src, AWS_ARRAY_SIZE(response_headers_src));
    uint32_t stream_id = aws_http_stream_get_id(stream);
    struct aws_h2_frame *response_frame =
        aws_h2_frame_new_headers(allocator, stream_id, response_headers, false /*end_stream*/, 0, NULL);
    ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, response_frame));

    struct aws_byte_buf response_body_bufs;
    size_t body_length = 5;

    /* fake peer sends a DATA frame larger than the window size we have */
    ASSERT_SUCCESS(aws_byte_buf_init(&response_body_bufs, allocator, body_length));
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&response_body_bufs, (uint8_t)'a', body_length));
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&response_body_bufs);
    ASSERT_SUCCESS(h2_fake_peer_send_data_frame(&s_tester.peer, stream_id, body_cursor, true /*end_stream*/));

    /* validate that stream completed with error */
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    /* check that callbacks were invoked before error_at, but not after */
    for (int i = 0; i < REQUEST_CALLBACK_COMPLETE; ++i) {
        if (i <= error_at) {
            ASSERT_TRUE(error_tester.callback_counts[i] > 0);
        } else {
            ASSERT_INT_EQUALS(0, error_tester.callback_counts[i]);
        }
    }

    /* validate the RST_STREAM sent and connection is still open */
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    struct h2_decoded_frame *rst_stream_frame =
        h2_decode_tester_find_frame(&s_tester.peer.decode, AWS_H2_FRAME_T_RST_STREAM, 0, NULL);
    ASSERT_NOT_NULL(rst_stream_frame);
    ASSERT_UINT_EQUALS(AWS_HTTP2_ERR_INTERNAL_ERROR, rst_stream_frame->error_code);
    ASSERT_TRUE(aws_http_connection_is_open(s_tester.connection));

    /* the on_complete callback should always fire though, and should receive the proper error_code */
    ASSERT_INT_EQUALS(1, error_tester.callback_counts[REQUEST_CALLBACK_COMPLETE]);
    ASSERT_INT_EQUALS(ERROR_FROM_CALLBACK_ERROR_CODE, error_tester.on_complete_error_code);

    aws_http_headers_release(response_headers);
    aws_byte_buf_clean_up(&response_body_bufs);
    aws_http_stream_release(stream);
    return s_tester_clean_up();
}

TEST_CASE(h2_client_error_from_outgoing_body_callback_reset_stream) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, ctx, REQUEST_CALLBACK_OUTGOING_BODY));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_client_error_from_incoming_headers_callback_reset_stream) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, ctx, REQUEST_CALLBACK_INCOMING_HEADERS));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_client_error_from_incoming_headers_done_callback_reset_stream) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, ctx, REQUEST_CALLBACK_INCOMING_HEADERS_DONE));
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_client_error_from_incoming_body_callback_reset_stream) {
    (void)ctx;
    ASSERT_SUCCESS(s_test_error_from_callback(allocator, ctx, REQUEST_CALLBACK_INCOMING_BODY));
    return AWS_OP_SUCCESS;
}

struct h2_client_manual_data_write_ctx {
    struct aws_allocator *allocator;
    struct aws_byte_buf data;
    int complete_error_code;
};

static struct aws_input_stream *s_h2_client_manual_data_write_generate_data(
    struct h2_client_manual_data_write_ctx *ctx) {
    struct aws_byte_cursor data = aws_byte_cursor_from_buf(&ctx->data);
    data.len = aws_max_size(rand() % ctx->data.capacity, 1);
    return aws_input_stream_new_from_cursor(ctx->allocator, &data);
}

TEST_CASE(h2_client_manual_data_write) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    size_t frame_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .http2_use_manual_data_writes = true,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);

    aws_http_stream_activate(stream);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    uint32_t stream_id = aws_http_stream_get_id(stream);

    struct aws_byte_buf payload;
    aws_byte_buf_init(&payload, allocator, 1024);

    struct h2_client_manual_data_write_ctx test_ctx = {
        .allocator = allocator,
        .data = payload,
    };
    size_t total_length = 0;

    /* Simulate writes coming in over time */
    for (int idx = 0; idx < 1000; ++idx) {
        struct aws_input_stream *data_stream = s_h2_client_manual_data_write_generate_data(&test_ctx);
        int64_t stream_length = 0;
        ASSERT_SUCCESS(aws_input_stream_get_length(data_stream, &stream_length));
        total_length += (size_t)stream_length;
        struct aws_http2_stream_write_data_options write = {
            .data = data_stream,
            .on_complete = NULL,
            .user_data = NULL,
        };
        ASSERT_SUCCESS(aws_http2_stream_write_data(stream, &write));
        /* fake peer sends WINDOW_UPDATE */
        struct aws_h2_frame *peer_frame = aws_h2_frame_new_window_update(allocator, stream_id, (uint32_t)stream_length);
        ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
        /* Connection level window update */
        peer_frame = aws_h2_frame_new_window_update(allocator, 0, (uint32_t)stream_length);
        ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
        if (idx % 10 == 0) {
            testing_channel_drain_queued_tasks(&s_tester.testing_channel);
            ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
        }
        aws_input_stream_release(data_stream);
    }
    struct aws_http2_stream_write_data_options last_write = {.end_stream = true};

    ASSERT_SUCCESS(aws_http2_stream_write_data(stream, &last_write));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    size_t frame_count2 = h2_decode_tester_frame_count(&s_tester.peer.decode);
    /* Peer should received header frame without end_stream and mutiple data frames and combined payload length should
     * be the same as total length sent. */
    struct h2_decoded_frame *header_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frame_count);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_HEADERS, header_frame->type);
    ASSERT_FALSE(header_frame->end_stream);
    size_t received_length = 0;
    for (size_t i = frame_count + 1; i < frame_count2; i++) {
        struct h2_decoded_frame *data_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, i);
        ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_DATA, data_frame->type);
        received_length += data_frame->data_payload_len;
        if (i == frame_count2 - 1) {
            ASSERT_TRUE(data_frame->end_stream);
        } else {
            ASSERT_FALSE(data_frame->end_stream);
        }
    }
    ASSERT_UINT_EQUALS(received_length, total_length);

    aws_http_message_release(request);
    aws_http_stream_release(stream);

    /* close the connection */
    aws_http_connection_close(s_tester.connection);

    aws_byte_buf_clean_up(&test_ctx.data);

    /* clean up */
    return s_tester_clean_up();
}

TEST_CASE(h2_client_manual_data_write_not_enabled) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .http2_use_manual_data_writes = false,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);

    aws_http_stream_activate(stream);

    struct aws_byte_buf payload;
    aws_byte_buf_init(&payload, allocator, 1024);

    struct h2_client_manual_data_write_ctx test_ctx = {
        .allocator = allocator,
        .data = payload,
    };

    /* Try writing the data */
    struct aws_input_stream *data_stream = s_h2_client_manual_data_write_generate_data(&test_ctx);
    int64_t stream_length = 0;
    ASSERT_SUCCESS(aws_input_stream_get_length(data_stream, &stream_length));
    struct aws_http2_stream_write_data_options write_options = {
        .data = data_stream,
    };
    ASSERT_ERROR(AWS_ERROR_HTTP_MANUAL_WRITE_NOT_ENABLED, aws_http2_stream_write_data(stream, &write_options));
    aws_input_stream_release(data_stream);
    aws_http_message_release(request);
    aws_http_stream_release(stream);

    /* close the connection */
    aws_http_connection_close(s_tester.connection);

    aws_byte_buf_clean_up(&test_ctx.data);

    /* clean up */
    return s_tester_clean_up();
}

TEST_CASE(h2_client_manual_data_write_with_body) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    size_t frame_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .http2_use_manual_data_writes = true,
    };
    size_t total_length = 0;

    /* set request body */
    const char *body_src = "hello";
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str(body_src);
    struct aws_input_stream *request_body = aws_input_stream_new_from_cursor(allocator, &body_cursor);
    aws_http_message_set_body_stream(request, request_body);
    int64_t body_length = 0;
    ASSERT_SUCCESS(aws_input_stream_get_length(request_body, &body_length));
    total_length += (size_t)body_length;
    aws_input_stream_release(request_body);

    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);

    aws_http_stream_activate(stream);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    uint32_t stream_id = aws_http_stream_get_id(stream);

    struct aws_byte_buf payload;
    aws_byte_buf_init(&payload, allocator, 1024);

    struct h2_client_manual_data_write_ctx test_ctx = {
        .allocator = allocator,
        .data = payload,
    };

    /* Simulate writes coming in over time */
    for (int idx = 0; idx < 1000; ++idx) {
        struct aws_input_stream *data_stream = s_h2_client_manual_data_write_generate_data(&test_ctx);
        int64_t stream_length = 0;
        ASSERT_SUCCESS(aws_input_stream_get_length(data_stream, &stream_length));
        total_length += (size_t)stream_length;
        struct aws_http2_stream_write_data_options write = {
            .data = data_stream,
            .on_complete = NULL,
            .user_data = NULL,
        };
        ASSERT_SUCCESS(aws_http2_stream_write_data(stream, &write));
        /* fake peer sends WINDOW_UPDATE */
        struct aws_h2_frame *peer_frame = aws_h2_frame_new_window_update(allocator, stream_id, (uint32_t)stream_length);
        ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
        /* Connection level window update */
        peer_frame = aws_h2_frame_new_window_update(allocator, 0, (uint32_t)stream_length);
        ASSERT_SUCCESS(h2_fake_peer_send_frame(&s_tester.peer, peer_frame));
        if (idx % 10 == 0) {
            testing_channel_drain_queued_tasks(&s_tester.testing_channel);
            ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
        }
        aws_input_stream_release(data_stream);
    }
    struct aws_http2_stream_write_data_options last_write = {.end_stream = true};

    ASSERT_SUCCESS(aws_http2_stream_write_data(stream, &last_write));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    size_t frame_count2 = h2_decode_tester_frame_count(&s_tester.peer.decode);
    /* Peer should received header frame without end_stream and mutiple data frames and combined payload length should
     * be the same as total length sent. */
    struct h2_decoded_frame *header_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frame_count);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_HEADERS, header_frame->type);
    ASSERT_FALSE(header_frame->end_stream);
    size_t received_length = 0;
    for (size_t i = frame_count + 1; i < frame_count2; i++) {
        struct h2_decoded_frame *data_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, i);
        ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_DATA, data_frame->type);
        received_length += data_frame->data_payload_len;
        if (i == frame_count2 - 1) {
            ASSERT_TRUE(data_frame->end_stream);
        } else {
            ASSERT_FALSE(data_frame->end_stream);
        }
    }
    ASSERT_UINT_EQUALS(received_length, total_length);

    aws_http_message_release(request);
    aws_http_stream_release(stream);

    /* close the connection */
    aws_http_connection_close(s_tester.connection);

    aws_byte_buf_clean_up(&test_ctx.data);

    /* clean up */
    return s_tester_clean_up();
}

TEST_CASE(h2_client_manual_data_write_no_data) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    size_t frame_count = h2_decode_tester_frame_count(&s_tester.peer.decode);

    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .http2_use_manual_data_writes = true,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);

    aws_http_stream_activate(stream);

    struct aws_http2_stream_write_data_options last_write = {.end_stream = true};
    ASSERT_SUCCESS(aws_http2_stream_write_data(stream, &last_write));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));
    size_t frame_count_2 = h2_decode_tester_frame_count(&s_tester.peer.decode);
    /* Peer should received header frame without end_stream and empty data frame with end_stream */
    ASSERT_UINT_EQUALS(frame_count + 2, frame_count_2);
    struct h2_decoded_frame *header_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frame_count);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_HEADERS, header_frame->type);
    ASSERT_FALSE(header_frame->end_stream);
    struct h2_decoded_frame *empty_data_frame = h2_decode_tester_get_frame(&s_tester.peer.decode, frame_count + 1);
    ASSERT_UINT_EQUALS(AWS_H2_FRAME_T_DATA, empty_data_frame->type);
    ASSERT_UINT_EQUALS(0, empty_data_frame->data_payload_len);
    ASSERT_TRUE(empty_data_frame->end_stream);
    aws_http_message_release(request);
    aws_http_stream_release(stream);

    /* close the connection */
    aws_http_connection_close(s_tester.connection);

    /* clean up */
    return s_tester_clean_up();
}

static void s_on_manual_data_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    struct h2_client_manual_data_write_ctx *test_ctx = (struct h2_client_manual_data_write_ctx *)user_data;
    test_ctx->complete_error_code = error_code;
}

/* Close the connection before finishes writing data */
TEST_CASE(h2_client_manual_data_write_connection_close) {

    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    /* get connection preface and acks out of the way */
    ASSERT_SUCCESS(h2_fake_peer_send_connection_preface_default_settings(&s_tester.peer));
    ASSERT_SUCCESS(h2_fake_peer_decode_messages_from_testing_channel(&s_tester.peer));

    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/"),
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct aws_byte_buf payload;
    aws_byte_buf_init(&payload, allocator, 1024);

    struct h2_client_manual_data_write_ctx test_ctx = {
        .allocator = allocator,
        .data = payload,
    };

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .http2_use_manual_data_writes = true,
        .on_complete = s_on_manual_data_stream_complete,
        .user_data = &test_ctx,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);

    struct aws_input_stream *data_stream = s_h2_client_manual_data_write_generate_data(&test_ctx);
    struct aws_http2_stream_write_data_options write = {
        .data = data_stream,
        .on_complete = NULL,
        .user_data = NULL,
    };
    /* Cannot write before activate the stream */
    ASSERT_FAILS(aws_http2_stream_write_data(stream, &write));
    aws_http_stream_activate(stream);
    ASSERT_SUCCESS(aws_http2_stream_write_data(stream, &write));

    /* close connection */
    aws_http_connection_close(s_tester.connection);

    ASSERT_SUCCESS(aws_http2_stream_write_data(stream, &write));

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    /* Cannot write after stream closed */
    ASSERT_FAILS(aws_http2_stream_write_data(stream, &write));

    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_CONNECTION_CLOSED, test_ctx.complete_error_code);

    aws_http_message_release(request);
    aws_http_stream_release(stream);

    /* clean up */
    aws_byte_buf_clean_up(&test_ctx.data);
    aws_input_stream_release(data_stream);
    return s_tester_clean_up();
}
