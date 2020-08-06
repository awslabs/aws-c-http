#ifndef AWS_HTTP_H2_TEST_HELPER_H
#define AWS_HTTP_H2_TEST_HELPER_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/http/private/h2_frames.h>
#include <aws/http/request_response.h>
#include <aws/testing/aws_test_harness.h>

struct aws_input_stream;

#define ASSERT_H2ERR_SUCCESS(condition, ...)                                                                           \
    do {                                                                                                               \
        struct aws_h2err assert_rv = (condition);                                                                      \
        if (!aws_h2err_success(assert_rv)) {                                                                           \
            if (!PRINT_FAIL_INTERNAL0(__VA_ARGS__)) {                                                                  \
                PRINT_FAIL_INTERNAL0(                                                                                  \
                    "Expected success at %s; got aws_h2err{%s, %s}\n",                                                 \
                    #condition,                                                                                        \
                    aws_http2_error_code_to_str(assert_rv.h2_code),                                                    \
                    aws_error_name(assert_rv.aws_code));                                                               \
            }                                                                                                          \
            POSTFAIL_INTERNAL();                                                                                       \
        }                                                                                                              \
    } while (0)

#define ASSERT_H2ERR_FAILS(condition, ...)                                                                             \
    do {                                                                                                               \
        struct aws_h2err assert_rv = (condition);                                                                      \
        if (!aws_h2err_failed(assert_rv)) {                                                                            \
            if (!PRINT_FAIL_INTERNAL0(__VA_ARGS__)) {                                                                  \
                PRINT_FAIL_INTERNAL0("Expected failure at %s; got AWS_H2ERR_SUCCESS\n", #condition);                   \
            }                                                                                                          \
            POSTFAIL_INTERNAL();                                                                                       \
        }                                                                                                              \
    } while (0)

#define ASSERT_H2ERR_ERROR(h2_error, condition, ...)                                                                   \
    do {                                                                                                               \
        struct aws_h2err assert_rv = (condition);                                                                      \
        if (!aws_h2err_failed(assert_rv)) {                                                                            \
            if (!PRINT_FAIL_INTERNAL0(__VA_ARGS__)) {                                                                  \
                PRINT_FAIL_INTERNAL0(                                                                                  \
                    "Expected %s failure at %s; got AWS_H2ERR_SUCCESS\n",                                              \
                    aws_http2_error_code_to_str(h2_error),                                                             \
                    #condition);                                                                                       \
            }                                                                                                          \
            POSTFAIL_INTERNAL();                                                                                       \
        }                                                                                                              \
        if (assert_rv.h2_code != h2_error) {                                                                           \
            PRINT_FAIL_INTERNAL0(                                                                                      \
                "Expected %s failure at %s; got aws_h2err{%s, %s}\n",                                                  \
                aws_http2_error_code_to_str(h2_error),                                                                 \
                #condition,                                                                                            \
                aws_http2_error_code_to_str(assert_rv.h2_code),                                                        \
                aws_error_name(assert_rv.aws_code));                                                                   \
        }                                                                                                              \
    } while (0)

/**
 * Information gathered about a given frame from decoder callbacks.
 * These aren't 1:1 with literal H2 frames:
 * - The decoder hides the existence of CONTINUATION frames,
 *   their data continues the preceding HEADERS or PUSH_PROMISE frame.
 *
 * - A DATA frame could appear as N on_data callbacks.
 *
 * - The on_end_stream callback fires after all other callbacks for that frame,
 *   so we count it as part of the preceding "finished" frame.
 */
struct h2_decoded_frame {
    /* If true, we expect no further callbacks regarding this frame */
    bool finished;

    enum aws_h2_frame_type type; /* All frame types have this */
    uint32_t stream_id;          /* All frame types have this */

    /*
     * Everything else is only found in certain frame types
     */

    bool end_stream; /* HEADERS and DATA might have this */
    bool ack;        /* PING and SETTINGS might have this */

    uint32_t error_code;                                /* RST_STREAM and GOAWAY have this */
    uint32_t promised_stream_id;                        /* PUSH_PROMISE has this */
    uint32_t goaway_last_stream_id;                     /* GOAWAY has this */
    uint32_t goaway_debug_data_remaining;               /* GOAWAY has this*/
    uint8_t ping_opaque_data[AWS_HTTP2_PING_DATA_SIZE]; /* PING has this */
    uint32_t window_size_increment;                     /* WINDOW_UPDATE has this */

    struct aws_http_headers *headers;             /* HEADERS and PUSH_PROMISE have this */
    bool headers_malformed;                       /* HEADERS and PUSH_PROMISE have this */
    enum aws_http_header_block header_block_type; /* HEADERS have this */
    struct aws_array_list settings;               /* contains aws_http2_setting, SETTINGS has this */
    struct aws_byte_buf data;                     /* DATA has this */
    uint32_t data_payload_len;                    /* DATA has this */
    bool data_end_stream;                         /* DATA has this */
};

/**
 * Check that:
 * - frame finished (ex: if HEADERS frame, then on_headers_end() fired)
 * - frame was in fact using the expected type and stream_id.
 */
int h2_decoded_frame_check_finished(
    const struct h2_decoded_frame *frame,
    enum aws_h2_frame_type expected_type,
    uint32_t expected_stream_id);

/******************************************************************************/

/**
 * Translates decoder callbacks into an array-list of h2_decoded_frames.
 */
struct h2_decode_tester {
    struct aws_allocator *alloc;
    struct aws_h2_decoder *decoder;
    struct aws_array_list frames; /* contains h2_decoded_frame */
};

struct h2_decode_tester_options {
    struct aws_allocator *alloc;
    bool is_server;
    bool skip_connection_preface;
};

int h2_decode_tester_init(struct h2_decode_tester *decode_tester, const struct h2_decode_tester_options *options);
void h2_decode_tester_clean_up(struct h2_decode_tester *decode_tester);

size_t h2_decode_tester_frame_count(const struct h2_decode_tester *decode_tester);
struct h2_decoded_frame *h2_decode_tester_get_frame(const struct h2_decode_tester *decode_tester, size_t i);
struct h2_decoded_frame *h2_decode_tester_latest_frame(const struct h2_decode_tester *decode_tester);

/**
 * Search for frame of a given type, starting at specified index.
 * To search for the next frame, pass search_start_idx = prev_idx + 1
 */
struct h2_decoded_frame *h2_decode_tester_find_frame(
    const struct h2_decode_tester *decode_tester,
    enum aws_h2_frame_type type,
    size_t search_start_idx,
    size_t *out_idx);

/**
 * Search for frame of a given stream-id, starting at specified index.
 * To search for the next frame, pass search_start_idx = prev_idx + 1
 */
struct h2_decoded_frame *h2_decode_tester_find_stream_frame_any_type(
    const struct h2_decode_tester *decode_tester,
    uint32_t stream_id,
    size_t search_start_idx,
    size_t *out_idx);

/**
 * Search for frame of a given type and stream-id, starting at specified index.
 * To search for the next frame, pass search_start_idx = prev_idx + 1
 */
struct h2_decoded_frame *h2_decode_tester_find_stream_frame(
    const struct h2_decode_tester *decode_tester,
    enum aws_h2_frame_type type,
    uint32_t stream_id,
    size_t search_start_idx,
    size_t *out_idx);

/**
 * Compare data (which may be split across N frames) against expected
 */
int h2_decode_tester_check_data_across_frames(
    const struct h2_decode_tester *decode_tester,
    uint32_t stream_id,
    struct aws_byte_cursor expected,
    bool expect_end_stream);

/**
 * Compare data (which may be split across N frames) against expected
 */
int h2_decode_tester_check_data_str_across_frames(
    const struct h2_decode_tester *decode_tester,
    uint32_t stream_id,
    const char *expected,
    bool expect_end_stream);

/******************************************************************************/

/**
 * Fake HTTP/2 peer.
 * Can decode H2 frames that are are written to the testing channel.
 * Can encode H2 frames and push it into the channel in the read direction.
 */
struct h2_fake_peer {
    struct aws_allocator *alloc;
    struct testing_channel *testing_channel;

    struct aws_h2_frame_encoder encoder;
    struct h2_decode_tester decode;
    bool is_server;
};

struct h2_fake_peer_options {
    struct aws_allocator *alloc;
    struct testing_channel *testing_channel;
    bool is_server;
};

int h2_fake_peer_init(struct h2_fake_peer *peer, const struct h2_fake_peer_options *options);
void h2_fake_peer_clean_up(struct h2_fake_peer *peer);

/**
 * Pop all written messages off the testing-channel and run them through the peer's decode-tester
 */
int h2_fake_peer_decode_messages_from_testing_channel(struct h2_fake_peer *peer);

/**
 * Encode frame and push it into the testing-channel in the read-direction.
 * Takes ownership of frame and destroys after sending.
 */
int h2_fake_peer_send_frame(struct h2_fake_peer *peer, struct aws_h2_frame *frame);

/**
 * Encode the entire byte cursor into a single DATA frame.
 * Fails if the cursor is too large for this to work.
 */
int h2_fake_peer_send_data_frame(
    struct h2_fake_peer *peer,
    uint32_t stream_id,
    struct aws_byte_cursor data,
    bool end_stream);

/**
 * Encode the entire string into a single DATA frame.
 * Fails if the string is too large for this to work.
 */
int h2_fake_peer_send_data_frame_str(struct h2_fake_peer *peer, uint32_t stream_id, const char *data, bool end_stream);

/**
 * Peer sends the connection preface with specified settings.
 * Takes ownership of frame and destroys after sending
 */
int h2_fake_peer_send_connection_preface(struct h2_fake_peer *peer, struct aws_h2_frame *settings);

/**
 * Peer sends the connection preface with default settings.
 */
int h2_fake_peer_send_connection_preface_default_settings(struct h2_fake_peer *peer);

/******************************************************************************/

/**
 * Create input stream that can do weird stuff in tests
 */
struct aws_input_stream *aws_input_stream_new_tester(struct aws_allocator *alloc, struct aws_byte_cursor cursor);

void aws_input_stream_tester_set_max_bytes_per_read(struct aws_input_stream *input_stream, size_t max_bytes);

void aws_input_stream_tester_set_reading_broken(struct aws_input_stream *input_stream, bool is_broken);

#endif /* AWS_HTTP_H2_TEST_HELPER_H */
