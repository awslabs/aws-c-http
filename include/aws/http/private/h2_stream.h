#ifndef AWS_HTTP_H2_STREAM_H
#define AWS_HTTP_H2_STREAM_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/h2_frames.h>
#include <aws/http/private/request_response_impl.h>

#include <aws/common/mutex.h>
#include <aws/io/channel.h>

#include <inttypes.h>

#define AWS_H2_STREAM_LOGF(level, stream, text, ...)                                                                   \
    AWS_LOGF_##level(                                                                                                  \
        AWS_LS_HTTP_STREAM,                                                                                            \
        "id=%" PRIu32 " connection=%p state=%s: " text,                                                                \
        (stream)->base.id,                                                                                             \
        (void *)(stream)->base.owning_connection,                                                                      \
        aws_h2_stream_state_to_str((stream)->thread_data.state),                                                       \
        __VA_ARGS__)
#define AWS_H2_STREAM_LOG(level, stream, text) AWS_H2_STREAM_LOGF(level, (stream), "%s", (text))

enum aws_h2_stream_state {
    /* Initial state, before anything sent or received. */
    AWS_H2_STREAM_STATE_IDLE,
    /* (server-only) stream-id was reserved via PUSH_PROMISE on another stream,
     * but HEADERS for this stream have not been sent yet */
    AWS_H2_STREAM_STATE_RESERVED_LOCAL,
    /* (client-only) stream-id was reserved via PUSH_PROMISE on another stream,
     * but HEADERS for this stream have not been received yet */
    AWS_H2_STREAM_STATE_RESERVED_REMOTE,
    /* Neither side is done sending their message. */
    AWS_H2_STREAM_STATE_OPEN,
    /* This side is done sending message (END_STREAM), but peer is not done. */
    AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL,
    /* Peer is done sending message (END_STREAM), but this side is not done */
    AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE,
    /* Both sides done sending message (END_STREAM),
     * or either side has sent RST_STREAM */
    AWS_H2_STREAM_STATE_CLOSED,

    AWS_H2_STREAM_STATE_COUNT,
};

/* simplified stream state for API implementation */
enum aws_h2_stream_api_state {
    AWS_H2_STREAM_API_STATE_INIT,
    AWS_H2_STREAM_API_STATE_ACTIVE,
    AWS_H2_STREAM_API_STATE_COMPLETE,
};

struct aws_h2_stream {
    struct aws_http_stream base;

    struct aws_linked_list_node node;
    struct aws_channel_task cross_thread_work_task;

    /* Only the event-loop thread may touch this data */
    struct {
        enum aws_h2_stream_state state;
        int32_t window_size_peer;
        /* The local window size.
         * We allow this value exceed the max window size (int64 can hold much more than 0x7FFFFFFF),
         * We leave it up to the remote peer to detect whether the max window size has been exceeded. */
        int64_t window_size_self;
        struct aws_http_message *outgoing_message;
        bool received_main_headers;
    } thread_data;

    /* Any thread may touch this data, but the lock must be held (unless it's an atomic) */
    struct {
        struct aws_mutex lock;

        bool is_cross_thread_work_task_scheduled;

        /* The window_update value for `thread_data.window_size_self` that haven't applied yet */
        size_t window_update_size;

        /* The aws_http2_error_code user wanted to send to remote peer via rst_stream. */
        uint32_t user_reset_error_code;

        bool reset_called;

        /* Simplified stream state. */
        enum aws_h2_stream_api_state api_state;
    } synced_data;

    /* Store the sent reset HTTP/2 error code, set to -1, if none has sent so far */
    int64_t sent_reset_error_code;

    /* Store the received reset HTTP/2 error code, set to -1, if none has received so far */
    int64_t received_reset_error_code;
};

const char *aws_h2_stream_state_to_str(enum aws_h2_stream_state state);

struct aws_h2_stream *aws_h2_stream_new_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);

enum aws_h2_stream_state aws_h2_stream_get_state(const struct aws_h2_stream *stream);

struct aws_h2err aws_h2_stream_window_size_change(struct aws_h2_stream *stream, int32_t size_changed, bool self);

/* Connection is ready to send frames from stream now */
int aws_h2_stream_on_activated(struct aws_h2_stream *stream, bool *out_has_outgoing_data);

/* Connection is ready to send data from stream now.
 * Stream may complete itself during this call.
 * data_encode_status:
 * AWS_H2_DATA_ENCODE_COMPLETE: Finished encoding data for the stream
 * AWS_H2_DATA_ENCODE_ONGOING: Stream has more data to send.
 * AWS_H2_DATA_ENCODE_ONGOING_BODY_STALLED: Stream has more data to send, but it's not ready right now
 * AWS_H2_DATA_ENCODE_ONGOING_WINDOW_STALLED: Stream has more data to send but its window size is too small, and stream
 * will be moved to stalled_window_stream_list */
int aws_h2_stream_encode_data_frame(
    struct aws_h2_stream *stream,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    int *data_encode_status);

struct aws_h2err aws_h2_stream_on_decoder_headers_begin(struct aws_h2_stream *stream);

struct aws_h2err aws_h2_stream_on_decoder_headers_i(
    struct aws_h2_stream *stream,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type);

struct aws_h2err aws_h2_stream_on_decoder_headers_end(
    struct aws_h2_stream *stream,
    bool malformed,
    enum aws_http_header_block block_type);

struct aws_h2err aws_h2_stream_on_decoder_push_promise(struct aws_h2_stream *stream, uint32_t promised_stream_id);
struct aws_h2err aws_h2_stream_on_decoder_data_begin(
    struct aws_h2_stream *stream,
    uint32_t payload_len,
    bool end_stream);
struct aws_h2err aws_h2_stream_on_decoder_data_i(struct aws_h2_stream *stream, struct aws_byte_cursor data);
struct aws_h2err aws_h2_stream_on_decoder_window_update(
    struct aws_h2_stream *stream,
    uint32_t window_size_increment,
    bool *window_resume);
struct aws_h2err aws_h2_stream_on_decoder_end_stream(struct aws_h2_stream *stream);
struct aws_h2err aws_h2_stream_on_decoder_rst_stream(struct aws_h2_stream *stream, uint32_t h2_error_code);

int aws_h2_stream_activate(struct aws_http_stream *stream);

#endif /* AWS_HTTP_H2_STREAM_H */
