#ifndef AWS_HTTP_WEBSOCKET_H
#define AWS_HTTP_WEBSOCKET_H
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

#include <aws/http/http.h>

struct aws_channel_handler;
struct aws_http_header;

/**
 * A websocket connection.
 */
struct aws_websocket;

/**
 * Opcode describing the type of a websocket frame.
 * RFC-6455 Section 5.2
 */
enum aws_websocket_opcode {
    AWS_WEBSOCKET_OPCODE_CONTINUATION = 0x0,
    AWS_WEBSOCKET_OPCODE_TEXT = 0x1,
    AWS_WEBSOCKET_OPCODE_BINARY = 0x2,
    AWS_WEBSOCKET_OPCODE_CLOSE = 0x8,
    AWS_WEBSOCKET_OPCODE_PING = 0x9,
    AWS_WEBSOCKET_OPCODE_PONG = 0xA,
};

#define AWS_WEBSOCKET_MAX_PAYLOAD_LENGTH 0x7FFFFFFFFFFFFFFF

/**
 * Called when websocket setup is complete.
 * If setup succeeds, error_code is zero and the websocket pointer is valid.
 * If setup failed, error_code will be non-zero and the pointer will be NULL.
 * Called exactly once on the websocket's event-loop thread.
 */
typedef void(aws_websocket_on_connection_setup_fn)(
    struct aws_websocket *websocket,
    int error_code,
    /* TODO: how to pass back misc response data like headers */
    void *user_data);

/**
 * Called when the websocket has finished shutting down.
 * Called once on the websocket's event-loop thread if setup succeeded.
 * If setup failed, this is never called.
 */
typedef void(aws_websocket_on_connection_shutdown_fn)(struct aws_websocket *websocket, int error_code, void *user_data);

/**
 * Data about an incoming frame.
 * See RFC-6455 Section 5.2.
 */
struct aws_websocket_incoming_frame {
    uint64_t payload_length;
    uint8_t opcode;
    bool fin;
    bool rsv[3];
};

/**
 * Called when a new frame arrives.
 * Invoked once per frame on the websocket's event-loop thread.
 * Each incoming-frame-begin call will eventually be followed by an incoming-frame-complete call,
 * before the next frame begins and before the websocket shuts down.
 */
typedef void(aws_websocket_on_incoming_frame_begin_fn)(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    void *user_data);

/**
 * Called repeatedly as payload data arrives.
 * Invoked 0 or more times on the websocket's event-loop thread.
 * Payload data will not be valid after this call, so copy if necessary.
 * The payload data is always unmasked at this point.
 *
 * `out_window_update_size` is how much to increment the flow-control window once this data is processed.
 * By default, it is the size of the data which has just come in.
 * Leaving this value untouched will increment the window back to its original size.
 * Setting this value to 0 will prevent the update and let the window shrink.
 * The window can be manually updated via aws_websocket_update_window()
 */
typedef void(aws_websocket_on_incoming_frame_payload_fn)(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    size_t *out_window_update_size,
    void *user_data);

/**
 * Called when done processing an incoming frame.
 * If error_code is non-zero, an error occurred and the payload may not have been completely received.
 * Invoked once per frame on the websocket's event-loop thread.
 */
typedef void(aws_websocket_on_incoming_frame_complete_fn)(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    int error_code,
    void *user_data);

/* WIP */
struct aws_websocket_client_connection_options {
    struct aws_allocator *allocator;

    struct aws_client_bootstrap *bootstrap;
    struct aws_byte_cursor host_name;
    uint16_t port;
    struct aws_socket_options *socket_options;
    struct aws_tls_connection_options *tls_options;
    size_t initial_window_size;

    /* TODO: How to take handshake request params. related, could take URI instead of host_name:port. */

    void *user_data;
    aws_websocket_on_connection_setup_fn *on_connection_setup;
    aws_websocket_on_connection_shutdown_fn *on_connection_shutdown;
    aws_websocket_on_incoming_frame_begin_fn *on_incoming_frame_begin;
    aws_websocket_on_incoming_frame_payload_fn *on_incoming_frame_payload;
    aws_websocket_on_incoming_frame_complete_fn *on_incoming_frame_complete;
};

enum aws_websocket_outgoing_payload_state {
    AWS_WEBSOCKET_OUTGOING_PAYLOAD_IN_PROGRESS,
    AWS_WEBSOCKET_OUTGOING_PAYLOAD_DONE,
};

/**
 * Called repeatedly as the websocket's payload is streamed out.
 * The user should write payload data to out_buf and return an enum to indicate their progress.
 * If the data is not yet available, your may return return IN_PROGRESS without writing out any data.
 * The websocket will mask this data for you, if necessary.
 * Invoked repeatedly on the websocket's event-loop thread.
 */
typedef enum aws_websocket_outgoing_payload_state(aws_websocket_stream_outgoing_payload_fn)(
    struct aws_websocket *websocket,
    struct aws_byte_buf *out_buf,
    void *user_data);

/**
 * Called when a aws_websocket_send_frame() operation completes.
 * error_code will be non-zero if the operation was successful.
 * "Success" does not guarantee that the peer actually received or processed the frame.
 * Invoked exactly once per sent frame on the websocket's event-loop thread.
 */
typedef void(
    aws_websocket_outgoing_frame_complete_fn)(struct aws_websocket *websocket, int error_code, void *user_data);

/**
 * Options for sending a websocket frame.
 * This structure is copied immediately by aws_websocket_send().
 * For descriptions of sopcode, fin, rsv, and payload_length see in RFC-6455 Section 5.2.
 */
struct aws_websocket_send_frame_options {
    /**
     * Size of payload to be sent via `stream_outgoing_payload` callback.
     */
    uint64_t payload_length;

    /**
     * User data passed to callbacks.
     */
    void *user_data;

    /**
     * Callback for sending payload data.
     * See `aws_websocket_stream_outgoing_payload_fn`.
     * Required if `payload_length` is non-zero.
     */
    aws_websocket_stream_outgoing_payload_fn *stream_outgoing_payload;

    /**
     * Callback for completion of send operation.
     * See `aws_websocket_outgoing_frame_complete_fn`.
     * Optional.
     */
    aws_websocket_outgoing_frame_complete_fn *on_complete;

    /**
     * Frame type.
     * `aws_websocket_opcode` enum provides standard values.
     */
    uint8_t opcode;

    /**
     * Indicates that this is the final fragment in a message. The first fragment MAY also be the final fragment.
     */
    bool fin;

    /**
     * If true, frame will be sent before those with normal priority.
     * Useful for opcodes like PING and PONG where low latency is important.
     * This feature may only be used with "control" opcodes, not "data" opcodes like BINARY and TEXT.
     */
    bool high_priority;

    /**
     * MUST be 0 unless an extension is negotiated that defines meanings for non-zero values.
     */
    bool rsv[3];
};

AWS_EXTERN_C_BEGIN

/**
 * Return true if opcode is for a data frame, false if opcode if for a control frame.
 */
AWS_HTTP_API
bool aws_websocket_is_data_frame(uint8_t opcode);

/* WIP */
AWS_HTTP_API
int aws_websocket_client_connect(const struct aws_websocket_client_connection_options *options);

/* TODO: Require all users to manually grab a hold? Http doesn't work like that... */
/* TODO: should the last release trigger a shutdown automatically? http does that, channel doesn't. */

/**
 * Ensure that the websocket cannot be destroyed until aws_websocket_release_hold() is called.
 * The websocket might still shutdown/close, but the public API will not crash when this websocket pointer is used.
 * If acquire_hold() is never called, the websocket is destroyed when its channel its channel is destroyed.
 */
AWS_HTTP_API
void aws_websocket_acquire_hold(struct aws_websocket *websocket);

/**
 * See aws_websocket_acquire_hold().
 * The websocket will shut itself down when the last hold is released.
 */
AWS_HTTP_API
void aws_websocket_release_hold(struct aws_websocket *websocket);

/**
 * Close the websocket connection.
 * It is safe to call this, even if the connection is already closed or closing.
 * The websocket will attempt to send a CLOSE frame during normal shutdown.
 */
AWS_HTTP_API
void aws_websocket_close(struct aws_websocket *websocket, int error_code);

/**
 * Send a websocket frame.
 * The `options` struct is copied.
 * A callback will be invoked when the operation completes.
 */
AWS_HTTP_API
int aws_websocket_send_frame(struct aws_websocket *websocket, const struct aws_websocket_send_frame_options *options);

/* WIP */
AWS_HTTP_API
int aws_websocket_install_channel_handler_to_right(
    struct aws_websocket *websocket,
    struct aws_channel_handler *right_handler);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_WEBSOCKET_H */
