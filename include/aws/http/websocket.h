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

struct aws_websocket;
struct aws_websocket_incoming_frame;

/* RFC-6455 Section 5.2 - Opcode */
enum aws_websocket_opcode {
    AWS_WEBSOCKET_OPCODE_CONTINUATION = 0x0,
    AWS_WEBSOCKET_OPCODE_TEXT = 0x1,
    AWS_WEBSOCKET_OPCODE_BINARY = 0x2,
    AWS_WEBSOCKET_OPCODE_CLOSE = 0x8,
    AWS_WEBSOCKET_OPCODE_PING = 0x9,
    AWS_WEBSOCKET_OPCODE_PONG = 0xA,
};

#define AWS_WEBSOCKET_MAX_PAYLOAD_LENGTH 0x7FFFFFFFFFFFFFFF

typedef void(aws_websocket_on_connection_setup_fn)(
    struct aws_websocket *websocket,
    int error_code,
    /* TODO: how to pass back misc response data like headers */
    void *user_data);

typedef void(aws_websocket_on_connection_shutdown_fn)(struct aws_websocket *websocket, int error_code, void *user_data);

typedef void(aws_websocket_on_incoming_frame_begin)(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    void *user_data);

typedef void(aws_websocket_on_incoming_frame_payload)(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    size_t *out_window_update_size,
    void *user_data);

typedef void(aws_websocket_on_incoming_frame_complete)(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    int error_code,
    void *user_data);

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
    aws_websocket_on_incoming_frame_begin *on_incoming_frame_begin;
    aws_websocket_on_incoming_frame_payload *on_incoming_frame_payload;
    aws_websocket_on_incoming_frame_complete *on_incoming_frame_complete;
};

enum aws_websocket_outgoing_payload_state {
    AWS_WEBSOCKET_OUTGOING_PAYLOAD_IN_PROGRESS,
    AWS_WEBSOCKET_OUTGOING_PAYLOAD_DONE,
};

typedef enum aws_websocket_outgoing_payload_state(aws_websocket_stream_outgoing_payload_fn)(
    struct aws_websocket *websocket,
    struct aws_byte_buf *out_buf,
    void *user_data);

typedef void(
    aws_websocket_outgoing_frame_complete_fn)(struct aws_websocket *websocket, int error_code, void *user_data);

struct aws_websocket_outgoing_frame_options {
    uint64_t payload_length;

    void *user_data;
    aws_websocket_stream_outgoing_payload_fn *stream_outgoing_payload;
    aws_websocket_outgoing_frame_complete_fn *on_complete;

    uint8_t opcode;
    bool fin;
    bool rsv[3];

    /**
     * If true, frame will be sent before those with normal priority.
     * Useful for opcodes like PING and PONG where low latency is important.
     * This feature may only be used with "control" opcodes, not "data" opcodes like BINARY and TEXT.
     */
    bool high_priority;
};

struct aws_websocket_incoming_frame {
    uint64_t payload_length;
    uint8_t opcode;
    bool fin;
    bool rsv[3];
};

/**
 * Return true if opcode is for a data frame, false if opcode if for a control frame.
 */
AWS_STATIC_IMPL
bool aws_websocket_is_data_frame(uint8_t opcode) {
    return !(opcode & 0x08); /* RFC-6455 Section 5.6: Most significant bit of (4 bit) data frame opcode is 0 */
}

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
int aws_websocket_client_connect(const struct aws_websocket_client_connection_options *options);

/* TODO: Require all users to manually grab a hold? Http doesn't work like that... */

AWS_HTTP_API
void aws_websocket_acquire_hold(struct aws_websocket *websocket);

AWS_HTTP_API
void aws_websocket_release_hold(struct aws_websocket *websocket);

AWS_HTTP_API
void aws_websocket_close(struct aws_websocket *websocket, int error_code);

AWS_HTTP_API
int aws_websocket_send_frame(
    struct aws_websocket *websocket,
    const struct aws_websocket_outgoing_frame_options *options);

AWS_HTTP_API
int aws_websocket_install_channel_handler_to_right(
    struct aws_websocket *websocket,
    struct aws_channel_handler *right_handler);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_WEBSOCKET_H */
