#ifndef AWS_HTTP_WEBSOCKET_IMPL_H
#define AWS_HTTP_WEBSOCKET_IMPL_H

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

#include <aws/http/websocket.h>

/* RFC-6455 Section 5.2 Base Framing Protocol
 * Payload length:  7 bits, 7+16 bits, or 7+64 bits
 *
 * The length of the "Payload data", in bytes: if 0-125, that is the
 * payload length.  If 126, the following 2 bytes interpreted as a
 * 16-bit unsigned integer are the payload length.  If 127, the
 * following 8 bytes interpreted as a 64-bit unsigned integer (the
 * most significant bit MUST be 0) are the payload length.  Multibyte
 * length quantities are expressed in network byte order.  Note that
 * in all cases, the minimal number of bytes MUST be used to encode
 * the length, for example, the length of a 124-byte-long string
 * can't be encoded as the sequence 126, 0, 124.  The payload length
 * is the length of the "Extension data" + the length of the
 * "Application data".  The length of the "Extension data" may be
 * zero, in which case the payload length is the length of the
 * "Application data".
 */
#define AWS_WEBSOCKET_7BIT_VALUE_FOR_2BYTE_EXTENDED_LENGTH 126
#define AWS_WEBSOCKET_7BIT_VALUE_FOR_8BYTE_EXTENDED_LENGTH 127

#define AWS_WEBSOCKET_2BYTE_EXTENDED_LENGTH_MIN_VALUE AWS_WEBSOCKET_7BIT_VALUE_FOR_2BYTE_EXTENDED_LENGTH
#define AWS_WEBSOCKET_2BYTE_EXTENDED_LENGTH_MAX_VALUE 0x000000000000FFFF

#define AWS_WEBSOCKET_8BYTE_EXTENDED_LENGTH_MIN_VALUE 0x0000000000010000
#define AWS_WEBSOCKET_8BYTE_EXTENDED_LENGTH_MAX_VALUE 0x7FFFFFFFFFFFFFFF

/* Max bytes necessary to send non-payload parts of a frame */
#define AWS_WEBSOCKET_MAX_FRAME_OVERHEAD (2 + 8 + 4) /* base + extended-length + masking-key */

/**
 * Full contents of a websocket frame, excluding the payload.
 */
struct aws_websocket_frame {
    bool fin;
    bool rsv[3];
    bool masked;
    uint8_t opcode;
    uint64_t payload_length;
    uint8_t masking_key[4];
};

struct aws_websocket_handler_options {
    struct aws_allocator *allocator;
    size_t initial_window_size;
    bool is_server;

    void *user_data;
    aws_websocket_on_connection_shutdown_fn *on_connection_shutdown;
    aws_websocket_on_incoming_frame_begin *on_incoming_frame_begin;
    aws_websocket_on_incoming_frame_payload *on_incoming_frame_payload;
    aws_websocket_on_incoming_frame_complete *on_incoming_frame_complete;
};

AWS_EXTERN_C_BEGIN

/**
 * Return total number of bytes needed to encode frame and its payload
 */
AWS_HTTP_API
uint64_t aws_websocket_frame_encoded_size(const struct aws_websocket_frame *frame);

AWS_HTTP_API
struct aws_channel_handler *aws_websocket_handler_new(const struct aws_websocket_handler_options *options);

AWS_HTTP_API
void aws_websocket_handler_destroy(struct aws_channel_handler *websocket_handler);

AWS_EXTERN_C_END
#endif /* AWS_HTTP_WEBSOCKET_IMPL_H */
