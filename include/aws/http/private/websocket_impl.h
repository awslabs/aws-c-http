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

#include <aws/http/http.h>

enum aws_websocket_opcode {
    AWS_WEBSOCKET_OPCODE_CONTINUATION = 0x0,
    AWS_WEBSOCKET_OPCODE_TEXT = 0x1,
    AWS_WEBSOCKET_OPCODE_BINARY = 0x2,
    AWS_WEBSOCKET_OPCODE_CLOSE = 0x8,
    AWS_WEBSOCKET_OPCODE_PING = 0x9,
    AWS_WEBSOCKET_OPCODE_PONG = 0xA,
};

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

/**
 * Return true if opcode is for a data frame, false if opcode if for a control frame.
 */
AWS_STATIC_IMPL
bool aws_websocket_is_data_frame(uint8_t opcode) {
    return !(opcode & 0x08); /* RFC-6455 Section 5.6: Most significant bit of (4 bit) data frame opcode is 0 */
}

#endif /* AWS_HTTP_WEBSOCKET_IMPL_H */
