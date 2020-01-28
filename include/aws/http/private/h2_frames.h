#ifndef AWS_HTTP_H2_FRAMES_H
#define AWS_HTTP_H2_FRAMES_H

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

#include <aws/http/request_response.h>

#include <aws/common/byte_buf.h>

/* Ids for each frame type (RFC-7540 6) */
enum aws_h2_frame_type {
    AWS_H2_FRAME_T_DATA = 0x00,
    AWS_H2_FRAME_T_HEADERS = 0x01,
    AWS_H2_FRAME_T_PRIORITY = 0x02,
    AWS_H2_FRAME_T_RST_STREAM = 0x03,
    AWS_H2_FRAME_T_SETTINGS = 0x04,
    AWS_H2_FRAME_T_PUSH_PROMISE = 0x05,
    AWS_H2_FRAME_T_PING = 0x06,
    AWS_H2_FRAME_T_GOAWAY = 0x07,
    AWS_H2_FRAME_T_WINDOW_UPDATE = 0x08,
    AWS_H2_FRAME_T_CONTINUATION = 0x09,
    AWS_H2_FRAME_T_UNKNOWN,
};

/* Represents flags that may be set on a frame (RFC-7540 6) */
enum aws_h2_frame_flag {
    AWS_H2_FRAME_F_ACK = 0x01,
    AWS_H2_FRAME_F_END_STREAM = 0x01,
    AWS_H2_FRAME_F_END_HEADERS = 0x04,
    AWS_H2_FRAME_F_PADDED = 0x08,
    AWS_H2_FRAME_F_PRIORITY = 0x20,
};

/* Error codes that may be present in RST_STREAM and GOAWAY frames (RFC-7540 7). */
enum aws_h2_error_codes {
    AWS_H2_ERR_NO_ERROR = 0x00,
    AWS_H2_ERR_PROTOCOL_ERROR = 0x01, /* corresponds to AWS_ERROR_HTTP_PROTOCOL_ERROR */
    AWS_H2_ERR_INTERNAL_ERROR = 0x02,
    AWS_H2_ERR_FLOW_CONTROL_ERROR = 0x03,
    AWS_H2_ERR_SETTINGS_TIMEOUT = 0x04,
    AWS_H2_ERR_STREAM_CLOSED = 0x05,    /* corresponds to AWS_ERROR_HTTP_STREAM_CLOSED */
    AWS_H2_ERR_FRAME_SIZE_ERROR = 0x06, /* corresponds to AWS_ERROR_HTTP_INVALID_FRAME_SIZE */
    AWS_H2_ERR_REFUSED_STREAM = 0x07,
    AWS_H2_ERR_CANCEL = 0x08,
    AWS_H2_ERR_COMPRESSION_ERROR = 0x09, /* corresponds to AWS_ERROR_HTTP_COMPRESSION */
    AWS_H2_ERR_CONNECT_ERROR = 0x0A,
    AWS_H2_ERR_ENHANCE_YOUR_CALM = 0x0B,
    AWS_H2_ERR_INADEQUATE_SECURITY = 0x0C,
    AWS_H2_ERR_HTTP_1_1_REQUIRED = 0x0D,
};

/* Predefined settings identifiers (RFC-7540 6.5.2) */
enum aws_h2_settings {
    AWS_H2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
    AWS_H2_SETTINGS_ENABLE_PUSH = 0x2,
    AWS_H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    AWS_H2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
    AWS_H2_SETTINGS_MAX_FRAME_SIZE = 0x5,
    AWS_H2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6,
};

/* RFC-7541 2.4 */
enum aws_h2_header_field_hpack_behavior {
    AWS_H2_HEADER_BEHAVIOR_SAVE,
    AWS_H2_HEADER_BEHAVIOR_NO_SAVE,
    AWS_H2_HEADER_BEHAVIOR_NO_FORWARD_SAVE,
};

/**
 * Present in all frames that may have set AWS_H2_FRAME_F_PRIORITY
 *
 * Encoded as:
 * +-+-------------------------------------------------------------+
 * |E|                  Stream Dependency (31)                     |
 * +-+-------------+-----------------------------------------------+
 * |   Weight (8)  |
 * +-+-------------+
 */
struct aws_h2_frame_priority_settings {
    uint32_t stream_dependency;
    bool stream_dependency_exclusive;
    uint8_t weight;
};

struct aws_h2_frame_header_field {
    struct aws_http_header header;
    enum aws_h2_header_field_hpack_behavior hpack_behavior;
    const size_t index; /* DO NOT TOUCH unless you're pretty sure you know what you're doing */
};
struct aws_h2_frame_header_block {
    /* array_list of aws_h2_frame_header_field */
    struct aws_array_list header_fields;
};

/* The header present in every h2 frame */
struct aws_h2_frame_header {
    uint8_t type; /* aws_h2_frame_type */
    uint32_t stream_id;
};

/* Represents a DATA frame */
struct aws_h2_frame_data {
    /* Header */
    struct aws_h2_frame_header header;

    /* Flags */
    bool end_stream; /* AWS_H2_FRAME_F_END_STREAM */

    /* Payload */
    uint8_t pad_length; /* Set to 0 to disable AWS_H2_FRAME_F_PADDED */
    struct aws_byte_cursor data;
};

/* Represents a HEADERS frame */
struct aws_h2_frame_headers {
    /* Header */
    struct aws_h2_frame_header header;

    /* Flags */
    bool end_stream;   /* AWS_H2_FRAME_F_END_STREAM */
    bool end_headers;  /* AWS_H2_FRAME_F_END_HEADERS */
    bool has_priority; /* AWS_H2_FRAME_F_PRIORITY */

    /* Payload */
    uint8_t pad_length; /* Set to 0 to disable AWS_H2_FRAME_F_PADDED */
    struct aws_h2_frame_priority_settings priority;
    struct aws_h2_frame_header_block header_block;
};

/* Represents a PRIORITY frame */
struct aws_h2_frame_priority {
    /* Header */
    struct aws_h2_frame_header header;

    /* Payload */
    struct aws_h2_frame_priority_settings priority;
};

/* Represents a RST_STREAM frame */
struct aws_h2_frame_rst_stream {
    /* Header */
    struct aws_h2_frame_header header;

    /* Payload */
    enum aws_h2_error_codes error_code;
};

/* A h2 setting and its value, used in SETTINGS frame */
struct aws_h2_frame_setting {
    uint16_t id; /* aws_h2_settings */
    uint32_t value;
};

/* Represents a SETTINGS frame */
struct aws_h2_frame_settings {
    /* Header */
    struct aws_h2_frame_header header;

    /* Flags */
    bool ack; /* AWS_H2_FRAME_F_ACK */

    /* Payload */
    struct aws_h2_frame_setting *settings_array;
    size_t settings_count;
};

/* Represents a PUSH_PROMISE frame */
struct aws_h2_frame_push_promise {
    /* Header */
    struct aws_h2_frame_header header;

    /* Flags */
    bool end_headers; /* AWS_H2_FRAME_F_END_HEADERS */

    /* Payload */
    uint8_t pad_length; /* Set to 0 to disable AWS_H2_FRAME_F_PADDED */
    uint32_t promised_stream_id;
    struct aws_h2_frame_header_block header_block;
};

#define AWS_H2_PING_DATA_SIZE (8)

/* Represents a PING frame */
struct aws_h2_frame_ping {
    /* Header */
    struct aws_h2_frame_header header;

    /* Flags */
    bool ack; /* AWS_H2_FRAME_F_ACK */

    /* Payload */
    uint8_t opaque_data[AWS_H2_PING_DATA_SIZE];
};

/* Represents a GOAWAY frame */
struct aws_h2_frame_goaway {
    /* Header */
    struct aws_h2_frame_header header;

    /* Payload */
    uint32_t last_stream_id;
    enum aws_h2_error_codes error_code;
    struct aws_byte_cursor debug_data;
};

/* Represents a WINDOW_UPDATE frame */
struct aws_h2_frame_window_update {
    /* Header */
    struct aws_h2_frame_header header;

    /* Payload */
    uint32_t window_size_increment;
};

/* Represents a CONTINUATION frame */
struct aws_h2_frame_continuation {
    /* Header */
    struct aws_h2_frame_header header;

    /* Flags */
    bool end_headers; /* AWS_H2_FRAME_F_END_HEADERS */

    /* Payload */
    struct aws_h2_frame_header_block header_block;
};

/* Used to encode a frame */
struct aws_h2_frame_encoder {
    /* Larger state */
    struct aws_allocator *allocator;
    struct aws_hpack_context *hpack;
    bool use_huffman;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
const char *aws_h2_frame_type_to_str(enum aws_h2_frame_type type);

/* Internal methods exposed for testing purposes only */
AWS_HTTP_API
int aws_h2_frame_header_block_init(struct aws_h2_frame_header_block *header_block, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_header_block_clean_up(struct aws_h2_frame_header_block *header_block);
AWS_HTTP_API
int aws_h2_frame_header_block_get_encoded_length(
    const struct aws_h2_frame_header_block *header_block,
    const struct aws_h2_frame_encoder *encoder,
    size_t *length);
AWS_HTTP_API
int aws_h2_frame_header_block_encode(
    const struct aws_h2_frame_header_block *header_block,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

/**
 * The process of encoding a frame looks like:
 * 1. Create a encoder object on the stack and initialize with aws_h2_frame_encoder_init
 * 2. Encode the header using aws_h2_frame_*_encode
 */
AWS_HTTP_API
int aws_h2_frame_encoder_init(struct aws_h2_frame_encoder *encoder, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_encoder_clean_up(struct aws_h2_frame_encoder *encoder);

/* #TODO: remove each frame type's specific encode() function from API */
AWS_HTTP_API
int aws_h2_encode_frame(
    struct aws_h2_frame_encoder *encoder,
    struct aws_h2_frame_header *frame_header,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_data_init(struct aws_h2_frame_data *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_data_clean_up(struct aws_h2_frame_data *frame);

AWS_HTTP_API
int aws_h2_frame_data_encode(
    struct aws_h2_frame_data *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_headers_init(struct aws_h2_frame_headers *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_headers_clean_up(struct aws_h2_frame_headers *frame);
AWS_HTTP_API
int aws_h2_frame_headers_encode(
    struct aws_h2_frame_headers *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_priority_init(struct aws_h2_frame_priority *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_priority_clean_up(struct aws_h2_frame_priority *frame);
AWS_HTTP_API
int aws_h2_frame_priority_encode(
    struct aws_h2_frame_priority *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_rst_stream_init(struct aws_h2_frame_rst_stream *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_rst_stream_clean_up(struct aws_h2_frame_rst_stream *frame);
AWS_HTTP_API
int aws_h2_frame_rst_stream_encode(
    struct aws_h2_frame_rst_stream *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_settings_init(struct aws_h2_frame_settings *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_settings_clean_up(struct aws_h2_frame_settings *frame);
AWS_HTTP_API
int aws_h2_frame_settings_encode(
    struct aws_h2_frame_settings *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_push_promise_init(struct aws_h2_frame_push_promise *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_push_promise_clean_up(struct aws_h2_frame_push_promise *frame);
AWS_HTTP_API
int aws_h2_frame_push_promise_encode(
    struct aws_h2_frame_push_promise *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_ping_init(struct aws_h2_frame_ping *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_ping_clean_up(struct aws_h2_frame_ping *frame);
AWS_HTTP_API
int aws_h2_frame_ping_encode(
    struct aws_h2_frame_ping *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_goaway_init(struct aws_h2_frame_goaway *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_goaway_clean_up(struct aws_h2_frame_goaway *frame);
AWS_HTTP_API
int aws_h2_frame_goaway_encode(
    struct aws_h2_frame_goaway *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_window_update_init(struct aws_h2_frame_window_update *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_window_update_clean_up(struct aws_h2_frame_window_update *frame);
AWS_HTTP_API
int aws_h2_frame_window_update_encode(
    struct aws_h2_frame_window_update *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_HTTP_API
int aws_h2_frame_continuation_init(struct aws_h2_frame_continuation *frame, struct aws_allocator *allocator);
AWS_HTTP_API
void aws_h2_frame_continuation_clean_up(struct aws_h2_frame_continuation *frame);
AWS_HTTP_API
int aws_h2_frame_continuation_encode(
    struct aws_h2_frame_continuation *frame,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H2_FRAMES_H */
