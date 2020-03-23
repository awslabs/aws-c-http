#ifndef AWS_HTTP_H2_DECODER_H
#define AWS_HTTP_H2_DECODER_H

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

#include <aws/http/private/h2_frames.h>
#include <aws/http/private/http_impl.h>

/* Decoder design goals:
 * - Minimize state tracking and verification required by user.
 *   For example, we have _begin()/_i()/_end() callbacks when something happens N times.
 *   The _begin() and _end() callbacks tell the user when to transition states.
 *   Without them the user needs to be like, oh, I was doing X but now I'm doing Y,
 *   so I guess I need to end X and start Y.

 * - A callback should result in 1 distinct action.
 *   For example, we have distinct callbacks for `on_ping()` and `on_ping_ack()`.
 *   We COULD have had just one `on_ping(bool ack)` callback, but since user must
 *   take two complete different actions based on the ACK, we opted for two callbacks.
 */

struct aws_h2_decoder_vtable {
    /* For HEADERS header-block: _begin() is called, then 0+ _i() calls, then _end().
     * No other decoder callbacks will occur in this time. */
    int (*on_headers_begin)(uint32_t stream_id, void *userdata);
    int (*on_headers_i)(uint32_t stream_id, const struct aws_http_header *header, void *userdata);
    int (*on_headers_end)(uint32_t stream_id, void *userdata);

    /* For PUSH_PROMISE header-block: _begin() is called, then 0+ _i() calls, then _end().
     * No other decoder callbacks will occur in this time. */
    int (*on_push_promise_begin)(uint32_t stream_id, uint32_t promised_stream_id, void *userdata);
    int (*on_push_promise_i)(uint32_t stream_id, const struct aws_http_header *header, void *userdata);

    int (*on_push_promise_end)(uint32_t stream_id, void *userdata);

    /* Called repeatedly as DATA frames are processed.
     * This may fire multiple times per actual DATA frame. */
    int (*on_data)(uint32_t stream_id, struct aws_byte_cursor data, void *userdata);

    /* Called at end of DATA frame containing the END_STREAM flag.
     * OR called at end of header-block which began with HEADERS frame containing the END_STREAM flag */
    int (*on_end_stream)(uint32_t stream_id, void *userdata);

    /* Called once for RST_STREAM frame */
    int (*on_rst_stream)(uint32_t stream_id, uint32_t error_code, void *userdata);

    /* Called once For PING frame with ACK flag set */
    int (*on_ping_ack)(uint8_t opaque_data[AWS_H2_PING_DATA_SIZE], void *userdata);

    /* Called once for PING frame (no ACK flag set)*/
    int (*on_ping)(uint8_t opaque_data[AWS_H2_PING_DATA_SIZE], void *userdata);

    /* Called once for SETTINGS frame with ACK flag */
    int (*on_settings_ack)(void *userdata);

    /* For SETTINGS frame (no ACK flag set): _begin() is called, then 0+ _i() calls, then _end().
     * No other decoder callbacks will occur in this time. */
    int (*on_settings_begin)(void *userdata);
    int (*on_settings_i)(uint16_t setting_id, uint32_t value, void *userdata);
    int (*on_settings_end)(void *userdata);

    /* For GOAWAY frame: _begin() is called, then 0+ _i() calls, then _end().
     * No other decoder callbacks will occur in this time. */
    int (*on_goaway_begin)(uint32_t last_stream, uint32_t error_code, uint32_t debug_data_length, void *userdata);
    int (*on_goaway_i)(struct aws_byte_cursor debug_data, void *userdata);
    int (*on_goaway_end)(void *userdata);

    /* Called once for WINDOW_UPDATE frame */
    int (*on_window_update)(uint32_t stream_id, uint32_t window_size_increment, void *userdata);
};

/**
 * Structure used to initialize an `aws_h2_decoder`.
 */
struct aws_h2_decoder_params {
    struct aws_allocator *alloc;
    const struct aws_h2_decoder_vtable *vtable;
    void *userdata;
    const void *logging_id;
    bool is_server;

    /* If true, do not expect the connection preface and immediately accept any frame type.
     * Only set this when testing the decoder itself */
    bool skip_connection_preface;
};

struct aws_h2_decoder;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API struct aws_h2_decoder *aws_h2_decoder_new(struct aws_h2_decoder_params *params);
AWS_HTTP_API void aws_h2_decoder_destroy(struct aws_h2_decoder *decoder);
AWS_HTTP_API int aws_h2_decode(struct aws_h2_decoder *decoder, struct aws_byte_cursor *data);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H2_DECODER_H */
