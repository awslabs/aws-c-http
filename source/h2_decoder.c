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
#include <aws/http/private/h2_decoder.h>

#include <aws/http/private/hpack.h>

#include <aws/common/string.h>
#include <aws/io/logging.h>

#include <inttypes.h>

/***********************************************************************************************************************
 * Constants
 **********************************************************************************************************************/

/* The scratch buffers data for states with bytes_required > 0. Must be big enough for largest state */
static const size_t s_scratch_space_size = 9;

/* Stream ids & dependencies should only write the bottom 31 bits */
static const uint32_t s_31_bit_mask = UINT32_MAX >> 1;

#define DECODER_LOGF(level, decoder, text, ...)                                                                        \
    AWS_LOGF_##level(AWS_LS_HTTP_DECODER, "id=%p " text, (decoder)->logging_id, __VA_ARGS__)
#define DECODER_LOG(level, decoder, text) DECODER_LOGF(level, decoder, "%s", text)

#define DECODER_CALL_VTABLE(decoder, fn)                                                                               \
    do {                                                                                                               \
        if ((decoder)->vtable->fn) {                                                                                   \
            DECODER_LOG(TRACE, decoder, "Calling user callback " #fn)                                                  \
            (decoder)->vtable->fn((decoder)->userdata);                                                                \
        }                                                                                                              \
    } while (false)
#define DECODER_CALL_VTABLE_ARGS(decoder, fn, ...)                                                                     \
    do {                                                                                                               \
        if ((decoder)->vtable->fn) {                                                                                   \
            DECODER_LOG(TRACE, decoder, "Calling user callback " #fn)                                                  \
            (decoder)->vtable->fn(__VA_ARGS__, (decoder)->userdata);                                                   \
        }                                                                                                              \
    } while (false)
#define DECODER_CALL_VTABLE_STREAM(decoder, fn)                                                                        \
    DECODER_CALL_VTABLE_ARGS(decoder, fn, (decoder)->frame_in_progress.stream_id)
#define DECODER_CALL_VTABLE_STREAM_ARGS(decoder, fn, ...)                                                              \
    DECODER_CALL_VTABLE_ARGS(decoder, fn, (decoder)->frame_in_progress.stream_id, __VA_ARGS__)

/***********************************************************************************************************************
 * State Machine
 **********************************************************************************************************************/

typedef int(state_fn)(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input);
struct decoder_state {
    state_fn *fn;
    uint32_t bytes_required;
    const char *name;
};

#define DEFINE_STATE(_name, _bytes_required)                                                                           \
    static state_fn s_state_fn_##_name;                                                                                \
    enum { s_state_##_name##_requires_##_bytes_required##_bytes = _bytes_required };                                   \
    static const struct decoder_state s_state_##_name = {                                                              \
        .fn = s_state_fn_##_name,                                                                                      \
        .bytes_required = s_state_##_name##_requires_##_bytes_required##_bytes,                                        \
        .name = #_name,                                                                                                \
    }

/* Common states */
DEFINE_STATE(prefix, 9);
DEFINE_STATE(padding_len, 1);
DEFINE_STATE(padding, 0);

DEFINE_STATE(priority_block, 5);

DEFINE_STATE(header_block_loop, 0);
DEFINE_STATE(header_block_entry, 1); /* requires 1 byte, but may consume more */

/* Frame-specific states */
DEFINE_STATE(frame_data, 0);
DEFINE_STATE(frame_headers, 0);
DEFINE_STATE(frame_priority, 0);
DEFINE_STATE(frame_rst_stream, 4);
DEFINE_STATE(frame_settings_begin, 0);
DEFINE_STATE(frame_settings_loop, 0);
DEFINE_STATE(frame_settings_i, 6);
DEFINE_STATE(frame_push_promise, 4);
DEFINE_STATE(frame_ping, 8);
DEFINE_STATE(frame_goaway, 8);
DEFINE_STATE(frame_goaway_debug_data, 0);
DEFINE_STATE(frame_window_update, 4);
DEFINE_STATE(frame_continuation, 0);
DEFINE_STATE(frame_unknown, 0);

/* States that have nothing to do with frames */
DEFINE_STATE(connection_preface_string, 1); /* requires 1 byte but may consume more */

/* Helper for states that need to transition to frame-type states */
static const struct decoder_state *s_state_frames[] = {
    [AWS_H2_FRAME_T_DATA] = &s_state_frame_data,
    [AWS_H2_FRAME_T_HEADERS] = &s_state_frame_headers,
    [AWS_H2_FRAME_T_PRIORITY] = &s_state_frame_priority,
    [AWS_H2_FRAME_T_RST_STREAM] = &s_state_frame_rst_stream,
    [AWS_H2_FRAME_T_SETTINGS] = &s_state_frame_settings_begin,
    [AWS_H2_FRAME_T_PUSH_PROMISE] = &s_state_frame_push_promise,
    [AWS_H2_FRAME_T_PING] = &s_state_frame_ping,
    [AWS_H2_FRAME_T_GOAWAY] = &s_state_frame_goaway,
    [AWS_H2_FRAME_T_WINDOW_UPDATE] = &s_state_frame_window_update,
    [AWS_H2_FRAME_T_CONTINUATION] = &s_state_frame_continuation,
    [AWS_H2_FRAME_T_UNKNOWN] = &s_state_frame_unknown,
};

/***********************************************************************************************************************
 * Struct
 **********************************************************************************************************************/

struct aws_h2_decoder {
    /* Implementation data. */
    struct aws_allocator *alloc;
    const void *logging_id;
    struct aws_hpack_context *hpack;
    bool is_server;
    struct aws_byte_buf scratch;
    const struct decoder_state *state;
    bool state_changed;

    /* HTTP/2 connection preface must be first thing received (RFC-7540 3.5):
     * Server must receive (client must send): magic string, then SETTINGS frame.
     * Client must receive (server must send): SETTINGS frame. */
    bool connection_preface_complete;

    /* Cursor over the canonical client connection preface string */
    struct aws_byte_cursor connection_preface_cursor;

    /* Frame-in-progress */
    struct aws_frame_in_progress {
        enum aws_h2_frame_type type;
        uint32_t stream_id;
        uint32_t payload_len;
        uint8_t padding_len;

        struct {
            bool ack;
            bool end_stream;
            bool end_headers;
            bool priority;
        } flags;
    } frame_in_progress;

    /* A header-block starts with a HEADERS or PUSH_PROMISE frame, followed by 0 or more CONTINUATION frames.
     * It's an error for any other frame-type or stream ID to arrive while a header-block is in progress.
     * The header-block ends when a frame has the END_HEADERS flag set. (RFC-7540 4.3) */
    struct {
        /* If 0, then no header-block in progress */
        uint32_t stream_id;

        /* T: PUSH_PROMISE header-block
         * F: HEADERS header-block */
        bool is_push_promise;

        /* If frame that starts header-block has END_STREAM flag,
         * then frame that ends header-block also ends the stream. */
        bool ends_stream;
    } header_block_in_progress;

    /* User callbacks and settings. */
    const struct aws_h2_decoder_vtable *vtable;
    void *userdata;

    /* If this is set to true, decode may no longer be called */
    bool has_errored;
};

/***********************************************************************************************************************
 * Public API
 **********************************************************************************************************************/

struct aws_h2_decoder *aws_h2_decoder_new(struct aws_h2_decoder_params *params) {
    AWS_PRECONDITION(params);
    AWS_PRECONDITION(params->alloc);
    AWS_PRECONDITION(params->vtable);

    struct aws_h2_decoder *decoder = NULL;
    void *scratch_buf = NULL;

    void *allocation = aws_mem_acquire_many(
        params->alloc, 2, &decoder, sizeof(struct aws_h2_decoder), &scratch_buf, s_scratch_space_size);
    if (!allocation) {
        goto failed_alloc;
    }

    AWS_ZERO_STRUCT(*decoder);
    decoder->alloc = params->alloc;
    decoder->vtable = params->vtable;
    decoder->userdata = params->userdata;
    decoder->logging_id = params->logging_id;
    decoder->is_server = params->is_server;
    decoder->connection_preface_complete = params->skip_connection_preface;

    decoder->scratch = aws_byte_buf_from_empty_array(scratch_buf, s_scratch_space_size);

    decoder->hpack = aws_hpack_context_new(params->alloc, AWS_LS_HTTP_DECODER, decoder);
    if (!decoder->hpack) {
        goto failed_new_hpack;
    }

    if (decoder->is_server && !params->skip_connection_preface) {
        decoder->state = &s_state_connection_preface_string;
        decoder->connection_preface_cursor = aws_h2_connection_preface_client_string;
    } else {
        decoder->state = &s_state_prefix;
    }

    return decoder;

failed_new_hpack:
    aws_mem_release(params->alloc, allocation);
failed_alloc:
    return NULL;
}

void aws_h2_decoder_destroy(struct aws_h2_decoder *decoder) {
    if (!decoder) {
        return;
    }
    aws_hpack_context_destroy(decoder->hpack);
    aws_mem_release(decoder->alloc, decoder);
}

int aws_h2_decode(struct aws_h2_decoder *decoder, struct aws_byte_cursor *data) {
    AWS_PRECONDITION(decoder);
    AWS_PRECONDITION(data);

    AWS_FATAL_ASSERT(!decoder->has_errored);

    /* Run decoder state machine until we're no longer changing states.
     * We don't simply loop `while(data->len)` because some states consume no data,
     * and these states should run even when there is no data left. */
    do {
        decoder->state_changed = false;

        const uint32_t bytes_required = decoder->state->bytes_required;
        AWS_ASSERT(bytes_required <= decoder->scratch.capacity);
        const char *current_state_name = decoder->state->name;
        const size_t prev_data_len = data->len;
        (void)prev_data_len;

        if (!decoder->scratch.len && data->len >= bytes_required) {
            /* Easy case, there is no scratch and we have enough data, so just send it to the state */

            DECODER_LOGF(TRACE, decoder, "Running state '%s' with %zu bytes available", current_state_name, data->len);

            if (decoder->state->fn(decoder, data)) {
                goto handle_error;
            }

            AWS_ASSERT(prev_data_len - data->len >= bytes_required && "Decoder state requested more data than it used");
        } else {
            /* Otherwise, state requires a minimum amount of data and we have to use the scratch */
            size_t bytes_to_read = bytes_required - decoder->scratch.len;
            bool will_finish_state = true;

            if (bytes_to_read > data->len) {
                /* Not enough in this cursor, need to read as much as possible and then come back */
                bytes_to_read = data->len;
                will_finish_state = false;
            }

            if (AWS_LIKELY(bytes_to_read)) {
                /* Read the appropriate number of bytes into scratch */
                struct aws_byte_cursor to_read = aws_byte_cursor_advance(data, bytes_to_read);
                bool succ = aws_byte_buf_write_from_whole_cursor(&decoder->scratch, to_read);
                AWS_ASSERT(succ);
                (void)succ;
            }

            /* If we have the correct number of bytes, call the state */
            if (will_finish_state) {

                DECODER_LOGF(TRACE, decoder, "Running state '%s' (using scratch)", current_state_name);

                struct aws_byte_cursor state_data = aws_byte_cursor_from_buf(&decoder->scratch);
                if (decoder->state->fn(decoder, &state_data)) {
                    goto handle_error;
                }

                AWS_ASSERT(state_data.len == 0 && "Decoder state requested more data than it used");
            } else {
                DECODER_LOGF(
                    TRACE,
                    decoder,
                    "State '%s' requires %" PRIu32 " bytes, but only %zu available, trying again later",
                    current_state_name,
                    bytes_required,
                    decoder->scratch.len);
            }
        }
    } while (decoder->state_changed);

    return AWS_OP_SUCCESS;

handle_error:
    decoder->has_errored = true;
    return AWS_OP_ERR;
}

/***********************************************************************************************************************
 * State functions
 **********************************************************************************************************************/

static int s_decoder_switch_state(struct aws_h2_decoder *decoder, const struct decoder_state *state) {
    /* Ensure payload is big enough to enter next state.
     * If this fails, then the payload length we received is too small for this frame type.
     * (ex: a RST_STREAM frame with < 4 bytes) */
    if (decoder->frame_in_progress.payload_len < state->bytes_required) {
        DECODER_LOGF(
            ERROR, decoder, "%s payload is too small", aws_h2_frame_type_to_str(decoder->frame_in_progress.type));
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_FRAME_SIZE);
    }

    DECODER_LOGF(TRACE, decoder, "Moving from state '%s' to '%s'", decoder->state->name, state->name);
    decoder->scratch.len = 0;
    decoder->state = state;
    decoder->state_changed = true;
    return AWS_OP_SUCCESS;
}

static int s_decoder_switch_to_frame_state(struct aws_h2_decoder *decoder) {
    AWS_ASSERT(decoder->frame_in_progress.type <= AWS_H2_FRAME_T_UNKNOWN);
    return s_decoder_switch_state(decoder, s_state_frames[decoder->frame_in_progress.type]);
}

static int s_decoder_reset_state(struct aws_h2_decoder *decoder) {
    /* Ensure we've consumed all payload (and padding) when state machine finishes this frame.
     * If this fails, the payload length we received is too large for this frame type.
     * (ex: a RST_STREAM frame with > 4 bytes) */
    if (decoder->frame_in_progress.payload_len > 0 || decoder->frame_in_progress.padding_len > 0) {
        DECODER_LOGF(
            ERROR, decoder, "%s frame payload is too large", aws_h2_frame_type_to_str(decoder->frame_in_progress.type));
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_FRAME_SIZE);
    }

    DECODER_LOGF(TRACE, decoder, "%s frame complete", aws_h2_frame_type_to_str(decoder->frame_in_progress.type));

    decoder->scratch.len = 0;
    decoder->state = &s_state_prefix;
    decoder->state_changed = true;

    AWS_ZERO_STRUCT(decoder->frame_in_progress);
    return AWS_OP_SUCCESS;
}

/** Returns as much of the current frame's payload as possible, and updates payload_len */
static struct aws_byte_cursor s_decoder_get_payload(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    struct aws_byte_cursor result;

    const uint32_t remaining_length = decoder->frame_in_progress.payload_len;
    if (input->len < remaining_length) {
        AWS_ASSERT(input->len <= UINT32_MAX);
        result = aws_byte_cursor_advance(input, input->len);
    } else {
        result = aws_byte_cursor_advance(input, remaining_length);
    }

    decoder->frame_in_progress.payload_len -= (uint32_t)result.len;

    return result;
}

/* clang-format off */

/* Mask of flags supported by each frame type.
 * Frames not listed have mask of 0, which means all flags will be ignored. */
static const uint8_t s_acceptable_flags_for_frame[AWS_H2_FRAME_T_UNKNOWN + 1] = {
    [AWS_H2_FRAME_T_DATA]           = AWS_H2_FRAME_F_END_STREAM | AWS_H2_FRAME_F_PADDED,
    [AWS_H2_FRAME_T_HEADERS]        = AWS_H2_FRAME_F_END_STREAM | AWS_H2_FRAME_F_END_HEADERS |
                                      AWS_H2_FRAME_F_PADDED | AWS_H2_FRAME_F_PRIORITY,
    [AWS_H2_FRAME_T_PRIORITY]       = 0,
    [AWS_H2_FRAME_T_RST_STREAM]     = 0,
    [AWS_H2_FRAME_T_SETTINGS]       = AWS_H2_FRAME_F_ACK,
    [AWS_H2_FRAME_T_PUSH_PROMISE]   = AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PADDED,
    [AWS_H2_FRAME_T_PING]           = AWS_H2_FRAME_F_ACK,
    [AWS_H2_FRAME_T_GOAWAY]         = 0,
    [AWS_H2_FRAME_T_WINDOW_UPDATE]  = 0,
    [AWS_H2_FRAME_T_CONTINUATION]   = AWS_H2_FRAME_F_END_HEADERS,
    [AWS_H2_FRAME_T_UNKNOWN]        = 0,
};

enum stream_id_rules {
    STREAM_ID_REQUIRED,
    STREAM_ID_FORBIDDEN,
    STREAM_ID_EITHER_WAY,
};

/* Frame-types generally either require a stream-id, or require that it be zero. */
static const enum stream_id_rules s_stream_id_rules_for_frame[AWS_H2_FRAME_T_UNKNOWN + 1] = {
    [AWS_H2_FRAME_T_DATA]           = STREAM_ID_REQUIRED,
    [AWS_H2_FRAME_T_HEADERS]        = STREAM_ID_REQUIRED,
    [AWS_H2_FRAME_T_PRIORITY]       = STREAM_ID_REQUIRED,
    [AWS_H2_FRAME_T_RST_STREAM]     = STREAM_ID_REQUIRED,
    [AWS_H2_FRAME_T_SETTINGS]       = STREAM_ID_FORBIDDEN,
    [AWS_H2_FRAME_T_PUSH_PROMISE]   = STREAM_ID_REQUIRED,
    [AWS_H2_FRAME_T_PING]           = STREAM_ID_FORBIDDEN,
    [AWS_H2_FRAME_T_GOAWAY]         = STREAM_ID_FORBIDDEN,
    [AWS_H2_FRAME_T_WINDOW_UPDATE]  = STREAM_ID_EITHER_WAY, /* WINDOW_UPDATE is special and can do either */
    [AWS_H2_FRAME_T_CONTINUATION]   = STREAM_ID_REQUIRED,
    [AWS_H2_FRAME_T_UNKNOWN]        = STREAM_ID_EITHER_WAY, /* Everything in an UNKNOWN frame type is ignored */
};
/* clang-format on */

/* All frames begin with a fixed 9-octet header followed by a variable-length payload. (RFC-7540 4.1)
 * This function processes everything preceding Frame Payload in the following diagram:
 *  +-----------------------------------------------+
 *  |                 Length (24)                   |
 *  +---------------+---------------+---------------+
 *  |   Type (8)    |   Flags (8)   |
 *  +-+-------------+---------------+-------------------------------+
 *  |R|                 Stream Identifier (31)                      |
 *  +=+=============================================================+
 *  |                   Frame Payload (0...)                      ...
 *  +---------------------------------------------------------------+
 */
static int s_state_fn_prefix(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_prefix_requires_9_bytes);

    struct aws_frame_in_progress *frame = &decoder->frame_in_progress;
    uint8_t raw_type = 0;
    uint8_t raw_flags = 0;

    /* Read the raw values from the first 9 bytes */
    bool all_read = true;
    all_read &= aws_byte_cursor_read_be24(input, &frame->payload_len);
    all_read &= aws_byte_cursor_read_u8(input, &raw_type);
    all_read &= aws_byte_cursor_read_u8(input, &raw_flags);
    all_read &= aws_byte_cursor_read_be32(input, &frame->stream_id);
    AWS_ASSERT(all_read);
    (void)all_read;

    /* Validate frame type */
    frame->type = raw_type < AWS_H2_FRAME_T_UNKNOWN ? raw_type : AWS_H2_FRAME_T_UNKNOWN;

    /* Validate the frame's flags
     * Flags that have no defined semantics for a particular frame type MUST be ignored (RFC-7540 4.1) */
    const uint8_t flags = raw_flags & s_acceptable_flags_for_frame[decoder->frame_in_progress.type];

    bool is_padded = flags & AWS_H2_FRAME_F_PADDED;
    decoder->frame_in_progress.flags.ack = flags & AWS_H2_FRAME_F_ACK;
    decoder->frame_in_progress.flags.end_stream = flags & AWS_H2_FRAME_F_END_STREAM;
    decoder->frame_in_progress.flags.end_headers = flags & AWS_H2_FRAME_F_END_HEADERS;
    decoder->frame_in_progress.flags.priority =
        flags & AWS_H2_FRAME_F_PRIORITY || decoder->frame_in_progress.type == AWS_H2_FRAME_T_PRIORITY;

    /* Connection preface requires that SETTINGS be sent first (RFC-7540 3.5).
     * This should be the first error we check for, so that a connection sending
     * total garbage data is likely to trigger this PROTOCOL_ERROR */
    if (!decoder->connection_preface_complete) {
        if (frame->type == AWS_H2_FRAME_T_SETTINGS && !frame->flags.ack) {
            DECODER_LOG(TRACE, decoder, "Connection preface satisfied.");
            decoder->connection_preface_complete = true;
        } else {
            DECODER_LOG(ERROR, decoder, "First frame must be SETTINGS");
            return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
        }
    }

    /* Validate the frame's stream ID. */

    /* Reserved bit (1st bit) MUST be ignored when receiving (RFC-7540 4.1) */
    frame->stream_id &= s_31_bit_mask;

    /* Some frame types require a stream ID, some frame types require that stream ID be zero. */
    const enum stream_id_rules stream_id_rules = s_stream_id_rules_for_frame[frame->type];
    if (frame->stream_id) {
        if (stream_id_rules == STREAM_ID_FORBIDDEN) {
            DECODER_LOGF(ERROR, decoder, "Stream ID for %s frame must be 0.", aws_h2_frame_type_to_str(frame->type));
            return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
        }
    } else {
        if (stream_id_rules == STREAM_ID_REQUIRED) {
            DECODER_LOGF(ERROR, decoder, "Stream ID for %s frame cannot be 0.", aws_h2_frame_type_to_str(frame->type));
            return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
        }
    }

    /* A header-block starts with a HEADERS or PUSH_PROMISE frame, followed by 0 or more CONTINUATION frames.
     * It's an error for any other frame-type or stream ID to arrive while a header-block is in progress.
     * (RFC-7540 4.3) */
    if (frame->type == AWS_H2_FRAME_T_CONTINUATION) {
        if (decoder->header_block_in_progress.stream_id != frame->stream_id) {
            DECODER_LOG(ERROR, decoder, "Unexpected CONTINUATION frame.");
            return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
        }
    } else {
        if (decoder->header_block_in_progress.stream_id) {
            DECODER_LOG(ERROR, decoder, "Expected CONTINUATION frame.");
            return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
        }
    }

    /* Validate payload length.  */
    static const uint32_t MAX_FRAME_SIZE = 16384; /* #TODO handle the SETTINGS_MAX_FRAME_SIZE setting */
    if (frame->payload_len > MAX_FRAME_SIZE) {
        DECODER_LOGF(
            ERROR,
            decoder,
            "Decoder's max frame size is %" PRIu32 ", but frame of size %" PRIu32 " was received.",
            MAX_FRAME_SIZE,
            frame->payload_len);
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_FRAME_SIZE);
    }

    DECODER_LOGF(
        TRACE,
        decoder,
        "Done decoding frame prefix (type=%s stream-id=%" PRIu32 " payload-len=%" PRIu32 "), moving on to payload",
        aws_h2_frame_type_to_str(frame->type),
        frame->stream_id,
        frame->payload_len);

    if (is_padded) {
        /* Read padding length if necessary */
        return s_decoder_switch_state(decoder, &s_state_padding_len);

    } else if (decoder->frame_in_progress.flags.priority) {
        /* Read the stream dependency and weight if PRIORITY is set */
        return s_decoder_switch_state(decoder, &s_state_priority_block);
    }

    /* Set the state to the appropriate frame's state */
    return s_decoder_switch_to_frame_state(decoder);
}

/* Frames that support padding, and have the PADDED flag set, begin with a 1-byte Pad Length.
 * (Actual padding comes later at the very end of the frame)
 *  +---------------+
 *  |Pad Length? (8)|
 *  +---------------+
 */
static int s_state_fn_padding_len(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_padding_len_requires_1_bytes);

    /* Read the padding length */
    bool succ = aws_byte_cursor_read_u8(input, &decoder->frame_in_progress.padding_len);
    AWS_ASSERT(succ);
    (void)succ;

    /* Adjust payload size so it doesn't include padding (or the 1-byte padding length) */
    uint32_t reduce_payload = s_state_padding_len_requires_1_bytes + decoder->frame_in_progress.padding_len;
    if (reduce_payload > decoder->frame_in_progress.payload_len) {
        DECODER_LOG(ERROR, decoder, "Padding length exceeds payload length");
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }
    decoder->frame_in_progress.payload_len -= reduce_payload;

    DECODER_LOGF(TRACE, decoder, "Padding length of frame: %" PRIu32, decoder->frame_in_progress.padding_len);

    if (decoder->frame_in_progress.flags.priority) {
        /* Read the stream dependency and weight if PRIORITY is set */
        return s_decoder_switch_state(decoder, &s_state_priority_block);
    }

    /* Set the state to the appropriate frame's state */
    return s_decoder_switch_to_frame_state(decoder);
}

static int s_state_fn_padding(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    const uint8_t remaining_len = decoder->frame_in_progress.padding_len;
    const uint8_t consuming_len = input->len < remaining_len ? (uint8_t)input->len : remaining_len;
    aws_byte_cursor_advance(input, consuming_len);
    decoder->frame_in_progress.padding_len -= consuming_len;

    if (remaining_len == consuming_len) {
        /* Done with the frame! */
        return s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}

/* Shared code for:
 * PRIORITY frame (RFC-7540 6.3)
 * Start of HEADERS frame IF the priority flag is set (RFC-7540 6.2)
 *  +-+-------------+-----------------------------------------------+
 *  |E|                 Stream Dependency (31)                      |
 *  +-+-------------+-----------------------------------------------+
 *  |  Weight (8)   |
 *  +-+-------------+-----------------------------------------------+
 */
static int s_state_fn_priority_block(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_priority_block_requires_5_bytes);

    /* #NOTE: throw priority data on the GROUND. They make us hecka vulnerable to DDoS and stuff.
     * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9513
     */
    aws_byte_cursor_advance(input, s_state_priority_block_requires_5_bytes);

    decoder->frame_in_progress.payload_len -= s_state_priority_block_requires_5_bytes;

    return s_decoder_switch_to_frame_state(decoder);
}

static int s_state_fn_frame_data(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    const struct aws_byte_cursor body_data = s_decoder_get_payload(decoder, input);
    if (body_data.len) {
        DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_data, body_data);
    }

    if (decoder->frame_in_progress.payload_len == 0) {
        /* If frame had END_STREAM flag, alert user now */
        if (decoder->frame_in_progress.flags.end_stream) {
            DECODER_CALL_VTABLE_STREAM(decoder, on_end_stream);
        }

        /* Process padding if necessary, otherwise we're done! */
        return s_decoder_switch_state(decoder, &s_state_padding);
    }

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_headers(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    /* Start header-block and alert the user */
    decoder->header_block_in_progress.stream_id = decoder->frame_in_progress.stream_id;
    decoder->header_block_in_progress.is_push_promise = false;
    decoder->header_block_in_progress.ends_stream = decoder->frame_in_progress.flags.end_stream;

    DECODER_CALL_VTABLE_STREAM(decoder, on_headers_begin);

    /* Read the header-block fragment */
    return s_decoder_switch_state(decoder, &s_state_header_block_loop);
}
static int s_state_fn_frame_priority(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    /* We already processed this data in the shared priority_block state, so we're done! */
    return s_decoder_reset_state(decoder);
}

/*  RST_STREAM is just a 4-byte error code.
 *  +---------------------------------------------------------------+
 *  |                        Error Code (32)                        |
 *  +---------------------------------------------------------------+
 */
static int s_state_fn_frame_rst_stream(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_frame_rst_stream_requires_4_bytes);

    uint32_t error_code = 0;
    bool succ = aws_byte_cursor_read_be32(input, &error_code);
    AWS_ASSERT(succ);
    (void)succ;

    decoder->frame_in_progress.payload_len -= s_state_frame_rst_stream_requires_4_bytes;

    DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_rst_stream, error_code);

    return s_decoder_reset_state(decoder);
}

/* A SETTINGS frame may contain any number of 6-byte entries.
 * This state consumes no data, but sends us into the appropriate next state */
static int s_state_fn_frame_settings_begin(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    /* If ack is set, report and we're done */
    if (decoder->frame_in_progress.flags.ack) {
        /* Receipt of a SETTINGS frame with the ACK flag set and a length field value other
         * than 0 MUST be treated as a connection error of type FRAME_SIZE_ERROR */
        if (decoder->frame_in_progress.payload_len) {
            DECODER_LOGF(
                ERROR,
                decoder,
                "SETTINGS ACK frame received, but it has non-0 payload length %" PRIu32,
                decoder->frame_in_progress.payload_len);
            return aws_raise_error(AWS_ERROR_HTTP_INVALID_FRAME_SIZE);
        }

        DECODER_CALL_VTABLE(decoder, on_settings_ack);
        return s_decoder_reset_state(decoder);
    }

    if (decoder->frame_in_progress.payload_len % s_state_frame_settings_i_requires_6_bytes != 0) {
        /* A SETTINGS frame with a length other than a multiple of 6 octets MUST be
         * treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR */
        DECODER_LOGF(
            ERROR,
            decoder,
            "Settings frame payload length is %" PRIu32 ", but it must be divisible by %" PRIu32,
            decoder->frame_in_progress.payload_len,
            s_state_frame_settings_i_requires_6_bytes);
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_FRAME_SIZE);
    }

    /* Report start of non-ACK settings frame */
    DECODER_CALL_VTABLE(decoder, on_settings_begin);

    /* Enter looping states until all entries are consumed. */
    return s_decoder_switch_state(decoder, &s_state_frame_settings_loop);
}

/* Check if we're done consuming settings */
static int s_state_fn_frame_settings_loop(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    if (decoder->frame_in_progress.payload_len == 0) {
        /* Huzzah, done with the frame */
        DECODER_CALL_VTABLE(decoder, on_settings_end);
        return s_decoder_reset_state(decoder);
    }

    return s_decoder_switch_state(decoder, &s_state_frame_settings_i);
}

/* Each run through this state consumes one 6-byte setting.
 * There may be multiple settings in a SETTINGS frame.
 *  +-------------------------------+
 *  |       Identifier (16)         |
 *  +-------------------------------+-------------------------------+
 *  |                        Value (32)                             |
 *  +---------------------------------------------------------------+
 */
static int s_state_fn_frame_settings_i(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_frame_settings_i_requires_6_bytes);

    uint16_t id = 0;
    uint32_t value = 0;

    bool succ = aws_byte_cursor_read_be16(input, &id);
    AWS_ASSERT(succ);
    (void)succ;

    succ = aws_byte_cursor_read_be32(input, &value);
    AWS_ASSERT(succ);
    (void)succ;

    /* An endpoint that receives a SETTINGS frame with any unknown or unsupported identifier MUST ignore that setting.
     * RFC-7540 6.5.2 */
    if (id >= AWS_H2_SETTINGS_BEGIN_RANGE && id < AWS_H2_SETTINGS_END_RANGE) {
        DECODER_CALL_VTABLE_ARGS(decoder, on_settings_i, id, value);
    }

    /* Update payload len */
    decoder->frame_in_progress.payload_len -= s_state_frame_settings_i_requires_6_bytes;

    return s_decoder_switch_state(decoder, &s_state_frame_settings_loop);
}

/* Read 4-byte Promised Stream ID
 * The rest of the frame is just like HEADERS, so move on to shared states...
 *  +-+-------------------------------------------------------------+
 *  |R|                  Promised Stream ID (31)                    |
 *  +-+-----------------------------+-------------------------------+
 */
static int s_state_fn_frame_push_promise(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_frame_push_promise_requires_4_bytes);

    uint32_t promised_stream_id = 0;
    bool succ = aws_byte_cursor_read_be32(input, &promised_stream_id);
    AWS_ASSERT(succ);
    (void)succ;

    decoder->frame_in_progress.payload_len -= s_state_frame_push_promise_requires_4_bytes;

    /* Reserved bit (top bit) must be ignored when receiving (RFC-7540 4.1) */
    promised_stream_id &= s_31_bit_mask;

    /* Promised stream ID must not be 0 (RFC-7540 6.6) */
    if (promised_stream_id == 0) {
        DECODER_LOGF(ERROR, decoder, "PUSH_PROMISE is promising invalid stream ID %" PRIu32, promised_stream_id);
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    /* Start header-block and alert the user. */
    decoder->header_block_in_progress.stream_id = decoder->frame_in_progress.stream_id;
    decoder->header_block_in_progress.is_push_promise = true;
    decoder->header_block_in_progress.ends_stream = false;

    DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_push_promise_begin, promised_stream_id);

    /* Read the header-block fragment */
    return s_decoder_switch_state(decoder, &s_state_header_block_loop);
}

/* PING frame is just 8-bytes of opaque data.
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                      Opaque Data (64)                         |
 *  |                                                               |
 *  +---------------------------------------------------------------+
 */
static int s_state_fn_frame_ping(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_frame_ping_requires_8_bytes);

    uint8_t opaque_data[AWS_H2_PING_DATA_SIZE] = {0};
    bool succ = aws_byte_cursor_read(input, &opaque_data, AWS_H2_PING_DATA_SIZE);
    AWS_ASSERT(succ);
    (void)succ;

    decoder->frame_in_progress.payload_len -= s_state_frame_ping_requires_8_bytes;

    if (decoder->frame_in_progress.flags.ack) {
        DECODER_CALL_VTABLE_ARGS(decoder, on_ping_ack, opaque_data);
    } else {
        DECODER_CALL_VTABLE_ARGS(decoder, on_ping, opaque_data);
    }

    return s_decoder_reset_state(decoder);
}

/* Read first 8 bytes of GOAWAY.
 * This may be followed by N bytes of debug data.
 *  +-+-------------------------------------------------------------+
 *  |R|                  Last-Stream-ID (31)                        |
 *  +-+-------------------------------------------------------------+
 *  |                      Error Code (32)                          |
 *  +---------------------------------------------------------------+
 */
static int s_state_fn_frame_goaway(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_frame_goaway_requires_8_bytes);

    uint32_t last_stream = 0;
    uint32_t error_code = AWS_H2_ERR_NO_ERROR;

    bool succ = aws_byte_cursor_read_be32(input, &last_stream);
    AWS_ASSERT(succ);
    (void)succ;

    last_stream &= s_31_bit_mask;

    succ = aws_byte_cursor_read_be32(input, &error_code);
    AWS_ASSERT(succ);
    (void)succ;

    decoder->frame_in_progress.payload_len -= s_state_frame_goaway_requires_8_bytes;

    DECODER_CALL_VTABLE_ARGS(decoder, on_goaway_begin, last_stream, error_code, decoder->frame_in_progress.payload_len);

    return s_decoder_switch_state(decoder, &s_state_frame_goaway_debug_data);
}

/* Optional remainder of GOAWAY frame.
 *  +---------------------------------------------------------------+
 *  |                  Additional Debug Data (*)                    |
 *  +---------------------------------------------------------------+
 */
static int s_state_fn_frame_goaway_debug_data(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    struct aws_byte_cursor debug_data = s_decoder_get_payload(decoder, input);
    if (debug_data.len > 0) {
        DECODER_CALL_VTABLE_ARGS(decoder, on_goaway_i, debug_data);
    }

    /* If this is the last data in the frame, reset decoder */
    if (decoder->frame_in_progress.payload_len == 0) {
        DECODER_CALL_VTABLE(decoder, on_goaway_end);
        return s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}

/* WINDOW_UPDATE frame.
 *  +-+-------------------------------------------------------------+
 *  |R|              Window Size Increment (31)                     |
 *  +-+-------------------------------------------------------------+
 */
static int s_state_fn_frame_window_update(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_ASSERT(input->len >= s_state_frame_window_update_requires_4_bytes);

    uint32_t window_increment = 0;
    bool succ = aws_byte_cursor_read_be32(input, &window_increment);
    AWS_ASSERT(succ);
    (void)succ;

    decoder->frame_in_progress.payload_len -= s_state_frame_window_update_requires_4_bytes;

    window_increment &= s_31_bit_mask;

    DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_window_update, window_increment);

    return s_decoder_reset_state(decoder);
}

/* CONTINUATION is a lot like HEADERS, so it uses shared states. */
static int s_state_fn_frame_continuation(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    /* Read the header-block fragment */
    return s_decoder_switch_state(decoder, &s_state_header_block_loop);
}

/* Implementations MUST ignore and discard any frame that has a type that is unknown. */
static int s_state_fn_frame_unknown(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    /* Read all data possible, and throw it on the floor */
    s_decoder_get_payload(decoder, input);

    /* If there's no more data expected, end the frame */
    if (decoder->frame_in_progress.payload_len == 0) {
        return s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}

/* This state checks whether we've consumed the current frame's entire header-block fragment.
 * We revisit this state after each entry is decoded.
 * This state consumes no data. */
static int s_state_fn_header_block_loop(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    /* If we're out of payload data, handle frame complete */
    if (decoder->frame_in_progress.payload_len == 0) {

        /* If this is the end of the header-block, invoke callback and clear header_block_in_progress */
        if (decoder->frame_in_progress.flags.end_headers) {
            DECODER_LOG(TRACE, decoder, "Done decoding header-block");

            if (decoder->header_block_in_progress.is_push_promise) {
                DECODER_CALL_VTABLE_STREAM(decoder, on_push_promise_end);
            } else {
                DECODER_CALL_VTABLE_STREAM(decoder, on_headers_end);
            }

            /* If header-block began with END_STREAM flag, alert user now */
            if (decoder->header_block_in_progress.ends_stream) {
                DECODER_CALL_VTABLE_STREAM(decoder, on_end_stream);
            }

            AWS_ZERO_STRUCT(decoder->header_block_in_progress);

        } else {
            DECODER_LOG(TRACE, decoder, "Done decoding header-block fragment, expecting CONTINUATION frames");
        }

        /* Finish this frame */
        return s_decoder_switch_state(decoder, &s_state_padding);
    }

    DECODER_LOGF(
        TRACE,
        decoder,
        "Decoding header-block entry, %" PRIu32 " bytes remaining in payload",
        decoder->frame_in_progress.payload_len);

    return s_decoder_switch_state(decoder, &s_state_header_block_entry);
}

/* We stay in this state until a single "entry" is decoded from the header-block fragment.
 * Then we return to the header_block_loop state */
static int s_state_fn_header_block_entry(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    /* This state requires at least 1 byte, but will likely consume more */
    AWS_ASSERT(input->len >= s_state_header_block_entry_requires_1_bytes);

    /* Feed header-block fragment to HPACK decoder.
     * Don't let decoder consume anything beyond payload_len. */
    struct aws_byte_cursor fragment = *input;
    if (fragment.len > decoder->frame_in_progress.payload_len) {
        fragment.len = decoder->frame_in_progress.payload_len;
    }

    const size_t prev_fragment_len = fragment.len;

    struct aws_hpack_decode_result result;
    if (aws_hpack_decode(decoder->hpack, &fragment, &result)) {
        DECODER_LOGF(ERROR, decoder, "Error decoding header-block fragment: %s", aws_error_name(aws_last_error()));

        /* Any possible error from HPACK decoder is treated as a COMPRESSION error */
        return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    /* HPACK decoder returns when it reaches the end of an entry, or when it's consumed the whole fragment.
     * Update input & payload_len to reflect the number of bytes consumed. */
    const size_t bytes_consumed = prev_fragment_len - fragment.len;
    aws_byte_cursor_advance(input, bytes_consumed);
    decoder->frame_in_progress.payload_len -= (uint32_t)bytes_consumed;

    if (result.type == AWS_HPACK_DECODE_T_ONGOING) {
        /* HPACK decoder hasn't finished entry */

        if (decoder->frame_in_progress.payload_len > 0) {
            /* More payload is coming. Remain in state until it arrives */
            DECODER_LOG(TRACE, decoder, "Header-block entry partially decoded, waiting for more data.");
            return AWS_OP_SUCCESS;
        }

        if (decoder->frame_in_progress.flags.end_headers) {
            /* Reached end of the frame's payload, and this frame ends the header-block.
             * Error if we ended up with a partially decoded entry. */
            DECODER_LOG(ERROR, decoder, "Compression error: incomplete entry at end of header-block");
            return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
        }

        /* Reached end of this frame's payload, but CONTINUATION frames are expected to arrive.
         * We'll resume decoding this entry when we get them. */
        DECODER_LOG(TRACE, decoder, "Header-block entry partially decoded, resumes in CONTINUATION frame");
        return s_decoder_switch_state(decoder, &s_state_header_block_loop);
    }

    /* Finished decoding HPACK entry! */

    /* #TODO Enforces dynamic table resize rules from RFC-7541 4.2
     * If dynamic table size changed via SETTINGS frame, next header-block must start with DYNAMIC_TABLE_RESIZE entry.
     * Is it illegal to receive a resize entry at other times? */

    /* #TODO Enforce pseudo-header rules from RFC-7540 8.1.2.1
     * - request must have specific pseudo-headers and can't have response ones, and vice-versa
     * - pseudo-headers must precede normal headers
     * - pseudo-headers must not appear in trailer
     * - can't have unrecognized/invalid pseudo-headers
     * These make the message "malformed", which is a STREAM error, not PROTOCOL error, not sure how to handle that */

    /* #TODO Cookie headers must be concatenated into single delivery RFC-7540 8.1.2.5 */

    if (result.type == AWS_HPACK_DECODE_T_HEADER_FIELD) {
        const struct aws_http_header *header_field = &result.data.header_field;

        DECODER_LOGF(
            TRACE,
            decoder,
            "Decoded header field: \"" PRInSTR ": " PRInSTR "\"",
            AWS_BYTE_CURSOR_PRI(header_field->name),
            AWS_BYTE_CURSOR_PRI(header_field->value));

        if (decoder->header_block_in_progress.is_push_promise) {
            DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_push_promise_i, header_field);
        } else {
            DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_headers_i, header_field);
        }
    }

    return s_decoder_switch_state(decoder, &s_state_header_block_loop);
}

/* The first thing a client sends on a connection is a 24 byte magic string (RFC-7540 3.5).
 * Note that this state doesn't "require" the full 24 bytes, it runs as data arrives.
 * This avoids hanging if < 24 bytes rolled in. */
static int s_state_fn_connection_preface_string(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    size_t remaining_len = decoder->connection_preface_cursor.len;
    size_t consuming_len = input->len < remaining_len ? input->len : remaining_len;

    struct aws_byte_cursor expected = aws_byte_cursor_advance(&decoder->connection_preface_cursor, consuming_len);

    struct aws_byte_cursor received = aws_byte_cursor_advance(input, consuming_len);

    if (!aws_byte_cursor_eq(&expected, &received)) {
        DECODER_LOG(ERROR, decoder, "Client connection preface is invalid");
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    if (decoder->connection_preface_cursor.len == 0) {
        /* Done receiving connection preface string, proceed to decoding normal frames. */
        return s_decoder_reset_state(decoder);
    }

    /* Remain in state until more data arrives */
    return AWS_OP_SUCCESS;
}
