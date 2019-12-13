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

static const size_t s_scratch_space_size = 512;

/* Stream ids & dependencies should only write the bottom 31 bits */
static const uint32_t s_31_bit_mask = UINT32_MAX >> 1;

/* The size of each id: value pair in a settings frame */
static const uint8_t s_setting_block_size = sizeof(uint16_t) + sizeof(uint32_t);

#define DECODER_LOGF(level, decoder, text, ...)                                                                        \
    AWS_LOGF_##level(AWS_LS_HTTP_DECODER, "id=%p " text, (decoder)->logging_id, __VA_ARGS__)
#define DECODER_LOG(level, decoder, text) DECODER_LOGF(level, decoder, "%s", text)

#define DECODER_CALL_VTABLE(decoder, fn)                                                                               \
    do {                                                                                                               \
        if ((decoder)->vtable.fn) {                                                                                    \
            DECODER_LOG(DEBUG, decoder, "Calling user callback " #fn)                                                  \
            (decoder)->vtable.fn((decoder)->userdata);                                                                 \
        }                                                                                                              \
    } while (false)
#define DECODER_CALL_VTABLE_ARGS(decoder, fn, ...)                                                                     \
    do {                                                                                                               \
        if ((decoder)->vtable.fn) {                                                                                    \
            DECODER_LOG(DEBUG, decoder, "Calling user callback " #fn)                                                  \
            (decoder)->vtable.fn(__VA_ARGS__, (decoder)->userdata);                                                    \
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
    static const struct decoder_state s_state_##_name = {                                                              \
        .fn = s_state_fn_##_name,                                                                                      \
        .bytes_required = (_bytes_required),                                                                           \
        .name = #_name,                                                                                                \
    }

/* Common states */
DEFINE_STATE(header, 9);
DEFINE_STATE(padding_len, 1);
DEFINE_STATE(padding, 0);

DEFINE_STATE(priority_block, 5);

/* Frame-specific states */
DEFINE_STATE(frame_data, 0);
DEFINE_STATE(frame_headers, 0);
DEFINE_STATE(frame_priority, 0);
DEFINE_STATE(frame_rst_stream, 4);
DEFINE_STATE(frame_settings_begin, 0);
DEFINE_STATE(frame_settings, 6);
DEFINE_STATE(frame_push_promise, 4);
DEFINE_STATE(frame_ping, 8);
DEFINE_STATE(frame_goaway, 8);
DEFINE_STATE(frame_goaway_debug_data, 0);
DEFINE_STATE(frame_window_update, 4);
DEFINE_STATE(frame_continuation, 0);
DEFINE_STATE(frame_unknown, 0);

/* Header-block states (NOTE: all of these states are streaming states) */
DEFINE_STATE(headers_begin, 0);
DEFINE_STATE(headers_indexed, 0);
DEFINE_STATE(headers_literal_index, 0);
DEFINE_STATE(headers_literal_name, 0);
DEFINE_STATE(headers_literal_value, 0);
DEFINE_STATE(headers_dyn_table_resize, 0);

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
    void *logging_id;
    struct aws_hpack_context *hpack;

    struct aws_byte_buf scratch;
    struct decoder_state state;

    /* Packet-in-progress */
    struct {
        enum aws_h2_frame_type type;
        uint32_t stream_id;
        uint32_t payload_len;
        uint8_t padding_len;

        /* Flags */
        bool ack;
        bool end_stream;
        bool end_headers;
        bool priority;
    } frame_in_progress;

    union {
        struct h2_header_progress_indexed {
            uint64_t index;
        } indexed;
        struct h2_header_progress_literal {
            uint8_t payload_len_prefix;
            uint64_t index;
            enum aws_h2_header_field_hpack_behavior hpack_behavior;
            struct aws_http_header header;
            size_t value_offset;
        } literal;
        struct {
            uint64_t new_size;
        } dyn_table_resize;
    } header_in_progress;

    /* User callbacks and settings. */
    struct aws_h2_decoder_vtable vtable;
    void *userdata;

    /* If this is set to true, decode may no longer be called */
    bool has_errored;
};

/***********************************************************************************************************************
 * Public API
 **********************************************************************************************************************/

static void s_decoder_reset_state(struct aws_h2_decoder *decoder);

struct aws_h2_decoder *aws_h2_decoder_new(struct aws_h2_decoder_params *params) {
    AWS_PRECONDITION(params);
    (void)params;

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

    decoder->scratch = aws_byte_buf_from_array(scratch_buf, s_scratch_space_size);

    decoder->hpack = aws_hpack_context_new(params->alloc, AWS_LS_HTTP_DECODER, decoder);
    if (!decoder->hpack) {
        goto failed_new_hpack;
    }

    AWS_ZERO_STRUCT(decoder->state);
    decoder->state.name = "<NONE>";
    s_decoder_reset_state(decoder);

    return decoder;

failed_new_hpack:
    aws_mem_release(params->alloc, allocation);
failed_alloc:
    return NULL;
}

void aws_h2_decoder_destroy(struct aws_h2_decoder *decoder) {
    aws_hpack_context_destroy(decoder->hpack);
    aws_mem_release(decoder->alloc, decoder);
}

int aws_h2_decode(struct aws_h2_decoder *decoder, struct aws_byte_cursor *data) {
    AWS_PRECONDITION(decoder);
    AWS_PRECONDITION(data);

    AWS_FATAL_ASSERT(!decoder->has_errored);

    int err = AWS_ERROR_SUCCESS;

    while (data->len) {
        const uint32_t bytes_required = decoder->state.bytes_required;
        if (!decoder->scratch.len && data->len >= bytes_required) {
            /* Easy case, there is no scratch and we have enough data, so just send it to the state */

            const char *current_state_name = decoder->state.name;
            const size_t pre_state_data_len = data->len;
            (void)pre_state_data_len;

            DECODER_LOGF(
                TRACE,
                decoder,
                "Skipping scratch and running state %s with %zu bytes available",
                current_state_name,
                data->len);

            err = decoder->state.fn(decoder, data);
            if (err) {
                goto handle_error;
            }

            AWS_ASSERT(
                (bytes_required == 0 || pre_state_data_len - data->len >= bytes_required) &&
                "Decoder state requested more data than it used");
        } else {
            /* In every other case, we have to copy to scratch */
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

            /* Root state to run, not used for anything, but can be useful for debugging */
            const char *current_state_name = decoder->state.name;

            /* If we have the correct number of bytes, call the state */
            if (will_finish_state) {

                DECODER_LOGF(TRACE, decoder, "Enough bytes now available, running state %s", current_state_name);

                struct aws_byte_cursor state_data = aws_byte_cursor_from_buf(&decoder->scratch);
                err = decoder->state.fn(decoder, &state_data);
                if (err) {
                    goto handle_error;
                }

                AWS_ASSERT(state_data.len == 0 && "Decoder state requested more data than it used");
            } else {
                DECODER_LOGF(
                    TRACE,
                    decoder,
                    "State %s requires %" PRIu32 " bytes, but only %zu available, trying again later",
                    current_state_name,
                    bytes_required,
                    decoder->scratch.len);
            }
        }
    }

    return AWS_OP_SUCCESS;

handle_error:
    decoder->has_errored = true;
    return err;
}

void aws_h2_decoder_set_logging_id(struct aws_h2_decoder *decoder, void *id) {
    decoder->logging_id = id;
}

/* Wrap hpack functions to do payload length checks */
static enum aws_hpack_decode_status s_decode_integer(
    struct aws_h2_decoder *decoder,
    struct aws_byte_cursor *input,
    uint8_t prefix_size,
    uint64_t *integer) {

    if (decoder->frame_in_progress.payload_len == 0) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    const size_t pre_decode_input_len = input->len;
    const enum aws_hpack_decode_status status = aws_hpack_decode_integer(decoder->hpack, input, prefix_size, integer);
    const size_t decoded_len = pre_decode_input_len - input->len;

    if (decoded_len > decoder->frame_in_progress.payload_len) {
        DECODER_LOGF(
            ERROR,
            decoder,
            "HPACK integer decoding decoded more data than was available '%s'",
            aws_error_debug_str(aws_last_error()));

        return AWS_HPACK_DECODE_ERROR;
    }
    decoder->frame_in_progress.payload_len -= (uint32_t)decoded_len;

    return status;
}
static enum aws_hpack_decode_status s_decode_string(
    struct aws_h2_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output) {

    if (decoder->frame_in_progress.payload_len == 0) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    const size_t pre_decode_input_len = input->len;
    const enum aws_hpack_decode_status status = aws_hpack_decode_string(decoder->hpack, input, output);
    const size_t decoded_len = pre_decode_input_len - input->len;

    if (decoded_len > decoder->frame_in_progress.payload_len) {
        DECODER_LOGF(
            ERROR,
            decoder,
            "HPACK integer decoding decoded more data than was available '%s'",
            aws_error_debug_str(aws_last_error()));

        return AWS_HPACK_DECODE_ERROR;
    }
    decoder->frame_in_progress.payload_len -= (uint32_t)decoded_len;

    return status;
}

/***********************************************************************************************************************
 * State functions
 **********************************************************************************************************************/

static void s_decoder_set_state(struct aws_h2_decoder *decoder, const struct decoder_state *state) {
    DECODER_LOGF(TRACE, decoder, "Moving from state %s to %s", decoder->state.name, state->name);

    decoder->scratch.len = 0;
    decoder->state = *state;
}

static void s_decoder_go_to_frame_state(struct aws_h2_decoder *decoder) {
    AWS_ASSERT(decoder->frame_in_progress.type <= AWS_H2_FRAME_T_UNKNOWN);
    s_decoder_set_state(decoder, s_state_frames[decoder->frame_in_progress.type]);
}

static void s_decoder_reset_state(struct aws_h2_decoder *decoder) {
    s_decoder_set_state(decoder, &s_state_header);

    DECODER_LOG(TRACE, decoder, "Resetting frame in progress");
    AWS_ZERO_STRUCT(decoder->frame_in_progress);
}

/** Returns as much of the current frame's payload as possible, and updates payload_len */
static struct aws_byte_cursor s_decoder_get_payload(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    struct aws_byte_cursor result;

    const uint32_t remaining_length = decoder->frame_in_progress.payload_len;
    if (input->len < remaining_length) {
        AWS_FATAL_ASSERT(input->len <= UINT32_MAX);
        result = aws_byte_cursor_advance(input, input->len);
        decoder->frame_in_progress.payload_len -= (uint32_t)input->len;
    } else {
        result = aws_byte_cursor_advance(input, remaining_length);
        decoder->frame_in_progress.payload_len = 0;
    }

    return result;
}

static int s_state_fn_header(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 9);

    uint32_t payload_len = 0;
    uint8_t *length_ptr = ((uint8_t *)&payload_len);

    /* Read the first 3 bytes */
    bool succ = aws_byte_cursor_read(input, length_ptr, 3);
    AWS_ASSERT(succ);
    (void)succ;

    /* Reverse from network order */
    payload_len = aws_ntoh24(payload_len);
    /* Assert top byte isn't set */
    AWS_FATAL_ASSERT((payload_len & 0xFF000000) == 0);

    /* #TODO handle the SETTINGS_MAX_FRAME_SIZE setting */
    static const uint32_t MAX_FRAME_SIZE = 16384;
    if (payload_len > MAX_FRAME_SIZE) {
        DECODER_LOGF(
            ERROR,
            decoder,
            "Decoder's max frame size is %" PRIu32 ", but frame of size %" PRIu32 " was received.",
            MAX_FRAME_SIZE,
            payload_len);
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_FRAME_SIZE);
    }

    /* Commit */
    decoder->frame_in_progress.payload_len = payload_len;

    /* Read the frame type */
    uint8_t frame_type = 0;
    succ = aws_byte_cursor_read_u8(input, &frame_type);
    AWS_ASSERT(succ);
    (void)succ;

    /* Validate frame type */
    if (frame_type > AWS_H2_FRAME_T_UNKNOWN) {
        frame_type = AWS_H2_FRAME_T_UNKNOWN;
    }
    decoder->frame_in_progress.type = frame_type;

    /* Read the frame's flags */
    uint8_t flags = 0;
    succ = aws_byte_cursor_read_u8(input, &flags);
    AWS_ASSERT(succ);
    (void)succ;

    /* Ensure this frame is allowed to be padded */
    uint8_t acceptable_flags = 0;
    switch (frame_type) {
        case AWS_H2_FRAME_T_DATA:
            acceptable_flags = AWS_H2_FRAME_F_END_STREAM | AWS_H2_FRAME_F_PADDED;
            break;
        case AWS_H2_FRAME_T_HEADERS:
            acceptable_flags = AWS_H2_FRAME_F_END_STREAM | AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PADDED |
                               AWS_H2_FRAME_T_PRIORITY;
            break;
        case AWS_H2_FRAME_T_PUSH_PROMISE:
            acceptable_flags = AWS_H2_FRAME_F_END_HEADERS | AWS_H2_FRAME_F_PADDED;
            break;
        case AWS_H2_FRAME_T_SETTINGS:
        case AWS_H2_FRAME_T_PING:
            acceptable_flags = AWS_H2_FRAME_F_ACK;
            break;
        case AWS_H2_FRAME_T_CONTINUATION:
            acceptable_flags = AWS_H2_FRAME_F_END_HEADERS;
            break;
        case AWS_H2_FRAME_T_UNKNOWN:
            /* Don't actually do anything with unknown frame flags */
            flags = 0;
            break;
        default:
            /* PRIORITY, RST_STREAM, GOAWAY, WINDOW_UPDATE dont have any flags */
            break;
    }

    /* Validate the flags */
    if (flags & ~acceptable_flags) {
        DECODER_LOGF(
            ERROR, decoder, "Frame type %s has invalid flags %" PRIu8, aws_h2_frame_type_to_str(frame_type), flags);
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    /* Don't store is_padded on the decoder so that other states must check padding_len instead */
    bool is_padded = false;
    if (flags & AWS_H2_FRAME_F_ACK) {
        decoder->frame_in_progress.ack = true;
    }
    if (flags & AWS_H2_FRAME_F_END_STREAM) {
        decoder->frame_in_progress.end_stream = true;
    }
    if (flags & AWS_H2_FRAME_F_END_HEADERS) {
        decoder->frame_in_progress.end_headers = true;
    }
    if (flags & AWS_H2_FRAME_F_PADDED) {
        is_padded = true;
    }
    if (frame_type == AWS_H2_FRAME_T_PRIORITY || flags & AWS_H2_FRAME_F_PRIORITY) {
        decoder->frame_in_progress.priority = true;
    }

    uint32_t stream_id = 0;
    succ = aws_byte_cursor_read_be32(input, &stream_id);
    AWS_ASSERT(succ);
    (void)succ;

    /* Discard top bit */
    decoder->frame_in_progress.stream_id = stream_id & s_31_bit_mask;

    DECODER_LOGF(
        TRACE,
        decoder,
        "Done decoding frame header, beginning to process body of frame (stream id=%" PRIu32 " payload len=%" PRIu32
        ")",
        decoder->frame_in_progress.stream_id,
        decoder->frame_in_progress.payload_len);

    if (is_padded) {

        /* Read padding length if necessary */
        s_decoder_set_state(decoder, &s_state_padding_len);
    } else if (decoder->frame_in_progress.priority) {

        /* Read the stream dependency and weight if PRIORITY is set */
        s_decoder_set_state(decoder, &s_state_priority_block);
    } else {

        /* Set the state to the appropriate frame's state */
        s_decoder_go_to_frame_state(decoder);
    }

    return AWS_OP_SUCCESS;
}

static int s_state_fn_padding_len(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 1);

    /* Read the padding length */
    bool succ = aws_byte_cursor_read_u8(input, &decoder->frame_in_progress.padding_len);
    AWS_ASSERT(succ);
    (void)succ;

    /* Adjust payload size */
    decoder->frame_in_progress.payload_len -= decoder->frame_in_progress.padding_len;

    DECODER_LOGF(TRACE, decoder, "Padding length of frame: %" PRIu32, decoder->frame_in_progress.padding_len);

    if (decoder->frame_in_progress.priority) {
        /* Read the stream dependency and weight if PRIORITY is set */
        s_decoder_set_state(decoder, &s_state_priority_block);
    } else {
        /* Set the state to the appropriate frame's state */
        s_decoder_go_to_frame_state(decoder);
    }

    return AWS_OP_SUCCESS;
}

static int s_state_fn_padding(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    const uint8_t padding_len = decoder->frame_in_progress.padding_len;
    bool will_finish_state = false;
    if (input->len >= padding_len) {
        will_finish_state = true;
        aws_byte_cursor_advance(input, padding_len);
    } else {
        AWS_FATAL_ASSERT(input->len <= UINT8_MAX);
        decoder->frame_in_progress.padding_len -= (uint8_t)input->len;
        aws_byte_cursor_advance(input, input->len);
    }

    if (will_finish_state) {
        /* Done with the frame! */
        s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}

static int s_state_fn_priority_block(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 5);

    /* Read the top 4 bytes */
    uint32_t top_bytes = 0;
    bool succ = aws_byte_cursor_read_be32(input, &top_bytes);
    AWS_ASSERT(succ);
    (void)succ;

    /* Write the priority weight */
    uint8_t weight = 0;
    succ = aws_byte_cursor_read_u8(input, &weight);
    AWS_ASSERT(succ);
    (void)succ;

    /* #NOTE: throw priority data on the GROUND. They make us hecka vulnerable to DDoS and stuff.
     * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9513
     */

    s_decoder_go_to_frame_state(decoder);

    return AWS_OP_SUCCESS;
}

static int s_state_fn_frame_data(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    const struct aws_byte_cursor body_data = s_decoder_get_payload(decoder, input);
    if (body_data.len) {
        DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_data, &body_data);
    }

    if (decoder->frame_in_progress.payload_len == 0) {
        /* Process padding if necessary, otherwise we're done! */
        s_decoder_set_state(decoder, &s_state_padding);
    }

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_headers(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    /* Read the headers block */
    s_decoder_set_state(decoder, &s_state_headers_begin);

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_priority(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    /* No data to process here, we're done! */
    s_decoder_reset_state(decoder);

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_rst_stream(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 4);

    uint32_t error_code = 0;
    bool succ = aws_byte_cursor_read_be32(input, &error_code);
    AWS_ASSERT(succ);
    (void)succ;

    DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_rst_stream, error_code);

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_settings_begin(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    /* If ack is set, report and abort */
    if (decoder->frame_in_progress.ack) {
        if (decoder->frame_in_progress.payload_len) {
            DECODER_LOGF(
                ERROR,
                decoder,
                "SETTINGS ACK frame received, but it has non-0 payload length %" PRIu32,
                decoder->frame_in_progress.payload_len);
            return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
        }

        DECODER_CALL_VTABLE(decoder, on_settings_ack);
        s_decoder_reset_state(decoder);
        return AWS_OP_SUCCESS;
    }

    if (decoder->frame_in_progress.payload_len % s_setting_block_size != 0) {
        /* Leftover data is not divisible by 6, error */
        DECODER_LOGF(
            ERROR,
            decoder,
            "Settings frame payload length is %" PRIu32 ", but it must be divisible by %" PRIu8,
            decoder->frame_in_progress.payload_len,
            s_setting_block_size);
        return aws_raise_error(AWS_ERROR_HTTP_PROTOCOL_ERROR);
    }

    /* If we've made it this far, we have a non-ACK settings frame with a valid payload length */
    s_decoder_set_state(decoder, &s_state_frame_settings);

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_settings(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 6);

    /* Truck through the list until we run out of space */
    while (input->len >= s_setting_block_size) {
        uint16_t id = 0;
        uint32_t value = 0;

        bool succ = aws_byte_cursor_read_be16(input, &id);
        AWS_ASSERT(succ);
        (void)succ;

        succ = aws_byte_cursor_read_be32(input, &value);
        AWS_ASSERT(succ);
        (void)succ;

        DECODER_CALL_VTABLE_ARGS(decoder, on_setting, id, value);

        /* Update payload len */
        decoder->frame_in_progress.payload_len -= s_setting_block_size;
    }

    if (decoder->frame_in_progress.payload_len == 0) {

        /* Huzzah, done with the frame */
        s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_push_promise(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 4);

    uint32_t promised_stream_id = 0;
    bool succ = aws_byte_cursor_read_be32(input, &promised_stream_id);
    AWS_FATAL_ASSERT(succ);
    decoder->frame_in_progress.payload_len -= 4;

    /* Remove top bit */
    promised_stream_id &= s_31_bit_mask;

    /* Alert the user */
    DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_push_promise, promised_stream_id);

    /* Update the stream id of the decoder so that future on_header and on_end_headers calls use the promised id */
    decoder->frame_in_progress.stream_id = promised_stream_id;

    /* Read the headers block */
    s_decoder_set_state(decoder, &s_state_headers_begin);

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_ping(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 8);

    uint8_t opaque_data[8] = {0};
    bool succ = aws_byte_cursor_read(input, &opaque_data, AWS_ARRAY_SIZE(opaque_data));
    AWS_ASSERT(succ);
    (void)succ;

    DECODER_CALL_VTABLE_ARGS(decoder, on_ping, decoder->frame_in_progress.ack, opaque_data);

    s_decoder_reset_state(decoder);

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_goaway(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 8);

    uint32_t last_stream = 0;
    uint32_t error_code = AWS_H2_ERR_NO_ERROR;

    bool succ = aws_byte_cursor_read_be32(input, &last_stream);
    AWS_ASSERT(succ);
    (void)succ;

    last_stream &= s_31_bit_mask;

    succ = aws_byte_cursor_read_be32(input, &error_code);
    AWS_ASSERT(succ);
    (void)succ;

    decoder->frame_in_progress.payload_len -= 8;

    DECODER_CALL_VTABLE_ARGS(decoder, on_goaway, last_stream, decoder->frame_in_progress.payload_len, error_code);

    if (decoder->frame_in_progress.payload_len) {
        s_decoder_set_state(decoder, &s_state_frame_goaway_debug_data);
    } else {
        s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_goaway_debug_data(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    struct aws_byte_cursor debug_data = s_decoder_get_payload(decoder, input);
    DECODER_CALL_VTABLE_ARGS(decoder, on_goaway_debug_data, &debug_data);

    /* This is the last data in the frame, so reset decoder */
    if (decoder->frame_in_progress.payload_len == 0) {
        s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_window_update(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    AWS_FATAL_ASSERT(input->len >= 4);

    uint32_t window_increment = 0;
    bool succ = aws_byte_cursor_read_be32(input, &window_increment);
    AWS_ASSERT(succ);
    (void)succ;

    window_increment &= s_31_bit_mask;

    /* #TODO I still have NO CLUE with this thing is for */

    s_decoder_reset_state(decoder);

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_continuation(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {
    (void)input;

    if (decoder->frame_in_progress.payload_len) {
        /* Read the headers block */
        s_decoder_set_state(decoder, &s_state_headers_begin);

    } else {
        /* For whatever reason, HEADERS and PUSH_PROMISE frames have padding but CONTINUATION doesn't */
        s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}
static int s_state_fn_frame_unknown(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    /* Read all data possible, and throw it on the floor */
    s_decoder_get_payload(decoder, input);

    /* If there's no more data expected, end the frame */
    if (decoder->frame_in_progress.payload_len == 0) {
        s_decoder_reset_state(decoder);
    }

    return AWS_OP_SUCCESS;
}

static int s_state_fn_headers_begin(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    /* Starting new header, so zero out the data */
    AWS_ZERO_STRUCT(decoder->header_in_progress);

    /* If we're out of payload data, handle frame complete */
    if (decoder->frame_in_progress.payload_len == 0) {

        DECODER_LOG(TRACE, decoder, "Done decoding header block");

        /* Hollaback if this is the last HEADERS frame */
        if (decoder->frame_in_progress.end_headers) {
            DECODER_CALL_VTABLE_STREAM(decoder, on_end_headers);
        }

        /* Finish the fight */
        s_decoder_set_state(decoder, &s_state_padding);
        return AWS_OP_SUCCESS;
    }

    DECODER_LOGF(
        TRACE,
        decoder,
        "Decoding header, %" PRIu32 " bytes remaining in payload",
        decoder->frame_in_progress.payload_len);

    /* Consts for decoding header blocks */
    static const uint8_t s_indexed_header_field_mask = 1 << 7;
    static const uint8_t s_literal_save_field_mask = 1 << 6;
    static const uint8_t s_dynamic_table_size_update_mask = 1 << 5;
    static const uint8_t s_literal_no_forward_save_mask = 1 << 4;

    uint8_t first_byte = *input->ptr;

    if (first_byte & s_indexed_header_field_mask) {
        /* This is a purely indexed header, so it's the easiest to decompress */
        s_decoder_set_state(decoder, &s_state_headers_indexed);

    } else if (first_byte & s_literal_save_field_mask || (first_byte & s_dynamic_table_size_update_mask) == 0) {

        if (first_byte & s_literal_save_field_mask) {
            decoder->header_in_progress.literal.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_SAVE;
            decoder->header_in_progress.literal.payload_len_prefix = 6;
        } else if (first_byte & s_literal_no_forward_save_mask) {
            decoder->header_in_progress.literal.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_NO_FORWARD_SAVE;
            decoder->header_in_progress.literal.payload_len_prefix = 4;
        } else {
            decoder->header_in_progress.literal.hpack_behavior = AWS_H2_HEADER_BEHAVIOR_NO_SAVE;
            decoder->header_in_progress.literal.payload_len_prefix = 4;
        }

        /* Process header data */
        s_decoder_set_state(decoder, &s_state_headers_literal_index);

    } else {
        /* This header is *actually* a dynamic table size update */
        s_decoder_set_state(decoder, &s_state_headers_dyn_table_resize);
    }

    return AWS_OP_SUCCESS;
}

static int s_state_fn_headers_indexed(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    struct h2_header_progress_indexed *progress = &decoder->header_in_progress.indexed;

    enum aws_hpack_decode_status status = s_decode_integer(decoder, input, 7, &progress->index);
    switch (status) {
        case AWS_HPACK_DECODE_COMPLETE:
            /* The rest of the function will process the data */
            break;

        case AWS_HPACK_DECODE_ONGOING:
            /* Come back with more data */
            return AWS_OP_SUCCESS;

        case AWS_HPACK_DECODE_ERROR:
            /* Report error upward */
            DECODER_LOGF(
                ERROR,
                decoder,
                "HPACK integer decoding failed during dyn table decode with error '%s'",
                aws_error_debug_str(aws_last_error()));
            return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    if (progress->index > SIZE_MAX) {
        DECODER_LOGF(
            ERROR, decoder, "HPACK integer index %" PRIu64 " is too large to fit in dynamic table", progress->index);
        return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    const struct aws_http_header *header = aws_hpack_get_header(decoder->hpack, (size_t)progress->index);
    if (!header) {
        DECODER_LOGF(
            ERROR,
            decoder,
            "HPACK integer index %" PRIu64 " was not found in the dynamic table (index is likely too large)",
            progress->index);
        return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_header, header, AWS_H2_HEADER_BEHAVIOR_SAVE);

    s_decoder_set_state(decoder, &s_state_headers_begin);
    return AWS_OP_SUCCESS;
}

static int s_state_fn_headers_literal_index(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    struct h2_header_progress_literal *progress = &decoder->header_in_progress.literal;
    const enum aws_hpack_decode_status status =
        s_decode_integer(decoder, input, progress->payload_len_prefix, &progress->index);

    switch (status) {
        case AWS_HPACK_DECODE_COMPLETE:
            break;

        case AWS_HPACK_DECODE_ONGOING:
            /* Come back with more data now, ya hear! */
            return AWS_OP_SUCCESS;

        case AWS_HPACK_DECODE_ERROR:
            /* Report error upward */
            DECODER_LOGF(
                ERROR,
                decoder,
                "HPACK integer decoding failed during header index decode with error '%s'",
                aws_error_debug_str(aws_last_error()));
            return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    /* Read the name */
    if (progress->index) {
        /* Name is indexed, so just read it */
        const struct aws_http_header *header = aws_hpack_get_header(decoder->hpack, (size_t)progress->index);
        if (!header) {
            return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
        }
        decoder->header_in_progress.literal.header.name = header->name;

        /* Name gotten, skip to value */
        s_decoder_set_state(decoder, &s_state_headers_literal_value);

    } else {

        /* Need to hpack decode the header name */
        s_decoder_set_state(decoder, &s_state_headers_literal_name);
    }

    return AWS_OP_SUCCESS;
}

static int s_state_fn_headers_literal_name(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    struct h2_header_progress_literal *progress = &decoder->header_in_progress.literal;

    /* New name, decode as string */
    const enum aws_hpack_decode_status status = s_decode_string(decoder, input, &decoder->scratch);
    switch (status) {
        case AWS_HPACK_DECODE_COMPLETE:
            break;

        case AWS_HPACK_DECODE_ONGOING:
            /* Come back with more data now, ya hear! */
            return AWS_OP_SUCCESS;

        case AWS_HPACK_DECODE_ERROR:
            /* Report error upward */
            DECODER_LOGF(
                ERROR,
                decoder,
                "HPACK string decoding failed during header name decode with error '%s'",
                aws_error_debug_str(aws_last_error()));
            return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    /* Get a cursor to the string we just decoded (this is the first thing in scratch, so no fancy math required) */
    progress->header.name = aws_byte_cursor_from_buf(&decoder->scratch);
    /* The value will start after the name, so save how long it is */
    progress->value_offset = decoder->scratch.len;

    /* Name gotten, go to value */
    s_decoder_set_state(decoder, &s_state_headers_literal_value);

    return AWS_OP_SUCCESS;
}

static int s_state_fn_headers_literal_value(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    struct h2_header_progress_literal *progress = &decoder->header_in_progress.literal;

    /* New value, decode as string */
    const enum aws_hpack_decode_status status = s_decode_string(decoder, input, &decoder->scratch);
    switch (status) {
        case AWS_HPACK_DECODE_COMPLETE:
            break;

        case AWS_HPACK_DECODE_ONGOING:
            /* Come back with more data now, ya hear! */
            return AWS_OP_SUCCESS;

        case AWS_HPACK_DECODE_ERROR:
            /* Report error upward */
            DECODER_LOGF(
                ERROR,
                decoder,
                "HPACK string decoding failed during header value decode with error '%s'",
                aws_error_debug_str(aws_last_error()));
            return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    /* Set the value to scratch, and advance past name if necessary */
    progress->header.value = aws_byte_cursor_from_buf(&decoder->scratch);
    aws_byte_cursor_advance(&progress->header.value, progress->value_offset);

    /* Save if necessary */
    if (progress->hpack_behavior == AWS_H2_HEADER_BEHAVIOR_SAVE) {
        if (aws_hpack_insert_header(decoder->hpack, &progress->header)) {
            return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
        }
    }

    /* Report to the user */
    DECODER_CALL_VTABLE_STREAM_ARGS(decoder, on_header, &progress->header, progress->hpack_behavior);

    s_decoder_set_state(decoder, &s_state_headers_begin);
    return AWS_OP_SUCCESS;
}

static int s_state_fn_headers_dyn_table_resize(struct aws_h2_decoder *decoder, struct aws_byte_cursor *input) {

    uint64_t *new_size = &decoder->header_in_progress.dyn_table_resize.new_size;

    /* Decode the new dynamic table size, and set it if decoding is complete */
    const enum aws_hpack_decode_status status = s_decode_integer(decoder, input, 5, new_size);
    switch (status) {
        case AWS_HPACK_DECODE_COMPLETE:
            /* The rest of the function will process the data */
            break;

        case AWS_HPACK_DECODE_ONGOING:
            /* Come back with more data */
            return AWS_OP_SUCCESS;

        case AWS_HPACK_DECODE_ERROR:
            /* Report error upward */
            DECODER_LOGF(
                ERROR,
                decoder,
                "HPACK integer decoding failed during dyn table decode with error '%s'",
                aws_error_debug_str(aws_last_error()));
            return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    DECODER_LOGF(INFO, decoder, "Resizing dynamic table to %" PRIu64, *new_size);

    if (aws_hpack_resize_dynamic_table(decoder->hpack, (size_t)*new_size)) {
        if (aws_last_error() == AWS_ERROR_INVALID_ARGUMENT) {
            DECODER_LOGF(ERROR, decoder, "Peer requested dynamic table resize to invalid size %" PRIu64, *new_size);
        } else {
            DECODER_LOGF(
                ERROR,
                decoder,
                "Failed resizing HPACK dynamic table with error %s",
                aws_error_debug_str(aws_last_error()));
        }
        return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
    }

    s_decoder_set_state(decoder, &s_state_headers_begin);
    return AWS_OP_SUCCESS;
}
