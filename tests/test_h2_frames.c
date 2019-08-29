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

#include <aws/testing/aws_test_harness.h>

#include <aws/http/private/h2_frames.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4232) /* function pointer to dll symbol */
#endif

enum { S_BUFFER_SIZE = 128 };

struct frame_test_fixture;

/* Function type used to init and cleanup a fixture */
typedef int(frame_init_fn)(struct frame_test_fixture *);
/* Function used to tear down frame instances */
typedef int(frame_clean_up_fn)(void *);
/* Function used to encode a frame (this should be set to a function from h2_frames.h) */
typedef int(frame_encode_fn)(void *, struct aws_h2_frame_encoder *, struct aws_byte_buf *);
/* Function used to check if two frames are equal */
typedef bool(frame_eq_fn)(const void *, const void *, size_t);

/* Helper for comparing the fixed headers of frames */
static bool s_fixed_header_eq(const struct aws_h2_frame_header *l, const struct aws_h2_frame_header *r) {

    return l->type == r->type && l->stream_id == r->stream_id;
}

/* Default frame compare function, checks headers then memcmps the rest */
static bool s_frame_eq_default(const void *a, const void *b, size_t size) {

    static const size_t HEADER_SIZE = sizeof(struct aws_h2_frame_header);

    return s_fixed_header_eq(a, b) &&
           memcmp((uint8_t *)a + HEADER_SIZE, (uint8_t *)b + HEADER_SIZE, size - HEADER_SIZE) == 0;
}

/* Contains all of the information required to run a frame's test case */
struct frame_test_fixture {
    enum aws_h2_frame_type type;
    size_t size;
    frame_init_fn *init;
    frame_encode_fn *encode;
    int (*decode)(struct frame_test_fixture *);
    frame_clean_up_fn *frame_clean_up;
    frame_init_fn *teardown;
    frame_eq_fn *equal;
    struct aws_allocator *allocator;
    struct aws_h2_frame_encoder encoder;
    struct aws_h2_frame_decoder decoder;

    void *in_frame;
    void *out_frame;
    struct aws_byte_buf buffer;
};

static void s_frame_test_before(struct aws_allocator *allocator, void *ctx) {

    struct frame_test_fixture *fixture = ctx;
    fixture->allocator = allocator;

    int ret_value = aws_h2_frame_encoder_init(&fixture->encoder, allocator);
    AWS_ASSERT(ret_value == AWS_OP_SUCCESS);
    (void)ret_value;

    ret_value = aws_h2_frame_decoder_init(&fixture->decoder, allocator);
    AWS_ASSERT(ret_value == AWS_OP_SUCCESS);
    (void)ret_value;

    /* Setup the fixture */
    fixture->in_frame = aws_mem_acquire(allocator, fixture->size);
    AWS_ASSERT(fixture->in_frame);
    memset(fixture->in_frame, 0, fixture->size);

    fixture->out_frame = aws_mem_acquire(allocator, fixture->size);
    AWS_ASSERT(fixture->out_frame);
    memset(fixture->out_frame, 0, fixture->size);
}

static int s_frame_test_run(struct aws_allocator *allocator, void *ctx) {

    struct frame_test_fixture *fixture = ctx;

    aws_byte_buf_init(&fixture->buffer, allocator, S_BUFFER_SIZE);

    /* Init the in_frame & buffer */
    ASSERT_SUCCESS(fixture->init(fixture));

    /* Encode */

    /* Create the output buffer */
    struct aws_byte_buf output_buffer;
    ASSERT_SUCCESS(aws_byte_buf_init(&output_buffer, allocator, S_BUFFER_SIZE));

    /* Encode the frame */
    ASSERT_SUCCESS(fixture->encode(fixture->in_frame, &fixture->encoder, &output_buffer));

    /* Compare the buffers */
    ASSERT_BIN_ARRAYS_EQUALS(fixture->buffer.buffer, fixture->buffer.len, output_buffer.buffer, output_buffer.len);

    aws_byte_buf_clean_up(&output_buffer);

    /* Decode */

    /* Decode the buffer */
    ASSERT_SUCCESS(fixture->decode(fixture));

    /* Compare the frames */
    if (fixture->equal) {
        ASSERT_TRUE(fixture->equal(fixture->out_frame, fixture->in_frame, fixture->size));
    } else {
        ASSERT_TRUE(s_frame_eq_default(fixture->out_frame, fixture->in_frame, fixture->size));
    }

    return AWS_OP_SUCCESS;
}

static void s_frame_test_after(struct aws_allocator *allocator, void *ctx) {

    struct frame_test_fixture *fixture = ctx;

    /* Tear down the frame & buffer */
    if (fixture->teardown) {
        fixture->teardown(fixture);
    }

    /* Tear down the fixture */
    aws_h2_frame_encoder_clean_up(&fixture->encoder);
    aws_h2_frame_decoder_clean_up(&fixture->decoder);
    fixture->frame_clean_up(fixture->in_frame);
    aws_mem_release(allocator, fixture->in_frame);
    fixture->frame_clean_up(fixture->out_frame);
    aws_mem_release(allocator, fixture->out_frame);
    aws_byte_buf_clean_up(&fixture->buffer);
}

#define FRAME_TEST_NAME(e_type, t_name, s_name, i, t, e)                                                               \
    static int s_h2_frame_##t_name##_decode(struct frame_test_fixture *fixture) {                                      \
        struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&fixture->buffer);                                    \
        aws_h2_frame_decoder_begin(&fixture->decoder, &cursor);                                                        \
        ASSERT_UINT_EQUALS(fixture->type, fixture->decoder.header.type);                                               \
        int ret_val = aws_h2_frame_##s_name##_decode(fixture->out_frame, &fixture->decoder);                           \
        ASSERT_SUCCESS(ret_val);                                                                                       \
        ASSERT_UINT_EQUALS(0, fixture->decoder.payload.len);                                                           \
        return ret_val;                                                                                                \
    }                                                                                                                  \
    static struct frame_test_fixture h2_frame_##t_name##_fixture = {                                                   \
        .type = AWS_H2_FRAME_T_##e_type,                                                                               \
        .size = sizeof(struct aws_h2_frame_##s_name),                                                                  \
        .init = (i),                                                                                                   \
        .encode = (frame_encode_fn *)&aws_h2_frame_##s_name##_encode,                                                  \
        .decode = s_h2_frame_##t_name##_decode,                                                                        \
        .frame_clean_up = (frame_clean_up_fn *)aws_h2_frame_##s_name##_clean_up,                                       \
        .teardown = (t),                                                                                               \
        .equal = (e),                                                                                                  \
    };                                                                                                                 \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        h2_frame_##t_name, s_frame_test_before, s_frame_test_run, s_frame_test_after, &h2_frame_##t_name##_fixture)

#define FRAME_TEST(e_type, s_name, i, t, e) FRAME_TEST_NAME(e_type, s_name, s_name, i, t, e)

/*****************************************************************************/
/* Data                                                                      */
static int s_test_data_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_data *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x01;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x08,               /* Payload length */
        fixture->type,                  /* Frame type */
        AWS_H2_FRAME_F_END_STREAM,      /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    static uint8_t frame_payload[] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write(&fixture->buffer, frame_payload, sizeof(frame_payload));

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_data_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->end_stream = true;
    frame->data = aws_byte_cursor_from_array(frame_payload, sizeof(frame_payload));

    return AWS_OP_SUCCESS;
}
static bool s_test_data_eq(const void *a, const void *b, size_t size) {

    (void)size;

    const struct aws_h2_frame_data *l = a;
    const struct aws_h2_frame_data *r = b;

    return s_fixed_header_eq(&l->header, &r->header) && l->end_stream == r->end_stream &&
           l->pad_length == r->pad_length && aws_byte_cursor_eq(&l->data, &r->data);
}
FRAME_TEST(DATA, data, &s_test_data_init, NULL, &s_test_data_eq)

/*****************************************************************************/
/* Headers                                                                   */
static int s_test_headers_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_headers *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x01;
    static const uint8_t pad_length = 4;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x01 + pad_length,  /* Payload length */
        fixture->type,                  /* Frame type */
        AWS_H2_FRAME_F_PADDED,          /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    uint8_t frame_payload[] = {
        pad_length,                     /* Pad length */
        0x00, 0x00, 0x00, 0x00,         /* Padding */
    };
    /* clang-format on */

    /* Not testing header block encoding, that's tested elsewhere */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write(&fixture->buffer, frame_payload, sizeof(frame_payload));

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_headers_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->pad_length = pad_length;

    return AWS_OP_SUCCESS;
}
FRAME_TEST(HEADERS, headers, &s_test_headers_init, NULL, NULL)

/*****************************************************************************/
/* Priority                                                                  */
static int s_test_priority_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_priority *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x01;
    static const uint32_t stream_dependency = 0x234567;
    static const uint8_t dependency_weight = 0x89;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x05,               /* Payload length */
        fixture->type,                  /* Frame type */
        0x00,                           /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write_be32(&fixture->buffer, (1ULL << 31) | stream_dependency);
    aws_byte_buf_write_u8(&fixture->buffer, dependency_weight);

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_priority_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->priority.stream_dependency_exclusive = true;
    frame->priority.stream_dependency = stream_dependency;
    frame->priority.weight = dependency_weight;

    return AWS_OP_SUCCESS;
}
FRAME_TEST(PRIORITY, priority, &s_test_priority_init, NULL, NULL)

/*****************************************************************************/
/* Reset Stream                                                              */
static int s_test_rst_stream_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_rst_stream *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x01;
    static const uint32_t error_code = AWS_H2_ERR_INADEQUATE_SECURITY;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x04,               /* Payload length */
        fixture->type,                  /* Frame type */
        0x00,                           /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write_be32(&fixture->buffer, error_code);

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_rst_stream_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->error_code = error_code;

    return AWS_OP_SUCCESS;
}
FRAME_TEST(RST_STREAM, rst_stream, &s_test_rst_stream_init, NULL, NULL)

/*****************************************************************************/
/* Settings                                                                  */
static int s_test_settings_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_settings *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x0;
    static const uint8_t setting_id = AWS_H2_SETTINGS_ENABLE_PUSH;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x06,               /* Payload length */
        fixture->type,                  /* Frame type */
        0x00,                           /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    uint8_t frame_payload[] = {
        0x00, setting_id,               /* Identifier */
        0x00, 0x00, 0x00, 0x01,         /* Value */
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write(&fixture->buffer, frame_payload, sizeof(frame_payload));

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_settings_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    aws_h2_frame_settings_set(frame, AWS_H2_SETTINGS_ENABLE_PUSH, 1);

    return AWS_OP_SUCCESS;
}
static bool s_test_settings_eq(const void *a, const void *b, size_t size) {

    (void)size;

    const struct aws_h2_frame_settings *l = a;
    const struct aws_h2_frame_settings *r = b;

    if (!s_fixed_header_eq(&l->header, &r->header) || l->ack != r->ack) {
        return false;
    }

    const size_t l_num_settings = aws_hash_table_get_entry_count(&l->settings);
    const size_t r_num_settings = aws_hash_table_get_entry_count(&r->settings);
    if (l_num_settings != r_num_settings) {
        return false;
    }

    struct aws_hash_iter iter = aws_hash_iter_begin(&l->settings);
    for (; !aws_hash_iter_done(&iter); aws_hash_iter_next(&iter)) {
        /* Check that it's in the other table */
        struct aws_hash_element *element = NULL;
        aws_hash_table_find(&r->settings, iter.element.key, &element);
        if (!element) {
            return false;
        }

        if (iter.element.value != element->value) {
            return false;
        }
    }

    return true;
}
FRAME_TEST(SETTINGS, settings, &s_test_settings_init, NULL, &s_test_settings_eq)

/*****************************************************************************/
/* Push Promise                                                              */
static int s_test_push_promise_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_push_promise *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x01;
    static const uint8_t promised_id = 0x02;
    static const uint8_t pad_length = 0x04;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x05 + pad_length,  /* Payload length */
        fixture->type,                  /* Frame type */
        AWS_H2_FRAME_F_PADDED,          /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    uint8_t frame_payload[] = {
        pad_length,                     /* Pad length */
        0x00, 0x00, 0x00, promised_id,  /* Promised stream id */
        0x00, 0x00, 0x00, 0x00,         /* Padding */
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write(&fixture->buffer, frame_payload, sizeof(frame_payload));

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_push_promise_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->promised_stream_id = promised_id;
    frame->pad_length = pad_length;

    return AWS_OP_SUCCESS;
}
FRAME_TEST(PUSH_PROMISE, push_promise, &s_test_push_promise_init, NULL, NULL)

/*****************************************************************************/
/* Ping                                                                      */
static int s_test_ping_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_ping *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x00;
    static const bool ack = true;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x08,               /* Payload length */
        fixture->type,                  /* Frame type */
        AWS_H2_FRAME_F_ACK,             /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    static uint8_t frame_payload[] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write(&fixture->buffer, frame_payload, sizeof(frame_payload));

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_ping_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->ack = ack;
    frame->opaque_data = aws_byte_cursor_from_array(frame_payload, sizeof(frame_payload));

    return AWS_OP_SUCCESS;
}
static bool s_frame_eq_ping(const void *a, const void *b, size_t size) {

    (void)size;

    const struct aws_h2_frame_ping *l = a;
    const struct aws_h2_frame_ping *r = b;

    return s_fixed_header_eq(&l->header, &r->header) && l->ack == r->ack &&
           aws_byte_cursor_eq(&l->opaque_data, &r->opaque_data);
}
FRAME_TEST(PING, ping, &s_test_ping_init, NULL, &s_frame_eq_ping)

/*****************************************************************************/
/* Go Away                                                                   */
static int s_test_goaway_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_goaway *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x00;
    static const uint32_t last_stream_id = 0x01234567;
    static const uint32_t error_code = AWS_H2_ERR_PROTOCOL_ERROR;

    /* Init buffer */
    /* clang-format off */
    static uint8_t debug_data[] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
    };
    uint8_t frame_header[] = {
        0x00, 0x00, 0x08 + sizeof(debug_data),  /* Payload length */
        fixture->type,                          /* Frame type */
        0x00,                                   /* Flags */
        0x00, 0x00, 0x00, stream_id,            /* Stream id */
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write_be32(&fixture->buffer, last_stream_id);
    aws_byte_buf_write_be32(&fixture->buffer, error_code);
    aws_byte_buf_write(&fixture->buffer, debug_data, sizeof(debug_data));

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_goaway_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->last_stream_id = last_stream_id;
    frame->error_code = error_code;
    frame->debug_data = aws_byte_cursor_from_array(debug_data, sizeof(debug_data));

    return AWS_OP_SUCCESS;
}
static bool s_frame_eq_goaway(const void *a, const void *b, size_t size) {

    (void)size;

    const struct aws_h2_frame_goaway *l = a;
    const struct aws_h2_frame_goaway *r = b;

    return s_fixed_header_eq(&l->header, &r->header) && l->last_stream_id == r->last_stream_id &&
           l->error_code == r->error_code && aws_byte_cursor_eq(&l->debug_data, &r->debug_data);
}
FRAME_TEST(GOAWAY, goaway, &s_test_goaway_init, NULL, &s_frame_eq_goaway)

/*****************************************************************************/
/* Window Update                                                             */
static int s_test_window_update_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_window_update *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x01;
    static const uint32_t window_size_increment = 0x0123;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x04,               /* Payload length */
        fixture->type,                  /* Frame type */
        0x00,                           /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));
    aws_byte_buf_write_be32(&fixture->buffer, window_size_increment);

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_window_update_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->window_size_increment = window_size_increment;

    return AWS_OP_SUCCESS;
}
FRAME_TEST(WINDOW_UPDATE, window_update, &s_test_window_update_init, NULL, NULL)

/*****************************************************************************/
/* Continuation                                                              */
static int s_test_continuation_init(struct frame_test_fixture *fixture) {

    struct aws_h2_frame_continuation *frame = fixture->in_frame;

    static const uint8_t stream_id = 0x01;

    /* Init buffer */
    /* clang-format off */
    uint8_t frame_header[] = {
        0x00, 0x00, 0x00,               /* Payload length */
        fixture->type,                  /* Frame type */
        AWS_H2_FRAME_F_END_HEADERS,     /* Flags */
        0x00, 0x00, 0x00, stream_id,    /* Stream id */
    };
    /* clang-format on */

    aws_byte_buf_write(&fixture->buffer, frame_header, sizeof(frame_header));

    /* Init packet */
    ASSERT_SUCCESS(aws_h2_frame_continuation_init(frame, fixture->allocator));
    frame->header.stream_id = stream_id;
    frame->end_headers = true;

    return AWS_OP_SUCCESS;
}
FRAME_TEST(CONTINUATION, continuation, &s_test_continuation_init, NULL, NULL)
