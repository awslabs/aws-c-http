/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/websocket_decoder.h>

#include <aws/io/logging.h>
#include <aws/testing/aws_test_harness.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define DECODER_TEST_CASE(NAME)                                                                                        \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct decoder_tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;

    struct aws_websocket_decoder decoder;
    void *specific_test_data;

    struct aws_websocket_frame frame;
    size_t on_frame_count;
    size_t fail_on_nth_frame;

    struct aws_byte_buf payload;
    size_t on_payload_count;
    size_t fail_on_nth_payload;
};

static int s_on_frame(const struct aws_websocket_frame *frame, void *user_data) {
    struct decoder_tester *tester = user_data;

    tester->frame = *frame;

    tester->on_frame_count++;
    if (tester->on_frame_count == tester->fail_on_nth_frame) {
        return aws_raise_error(AWS_ERROR_HTTP_UNKNOWN);
    }

    return AWS_OP_SUCCESS;
}

static int s_on_payload(struct aws_byte_cursor data, void *user_data) {
    struct decoder_tester *tester = user_data;

    ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&tester->payload, &data));

    tester->on_payload_count++;
    if (tester->on_payload_count == tester->fail_on_nth_payload) {
        return aws_raise_error(AWS_ERROR_HTTP_UNKNOWN);
    }

    return AWS_OP_SUCCESS;
}

/* For resetting the decoder and its results mid-test */
static void s_decoder_tester_reset(struct decoder_tester *tester) {
    aws_websocket_decoder_clean_up(&tester->decoder);
    aws_websocket_decoder_init(&tester->decoder, tester->alloc, s_on_frame, s_on_payload, tester);
    AWS_ZERO_STRUCT(tester->frame);
    tester->on_frame_count = 0;
    tester->payload.len = 0;
    tester->on_payload_count = 0;
}

static int s_decoder_tester_init(struct decoder_tester *tester, struct aws_allocator *alloc) {
    aws_http_library_init(alloc);

    AWS_ZERO_STRUCT(*tester);
    tester->alloc = alloc;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    ASSERT_SUCCESS(aws_byte_buf_init(&tester->payload, alloc, 1024));

    s_decoder_tester_reset(tester);

    return AWS_OP_SUCCESS;
}

static int s_decoder_tester_clean_up(struct decoder_tester *tester) {
    aws_byte_buf_clean_up(&tester->payload);
    aws_websocket_decoder_clean_up(&tester->decoder);
    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);
    return AWS_OP_SUCCESS;
}

static int s_compare_frame(const struct aws_websocket_frame *expected, const struct aws_websocket_frame *decoded) {
    uint8_t a[24];
    memcpy(a, expected, 24);
    uint8_t b[24];
    memcpy(b, decoded, 24);

    /* compare each field so it's clear where test failed */
    ASSERT_UINT_EQUALS(expected->fin, decoded->fin);
    ASSERT_UINT_EQUALS(expected->rsv[0], decoded->rsv[0]);
    ASSERT_UINT_EQUALS(expected->rsv[1], decoded->rsv[1]);
    ASSERT_UINT_EQUALS(expected->rsv[2], decoded->rsv[2]);
    ASSERT_UINT_EQUALS(expected->masked, decoded->masked);
    ASSERT_UINT_EQUALS(expected->opcode, decoded->opcode);
    ASSERT_UINT_EQUALS(expected->payload_length, decoded->payload_length);
    ASSERT_UINT_EQUALS(expected->masking_key[0], decoded->masking_key[0]);
    ASSERT_UINT_EQUALS(expected->masking_key[1], decoded->masking_key[1]);
    ASSERT_UINT_EQUALS(expected->masking_key[2], decoded->masking_key[2]);
    ASSERT_UINT_EQUALS(expected->masking_key[3], decoded->masking_key[3]);

    return AWS_OP_SUCCESS;
};

DECODER_TEST_CASE(websocket_decoder_sanity_check) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));
    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test decoding simplest possible frame, no payload */
DECODER_TEST_CASE(websocket_decoder_simplest_frame) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        0x89, // fin | rsv1 | rsv2 | rsv3 | 4bit opcode
        0x00, // mask | 7bit payload len
    };

    struct aws_websocket_frame expected_frame = {
        .fin = true,
        .opcode = 9,
    };

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

    /* check result */
    ASSERT_TRUE(frame_complete);
    ASSERT_UINT_EQUALS(1, tester.on_frame_count);
    ASSERT_UINT_EQUALS(0, tester.on_payload_count);
    ASSERT_UINT_EQUALS(0, tester.payload.len);
    ASSERT_UINT_EQUALS(0, input_cursor.len);

    ASSERT_SUCCESS(s_compare_frame(&expected_frame, &tester.frame));

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test the 3 RSV bools */
DECODER_TEST_CASE(websocket_decoder_rsv) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    /* Test 3 times, each time with one RSV bool set */
    for (int rsv = 0; rsv < 3; ++rsv) {

        uint8_t input[] = {
            0x89, // fin | rsv1 | rsv2 | rsv3 | 4bit opcode
            0x00, // mask | 7bit payload len
        };

        /* Set the appropriate RSV */
        /* the bit arithmetic is setup this way to avoid Conversion warnings from the compiler. */
        input[0] |= (1 << (6 - rsv));

        struct aws_websocket_frame expected_frame = {
            .fin = true,
            .opcode = 9,
        };
        expected_frame.rsv[rsv] = true;

        bool frame_complete;
        struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
        ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

        /* check result */
        ASSERT_TRUE(frame_complete);
        ASSERT_SUCCESS(s_compare_frame(&expected_frame, &tester.frame));
    }

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test decoding a simple data frame, with a payload */
DECODER_TEST_CASE(websocket_decoder_data_frame) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        0x82, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x04, /* mask | 7bit payload len */
        /* payload */
        0x00,
        0x0F,
        0xF0,
        0xFF,
    };

    const uint8_t expected_payload[] = {0x00, 0x0F, 0xF0, 0xFF};

    struct aws_websocket_frame expected_frame = {
        .fin = true,
        .opcode = 2,
        .payload_length = sizeof(expected_payload),
    };

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

    /* check result */
    ASSERT_TRUE(frame_complete);
    ASSERT_UINT_EQUALS(1, tester.on_frame_count);
    ASSERT_UINT_EQUALS(1, tester.on_payload_count);
    ASSERT_UINT_EQUALS(0, input_cursor.len);

    ASSERT_SUCCESS(s_compare_frame(&expected_frame, &tester.frame));

    struct aws_byte_cursor expected_cursor = aws_byte_cursor_from_array(expected_payload, sizeof(expected_payload));
    ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&expected_cursor, &tester.payload));

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test aws_websocket_decoder_process() returns at the end of each frame */
DECODER_TEST_CASE(websocket_decoder_stops_at_frame_end) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        0x82, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x04, /* mask | 7bit payload len */
        /* payload */
        0x00,
        0x0F,
        0xF0,
        0xFF,
        /* extra data that should not be processed */
        0x11,
        0x22,
    };

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

    /* check result */
    ASSERT_TRUE(frame_complete);
    ASSERT_UINT_EQUALS(1, tester.on_frame_count);
    ASSERT_UINT_EQUALS(1, tester.on_payload_count);
    ASSERT_UINT_EQUALS(2, input_cursor.len); /* Check that there's data left over */

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test a single frame masked text message */
DECODER_TEST_CASE(websocket_decoder_masking) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    /* Test from RFC-6545 Section 5.7 - Examples - A single-frame masked text message */
    uint8_t input[] = {
        0x81, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x85, /* mask | 7bit payload len */
        /* masking key */
        0x37,
        0xfa,
        0x21,
        0x3d,
        /* payload */
        0x7f,
        0x9f,
        0x4d,
        0x51,
        0x58,
    };

    const char *expected_payload = "Hello";

    struct aws_websocket_frame expected_frame = {
        .fin = true,
        .opcode = 1,
        .masked = true,
        .masking_key = {0x37, 0xfa, 0x21, 0x3d},
        .payload_length = strlen(expected_payload),
    };

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

    /* check result */
    ASSERT_TRUE(frame_complete);
    ASSERT_SUCCESS(s_compare_frame(&expected_frame, &tester.frame));
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&tester.payload, expected_payload));

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test a data frame which uses the 2 byte extended-length encoding */
DECODER_TEST_CASE(websocket_decoder_extended_length_2byte) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    struct length_validity_pair {
        uint16_t len;
        bool valid;
    };

    uint8_t input[4] = {
        0x82, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x7E, /* mask | 7bit payload len */
        /* 2byte extended length... */
    };

    struct aws_websocket_frame expected_frame = {
        .fin = true,
        .opcode = 2,
    };

    /* lengths greater than 125 should be encoded in 2 bytes */
    struct length_validity_pair length_validity_pairs[] = {
        {0, false},     /* should use 7bit length encoding */
        {1, false},     /* should use 7bit length encoding */
        {125, false},   /* highest number for 7bit length encoding */
        {126, true},    /* lowest number for 2byte extended length */
        {127, true},    /* should be encoded in 2byte extended length */
        {0x0100, true}, /* just another value for 2byte extended length */
        {0xFFFF, true}, /* highest number for 2byte extended length */
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(length_validity_pairs); ++i) {
        struct length_validity_pair pair_i = length_validity_pairs[i];
        s_decoder_tester_reset(&tester);

        /* write extended-length to input buffer */
        uint16_t network_num = aws_hton16(pair_i.len);
        memcpy(input + 2, &network_num, sizeof(network_num));

        /* adapt expected_frame */
        expected_frame.payload_length = pair_i.len;

        /* Process input (only sending non-payload portion of frame) */
        bool frame_complete;
        struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));

        if (pair_i.valid) {
            ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

            /* check result */
            ASSERT_FALSE(frame_complete);
            ASSERT_UINT_EQUALS(0, input_cursor.len);
            ASSERT_UINT_EQUALS(1, tester.on_frame_count);
            ASSERT_UINT_EQUALS(0, tester.on_payload_count);
            ASSERT_SUCCESS(s_compare_frame(&expected_frame, &tester.frame));
        } else {
            aws_raise_error(-1); /* overwrite last-error */

            ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
            ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_PROTOCOL_ERROR, aws_last_error());
        }
    }

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

DECODER_TEST_CASE(websocket_decoder_extended_length_8byte) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    struct length_validity_pair {
        uint64_t len;
        bool valid;
    };

    uint8_t input[10] = {
        0x82, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x7F, /* mask | 7bit payload len */
        /* 8byte extended length... */
    };

    struct aws_websocket_frame expected_frame = {
        .fin = true,
        .opcode = 2,
    };

    /* 8byte lengths should require at least 2 bytes to encode, and the high-order bit should be 0 */
    struct length_validity_pair length_validity_pairs[] = {
        {125, false},                /* highest number for 7bit length encoding */
        {126, false},                /* lowest number for 2byte extended length */
        {127, false},                /* should be encoded in 2byte extended length */
        {0x0100, false},             /* just another value for 2byte extended length */
        {0xFFFF, false},             /* highest number for 2byte extended length */
        {0x0000000000010000, true},  /* lowest number for 8byte extended length */
        {0x7FFFFFFFFFFFFFFF, true},  /* highest number for 8byte extended length */
        {0x123456789ABCDEF0, true},  /* just another value for 8byte extended length */
        {0x8000000000000000, false}, /* illegal use high bit in 8byte extended length */
        {0xFFFFFFFFFFFFFFFF, false}, /* illegal use high bit in 8byte extended length */
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(length_validity_pairs); ++i) {
        struct length_validity_pair pair_i = length_validity_pairs[i];
        s_decoder_tester_reset(&tester);

        /* write extended-length to input buffer */
        uint64_t network_num = aws_hton64(pair_i.len);
        memcpy(input + 2, &network_num, sizeof(network_num));

        /* adapt expected_frame */
        expected_frame.payload_length = pair_i.len;

        /* Process input (only sending non-payload portion of frame) */
        bool frame_complete;
        struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));

        if (pair_i.valid) {
            ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

            /* check result */
            ASSERT_FALSE(frame_complete);
            ASSERT_UINT_EQUALS(0, input_cursor.len);
            ASSERT_UINT_EQUALS(1, tester.on_frame_count);
            ASSERT_UINT_EQUALS(0, tester.on_payload_count);
            ASSERT_SUCCESS(s_compare_frame(&expected_frame, &tester.frame));
        } else {
            aws_raise_error(-1); /* overwrite last-error */

            ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
            ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_PROTOCOL_ERROR, aws_last_error());
        }
    }

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test that decoder can handle data that's split at any possible point */
DECODER_TEST_CASE(websocket_decoder_1byte_at_a_time) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    /* Use all optional frame features in this test (8byte extended payload length and masking-key).
     * Even though we say the payload is long, we're only going to send a portion of it in this test */
    uint8_t input[] = {
        0x81, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0xFF, /* mask | 7bit payload len */
        /* 8byte extended payload len */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        /* masking key */
        0x37,
        0xfa,
        0x21,
        0x3d,
        /* payload */
        0x7f,
        0x9f,
        0x4d,
        0x51,
        0x58,
    };

    const char *expected_payload = "Hello";

    struct aws_websocket_frame expected_frame = {
        .fin = true,
        .opcode = 1,
        .masked = true,
        .masking_key = {0x37, 0xfa, 0x21, 0x3d},
        .payload_length = 0x10000,
    };

    for (size_t i = 0; i < sizeof(input); ++i) {
        bool frame_complete;
        struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input + i, 1);
        ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
        ASSERT_FALSE(frame_complete);
        ASSERT_UINT_EQUALS(0, input_cursor.len);
    }

    /* check result */
    ASSERT_UINT_EQUALS(1, tester.on_frame_count);
    ASSERT_UINT_EQUALS(5, tester.on_payload_count);
    ASSERT_SUCCESS(s_compare_frame(&expected_frame, &tester.frame));
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&tester.payload, expected_payload));

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

DECODER_TEST_CASE(websocket_decoder_fail_on_unknown_opcode) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        0x07, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x00, /* mask | 7bit payload len */
    };

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_PROTOCOL_ERROR, aws_last_error());

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test fragmented messages, which arrive across multiple frames whose FIN bit is cleared */
DECODER_TEST_CASE(websocket_decoder_fragmented_message) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        /* TEXT FRAME */
        0x01, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x03, /* mask | 7bit payload len */
        'h',
        'o',
        't',

        /* CONTINUATION FRAME */
        0x00, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x02, /* mask | 7bit payload len */
        'd',
        'o',

        /* PING FRAME - Control frames may be injected in the middle of a fragmented message. */
        0x89, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x00, /* mask | 7bit payload len */

        /* CONTINUATION FRAME */
        0x80, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        'g',
    };

    struct aws_websocket_frame expected_frames[] = {
        {
            .fin = false,
            .opcode = 1,
            .payload_length = 3,
        },
        {
            .fin = false,
            .opcode = 0,
            .payload_length = 2,
        },
        {
            .fin = true,
            .opcode = 9,
        },
        {
            .fin = true,
            .opcode = 0,
            .payload_length = 1,
        },
    };

    const char *expected_payload = "hotdog";

    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    for (size_t i = 0; i < AWS_ARRAY_SIZE(expected_frames); ++i) {
        bool frame_complete;
        ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
        ASSERT_TRUE(frame_complete);
        ASSERT_UINT_EQUALS(i + 1, tester.on_frame_count);
        ASSERT_SUCCESS(s_compare_frame(&expected_frames[i], &tester.frame));
    }

    ASSERT_TRUE(aws_byte_buf_eq_c_str(&tester.payload, expected_payload));

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

DECODER_TEST_CASE(websocket_decoder_fail_on_bad_fragmentation) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        /* TEXT FRAME with FIN=0 */
        0x01, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        'a',

        /* TEXT FRAME - but ought to be a CONTINUATION frame */
        0x01, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        'b',
    };

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
    ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_PROTOCOL_ERROR, aws_last_error());

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Control frames must have FIN bit set */
DECODER_TEST_CASE(websocket_decoder_control_frame_cannot_be_fragmented) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        0x0A, // fin | rsv1 | rsv2 | rsv3 | 4bit opcode
        0x00, // mask | 7bit payload len
    };

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_PROTOCOL_ERROR, aws_last_error());

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test that we can process a TEXT frame with UTF-8 in it */
DECODER_TEST_CASE(websocket_decoder_utf8_text) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        /* TEXT FRAME */
        0x81, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x04, /* mask | 7bit payload len */
        /* payload - codepoint U+10348 as 4-byte UTF-8 */
        0xF0,
        0x90,
        0x8D,
        0x88,
    };

    struct aws_websocket_frame expected_frame = {
        .fin = true,
        .opcode = AWS_WEBSOCKET_OPCODE_TEXT,
        .payload_length = 4,
    };
    const char *expected_payload = "\xF0\x90\x8D\x88";

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

    /* check result */
    ASSERT_TRUE(frame_complete);
    ASSERT_SUCCESS(s_compare_frame(&expected_frame, &tester.frame));
    ASSERT_TRUE(aws_byte_buf_eq_c_str(&tester.payload, expected_payload));

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test that a TEXT frame with invalid UTF-8 fails */
DECODER_TEST_CASE(websocket_decoder_fail_on_bad_utf8_text) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    { /* Test validation failing when it hits totally bad byte values */
        uint8_t input[] = {
            /* TEXT FRAME */
            0x81, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
            0x01, /* mask | 7bit payload len */
            /* payload - illegal UTF-8 value */
            0xFF,
        };

        bool frame_complete;
        struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
        ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
        ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_PROTOCOL_ERROR, aws_last_error());
    }

    s_decoder_tester_reset(&tester);

    { /* Test validation failing at the end, due to a 4-byte codepoint missing 1 byte */
        uint8_t input[] = {
            /* TEXT FRAME */
            0x81, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
            0x03, /* mask | 7bit payload len */
            /* payload - codepoint U+10348 as 4-byte UTF-8, but missing 4th byte */
            0xF0,
            0x90,
            0x8D,
            /* 0x88, <-- missing 4th byte */
        };

        bool frame_complete;
        struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
        ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
        ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_PROTOCOL_ERROR, aws_last_error());
    }

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test that UTF-8 can be validated even if it's fragmented across frames  */
DECODER_TEST_CASE(websocket_decoder_fragmented_utf8_text) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    /* Split a 4-byte UTF-8 codepoint across a fragmented message.
     * codepoint U+10348 is UTF-8 bytes: 0xF0, 0x90, 0x8D, 0x88 */
    uint8_t input[] = {
        /* TEXT FRAME */
        0x01, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        /* payload */
        0xF0, /* 1/4 UTF-8 bytes */

        /* CONTINUATION FRAME */
        0x00, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x02, /* mask | 7bit payload len */
        /* payload */
        0x90, /* 2/4 UTF-8 bytes */
        0x8D, /* 3/4 UTF-8 bytes */

        /* PING FRAME - Control frames may be injected in the middle of a fragmented message. */
        0x89, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        /* payload - PING payload should not interfere with validation */
        0xFF,

        /* CONTINUATION FRAME */
        0x80, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        /* payload */
        0x88, /* 4/4 UTF-8 bytes */
    };

    struct aws_websocket_frame expected_frames[] = {
        {
            .fin = false,
            .opcode = 1,
            .payload_length = 1,
        },
        {
            .fin = false,
            .opcode = 0,
            .payload_length = 2,
        },
        {
            .fin = true,
            .opcode = 9,
            .payload_length = 1,
        },
        {
            .fin = true,
            .opcode = 0,
            .payload_length = 1,
        },
    };

    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    for (size_t i = 0; i < AWS_ARRAY_SIZE(expected_frames); ++i) {
        bool frame_complete;
        ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
        ASSERT_TRUE(frame_complete);
        ASSERT_UINT_EQUALS(i + 1, tester.on_frame_count);
        ASSERT_SUCCESS(s_compare_frame(&expected_frames[i], &tester.frame));
    }
    ASSERT_UINT_EQUALS(0, input_cursor.len);

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test that UTF-8 validator works even when text is fragmented across multiple frames */
DECODER_TEST_CASE(websocket_decoder_fail_on_fragmented_bad_utf8_text) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    /* Split a 4-byte UTF-8 codepoint across a fragmented message, but omit he last byte.
     * codepoint U+10348 is UTF-8 bytes: 0xF0, 0x90, 0x8D, 0x88 */
    uint8_t input[] = {
        /* TEXT FRAME */
        0x01, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        /* payload */
        0xF0, /* 1/4 UTF-8 bytes */

        /* CONTINUATION FRAME */
        0x00, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        /* payload */
        0x90, /* 2/4 UTF-8 bytes */

        /* PING FRAME - Control frames may be injected in the middle of a fragmented message. */
        0x89, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        /* payload - PING payload shouldn't interfere with the TEXT's validation */
        0x8D,

        /* CONTINUATION FRAME */
        0x80, /* fin | rsv1 | rsv2 | rsv3 | 4bit opcode */
        0x01, /* mask | 7bit payload len */
        /* payload */
        0x8D, /* 3/4 UTF-8 bytes */
        /* 0x88, <-- MISSING 4/4 UTF-8 bytes */
    };

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));

    /* TEXT should pass */
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
    ASSERT_TRUE(frame_complete);

    /* CONTINUATION should pass */
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
    ASSERT_TRUE(frame_complete);

    /* PING should pass */
    ASSERT_SUCCESS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
    ASSERT_TRUE(frame_complete);

    /* final CONTINUATION should fail because the message ended with an incomplete UTF-8 encoding */
    ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_WEBSOCKET_PROTOCOL_ERROR, aws_last_error());

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Test that an error from the on_frame callback fails the decoder */
DECODER_TEST_CASE(websocket_decoder_on_frame_callback_can_fail_decoder) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        0x81, // fin | rsv1 | rsv2 | rsv3 | 4bit opcode
        0x01, // mask | 7bit payload len
        'a',
    };

    tester.fail_on_nth_frame = 1;

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

    /* Check that error returned by callback bubbles up.
     * UNKNOWN error just happens to be what our test callback throws */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_UNKNOWN, aws_last_error());

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

DECODER_TEST_CASE(websocket_decoder_on_payload_callback_can_fail_decoder) {
    (void)ctx;
    struct decoder_tester tester;
    ASSERT_SUCCESS(s_decoder_tester_init(&tester, allocator));

    uint8_t input[] = {
        0x81, // fin | rsv1 | rsv2 | rsv3 | 4bit opcode
        0x01, // mask | 7bit payload len
        'a',
    };

    tester.fail_on_nth_payload = 1;

    bool frame_complete;
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input, sizeof(input));
    ASSERT_FAILS(aws_websocket_decoder_process(&tester.decoder, &input_cursor, &frame_complete));

    /* Check that error returned by callback bubbles up.
     * UNKNOWN error just happens to be what our test callback throws */
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_UNKNOWN, aws_last_error());

    ASSERT_SUCCESS(s_decoder_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
