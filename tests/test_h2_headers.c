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

#include <aws/http/private/h2_decoder.h>
#include <aws/http/private/h2_frames.h>
#include <aws/http/private/hpack.h>

enum { S_BUFFER_SIZE = 128 };

struct header_test_fixture;

/* Function type used to init and cleanup a fixture */
typedef int(header_init_fn)(struct header_test_fixture *);
/* Function used to tear down header instances */
typedef int(header_clean_up_fn)(void *);

/* Header compare function */
static int s_header_block_eq(
    const struct aws_array_list *l_header_fields,
    const struct aws_array_list *r_header_fields) {

    const size_t l_size = aws_array_list_length(l_header_fields);
    const size_t r_size = aws_array_list_length(r_header_fields);
    ASSERT_UINT_EQUALS(l_size, r_size);

    for (size_t i = 0; i < l_size; ++i) {
        const struct aws_h2_frame_header_field *l_field = NULL;
        aws_array_list_get_at_ptr(l_header_fields, (void **)&l_field, i);
        AWS_FATAL_ASSERT(l_field);

        const struct aws_h2_frame_header_field *r_field = NULL;
        aws_array_list_get_at_ptr(r_header_fields, (void **)&r_field, i);
        AWS_FATAL_ASSERT(r_field);

        ASSERT_INT_EQUALS(l_field->hpack_behavior, r_field->hpack_behavior);
        ASSERT_TRUE(aws_byte_cursor_eq(&l_field->header.name, &r_field->header.name));
        ASSERT_TRUE(aws_byte_cursor_eq(&l_field->header.value, &r_field->header.value));
    }

    return AWS_OP_SUCCESS;
}

/* Contains all of the information required to run a header's test case */
struct header_test_fixture {
    header_init_fn *init;
    header_clean_up_fn *header_clean_up;
    header_init_fn *teardown;

    struct aws_allocator *allocator;

    struct aws_h2_frame_encoder encoder;
    struct aws_h2_decoder *decoder;

    struct aws_h2_frame_headers headers_to_encode;
    struct aws_byte_buf expected_encoding_buf;
    struct aws_array_list decoded_headers;   /* array_list of aws_h2_frame_header_field */
    struct aws_byte_buf decoder_storage_buf; /* string storage */
};

static int s_decoder_on_header(
    uint32_t stream_id,
    const struct aws_http_header *header,
    enum aws_h2_header_field_hpack_behavior hpack_behavior,
    void *userdata) {

    (void)stream_id;
    struct header_test_fixture *fixture = userdata;
    struct aws_h2_frame_header_field header_field = {
        .header = *header,
        .hpack_behavior = hpack_behavior,
    };

    /* Backup string values */
    ASSERT_SUCCESS(aws_byte_buf_append_and_update(&fixture->decoder_storage_buf, &header_field.header.name));
    ASSERT_SUCCESS(aws_byte_buf_append_and_update(&fixture->decoder_storage_buf, &header_field.header.value));

    ASSERT_SUCCESS(aws_array_list_push_back(&fixture->decoded_headers, &header_field));

    return AWS_OP_SUCCESS;
}

static struct aws_h2_decoder_vtable s_decoder_vtable = {
    .on_header = s_decoder_on_header,
};

static int s_header_test_before(struct aws_allocator *allocator, void *ctx) {

    struct header_test_fixture *fixture = ctx;
    fixture->allocator = allocator;

    aws_http_library_init(allocator);

    ASSERT_SUCCESS(aws_h2_frame_encoder_init(&fixture->encoder, allocator));

    struct aws_h2_decoder_params decoder_params = {
        .alloc = allocator,
        .vtable = s_decoder_vtable,
        .userdata = fixture,
    };
    fixture->decoder = aws_h2_decoder_new(&decoder_params);
    ASSERT_NOT_NULL(fixture->decoder);
    ASSERT_SUCCESS(aws_h2_frame_headers_init(&fixture->headers_to_encode, allocator));
    fixture->headers_to_encode.header.stream_id = 1;

    ASSERT_SUCCESS(aws_byte_buf_init(&fixture->expected_encoding_buf, allocator, S_BUFFER_SIZE));
    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&fixture->decoded_headers, allocator, 8, sizeof(struct aws_h2_frame_header_field)));
    ASSERT_SUCCESS(aws_byte_buf_init(&fixture->decoder_storage_buf, allocator, S_BUFFER_SIZE));

    return AWS_OP_SUCCESS;
}

static int s_header_test_run(struct aws_allocator *allocator, void *ctx) {

    struct header_test_fixture *fixture = ctx;

    /* Init the in_header & buffer */
    ASSERT_SUCCESS(fixture->init(fixture));

    /* Encode */

    /* Create the output buffer */
    struct aws_byte_buf output_buffer;
    ASSERT_SUCCESS(aws_byte_buf_init(&output_buffer, allocator, S_BUFFER_SIZE));

    /* Encode the header */
    ASSERT_SUCCESS(aws_h2_frame_headers_encode(&fixture->headers_to_encode, &fixture->encoder, &output_buffer));

    /* Skip past the 9 byte frame header, this is tested elsewhere */
    struct aws_byte_cursor header_block_output = aws_byte_cursor_from_buf(&output_buffer);
    aws_byte_cursor_advance(&header_block_output, 9);

    /* Compare the remainder of encoded output against the expected header block fragment */
    ASSERT_BIN_ARRAYS_EQUALS(
        fixture->expected_encoding_buf.buffer,
        fixture->expected_encoding_buf.len,
        header_block_output.ptr,
        header_block_output.len);

    /* Decode */

    struct aws_byte_cursor payload = aws_byte_cursor_from_buf(&output_buffer);

    /* Decode the buffer */
    ASSERT_SUCCESS(aws_h2_decode(fixture->decoder, &payload));
    ASSERT_UINT_EQUALS(0, payload.len);

    /* Compare the headers */
    ASSERT_SUCCESS(
        s_header_block_eq(&fixture->headers_to_encode.header_block.header_fields, &fixture->decoded_headers));

    aws_byte_buf_clean_up(&output_buffer);
    return AWS_OP_SUCCESS;
}

static int s_header_test_after(struct aws_allocator *allocator, int setup_res, void *ctx) {

    (void)allocator;

    if (!setup_res) {
        struct header_test_fixture *fixture = ctx;

        /* Tear down the header & buffer */
        if (fixture->teardown) {
            fixture->teardown(fixture);
        }

        /* Tear down the fixture */
        aws_byte_buf_clean_up(&fixture->decoder_storage_buf);
        aws_array_list_clean_up(&fixture->decoded_headers);
        aws_h2_frame_headers_clean_up(&fixture->headers_to_encode);
        aws_byte_buf_clean_up(&fixture->expected_encoding_buf);
        aws_h2_decoder_destroy(fixture->decoder);
        aws_h2_frame_encoder_clean_up(&fixture->encoder);
    }
    aws_http_library_clean_up();

    return AWS_OP_SUCCESS;
}

#define HEADER_TEST(t_name, i, t)                                                                                      \
    static struct header_test_fixture s_##t_name##_fixture = {                                                         \
        .init = (i),                                                                                                   \
        .teardown = (t),                                                                                               \
    };                                                                                                                 \
    AWS_TEST_CASE_FIXTURE(t_name, s_header_test_before, s_header_test_run, s_header_test_after, &s_##t_name##_fixture)

#define DEFINE_STATIC_HEADER(_name, _key, _value, _behavior)                                                           \
    static const struct aws_h2_frame_header_field _name = {                                                            \
        .header =                                                                                                      \
            {                                                                                                          \
                .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_key),                                                   \
                .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_value),                                                \
            },                                                                                                         \
        .hpack_behavior = AWS_H2_HEADER_BEHAVIOR_##_behavior,                                                          \
    }

/* Test HEADERS frame with empty payload */
static int s_test_empty_payload(struct header_test_fixture *fixture) {
    (void)fixture;
    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_empty_payload, s_test_empty_payload, NULL);

/* RFC-7541 - Header Field Representation Examples - C.2.1. Literal Header Field with Indexing */
static int s_test_ex_2_1_init(struct header_test_fixture *fixture) {

    DEFINE_STATIC_HEADER(header, "custom-key", "custom-header", SAVE);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header);

    static const uint8_t encoded[] = {
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0d,
        0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_2_1, s_test_ex_2_1_init, NULL);

/* RFC-7541 - Header Field Representation Examples - C.2.2. Literal Header Field without Indexing */
static int s_test_ex_2_2_init(struct header_test_fixture *fixture) {

    DEFINE_STATIC_HEADER(header, ":path", "/sample/path", NO_SAVE);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header);

    static const uint8_t encoded[] = {
        0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68};

    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_2_2, s_test_ex_2_2_init, NULL);

/* RFC-7541 - Header Field Representation Examples - C.2.3. Literal Header Field Never Indexed */
static int s_test_ex_2_3_init(struct header_test_fixture *fixture) {

    DEFINE_STATIC_HEADER(header, "password", "secret", NO_FORWARD_SAVE);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header);

    static const uint8_t encoded[] = {
        0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74};

    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_2_3, s_test_ex_2_3_init, NULL);

/* RFC-7541 - Header Field Representation Examples - C.2.3. Indexed Header Field */
static int s_test_ex_2_4_init(struct header_test_fixture *fixture) {

    DEFINE_STATIC_HEADER(header, ":method", "GET", SAVE);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header);

    static const uint8_t encoded[] = {
        0x82,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_2_4, s_test_ex_2_4_init, NULL);

/* RFC-7541 - Request Examples without Huffman Coding - C.3.1. First Request */
static int s_test_ex_3_1_init(struct header_test_fixture *fixture) {

    DEFINE_STATIC_HEADER(header_method, ":method", "GET", SAVE);
    DEFINE_STATIC_HEADER(header_scheme, ":scheme", "http", SAVE);
    DEFINE_STATIC_HEADER(header_path, ":path", "/", SAVE);
    DEFINE_STATIC_HEADER(header_authority, ":authority", "www.example.com", SAVE);

    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_method);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_scheme);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_path);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_authority);

    static const uint8_t encoded[] = {
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_3_1, s_test_ex_3_1_init, NULL);

/* RFC-7541 - Request Examples with Huffman Coding - C.4.1. First Request */
static int s_test_ex_4_1_init(struct header_test_fixture *fixture) {

    fixture->encoder.use_huffman = true;

    DEFINE_STATIC_HEADER(header_method, ":method", "GET", SAVE);
    DEFINE_STATIC_HEADER(header_scheme, ":scheme", "http", SAVE);
    DEFINE_STATIC_HEADER(header_path, ":path", "/", SAVE);
    DEFINE_STATIC_HEADER(header_authority, ":authority", "www.example.com", SAVE);

    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_method);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_scheme);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_path);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_authority);

    static const uint8_t encoded[] = {
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};

    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_4_1, s_test_ex_4_1_init, NULL);

/* RFC-7541 - Response Examples without Huffman Coding - C.5.1. First Response */
static int s_test_ex_5_1_init(struct header_test_fixture *fixture) {

    DEFINE_STATIC_HEADER(header_status, ":status", "302", SAVE);
    DEFINE_STATIC_HEADER(header_cache_control, "cache-control", "private", SAVE);
    DEFINE_STATIC_HEADER(header_date, "date", "Mon, 21 Oct 2013 20:13:21 GMT", SAVE);
    DEFINE_STATIC_HEADER(header_location, "location", "https://www.example.com", SAVE);

    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_status);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_cache_control);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_date);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_location);

    static const uint8_t encoded[] = {
        0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x61, 0x1d, 0x4d, 0x6f,
        0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a,
        0x31, 0x33, 0x3a, 0x32, 0x31, 0x20, 0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
        0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_5_1, s_test_ex_5_1_init, NULL);

/* RFC-7541 - Response Examples with Huffman Coding - C.6.1. First Response */
static int s_test_ex_6_1_init(struct header_test_fixture *fixture) {

    fixture->encoder.use_huffman = true;

    DEFINE_STATIC_HEADER(header_status, ":status", "302", SAVE);
    DEFINE_STATIC_HEADER(header_cache_control, "cache-control", "private", SAVE);
    DEFINE_STATIC_HEADER(header_date, "date", "Mon, 21 Oct 2013 20:13:21 GMT", SAVE);
    DEFINE_STATIC_HEADER(header_location, "location", "https://www.example.com", SAVE);

    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_status);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_cache_control);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_date);
    aws_array_list_push_back(&fixture->headers_to_encode.header_block.header_fields, &header_location);

    static const uint8_t encoded[] = {
        0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10,
        0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff, 0x6e,
        0x91, 0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3,
    };
    aws_byte_buf_write(&fixture->expected_encoding_buf, encoded, sizeof(encoded));

    return AWS_OP_SUCCESS;
}
HEADER_TEST(h2_header_ex_6_1, s_test_ex_6_1_init, NULL);
