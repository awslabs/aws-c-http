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

#include <aws/http/private/hpack.h>

#include <aws/http/request_response.h>

#include <aws/compression/huffman.h>

#include <aws/common/hash_table.h>
#include <aws/common/string.h>

#include <assert.h>

int aws_hpack_encode_integer(uint64_t integer, uint8_t prefix_size, struct aws_byte_buf *output) {
    assert(prefix_size <= 8);

    if (output->len == output->capacity) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    const uint8_t cut_bits = 8 - prefix_size;
    const uint8_t prefix_mask = UINT8_MAX >> cut_bits;

    if (integer < prefix_mask) {
        /* If the integer fits inside the specified number of bits but
           won't be all 1's, just write it */

        /* Just write out the bits we care about */
        *output->buffer |= integer;
        ++output->len;
    } else {
        /* Set all of the bits in the first octet to 1 */
        *output->buffer |= prefix_mask;
        ++output->len;

        integer -= prefix_mask;

        const uint64_t hi_57bit_mask = UINT64_MAX - (UINT8_MAX >> 1);

        while (integer) {
            if (output->len == output->capacity) {
                return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            }

            /* Take top 7 bits from the integer */
            uint8_t this_octet = integer % 128;
            if (integer & hi_57bit_mask) {
                /* If there's more after this octet, set the hi bit */
                this_octet += 128;
            }

            aws_byte_buf_write_u8(output, this_octet);

            /* Remove the written bits */
            integer >>= 7;
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_hpack_decode_integer(struct aws_byte_cursor *to_decode, uint8_t prefix_size, uint64_t *integer) {
    assert(prefix_size <= 8);
    assert(integer);

    if (to_decode->len == 0) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    const uint8_t cut_bits = 8 - prefix_size;
    const uint8_t prefix_mask = UINT8_MAX >> cut_bits;

    uint8_t byte = 0;
    if (!aws_byte_cursor_read_u8(to_decode, &byte)) {
        return AWS_OP_ERR;
    }
    /* Cut the prefix */
    byte &= prefix_mask;

    /* No matter what, the first byte's value is always added to the integer */
    *integer = byte;

    if (byte == prefix_mask) {
        uint8_t bit_count = 0;
        do {
            if (!aws_byte_cursor_read_u8(to_decode, &byte)) {
                return AWS_OP_ERR;
            }
            *integer += (byte & 127) << bit_count;
            bit_count += 7;
        } while (byte & 128);
    }

    return AWS_OP_SUCCESS;
}

int aws_hpack_encode_string(
    const struct aws_byte_cursor *to_encode,
    struct aws_huffman_encoder *encoder,
    struct aws_byte_buf *output) {

    if (output->len == output->capacity) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    bool use_huffman = encoder != NULL;

    /* Write the use_huffman bit */
    *output->buffer |= use_huffman << 7;

    /* Write the header */
    if (aws_hpack_encode_integer(to_encode->len, 7, output)) {
        return AWS_OP_ERR;
    }

    if (use_huffman) {
        struct aws_byte_cursor to_encode_copy = *to_encode;
        return aws_huffman_encode(encoder, &to_encode_copy, output);
    }

    return aws_byte_buf_write_from_whole_cursor(output, *to_encode);
}

#define HEADER(_index, _name)                                                                                          \
    [_index] = {                                                                                                       \
        .name =                                                                                                        \
            {                                                                                                          \
                .ptr = (uint8_t *)(_name),                                                                             \
                .len = AWS_ARRAY_SIZE(_name),                                                                          \
            },                                                                                                         \
        .value =                                                                                                       \
            {                                                                                                          \
                .ptr = NULL,                                                                                           \
                .len = 0,                                                                                              \
            },                                                                                                         \
    },

#define HEADER_WITH_VALUE(_index, _name, _value)                                                                       \
    [_index] = {                                                                                                       \
        .name =                                                                                                        \
            {                                                                                                          \
                .ptr = (uint8_t *)(_name),                                                                             \
                .len = AWS_ARRAY_SIZE(_name),                                                                          \
            },                                                                                                         \
        .value =                                                                                                       \
            {                                                                                                          \
                .ptr = (uint8_t *)(_value),                                                                            \
                .len = AWS_ARRAY_SIZE(_value),                                                                         \
            },                                                                                                         \
    },

struct aws_http_header s_static_header_table[] = {
#include <aws/http/private/hpack_header_static_table.def>
};

#undef HEADER
#undef HEADER_WITH_VALUE

static struct aws_hash_table s_static_header_reverse_lookup;

static uint64_t s_header_hash(const void *key) {
    const struct aws_http_header *header = key;

    return aws_hash_byte_cursor_ptr(&header->name);
}

static bool s_header_eq(const void *a, const void *b) {
    const struct aws_http_header *left = a;
    const struct aws_http_header *right = b;

    return aws_byte_cursor_eq(&left->name, &right->name) && aws_byte_cursor_eq(&left->value, &right->value);
}

void aws_hpack_build_lookup_table(struct aws_allocator *allocator) {

    aws_hash_table_init(
        &s_static_header_reverse_lookup,
        allocator,
        AWS_ARRAY_SIZE(s_static_header_table) - 1,
        s_header_hash,
        s_header_eq,
        NULL,
        NULL);

#define HEADER(_index, _name)                                                                                          \
    aws_hash_table_put(&s_static_header_reverse_lookup, &s_static_header_table[_index], (void *)_index, NULL);
#define HEADER_WITH_VALUE(_index, _name, _value) HEADER(_index, _name)

#include <aws/http/private/hpack_header_static_table.def>

#undef HEADER
#undef HEADER_WITH_VALUE
}

struct aws_http_header *aws_hpack_get_index_header(size_t index) {
    assert(index > 0);
    assert(index < AWS_ARRAY_SIZE(s_static_header_table));

    return &s_static_header_table[index];
}

uint64_t aws_hpack_get_index_for_header(const struct aws_http_header *header) {

    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&s_static_header_reverse_lookup, header, &elem);
    if (elem) {
        return (uint64_t)elem->value;
    }

    return 0;
}
