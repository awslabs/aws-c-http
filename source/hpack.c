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

#include <aws/http/hpack.h>

#include <aws/compression/huffman.h>

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

int aws_hpack_encode_string(const struct aws_byte_cursor *to_encode, struct aws_huffman_encoder *encoder, struct aws_byte_buf *output) {
    if (output->len == output->capacity) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    unsigned use_huffman = encoder != NULL;

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

/*
FOR STRINGS: Checks the last bits match EOS
struct aws_huffman_code eos = ...

uint64_t leftovers = (decoder->working_bits >> (BITSIZEOF(decoder->working_bits) - bits_left));
uint64_t expected = eos.pattern >> (eos.num_bits - bits_left);

if (bits_left < 8 &&
    leftovers == expected) {
    return AWS_HUFFMAN_EOS_REACHED;
}
*/
