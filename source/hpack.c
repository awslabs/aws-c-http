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

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>

/* #TODO split hpack encoder/decoder into different types */

/* RFC-7540 6.5.2 */
const size_t s_hpack_dynamic_table_initial_size = 4096;
const size_t s_hpack_dynamic_table_initial_elements = 512;
/* TBD */
const size_t s_hpack_dynamic_table_max_size = 16 * 1024 * 1024;

/* Used for growing the dynamic table buffer when it fills up */
const float s_hpack_dynamic_table_buffer_growth_rate = 1.5F;

/* Used while decoding the header name & value, grows if necessary */
const size_t s_hpack_decoder_scratch_initial_size = 512;

struct aws_huffman_symbol_coder *hpack_get_coder(void);

/* Return a byte with the N right-most bits masked.
 * Ex: 2 -> 00000011 */
static uint8_t s_masked_right_bits_u8(uint8_t num_masked_bits) {
    AWS_ASSERT(num_masked_bits <= 8);
    const uint8_t cut_bits = 8 - num_masked_bits;
    return UINT8_MAX >> cut_bits;
}

size_t aws_hpack_get_encoded_length_integer(uint64_t integer, uint8_t prefix_size) {
    const uint8_t prefix_mask = s_masked_right_bits_u8(prefix_size);

    if (integer < prefix_mask) {
        /* If the integer fits inside the specified number of bits but won't be all 1's, then that's all she wrote */

        return 1;
    } else {
        integer -= prefix_mask;

        size_t num_bytes = 1;
        do {
            ++num_bytes;
            integer >>= 7;
        } while (integer);
        return num_bytes;
    }
}

int aws_hpack_encode_integer(uint64_t integer, uint8_t prefix_size, struct aws_byte_buf *output) {
    AWS_ASSERT(prefix_size <= 8);

    const struct aws_byte_buf output_backup = *output;

    if (output->len == output->capacity) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }
    const uint8_t prefix_mask = s_masked_right_bits_u8(prefix_size);

    if (integer < prefix_mask) {
        /* If the integer fits inside the specified number of bits but won't be all 1's, just write it */

        /* Just write out the bits we care about */
        output->buffer[output->len] = (output->buffer[output->len] & ~prefix_mask) | (uint8_t)integer;
        ++output->len;
    } else {
        /* Set all of the bits in the first octet to 1 */
        output->buffer[output->len] = (output->buffer[output->len] & ~prefix_mask) | prefix_mask;
        ++output->len;

        integer -= prefix_mask;

        const uint64_t hi_57bit_mask = UINT64_MAX - (UINT8_MAX >> 1);

        do {
            if (output->len == output->capacity) {
                *output = output_backup;
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
        } while (integer);
    }

    return AWS_OP_SUCCESS;
}

struct aws_http_header s_static_header_table[] = {
#define HEADER(_index, _name)                                                                                          \
    [_index] = {                                                                                                       \
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_name),                                                          \
    },

#define HEADER_WITH_VALUE(_index, _name, _value)                                                                       \
    [_index] = {                                                                                                       \
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_name),                                                          \
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_value),                                                        \
    },

#include <aws/http/private/hpack_header_static_table.def>

#undef HEADER
#undef HEADER_WITH_VALUE
};
static const size_t s_static_header_table_size = AWS_ARRAY_SIZE(s_static_header_table);

struct aws_byte_cursor s_static_header_table_name_only[] = {
#define HEADER(_index, _name) [_index] = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_name),
#define HEADER_WITH_VALUE(_index, _name, _value) HEADER(_index, _name)

#include <aws/http/private/hpack_header_static_table.def>

#undef HEADER
#undef HEADER_WITH_VALUE
};

/* aws_http_header * -> size_t */
static struct aws_hash_table s_static_header_reverse_lookup;
/* aws_byte_cursor * -> size_t */
static struct aws_hash_table s_static_header_reverse_lookup_name_only;

static uint64_t s_header_hash(const void *key) {
    const struct aws_http_header *header = key;

    return aws_hash_byte_cursor_ptr(&header->name);
}

static bool s_header_eq(const void *a, const void *b) {
    const struct aws_http_header *left = a;
    const struct aws_http_header *right = b;

    if (!aws_byte_cursor_eq(&left->name, &right->name)) {
        return false;
    }

    /* If the header stored in the table doesn't have a value, then it's a match */
    return !right->value.ptr || aws_byte_cursor_eq(&left->value, &right->value);
}

void aws_hpack_static_table_init(struct aws_allocator *allocator) {

    int result = aws_hash_table_init(
        &s_static_header_reverse_lookup,
        allocator,
        s_static_header_table_size - 1,
        s_header_hash,
        s_header_eq,
        NULL,
        NULL);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == result);

    result = aws_hash_table_init(
        &s_static_header_reverse_lookup_name_only,
        allocator,
        s_static_header_table_size - 1,
        aws_hash_byte_cursor_ptr,
        (aws_hash_callback_eq_fn *)aws_byte_cursor_eq,
        NULL,
        NULL);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == result);

    /* Process in reverse so that name_only prefers lower indices */
    for (size_t i = s_static_header_table_size; i > 0; --i) {
        /* Thanks, 1-based indexing. Thanks. */
        const size_t static_index = i - 1;

        result = aws_hash_table_put(
            &s_static_header_reverse_lookup, &s_static_header_table[static_index], (void *)static_index, NULL);
        AWS_FATAL_ASSERT(AWS_OP_SUCCESS == result);

        result = aws_hash_table_put(
            &s_static_header_reverse_lookup_name_only,
            &s_static_header_table_name_only[static_index],
            (void *)(static_index),
            NULL);
        AWS_FATAL_ASSERT(AWS_OP_SUCCESS == result);
    }
}

void aws_hpack_static_table_clean_up() {
    aws_hash_table_clean_up(&s_static_header_reverse_lookup);
    aws_hash_table_clean_up(&s_static_header_reverse_lookup_name_only);
}

/* Insertion is backwards, indexing is forwards */
struct aws_hpack_context {
    struct aws_allocator *allocator;

    enum aws_http_log_subject log_subject;
    void *log_id;

    struct aws_huffman_encoder encoder;
    struct aws_huffman_decoder decoder;

    struct {
        struct aws_http_header *buffer;
        size_t buffer_capacity; /* Number of http_headers that can fit in buffer */

        size_t num_elements;
        size_t index_0;

        /* Size in bytes, according to [4.1] */
        size_t size;
        size_t max_size;

        /* aws_http_header * -> size_t */
        struct aws_hash_table reverse_lookup;
        /* aws_byte_cursor * -> size_t */
        struct aws_hash_table reverse_lookup_name_only;
    } dynamic_table;

    /* PRO TIP: Don't union these, since string_decode calls integer_decode */
    struct hpack_progress_integer {
        enum {
            HPACK_INTEGER_STATE_INIT,
            HPACK_INTEGER_STATE_VALUE,
        } state;
        uint8_t bit_count;
    } progress_integer;
    struct hpack_progress_string {
        enum {
            HPACK_STRING_STATE_INIT,
            HPACK_STRING_STATE_LENGTH,
            HPACK_STRING_STATE_VALUE,
        } state;
        bool use_huffman;
        uint64_t length;
    } progress_string;

    struct hpack_progress_entry {
        enum {
            HPACK_ENTRY_STATE_INIT,
            /* Indexed header field: just 1 state. read index, find name and value at index */
            HPACK_ENTRY_STATE_INDEXED,
            /* Literal header field: name may be indexed OR literal, value is always literal */
            HPACK_ENTRY_STATE_LITERAL_BEGIN,
            HPACK_ENTRY_STATE_LITERAL_NAME_STRING,
            HPACK_ENTRY_STATE_LITERAL_VALUE_STRING,
            /* Dynamic table resize: just 1 state. read new size */
            HPACK_ENTRY_STATE_DYNAMIC_TABLE_RESIZE,
            /* Done */
            HPACK_ENTRY_STATE_COMPLETE,
        } state;

        union {
            struct {
                uint64_t index;
            } indexed;

            struct hpack_progress_literal {
                uint8_t prefix_size;
                enum aws_http_header_compression compression;
                uint64_t name_index;
                size_t name_length;
            } literal;

            struct {
                uint64_t size;
            } dynamic_table_resize;
        } u;

        enum aws_hpack_decode_type type;

        /* Scratch holds header name and value while decoding */
        struct aws_byte_buf scratch;
    } progress_entry;
};

#define HPACK_LOGF(level, hpack, text, ...)                                                                            \
    AWS_LOGF_##level((hpack)->log_subject, "id=%p [HPACK]: " text, (hpack)->log_id, __VA_ARGS__)
#define HPACK_LOG(level, hpack, text) HPACK_LOGF(level, hpack, "%s", text)

struct aws_hpack_context *aws_hpack_context_new(
    struct aws_allocator *allocator,
    enum aws_http_log_subject log_subject,
    void *log_id) {

    struct aws_hpack_context *context = aws_mem_calloc(allocator, 1, sizeof(struct aws_hpack_context));
    if (!context) {
        return NULL;
    }
    context->allocator = allocator;
    context->log_subject = log_subject;
    context->log_id = log_id;

    /* Initialize the huffman coders */
    struct aws_huffman_symbol_coder *hpack_coder = hpack_get_coder();
    aws_huffman_encoder_init(&context->encoder, hpack_coder);
    aws_huffman_decoder_init(&context->decoder, hpack_coder);
    aws_huffman_decoder_allow_growth(&context->decoder, true);

    /* #TODO Rewrite to be based on octet-size instead of list-size */

    /* Initialize dynamic table */
    context->dynamic_table.max_size = s_hpack_dynamic_table_initial_size;

    context->dynamic_table.buffer_capacity = s_hpack_dynamic_table_initial_elements;
    context->dynamic_table.buffer =
        aws_mem_calloc(allocator, context->dynamic_table.buffer_capacity, sizeof(struct aws_http_header));
    if (!context->dynamic_table.buffer) {
        goto dynamic_table_buffer_failed;
    }

    if (aws_hash_table_init(
            &context->dynamic_table.reverse_lookup,
            allocator,
            s_hpack_dynamic_table_initial_elements,
            s_header_hash,
            s_header_eq,
            NULL,
            NULL)) {
        goto reverse_lookup_failed;
    }

    if (aws_hash_table_init(
            &context->dynamic_table.reverse_lookup_name_only,
            allocator,
            s_hpack_dynamic_table_initial_elements,
            aws_hash_byte_cursor_ptr,
            (aws_hash_callback_eq_fn *)aws_byte_cursor_eq,
            NULL,
            NULL)) {
        goto name_only_failed;
    }

    if (aws_byte_buf_init(&context->progress_entry.scratch, allocator, s_hpack_decoder_scratch_initial_size)) {
        goto scratch_failed;
    }

    return context;

scratch_failed:
    aws_hash_table_clean_up(&context->dynamic_table.reverse_lookup_name_only);

name_only_failed:
    aws_hash_table_clean_up(&context->dynamic_table.reverse_lookup);

reverse_lookup_failed:
    if (context->dynamic_table.buffer) {
        aws_mem_release(allocator, context->dynamic_table.buffer);
    }

dynamic_table_buffer_failed:
    aws_mem_release(allocator, context);

    return NULL;
}

void aws_hpack_context_destroy(struct aws_hpack_context *context) {
    if (!context) {
        return;
    }
    if (context->dynamic_table.buffer) {
        aws_mem_release(context->allocator, context->dynamic_table.buffer);
    }
    aws_hash_table_clean_up(&context->dynamic_table.reverse_lookup);
    aws_hash_table_clean_up(&context->dynamic_table.reverse_lookup_name_only);
    aws_byte_buf_clean_up(&context->progress_entry.scratch);
    aws_mem_release(context->allocator, context);
}

size_t aws_hpack_get_header_size(const struct aws_http_header *header) {
    return header->name.len + header->value.len + 32;
}

/*
 * Gets the header from the dynamic table.
 * NOTE: This function only bounds checks on the buffer size, not the number of elements.
 */
static struct aws_http_header *s_dynamic_table_get(const struct aws_hpack_context *context, size_t index) {

    AWS_ASSERT(index < context->dynamic_table.buffer_capacity);

    return &context->dynamic_table
                .buffer[(context->dynamic_table.index_0 + index) % context->dynamic_table.buffer_capacity];
}

const struct aws_http_header *aws_hpack_get_header(const struct aws_hpack_context *context, size_t index) {
    if (index == 0 || index >= s_static_header_table_size + context->dynamic_table.num_elements) {
        aws_raise_error(AWS_ERROR_INVALID_INDEX);
        return NULL;
    }

    /* Check static table */
    if (index < s_static_header_table_size) {
        return &s_static_header_table[index];
    }

    /* Check dynamic table */
    return s_dynamic_table_get(context, index - s_static_header_table_size);
}

static const struct aws_http_header *s_get_header_u64(const struct aws_hpack_context *context, uint64_t index) {
    if (index > SIZE_MAX) {
        HPACK_LOG(ERROR, context, "Header index is absurdly large")
        aws_raise_error(AWS_ERROR_INVALID_INDEX);
        return NULL;
    }

    return aws_hpack_get_header(context, (size_t)index);
}

size_t aws_hpack_find_index(
    const struct aws_hpack_context *context,
    const struct aws_http_header *header,
    bool *found_value) {

    *found_value = false;

    /* Check static table */
    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&s_static_header_reverse_lookup, header, &elem);
    if (elem) {
        *found_value = ((const struct aws_http_header *)elem->key)->value.len;
        return (size_t)elem->value;
    }
    /* If not found, check name only table. Don't set found_value, it will be false */
    aws_hash_table_find(&s_static_header_reverse_lookup_name_only, &header->name, &elem);
    if (elem) {
        return (size_t)elem->value;
    }

    /* Check dynamic table */
    aws_hash_table_find(&context->dynamic_table.reverse_lookup, header, &elem);
    if (elem) {
        /* If an element was found, check if it has a value */
        *found_value = ((const struct aws_http_header *)elem->key)->value.len;
    } else {
        /* If not found, check name only table. Don't set found_value, it will be false */
        aws_hash_table_find(&context->dynamic_table.reverse_lookup_name_only, &header->name, &elem);
    }

    if (elem) {
        /* DO NOT SET found_value HERE! We only found the name, not the value! */

        size_t index;
        const size_t absolute_index = (size_t)elem->value;
        if (absolute_index >= context->dynamic_table.index_0) {
            index = absolute_index - context->dynamic_table.index_0;
        } else {
            index = (context->dynamic_table.buffer_capacity - context->dynamic_table.index_0) + absolute_index;
        }
        /* Need to add the static table size to re-base indicies */
        index += s_static_header_table_size;
        return index;
    }

    return 0;
}

/* Remove elements from the dynamic table until it fits in max_size bytes */
static int s_dynamic_table_shrink(struct aws_hpack_context *context, size_t max_size) {
    while (context->dynamic_table.size > max_size && context->dynamic_table.num_elements > 0) {
        struct aws_http_header *back = s_dynamic_table_get(context, context->dynamic_table.num_elements - 1);

        /* "Remove" the header from the table */
        context->dynamic_table.size -= aws_hpack_get_header_size(back);
        context->dynamic_table.num_elements -= 1;

        /* Remove old header from hash tables */
        if (aws_hash_table_remove(&context->dynamic_table.reverse_lookup, back, NULL, NULL)) {
            HPACK_LOG(ERROR, context, "Failed to remove header from the reverse lookup table");
            goto error;
        }

        /* If the name-only lookup is pointing to the element we're removing, it needs to go.
         * If not, it's pointing to a younger, sexier element. */
        struct aws_hash_element *elem = NULL;
        aws_hash_table_find(&context->dynamic_table.reverse_lookup_name_only, &back->name, &elem);
        if (elem && elem->key == back) {
            if (aws_hash_table_remove_element(&context->dynamic_table.reverse_lookup_name_only, elem)) {
                HPACK_LOG(ERROR, context, "Failed to remove header from the reverse lookup (name-only) table");
                goto error;
            }
        }
    }

    return AWS_OP_SUCCESS;

error:
    return AWS_OP_ERR;
}

/*
 * Resizes the dynamic table storage buffer to new_max_elements.
 * Useful when inserting over capacity, or when downsizing.
 */
static int s_dynamic_table_resize_buffer(struct aws_hpack_context *context, size_t new_max_elements) {

    /* Clear the old hash tables */
    aws_hash_table_clear(&context->dynamic_table.reverse_lookup);
    aws_hash_table_clear(&context->dynamic_table.reverse_lookup_name_only);

    struct aws_http_header *new_buffer = NULL;

    if (AWS_UNLIKELY(new_max_elements == 0)) {
        /* If new buffer is of size 0, don't both initializing, just clean up the old one. */
        goto cleanup_old_buffer;
    }

    /* Allocate the new buffer */
    new_buffer = aws_mem_calloc(context->allocator, new_max_elements, sizeof(struct aws_http_header));
    if (!new_buffer) {
        return AWS_OP_ERR;
    }

    /* Don't bother copying data if old buffer was of size 0 */
    if (AWS_UNLIKELY(context->dynamic_table.num_elements == 0)) {
        goto reset_dyn_table_state;
    }

    /*
     * Take a buffer that looks like this:
     *
     *               Index 0
     *               ^
     * +---------------------------+
     * | Below Block | Above Block |
     * +---------------------------+
     * And make it look like this:
     *
     * Index 0
     * ^
     * +-------------+-------------+
     * | Above Block | Below Block |
     * +-------------+-------------+
     */

    /* Copy as much the above block as possible */
    size_t above_block_size = context->dynamic_table.buffer_capacity - context->dynamic_table.index_0;
    if (above_block_size > new_max_elements) {
        above_block_size = new_max_elements;
    }
    memcpy(
        new_buffer,
        context->dynamic_table.buffer + context->dynamic_table.index_0,
        above_block_size * sizeof(struct aws_http_header));

    /* Copy as much of below block as possible */
    const size_t free_blocks_available = new_max_elements - above_block_size;
    const size_t old_blocks_to_copy = context->dynamic_table.buffer_capacity - above_block_size;
    const size_t below_block_size =
        free_blocks_available > old_blocks_to_copy ? old_blocks_to_copy : free_blocks_available;
    if (below_block_size) {
        memcpy(
            new_buffer + above_block_size,
            context->dynamic_table.buffer,
            below_block_size * sizeof(struct aws_http_header));
    }

    /* Free the old memory */
cleanup_old_buffer:
    aws_mem_release(context->allocator, context->dynamic_table.buffer);

    /* Reset state */
reset_dyn_table_state:
    if (context->dynamic_table.num_elements > new_max_elements) {
        context->dynamic_table.num_elements = new_max_elements;
    }
    context->dynamic_table.buffer_capacity = new_max_elements;
    context->dynamic_table.index_0 = 0;
    context->dynamic_table.buffer = new_buffer;

    /* Re-insert all of the reverse lookup elements */
    for (size_t i = 0; i < context->dynamic_table.num_elements; ++i) {
        aws_hash_table_put(&context->dynamic_table.reverse_lookup, &context->dynamic_table.buffer[i], (void *)i, NULL);
        aws_hash_table_put(
            &context->dynamic_table.reverse_lookup_name_only, &context->dynamic_table.buffer[i].name, (void *)i, NULL);
    }

    return AWS_OP_SUCCESS;
}

int aws_hpack_insert_header(struct aws_hpack_context *context, const struct aws_http_header *header) {

    /* Don't move forward if no elements allowed in the dynamic table */
    if (AWS_UNLIKELY(context->dynamic_table.max_size == 0)) {
        return AWS_OP_SUCCESS;
    }

    const size_t header_size = aws_hpack_get_header_size(header);

    /* If for whatever reason this new header is bigger than the total table size, burn everything to the ground. */
    if (AWS_UNLIKELY(header_size > context->dynamic_table.max_size)) {
        goto error;
    }

    /* Rotate out headers until there's room for the new header (this function will return immediately if nothing needs
     * to be evicted) */
    if (s_dynamic_table_shrink(context, context->dynamic_table.max_size - header_size)) {
        goto error;
    }

    /* If we're out of space in the buffer, grow it */
    if (context->dynamic_table.num_elements == context->dynamic_table.buffer_capacity) {
        /* If the buffer is currently of 0 size, reset it back to its initial size */
        const size_t new_size =
            context->dynamic_table.buffer_capacity
                ? (size_t)(context->dynamic_table.buffer_capacity * s_hpack_dynamic_table_buffer_growth_rate)
                : s_hpack_dynamic_table_initial_elements;

        if (s_dynamic_table_resize_buffer(context, new_size)) {
            goto error;
        }
    }

    /* Decrement index 0, wrapping if necessary */
    if (context->dynamic_table.index_0 == 0) {
        context->dynamic_table.index_0 = context->dynamic_table.buffer_capacity - 1;
    } else {
        context->dynamic_table.index_0--;
    }

    /* Increment num_elements */
    context->dynamic_table.num_elements++;
    /* Increment the size */
    context->dynamic_table.size += header_size;

    /* Put the header at the "front" of the table */
    struct aws_http_header *table_header = s_dynamic_table_get(context, 0);
    *table_header = *header;

    /* Write the new header to the look up tables */
    if (aws_hash_table_put(
            &context->dynamic_table.reverse_lookup, table_header, (void *)context->dynamic_table.index_0, NULL)) {
        goto error;
    }
    /* Note that we can just blindly put here, we want to overwrite any older entry so it isn't accidentally removed. */
    if (aws_hash_table_put(
            &context->dynamic_table.reverse_lookup_name_only,
            &table_header->name,
            (void *)context->dynamic_table.index_0,
            NULL)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    /* Do not attempt to handle the error, if something goes wrong, close the connection */
    return AWS_OP_ERR;
}

int aws_hpack_resize_dynamic_table(struct aws_hpack_context *context, size_t new_max_size) {

    /* Nothing to see here! */
    if (new_max_size == context->dynamic_table.max_size) {
        return AWS_OP_SUCCESS;
    }

    if (new_max_size > s_hpack_dynamic_table_max_size) {

        HPACK_LOGF(
            ERROR,
            context,
            "New dynamic table max size %zu is greater than the supported max size (%zu)",
            new_max_size,
            s_hpack_dynamic_table_max_size);
        goto error;
    }

    /* If downsizing, remove elements until we're within the new size constraints */
    if (s_dynamic_table_shrink(context, new_max_size)) {
        goto error;
    }

    /* Resize the buffer to the current size */
    if (s_dynamic_table_resize_buffer(context, context->dynamic_table.num_elements)) {
        goto error;
    }

    /* Update the max size */
    context->dynamic_table.max_size = new_max_size;

    return AWS_OP_SUCCESS;

error:
    return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
}

int aws_hpack_decode_integer(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_decode,
    uint8_t prefix_size,
    uint64_t *integer,
    bool *complete) {

    AWS_PRECONDITION(context);
    AWS_PRECONDITION(to_decode);
    AWS_PRECONDITION(prefix_size <= 8);
    AWS_PRECONDITION(integer);

    const uint8_t prefix_mask = s_masked_right_bits_u8(prefix_size);

    struct hpack_progress_integer *progress = &context->progress_integer;

    while (to_decode->len) {
        switch (progress->state) {
            case HPACK_INTEGER_STATE_INIT: {
                /* Read the first byte, and check whether this is it, or we need to continue */
                uint8_t byte = 0;
                bool succ = aws_byte_cursor_read_u8(to_decode, &byte);
                AWS_FATAL_ASSERT(succ);

                /* Cut the prefix */
                byte &= prefix_mask;

                /* No matter what, the first byte's value is always added to the integer */
                *integer = byte;

                if (byte != prefix_mask) {
                    goto handle_complete;
                }

                progress->state = HPACK_INTEGER_STATE_VALUE;
            } break;

            case HPACK_INTEGER_STATE_VALUE: {
                uint8_t byte = 0;
                bool succ = aws_byte_cursor_read_u8(to_decode, &byte);
                AWS_FATAL_ASSERT(succ);

                uint64_t new_byte_value = (uint64_t)(byte & 127) << progress->bit_count;
                if (*integer + new_byte_value < *integer) {
                    return aws_raise_error(AWS_ERROR_OVERFLOW_DETECTED);
                }
                *integer += new_byte_value;

                /* Check if we're done */
                if ((byte & 128) == 0) {
                    goto handle_complete;
                }

                /* Increment the bit count */
                progress->bit_count += 7;

                /* 7 Bits are expected to be used, so if we get to the point where any of
                 * those bits can't be used it's a decoding error */
                if (progress->bit_count > 64 - 7) {
                    return aws_raise_error(AWS_ERROR_OVERFLOW_DETECTED);
                }
            } break;
        }
    }

    /* Fell out of data loop, must need more data */
    *complete = false;
    return AWS_OP_SUCCESS;

handle_complete:
    AWS_ZERO_STRUCT(context->progress_integer);
    *complete = true;
    return AWS_OP_SUCCESS;
}

size_t aws_hpack_get_encoded_length_string(
    struct aws_hpack_context *context,
    struct aws_byte_cursor to_encode,
    bool huffman_encode) {

    AWS_PRECONDITION(context);
    AWS_PRECONDITION(to_encode.ptr && to_encode.len);

    size_t length = 0;

    /* Get the header length */
    size_t encoded_length;
    if (huffman_encode) {
        encoded_length = aws_huffman_get_encoded_length(&context->encoder, to_encode);
    } else {
        encoded_length = to_encode.len;
    }
    length += aws_hpack_get_encoded_length_integer(encoded_length, 7);

    /* Add the string length */
    length += encoded_length;

    return length;
}

int aws_hpack_encode_string(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_encode,
    bool huffman_encode,
    struct aws_byte_buf *output) {

    AWS_PRECONDITION(context);
    AWS_PRECONDITION(to_encode);
    AWS_PRECONDITION(output);

    if (output->len == output->capacity) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    struct aws_byte_cursor to_encode_backup = *to_encode;

    /* Write the use_huffman bit */
    output->buffer[output->len] = huffman_encode << 7;

    /* Write the header */
    size_t encoded_length;
    if (huffman_encode) {
        encoded_length = aws_huffman_get_encoded_length(&context->encoder, *to_encode);
    } else {
        encoded_length = to_encode->len;
    }
    if (aws_hpack_encode_integer(encoded_length, 7, output)) {
        goto error;
    }

    if (huffman_encode) {
        aws_huffman_encoder_reset(&context->encoder);
        int result = aws_huffman_encode(&context->encoder, to_encode, output);
        if (result) {
            goto error;
        }
    } else {
        bool result = aws_byte_buf_write_from_whole_cursor(output, *to_encode);
        if (!result) {
            aws_raise_error(AWS_ERROR_SHORT_BUFFER);
            goto error;
        }
        aws_byte_cursor_advance(to_encode, to_encode->len);
    }
    return AWS_OP_SUCCESS;

error:
    *to_encode = to_encode_backup;
    return AWS_OP_ERR;
}

int aws_hpack_decode_string(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_decode,
    struct aws_byte_buf *output,
    bool *complete) {

    AWS_PRECONDITION(context);
    AWS_PRECONDITION(to_decode);
    AWS_PRECONDITION(output);
    AWS_PRECONDITION(complete);

    struct hpack_progress_string *progress = &context->progress_string;

    while (to_decode->len) {
        switch (progress->state) {
            case HPACK_STRING_STATE_INIT: {
                /* Do init stuff */
                progress->state = HPACK_STRING_STATE_LENGTH;
                progress->use_huffman = *to_decode->ptr >> 7;
                aws_huffman_decoder_reset(&context->decoder);
                /* fallthrough, since we didn't consume any data */
            }
            /* FALLTHRU */
            case HPACK_STRING_STATE_LENGTH: {
                bool length_complete = false;
                if (aws_hpack_decode_integer(context, to_decode, 7, &progress->length, &length_complete)) {
                    return AWS_OP_ERR;
                }

                if (!length_complete) {
                    goto handle_ongoing;
                }

                if (progress->length == 0) {
                    goto handle_complete;
                }

                if (progress->length > SIZE_MAX) {
                    return aws_raise_error(AWS_ERROR_OVERFLOW_DETECTED);
                }

                progress->state = HPACK_STRING_STATE_VALUE;
            } break;

            case HPACK_STRING_STATE_VALUE: {
                /* Take either as much data as we need, or as much as we can */
                size_t to_process = (size_t)progress->length;
                if (to_process > to_decode->len) {
                    to_process = to_decode->len;
                }
                progress->length -= to_process;

                struct aws_byte_cursor chunk = aws_byte_cursor_advance(to_decode, to_process);

                if (progress->use_huffman) {
                    if (aws_huffman_decode(&context->decoder, &chunk, output)) {
                        HPACK_LOGF(ERROR, context, "Error from Huffman decoder: %s", aws_error_name(aws_last_error()));
                        return AWS_OP_ERR;
                    }

                    /* Decoder should consume all bytes we feed it.
                     * EOS (end-of-string) symbol could stop it early, but HPACK says to treat EOS as error. */
                    if (chunk.len != 0) {
                        HPACK_LOG(ERROR, context, "Huffman encoded end-of-string symbol is illegal");
                        return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
                    }
                } else {
                    if (aws_byte_buf_append_dynamic(output, &chunk)) {
                        return AWS_OP_ERR;
                    }
                }

                /* If whole length consumed, we're done */
                if (progress->length == 0) {
                    /* #TODO Validate any padding bits left over in final byte of string.
                     * "A padding not corresponding to the most significant bits of the
                     * code for the EOS symbol MUST be treated as a decoding error" */

                    /* #TODO impose limits on string length */

                    goto handle_complete;
                }
            } break;
        }
    }

handle_ongoing:
    /* Fell out of to_decode loop, must still be in progress */
    AWS_ASSERT(to_decode->len == 0);
    *complete = false;
    return AWS_OP_SUCCESS;

handle_complete:
    AWS_ASSERT(context->progress_string.length == 0);
    AWS_ZERO_STRUCT(context->progress_string);
    *complete = true;
    return AWS_OP_SUCCESS;
}

/* Implements RFC-7541 Section 6 - Binary Format */
int aws_hpack_decode(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_decode,
    struct aws_hpack_decode_result *result) {

    AWS_PRECONDITION(context);
    AWS_PRECONDITION(to_decode);
    AWS_PRECONDITION(result);

    /* Run state machine until we decode a complete entry.
     * Every state requires data, so we can simply loop until no more data available. */
    while (to_decode->len) {
        switch (context->progress_entry.state) {

            case HPACK_ENTRY_STATE_INIT: {
                /* Reset entry */
                AWS_ZERO_STRUCT(context->progress_entry.u);
                context->progress_entry.scratch.len = 0;

                /* Determine next state by looking at first few bits of the next byte:
                 * 1xxxxxxx: Indexed Header Field Representation
                 * 01xxxxxx: Literal Header Field with Incremental Indexing
                 * 001xxxxx: Dynamic Table Size Update
                 * 0001xxxx: Literal Header Field Never Indexed
                 * 0000xxxx: Literal Header Field without Indexing */
                uint8_t first_byte = to_decode->ptr[0];
                if (first_byte & (1 << 7)) {
                    /* 1xxxxxxx: Indexed Header Field Representation */
                    context->progress_entry.state = HPACK_ENTRY_STATE_INDEXED;

                } else if (first_byte & (1 << 6)) {
                    /* 01xxxxxx: Literal Header Field with Incremental Indexing */
                    context->progress_entry.u.literal.compression = AWS_HTTP_HEADER_COMPRESSION_USE_CACHE;
                    context->progress_entry.u.literal.prefix_size = 6;
                    context->progress_entry.state = HPACK_ENTRY_STATE_LITERAL_BEGIN;

                } else if (first_byte & (1 << 5)) {
                    /* 001xxxxx: Dynamic Table Size Update */
                    context->progress_entry.state = HPACK_ENTRY_STATE_DYNAMIC_TABLE_RESIZE;

                } else if (first_byte & (1 << 4)) {
                    /* 0001xxxx: Literal Header Field Never Indexed */
                    context->progress_entry.u.literal.compression = AWS_HTTP_HEADER_COMPRESSION_NO_FORWARD_CACHE;
                    context->progress_entry.u.literal.prefix_size = 4;
                    context->progress_entry.state = HPACK_ENTRY_STATE_LITERAL_BEGIN;
                } else {
                    /* 0000xxxx: Literal Header Field without Indexing */
                    context->progress_entry.u.literal.compression = AWS_HTTP_HEADER_COMPRESSION_NO_CACHE;
                    context->progress_entry.u.literal.prefix_size = 4;
                    context->progress_entry.state = HPACK_ENTRY_STATE_LITERAL_BEGIN;
                }
            } break;

            /* RFC-7541 6.1. Indexed Header Field Representation.
             * Decode one integer, which is an index into the table.
             * Result is the header name and value stored there. */
            case HPACK_ENTRY_STATE_INDEXED: {
                bool complete = false;
                uint64_t *index = &context->progress_entry.u.indexed.index;
                if (aws_hpack_decode_integer(context, to_decode, 7, index, &complete)) {
                    return AWS_OP_ERR;
                }

                if (!complete) {
                    break;
                }

                const struct aws_http_header *header = s_get_header_u64(context, *index);
                if (!header) {
                    return AWS_OP_ERR;
                }

                result->type = AWS_HPACK_DECODE_T_HEADER_FIELD;
                result->data.header_field = *header;
                goto handle_complete;
            } break;

            /* RFC-7541 6.2. Literal Header Field Representation.
             * We use multiple states to decode a literal...
             * The header-name MAY come from the table and MAY be encoded as a string.
             * The header-value is ALWAYS encoded as a string.
             *
             * This BEGIN state decodes one integer.
             * If it's non-zero, then it's the index in the table where we'll get the header-name from.
             * If it's zero, then we move to the HEADER_NAME state and decode header-name as a string instead */
            case HPACK_ENTRY_STATE_LITERAL_BEGIN: {
                struct hpack_progress_literal *literal = &context->progress_entry.u.literal;

                bool index_complete = false;
                if (aws_hpack_decode_integer(
                        context, to_decode, literal->prefix_size, &literal->name_index, &index_complete)) {
                    return AWS_OP_ERR;
                }

                if (!index_complete) {
                    break;
                }

                if (literal->name_index == 0) {
                    /* Index 0 means header-name is not in table. Need to decode header-name as a string instead */
                    context->progress_entry.state = HPACK_ENTRY_STATE_LITERAL_NAME_STRING;
                    break;
                }

                /* Otherwise we found index of header-name in table. */
                const struct aws_http_header *header = s_get_header_u64(context, literal->name_index);
                if (!header) {
                    return AWS_OP_ERR;
                }

                /* Store the name in scratch. We don't just keep a pointer to it because it could be
                 * evicted from the dynamic table later, when we save the literal. */
                if (aws_byte_buf_append_dynamic(&context->progress_entry.scratch, &header->name)) {
                    return AWS_OP_ERR;
                }

                /* Move on to decoding header-value.
                 * Value will also decode into the scratch, so save where name ends. */
                literal->name_length = header->name.len;
                context->progress_entry.state = HPACK_ENTRY_STATE_LITERAL_VALUE_STRING;
            } break;

            /* We only end up in this state if header-name is encoded as string. */
            case HPACK_ENTRY_STATE_LITERAL_NAME_STRING: {
                bool string_complete = false;
                if (aws_hpack_decode_string(context, to_decode, &context->progress_entry.scratch, &string_complete)) {
                    return AWS_OP_ERR;
                }

                if (!string_complete) {
                    break;
                }

                /* Done decoding name string! Move on to decoding the value string.
                 * Value will also decode into the scratch, so save where name ends. */
                context->progress_entry.u.literal.name_length = context->progress_entry.scratch.len;
                context->progress_entry.state = HPACK_ENTRY_STATE_LITERAL_VALUE_STRING;
            } break;

            /* Final state for "literal" entries.
             * Decode the header-value string, then deliver the results. */
            case HPACK_ENTRY_STATE_LITERAL_VALUE_STRING: {
                bool string_complete = false;
                if (aws_hpack_decode_string(context, to_decode, &context->progress_entry.scratch, &string_complete)) {
                    return AWS_OP_ERR;
                }

                if (!string_complete) {
                    break;
                }

                /* Done decoding value string. Done decoding entry. */
                struct hpack_progress_literal *literal = &context->progress_entry.u.literal;

                /* Set up a header with name and value (which are packed one after the other in scratch) */
                struct aws_http_header header;
                header.value = aws_byte_cursor_from_buf(&context->progress_entry.scratch);
                header.name = aws_byte_cursor_advance(&header.value, literal->name_length);
                header.compression = literal->compression;

                /* Save to table if necessary */
                if (literal->compression == AWS_HTTP_HEADER_COMPRESSION_USE_CACHE) {
                    if (aws_hpack_insert_header(context, &header)) {
                        return AWS_OP_ERR;
                    }
                }

                result->type = AWS_HPACK_DECODE_T_HEADER_FIELD;
                result->data.header_field = header;
                goto handle_complete;
            } break;

            /* RFC-7541 6.3. Dynamic Table Size Update
             * Read one integer, which is the new maximum size for the dynamic table. */
            case HPACK_ENTRY_STATE_DYNAMIC_TABLE_RESIZE: {
                uint64_t *size64 = &context->progress_entry.u.dynamic_table_resize.size;
                bool size_complete = false;
                if (aws_hpack_decode_integer(context, to_decode, 5, size64, &size_complete)) {
                    return AWS_OP_ERR;
                }

                if (!size_complete) {
                    break;
                }

                if (*size64 > SIZE_MAX) {
                    HPACK_LOG(ERROR, context, "Dynamic table update size is absurdly large");
                    return aws_raise_error(AWS_ERROR_HTTP_COMPRESSION);
                }
                size_t size = *size64;

                HPACK_LOGF(TRACE, context, "Dynamic table size update %zu", size);
                if (aws_hpack_resize_dynamic_table(context, size)) {
                    return AWS_OP_ERR;
                }

                result->type = AWS_HPACK_DECODE_T_DYNAMIC_TABLE_RESIZE;
                result->data.dynamic_table_resize = size;
                goto handle_complete;
            } break;

            default: {
                AWS_ASSERT(0 && "invalid state");
            } break;
        }
    }

    AWS_ASSERT(to_decode->len == 0);
    result->type = AWS_HPACK_DECODE_T_ONGOING;
    return AWS_OP_SUCCESS;

handle_complete:
    AWS_ASSERT(result->type != AWS_HPACK_DECODE_T_ONGOING);
    context->progress_entry.state = HPACK_ENTRY_STATE_INIT;
    return AWS_OP_SUCCESS;
}
