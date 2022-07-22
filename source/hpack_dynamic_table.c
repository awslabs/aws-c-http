/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/http/private/hpack.h>

/* RFC-7540 6.5.2 */
const size_t s_hpack_dynamic_table_initial_size = 4096;
const size_t s_hpack_dynamic_table_initial_elements = 512;
/* TBD */
const size_t s_hpack_dynamic_table_max_size = 16 * 1024 * 1024;

/* Used for growing the dynamic table buffer when it fills up */
const float s_hpack_dynamic_table_buffer_growth_rate = 1.5F;

size_t aws_hpack_get_header_size(const struct aws_http_header *header) {
    return header->name.len + header->value.len + 32;
}

void aws_hpack_dynamic_table_init(struct aws_hpack_dynamic_table *table, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*table);

    table->max_size = s_hpack_dynamic_table_initial_size;
    /* Initial header table size for http2 setting is the same as initial size for dynamic table */
    table->protocol_max_size_setting = s_hpack_dynamic_table_initial_size;
    table->buffer_capacity = s_hpack_dynamic_table_initial_elements;
    table->buffer = aws_mem_calloc(allocator, table->buffer_capacity, sizeof(struct aws_http_header));

    aws_hash_table_init(
        &table->reverse_lookup,
        allocator,
        s_hpack_dynamic_table_initial_elements,
        aws_hpack_header_table_hash,
        aws_hpack_header_table_eq,
        NULL,
        NULL);

    aws_hash_table_init(
        &table->reverse_lookup_name_only,
        allocator,
        s_hpack_dynamic_table_initial_elements,
        aws_hash_byte_cursor_ptr,
        (aws_hash_callback_eq_fn *)aws_byte_cursor_eq,
        NULL,
        NULL);
}

/*
 * Gets the header from the dynamic table.
 * NOTE: This function only bounds checks on the buffer size, not the number of elements.
 */
static struct aws_http_header *s_dynamic_table_get(const struct aws_hpack_dynamic_table *table, size_t index) {

    AWS_ASSERT(index < table->buffer_capacity);

    return &table->buffer[(table->index_0 + index) % table->buffer_capacity];
}

void aws_hpack_dynamic_table_clean_up(struct aws_hpack_dynamic_table *table) {
    if (table->buffer) {
        while (table->num_elements > 0) {
            struct aws_http_header *back = s_dynamic_table_get(table, table->num_elements - 1);
            table->num_elements -= 1;
            /* clean-up the memory we allocate for it */
            aws_mem_release(table->allocator, back->name.ptr);
        }
        aws_mem_release(table->allocator, table->buffer);
    }

    aws_hash_table_clean_up(&table->reverse_lookup);
    aws_hash_table_clean_up(&table->reverse_lookup_name_only);
    AWS_ZERO_STRUCT(*table);
}

size_t aws_hpack_dynamic_table_get_num_elements(const struct aws_hpack_dynamic_table *table) {
    return table->num_elements;
}

/* Given index from elem->value, return HPACK index which takes index_0 and static table size into account */
static size_t s_translate_index_from_dynamic_table(const struct aws_hpack_dynamic_table *table, size_t absolute_index) {
    size_t index;
    if (absolute_index >= table->index_0) {
        index = absolute_index - table->index_0;
    } else {
        index = (table->buffer_capacity - table->index_0) + absolute_index;
    }
    /* Need to add the static table size to re-base index */
    index += aws_hpack_static_table_num_elements;
    return index;
}

size_t aws_hpack_dynamic_table_find_name_and_value(
    const struct aws_hpack_dynamic_table *table,
    const struct aws_http_header *header,
    bool *out_has_value) {

    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&table->reverse_lookup, header, &elem);
    if (elem) {
        *out_has_value = ((const struct aws_http_header *)elem->key)->value.len;
        return s_translate_index_from_dynamic_table((size_t)elem->value);
    }
    return 0;
}

size_t aws_hpack_dynamic_table_find_name_only(
    const struct aws_hpack_dynamic_table *table,
    struct aws_byte_cursor name) {

    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&encoder->dynamic_table.reverse_lookup_name_only, &header->name, &elem);
    if (elem) {
        return s_translate_index_from_dynamic_table((size_t)->elem->value);
    }
    return 0;
}

/* Remove elements from the dynamic table until it fits in max_size bytes */
static int s_dynamic_table_shrink(struct aws_hpack_dynamic_table *table, size_t max_size) {
    while (table->size > max_size && table->num_elements > 0) {
        struct aws_http_header *back = s_dynamic_table_get(context, table->num_elements - 1);

        /* "Remove" the header from the table */
        table->size -= aws_hpack_get_header_size(back);
        table->num_elements -= 1;

        /* Remove old header from hash tables */
        if (aws_hash_table_remove(&table->reverse_lookup, back, NULL, NULL)) {
            HPACK_LOG(ERROR, context, "Failed to remove header from the reverse lookup table");
            goto error;
        }

        /* If the name-only lookup is pointing to the element we're removing, it needs to go.
         * If not, it's pointing to a younger, sexier element. */
        struct aws_hash_element *elem = NULL;
        aws_hash_table_find(&table->reverse_lookup_name_only, &back->name, &elem);
        if (elem && elem->key == back) {
            if (aws_hash_table_remove_element(&table->reverse_lookup_name_only, elem)) {
                HPACK_LOG(ERROR, context, "Failed to remove header from the reverse lookup (name-only) table");
                goto error;
            }
        }

        /* clean up the memory we allocated to hold the name and value string*/
        aws_mem_release(context->allocator, back->name.ptr);
    }

    return AWS_OP_SUCCESS;

error:
    return AWS_OP_ERR;
}

/*
 * Resizes the dynamic table storage buffer to new_max_elements.
 * Useful when inserting over capacity, or when downsizing.
 * Do shrink first, if you want to remove elements, or memory leak will happen.
 */
static int s_dynamic_table_resize_buffer(struct aws_hpack_dynamic_table *table, size_t new_max_elements) {

    /* Clear the old hash tables */
    aws_hash_table_clear(&table->reverse_lookup);
    aws_hash_table_clear(&table->reverse_lookup_name_only);

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
    if (AWS_UNLIKELY(table->num_elements == 0)) {
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
    size_t above_block_size = table->buffer_capacity - table->index_0;
    if (above_block_size > new_max_elements) {
        above_block_size = new_max_elements;
    }
    memcpy(new_buffer, table->buffer + table->index_0, above_block_size * sizeof(struct aws_http_header));

    /* Copy as much of below block as possible */
    const size_t free_blocks_available = new_max_elements - above_block_size;
    const size_t old_blocks_to_copy = table->buffer_capacity - above_block_size;
    const size_t below_block_size = aws_min_size(free_blocks_available, old_blocks_to_copy);
    if (below_block_size) {
        memcpy(new_buffer + above_block_size, table->buffer, below_block_size * sizeof(struct aws_http_header));
    }

    /* Free the old memory */
cleanup_old_buffer:
    aws_mem_release(context->allocator, table->buffer);

    /* Reset state */
reset_dyn_table_state:
    if (table->num_elements > new_max_elements) {
        table->num_elements = new_max_elements;
    }
    table->buffer_capacity = new_max_elements;
    table->index_0 = 0;
    table->buffer = new_buffer;

    /* Re-insert all of the reverse lookup elements */
    for (size_t i = 0; i < table->num_elements; ++i) {
        if (aws_hash_table_put(&table->reverse_lookup, &table->buffer[i], (void *)i, NULL)) {
            return AWS_OP_ERR;
        }
        if (aws_hash_table_put(&table->reverse_lookup_name_only, &table->buffer[i].name, (void *)i, NULL)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_hpack_dynamic_table_insert_header(struct aws_hpack_dynamic_table *table, const struct aws_http_header *header) {

    /* Don't move forward if no elements allowed in the dynamic table */
    if (AWS_UNLIKELY(table->max_size == 0)) {
        return AWS_OP_SUCCESS;
    }

    const size_t header_size = aws_hpack_get_header_size(header);

    /* If for whatever reason this new header is bigger than the total table size, burn everything to the ground. */
    if (AWS_UNLIKELY(header_size > table->max_size)) {
        /* #TODO handle this. It's not an error. It should simply result in an empty table RFC-7541 4.4 */
        goto error;
    }

    /* Rotate out headers until there's room for the new header (this function will return immediately if nothing needs
     * to be evicted) */
    if (s_dynamic_table_shrink(context, table->max_size - header_size)) {
        goto error;
    }

    /* If we're out of space in the buffer, grow it */
    if (table->num_elements == table->buffer_capacity) {
        /* If the buffer is currently of 0 size, reset it back to its initial size */
        const size_t new_size = table->buffer_capacity
                                    ? (size_t)(table->buffer_capacity * s_hpack_dynamic_table_buffer_growth_rate)
                                    : s_hpack_dynamic_table_initial_elements;

        if (s_dynamic_table_resize_buffer(context, new_size)) {
            goto error;
        }
    }

    /* Decrement index 0, wrapping if necessary */
    if (table->index_0 == 0) {
        table->index_0 = table->buffer_capacity - 1;
    } else {
        table->index_0--;
    }

    /* Increment num_elements */
    table->num_elements++;
    /* Increment the size */
    table->size += header_size;

    /* Put the header at the "front" of the table */
    struct aws_http_header *table_header = s_dynamic_table_get(table, 0);

    /* TODO:: We can optimize this with ring buffer. */
    /* allocate memory for the name and value, which will be deallocated whenever the entry is evicted from the table or
     * the table is cleaned up. We keep the pointer in the name pointer of each entry */
    const size_t buf_memory_size = header->name.len + header->value.len;

    if (buf_memory_size) {
        uint8_t *buf_memory = aws_mem_acquire(context->allocator, buf_memory_size);
        if (!buf_memory) {
            return AWS_OP_ERR;
        }
        struct aws_byte_buf buf = aws_byte_buf_from_empty_array(buf_memory, buf_memory_size);
        /* Copy header, then backup strings into our own allocation */
        *table_header = *header;
        aws_byte_buf_append_and_update(&buf, &table_header->name);
        aws_byte_buf_append_and_update(&buf, &table_header->value);
    } else {
        /* if buf_memory_size is 0, no memory needed, we will insert the empty header into dynamic table */
        *table_header = *header;
        table_header->name.ptr = NULL;
        table_header->value.ptr = NULL;
    }
    /* Write the new header to the look up tables */
    if (aws_hash_table_put(&table->reverse_lookup, table_header, (void *)table->index_0, NULL)) {
        goto error;
    }
    /* Note that we can just blindly put here, we want to overwrite any older entry so it isn't accidentally removed. */
    if (aws_hash_table_put(&table->reverse_lookup_name_only, &table_header->name, (void *)table->index_0, NULL)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    /* Do not attempt to handle the error, if something goes wrong, close the connection */
    return AWS_OP_ERR;
}

int aws_hpack_dynamic_table_resize(struct aws_hpack_dynamic_table *table, size_t new_max_size) {

    /* Nothing to see here! */
    if (new_max_size == table->max_size) {
        return AWS_OP_SUCCESS;
    }

    if (new_max_size > s_hpack_dynamic_table_max_size) {

        HPACK_LOGF(
            ERROR,
            context,
            "New dynamic table max size %zu is greater than the supported max size (%zu)",
            new_max_size,
            s_hpack_dynamic_table_max_size);
        aws_raise_error(AWS_ERROR_OVERFLOW_DETECTED);
        goto error;
    }

    /* If downsizing, remove elements until we're within the new size constraints */
    if (s_dynamic_table_shrink(context, new_max_size)) {
        goto error;
    }

    /* Resize the buffer to the current size */
    if (s_dynamic_table_resize_buffer(context, table->num_elements)) {
        goto error;
    }

    /* Update the max size */
    table->max_size = new_max_size;

    return AWS_OP_SUCCESS;

error:
    return AWS_OP_ERR;
}
