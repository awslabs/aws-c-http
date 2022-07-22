
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/http/private/hpack.h>


struct aws_huffman_symbol_coder *hpack_get_coder(void);

/* aws_http_header * -> size_t */
static struct aws_hash_table s_static_header_reverse_lookup;
/* aws_byte_cursor * -> size_t */
static struct aws_hash_table s_static_header_reverse_lookup_name_only;

void aws_hpack_static_table_init(struct aws_allocator *allocator) {

    int result = aws_hash_table_init(
        &s_static_header_reverse_lookup,
        allocator,
        aws_hpack_static_table_num_elements - 1,
        aws_hpack_header_table_hash,
        aws_hpack_header_table_eq,
        NULL,
        NULL);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == result);

    result = aws_hash_table_init(
        &s_static_header_reverse_lookup_name_only,
        allocator,
        aws_hpack_static_table_num_elements - 1,
        aws_hash_byte_cursor_ptr,
        (aws_hash_callback_eq_fn *)aws_byte_cursor_eq,
        NULL,
        NULL);
    AWS_FATAL_ASSERT(AWS_OP_SUCCESS == result);

    /* Process in reverse so that name_only prefers lower indices */
    for (size_t i = aws_hpack_static_table_num_elements - 1; i > 0; --i) {
        /* the tables are created as 1-based indexing */
        result = aws_hash_table_put(&s_static_header_reverse_lookup, &s_static_header_table[i], (void *)i, NULL);
        AWS_FATAL_ASSERT(AWS_OP_SUCCESS == result);

        result = aws_hash_table_put(
            &s_static_header_reverse_lookup_name_only, &s_static_header_table_name_only[i], (void *)(i), NULL);
        AWS_FATAL_ASSERT(AWS_OP_SUCCESS == result);
    }
}

void aws_hpack_static_table_clean_up() {
    aws_hash_table_clean_up(&s_static_header_reverse_lookup);
    aws_hash_table_clean_up(&s_static_header_reverse_lookup_name_only);
}

uint64_t aws_hpack_header_table_hash(const void *key) {
    const struct aws_http_header *header = key;

    return aws_hash_combine(aws_hash_byte_cursor_ptr(&header->name), aws_hash_byte_cursor_ptr(&header->value));
}

bool aws_hpack_header_table_eq(const void *a, const void *b) {
    const struct aws_http_header *left = a;
    const struct aws_http_header *right = b;

    if (!aws_byte_cursor_eq(&left->name, &right->name)) {
        return false;
    }

    return aws_byte_cursor_eq(&left->value, &right->value);
}

size_t aws_hpack_static_table_find_name_and_value(const struct aws_http_header *header, bool *out_has_value) {
    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&s_static_header_reverse_lookup, header, &elem);
    if (elem) {
        /* If an element was found, check if it has a value */
        *out_has_value = ((const struct aws_http_header *)elem->key)->value.len;
        return (size_t)elem->value;
    }

    return 0;
}

size_t aws_hpack_static_table_find_name_only(struct aws_byte_cursor name) {
    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&s_static_header_reverse_lookup_name_only, &header->name, &elem);
    if (elem) {
        return (size_t)elem->value;
    }
    return 0;
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
const size_t aws_hpack_static_table_num_elements = AWS_ARRAY_SIZE(s_static_header_table);

struct aws_byte_cursor s_static_header_table_name_only[] = {
#define HEADER(_index, _name) [_index] = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(_name),
#define HEADER_WITH_VALUE(_index, _name, _value) HEADER(_index, _name)

#include <aws/http/private/hpack_header_static_table.def>

#undef HEADER
#undef HEADER_WITH_VALUE
};
