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

#include <aws/http/private/byte_vault.h>

struct aws_byte_buf *s_get_back_buf(struct aws_byte_vault *vault) {
    struct aws_byte_buf *retval;
    aws_array_list_get_at_ptr(&vault->buf_array, &retval, aws_array_list_length(&vault->buf_array) - 1);
    return retval;
}

struct aws_byte_buf *s_add_buf(struct aws_byte_vault *vault, size_t min_size) {
    /* Allocate byte-buf */
    size_t capacity = min_size < vault->block_size ? vault->block_size : min_size;
    struct aws_byte_buf buf;
    if (aws_byte_buf_init(&buf, vault->buf_array.alloc, capacity)) {
        return NULL;
    }

    /* Add byte-buf to array-list */
    if (aws_array_list_push_back(&vault->buf_array, &buf)) {
        aws_byte_buf_clean_up(&buf);
        return NULL;
    }

    return s_get_back_buf(vault);
}

int aws_byte_vault_init(struct aws_byte_vault *vault, struct aws_allocator *allocator, size_t reserve) {
    AWS_PRECONDITION(vault);
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(reserve > 0);

    AWS_ZERO_STRUCT(*vault);
    vault->block_size = reserve;
    if (aws_array_list_init_dynamic(&vault->buf_array, allocator, 4, sizeof(struct aws_byte_buffer))) {
        goto error;
    }

    /* Add one byte-buf to start with */
    if (s_add_buf(vault, reserve) == NULL) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    aws_byte_vault_clean_up(vault);
    return AWS_OP_ERR;
}

void aws_byte_vault_clean_up(struct aws_byte_vault *vault) {
    if (aws_array_list_is_valid(vault)) {
        size_t len = aws_array_list_get_length(&vault->buf_array);
        for (size_t i = 0; i < len; ++i) {
            struct aws_byte_buf *buf;
            aws_array_list_get_at_ptr(&vault->buf_array, &buf, i);
            aws_byte_buf_clean_up(&buf);
        }
        aws_array_list_clean_up(&vault->buf_array);
    }
    AWS_ZERO_STRUCT(vault);
}

int aws_byte_vault_add(struct aws_byte_vault *vault, struct aws_byte_cursor src, struct aws_byte_cursor *out) {
    AWS_PRECONDITION(vault);
    AWS_PRECONDITION(aws_array_list_is_valid(&vault->buf_array));
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&src));
    AWS_PRECONDITION(out);

    AWS_ZERO_STRUCT(*out);

    if (src.len == 0) {
        return AWS_OP_SUCCESS;
    }

    /* Add bytes to current buf. If it doesn't have enough space, make a new one. */
    struct aws_byte_buf *buf = s_get_back_buf(vault);
    if ((buf->capacity - buf->len) < src.len) {
        buf = s_add_buf(vault, src.len);
        if (!buf) {
            return AWS_OP_ERR;
        }
    }

    out->ptr = buf->buffer + buf->len;
    out->len = src.len;
    aws_byte_buf_write_from_whole_cursor(buf, src);

    return AWS_OP_SUCCESS;

}
