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

#include <aws/common/byte_buf.h>

/**
 * Datastructure for stable and efficient string storage
 * Strings are stable in memory, once added to the vault they never move.
 * Memory is pooled, there is not a single allocation per string.
 * WARNING: in the current implementation, strings are never removed.
 */
struct aws_byte_vault {
    /* Array-list of byte-buffers.
     * Each byte-buffer is block_size in length.*/
    struct aws_array_list buf_array;
    size_t block_size;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
int aws_byte_vault_init(struct aws_byte_vault *vault, struct aws_allocator *allocator, size_t reserve);

AWS_HTTP_API
void aws_byte_vault_clean_up(struct aws_byte_vault *vault);

AWS_HTTP_API
int aws_byte_vault_add(struct aws_byte_vault *vault, struct aws_byte_cursor src, struct aws_byte_cursor *out);

AWS_EXTERN_C_END
