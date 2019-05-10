#ifndef AWS_HTTP_HPACK_H
#define AWS_HTTP_HPACK_H

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

AWS_EXTERN_C_BEGIN

struct aws_http_header;
struct aws_hpack_context;

/* Library-level init and shutdown */
void aws_hpack_static_table_init(struct aws_allocator *allocator);
void aws_hpack_static_table_clean_up(void);

/* General HPACK API */
struct aws_hpack_context *aws_hpack_context_new(struct aws_allocator *allocator, size_t max_dynamic_elements);
void aws_hpack_context_destroy(struct aws_hpack_context *context);
struct aws_http_header *aws_hpack_get_header(struct aws_hpack_context *context, size_t index);
int aws_hpack_find_index(struct aws_hpack_context *context, const struct aws_http_header *header, size_t *index);
int aws_hpack_insert_header(struct aws_hpack_context *context, const struct aws_http_header *header);
int aws_hpack_resize_dynamic_table(struct aws_hpack_context *context, size_t new_max_elements);

/* Public for testing purposes */
int aws_hpack_encode_integer(uint64_t integer, uint8_t prefix_size, struct aws_byte_buf *output);
int aws_hpack_decode_integer(struct aws_byte_cursor *to_decode, uint8_t prefix_size, uint64_t *integer);
int aws_hpack_encode_string(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_encode,
    bool huffman_encode,
    struct aws_byte_buf *output);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_HPACK_H */
