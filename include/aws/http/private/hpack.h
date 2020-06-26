#ifndef AWS_HTTP_HPACK_H
#define AWS_HTTP_HPACK_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/http/request_response.h>

struct aws_byte_buf;
struct aws_byte_cursor;
struct aws_http_header;
struct aws_hpack_context;

/**
 * Result of aws_hpack_decode() call.
 * If a complete entry has not been decoded yet, type is ONGOING.
 * Otherwise, type informs which data to look at.
 */
struct aws_hpack_decode_result {
    enum aws_hpack_decode_type {
        AWS_HPACK_DECODE_T_ONGOING,
        AWS_HPACK_DECODE_T_HEADER_FIELD,
        AWS_HPACK_DECODE_T_DYNAMIC_TABLE_RESIZE,
    } type;

    union {
        /* If type is AWS_HPACK_DECODE_T_HEADER_FIELD */
        struct aws_http_header header_field;

        /* If type is AWS_HPACK_DECODE_T_DYNAMIC_TABLE_RESIZE */
        size_t dynamic_table_resize;
    } data;
};

/**
 * Controls whether non-indexed strings will use Huffman encoding.
 * In SMALLEST mode, strings will only be sent with Huffman encoding if it makes them smaller.
 *
 * Note: This does not control compression via "indexing",
 * for that, see `aws_http_header_compression`.
 * This only controls how string values are encoded when they're not already in a table.
 */
enum aws_hpack_huffman_mode {
    AWS_HPACK_HUFFMAN_SMALLEST,
    AWS_HPACK_HUFFMAN_NEVER,
    AWS_HPACK_HUFFMAN_ALWAYS,
};

AWS_EXTERN_C_BEGIN

/* Library-level init and shutdown */
AWS_HTTP_API
void aws_hpack_static_table_init(struct aws_allocator *allocator);

AWS_HTTP_API
void aws_hpack_static_table_clean_up(void);

/* General HPACK API */
AWS_HTTP_API
struct aws_hpack_context *aws_hpack_context_new(
    struct aws_allocator *allocator,
    enum aws_http_log_subject log_subject,
    const void *log_id);

AWS_HTTP_API
void aws_hpack_context_destroy(struct aws_hpack_context *context);

/**
 * Decode the next entry in the header-block-fragment.
 * If result->type is ONGOING, then call decode() again with more data to resume decoding.
 * Otherwise, type is either a HEADER_FIELD or a DYNAMIC_TABLE_RESIZE.
 *
 * If an error occurs, the decoder is broken and decode() must not be called again.
 */
AWS_HTTP_API
int aws_hpack_decode(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_decode,
    struct aws_hpack_decode_result *result);

/**
 * Encode header-block into the output.
 * This function will mutate the hpack context, so an error means the context can no longer be used.
 * Note that output will be dynamically resized if it's too short.
 */
AWS_HTTP_API
int aws_hpack_encode_header_block(
    struct aws_hpack_context *context,
    const struct aws_http_headers *headers,
    struct aws_byte_buf *output);

/* Returns the hpack size of a header (name.len + value.len + 32) [4.1] */
AWS_HTTP_API
size_t aws_hpack_get_header_size(const struct aws_http_header *header);

/* Returns the number of elements in dynamic table now */
AWS_HTTP_API
size_t aws_hpack_get_dynamic_table_num_elements(const struct aws_hpack_context *context);

AWS_HTTP_API
const struct aws_http_header *aws_hpack_get_header(const struct aws_hpack_context *context, size_t index);
/* A return value of 0 indicates that the header wasn't found */
AWS_HTTP_API
size_t aws_hpack_find_index(
    const struct aws_hpack_context *context,
    const struct aws_http_header *header,
    bool search_value,
    bool *found_value);

AWS_HTTP_API
int aws_hpack_insert_header(struct aws_hpack_context *context, const struct aws_http_header *header);

/**
 * Set the max size of the dynamic table (in octets). The size of each header is name.len + value.len + 32 [4.1].
 */
AWS_HTTP_API
int aws_hpack_resize_dynamic_table(struct aws_hpack_context *context, size_t new_max_size);

/* When setting for table size changes, call this function to memorize all updates between the transmission of
 * two header blocks. The dynamic table resize and the dynamic table size update entry will be handled properly when we
 * encode the next header block  */
AWS_HTTP_API
void aws_hpack_set_max_table_size(struct aws_hpack_context *context, uint32_t new_max_size);

AWS_HTTP_API
void aws_hpack_set_protocol_max_size_setting(struct aws_hpack_context *context, uint32_t setting_max_size);

AWS_HTTP_API
void aws_hpack_set_huffman_mode(struct aws_hpack_context *context, enum aws_hpack_huffman_mode mode);

/* Public for testing purposes.
 * Output will be dynamically resized if it's too short */
AWS_HTTP_API
int aws_hpack_encode_integer(uint64_t integer, uint8_t starting_bits, uint8_t prefix_size, struct aws_byte_buf *output);

/* Public for testing purposes */
AWS_HTTP_API
int aws_hpack_decode_integer(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_decode,
    uint8_t prefix_size,
    uint64_t *integer,
    bool *complete);

/* Public for testing purposes.
 * Output will be dynamically resized if it's too short */
AWS_HTTP_API
int aws_hpack_encode_string(
    struct aws_hpack_context *context,
    struct aws_byte_cursor to_encode,
    struct aws_byte_buf *output);

/* Public for testing purposes */
AWS_HTTP_API
int aws_hpack_decode_string(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_decode,
    struct aws_byte_buf *output,
    bool *complete);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_HPACK_H */
