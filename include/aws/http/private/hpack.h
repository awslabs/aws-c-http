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
#include <aws/http/private/h2_frames.h>

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

enum aws_hpack_entry_type {
    AWS_HPACK_ENTRY_INDEXED_HEADER_FIELD,                                   /* RFC-7541 6.1 */
    AWS_HPACK_ENTRY_LITERAL_HEADER_FIELD_INCREMENTAL_INDEXING_INDEXED_NAME, /* RFC-7541 6.2.1 */
    AWS_HPACK_ENTRY_LITERAL_HEADER_FIELD_INCREMENTAL_INDEXING_NEW_NAME,
    AWS_HPACK_ENTRY_LITERAL_HEADER_FIELD_WITHOUT_INDEXING_INDEXED_NAME, /* RFC-7541 6.2.2 */
    AWS_HPACK_ENTRY_LITERAL_HEADER_FIELD_WITHOUT_INDEXING_NEW_NAME,
    AWS_HPACK_ENTRY_LITERAL_HEADER_FIELD_NEVER_INDEXED_INDEXED_NAME, /* RFC-7541 6.2.3 */
    AWS_HPACK_ENTRY_LITERAL_HEADER_FIELD_NEVER_INDEXED_NEW_NAME,
    AWS_HPACK_ENTRY_DYNAMIC_TABLE_RESIZE, /* RFC-7541 6.3 */
    AWS_HPACK_ENTRY_TYPE_COUNT,
};

/**
 * HPACK encoding is performed as a 2 step process.
 * The first step how each entry will be encoded, and how long the entry will be.
 * The second step actully encodes output to a buffer.
 */
struct aws_hpack_encoder_cmd {
    size_t encoded_length;

    union {
        struct {
            struct aws_byte_cursor name_cursor;  /* name to encode (if new-name type) */
            struct aws_byte_cursor value_cursor; /* value to encode (if literal type) */
            size_t index;                        /* index (if indexed type) */
            size_t name_encoded_str_length;  /* length of encoded name string, excluding integer (if new-name type) */
            size_t value_encoded_str_length; /* length of encoded value string, excluding integer (if literal type) */
            bool name_uses_huffman;          /* encode new name with huffman (if new-name type) */
            bool value_uses_huffman;         /* encode value with huffman (if literal type) */
        } header;

        size_t dynamic_table_resize;
    } data;

    uint8_t type; /* aws_hpack_entry_type */
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
    AWS_HPACK_HUFFMAN_NEVER,
    AWS_HPACK_HUFFMAN_ALWAYS,
    AWS_HPACK_HUFFMAN_SMALLEST,
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
    void *log_id);

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
 * Initialize cmd with details for encoding a header-field.
 * This function will mutate the hpack context, so any error is unrecoverable.
 * cmds must be fed to aws_hpack_encode() in the order they are initialized.
 */
AWS_HTTP_API
int aws_hpack_pre_encode_header(
    struct aws_hpack_context *context,
    const struct aws_http_header *header,
    enum aws_hpack_huffman_mode huffman_mode,
    struct aws_hpack_encoder_cmd *cmd);

/**
 * Initialize cmd with details for encoding a Dynamic Table Size Update (RFC-7541 6.3).
 * cmds must be fed to aws_hpack_encode() in the order they are initialized.
 */
AWS_HTTP_API
void aws_hpack_pre_encode_dynamic_table_resize(
    struct aws_hpack_context *context,
    size_t size,
    struct aws_hpack_encoder_cmd *cmd);

/**
 * Encode a cmd to the output buffer.
 * At least cmd->encode_length must be available in the buffer.
 * cmds must have been initialized in the order that they are passed to aws_hpack_encode().
 */
AWS_HTTP_API
int aws_hpack_encode(
    struct aws_hpack_context *context,
    const struct aws_hpack_encoder_cmd *cmd,
    struct aws_byte_buf *output);

/* Returns the hpack size of a header (name.len + value.len + 32) [4.1] */
AWS_HTTP_API
size_t aws_hpack_get_header_size(const struct aws_http_header *header);

AWS_HTTP_API
const struct aws_http_header *aws_hpack_get_header(const struct aws_hpack_context *context, size_t index);
/* A return value of 0 indicates that the header wasn't found */
AWS_HTTP_API
size_t aws_hpack_find_index(
    const struct aws_hpack_context *context,
    const struct aws_http_header *header,
    bool *found_value);

AWS_HTTP_API
int aws_hpack_insert_header(struct aws_hpack_context *context, const struct aws_http_header *header);

/**
 * Set the max size of the dynamic table (in octets). The size of each header is name.len + value.len + 32 [4.1].
 */
AWS_HTTP_API
int aws_hpack_resize_dynamic_table(struct aws_hpack_context *context, size_t new_max_size);

/* Public for testing purposes */
AWS_HTTP_API
size_t aws_hpack_get_encoded_length_integer(uint64_t integer, uint8_t prefix_size);

AWS_HTTP_API
int aws_hpack_encode_integer(uint64_t integer, uint8_t prefix_size, struct aws_byte_buf *output);

/* Public for testing purposes */
AWS_HTTP_API
int aws_hpack_decode_integer(
    struct aws_hpack_context *context,
    struct aws_byte_cursor *to_decode,
    uint8_t prefix_size,
    uint64_t *integer,
    bool *complete);

/* #TODOD remove from public API? */
AWS_HTTP_API
int aws_hpack_pre_encode_string(
    struct aws_hpack_context *context,
    struct aws_byte_cursor to_encode,
    enum aws_hpack_huffman_mode huffman_mode,
    size_t *out_str_length,
    bool *out_use_huffman,
    size_t *in_out_sum_total_length);

AWS_HTTP_API
int aws_hpack_encode_string(
    struct aws_hpack_context *context,
    struct aws_byte_cursor to_encode,
    size_t encoded_str_length,
    bool huffman_encode,
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
