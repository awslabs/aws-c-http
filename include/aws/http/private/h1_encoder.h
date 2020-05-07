#ifndef AWS_HTTP_H1_ENCODER_H
#define AWS_HTTP_H1_ENCODER_H
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

#include <aws/common/mutex.h>
#include <aws/http/private/http_impl.h>
#include <aws/http/private/request_response_impl.h>

struct aws_http1_stream_chunk {
    struct aws_allocator *allocator;
    struct aws_input_stream *data;
    aws_http1_stream_write_chunk_complete_fn *on_complete;
    void *user_data;
    struct aws_linked_list_node node;
    struct aws_byte_buf chunk_line;
    struct aws_byte_cursor chunk_line_cursor;
};

struct aws_http1_chunks {
    struct aws_mutex lock;
    struct aws_linked_list chunk_list;
    bool paused;
};

/**
 * Message to be submitted to encoder.
 * Contains data necessary for encoder to write an outgoing request or response.
 */
struct aws_h1_encoder_message {
    /* Upon creation, the "head" (everything preceding body) is buffered here. */
    struct aws_byte_buf outgoing_head_buf;
    struct aws_input_stream *body;
    /* The currently ready for encoding chunk of data. This path is only used for Transfer-Encoding chunked. */
    struct aws_http1_stream_chunk *body_chunk;
    uint64_t content_length;
    bool has_connection_close_header;
    bool has_chunked_encoding_header;
};

enum aws_h1_encoder_state {
    AWS_H1_ENCODER_STATE_INIT,
    AWS_H1_ENCODER_STATE_HEAD,
    AWS_H1_ENCODER_STATE_BODY,
    AWS_H1_ENCODER_STATE_DONE,
};

enum aws_h1_encoder_body_stream_state {
    AWS_H1_ENCODER_STATE_CHUNK_INIT,
    AWS_H1_ENCODER_STATE_CHUNK_LINE,
    AWS_H1_ENCODER_STATE_CHUNK_PAYLOAD,
    AWS_H1_ENCODER_STATE_CHUNK_END,
    AWS_H1_ENCODER_STATE_CHUNK_TERMINATED,
};
#define MAX_ASCII_HEX_CHUNK_STR_SIZE sizeof(size_t) * 2 + 1
#define CRLF_SIZE 2

struct aws_h1_encoder {
    struct aws_allocator *allocator;

    enum aws_h1_encoder_state state;
    enum aws_h1_encoder_body_stream_state stream_state;
    struct aws_h1_encoder_message *message;
    uint64_t progress_bytes;
    const void *logging_id;
};

AWS_EXTERN_C_BEGIN

/* Validate request and cache any info the encoder will need later in the "encoder message". */
AWS_HTTP_API
int aws_h1_encoder_message_init_from_request(
    struct aws_h1_encoder_message *message,
    struct aws_allocator *allocator,
    const struct aws_http_message *request);

int aws_h1_encoder_message_init_from_response(
    struct aws_h1_encoder_message *message,
    struct aws_allocator *allocator,
    const struct aws_http_message *response,
    bool body_headers_ignored);

AWS_HTTP_API
void aws_h1_encoder_message_clean_up(struct aws_h1_encoder_message *message);

AWS_HTTP_API
void aws_h1_encoder_init(struct aws_h1_encoder *encoder, struct aws_allocator *allocator);

AWS_HTTP_API
void aws_h1_encoder_clean_up(struct aws_h1_encoder *encoder);

AWS_HTTP_API
int aws_h1_encoder_start_message(
    struct aws_h1_encoder *encoder,
    struct aws_h1_encoder_message *message,
    void *log_as_stream);

AWS_HTTP_API
int aws_h1_encoder_process(struct aws_h1_encoder *encoder, struct aws_byte_buf *out_buf);

AWS_HTTP_API
bool aws_h1_encoder_is_message_in_progress(const struct aws_h1_encoder *encoder);

void aws_h1_lock_stream_list(struct aws_http1_chunks *body_chunks);

void aws_h1_unlock_stream_list(struct aws_http1_chunks *body_chunks);

bool write_chunk_size(struct aws_byte_buf *dst, struct aws_input_stream *chunk);

bool write_crlf(struct aws_byte_buf *dst);

bool write_chunk_extension(struct aws_byte_buf *dst, struct aws_http1_chunk_extension *chunk_extension);
AWS_EXTERN_C_END

#endif /* AWS_HTTP_H1_ENCODER_H */
