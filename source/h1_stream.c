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
#include <aws/http/private/h1_stream.h>

#include <aws/http/private/connection_impl.h>

#include <aws/http/status_code.h>
#include <aws/io/logging.h>
#include <aws/io/stream.h>

static void s_stream_destroy(struct aws_http_stream *stream_base) {
    struct aws_h1_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h1_stream, base);

    aws_h1_stream_body_chunks_clean_up(stream);
    aws_h1_encoder_message_clean_up(&stream->encoder_message);
    aws_byte_buf_clean_up(&stream->incoming_storage_buf);
    aws_mem_release(stream->base.alloc, stream);
}

static void s_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    aws_http_connection_update_window(stream->owning_connection, increment_size);
}

static int s_body_chunks_init(struct aws_h1_stream *stream) {
    AWS_PRECONDITION(stream);
    aws_linked_list_init(&stream->body_chunks.chunk_list);
    stream->body_chunks.current_chunk = NULL;
    stream->body_chunks.paused = false;
    return aws_mutex_init(&stream->body_chunks.lock);
}

static void s_clean_up_body_chunk(struct aws_http1_stream_chunk **chunk) {
    AWS_PRECONDITION(chunk);
    aws_h1_stream_release_chunk(*chunk);
    *chunk = NULL;
}

void aws_h1_stream_body_chunks_clean_up(struct aws_h1_stream *stream) {
    AWS_PRECONDITION(stream);
    if (!stream->body_chunks.lock.initialized) {
        return;
    }
    do {
        if (NULL != stream->body_chunks.current_chunk) {
            s_clean_up_body_chunk(&stream->body_chunks.current_chunk);
        }
    } while (aws_h1_populate_current_stream_chunk(&stream->body_chunks));
    aws_mutex_clean_up(&stream->body_chunks.lock);
}

bool aws_h1_stream_is_paused(struct aws_h1_stream *stream) {
    AWS_PRECONDITION(stream);
    if (!stream->encoder_message.has_chunked_encoding_header) {
        return false;
    }
    bool is_paused = false;
    /* Begin critical section */
    aws_h1_lock_chunked_list(&stream->body_chunks);
    is_paused = stream->body_chunks.paused;
    aws_h1_unlock_chunked_list(&stream->body_chunks);
    /* End critical section */
    return is_paused;
}

static int s_aws_h1_stream_write_chunk(struct aws_http_stream *stream_base, struct aws_http1_chunk_options *options) {
    AWS_PRECONDITION(stream_base);
    AWS_PRECONDITION(options);
    struct aws_h1_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h1_stream, base);
    const size_t chunk_alloc_size = sizeof(struct aws_http1_stream_chunk);
    struct aws_http1_stream_chunk *chunk = aws_mem_calloc(options->chunk_data->allocator, 1, chunk_alloc_size);
    if (AWS_UNLIKELY(NULL == chunk)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_STREAM,
            "static: Failed to initialize streamed chunk, error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        return AWS_OP_ERR;
    }
    if (AWS_OP_SUCCESS != aws_chunk_line_from_options(options, &chunk->chunk_line)) {
        s_clean_up_body_chunk(&chunk);
        return AWS_OP_ERR;
    }
    chunk->data = options->chunk_data;
    chunk->data_size = options->chunk_data_size;
    chunk->on_complete = options->on_complete;
    chunk->user_data = options->user_data;
    aws_linked_list_node_reset(&chunk->node);
    chunk->chunk_line_cursor = aws_byte_cursor_from_buf(&chunk->chunk_line);

    /* Begin critical section */
    aws_h1_lock_chunked_list(&stream->body_chunks);
    aws_linked_list_push_back(&stream->body_chunks.chunk_list, &chunk->node);
    AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: adding chunk to stream", (void *)stream);
    if (stream->body_chunks.paused) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Waking up stream on new data available", (void *)stream);
        stream->body_chunks.paused = false;
        AWS_ASSERT(stream->base.owning_connection);
        aws_h1_stream_schedule_outgoing_stream_task(&stream->base);
    }
    aws_h1_unlock_chunked_list(&stream->body_chunks);
    /* End critical section */

    return AWS_OP_SUCCESS;
}

static const struct aws_http_stream_vtable s_stream_vtable = {
    .destroy = s_stream_destroy,
    .update_window = s_stream_update_window,
    .activate = aws_h1_stream_activate,
    .http1_write_chunk = s_aws_h1_stream_write_chunk,
};

static struct aws_h1_stream *s_stream_new_common(
    struct aws_http_connection *owning_connection,
    bool manual_window_management,
    void *user_data,
    aws_http_on_incoming_headers_fn *on_incoming_headers,
    aws_http_on_incoming_header_block_done_fn *on_incoming_header_block_done,
    aws_http_on_incoming_body_fn *on_incoming_body,
    aws_http_on_stream_complete_fn on_complete) {

    struct aws_h1_stream *stream = aws_mem_calloc(owning_connection->alloc, 1, sizeof(struct aws_h1_stream));
    if (!stream) {
        return NULL;
    }

    stream->base.vtable = &s_stream_vtable;
    stream->base.alloc = owning_connection->alloc;
    stream->base.owning_connection = owning_connection;
    stream->base.manual_window_management = manual_window_management;
    stream->base.user_data = user_data;
    stream->base.on_incoming_headers = on_incoming_headers;
    stream->base.on_incoming_header_block_done = on_incoming_header_block_done;
    stream->base.on_incoming_body = on_incoming_body;
    stream->base.on_complete = on_complete;

    /* Stream refcount starts at 1 for user and is incremented upon activation for the connection */
    aws_atomic_init_int(&stream->base.refcount, 1);

    return stream;
}

struct aws_h1_stream *aws_h1_stream_new_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {

    struct aws_h1_stream *stream = s_stream_new_common(
        client_connection,
        client_connection->manual_window_management,
        options->user_data,
        options->on_response_headers,
        options->on_response_header_block_done,
        options->on_response_body,
        options->on_complete);
    if (!stream) {
        return NULL;
    }

    /* Transform request if necessary */
    if (client_connection->proxy_request_transform) {
        if (client_connection->proxy_request_transform(options->request, client_connection->user_data)) {
            goto error;
        }
    }

    if (AWS_UNLIKELY(AWS_OP_SUCCESS != s_body_chunks_init(stream))) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_STREAM,
            "static: Failed to initialize streamed chunks mutex, error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    stream->base.client_data = &stream->base.client_or_server_data.client;
    stream->base.client_data->response_status = AWS_HTTP_STATUS_CODE_UNKNOWN;

    /* Validate request and cache info that the encoder will eventually need */
    int err = aws_h1_encoder_message_init_from_request(
        &stream->encoder_message, client_connection->alloc, options->request, &stream->body_chunks);
    if (err) {
        goto error;
    }

    /* RFC-7230 Section 6.3: The "close" connection option is used to signal
     * that a connection will not persist after the current request/response*/
    if (stream->encoder_message.has_connection_close_header) {
        stream->is_final_stream = true;
    }

    return stream;

error:
    s_stream_destroy(&stream->base);
    return NULL;
}

struct aws_h1_stream *aws_h1_stream_new_request_handler(const struct aws_http_request_handler_options *options) {
    struct aws_h1_stream *stream = s_stream_new_common(
        options->server_connection,
        options->server_connection->manual_window_management,
        options->user_data,
        options->on_request_headers,
        options->on_request_header_block_done,
        options->on_request_body,
        options->on_complete);
    if (!stream) {
        return NULL;
    }

    /* This code is only executed in server mode and can only be invoked from the event-loop thread so don't worry
     * with the lock here. */
    stream->base.id = aws_http_connection_get_next_stream_id(options->server_connection);

    stream->base.server_data = &stream->base.client_or_server_data.server;
    stream->base.server_data->on_request_done = options->on_request_done;
    aws_atomic_fetch_add(&stream->base.refcount, 1);

    return stream;
}
