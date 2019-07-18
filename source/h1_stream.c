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
#include <aws/io/logging.h>

static void s_stream_destroy(struct aws_http_stream *stream_base) {
    AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Stream destroyed.", (void *)stream_base);

    struct aws_h1_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h1_stream, base);

    aws_byte_buf_clean_up(&stream->incoming_storage_buf);
    aws_mem_release(stream->base.alloc, stream);
}

static void s_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    aws_http_connection_update_window(stream->owning_connection, increment_size);
}

static const struct aws_http_stream_vtable s_stream_vtable = {
    .destroy = s_stream_destroy,
    .update_window = s_stream_update_window,
};

struct aws_h1_stream *aws_h1_stream_new_request(const struct aws_http_request_options *options) {
    struct aws_h1_stream *stream = aws_mem_calloc(options->client_connection->alloc, 1, sizeof(struct aws_h1_stream));
    if (!stream) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION, "id=%p: Failed to create stream object.", (void *)options->client_connection);
        return NULL;
    }

    stream->base.vtable = &s_stream_vtable;
    stream->base.alloc = options->client_connection->alloc;
    stream->base.owning_connection = options->client_connection;
    stream->base.outgoing_body = aws_http_request_get_body_stream(options->request);
    stream->base.manual_window_management = options->manual_window_management;
    stream->base.user_data = options->user_data;
    stream->base.on_incoming_headers = options->on_response_headers;
    stream->base.on_incoming_header_block_done = options->on_response_header_block_done;
    stream->base.on_incoming_body = options->on_response_body;
    stream->base.on_complete = options->on_complete;
    stream->base.client_or_server_data.client.incoming_response_status = AWS_HTTP_STATUS_UNKNOWN;

    /* Stream refcount starts at 2. 1 for user and 1 for connection to release it's done with the stream */
    aws_atomic_init_int(&stream->base.refcount, 2);

    return stream;
}
