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

static int s_stream_configure_server_request_handler(
    struct aws_http_stream *stream_base,
    const struct aws_http_request_handler_options *options);

static void s_stream_destroy(struct aws_http_stream *stream_base) {
    struct aws_h1_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h1_stream, base);

    aws_h1_encoder_message_clean_up(&stream->encoder_message);
    aws_byte_buf_clean_up(&stream->incoming_storage_buf);
    aws_mem_release(stream->base.alloc, stream);
}

static void s_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    aws_http_connection_update_window(stream->owning_connection, increment_size);
}

static const struct aws_http_stream_vtable s_stream_vtable = {
    .destroy = s_stream_destroy,
    .update_window = s_stream_update_window,
    .configure_server_request_handler = s_stream_configure_server_request_handler,
};

static struct aws_h1_stream *s_stream_new_common(struct aws_http_connection *owning_connection) {
    struct aws_h1_stream *stream = aws_mem_calloc(owning_connection->alloc, 1, sizeof(struct aws_h1_stream));
    if (!stream) {
        return NULL;
    }

    stream->base.vtable = &s_stream_vtable;
    stream->base.alloc = owning_connection->alloc;
    stream->base.owning_connection = owning_connection;

    /* Stream refcount starts at 2. 1 for user and 1 for connection to release it's done with the stream */
    aws_atomic_init_int(&stream->base.refcount, 2);

    return stream;
}

struct aws_h1_stream *aws_h1_stream_new_request(const struct aws_http_request_options *options) {
    struct aws_h1_stream *stream = s_stream_new_common(options->client_connection);
    if (!stream) {
        return NULL;
    }

    if (options->client_connection->request_transform(options->request, options->client_connection->user_data)) {
        goto error;
    }

    /* Validate request and cache info that the encoder will eventually need */
    int err = aws_h1_encoder_message_init_from_request(
        &stream->encoder_message, options->client_connection->alloc, options->request);
    if (err) {
        goto error;
    }

    stream->base.manual_window_management = options->manual_window_management;
    stream->base.user_data = options->user_data;
    stream->base.on_incoming_headers = options->on_response_headers;
    stream->base.on_incoming_header_block_done = options->on_response_header_block_done;
    stream->base.on_incoming_body = options->on_response_body;
    stream->base.on_complete = options->on_complete;
    stream->base.client_data = &stream->base.client_or_server_data.client;
    stream->base.client_data->response_status = AWS_HTTP_STATUS_UNKNOWN;

    return stream;

error:
    s_stream_destroy(&stream->base);
    return NULL;
}

struct aws_h1_stream *aws_h1_stream_new_request_handler(struct aws_http_connection *server_connection) {
    struct aws_h1_stream *stream = s_stream_new_common(server_connection);
    if (!stream) {
        return NULL;
    }

    stream->base.server_data = &stream->base.client_or_server_data.server;
    return stream;
}

static int s_stream_configure_server_request_handler(
    struct aws_http_stream *stream_base,
    const struct aws_http_request_handler_options *options) {

    struct aws_h1_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h1_stream, base);

    stream->base.manual_window_management = options->manual_window_management;
    stream->base.user_data = options->user_data;
    stream->base.on_incoming_headers = options->on_request_headers;
    stream->base.on_incoming_header_block_done = options->on_request_header_block_done;
    stream->base.on_incoming_body = options->on_request_body;
    stream->base.on_complete = options->on_complete;
    stream->base.server_data->on_request_done = options->on_request_done;
    stream->base.server_data->configured = true;

    return AWS_OP_SUCCESS;
}
