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

#include <aws/http/private/request_response_impl.h>

#include <aws/http/private/connection_impl.h>
#include <aws/io/logging.h>

struct aws_http_stream *aws_http_stream_new_client_request(const struct aws_http_request_options *options) {
    if (!options || options->self_size == 0 || !options->client_connection) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create client request, options are invalid.",
            (void *)(options ? options->client_connection : NULL));
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    /* Connection owns stream, and must outlive stream */
    aws_atomic_fetch_add(&options->client_connection->refcount, 1);

    struct aws_http_stream *stream = options->client_connection->vtable->new_client_request_stream(options);
    if (!stream) {
        aws_http_connection_release(options->client_connection);
        return NULL;
    }

    return stream;
}

void aws_http_stream_release(struct aws_http_stream *stream) {
    assert(stream);

    size_t prev_refcount = aws_atomic_fetch_sub(&stream->refcount, 1);
    if (prev_refcount == 1) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Final stream refcount released.", (void *)stream);

        struct aws_http_connection *owning_connection = stream->owning_connection;
        stream->vtable->destroy(stream);

        /* Connection needed to outlive stream, but it's free to go now */
        aws_http_connection_release(owning_connection);
    } else {
        assert(prev_refcount != 0);
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_STREAM, "id=%p: Stream refcount released, %zu remaining.", (void *)stream, prev_refcount - 1);
    }
}

struct aws_http_connection *aws_http_stream_get_connection(const struct aws_http_stream *stream) {
    assert(stream);
    return stream->owning_connection;
}

int aws_http_stream_get_incoming_response_status(const struct aws_http_stream *stream, int *out_status) {
    assert(stream);

    if (stream->incoming_response_status == (int)AWS_HTTP_STATUS_UNKNOWN) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Status code not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_status = stream->incoming_response_status;
    return AWS_OP_SUCCESS;
}

int aws_http_stream_get_incoming_request_method(
    const struct aws_http_stream *stream,
    struct aws_byte_cursor *out_method) {

    assert(stream);

    if (!stream->incoming_request_method_str.ptr) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Request method not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_method = stream->incoming_request_method_str;
    return AWS_OP_SUCCESS;
}

int aws_http_stream_get_incoming_request_uri(const struct aws_http_stream *stream, struct aws_byte_cursor *out_uri) {
    assert(stream);

    if (!stream->incoming_request_uri.ptr) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Request URI not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_uri = stream->incoming_request_uri;
    return AWS_OP_SUCCESS;
}

void aws_http_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    stream->vtable->update_window(stream, increment_size);
}
