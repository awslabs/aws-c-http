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

struct aws_http_stream *aws_http_stream_new_client_request(const struct aws_http_request_options *options) {
    if (!options || options->self_size == 0 || !options->client_connection) {
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

    if (aws_atomic_fetch_sub(&stream->refcount, 1) == 1) {
        stream->vtable->destroy(stream);

        /* Connection needed to outlive stream, but it's free to go now */
        aws_http_connection_release(stream->owning_connection);
    }
}
