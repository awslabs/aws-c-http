#ifndef AWS_HTTP_REQUEST_RESPONSE_IMPL_H
#define AWS_HTTP_REQUEST_RESPONSE_IMPL_H

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

#include <aws/http/request_response.h>

#include <aws/http/private/http_impl.h>

#include <aws/common/atomics.h>

struct aws_http_stream_vtable {
    void (*destroy)(struct aws_http_stream *stream);
    void (*update_window)(struct aws_http_stream *stream, size_t increment_size);
    int (*activate)(struct aws_http_stream *stream);
};

/**
 * Base class for streams.
 * There are specific implementations for each HTTP version.
 */
struct aws_http_stream {
    const struct aws_http_stream_vtable *vtable;
    struct aws_allocator *alloc;
    struct aws_http_connection *owning_connection;

    uint32_t id;

    bool manual_window_management;

    void *user_data;
    aws_http_on_incoming_headers_fn *on_incoming_headers;
    aws_http_on_incoming_header_block_done_fn *on_incoming_header_block_done;
    aws_http_on_incoming_body_fn *on_incoming_body;
    aws_http_on_stream_complete_fn *on_complete;

    struct aws_atomic_var refcount;
    enum aws_http_method request_method;

    union {
        struct aws_http_stream_client_data {
            int response_status;
        } client;
        struct aws_http_stream_server_data {
            struct aws_byte_cursor request_method_str;
            struct aws_byte_cursor request_path;
            aws_http_on_incoming_request_done_fn *on_request_done;
        } server;
    } client_or_server_data;

    /* On client connections, `client_data` points to client_or_server_data.client and `server_data` is null.
     * Opposite is true on server connections */
    struct aws_http_stream_client_data *client_data;
    struct aws_http_stream_server_data *server_data;
};

#endif /* AWS_HTTP_REQUEST_RESPONSE_IMPL_H */
