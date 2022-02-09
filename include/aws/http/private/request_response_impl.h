#ifndef AWS_HTTP_REQUEST_RESPONSE_IMPL_H
#define AWS_HTTP_REQUEST_RESPONSE_IMPL_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/request_response.h>

#include <aws/http/private/http_impl.h>

#include <aws/common/atomics.h>

struct aws_http_stream_vtable {
    void (*destroy)(struct aws_http_stream *stream);
    void (*update_window)(struct aws_http_stream *stream, size_t increment_size);
    int (*activate)(struct aws_http_stream *stream);

    int (*http1_write_chunk)(struct aws_http_stream *http1_stream, const struct aws_http1_chunk_options *options);
    int (*http1_add_trailer)(struct aws_http_stream *http1_stream, const struct aws_http_headers *trailing_headers);

    int (*http2_reset_stream)(struct aws_http_stream *http2_stream, uint32_t http2_error);
    int (*http2_get_received_error_code)(struct aws_http_stream *http2_stream, uint32_t *http2_error);
    int (*http2_get_sent_error_code)(struct aws_http_stream *http2_stream, uint32_t *http2_error);
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

AWS_EXTERN_C_BEGIN

/**
 * Create an HTTP/2 message from HTTP/1.1 message.
 * pseudo headers will be created from the context and added to the headers of new message.
 * Normal headers will be copied to the headers of new message.
 * Note: `host` will stay and `:authority` will not be set. (RFC-7540 8.1.2.3). Some sever don't support it.
 * TODO: (Maybe more, connection-specific header will be removed, etc...)
 * TODO: REFCOUNT INPUT_STREAMS!!! And make it public.
 */
AWS_HTTP_API
struct aws_http_message *aws_http2_message_new_from_http1(
    struct aws_http_message *http1_msg,
    struct aws_allocator *alloc);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_REQUEST_RESPONSE_IMPL_H */
