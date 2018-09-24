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

#ifndef AWS_HTTP_CONNECTION_H
#define AWS_HTTP_CONNECTION_H

#include <aws/http/decode.h>
#include <aws/http/http.h>

#include <aws/io/channel_bootstrap.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

struct aws_http_message;

/* Automatically handle 100-continue? */
/* Detect expect-continue header, stop writing the body to socket, wait for the 100-continue response. */

struct aws_http_connection_callbacks {
    /**
     * Called when a request is received and the method + uri have been parsed and are ready to read.
     * The `uri` pointer is not valid after this callback returns.
     */
    void (*on_request)(enum aws_http_method method, const struct aws_byte_cursor *uri, void *user_data);

    /**
     * Called when a response is received and parsed.
     */
    void (*on_response)(enum aws_http_code code, void *user_data);

    /**
     * Called when a header is available for reading from the connection.
     * The `name` and `value` pointers are not valid after this callback returns.
     */
    void (*on_read_header)(
        enum aws_http_header_name name_enum,
        const struct aws_byte_cursor *name,
        const struct aws_byte_cursor *value,
        void *user_data);

    /**
     * Called when body data is ready for reading. Return true to let the underlying io you have finished reading
     * `data`, and false for the io to hold onto the buffered data until `aws_http_release_body_data` is called.
     * `last_segment` is true if this is the final chunk of the body data for the http message.
     */
    void (*on_read_body)(const struct aws_byte_cursor *data, bool last_segment, void *user_data);

    /**
     * Called when the underlying io is ready to write headers after a call to `aws_http_send_request` or
     * `aws_http_send_response` is called. Set `*names`, and `*values` to point to two different arrays.
     * Set `*count` to the length of the arrays.
     */
    void (*on_write_headers)(
        const struct aws_byte_cursor **names,
        const struct aws_byte_cursor **values,
        int *count,
        void *user_data);

    /**
     * Called when the underlying io is ready to write headers after a call to `aws_http_send_request` or
     * `aws_http_send_response` is called, and the underlying io is ready to write body data, up to `buffer_size`
     * bytes. Copy in data to the `buffer` pointer`, and specify how many bytes were written with `bytes_written`.
     * Let the io know if this callback has written the final chunk of body data returning true.
     */
    bool (*on_write_body)(void *buffer, int buffer_size, int *bytes_written, void *user_data);

    /**
     * Called when the underlying io has completely finished writing the final byte of an http message to the
     * underlying io.
     */
    int (*on_sent)(uint64_t msg_id, void *user_data);
};

struct aws_http_connection;
struct aws_http_message;

#ifdef __cplusplus
extern "C" {
#endif

AWS_HTTP_API struct aws_http_connection *aws_http_client_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_client_bootstrap *bootstrap,
    struct aws_http_connection_callbacks *user_callbacks,
    void *user_data);
AWS_HTTP_API struct aws_http_connection *aws_http_server_connection_new(
    struct aws_allocator *alloc,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *socket_options,
    struct aws_tls_connection_options *tls_options,
    struct aws_server_bootstrap *bootstrap,
    struct aws_http_connection_callbacks *user_callbacks,
    void *user_data);
AWS_HTTP_API void aws_http_connection_destroy(struct aws_http_connection *connection);

AWS_HTTP_API int aws_http_send_request(
    struct aws_http_connection *connection,
    enum aws_http_method method,
    const struct aws_byte_cursor *uri,
    uint64_t *msg_id);

AWS_HTTP_API int aws_http_send_response(
    struct aws_http_connection *connection,
    enum aws_http_code code,
    uint64_t *msg_id);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_CONNECTION_H */
