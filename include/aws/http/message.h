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

#ifndef AWS_HTTP_MESSAGE_H
#define AWS_HTTP_MESSAGE_H

#include <aws/http/http.h>

struct aws_http_connection;
struct aws_http_exchange;

struct aws_http_body_reader_vtable {
    /* (chunked only) invoked at start of each chunk. Tells the size of the next chunk body */
    void (*on_chunk_size)(size_t body_size, void *user_data);

    /* (chunked only) invoked once per chunk extension (after on_chunk_size, before on_body_data) */
    void (
        *on_chunk_extension)(const struct aws_byte_cursor *name, const struct aws_byte_cursor *value, void *user_data);

    /* invoked repeatedly until entire body is read.
     * for chunked encoding, each call to on_chunk_size tells the total size of the next chunk's body
     * for non-chunked, the content-length header tells the total size of the body.
     *
     * out_window_update_size: the amount by which the window is updated after reading data.
     * By default, it is the same size as the data coming in.
     * To prevent the window from updating, set this value to 0.
     * The window can be manually updated later via aws_http_exchange_update_window() */
    void (*on_body_data)(
        const struct aws_byte_cursor *data,
        bool is_last, /* flags instead? in addition? */
        size_t *out_window_update_size,
        void *user_data);

    /* (chunked only) invoked once per header in the chunked trailer */
    void (*on_chunked_trailer_header)(
        enum aws_http_header_name name_enum,
        const struct aws_byte_cursor *name,
        const struct aws_byte_cursor *value,
        void *user_data);
};

enum aws_http_body_writer_state {
    /* invalid state */
    AWS_HTTP_BODY_WRITER_STATE_UNKNOWN,

    /* (chunked only) write size of next chunk, write 0 to make this the last chunk */
    AWS_HTTP_BODY_WRITER_STATE_CHUNK_SIZE,

    /* (chunked only) write next chunk extension, do nothing to finish writing extensions for this chunk */
    AWS_HTTP_BODY_WRITER_STATE_CHUNK_EXTENSION,

    /* write body data.
     * writer remains in this state until total bytes written equals the declared size.
     *
     * if chunked, declared size is the size of this chunk
     * otherwise, declared size is the content-lenth
     * If neither chunked or content-length is set, this state is never reached.
     *
     * If body data isn't available to be written yet, call aws_http_exchange_pause_body_writer(),
     * then unpause once data is ready again */
    AWS_HTTP_BODY_WRITER_STATE_BODY_DATA,

    /* (chunked only) write next header at the end of a chunked message, do nothing to finish writing headers */
    AWS_HTTP_BODY_WRITER_STATE_CHUNKED_TRAILER_HEADER,
};

typedef void(
    aws_http_body_writer_fn)(struct aws_http_exchange *exchange, enum aws_http_body_writer_state, void *user_data);

typedef void(aws_http_on_incoming_header_fn)(
    struct aws_http_exchange *exchange,
    enum aws_http_header_name name_enum,
    const struct aws_byte_cursor *name,
    const struct aws_byte_cursor *value,
    void *user_data);

typedef void(aws_http_on_incoming_head_done_fn)(struct aws_http_exchange *exchange, bool has_body, void *user_data);

typedef void(aws_http_on_exchange_complete_fn)(
    struct aws_http_exchange *exchange,
    int error_code,
    enum aws_http_code http_code,
    void *user_data);

struct aws_http_request_def {
    struct aws_http_connection *client_connection;

    enum aws_http_method method;
    struct aws_byte_cursor uri;
    struct aws_http_header *headers;
    size_t num_headers;

    void *user_data;

    aws_http_body_writer_fn *request_body_writer;

    /* Invoked once per header in the response.
     * At this point, aws_http_exchange_get_incoming_response_status() can be used */
    aws_http_on_incoming_header_fn *on_response_header;

    /* Invoked when header block has been completely read.
     * User must call aws_http_exchange_set_body_reader() if response has a body */
    aws_http_on_incoming_head_done_fn *on_response_head_done;

    /* Invoked when request/response exchange is complete, whether successful or unsucessful */
    aws_http_on_exchange_complete_fn *on_complete;

    /* Misc options...
     * All timeouts in ms. Set -1 for infinite, 0 to use connection defaults */
    int64_t timeout_ms;
};

struct aws_http_request_handler_def {
    struct aws_http_connection *server_connection;
    void *user_data;

    aws_http_on_incoming_header_fn *on_request_header;
    aws_http_on_incoming_head_done_fn *on_request_head_done;
    aws_http_on_exchange_complete_fn *on_complete;
};

struct aws_http_response_def {
    enum aws_http_code status;
    struct aws_byte_cursor reason;
    struct aws_http_header *headers;
    size_t num_headers;
    aws_http_body_writer_fn *body_writer;
};

AWS_EXTERN_C_BEGIN

/**
 * Create an exchange, with a client connection sending a request.
 * The request starts sending automatically once the exchange is created.
 * The `def`, and all memory it references, is copied during this call.
 */
AWS_HTTP_API
struct aws_http_exchange *aws_http_exchange_new_request(struct aws_http_request_def *def);

/**
 * Create an exchange, with a server connection receiving and responding to a request.
 * aws_http_exchange_send_response() should be used to send a response.
 */
AWS_HTTP_API
struct aws_http_exchange *aws_http_exchange_new_request_handler(struct aws_http_request_handler_def *def);

AWS_HTTP_API
void aws_http_exchange_destroy(struct aws_http_exchange *exchange);

AWS_HTTP_API
struct aws_http_connection *aws_http_exchange_get_connection(struct aws_http_exchange *exchange);

/* Only valid in "request" exchanges, once response headers start arriving */
AWS_HTTP_API
int aws_http_exchange_get_incoming_response_status(struct aws_http_exchange *exchange, enum aws_http_code *out_status);

AWS_HTTP_API
int aws_http_exchange_get_incoming_response_reason(struct aws_http_exchange *exchange, struct aws_byte_cursor *out_reason);

/* Only valid in "request handler" exchanges, once request headers start arriving */
AWS_HTTP_API
int aws_http_exchange_get_incoming_request_method(
    struct aws_http_exchange *exchange,
    enum aws_http_method *out_method,
    struct aws_byte_cursor *out_method_raw); // TODO: how to support "extensions"?

AWS_HTTP_API
int aws_http_exchange_get_incoming_request_uri(struct aws_http_exchange *exchange, struct aws_byte_cursor *out_uri);

/* only callable from "request handler" exchanges */
AWS_HTTP_API
int aws_http_exchange_send_response(struct aws_http_exchange *exchange, struct aws_http_response_def *def);

/* Only callable during AWS_HTTP_BODY_WRITER_STATE_CHUNK_SIZE */
AWS_HTTP_API
int aws_http_exchange_write_chunk_size(struct aws_http_exchange *exchange, size_t size);

/* Only callable during AWS_HTTP_BODY_WRITER_STATE_CHUNK_EXTENSION */
AWS_HTTP_API
int aws_http_exchange_write_chunk_extension(
    struct aws_http_exchange *exchange,
    const struct aws_byte_cursor *name,
    const struct aws_byte_cursor *value);

/* Only callable during AWS_HTTP_BODY_WRITER_STATE_BODY_DATA */
AWS_HTTP_API
int aws_http_exchange_write_body_data(
    struct aws_http_exchange *exchange,
    const struct aws_byte_cursor *data,
    size_t *out_bytes_written);

/* Only callable during AWS_HTTP_BODY_WRITER_STATE_CHUNKED_TRAILER_HEADER */
AWS_HTTP_API
int aws_http_exchange_write_chunked_trailer_header(
    struct aws_http_exchange *exchange,
    enum aws_http_header_name enum_name,
    const struct aws_byte_cursor *name,
    const struct aws_byte_cursor *value);

/* Pauses body writer. Useful if body writer is running, but data isn't available yet */
AWS_HTTP_API
void aws_http_exchange_pause_body_writer(struct aws_http_exchange *exchange);

/* If body writer was paused, unpause it */
AWS_HTTP_API
void aws_http_exchange_unpause_body_writer(struct aws_http_exchange *exchange);

/* Must be set before body of incoming message arrives. */
AWS_HTTP_API
void aws_http_exchange_set_body_reader(
    struct aws_http_exchange *exchange,
    const struct aws_http_body_reader_vtable *reader);

/* Manually issue a window update.
 * This should only be called if the body reader is reducing the automatic window update size */
AWS_HTTP_API
int aws_http_exchange_update_window(struct aws_http_exchange *exchange, size_t increment_size);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_MESSAGE_H */
