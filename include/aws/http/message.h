#ifndef AWS_HTTP_MESSAGE_H
#define AWS_HTTP_MESSAGE_H

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

#include <aws/http/http.h>

struct aws_http_connection;
struct aws_http_exchange;

/**
 * Called repeatedly whenever body data can be sent.
 * Write up to `size` bytes to the `buffer` and return the number of bytes written.
 * Return 0 to end the body.
 */
typedef size_t(
    aws_http_body_sender_fn)(struct aws_http_exchange *exchange, uint8_t *buffer, size_t size, void *user_data);

typedef void(aws_http_on_incoming_headers_fn)(
    struct aws_http_exchange *exchange,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data);

typedef void(
    aws_http_on_incoming_header_block_done_fn)(struct aws_http_exchange *exchange, bool has_body, void *user_data);

/**
 * Called repeatedly as body data is received.
 * The data must be copied immediately if you wish to preserve it.
 *
 * `out_window_update_size` is the amount by which the window is updated after reading data.
 * By default, it is the same size as the data which has just come in.
 * To prevent the window from updating, set this value to 0.
 * The window can be manually updated later via aws_http_exchange_update_window()
 */
typedef void(aws_http_on_incoming_body_fn)(
    struct aws_http_exchange *exchange,
    const struct aws_byte_cursor *data,
    size_t *out_window_update_size,
    void *user_data);

typedef void(aws_http_on_exchange_complete_fn)(struct aws_http_exchange *exchange, int error_code, void *user_data);

struct aws_http_request_options {
    /**
     * Set to sizeof() this struct, used for versioning.
     * Required.
     */
    size_t self_size;

    /**
     * Required.
     */
    struct aws_http_connection *client_connection;

    /**
     * Either `method`, or `method_str` are required for HTTP/1.
     * Not required in HTTP/2 if :method header is passed in.
     */
    enum aws_http_method method;

    /**
     * Either `method`, or `method_str` are required for HTTP/1.
     * Not required in HTTP/2 if :method header is passed in.
     */
    struct aws_byte_cursor method_str;

    /**
     * Required for HTTP/1.
     * Not required in HTTP/2 if :path header is passed in.
     */
    struct aws_byte_cursor uri;

    /**
     * Array of request headers.
     * Optional.
     * For HTTP/2, if :method and :path headers not passed in they will be generated from the `method` and `uri`.
     */
    struct aws_http_header *header_array;
    size_t num_headers;

    void *user_data;

    /**
     * Callback responsible for sending the request body.
     * Required if request has a body.
     */
    aws_http_body_sender_fn *body_sender;

    /**
     * Invoked repeatedly times as headers are received.
     * At this point, aws_http_exchange_get_incoming_response_status() can be called.
     * Optional.
     */
    aws_http_on_incoming_headers_fn *on_response_headers;

    /**
     * Invoked when response header block has been completely read.
     * Optional.
     */
    aws_http_on_incoming_header_block_done_fn *on_response_header_block_done;

    /**
     * Invoked repeatedly as body data is received.
     * Optional.
     */
    aws_http_on_incoming_body_fn *on_response_body;

    /**
     * Invoked when request/response exchange is complete, whether successful or unsucessful
     * Optional.
     */
    aws_http_on_exchange_complete_fn *on_complete;
};

struct aws_http_request_handler_options {
    /* Set to sizeof() this struct, used for versioning. */
    size_t self_size;

    struct aws_http_connection *server_connection;
    void *user_data;

    aws_http_on_incoming_headers_fn *on_request_headers;
    aws_http_on_incoming_header_block_done_fn *on_request_header_block_done;
    aws_http_on_incoming_body_fn *on_request_body;
    aws_http_on_exchange_complete_fn *on_complete;
};

struct aws_http_response_options {
    /* Set to sizeof() this struct, used for versioning. */
    size_t self_size;

    int status;
    struct aws_http_header *header_array;
    size_t num_headers;
    aws_http_body_sender_fn *body_sender;
};

AWS_EXTERN_C_BEGIN

/**
 * Create an exchange, with a client connection sending a request.
 * The request starts sending automatically once the exchange is created.
 * The `def`, and all memory it references, is copied during this call.
 */
AWS_HTTP_API
struct aws_http_exchange *aws_http_exchange_new_request(const struct aws_http_request_options *options);

/**
 * Create an exchange, with a server connection receiving and responding to a request.
 * aws_http_exchange_send_response() should be used to send a response.
 */
AWS_HTTP_API
struct aws_http_exchange *aws_http_exchange_new_request_handler(const struct aws_http_request_handler_options *options);

AWS_HTTP_API
void aws_http_exchange_destroy(struct aws_http_exchange *exchange);

AWS_HTTP_API
struct aws_http_connection *aws_http_exchange_get_connection(const struct aws_http_exchange *exchange);

/* Only valid in "request" exchanges, once response headers start arriving */
AWS_HTTP_API
int aws_http_exchange_get_incoming_response_status(const struct aws_http_exchange *exchange, int *out_status);

/* Only valid in "request handler" exchanges, once request headers start arriving */
AWS_HTTP_API
int aws_http_exchange_get_incoming_request_method(
    const struct aws_http_exchange *exchange,
    enum aws_http_method *out_method);

AWS_HTTP_API
int aws_http_exchange_get_incoming_request_method_str(
    const struct aws_http_exchange *exchange,
    struct aws_byte_cursor *out_method);

AWS_HTTP_API
int aws_http_exchange_get_incoming_request_uri(
    const struct aws_http_exchange *exchange,
    struct aws_byte_cursor *out_uri);

/* only callable from "request handler" exchanges */
AWS_HTTP_API
int aws_http_exchange_send_response(
    struct aws_http_exchange *exchange,
    const struct aws_http_response_options *options);

/* Manually issue a window update.
 * This should only be called if the body reader is reducing the automatic window update size */
AWS_HTTP_API
int aws_http_exchange_update_window(struct aws_http_exchange *exchange, size_t increment_size);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_MESSAGE_H */
