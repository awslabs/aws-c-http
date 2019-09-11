#ifndef AWS_HTTP_REQUEST_RESPONSE_H
#define AWS_HTTP_REQUEST_RESPONSE_H

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
struct aws_input_stream;

/**
 * A stream exists for the duration of a request/response exchange.
 * A client creates a stream to send a request and receive a response.
 * A server creates a stream to receive a request and send a response.
 * In http/2, a push-promise stream can be sent by a server and received by a client.
 */
struct aws_http_stream;

/**
 * A lightweight HTTP header struct.
 * Note that the underlying strings are not owned by the byte cursors.
 */
struct aws_http_header {
    struct aws_byte_cursor name;
    struct aws_byte_cursor value;
};

/**
 * Header block type.
 * INFORMATIONAL: Header block for 1xx informational (interim) responses.
 * MAIN: Main header block sent with request or response.
 * TRAILING: Headers sent after the body of a request or response.
 */
enum aws_http_header_block {
    AWS_HTTP_HEADER_BLOCK_MAIN,
    AWS_HTTP_HEADER_BLOCK_INFORMATIONAL,
    AWS_HTTP_HEADER_BLOCK_TRAILING,
};

/**
 * The definition for an outgoing HTTP request or response.
 * The message may be transformed (ex: signing the request) before its data is eventually sent.
 *
 * The message keeps internal copies of its trivial strings (method, path, headers)
 * but does NOT take ownership of its body stream.
 *
 * A language binding would likely present this as an HttpMessage base class with
 * HttpRequest and HttpResponse subclasses.
 */
struct aws_http_message;

/**
 * Function to invoke when a message transformation completes.
 * This function MUST be invoked or the application will soft-lock.
 * `message` and `complete_ctx` must be the same pointers provided to the `aws_http_message_transform_fn`.
 * `error_code` should should be AWS_ERROR_SUCCESS if transformation was successful,
 * otherwise pass a different AWS_ERROR_X value.
 */
typedef void(
    aws_http_message_transform_complete_fn)(struct aws_http_message *message, int error_code, void *complete_ctx);

/**
 * A function that may modify a request or response before it is sent.
 * The transformation may be asynchronous or immediate.
 * The user MUST invoke the `complete_fn` when transformation is complete or the application will soft-lock.
 * When invoking the `complete_fn`, pass along the `message` and `complete_ctx` provided here and an error code.
 * The error code should be AWS_ERROR_SUCCESS if transformation was successful,
 * otherwise pass a different AWS_ERROR_X value.
 */
typedef void(aws_http_message_transform_fn)(
    struct aws_http_message *message,
    void *user_data,
    aws_http_message_transform_complete_fn *complete_fn,
    void *complete_ctx);

/**
 * Invoked repeatedly times as headers are received.
 * At this point, aws_http_stream_get_incoming_response_status() can be called for the client.
 * And aws_http_stream_get_incoming_request_method() and aws_http_stream_get_incoming_request_uri() can be called for
 * the server.
 * This is always invoked on the HTTP connection's event-loop thread.
 *
 * Return AWS_OP_SUCCESS to continue processing the stream.
 * Return AWS_OP_ERR to indicate failure and cancel the stream.
 */
typedef int(aws_http_on_incoming_headers_fn)(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data);

/**
 * Invoked when the incoming header block of this type(informational/main/trailing) has been completely read.
 * This is always invoked on the HTTP connection's event-loop thread.
 *
 * Return AWS_OP_SUCCESS to continue processing the stream.
 * Return AWS_OP_ERR to indicate failure and cancel the stream.
 */
typedef int(aws_http_on_incoming_header_block_done_fn)(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data);

/**
 * Called repeatedly as body data is received.
 * The data must be copied immediately if you wish to preserve it.
 * This is always invoked on the HTTP connection's event-loop thread.
 *
 * Note that, if the stream is using manual_window_management then the window
 * size has shrunk by the amount of body data received. If the window size
 * reaches 0 no further data will be received. Increment the window size with
 * aws_http_stream_update_window().
 *
 * Return AWS_OP_SUCCESS to continue processing the stream.
 * Return AWS_OP_ERR to indicate failure and cancel the stream.
 */
typedef int(
    aws_http_on_incoming_body_fn)(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data);

/**
 * Invoked when request has been completely read.
 * This is always invoked on the HTTP connection's event-loop thread.
 *
 * Return AWS_OP_SUCCESS to continue processing the stream.
 * Return AWS_OP_ERR to indicate failure and cancel the stream.
 */
typedef int(aws_http_on_incoming_request_done_fn)(struct aws_http_stream *stream, void *user_data);

/**
 * Invoked when request/response stream is complete, whether successful or unsuccessful
 * This is always invoked on the HTTP connection's event-loop thread.
 */
typedef void(aws_http_on_stream_complete_fn)(struct aws_http_stream *stream, int error_code, void *user_data);

/**
 * Options for creating a stream which sends a request from the client and receives a response from the server.
 */
struct aws_http_make_request_options {
    /**
     * The sizeof() this struct, used for versioning.
     * Required.
     */
    size_t self_size;

    /**
     * Definition for outgoing request.
     * Required.
     * This object must stay alive at least until on_complete is called.
     */
    struct aws_http_message *request;

    void *user_data;

    /**
     * Invoked repeatedly times as headers are received.
     * Optional.
     * See `aws_http_on_incoming_headers_fn`.
     */
    aws_http_on_incoming_headers_fn *on_response_headers;

    /**
     * Invoked when response header block has been completely read.
     * Optional.
     * See `aws_http_on_incoming_header_block_done_fn`.
     */
    aws_http_on_incoming_header_block_done_fn *on_response_header_block_done;

    /**
     * Invoked repeatedly as body data is received.
     * Optional.
     * See `aws_http_on_incoming_body_fn`.
     */
    aws_http_on_incoming_body_fn *on_response_body;

    /**
     * Invoked when request/response stream is complete, whether successful or unsuccessful
     * Optional.
     * See `aws_http_on_stream_complete_fn`.
     */
    aws_http_on_stream_complete_fn *on_complete;

    /**
     * Set to true to manually manage the read window size.
     *
     * If this is false, the connection will maintain a constant window size.
     *
     * If this is true, the caller must manually increment the window size using aws_http_stream_update_window().
     * If the window is not incremented, it will shrink by the amount of body data received. If the window size
     * reaches 0, no further data will be received.
     */
    bool manual_window_management;
};

struct aws_http_request_handler_options {
    /* Set to sizeof() this struct, used for versioning. */
    size_t self_size;

    /**
     * Required.
     */
    struct aws_http_connection *server_connection;

    /**
     * user_data passed to callbacks.
     * Optional.
     */
    void *user_data;

    /**
     * Invoked repeatedly times as headers are received.
     * Optional.
     * See `aws_http_on_incoming_headers_fn`.
     */
    aws_http_on_incoming_headers_fn *on_request_headers;

    /**
     * Invoked when the request header block has been completely read.
     * Optional.
     * See `aws_http_on_incoming_header_block_done_fn`.
     */
    aws_http_on_incoming_header_block_done_fn *on_request_header_block_done;

    /**
     * Invoked as body data is received.
     * Optional.
     * See `aws_http_on_incoming_body_fn`.
     */
    aws_http_on_incoming_body_fn *on_request_body;

    /**
     * Invoked when request has been completely read.
     * Optional.
     * See `aws_http_on_incoming_request_done_fn`.
     */
    aws_http_on_incoming_request_done_fn *on_request_done;

    /**
     * Invoked when request/response stream is complete, whether successful or unsuccessful
     * Optional.
     * See `aws_http_on_stream_complete_fn`.
     */
    aws_http_on_stream_complete_fn *on_complete;

    /**
     * Set to true to manually manage the read window size.
     *
     * If this is false, the connection will maintain a constant window size.
     *
     * If this is true, the caller must manually increment the window size using aws_http_stream_update_window().
     * If the window is not incremented, it will shrink by the amount of body data received. If the window size
     * reaches 0, no further data will be received.
     */
    bool manual_window_management;
};

#define AWS_HTTP_REQUEST_HANDLER_OPTIONS_INIT                                                                          \
    { .self_size = sizeof(struct aws_http_request_handler_options), }

AWS_EXTERN_C_BEGIN

/**
 * Create a new request message.
 * The message is blank, all properties (method, path, etc) must be set individually.
 */
AWS_HTTP_API
struct aws_http_message *aws_http_message_new_request(struct aws_allocator *allocator);

/**
 * Create a new response message.
 * The message is blank, all properties (status, headers, etc) must be set individually.
 */
AWS_HTTP_API
struct aws_http_message *aws_http_message_new_response(struct aws_allocator *allocator);

/**
 * Destroy the message.
 */
AWS_HTTP_API
void aws_http_message_destroy(struct aws_http_message *message);

AWS_HTTP_API
bool aws_http_message_is_request(const struct aws_http_message *message);

AWS_HTTP_API
bool aws_http_message_is_response(const struct aws_http_message *message);

/**
 * Get the method (request messages only).
 */
AWS_HTTP_API
int aws_http_message_get_request_method(
    const struct aws_http_message *request_message,
    struct aws_byte_cursor *out_method);

/**
 * Set the method (request messages only).
 * The request makes its own copy of the underlying string.
 */
AWS_HTTP_API
int aws_http_message_set_request_method(struct aws_http_message *request_message, struct aws_byte_cursor method);

/*
 * Get the path-and-query value (request messages only).
 */
AWS_HTTP_API
int aws_http_message_get_request_path(const struct aws_http_message *request_message, struct aws_byte_cursor *out_path);

/**
 * Set the path-and-query value (request messages only).
 * The request makes its own copy of the underlying string.
 */
AWS_HTTP_API
int aws_http_message_set_request_path(struct aws_http_message *request_message, struct aws_byte_cursor path);

/**
 * Get the status code (response messages only).
 * If no status is set, AWS_ERROR_HTTP_DATA_NOT_AVAILABLE is raised.
 */
AWS_HTTP_API
int aws_http_message_get_response_status(const struct aws_http_message *response_message, int *out_status_code);

/**
 * Set the status code (response messages only).
 */
AWS_HTTP_API
int aws_http_message_set_response_status(struct aws_http_message *response_message, int status_code);

/**
 * Get the body stream.
 * Returns NULL if no body stream is set.
 */
AWS_HTTP_API
struct aws_input_stream *aws_http_message_get_body_stream(const struct aws_http_message *message);

/**
 * Set the body stream.
 * NULL is an acceptable value for messages with no body.
 * Note: The message does NOT take ownership of the body stream.
 * The stream must not be destroyed until the message is complete.
 */
AWS_HTTP_API
void aws_http_message_set_body_stream(struct aws_http_message *message, struct aws_input_stream *body_stream);

/**
 * Get the number of headers.
 */
AWS_HTTP_API
size_t aws_http_message_get_header_count(const struct aws_http_message *message);

/**
 * Get the header at the specified index.
 * This function cannot fail if a valid index is provided.
 * Otherwise, AWS_ERROR_INVALID_INDEX will be raised.
 *
 * The underlying strings are stored within the message.
 */
AWS_HTTP_API
int aws_http_message_get_header(
    const struct aws_http_message *message,
    struct aws_http_header *out_header,
    size_t index);

/**
 * Add a header to the end of the array.
 * The message makes its own copy of the underlying strings.
 */
AWS_HTTP_API
int aws_http_message_add_header(struct aws_http_message *message, struct aws_http_header header);

/**
 * Add an array of headers to the end of the header array.
 * The message makes its own copy of the underlying strings.
 *
 * This is a helper function useful when it's easier to define headers as a stack array, rather than calling add_header
 * repeatedly.
 */
AWS_HTTP_API
int aws_http_message_add_header_array(
    struct aws_http_message *message,
    const struct aws_http_header *headers,
    size_t num_headers);

/**
 * Modify the header at the specified index.
 * The message makes its own copy of the underlying strings.
 * The previous strings may be destroyed.
 */
AWS_HTTP_API
int aws_http_message_set_header(struct aws_http_message *message, struct aws_http_header header, size_t index);

/**
 * Remove the header at the specified index.
 * Headers after this index are all shifted back one position.
 *
 * This function cannot fail if a valid index is provided.
 * Otherwise, AWS_ERROR_INVALID_INDEX will be raised.
 */
AWS_HTTP_API
int aws_http_message_erase_header(struct aws_http_message *message, size_t index);

/**
 * Create a stream, with a client connection sending a request.
 * The request starts sending automatically once the stream is created.
 * The `options` are copied during this call.
 *
 * Tip for language bindings: Do not bind the `options` struct. Use something more natural for your language,
 * such as Builder Pattern in Java, or Python's ability to take many optional arguments by name.
 */
AWS_HTTP_API
struct aws_http_stream *aws_http_connection_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);

/**
 * Create a stream, with a server connection receiving and responding to a request.
 * This function can only be called from the `aws_http_on_incoming_request_fn` callback.
 * aws_http_stream_send_response() should be used to send a response.
 */
AWS_HTTP_API
struct aws_http_stream *aws_http_stream_new_server_request_handler(
    const struct aws_http_request_handler_options *options);
/**
 * Users must release the stream when they are done with it, or its memory will never be cleaned up.
 * This will not cancel the stream, its callbacks will still fire if the stream is still in progress.
 *
 * Tips for language bindings:
 * - Invoke this from the wrapper class's finalizer/destructor.
 * - Do not let the wrapper class be destroyed until on_complete() has fired.
 */
AWS_HTTP_API
void aws_http_stream_release(struct aws_http_stream *stream);

AWS_HTTP_API
struct aws_http_connection *aws_http_stream_get_connection(const struct aws_http_stream *stream);

/* Only valid in "request" streams, once response headers start arriving */
AWS_HTTP_API
int aws_http_stream_get_incoming_response_status(const struct aws_http_stream *stream, int *out_status);

/* Only valid in "request handler" streams, once request headers start arriving */
AWS_HTTP_API
int aws_http_stream_get_incoming_request_method(
    const struct aws_http_stream *stream,
    struct aws_byte_cursor *out_method);

AWS_HTTP_API
int aws_http_stream_get_incoming_request_uri(const struct aws_http_stream *stream, struct aws_byte_cursor *out_uri);

/**
 * Send response (only callable from "request handler" streams)
 * The response object must stay alive at least until the stream's on_complete is called.
 */
AWS_HTTP_API
int aws_http_stream_send_response(struct aws_http_stream *stream, struct aws_http_message *response);

/**
 * Manually issue a window update.
 * Note that the stream's default behavior is to issue updates which keep the window at its original size.
 * See aws_http_make_request_options.manual_window_management for details on letting the window shrink.
 */
AWS_HTTP_API
void aws_http_stream_update_window(struct aws_http_stream *stream, size_t increment_size);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_REQUEST_RESPONSE_H */
