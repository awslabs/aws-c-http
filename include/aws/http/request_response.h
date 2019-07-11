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
struct aws_hash_table;

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
 * The definition for an HTTP request.
 * This datastructure may be transformed (ex: signing the request) before it is used to create a stream.
 *
 * The request keeps internal copies of its trivial strings (method, path, headers)
 * but does NOT take ownership of its body stream.
 */
struct aws_http_request;

/**
 * A function that may modify the request before it is sent.
 * Return AWS_OP_SUCCESS to indicate that transformation was successful,
 * or AWS_OP_ERR to indicate failure and cancel the operation.
 */
typedef int aws_http_request_transform_fn(struct aws_http_request *request, void *user_data);

enum aws_http_outgoing_body_state {
    AWS_HTTP_OUTGOING_BODY_IN_PROGRESS,
    AWS_HTTP_OUTGOING_BODY_DONE,
};

/**
 * Called repeatedly whenever body data can be sent.
 * User should write body to buffer using aws_byte_buf_write_X functions.
 * Note that the buffer might already be partially full.
 * Return AWS_HTTP_OUTGOING_BODY_DONE when the body has been written to its end.
 */
typedef enum aws_http_outgoing_body_state(
    aws_http_stream_outgoing_body_fn)(struct aws_http_stream *stream, struct aws_byte_buf *buf, void *user_data);

typedef void(aws_http_on_incoming_headers_fn)(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data);

typedef void(aws_http_on_incoming_header_block_done_fn)(struct aws_http_stream *stream, bool has_body, void *user_data);

/**
 * Called repeatedly as body data is received.
 * The data must be copied immediately if you wish to preserve it.
 *
 * `out_window_update_size` is how much to increment the window once this data is processed.
 * By default, it is the size of the data which has just come in.
 * Leaving this value untouched will increment the window back to its original size.
 * Setting this value to 0 will prevent the update and let the window shrink.
 * The window can be manually updated via aws_http_stream_update_window()
 */
typedef void(aws_http_on_incoming_body_fn)(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    size_t *out_window_update_size,
    void *user_data);

typedef void(aws_http_on_stream_complete_fn)(struct aws_http_stream *stream, int error_code, void *user_data);

/**
 * Options for creating a stream which sends a request from the client and receives a response from the server.
 * Initialize with AWS_HTTP_REQUEST_OPTIONS_INIT to set default values.
 */
struct aws_http_request_options {
    /**
     * The sizeof() this struct, used for versioning.
     * Set by AWS_HTTP_REQUEST_OPTIONS_INIT.
     */
    size_t self_size;

    /**
     * Required.
     */
    struct aws_http_connection *client_connection;

    /**
     * Required.
     * This object must stay alive at least until on_complete is called.
     */
    struct aws_http_request *request;

    void *user_data;

    /**
     * Invoked repeatedly times as headers are received.
     * At this point, aws_http_stream_get_incoming_response_status() can be called.
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
     * Invoked when request/response stream is complete, whether successful or unsuccessful
     * Optional.
     */
    aws_http_on_stream_complete_fn *on_complete;
};

typedef int(aws_transform_http_request_fn)(
    struct aws_http_request *request,
    struct aws_allocator *allocator,
    const struct aws_hash_table *context);

/**
 * Initializes aws_http_request_options with default values.
 */
#define AWS_HTTP_REQUEST_OPTIONS_INIT                                                                                  \
    { .self_size = sizeof(struct aws_http_request_options), }

struct aws_http_request_handler_options {
    /* Set to sizeof() this struct, used for versioning. */
    size_t self_size;

    struct aws_http_connection *server_connection;
    void *user_data;

    aws_http_on_incoming_headers_fn *on_request_headers;
    aws_http_on_incoming_header_block_done_fn *on_request_header_block_done;
    aws_http_on_incoming_body_fn *on_request_body;
    aws_http_on_stream_complete_fn *on_complete;
};

#define AWS_HTTP_REQUEST_HANDLER_OPTIONS_INIT                                                                          \
    { .self_size = sizeof(struct aws_http_request_handler_options), }

struct aws_http_response_options {
    /* Set to sizeof() this struct, used for versioning. */
    size_t self_size;

    int status;
    const struct aws_http_header *header_array;
    size_t num_headers;
    aws_http_stream_outgoing_body_fn *stream_outgoing_body;
};

AWS_EXTERN_C_BEGIN

/**
 * Create a new request.
 * The request is blank, all properties (method, path, etc) must be set individually.
 */
AWS_HTTP_API
struct aws_http_request *aws_http_request_new(struct aws_allocator *allocator);

/**
 * Destroy the the request.
 */
AWS_HTTP_API
void aws_http_request_destroy(struct aws_http_request *request);

/**
 * Get the method.
 * If no method is set, AWS_ERROR_HTTP_DATA_NOT_AVAILABLE is raised.
 */
AWS_HTTP_API
int aws_http_request_get_method(const struct aws_http_request *request, struct aws_byte_cursor *out_method);

/**
 * Set the method.
 * The request makes its own copy of the underlying string.
 */
AWS_HTTP_API
int aws_http_request_set_method(struct aws_http_request *request, struct aws_byte_cursor method);

/**
 * Get the path (and query) value.
 * If no path is set, AWS_ERROR_HTTP_DATA_NOT_AVAILABLE is raised.
 */
AWS_HTTP_API
int aws_http_request_get_path(const struct aws_http_request *request, struct aws_byte_cursor *out_path);

/**
 * Set the path (and-query) value.
 * The request makes its own copy of the underlying string.
 */
AWS_HTTP_API
int aws_http_request_set_path(struct aws_http_request *request, struct aws_byte_cursor path);

/**
 * Get the body stream.
 * Returns NULL if no body stream is set.
 */
AWS_HTTP_API
struct aws_input_stream *aws_http_request_get_body_stream(const struct aws_http_request *request);

/**
 * Set the body stream.
 * NULL is an acceptable value for requests with no body.
 * Note: The request does NOT take ownership of the body stream.
 * The stream must not be destroyed until the request is complete.
 */
AWS_HTTP_API
void aws_http_request_set_body_stream(struct aws_http_request *request, struct aws_input_stream *body_stream);

/**
 * Get the number of headers.
 * Headers are stored in a linear array.
 */
AWS_HTTP_API
size_t aws_http_request_get_header_count(const struct aws_http_request *request);

/**
 * Get the header at the specified index.
 * This function cannot fail if a valid index is provided.
 * Otherwise, AWS_ERROR_INVALID_INDEX will be raised.
 *
 * The underlying strings are stored within the request.
 */
AWS_HTTP_API
int aws_http_request_get_header(
    const struct aws_http_request *request,
    struct aws_http_header *out_header,
    size_t index);

/**
 * Add a header to the end of the array.
 * The request makes its own copy of the underlying strings.
 */
AWS_HTTP_API
int aws_http_request_add_header(struct aws_http_request *request, struct aws_http_header header);

/**
 * Add an array of headers to the end of the header array.
 * The request makes its own copy of the underlying strings.
 *
 * This is a helper function useful when it's easier to define headers as a stack array, rather than calling add_header
 * repeatedly.
 */
AWS_HTTP_API
int aws_http_request_add_header_array(
    struct aws_http_request *request,
    const struct aws_http_header *headers,
    size_t num_headers);

/**
 * Modify the header at the specified index.
 * The request makes its own copy of the underlying strings.
 * The previous strings may be destroyed.
 */
AWS_HTTP_API
int aws_http_request_set_header(struct aws_http_request *request, struct aws_http_header header, size_t index);

/**
 * Remove the header at the specified index.
 * Headers after this index are all shifted back one position.
 *
 * This function cannot fail if a valid index is provided.
 * Otherwise, AWS_ERROR_INVALID_INDEX will be raised.
 */
AWS_HTTP_API
int aws_http_request_erase_header(struct aws_http_request *request, size_t index);

/**
 * Create a stream, with a client connection sending a request.
 * The request starts sending automatically once the stream is created.
 * The `def`, and all memory it references, is copied during this call.
 */
AWS_HTTP_API
struct aws_http_stream *aws_http_stream_new_client_request(const struct aws_http_request_options *options);

/**
 * Create a stream, with a server connection receiving and responding to a request.
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

/* only callable from "request handler" streams */
AWS_HTTP_API
int aws_http_stream_send_response(struct aws_http_stream *stream, const struct aws_http_response_options *options);

/**
 * Manually issue a window update.
 * Note that the stream's default behavior is to issue updates which keep the window at its original size.
 * See aws_http_on_incoming_body_fn() for details on letting the window shrink.
 */
AWS_HTTP_API
void aws_http_stream_update_window(struct aws_http_stream *stream, size_t increment_size);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_REQUEST_RESPONSE_H */
