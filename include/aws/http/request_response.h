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
 * Controls whether a header's strings may be compressed by encoding the index of
 * strings in a cache, rather than encoding the literal string.
 *
 * This setting has no effect on HTTP/1.x connections.
 * On HTTP/2 connections this controls HPACK behavior.
 * See RFC-7541 Section 7.1 for security considerations.
 */
enum aws_http_header_compression {
    /**
     * Compress header by encoding the cached index of its strings,
     * or by updating the cache to contain these strings for future reference.
     * Best for headers that are sent repeatedly.
     * This is the default setting.
     */
    AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,

    /**
     * Encode header strings literally.
     * If an intermediary re-broadcasts the headers, it is permitted to use cache.
     * Best for unique headers that are unlikely to repeat.
     */
    AWS_HTTP_HEADER_COMPRESSION_NO_CACHE,

    /**
     * Encode header strings literally and forbid all intermediaries from using
     * cache when re-broadcasting.
     * Best for header fields that are highly valuable or sensitive to recovery.
     */
    AWS_HTTP_HEADER_COMPRESSION_NO_FORWARD_CACHE,
};

/**
 * A lightweight HTTP header struct.
 * Note that the underlying strings are not owned by the byte cursors.
 */
struct aws_http_header {
    struct aws_byte_cursor name;
    struct aws_byte_cursor value;

    /* Controls whether the header's strings may be compressed via caching. */
    enum aws_http_header_compression compression;
};

/**
 * A transformable block of HTTP headers.
 * Provides a nice API for getting/setting header names and values.
 *
 * All strings are copied and stored within this datastructure.
 * The index of a given header may change any time headers are modified.
 * When iterating headers, the following ordering rules apply:
 *
 * - Headers with the same name will always be in the same order, relative to one another.
 *   If "A: one" is added before "A: two", then "A: one" will always precede "A: two".
 *
 * - Headers with different names could be in any order, relative to one another.
 *   If "A: one" is seen before "B: bee" in one iteration, you might see "B: bee" before "A: one" on the next.
 */
struct aws_http_headers;

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
 * Note that, if the connection is using manual_window_management then the window
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
};

#define AWS_HTTP_REQUEST_HANDLER_OPTIONS_INIT                                                                          \
    { .self_size = sizeof(struct aws_http_request_handler_options), }

AWS_EXTERN_C_BEGIN

/**
 * Return whether both names are equivalent.
 * This is a case-insensitive string comparison.
 *
 * Example Matches:
 * "Content-Length" == "content-length" // upper or lower case ok

 * Example Mismatches:
 * "Content-Length" != " Content-Length" // leading whitespace bad
 */
AWS_HTTP_API
bool aws_http_header_name_eq(struct aws_byte_cursor name_a, struct aws_byte_cursor name_b);

/**
 * Create a new headers object.
 * The caller has a hold on the object and must call aws_http_headers_release() when they are done with it.
 */
AWS_HTTP_API
struct aws_http_headers *aws_http_headers_new(struct aws_allocator *allocator);

/**
 * Acquire a hold on the object, preventing it from being deleted until
 * aws_http_headers_release() is called by all those with a hold on it.
 */
AWS_HTTP_API
void aws_http_headers_acquire(struct aws_http_headers *headers);

/**
 * Release a hold on the object.
 * The object is deleted when all holds on it are released.
 */
AWS_HTTP_API
void aws_http_headers_release(struct aws_http_headers *headers);

/**
 * Add a header.
 * The underlying strings are copied.
 */
AWS_HTTP_API
int aws_http_headers_add_header(struct aws_http_headers *headers, const struct aws_http_header *header);

/**
 * Add a header.
 * The underlying strings are copied.
 */
AWS_HTTP_API
int aws_http_headers_add(struct aws_http_headers *headers, struct aws_byte_cursor name, struct aws_byte_cursor value);

/**
 * Add an array of headers.
 * The underlying strings are copied.
 */
AWS_HTTP_API
int aws_http_headers_add_array(struct aws_http_headers *headers, const struct aws_http_header *array, size_t count);

/**
 * Set a header value.
 * The header is added if necessary and any existing values for this name are removed.
 * The underlying strings are copied.
 */
AWS_HTTP_API
int aws_http_headers_set(struct aws_http_headers *headers, struct aws_byte_cursor name, struct aws_byte_cursor value);

/**
 * Get the total number of headers.
 */
AWS_HTTP_API
size_t aws_http_headers_count(const struct aws_http_headers *headers);

/**
 * Get the header at the specified index.
 * The index of a given header may change any time headers are modified.
 * When iterating headers, the following ordering rules apply:
 *
 * - Headers with the same name will always be in the same order, relative to one another.
 *   If "A: one" is added before "A: two", then "A: one" will always precede "A: two".
 *
 * - Headers with different names could be in any order, relative to one another.
 *   If "A: one" is seen before "B: bee" in one iteration, you might see "B: bee" before "A: one" on the next.
 *
 * AWS_ERROR_INVALID_INDEX is raised if the index is invalid.
 */
AWS_HTTP_API
int aws_http_headers_get_index(
    const struct aws_http_headers *headers,
    size_t index,
    struct aws_http_header *out_header);

/**
 * Get the first value for this name, ignoring any additional values.
 * AWS_ERROR_HTTP_HEADER_NOT_FOUND is raised if the name is not found.
 */
AWS_HTTP_API
int aws_http_headers_get(
    const struct aws_http_headers *headers,
    struct aws_byte_cursor name,
    struct aws_byte_cursor *out_value);

/**
 * Test if header name exists or not in headers
 */
AWS_HTTP_API
bool aws_http_headers_has(const struct aws_http_headers *headers, struct aws_byte_cursor name);

/**
 * Remove all headers with this name.
 * AWS_ERROR_HTTP_HEADER_NOT_FOUND is raised if no headers with this name are found.
 */
AWS_HTTP_API
int aws_http_headers_erase(struct aws_http_headers *headers, struct aws_byte_cursor name);

/**
 * Remove the first header found with this name and value.
 * AWS_ERROR_HTTP_HEADER_NOT_FOUND is raised if no such header is found.
 */
AWS_HTTP_API
int aws_http_headers_erase_value(
    struct aws_http_headers *headers,
    struct aws_byte_cursor name,
    struct aws_byte_cursor value);

/**
 * Remove the header at the specified index.
 *
 * AWS_ERROR_INVALID_INDEX is raised if the index is invalid.
 */
AWS_HTTP_API
int aws_http_headers_erase_index(struct aws_http_headers *headers, size_t index);

/**
 * Clear all headers.
 */
AWS_HTTP_API
void aws_http_headers_clear(struct aws_http_headers *headers);

/**
 * Create a new request message.
 * The message is blank, all properties (method, path, etc) must be set individually.
 *
 * The caller has a hold on the object and must call aws_http_message_release() when they are done with it.
 */
AWS_HTTP_API
struct aws_http_message *aws_http_message_new_request(struct aws_allocator *allocator);

/**
 * Like aws_http_message_new_request(), but uses existing aws_http_headers instead of creating a new one.
 * Acquires a hold on the headers, and releases it when the request is destroyed.
 */
AWS_HTTP_API
struct aws_http_message *aws_http_message_new_request_with_headers(
    struct aws_allocator *allocator,
    struct aws_http_headers *existing_headers);

/**
 * Create a new response message.
 * The message is blank, all properties (status, headers, etc) must be set individually.
 *
 * The caller has a hold on the object and must call aws_http_message_release() when they are done with it.
 */
AWS_HTTP_API
struct aws_http_message *aws_http_message_new_response(struct aws_allocator *allocator);

/**
 * Acquire a hold on the object, preventing it from being deleted until
 * aws_http_message_release() is called by all those with a hold on it.
 */
AWS_HTTP_API
void aws_http_message_acquire(struct aws_http_message *message);

/**
 * Release a hold on the object.
 * The object is deleted when all holds on it are released.
 */
AWS_HTTP_API
void aws_http_message_release(struct aws_http_message *message);

/**
 * Deprecated. This is equivalent to aws_http_message_release().
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
 * Get the message's aws_http_headers.
 *
 * This datastructure has more functions for inspecting and modifying headers than
 * are available on the aws_http_message datastructure.
 */
AWS_HTTP_API
struct aws_http_headers *aws_http_message_get_headers(struct aws_http_message *message);

/**
 * Get the message's const aws_http_headers.
 */
AWS_HTTP_API
const struct aws_http_headers *aws_http_message_get_const_headers(const struct aws_http_message *message);

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
 * The request does not start sending automatically once the stream is created. You must call
 * aws_http_stream_activate to begin execution of the request.
 *
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

/**
 * Only used for client initiated streams (immediately following a call to aws_http_connection_make_request).
 *
 * Activates the request's outgoing stream processing.
 */
AWS_HTTP_API int aws_http_stream_activate(struct aws_http_stream *stream);

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

/**
 * Gets the Http/2 id associated with a stream.  Even h1 streams have an id (using the same allocation procedure
 * as http/2) for easier tracking purposes. For client streams, this will only be non-zero after a successful call
 * to aws_http_stream_activate()
 */
AWS_HTTP_API
uint32_t aws_http_stream_get_id(const struct aws_http_stream *stream);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_REQUEST_RESPONSE_H */
