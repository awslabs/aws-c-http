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

#include <aws/http/private/websocket_impl.h>

#include <aws/http/connection.h>
#include <aws/http/private/http_impl.h>
#include <aws/http/request_response.h>
#include <aws/io/uri.h>

/* TODO: what id to use for logging. CHANNEL_BOOTSTRAP? pre-allocate websocket? */

/**
 * The websocket bootstrap brings a websocket connection into this world, and sees it out again.
 * Spins up an HTTP client, performs the opening handshake (HTTP Upgrade request),
 * creates the websocket handler, and inserts it into the channel.
 * The bootstrap is responsible for firing the on_connection_setup and on_connection_shutdown callbacks.
 */
struct aws_websocket_client_bootstrap {
    struct aws_allocator *alloc;
    struct aws_websocket *websocket;

    /* Handshake request data */
    struct aws_byte_cursor request_path;
    struct aws_http_header *request_header_array;
    size_t num_request_headers;
    struct aws_byte_buf request_storage;

    /* Handshake response data */
    int response_status;
    struct aws_array_list response_headers;
    struct aws_byte_buf response_storage;

    /* Setup callback will be set NULL once it's invoked.
     * This is used to determine whether setup or shutdown should be invoked
     * from the HTTP-shutdown callback. */
    aws_websocket_on_connection_setup_fn *websocket_setup_callback;
    aws_websocket_on_connection_shutdown_fn *websocket_shutdown_callback;
    void *user_data;

    int setup_error_code;
};

static void s_ws_bootstrap_destroy(struct aws_websocket_client_bootstrap *ws_bootstrap);
static void s_ws_bootstrap_cancel_setup_due_to_err(
    struct aws_websocket_client_bootstrap *ws_bootstrap,
    struct aws_http_connection *http_connection,
    int error_code);
static void s_ws_bootstrap_on_http_setup(
    struct aws_http_connection *http_connection,
    int error_code,
    void *user_data);
static void s_ws_bootstrap_on_http_shutdown(
    struct aws_http_connection *http_connection,
    int error_code,
    void *user_data);
static void s_ws_bootstrap_on_handshake_response_headers(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data);
static void s_ws_bootstrap_on_handshake_complete(struct aws_http_stream *stream, int error_code, void *user_data);

int aws_websocket_client_connect(const struct aws_websocket_client_connection_options *options) {
    aws_http_fatal_assert_library_initialized();
    AWS_ASSERT(options);
    AWS_ASSERT(options->num_handhake_headers > 0);
    int err;
    /* TODO: verify options */

    struct aws_websocket_client_bootstrap *ws_bootstrap =
        aws_mem_calloc(options->allocator, 1, sizeof(struct aws_websocket_client_bootstrap));
    if (!ws_bootstrap) {
        goto error;
    }

    ws_bootstrap->alloc = options->allocator;
    ws_bootstrap->response_status = AWS_HTTP_STATUS_UNKNOWN;

    /* Deep-copy all request headers, plus the request path. */
    size_t request_storage_size = aws_uri_path_and_query(options->uri)->len;
    for (size_t i = 0; i < options->num_handhake_headers; ++i) {
        request_storage_size += options->handshake_header_array[i].name.len;
        request_storage_size += options->handshake_header_array[i].value.len;
    }

    err = aws_byte_buf_init(&ws_bootstrap->request_storage, ws_bootstrap->alloc, request_storage_size);
    if (err) {
        goto error;
    }

    ws_bootstrap->request_path.len = aws_uri_path_and_query(options->uri)->len;
    ws_bootstrap->request_path.ptr = ws_bootstrap->request_storage.buffer + ws_bootstrap->request_storage.len;
    bool write_success =
        aws_byte_buf_write_from_whole_cursor(&ws_bootstrap->request_storage, *aws_uri_path_and_query(options->uri));

    ws_bootstrap->num_request_headers = options->num_handhake_headers;
    ws_bootstrap->request_header_array =
        aws_mem_calloc(ws_bootstrap->alloc, ws_bootstrap->num_request_headers, sizeof(struct aws_http_header));
    if (!ws_bootstrap->request_header_array) {
        goto error;
    }

    for (size_t i = 0; i < options->num_handhake_headers; ++i) {
        const struct aws_http_header *src = &options->handshake_header_array[i];
        struct aws_http_header *dst = &ws_bootstrap->request_header_array[i];

        dst->name.len = src->name.len;
        dst->name.ptr = ws_bootstrap->request_storage.buffer + ws_bootstrap->request_storage.len;
        write_success &= aws_byte_buf_write_from_whole_cursor(&ws_bootstrap->request_storage, src->name);

        dst->value.len = src->value.len;
        dst->value.ptr = ws_bootstrap->request_storage.buffer + ws_bootstrap->request_storage.len;
        write_success &= aws_byte_buf_write_from_whole_cursor(&ws_bootstrap->request_storage, src->value);
    }

    if (!write_success) {
        goto error;
    }

    /* Pre-allocate space for response headers */
    size_t estimated_response_headers = ws_bootstrap->num_request_headers + 10;
    size_t estimated_response_header_length = 64;

    err = aws_array_list_init_dynamic(
        &ws_bootstrap->response_headers,
        ws_bootstrap->alloc,
        estimated_response_headers,
        sizeof(struct aws_http_header));
    if (err) {
        goto error;
    }

    err = aws_byte_buf_init(
        &ws_bootstrap->response_storage,
        ws_bootstrap->alloc,
        estimated_response_headers * estimated_response_header_length);
    if (err) {
        goto error;
    }

    /* Initiate HTTP connection */
    struct aws_http_client_connection_options http_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    http_options.allocator = ws_bootstrap->alloc;
    http_options.bootstrap = options->bootstrap;
    http_options.host_name = *aws_uri_host_name(options->uri);
    http_options.port = aws_uri_port(options->uri); /* TODO: require user to specify port? or infer from scheme? */
    http_options.socket_options = options->socket_options;
    http_options.tls_options = options->tls_options;
    http_options.initial_window_size = 1024; /* Adequate space for response data to trickle in */
    http_options.user_data = ws_bootstrap;
    http_options.on_setup = s_ws_bootstrap_on_http_setup;
    http_options.on_shutdown = s_ws_bootstrap_on_http_shutdown;

    err = aws_http_client_connect(&http_options);
    if (err) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    s_ws_bootstrap_destroy(ws_bootstrap);
    return AWS_OP_ERR;
}

static void s_ws_bootstrap_destroy(struct aws_websocket_client_bootstrap *ws_bootstrap) {
    if (!ws_bootstrap) {
        return;
    }

    if (ws_bootstrap->request_header_array) {
        aws_mem_release(ws_bootstrap->alloc, ws_bootstrap->request_header_array);
    }
    aws_byte_buf_clean_up(&ws_bootstrap->request_storage);
    aws_array_list_clean_up(&ws_bootstrap->response_headers);
    aws_byte_buf_clean_up(&ws_bootstrap->response_storage);

    aws_mem_release(ws_bootstrap->alloc, ws_bootstrap);
}

/* Call if something goes wrong between an HTTP connection being established, and the websocket setup completing. */
static void s_ws_bootstrap_cancel_setup_due_to_err(
    struct aws_websocket_client_bootstrap *ws_bootstrap,
    struct aws_http_connection *http_connection,
    int error_code) {

    if (!ws_bootstrap->setup_error_code) {
        ws_bootstrap->setup_error_code = error_code;

        aws_http_connection_close(http_connection);
    }
}

static void s_ws_bootstrap_on_http_setup(
    struct aws_http_connection *http_connection,
    int error_code,
    void *user_data) {

    struct aws_websocket_client_bootstrap *ws_bootstrap = user_data;

    /* Setup callback contract is: if error_code is non-zero then connection is NULL. */
    AWS_FATAL_ASSERT((error_code != 0) == (http_connection == NULL));

    /* If http connection failed, inform the user immediately and clean up the websocket boostrapper. */
    if (error_code) {
        ws_bootstrap->websocket_setup_callback(
            NULL, error_code, AWS_HTTP_STATUS_UNKNOWN, NULL, 0, ws_bootstrap->user_data);

        s_ws_bootstrap_destroy(ws_bootstrap);
        return;
    }

    /* Connection exists!
     * Note that if anything goes wrong with websocket setup from hereon out, we must close the http connection
     * first and wait for shutdown to complete before informing the user of setup failure. */

    /* Send the handshake request */
    struct aws_http_request_options options = AWS_HTTP_REQUEST_OPTIONS_INIT;
    options.client_connection = http_connection;
    options.method = aws_byte_cursor_from_c_str("GET");
    options.uri = ws_bootstrap->request_path;
    options.header_array = ws_bootstrap->request_header_array;
    options.num_headers = ws_bootstrap->num_request_headers;
    options.user_data = ws_bootstrap;
    options.on_response_headers = s_ws_bootstrap_on_handshake_response_headers;
    options.on_complete = s_ws_bootstrap_on_handshake_complete;

    struct aws_http_stream *handshake_stream = aws_http_stream_new_client_request(&options);
    if (handshake_stream) {
        // TODO: LOG
    } else {
        // TODO: LOG
        s_ws_bootstrap_cancel_setup_due_to_err(ws_bootstrap, http_connection, aws_last_error());
    }
}

static void s_ws_bootstrap_on_http_shutdown(
    struct aws_http_connection *http_connection,
    int error_code,
    void *user_data) {

    struct aws_websocket_client_bootstrap *ws_bootstrap = user_data;

    /* Inform user that connection has completely shut down.
     * If setup callback still hasn't fired, invoke it now and indicate failure.
     * Otherwise, invoke shutdown callback. */
    if (ws_bootstrap->websocket_setup_callback) {
        /* Ensure non-zero error_code is passed */
        if (!error_code) {
            error_code = ws_bootstrap->setup_error_code;
            if (!error_code) {
                error_code = AWS_ERROR_UNKNOWN;
            }
        }

        /* Pass response data (if any) */
        size_t num_headers = aws_array_list_length(&ws_bootstrap->response_headers);
        const struct aws_http_header *header_array = NULL;
        if (num_headers) {
            aws_array_list_get_at_ptr(&ws_bootstrap->response_headers, (void **)&header_array, 0);
        }

        ws_bootstrap->websocket_setup_callback(
            NULL,
            error_code,
            ws_bootstrap->response_status,
            header_array,
            num_headers,
            ws_bootstrap->user_data);

    } else if (ws_bootstrap->websocket_shutdown_callback) {
        ws_bootstrap->websocket_shutdown_callback(ws_bootstrap->websocket, error_code, ws_bootstrap->user_data);
    }

    /* Clean up HTTP connection and websocket-bootstrap.
     * It's still up to the user to release the websocket itself. */
    aws_http_connection_release(http_connection);

    s_ws_bootstrap_destroy(ws_bootstrap);
}

static void s_ws_bootstrap_on_handshake_response_headers(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    struct aws_websocket_client_bootstrap *ws_bootstrap = user_data;
    int err;

    /* Deep-copy headers into ws_bootstrap */
    for (size_t i = 0; i < num_headers; ++i) {
        struct aws_http_header src_header = header_array[i];
        struct aws_http_header dst_header;

        dst_header.name.len = src_header.name.len;
        dst_header.name.ptr = ws_bootstrap->response_storage.buffer + ws_bootstrap->response_storage.len;
        err = aws_byte_buf_append_dynamic(&ws_bootstrap->response_storage, &src_header.name);
        if (err) {
            goto error;
        }

        dst_header.value.len = src_header.value.len;
        dst_header.value.ptr = ws_bootstrap->response_storage.buffer + ws_bootstrap->response_storage.len;
        err = aws_byte_buf_append_dynamic(&ws_bootstrap->response_storage, &src_header.value);
        if (err) {
            goto error;
        }

        err = aws_array_list_push_back(&ws_bootstrap->response_headers, &dst_header);
        if (err) {
            goto error;
        }
    }

    return;
error:
    s_ws_bootstrap_cancel_setup_due_to_err(ws_bootstrap, aws_http_stream_get_connection(stream), aws_last_error());
}

static void s_ws_bootstrap_on_handshake_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_websocket_client_bootstrap *ws_bootstrap = user_data;

    if (error_code) {
        goto error;
    }

    int err = aws_http_stream_get_incoming_response_status(stream, &ws_bootstrap->response_status);
    if (err) {
        goto error;
    }

    aws_http_stream_release(stream);
    stream = NULL;

    /* Verify handshake response. RFC-6455 Section 1.3 */
    if (ws_bootstrap->response_status != AWS_HTTP_STATUS_SWITCHING_PROTOCOLS) {
        aws_raise_error(AWS_ERROR_HTTP_WEBSOCKET_UPGRADE_FAILURE);
        goto error;
    }

    /* TODO: validate Sec-WebSocket-Accept header */

    /* Upgrade http connection to midchannel handler */

    /* Insert websocket handler into channel */

    /* Finally, invoke setup callback */
    size_t num_headers = aws_array_list_length(&ws_bootstrap->response_headers);
    const struct aws_http_header *header_array = NULL;
    if (num_headers) {
        aws_array_list_get_at_ptr(&ws_bootstrap->response_headers, (void **)&header_array, 0);
    }

    ws_bootstrap->websocket_setup_callback(
        ws_bootstrap->websocket, 0, ws_bootstrap->response_status, header_array, num_headers, ws_bootstrap->user_data);

    /* Clear setup callback so that we know it's been called. */
    ws_bootstrap->websocket_setup_callback = NULL;
    return;

error:
    if (!error_code) {
        error_code = aws_last_error();
    }

    /* Release stream, if we haven't already done so. */
    if (stream) {
        aws_http_stream_release(stream);
    }

    s_ws_bootstrap_cancel_setup_due_to_err(ws_bootstrap, aws_http_stream_get_connection(stream), error_code);
}
