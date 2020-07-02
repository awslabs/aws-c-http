/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/logging.h>
#include <aws/http/connection.h>
#include <aws/http/private/http_impl.h>
#include <aws/http/private/websocket_impl.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/uri.h>

#include <inttypes.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

/**
 * Allow unit-tests to mock interactions with external systems.
 */
static const struct aws_websocket_client_bootstrap_system_vtable s_default_system_vtable = {
    .aws_http_client_connect = aws_http_client_connect,
    .aws_http_connection_release = aws_http_connection_release,
    .aws_http_connection_close = aws_http_connection_close,
    .aws_http_connection_get_channel = aws_http_connection_get_channel,
    .aws_http_connection_make_request = aws_http_connection_make_request,
    .aws_http_stream_activate = aws_http_stream_activate,
    .aws_http_stream_release = aws_http_stream_release,
    .aws_http_stream_get_connection = aws_http_stream_get_connection,
    .aws_http_stream_get_incoming_response_status = aws_http_stream_get_incoming_response_status,
    .aws_websocket_handler_new = aws_websocket_handler_new,
};

static const struct aws_websocket_client_bootstrap_system_vtable *s_system_vtable = &s_default_system_vtable;

void aws_websocket_client_bootstrap_set_system_vtable(
    const struct aws_websocket_client_bootstrap_system_vtable *system_vtable) {

    s_system_vtable = system_vtable;
}

/**
 * The websocket bootstrap brings a websocket connection into this world, and sees it out again.
 * Spins up an HTTP client, performs the opening handshake (HTTP Upgrade request),
 * creates the websocket handler, and inserts it into the channel.
 * The bootstrap is responsible for firing the on_connection_setup and on_connection_shutdown callbacks.
 */
struct aws_websocket_client_bootstrap {
    /* Settings copied in from aws_websocket_client_connection_options */
    struct aws_allocator *alloc;
    size_t initial_window_size;
    bool manual_window_update;
    void *user_data;
    /* Setup callback will be set NULL once it's invoked.
     * This is used to determine whether setup or shutdown should be invoked
     * from the HTTP-shutdown callback. */
    aws_websocket_on_connection_setup_fn *websocket_setup_callback;
    aws_websocket_on_connection_shutdown_fn *websocket_shutdown_callback;
    aws_websocket_on_incoming_frame_begin_fn *websocket_frame_begin_callback;
    aws_websocket_on_incoming_frame_payload_fn *websocket_frame_payload_callback;
    aws_websocket_on_incoming_frame_complete_fn *websocket_frame_complete_callback;

    /* Handshake request data */
    struct aws_http_message *handshake_request;

    /* Handshake response data */
    int response_status;
    struct aws_array_list response_headers;
    struct aws_byte_buf response_storage;

    int setup_error_code;
    struct aws_websocket *websocket;
};

static void s_ws_bootstrap_destroy(struct aws_websocket_client_bootstrap *ws_bootstrap);
static void s_ws_bootstrap_cancel_setup_due_to_err(
    struct aws_websocket_client_bootstrap *ws_bootstrap,
    struct aws_http_connection *http_connection,
    int error_code);
static void s_ws_bootstrap_on_http_setup(struct aws_http_connection *http_connection, int error_code, void *user_data);
static void s_ws_bootstrap_on_http_shutdown(
    struct aws_http_connection *http_connection,
    int error_code,
    void *user_data);
static int s_ws_bootstrap_on_handshake_response_headers(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data);
static int s_ws_bootstrap_on_handshake_response_header_block_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data);
static void s_ws_bootstrap_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data);

int aws_websocket_client_connect(const struct aws_websocket_client_connection_options *options) {
    aws_http_fatal_assert_library_initialized();
    AWS_ASSERT(options);

    /* Validate options */
    struct aws_byte_cursor path;
    aws_http_message_get_request_path(options->handshake_request, &path);
    if (!options->allocator || !options->bootstrap || !options->socket_options || !options->host.len || !path.len ||
        !options->on_connection_setup) {

        AWS_LOGF_ERROR(AWS_LS_HTTP_WEBSOCKET_SETUP, "id=static: Missing required websocket connection options.");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_byte_cursor method;
    aws_http_message_get_request_method(options->handshake_request, &method);
    if (aws_http_str_to_method(method) != AWS_HTTP_METHOD_GET) {

        AWS_LOGF_ERROR(AWS_LS_HTTP_WEBSOCKET_SETUP, "id=static: Websocket request must have method be 'GET'.");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    bool all_frame_callbacks_set =
        options->on_incoming_frame_begin && options->on_incoming_frame_payload && options->on_incoming_frame_begin;

    bool no_frame_callbacks_set =
        !options->on_incoming_frame_begin && !options->on_incoming_frame_payload && !options->on_incoming_frame_begin;

    if (!(all_frame_callbacks_set || no_frame_callbacks_set)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Invalid websocket connection options,"
            " either all frame-handling callbacks must be set, or none must be set.");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (!options->handshake_request) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Invalid connection options, missing required request for websocket client handshake.");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Create bootstrap */
    struct aws_websocket_client_bootstrap *ws_bootstrap =
        aws_mem_calloc(options->allocator, 1, sizeof(struct aws_websocket_client_bootstrap));
    if (!ws_bootstrap) {
        goto error;
    }

    ws_bootstrap->alloc = options->allocator;
    ws_bootstrap->initial_window_size = options->initial_window_size;
    ws_bootstrap->manual_window_update = options->manual_window_management;
    ws_bootstrap->user_data = options->user_data;
    ws_bootstrap->websocket_setup_callback = options->on_connection_setup;
    ws_bootstrap->websocket_shutdown_callback = options->on_connection_shutdown;
    ws_bootstrap->websocket_frame_begin_callback = options->on_incoming_frame_begin;
    ws_bootstrap->websocket_frame_payload_callback = options->on_incoming_frame_payload;
    ws_bootstrap->websocket_frame_complete_callback = options->on_incoming_frame_complete;
    ws_bootstrap->handshake_request = options->handshake_request;
    ws_bootstrap->response_status = AWS_HTTP_STATUS_CODE_UNKNOWN;

    /* Pre-allocate space for response headers */
    /* Values are just guesses */
    size_t estimated_response_headers = aws_http_message_get_header_count(ws_bootstrap->handshake_request) + 10;
    size_t estimated_response_header_length = 64;

    int err = aws_array_list_init_dynamic(
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
    http_options.host_name = options->host;
    http_options.socket_options = options->socket_options;
    http_options.tls_options = options->tls_options;
    http_options.proxy_options = options->proxy_options;
    http_options.initial_window_size = 1024; /* Adequate space for response data to trickle in */

    /* TODO: websockets has issues if back-pressure is disabled on the whole channel. This should be fixed. */
    http_options.manual_window_management = true;

    http_options.user_data = ws_bootstrap;
    http_options.on_setup = s_ws_bootstrap_on_http_setup;
    http_options.on_shutdown = s_ws_bootstrap_on_http_shutdown;

    /* Infer port, if not explicitly specified in URI */
    http_options.port = options->port;
    if (!http_options.port) {
        http_options.port = options->tls_options ? 443 : 80;
    }

    err = s_system_vtable->aws_http_client_connect(&http_options);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Websocket failed to initiate HTTP connection, error %d (%s)",
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error_already_logged;
    }

    /* Success! (so far) */
    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET_SETUP,
        "id=%p: Websocket setup begun, connecting to " PRInSTR ":%" PRIu16 PRInSTR,
        (void *)ws_bootstrap,
        AWS_BYTE_CURSOR_PRI(options->host),
        options->port,
        AWS_BYTE_CURSOR_PRI(path));

    return AWS_OP_SUCCESS;

error:
    AWS_LOGF_ERROR(
        AWS_LS_HTTP_WEBSOCKET_SETUP,
        "id=static: Failed to initiate websocket connection, error %d (%s)",
        aws_last_error(),
        aws_error_name(aws_last_error()));

error_already_logged:
    s_ws_bootstrap_destroy(ws_bootstrap);
    return AWS_OP_ERR;
}

static void s_ws_bootstrap_destroy(struct aws_websocket_client_bootstrap *ws_bootstrap) {
    if (!ws_bootstrap) {
        return;
    }

    aws_array_list_clean_up(&ws_bootstrap->response_headers);
    aws_byte_buf_clean_up(&ws_bootstrap->response_storage);

    aws_mem_release(ws_bootstrap->alloc, ws_bootstrap);
}

/* Called if something goes wrong after an HTTP connection is established.
 * The HTTP connection is closed.
 * We must wait for its shutdown to complete before informing user of the failed websocket setup. */
static void s_ws_bootstrap_cancel_setup_due_to_err(
    struct aws_websocket_client_bootstrap *ws_bootstrap,
    struct aws_http_connection *http_connection,
    int error_code) {

    AWS_ASSERT(error_code);
    AWS_ASSERT(http_connection);

    if (!ws_bootstrap->setup_error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=%p: Canceling websocket setup due to error %d (%s).",
            (void *)ws_bootstrap,
            error_code,
            aws_error_name(error_code));

        ws_bootstrap->setup_error_code = error_code;

        s_system_vtable->aws_http_connection_close(http_connection);
    }
}

/* Invoked when HTTP connection has been established (or failed to be established) */
static void s_ws_bootstrap_on_http_setup(struct aws_http_connection *http_connection, int error_code, void *user_data) {

    struct aws_websocket_client_bootstrap *ws_bootstrap = user_data;

    /* Setup callback contract is: if error_code is non-zero then connection is NULL. */
    AWS_FATAL_ASSERT((error_code != 0) == (http_connection == NULL));

    /* If http connection failed, inform the user immediately and clean up the websocket boostrapper. */
    if (error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=%p: Websocket setup failed to establish HTTP connection, error %d (%s).",
            (void *)ws_bootstrap,
            error_code,
            aws_error_name(error_code));

        ws_bootstrap->websocket_setup_callback(
            NULL, error_code, AWS_HTTP_STATUS_CODE_UNKNOWN, NULL, 0, ws_bootstrap->user_data);

        s_ws_bootstrap_destroy(ws_bootstrap);
        return;
    }

    /* Connection exists!
     * Note that if anything goes wrong with websocket setup from hereon out, we must close the http connection
     * first and wait for shutdown to complete before informing the user of setup failure. */

    /* Send the handshake request */
    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = ws_bootstrap->handshake_request,
        .user_data = ws_bootstrap,
        .on_response_headers = s_ws_bootstrap_on_handshake_response_headers,
        .on_response_header_block_done = s_ws_bootstrap_on_handshake_response_header_block_done,
        .on_complete = s_ws_bootstrap_on_stream_complete,
    };

    struct aws_http_stream *handshake_stream =
        s_system_vtable->aws_http_connection_make_request(http_connection, &options);

    if (!handshake_stream || s_system_vtable->aws_http_stream_activate(handshake_stream)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=%p: Failed to initiate websocket upgrade request, error %d (%s).",
            (void *)ws_bootstrap,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    /* Success! (so far) */
    AWS_LOGF_TRACE(
        AWS_LS_HTTP_WEBSOCKET_SETUP,
        "id=%p: HTTP connection established, sending websocket upgrade request.",
        (void *)ws_bootstrap);
    return;

error:
    s_ws_bootstrap_cancel_setup_due_to_err(ws_bootstrap, http_connection, aws_last_error());
}

/* Invoked when the HTTP connection has shut down.
 * This is never called if the HTTP connection failed its setup */
static void s_ws_bootstrap_on_http_shutdown(
    struct aws_http_connection *http_connection,
    int error_code,
    void *user_data) {

    struct aws_websocket_client_bootstrap *ws_bootstrap = user_data;

    /* Inform user that connection has completely shut down.
     * If setup callback still hasn't fired, invoke it now and indicate failure.
     * Otherwise, invoke shutdown callback. */
    if (ws_bootstrap->websocket_setup_callback) {
        AWS_ASSERT(!ws_bootstrap->websocket);

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

        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=%p: Websocket setup failed, error %d (%s).",
            (void *)ws_bootstrap,
            error_code,
            aws_error_name(error_code));

        ws_bootstrap->websocket_setup_callback(
            NULL, error_code, ws_bootstrap->response_status, header_array, num_headers, ws_bootstrap->user_data);

    } else if (ws_bootstrap->websocket_shutdown_callback) {
        AWS_ASSERT(ws_bootstrap->websocket);

        AWS_LOGF_DEBUG(
            AWS_LS_HTTP_WEBSOCKET,
            "id=%p: Websocket client connection shut down with error %d (%s).",
            (void *)ws_bootstrap->websocket,
            error_code,
            aws_error_name(error_code));

        ws_bootstrap->websocket_shutdown_callback(ws_bootstrap->websocket, error_code, ws_bootstrap->user_data);
    }

    /* Clean up HTTP connection and websocket-bootstrap.
     * It's still up to the user to release the websocket itself. */
    s_system_vtable->aws_http_connection_release(http_connection);

    s_ws_bootstrap_destroy(ws_bootstrap);
}

/* Invoked repeatedly as handshake response headers arrive */
static int s_ws_bootstrap_on_handshake_response_headers(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)header_block;

    struct aws_websocket_client_bootstrap *ws_bootstrap = user_data;
    int err;

    /* Deep-copy headers into ws_bootstrap */
    for (size_t i = 0; i < num_headers; ++i) {
        const struct aws_http_header *src_header = &header_array[i];
        struct aws_http_header dst_header;

        dst_header.name.len = src_header->name.len;
        dst_header.name.ptr = ws_bootstrap->response_storage.buffer + ws_bootstrap->response_storage.len;
        err = aws_byte_buf_append_dynamic(&ws_bootstrap->response_storage, &src_header->name);
        if (err) {
            goto error;
        }

        dst_header.value.len = src_header->value.len;
        dst_header.value.ptr = ws_bootstrap->response_storage.buffer + ws_bootstrap->response_storage.len;
        err = aws_byte_buf_append_dynamic(&ws_bootstrap->response_storage, &src_header->value);
        if (err) {
            goto error;
        }

        err = aws_array_list_push_back(&ws_bootstrap->response_headers, &dst_header);
        if (err) {
            goto error;
        }
    }

    return AWS_OP_SUCCESS;
error:
    AWS_LOGF_ERROR(
        AWS_LS_HTTP_WEBSOCKET_SETUP,
        "id=%p: Error while processing response headers, %d (%s)",
        (void *)ws_bootstrap,
        aws_last_error(),
        aws_error_name(aws_last_error()));

    s_ws_bootstrap_cancel_setup_due_to_err(
        ws_bootstrap, s_system_vtable->aws_http_stream_get_connection(stream), aws_last_error());

    return AWS_OP_ERR;
}

/**
 * Invoked each time we reach the end of a block of response headers.
 * If we got a valid 101 Switching Protocols response, we insert the websocket handler.
 * Note:
 *      In HTTP, 1xx responses are "interim" responses. So a 101 Switching Protocols
 *      response does not "complete" the stream. Once the connection has switched
 *      protocols, the stream does not end until the whole connection is closed.
 */
static int s_ws_bootstrap_on_handshake_response_header_block_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {

    (void)header_block;

    struct aws_websocket_client_bootstrap *ws_bootstrap = user_data;
    struct aws_http_connection *http_connection = s_system_vtable->aws_http_stream_get_connection(stream);
    AWS_ASSERT(http_connection);

    /* Get data from stream */
    s_system_vtable->aws_http_stream_get_incoming_response_status(stream, &ws_bootstrap->response_status);

    /* Verify handshake response. RFC-6455 Section 1.3 */
    if (ws_bootstrap->response_status != AWS_HTTP_STATUS_CODE_101_SWITCHING_PROTOCOLS) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=%p: Server refused websocket upgrade, responded with status code %d",
            (void *)ws_bootstrap,
            ws_bootstrap->response_status);

        aws_raise_error(AWS_ERROR_HTTP_WEBSOCKET_UPGRADE_FAILURE);
        goto error;
    }

    /* TODO: validate Sec-WebSocket-Accept header */

    /* Insert websocket handler into channel */
    struct aws_channel *channel = s_system_vtable->aws_http_connection_get_channel(http_connection);
    AWS_ASSERT(channel);

    struct aws_websocket_handler_options ws_options = {
        .allocator = ws_bootstrap->alloc,
        .channel = channel,
        .initial_window_size = ws_bootstrap->initial_window_size,
        .user_data = ws_bootstrap->user_data,
        .on_incoming_frame_begin = ws_bootstrap->websocket_frame_begin_callback,
        .on_incoming_frame_payload = ws_bootstrap->websocket_frame_payload_callback,
        .on_incoming_frame_complete = ws_bootstrap->websocket_frame_complete_callback,
        .is_server = false,
        .manual_window_update = ws_bootstrap->manual_window_update,
    };

    ws_bootstrap->websocket = s_system_vtable->aws_websocket_handler_new(&ws_options);
    if (!ws_bootstrap->websocket) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=%p: Failed to create websocket handler, error %d (%s)",
            (void *)ws_bootstrap,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    /* Success! Setup complete! */
    AWS_LOGF_TRACE(/* Log for tracing setup id to websocket id.  */
                   AWS_LS_HTTP_WEBSOCKET_SETUP,
                   "id=%p: Setup success, created websocket=%p",
                   (void *)ws_bootstrap,
                   (void *)ws_bootstrap->websocket);

    AWS_LOGF_DEBUG(/* Debug log about creation of websocket. */
                   AWS_LS_HTTP_WEBSOCKET,
                   "id=%p: Websocket client connection established.",
                   (void *)ws_bootstrap->websocket);

    size_t num_headers = aws_array_list_length(&ws_bootstrap->response_headers);
    const struct aws_http_header *header_array = NULL;
    if (num_headers) {
        aws_array_list_get_at_ptr(&ws_bootstrap->response_headers, (void **)&header_array, 0);
    }

    ws_bootstrap->websocket_setup_callback(
        ws_bootstrap->websocket, 0, ws_bootstrap->response_status, header_array, num_headers, ws_bootstrap->user_data);

    /* Clear setup callback so that we know that it's been invoked. */
    ws_bootstrap->websocket_setup_callback = NULL;

    return AWS_OP_SUCCESS;

error:
    s_ws_bootstrap_cancel_setup_due_to_err(ws_bootstrap, http_connection, aws_last_error());
    /* Returning error stops HTTP from processing any further data */
    return AWS_OP_ERR;
}

static void s_ws_bootstrap_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    /* Not checking error_code because a stream error ends the HTTP connection.
     * We'll deal with finishing setup and/or shutdown from the http-shutdown callback */
    (void)error_code;
    (void)user_data;

    /* Done with stream, let it be cleaned up */
    s_system_vtable->aws_http_stream_release(stream);
}
