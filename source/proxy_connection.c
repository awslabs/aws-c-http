/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/proxy_impl.h>

#include <aws/common/encoding.h>
#include <aws/common/string.h>
#include <aws/http/connection_manager.h>
#include <aws/http/private/connection_impl.h>
#include <aws/http/proxy.h>
#include <aws/http/request_response.h>
#include <aws/io/channel.h>
#include <aws/io/logging.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#    pragma warning(disable : 4232) /* function pointer to dll symbol */
#endif

AWS_STATIC_STRING_FROM_LITERAL(s_host_header_name, "Host");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_connection_header_name, "Proxy-Connection");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_connection_header_value, "Keep-Alive");
AWS_STATIC_STRING_FROM_LITERAL(s_options_method, "OPTIONS");
AWS_STATIC_STRING_FROM_LITERAL(s_star_path, "*");
AWS_STATIC_STRING_FROM_LITERAL(s_http_scheme, "http");

static struct aws_http_proxy_system_vtable s_default_vtable = {
    .setup_client_tls = &aws_channel_setup_client_tls,
};

static struct aws_http_proxy_system_vtable *s_vtable = &s_default_vtable;

void aws_http_proxy_system_set_vtable(struct aws_http_proxy_system_vtable *vtable) {
    s_vtable = vtable;
}

void aws_http_proxy_user_data_destroy(struct aws_http_proxy_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    aws_string_destroy(user_data->original_host);
    if (user_data->proxy_config) {
        aws_http_proxy_config_destroy(user_data->proxy_config);
    }

    if (user_data->tls_options) {
        aws_tls_connection_options_clean_up(user_data->tls_options);
        aws_mem_release(user_data->allocator, user_data->tls_options);
    }

    aws_http_proxy_negotiator_release(user_data->proxy_negotiator);

    aws_client_bootstrap_release(user_data->bootstrap);

    aws_mem_release(user_data->allocator, user_data);
}

struct aws_http_proxy_user_data *aws_http_proxy_user_data_new(
    struct aws_allocator *allocator,
    const struct aws_http_client_connection_options *options) {

    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    struct aws_http_proxy_user_data *user_data = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_user_data));
    if (user_data == NULL) {
        return NULL;
    }

    user_data->allocator = allocator;
    user_data->state = AWS_PBS_SOCKET_CONNECT;
    user_data->error_code = AWS_ERROR_SUCCESS;
    user_data->connect_status_code = AWS_HTTP_STATUS_CODE_UNKNOWN;
    user_data->bootstrap = aws_client_bootstrap_acquire(options->bootstrap);
    if (options->socket_options != NULL) {
        user_data->socket_options = *options->socket_options;
    }
    user_data->manual_window_management = options->manual_window_management;
    user_data->initial_window_size = options->initial_window_size;

    user_data->original_host = aws_string_new_from_cursor(allocator, &options->host_name);
    if (user_data->original_host == NULL) {
        goto on_error;
    }

    user_data->original_port = options->port;

    user_data->proxy_config = aws_http_proxy_config_new_from_connection_options(allocator, options);
    if (user_data->proxy_config == NULL) {
        goto on_error;
    }

    user_data->proxy_negotiator =
        aws_http_proxy_strategy_create_negotiator(user_data->proxy_config->proxy_strategy, allocator);
    if (user_data->proxy_negotiator == NULL) {
        goto on_error;
    }

    if (options->tls_options) {
        /* clone tls options, but redirect user data to what we're creating */
        user_data->tls_options = aws_mem_calloc(allocator, 1, sizeof(struct aws_tls_connection_options));
        if (user_data->tls_options == NULL ||
            aws_tls_connection_options_copy(user_data->tls_options, options->tls_options)) {
            goto on_error;
        }

        user_data->tls_options->user_data = user_data;
    }

    user_data->original_on_setup = options->on_setup;
    user_data->original_on_shutdown = options->on_shutdown;
    user_data->original_user_data = options->user_data;

    return user_data;

on_error:

    AWS_LOGF_ERROR(
        AWS_LS_HTTP_CONNECTION,
        "(STATIC) Proxy connection failed to create user data with error %d(%s)",
        aws_last_error(),
        aws_error_str(aws_last_error()));

    aws_http_proxy_user_data_destroy(user_data);

    return NULL;
}

struct aws_http_proxy_user_data *aws_http_proxy_user_data_new_reset_clone(
    struct aws_allocator *allocator,
    struct aws_http_proxy_user_data *old_user_data) {

    AWS_FATAL_ASSERT(old_user_data != NULL);

    struct aws_http_proxy_user_data *user_data = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_user_data));
    if (user_data == NULL) {
        return NULL;
    }

    user_data->allocator = allocator;
    user_data->state = AWS_PBS_SOCKET_CONNECT;
    user_data->error_code = AWS_ERROR_SUCCESS;
    user_data->connect_status_code = AWS_HTTP_STATUS_CODE_UNKNOWN;
    user_data->bootstrap = aws_client_bootstrap_acquire(old_user_data->bootstrap);
    user_data->socket_options = old_user_data->socket_options;
    user_data->manual_window_management = old_user_data->manual_window_management;
    user_data->initial_window_size = old_user_data->initial_window_size;

    user_data->original_host = aws_string_new_from_string(allocator, old_user_data->original_host);
    if (user_data->original_host == NULL) {
        goto on_error;
    }

    user_data->original_port = old_user_data->original_port;

    user_data->proxy_config = aws_http_proxy_config_new_clone(allocator, old_user_data->proxy_config);
    if (user_data->proxy_config == NULL) {
        goto on_error;
    }

    user_data->proxy_negotiator = aws_http_proxy_negotiator_acquire(old_user_data->proxy_negotiator);
    if (user_data->proxy_negotiator == NULL) {
        goto on_error;
    }

    if (old_user_data->tls_options) {
        /* clone tls options, but redirect user data to what we're creating */
        user_data->tls_options = aws_mem_calloc(allocator, 1, sizeof(struct aws_tls_connection_options));
        if (user_data->tls_options == NULL ||
            aws_tls_connection_options_copy(user_data->tls_options, old_user_data->tls_options)) {
            goto on_error;
        }

        user_data->tls_options->user_data = user_data;
    }

    user_data->original_on_setup = old_user_data->original_on_setup;
    user_data->original_on_shutdown = old_user_data->original_on_shutdown;
    user_data->original_user_data = old_user_data->original_user_data;

    return user_data;

on_error:

    AWS_LOGF_ERROR(
        AWS_LS_HTTP_CONNECTION,
        "(STATIC) Proxy connection failed to create user data with error %d(%s)",
        aws_last_error(),
        aws_error_str(aws_last_error()));

    aws_http_proxy_user_data_destroy(user_data);

    return NULL;
}

/*
 * Connection callback used ONLY by http proxy connections.  After this,
 * the connection is live and the user is notified
 */
static void s_aws_http_on_client_connection_http_forwarding_proxy_setup_fn(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    proxy_ud->original_on_setup(connection, error_code, proxy_ud->original_user_data);

    if (error_code != AWS_ERROR_SUCCESS) {
        aws_http_proxy_user_data_destroy(user_data);
    } else {
        proxy_ud->state = AWS_PBS_SUCCESS;
    }
}

/*
 * Connection shutdown callback used by both http and https proxy connections.  Only invokes
 * user shutdown if the connection was successfully established.  Otherwise, it invokes
 * the user setup function with an error.
 */
static void s_aws_http_on_client_connection_http_proxy_shutdown_fn(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    struct aws_http_proxy_user_data *proxy_ud = user_data;

    if (proxy_ud->state == AWS_PBS_SUCCESS) {
        AWS_LOGF_INFO(AWS_LS_HTTP_CONNECTION, "(%p) Proxy connection shutting down.", (void *)connection);
        proxy_ud->original_on_shutdown(connection, error_code, proxy_ud->original_user_data);
    } else {
        int ec = error_code;
        if (ec == AWS_ERROR_SUCCESS) {
            ec = proxy_ud->error_code;
        }
        if (ec == AWS_ERROR_SUCCESS) {
            ec = AWS_ERROR_UNKNOWN;
        }

        AWS_LOGF_WARN(
            AWS_LS_HTTP_CONNECTION,
            "(%p) Error %d while connecting to \"%s\" via proxy.",
            (void *)connection,
            ec,
            (char *)proxy_ud->original_host->bytes);

        if (proxy_ud->original_on_setup != NULL) {
            proxy_ud->original_on_setup(NULL, ec, proxy_ud->original_user_data);
        }
    }

    aws_http_proxy_user_data_destroy(user_data);
}

/*
 * On-any-error entry point that releases all resources involved in establishing the proxy connection.
 */
static void s_aws_http_proxy_user_data_shutdown(struct aws_http_proxy_user_data *user_data) {

    user_data->state = AWS_PBS_FAILURE;

    if (user_data->connection == NULL) {
        user_data->original_on_setup(NULL, user_data->error_code, user_data->original_user_data);
        aws_http_proxy_user_data_destroy(user_data);
        return;
    }

    if (user_data->connect_stream) {
        aws_http_stream_release(user_data->connect_stream);
        user_data->connect_stream = NULL;
    }

    if (user_data->connect_request) {
        aws_http_message_destroy(user_data->connect_request);
        user_data->connect_request = NULL;
    }

    struct aws_http_connection *http_connection = user_data->connection;
    user_data->connection = NULL;

    aws_channel_shutdown(http_connection->channel_slot->channel, user_data->error_code);
    aws_http_connection_release(http_connection);
}

/*
 * Builds the CONNECT request issued after proxy connection establishment, during the creation of
 * tls-enabled proxy connections.
 */
static struct aws_http_message *s_build_proxy_connect_request(struct aws_http_proxy_user_data *user_data) {
    struct aws_http_message *request = aws_http_message_new_request(user_data->allocator);
    if (request == NULL) {
        return NULL;
    }

    struct aws_byte_buf path_buffer;
    AWS_ZERO_STRUCT(path_buffer);

    if (aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("CONNECT"))) {
        goto on_error;
    }

    if (aws_byte_buf_init(&path_buffer, user_data->allocator, user_data->original_host->len + 10)) {
        goto on_error;
    }

    struct aws_byte_cursor host_cursor = aws_byte_cursor_from_string(user_data->original_host);
    if (aws_byte_buf_append(&path_buffer, &host_cursor)) {
        goto on_error;
    }

    struct aws_byte_cursor colon_cursor = aws_byte_cursor_from_c_str(":");
    if (aws_byte_buf_append(&path_buffer, &colon_cursor)) {
        goto on_error;
    }

    char port_str[20] = "\0";
    snprintf(port_str, sizeof(port_str), "%d", (int)user_data->original_port);
    struct aws_byte_cursor port_cursor = aws_byte_cursor_from_c_str(port_str);
    if (aws_byte_buf_append(&path_buffer, &port_cursor)) {
        goto on_error;
    }

    struct aws_byte_cursor path_cursor = aws_byte_cursor_from_array(path_buffer.buffer, path_buffer.len);
    if (aws_http_message_set_request_path(request, path_cursor)) {
        goto on_error;
    }

    struct aws_http_header host_header = {
        .name = aws_byte_cursor_from_string(s_host_header_name),
        .value = aws_byte_cursor_from_array(path_buffer.buffer, path_buffer.len),
    };
    if (aws_http_message_add_header(request, host_header)) {
        goto on_error;
    }

    struct aws_http_header keep_alive_header = {
        .name = aws_byte_cursor_from_string(s_proxy_connection_header_name),
        .value = aws_byte_cursor_from_string(s_proxy_connection_header_value),
    };
    if (aws_http_message_add_header(request, keep_alive_header)) {
        goto on_error;
    }

    aws_byte_buf_clean_up(&path_buffer);

    return request;

on_error:

    AWS_LOGF_ERROR(
        AWS_LS_HTTP_CONNECTION,
        "(%p) TLS proxy connection failed to build CONNECT request with error %d(%s)",
        (void *)user_data->connection,
        aws_last_error(),
        aws_error_str(aws_last_error()));

    aws_byte_buf_clean_up(&path_buffer);
    aws_http_message_destroy(request);

    return NULL;
}

static int s_aws_http_on_incoming_body_tunnel_proxy(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {
    (void)stream;

    struct aws_http_proxy_user_data *context = user_data;
    aws_http_proxy_negotiator_connect_on_incoming_body_fn *on_incoming_body =
        context->proxy_negotiator->strategy_vtable.tunnelling_vtable->on_incoming_body_callback;
    if (on_incoming_body != NULL) {
        (*on_incoming_body)(context->proxy_negotiator, data);
    }

    aws_http_stream_update_window(stream, data->len);

    return AWS_OP_SUCCESS;
}

static int s_aws_http_on_response_headers_tunnel_proxy(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)stream;

    struct aws_http_proxy_user_data *context = user_data;
    aws_http_proxy_negotiation_connect_on_incoming_headers_fn *on_incoming_headers =
        context->proxy_negotiator->strategy_vtable.tunnelling_vtable->on_incoming_headers_callback;
    if (on_incoming_headers != NULL) {
        (*on_incoming_headers)(context->proxy_negotiator, header_block, header_array, num_headers);
    }

    return AWS_OP_SUCCESS;
}

/*
 * Headers done callback for the CONNECT request made during tls proxy connections
 */
static int s_aws_http_on_incoming_header_block_done_tunnel_proxy(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {

    struct aws_http_proxy_user_data *context = user_data;

    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        int status_code = AWS_HTTP_STATUS_CODE_UNKNOWN;
        aws_http_stream_get_incoming_response_status(stream, &status_code);
        context->connect_status_code = (enum aws_http_status_code)status_code;
        if (context->connect_status_code != AWS_HTTP_STATUS_CODE_200_OK) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "(%p) Proxy CONNECT request failed with status code %d",
                (void *)context->connection,
                context->connect_status_code);
            context->error_code = AWS_ERROR_HTTP_PROXY_CONNECT_FAILED;
        }

        aws_http_proxy_negotiator_connect_status_fn *on_status =
            context->proxy_negotiator->strategy_vtable.tunnelling_vtable->on_status_callback;
        if (on_status != NULL) {
            (*on_status)(context->proxy_negotiator, context->connect_status_code);
        }
    }

    return AWS_OP_SUCCESS;
}

/*
 * Tls negotiation callback for tls proxy connections
 */
static void s_on_origin_server_tls_negotation_result(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int error_code,
    void *user_data) {

    (void)handler;
    (void)slot;

    struct aws_http_proxy_user_data *context = user_data;
    if (error_code != AWS_ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "(%p) Proxy connection failed origin server TLS negotiation with error %d(%s)",
            (void *)context->connection,
            error_code,
            aws_error_str(error_code));
        context->error_code = error_code;
        s_aws_http_proxy_user_data_shutdown(context);
        return;
    }

    context->state = AWS_PBS_SUCCESS;
    context->original_on_setup(context->connection, AWS_ERROR_SUCCESS, context->original_user_data);
}

static int s_create_tunneling_connection(struct aws_http_proxy_user_data *user_data);
static int s_make_proxy_connect_request(struct aws_http_proxy_user_data *user_data);

/*
 * Stream done callback for the CONNECT request made during tls proxy connections
 */
static void s_aws_http_on_stream_complete_tunnel_proxy(
    struct aws_http_stream *stream,
    int error_code,
    void *user_data) {
    struct aws_http_proxy_user_data *context = user_data;
    AWS_FATAL_ASSERT(stream == context->connect_stream);

    if (context->error_code == AWS_ERROR_SUCCESS && error_code != AWS_ERROR_SUCCESS) {
        context->error_code = error_code;
    }

    if (context->error_code != AWS_ERROR_SUCCESS) {
        context->error_code = AWS_ERROR_HTTP_PROXY_CONNECT_FAILED;
        if (context->connect_status_code == AWS_HTTP_STATUS_CODE_407_PROXY_AUTHENTICATION_REQUIRED) {
            enum aws_http_proxy_negotiation_retry_directive retry_directive =
                aws_http_proxy_negotiator_get_retry_directive(context->proxy_negotiator);

            if (retry_directive == AWS_HPNRD_NEW_CONNECTION) {
                struct aws_http_proxy_user_data *new_context =
                    aws_http_proxy_user_data_new_reset_clone(context->allocator, context);
                if (new_context != NULL && s_create_tunneling_connection(new_context) == AWS_OP_SUCCESS) {
                    /*
                     * We successfully kicked off a new connection.  By NULLing the callbacks on the old one, we can
                     * shut it down quietly without the user being notified.  The new connection will notify the user
                     * based on its success or failure.
                     */
                    context->original_on_shutdown = NULL;
                    context->original_on_setup = NULL;
                    context->error_code = AWS_ERROR_HTTP_PROXY_CONNECT_FAILED_RETRYABLE;
                }
            } else if (retry_directive == AWS_HPNRD_CURRENT_CONNECTION) {
                context->error_code = AWS_ERROR_SUCCESS;
                if (s_make_proxy_connect_request(context) == AWS_OP_SUCCESS) {
                    return;
                }
            }
        }

        s_aws_http_proxy_user_data_shutdown(context);
        return;
    }

    AWS_LOGF_INFO(
        AWS_LS_HTTP_CONNECTION,
        "(%p) Proxy connection made successful CONNECT request to \"%s\" via proxy",
        (void *)context->connection,
        context->original_host->bytes);

    /*
     * We're finished with these, let's release
     */
    aws_http_stream_release(stream);
    context->connect_stream = NULL;
    aws_http_message_destroy(context->connect_request);
    context->connect_request = NULL;

    AWS_LOGF_INFO(AWS_LS_HTTP_CONNECTION, "(%p) Beginning TLS negotiation", (void *)context->connection);

    if (context->tls_options != NULL) {
        /*
         * Perform TLS negotiation to the origin server through proxy
         */
        context->tls_options->on_negotiation_result = s_on_origin_server_tls_negotation_result;

        context->state = AWS_PBS_TLS_NEGOTIATION;
        struct aws_channel *channel = aws_http_connection_get_channel(context->connection);

        struct aws_channel_slot *left_of_tls_slot = aws_channel_get_first_slot(channel);
        if (context->proxy_config->tls_options != NULL) {
            /*
             * If making secure (double TLS) proxy connection, we need to go after the second slot:
             *
             * Socket -> TLS(proxy) -> TLS(origin server) -> Http
             */
            left_of_tls_slot = left_of_tls_slot->adj_right;
        }

        if (s_vtable->setup_client_tls(left_of_tls_slot, context->tls_options)) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "(%p) Proxy connection failed to start TLS negotiation with error %d(%s)",
                (void *)context->connection,
                aws_last_error(),
                aws_error_str(aws_last_error()));
            s_aws_http_proxy_user_data_shutdown(context);
            return;
        }
    } else {
        /*
         * The tunnel has been established.
         */
        context->state = AWS_PBS_SUCCESS;
        context->original_on_setup(context->connection, AWS_ERROR_SUCCESS, context->original_user_data);
    }
}

static void s_terminate_tunneling_connect(
    struct aws_http_message *message,
    int error_code,
    void *internal_proxy_user_data) {
    (void)message;

    struct aws_http_proxy_user_data *proxy_ud = internal_proxy_user_data;

    AWS_LOGF_ERROR(
        AWS_LS_HTTP_CONNECTION,
        "(%p) Tunneling proxy connection failed to create request stream for CONNECT request with error %d(%s)",
        (void *)proxy_ud->connection,
        error_code,
        aws_error_str(error_code));

    proxy_ud->error_code = error_code;
    s_aws_http_proxy_user_data_shutdown(proxy_ud);
}

static void s_continue_tunneling_connect(struct aws_http_message *message, void *internal_proxy_user_data) {
    struct aws_http_proxy_user_data *proxy_ud = internal_proxy_user_data;

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = message,
        .user_data = proxy_ud,
        .on_response_headers = s_aws_http_on_response_headers_tunnel_proxy,
        .on_response_header_block_done = s_aws_http_on_incoming_header_block_done_tunnel_proxy,
        .on_response_body = s_aws_http_on_incoming_body_tunnel_proxy,
        .on_complete = s_aws_http_on_stream_complete_tunnel_proxy,
    };

    if (proxy_ud->connect_stream != NULL) {
        aws_http_stream_release(proxy_ud->connect_stream);
    }

    proxy_ud->connect_stream = aws_http_connection_make_request(proxy_ud->connection, &request_options);
    if (proxy_ud->connect_stream == NULL) {
        goto on_error;
    }

    aws_http_stream_activate(proxy_ud->connect_stream);

    return;

on_error:

    s_aws_http_proxy_user_data_shutdown(proxy_ud);
}

/*
 * Issues a CONNECT request on an http connection
 */
static int s_make_proxy_connect_request(struct aws_http_proxy_user_data *user_data) {
    if (user_data->connect_request != NULL) {
        aws_http_message_destroy(user_data->connect_request);
        user_data->connect_request = NULL;
    }

    user_data->connect_request = s_build_proxy_connect_request(user_data);
    if (user_data->connect_request == NULL) {
        return AWS_OP_ERR;
    }

    (*user_data->proxy_negotiator->strategy_vtable.tunnelling_vtable->connect_request_transform)(
        user_data->proxy_negotiator,
        user_data->connect_request,
        s_terminate_tunneling_connect,
        s_continue_tunneling_connect,
        user_data);

    return AWS_OP_SUCCESS;
}

/*
 * Connection setup callback for tunneling proxy connections.
 */
static void s_aws_http_on_client_connection_http_tunneling_proxy_setup_fn(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    struct aws_http_proxy_user_data *proxy_ud = user_data;

    proxy_ud->error_code = error_code;
    if (error_code != AWS_ERROR_SUCCESS) {
        goto on_error;
    }

    AWS_LOGF_INFO(AWS_LS_HTTP_CONNECTION, "(%p) Making CONNECT request to proxy", (void *)proxy_ud->connection);

    proxy_ud->connection = connection;
    proxy_ud->state = AWS_PBS_HTTP_CONNECT;
    if (s_make_proxy_connect_request(proxy_ud)) {
        goto on_error;
    }

    return;

on_error:

    s_aws_http_proxy_user_data_shutdown(proxy_ud);
}

/*
 * Checks for the special case when a request is an OPTIONS request with *
 * path and no query params
 */
static bool s_is_star_path_options_method(const struct aws_http_message *request) {
    struct aws_byte_cursor method_cursor;
    if (aws_http_message_get_request_method(request, &method_cursor)) {
        return false;
    }

    struct aws_byte_cursor options_cursor = aws_byte_cursor_from_string(s_options_method);
    if (!aws_byte_cursor_eq_ignore_case(&method_cursor, &options_cursor)) {
        return false;
    }

    struct aws_byte_cursor path_cursor;
    if (aws_http_message_get_request_path(request, &path_cursor)) {
        return false;
    }

    struct aws_byte_cursor star_cursor = aws_byte_cursor_from_string(s_star_path);
    if (!aws_byte_cursor_eq_ignore_case(&path_cursor, &star_cursor)) {
        return false;
    }

    return true;
}

/*
 * Modifies a requests uri by transforming it to absolute form according to
 * section 5.3.2 of rfc 7230
 *
 * We do this by parsing the existing uri and then rebuilding it as an
 * absolute resource path (using the original connection options)
 */
int aws_http_rewrite_uri_for_proxy_request(
    struct aws_http_message *request,
    struct aws_http_proxy_user_data *proxy_user_data) {
    int result = AWS_OP_ERR;

    struct aws_uri target_uri;
    AWS_ZERO_STRUCT(target_uri);

    struct aws_byte_cursor path_cursor;
    AWS_ZERO_STRUCT(path_cursor);

    if (aws_http_message_get_request_path(request, &path_cursor)) {
        goto done;
    }

    /* Pull out the original path/query */
    struct aws_uri uri;
    if (aws_uri_init_parse(&uri, proxy_user_data->allocator, &path_cursor)) {
        goto done;
    }

    const struct aws_byte_cursor *actual_path_cursor = aws_uri_path(&uri);
    const struct aws_byte_cursor *actual_query_cursor = aws_uri_query_string(&uri);

    /* now rebuild the uri with scheme, host and port subbed in from the original connection options */
    struct aws_uri_builder_options target_uri_builder;
    AWS_ZERO_STRUCT(target_uri_builder);
    target_uri_builder.scheme = aws_byte_cursor_from_string(s_http_scheme);
    target_uri_builder.path = *actual_path_cursor;
    target_uri_builder.host_name = aws_byte_cursor_from_string(proxy_user_data->original_host);
    target_uri_builder.port = proxy_user_data->original_port;
    target_uri_builder.query_string = *actual_query_cursor;

    if (aws_uri_init_from_builder_options(&target_uri, proxy_user_data->allocator, &target_uri_builder)) {
        goto done;
    }

    struct aws_byte_cursor full_target_uri =
        aws_byte_cursor_from_array(target_uri.uri_str.buffer, target_uri.uri_str.len);

    /*
     * By rfc 7230, Section 5.3.4, a star-pathed options request made through a proxy MUST be transformed (at the last
     * proxy) back into a star-pathed request if the proxy request has an empty path and no query string.  This
     * is behavior we want to support.  So from our side, we need to make sure that star-pathed options requests
     * get translated into options requests with the authority as the uri and an empty path-query.
     *
     * Our URI transform always ends with a '/' which is technically not an empty path. To address this,
     * the easiest thing to do is just detect if this was originally a star-pathed options request
     * and drop the final '/' from the path.
     */
    if (s_is_star_path_options_method(request)) {
        if (full_target_uri.len > 0 && *(full_target_uri.ptr + full_target_uri.len - 1) == '/') {
            full_target_uri.len -= 1;
        }
    }

    /* mutate the request with the new path value */
    if (aws_http_message_set_request_path(request, full_target_uri)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_uri_clean_up(&target_uri);
    aws_uri_clean_up(&uri);

    return result;
}

/*
 * Plaintext proxy request transformation function
 *
 * Rewrites the target uri to absolute form and injects any desired headers
 */
static int s_proxy_http_request_transform(struct aws_http_message *request, void *user_data) {
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    if (aws_http_rewrite_uri_for_proxy_request(request, proxy_ud)) {
        return AWS_OP_ERR;
    }

    if ((*proxy_ud->proxy_negotiator->strategy_vtable.forwarding_vtable->forward_request_transform)(
            proxy_ud->proxy_negotiator, request)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * Top-level function to route a connection request through a proxy server, with no channel security
 */
static int s_aws_http_client_connect_via_forwarding_proxy(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options->tls_options == NULL);

    AWS_LOGF_INFO(
        AWS_LS_HTTP_CONNECTION,
        "(STATIC) Connecting to \"" PRInSTR "\" via proxy \"" PRInSTR "\"",
        AWS_BYTE_CURSOR_PRI(options->host_name),
        AWS_BYTE_CURSOR_PRI(options->proxy_options->host));

    /* Create a wrapper user data that contains all proxy-related information, state, and user-facing callbacks */
    struct aws_http_proxy_user_data *proxy_user_data = aws_http_proxy_user_data_new(options->allocator, options);
    if (proxy_user_data == NULL) {
        return AWS_OP_ERR;
    }

    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    /* Fill in a new connection options pointing at the proxy */
    struct aws_http_client_connection_options options_copy = *options;

    options_copy.proxy_options = NULL;
    options_copy.host_name = options->proxy_options->host;
    options_copy.port = options->proxy_options->port;
    options_copy.user_data = proxy_user_data;
    options_copy.on_setup = s_aws_http_on_client_connection_http_forwarding_proxy_setup_fn;
    options_copy.on_shutdown = s_aws_http_on_client_connection_http_proxy_shutdown_fn;
    options_copy.tls_options = options->proxy_options->tls_options;

    int result = aws_http_client_connect_internal(&options_copy, s_proxy_http_request_transform);
    if (result == AWS_OP_ERR) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "(STATIC) Proxy http connection failed client connect with error %d(%s)",
            aws_last_error(),
            aws_error_str(aws_last_error()));

        aws_http_proxy_user_data_destroy(proxy_user_data);
    }

    return result;
}

static int s_create_tunneling_connection(struct aws_http_proxy_user_data *user_data) {
    struct aws_http_client_connection_options connect_options;
    AWS_ZERO_STRUCT(connect_options);

    connect_options.self_size = sizeof(struct aws_http_client_connection_options);
    connect_options.allocator = user_data->allocator;
    connect_options.bootstrap = user_data->bootstrap;
    connect_options.host_name = aws_byte_cursor_from_buf(&user_data->proxy_config->host);
    connect_options.port = user_data->proxy_config->port;
    connect_options.socket_options = &user_data->socket_options;
    connect_options.tls_options = user_data->proxy_config->tls_options;
    connect_options.monitoring_options = NULL; /* ToDo */
    connect_options.manual_window_management = user_data->manual_window_management;
    connect_options.initial_window_size = user_data->initial_window_size;
    connect_options.user_data = user_data;
    connect_options.on_setup = s_aws_http_on_client_connection_http_tunneling_proxy_setup_fn;
    connect_options.on_shutdown = s_aws_http_on_client_connection_http_proxy_shutdown_fn;
    connect_options.http1_options = NULL; /* ToDo */
    connect_options.http2_options = NULL; /* ToDo */

    int result = aws_http_client_connect(&connect_options);
    if (result == AWS_OP_ERR) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "(STATIC) Proxy tunnel connection failed client connect with error %d(%s)",
            aws_last_error(),
            aws_error_str(aws_last_error()));
        aws_http_proxy_user_data_destroy(user_data);
    }

    return result;
}

/*
 * Top-level function to route a connection through a proxy server via a CONNECT request
 */
static int s_aws_http_client_connect_via_tunneling_proxy(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    AWS_LOGF_INFO(
        AWS_LS_HTTP_CONNECTION,
        "(STATIC) Connecting to \"" PRInSTR "\" through a tunnel via proxy \"" PRInSTR "\"",
        AWS_BYTE_CURSOR_PRI(options->host_name),
        AWS_BYTE_CURSOR_PRI(options->proxy_options->host));

    /* Create a wrapper user data that contains all proxy-related information, state, and user-facing callbacks */
    struct aws_http_proxy_user_data *user_data = aws_http_proxy_user_data_new(options->allocator, options);
    if (user_data == NULL) {
        return AWS_OP_ERR;
    }

    return s_create_tunneling_connection(user_data);
}

static enum aws_http_proxy_connection_type s_determine_proxy_connection_type(
    enum aws_http_proxy_connection_type proxy_connection_type,
    const struct aws_tls_connection_options *tls_options) {
    if (proxy_connection_type != AWS_HPCT_HTTP_LEGACY) {
        return proxy_connection_type;
    }

    if (tls_options != NULL) {
        return AWS_HPCT_HTTP_TUNNEL;
    } else {
        return AWS_HPCT_HTTP_FORWARD;
    }
}

/*
 * Dispatches a proxy-enabled connection request to the appropriate top-level connection function
 */
int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options) {
    if (aws_http_options_validate_proxy_configuration(options)) {
        return AWS_OP_ERR;
    }

    enum aws_http_proxy_connection_type proxy_connection_type =
        s_determine_proxy_connection_type(options->proxy_options->connection_type, options->tls_options);

    switch (proxy_connection_type) {
        case AWS_HPCT_HTTP_FORWARD:
            return s_aws_http_client_connect_via_forwarding_proxy(options);

        case AWS_HPCT_HTTP_TUNNEL:
            return s_aws_http_client_connect_via_tunneling_proxy(options);

        default:
            return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
    }
}

static struct aws_http_proxy_config *s_aws_http_proxy_config_new(
    struct aws_allocator *allocator,
    const struct aws_http_proxy_options *proxy_options,
    enum aws_http_proxy_connection_type override_proxy_connection_type) {
    AWS_FATAL_ASSERT(proxy_options != NULL);

    struct aws_http_proxy_config *config = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_config));
    if (config == NULL) {
        return NULL;
    }

    config->connection_type = override_proxy_connection_type;

    if (aws_byte_buf_init_copy_from_cursor(&config->host, allocator, proxy_options->host)) {

        goto on_error;
    }

    if (proxy_options->tls_options) {
        config->tls_options = aws_mem_calloc(allocator, 1, sizeof(struct aws_tls_connection_options));
        if (aws_tls_connection_options_copy(config->tls_options, proxy_options->tls_options)) {
            goto on_error;
        }
    }

    config->allocator = allocator;
    config->port = proxy_options->port;

    if (proxy_options->proxy_strategy != NULL) {
        config->proxy_strategy = aws_http_proxy_strategy_acquire(proxy_options->proxy_strategy);
    } else if (proxy_options->auth_type == AWS_HPAT_BASIC) {
        struct aws_http_proxy_strategy_basic_auth_options basic_config;
        AWS_ZERO_STRUCT(basic_config);

        basic_config.proxy_connection_type = override_proxy_connection_type;
        basic_config.user_name = proxy_options->auth_username;
        basic_config.password = proxy_options->auth_password;

        config->proxy_strategy = aws_http_proxy_strategy_new_basic_auth(allocator, &basic_config);
    }

    if (config->proxy_strategy == NULL) {
        switch (override_proxy_connection_type) {
            case AWS_HPCT_HTTP_FORWARD:
                config->proxy_strategy = aws_http_proxy_strategy_new_forwarding_identity(allocator);
                break;

            case AWS_HPCT_HTTP_TUNNEL:
                config->proxy_strategy = aws_http_proxy_strategy_new_tunneling_one_time_identity(allocator);
                break;

            default:
                break;
        }

        if (config->proxy_strategy == NULL) {
            goto on_error;
        }
    }

    return config;

on_error:

    aws_http_proxy_config_destroy(config);

    return NULL;
}

struct aws_http_proxy_config *aws_http_proxy_config_new_from_connection_options(
    struct aws_allocator *allocator,
    const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options != NULL);
    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    return s_aws_http_proxy_config_new(
        allocator,
        options->proxy_options,
        s_determine_proxy_connection_type(options->proxy_options->connection_type, options->tls_options));
}

struct aws_http_proxy_config *aws_http_proxy_config_new_from_manager_options(
    struct aws_allocator *allocator,
    const struct aws_http_connection_manager_options *options) {
    AWS_FATAL_ASSERT(options != NULL);
    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    return s_aws_http_proxy_config_new(
        allocator,
        options->proxy_options,
        s_determine_proxy_connection_type(options->proxy_options->connection_type, options->tls_connection_options));
}

struct aws_http_proxy_config *aws_http_proxy_config_new_tunneling_from_proxy_options(
    struct aws_allocator *allocator,
    const struct aws_http_proxy_options *proxy_options) {

    return s_aws_http_proxy_config_new(allocator, proxy_options, AWS_HPCT_HTTP_TUNNEL);
}

struct aws_http_proxy_config *aws_http_proxy_config_new_clone(
    struct aws_allocator *allocator,
    const struct aws_http_proxy_config *proxy_config) {

    AWS_FATAL_ASSERT(proxy_config != NULL);

    struct aws_http_proxy_config *config = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_config));
    if (config == NULL) {
        return NULL;
    }

    config->connection_type = proxy_config->connection_type;

    if (aws_byte_buf_init_copy_from_cursor(&config->host, allocator, aws_byte_cursor_from_buf(&proxy_config->host))) {
        goto on_error;
    }

    if (proxy_config->tls_options) {
        config->tls_options = aws_mem_calloc(allocator, 1, sizeof(struct aws_tls_connection_options));
        if (aws_tls_connection_options_copy(config->tls_options, proxy_config->tls_options)) {
            goto on_error;
        }
    }

    config->allocator = allocator;
    config->port = proxy_config->port;
    config->proxy_strategy = aws_http_proxy_strategy_acquire(proxy_config->proxy_strategy);

    return config;

on_error:

    aws_http_proxy_config_destroy(config);

    return NULL;
}

void aws_http_proxy_config_destroy(struct aws_http_proxy_config *config) {
    if (config == NULL) {
        return;
    }

    aws_byte_buf_clean_up(&config->host);

    if (config->tls_options) {
        aws_tls_connection_options_clean_up(config->tls_options);
        aws_mem_release(config->allocator, config->tls_options);
    }

    aws_http_proxy_strategy_release(config->proxy_strategy);

    aws_mem_release(config->allocator, config);
}

void aws_http_proxy_options_init_from_config(
    struct aws_http_proxy_options *options,
    const struct aws_http_proxy_config *config) {
    AWS_FATAL_ASSERT(options && config);

    options->connection_type = config->connection_type;
    options->host = aws_byte_cursor_from_buf(&config->host);
    options->port = config->port;
    options->tls_options = config->tls_options;
    options->proxy_strategy = config->proxy_strategy;
}

int aws_http_options_validate_proxy_configuration(const struct aws_http_client_connection_options *options) {
    if (options == NULL || options->proxy_options == NULL) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    enum aws_http_proxy_connection_type proxy_type = options->proxy_options->connection_type;
    if (proxy_type == AWS_HPCT_HTTP_FORWARD && options->tls_options != NULL) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    struct aws_http_proxy_strategy *proxy_strategy = options->proxy_options->proxy_strategy;
    if (proxy_strategy != NULL) {
        if (proxy_strategy->proxy_connection_type != proxy_type) {
            return aws_raise_error(AWS_ERROR_INVALID_STATE);
        }
    }

    return AWS_OP_SUCCESS;
}
