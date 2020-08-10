/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/proxy_impl.h>

#include <aws/common/encoding.h>
#include <aws/common/string.h>
#include <aws/http/private/connection_impl.h>
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
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_name, "Proxy-Authorization");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_basic_prefix, "Basic ");
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

    user_data->original_host = aws_string_new_from_cursor(allocator, &options->host_name);
    if (user_data->original_host == NULL) {
        goto on_error;
    }

    user_data->original_port = options->port;

    user_data->proxy_config = aws_http_proxy_config_new(allocator, options->proxy_options);
    if (user_data->proxy_config == NULL) {
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

/*
 * Adds a proxy authentication header based on the basic authentication mode, rfc7617
 */
static int s_add_basic_proxy_authentication_header(
    struct aws_http_message *request,
    struct aws_http_proxy_user_data *proxy_user_data) {

    struct aws_byte_buf base64_input_value;
    AWS_ZERO_STRUCT(base64_input_value);

    struct aws_byte_buf header_value;
    AWS_ZERO_STRUCT(header_value);

    int result = AWS_OP_ERR;

    if (aws_byte_buf_init(
            &base64_input_value,
            proxy_user_data->allocator,
            proxy_user_data->proxy_config->auth_username.len + proxy_user_data->proxy_config->auth_password.len + 1)) {
        goto done;
    }

    /* First build a buffer with "username:password" in it */
    struct aws_byte_cursor username_cursor = aws_byte_cursor_from_buf(&proxy_user_data->proxy_config->auth_username);
    if (aws_byte_buf_append(&base64_input_value, &username_cursor)) {
        goto done;
    }

    struct aws_byte_cursor colon_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(":");
    if (aws_byte_buf_append(&base64_input_value, &colon_cursor)) {
        goto done;
    }

    struct aws_byte_cursor password_cursor = aws_byte_cursor_from_buf(&proxy_user_data->proxy_config->auth_password);
    if (aws_byte_buf_append(&base64_input_value, &password_cursor)) {
        goto done;
    }

    struct aws_byte_cursor base64_source_cursor =
        aws_byte_cursor_from_array(base64_input_value.buffer, base64_input_value.len);

    /* Figure out how much room we need in our final header value buffer */
    size_t required_size = 0;
    if (aws_base64_compute_encoded_len(base64_source_cursor.len, &required_size)) {
        goto done;
    }

    required_size += s_proxy_authorization_header_basic_prefix->len + 1;
    if (aws_byte_buf_init(&header_value, proxy_user_data->allocator, required_size)) {
        goto done;
    }

    /* Build the final header value by appending the authorization type and the base64 encoding string together */
    struct aws_byte_cursor basic_prefix = aws_byte_cursor_from_string(s_proxy_authorization_header_basic_prefix);
    if (aws_byte_buf_append_dynamic(&header_value, &basic_prefix)) {
        goto done;
    }

    if (aws_base64_encode(&base64_source_cursor, &header_value)) {
        goto done;
    }

    struct aws_http_header header = {.name = aws_byte_cursor_from_string(s_proxy_authorization_header_name),
                                     .value = aws_byte_cursor_from_array(header_value.buffer, header_value.len)};

    if (aws_http_message_add_header(request, header)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_byte_buf_clean_up(&header_value);
    aws_byte_buf_clean_up(&base64_input_value);

    return result;
}

/*
 * Connection callback used ONLY by http proxy connections.  After this,
 * the connection is live and the user is notified
 */
static void s_aws_http_on_client_connection_http_proxy_setup_fn(
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

        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "(%p) Error %d while connecting to \"%s\" via proxy.",
            (void *)connection,
            ec,
            (char *)proxy_ud->original_host->bytes);

        proxy_ud->original_on_setup(NULL, ec, proxy_ud->original_user_data);
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

    aws_http_connection_release(user_data->connection);
    user_data->connection = NULL;
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

    struct aws_http_header host_header = {.name = aws_byte_cursor_from_string(s_host_header_name),
                                          .value = aws_byte_cursor_from_string(user_data->original_host)};
    if (aws_http_message_add_header(request, host_header)) {
        goto on_error;
    }

    struct aws_http_header keep_alive_header = {.name = aws_byte_cursor_from_string(s_proxy_connection_header_name),
                                                .value = aws_byte_cursor_from_string(s_proxy_connection_header_value)};
    if (aws_http_message_add_header(request, keep_alive_header)) {
        goto on_error;
    }

    if (user_data->proxy_config->auth_type == AWS_HPAT_BASIC &&
        s_add_basic_proxy_authentication_header(request, user_data)) {
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

/*
 * Headers done callback for the CONNECT request made during tls proxy connections
 */
static int s_aws_http_on_incoming_header_block_done_tls_proxy(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {

    struct aws_http_proxy_user_data *context = user_data;

    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        int status = 0;
        if (aws_http_stream_get_incoming_response_status(stream, &status) || status != 200) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "(%p) Proxy CONNECT request failed with status code %d",
                (void *)context->connection,
                status);
            context->error_code = AWS_ERROR_HTTP_PROXY_TLS_CONNECT_FAILED;
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

/*
 * Stream done callback for the CONNECT request made during tls proxy connections
 */
static void s_aws_http_on_stream_complete_tls_proxy(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_http_proxy_user_data *context = user_data;
    AWS_FATAL_ASSERT(stream == context->connect_stream);

    if (context->error_code == AWS_ERROR_SUCCESS && error_code != AWS_ERROR_SUCCESS) {
        context->error_code = error_code;
    }

    if (context->error_code != AWS_ERROR_SUCCESS) {
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

    /*
     * Perform TLS negotiation to the origin server through proxy
     */
    context->tls_options->on_negotiation_result = s_on_origin_server_tls_negotation_result;

    context->state = AWS_PBS_TLS_NEGOTIATION;
    struct aws_channel *channel = aws_http_connection_get_channel(context->connection);

    /*
     * TODO: if making secure (double TLS) proxy connection, we need to go after the second slot:
     *
     * Socket -> TLS(proxy) -> TLS(origin server) -> Http
     */
    if (channel == NULL || s_vtable->setup_client_tls(aws_channel_get_first_slot(channel), context->tls_options)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "(%p) Proxy connection failed to start TLS negotiation with error %d(%s)",
            (void *)context->connection,
            aws_last_error(),
            aws_error_str(aws_last_error()));
        s_aws_http_proxy_user_data_shutdown(context);
        return;
    }
}

/*
 * Issues a CONNECT request on a newly-established proxy connection with the intent
 * of upgrading with TLS on success
 */
static int s_make_proxy_connect_request(
    struct aws_http_connection *connection,
    struct aws_http_proxy_user_data *user_data) {
    struct aws_http_message *request = s_build_proxy_connect_request(user_data);
    if (request == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = user_data,
        .on_response_header_block_done = s_aws_http_on_incoming_header_block_done_tls_proxy,
        .on_complete = s_aws_http_on_stream_complete_tls_proxy,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(connection, &request_options);
    if (stream == NULL) {
        goto on_error;
    }

    user_data->connect_stream = stream;
    user_data->connect_request = request;

    aws_http_stream_activate(stream);

    return AWS_OP_SUCCESS;

on_error:

    AWS_LOGF_ERROR(
        AWS_LS_HTTP_CONNECTION,
        "(%p) Proxy connection failed to create request stream for CONNECT request with error %d(%s)",
        (void *)connection,
        aws_last_error(),
        aws_error_str(aws_last_error()));

    aws_http_message_destroy(request);

    return AWS_OP_ERR;
}

/*
 * Connection setup callback for tls-based proxy connections.
 * Could be unified with non-tls version by checking tls options and branching post-success
 */
static void s_aws_http_on_client_connection_http_tls_proxy_setup_fn(
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
    if (s_make_proxy_connect_request(connection, proxy_ud)) {
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

    struct aws_byte_buf auth_header_value;
    AWS_ZERO_STRUCT(auth_header_value);

    int result = AWS_OP_ERR;

    if (proxy_ud->proxy_config->auth_type == AWS_HPAT_BASIC &&
        s_add_basic_proxy_authentication_header(request, proxy_ud)) {
        goto done;
    }

    if (aws_http_rewrite_uri_for_proxy_request(request, proxy_ud)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_byte_buf_clean_up(&auth_header_value);

    return result;
}

/*
 * Top-level function to route a connection request through a proxy server, with no channel security
 */
static int s_aws_http_client_connect_via_proxy_http(const struct aws_http_client_connection_options *options) {
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
    options_copy.on_setup = s_aws_http_on_client_connection_http_proxy_setup_fn;
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

/*
 * Top-level function to route a TLS connection through a proxy server
 */
static int s_aws_http_client_connect_via_proxy_https(const struct aws_http_client_connection_options *options) {

    AWS_FATAL_ASSERT(options->tls_options != NULL);
    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    AWS_LOGF_INFO(
        AWS_LS_HTTP_CONNECTION,
        "(STATIC) Connecting to \"" PRInSTR "\" through TLS via proxy \"" PRInSTR "\"",
        AWS_BYTE_CURSOR_PRI(options->host_name),
        AWS_BYTE_CURSOR_PRI(options->proxy_options->host));

    /* Create a wrapper user data that contains all proxy-related information, state, and user-facing callbacks */
    struct aws_http_proxy_user_data *user_data = aws_http_proxy_user_data_new(options->allocator, options);
    if (user_data == NULL) {
        return AWS_OP_ERR;
    }

    /* Fill in a new connection options pointing at the proxy */
    struct aws_http_client_connection_options options_copy = *options;

    options_copy.proxy_options = NULL;
    options_copy.tls_options = NULL;
    options_copy.host_name = options->proxy_options->host;
    options_copy.port = options->proxy_options->port;
    options_copy.user_data = user_data;
    options_copy.on_setup = s_aws_http_on_client_connection_http_tls_proxy_setup_fn;
    options_copy.on_shutdown = s_aws_http_on_client_connection_http_proxy_shutdown_fn;
    options_copy.tls_options = options->proxy_options->tls_options;

    int result = aws_http_client_connect(&options_copy);
    if (result == AWS_OP_ERR) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "(STATIC) Proxy https connection failed client connect with error %d(%s)",
            aws_last_error(),
            aws_error_str(aws_last_error()));
        aws_http_proxy_user_data_destroy(user_data);
    }

    return result;
}

/*
 * Dispatches a proxy-enabled connection request to the appropriate top-level connection function
 */
int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    if (options->tls_options != NULL) {
        return s_aws_http_client_connect_via_proxy_https(options);
    } else {
        return s_aws_http_client_connect_via_proxy_http(options);
    }
}

struct aws_http_proxy_config *aws_http_proxy_config_new(
    struct aws_allocator *allocator,
    const struct aws_http_proxy_options *options) {
    AWS_FATAL_ASSERT(options != NULL);
    struct aws_http_proxy_config *config = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_config));
    if (config == NULL) {
        return NULL;
    }

    if (aws_byte_buf_init_copy_from_cursor(&config->host, allocator, options->host)) {
        goto on_error;
    }

    if (aws_byte_buf_init_copy_from_cursor(&config->auth_username, allocator, options->auth_username)) {
        goto on_error;
    }

    if (aws_byte_buf_init_copy_from_cursor(&config->auth_password, allocator, options->auth_password)) {
        goto on_error;
    }

    if (options->tls_options) {
        config->tls_options = aws_mem_calloc(allocator, 1, sizeof(struct aws_tls_connection_options));
        if (aws_tls_connection_options_copy(config->tls_options, options->tls_options)) {
            goto on_error;
        }
    }

    config->allocator = allocator;
    config->auth_type = options->auth_type;
    config->port = options->port;

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
    aws_byte_buf_clean_up(&config->auth_username);
    aws_byte_buf_clean_up(&config->auth_password);

    if (config->tls_options) {
        aws_tls_connection_options_clean_up(config->tls_options);
        aws_mem_release(config->allocator, config->tls_options);
    }

    aws_mem_release(config->allocator, config);
}

void aws_http_proxy_options_init_from_config(
    struct aws_http_proxy_options *options,
    const struct aws_http_proxy_config *config) {
    AWS_FATAL_ASSERT(options && config);

    options->host = aws_byte_cursor_from_buf(&config->host);
    options->auth_username = aws_byte_cursor_from_buf(&config->auth_username);
    options->auth_password = aws_byte_cursor_from_buf(&config->auth_password);
    options->auth_type = config->auth_type;
    options->port = config->port;
    options->tls_options = config->tls_options;
}
