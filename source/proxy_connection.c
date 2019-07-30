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

#include <aws/http/private/proxy_impl.h>

#include <aws/common/encoding.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/channel.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

AWS_STATIC_STRING_FROM_LITERAL(s_host_header_name, "Host");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_name, "Proxy-Authorization");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_basic_prefix, "Basic ");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_connection_header_name, "Proxy-Connection");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_connection_header_value, "Keep-Alive");
AWS_STATIC_STRING_FROM_LITERAL(s_user_agent_header_name, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_user_agent_header_value, "aws-c-http");
AWS_STATIC_STRING_FROM_LITERAL(s_options_method, "OPTIONS");
AWS_STATIC_STRING_FROM_LITERAL(s_star_path, "*");

void aws_http_proxy_user_data_destroy(struct aws_http_proxy_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    aws_string_destroy(user_data->original_host);
    aws_string_destroy(user_data->username);
    aws_string_destroy(user_data->password);

    if (user_data->tls_options) {
        aws_tls_connection_options_clean_up(user_data->tls_options);
        aws_mem_release(user_data->allocator, user_data->tls_options);
    }

    aws_mem_release(user_data->allocator, user_data);
}

struct aws_http_proxy_user_data *aws_http_proxy_user_data_new(
    struct aws_allocator *allocator,
    const struct aws_http_client_connection_options *options) {

    struct aws_http_proxy_user_data *user_data = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_user_data));
    if (user_data == NULL) {
        return NULL;
    }

    user_data->allocator = allocator;
    user_data->state = AWS_PBS_SOCKET_CONNECT;
    user_data->error_code = AWS_ERROR_SUCCESS;

    user_data->original_host = aws_string_new_from_array(allocator, options->host_name.ptr, options->host_name.len);
    if (user_data->original_host == NULL) {
        goto on_error;
    }

    user_data->original_port = options->port;
    user_data->auth_type = options->proxy_options->auth_type;
    if (user_data->auth_type == AWS_HPAT_BASIC) {
        const struct aws_byte_cursor *user_name = &options->proxy_options->auth_username;
        user_data->username = aws_string_new_from_array(allocator, user_name->ptr, user_name->len);
        if (user_data->username == NULL) {
            goto on_error;
        }

        const struct aws_byte_cursor *password = &options->proxy_options->auth_password;
        user_data->password = aws_string_new_from_array(allocator, password->ptr, password->len);
        if (user_data->password == NULL) {
            goto on_error;
        }
    }

    if (options->tls_options) {
        user_data->tls_options = aws_mem_calloc(allocator, 1, sizeof(struct aws_tls_connection_options));
        if (aws_tls_connection_options_copy(user_data->tls_options, options->tls_options)) {
            goto on_error;
        }

        user_data->tls_options->user_data = user_data;
    }

    user_data->original_on_setup = options->on_setup;
    user_data->original_on_shutdown = options->on_shutdown;
    user_data->original_user_data = options->user_data;

    return user_data;

on_error:

    aws_http_proxy_user_data_destroy(user_data);

    return NULL;
}

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
            proxy_user_data->username->len + proxy_user_data->password->len + 1)) {
        goto done;
    }

    /* First build a buffer with "username:password" in it */
    struct aws_byte_cursor username_cursor = aws_byte_cursor_from_string(proxy_user_data->username);
    if (aws_byte_buf_append(&base64_input_value, &username_cursor)) {
        goto done;
    }

    struct aws_byte_cursor colon_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(":");
    if (aws_byte_buf_append(&base64_input_value, &colon_cursor)) {
        goto done;
    }

    struct aws_byte_cursor password_cursor = aws_byte_cursor_from_string(proxy_user_data->password);
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

static void s_aws_http_on_client_connection_http_proxy_shutdown_fn(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    struct aws_http_proxy_user_data *proxy_ud = user_data;

    if (proxy_ud->state == AWS_PBS_SUCCESS) {
        proxy_ud->original_on_shutdown(connection, error_code, proxy_ud->original_user_data);
    } else {
        int ec = error_code;
        if (ec == AWS_ERROR_SUCCESS) {
            ec = proxy_ud->error_code;
        }
        if (ec == AWS_ERROR_SUCCESS) {
            ec = AWS_ERROR_UNKNOWN;
        }

        proxy_ud->original_on_setup(NULL, ec, proxy_ud->original_user_data);
    }

    aws_http_proxy_user_data_destroy(user_data);
}

static void s_aws_http_proxy_user_data_shutdown(struct aws_http_proxy_user_data *user_data) {

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

    char port_str[6] = "XXXXXX";
    snprintf(port_str, sizeof(port_str), "%05d", (int)user_data->original_port);
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

    struct aws_http_header user_agent = {.name = aws_byte_cursor_from_string(s_user_agent_header_name),
                                         .value = aws_byte_cursor_from_string(s_user_agent_header_value)};
    if (aws_http_message_add_header(request, user_agent)) {
        goto on_error;
    }

    if (user_data->auth_type == AWS_HPAT_BASIC && s_add_basic_proxy_authentication_header(request, user_data)) {
        goto on_error;
    }

    aws_byte_buf_clean_up(&path_buffer);

    return request;

on_error:

    aws_byte_buf_clean_up(&path_buffer);
    aws_http_message_destroy(request);

    return NULL;
}

static int s_aws_http_on_incoming_header_block_done_tls_proxy(
    struct aws_http_stream *stream,
    bool has_body,
    void *user_data) {

    (void)has_body;

    struct aws_http_proxy_user_data *context = user_data;
    int status = 0;
    if (aws_http_stream_get_incoming_response_status(stream, &status) || status != 200) {
        context->error_code = AWS_ERROR_HTTP_PROXY_TLS_CONNECT_FAILED;
    }

    return AWS_OP_SUCCESS;
}

static void s_on_tls_negotation_result(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int error_code,
    void *user_data) {

    (void)handler;
    (void)slot;

    struct aws_http_proxy_user_data *context = user_data;
    if (error_code != AWS_ERROR_SUCCESS) {
        context->error_code = error_code;
        s_aws_http_proxy_user_data_shutdown(context);
        return;
    }

    context->state = AWS_PBS_SUCCESS;
    context->original_on_setup(context->connection, AWS_ERROR_SUCCESS, context->original_user_data);
}

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

    aws_http_stream_release(stream);
    context->connect_stream = NULL;
    aws_http_message_destroy(context->connect_request);
    context->connect_request = NULL;

    context->tls_options->on_negotiation_result = s_on_tls_negotation_result;

    struct aws_channel *channel = aws_http_connection_get_channel(context->connection);
    if (channel == NULL || aws_channel_setup_client_tls(aws_channel_get_first_slot(channel), context->tls_options)) {
        s_aws_http_proxy_user_data_shutdown(context);
        return;
    }

    context->state = AWS_PBS_TLS_NEGOTIATION;
}

static int s_make_proxy_connect_request(
    struct aws_http_connection *connection,
    struct aws_http_proxy_user_data *user_data) {
    struct aws_http_message *request = s_build_proxy_connect_request(user_data);
    if (request == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);

    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.client_connection = connection;
    request_options.request = request;
    request_options.user_data = user_data;
    request_options.on_response_header_block_done = s_aws_http_on_incoming_header_block_done_tls_proxy;
    request_options.on_complete = s_aws_http_on_stream_complete_tls_proxy;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);
    if (stream == NULL) {
        goto on_error;
    }

    user_data->connect_stream = stream;
    user_data->connect_request = request;

    return AWS_OP_SUCCESS;

on_error:

    aws_http_message_destroy(request);

    return AWS_OP_ERR;
}

static void s_aws_http_on_client_connection_http_tls_proxy_setup_fn(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    struct aws_http_proxy_user_data *proxy_ud = user_data;

    proxy_ud->error_code = error_code;
    if (error_code != AWS_ERROR_SUCCESS) {
        goto on_error;
    }

    proxy_ud->connection = connection;
    if (s_make_proxy_connect_request(connection, proxy_ud)) {
        goto on_error;
    }

    proxy_ud->state = AWS_PBS_HTTP_CONNECT;
    return;

on_error:

    s_aws_http_proxy_user_data_shutdown(proxy_ud);
}

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

AWS_STATIC_STRING_FROM_LITERAL(s_http_scheme, "http");

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

static int s_proxy_http_request_transform(struct aws_http_message *request, void *user_data) {
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    struct aws_byte_buf auth_header_value;
    AWS_ZERO_STRUCT(auth_header_value);

    int result = AWS_OP_ERR;

    if (proxy_ud->auth_type == AWS_HPAT_BASIC && s_add_basic_proxy_authentication_header(request, proxy_ud)) {
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

static int s_aws_http_client_connect_via_proxy_http(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options->tls_options == NULL);

    /* Create a wrapper user data that contains the connection options we'll need to rewrite requests */
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
    options_copy.message_transform = s_proxy_http_request_transform;
    options_copy.user_data = proxy_user_data;
    options_copy.on_setup = s_aws_http_on_client_connection_http_proxy_setup_fn;
    options_copy.on_shutdown = s_aws_http_on_client_connection_http_proxy_shutdown_fn;

    int result = aws_http_client_connect(&options_copy);
    if (result == AWS_OP_ERR) {
        aws_http_proxy_user_data_destroy(proxy_user_data);
    }

    return result;
}

static int s_aws_http_client_connect_via_proxy_https(const struct aws_http_client_connection_options *options) {

    AWS_FATAL_ASSERT(options->tls_options != NULL);
    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    /* Create a wrapper user data that contains the connection options we'll need to rewrite requests */
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

    int result = aws_http_client_connect(&options_copy);
    if (result == AWS_OP_ERR) {
        aws_http_proxy_user_data_destroy(user_data);
    }

    return result;
}

int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    if (options->tls_options != NULL) {
        return s_aws_http_client_connect_via_proxy_https(options);
    } else {
        return s_aws_http_client_connect_via_proxy_http(options);
    }
}
