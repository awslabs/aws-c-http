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
#include <aws/io/uri.h>

void aws_http_proxy_user_data_destroy(struct aws_http_proxy_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    aws_string_destroy(user_data->original_host);
    aws_string_destroy(user_data->username);
    aws_string_destroy(user_data->password);

    aws_mem_release(user_data->allocator, user_data);
}

static struct aws_http_proxy_user_data *s_aws_http_proxy_user_data_new(
    struct aws_allocator *allocator,
    const struct aws_http_client_connection_options *options) {
    struct aws_http_proxy_user_data *user_data = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_user_data));
    if (user_data == NULL) {
        return NULL;
    }

    user_data->allocator = allocator;
    user_data->original_host = aws_string_new_from_array(allocator, options->host_name.ptr, options->host_name.len);
    if (user_data->original_host == NULL) {
        goto on_error;
    }

    user_data->original_port = options->port;
    user_data->auth_type = options->proxy_options->auth.type;
    if (user_data->auth_type == AWS_HPAT_BASIC) {
        const struct aws_byte_cursor *user_name = &options->proxy_options->auth.type_options.basic_options.user;
        user_data->username = aws_string_new_from_array(allocator, user_name->ptr, user_name->len);
        if (user_data->username == NULL) {
            goto on_error;
        }

        const struct aws_byte_cursor *password = &options->proxy_options->auth.type_options.basic_options.password;
        user_data->password = aws_string_new_from_array(allocator, password->ptr, password->len);
        if (user_data->password == NULL) {
            goto on_error;
        }
    }

    user_data->original_on_setup = options->on_setup;
    user_data->original_on_shutdown = options->on_shutdown;
    user_data->original_user_data = options->user_data;

    return user_data;

on_error:

    aws_http_proxy_user_data_destroy(user_data);

    return NULL;
}

static void s_aws_http_on_client_connection_http_proxy_setup_fn(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    proxy_ud->original_on_setup(connection, error_code, proxy_ud->original_user_data);

    if (error_code != AWS_ERROR_SUCCESS) {
        aws_http_proxy_user_data_destroy(user_data);
    }
}

static void s_aws_http_on_client_connection_http_proxy_shutdown_fn(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    proxy_ud->original_on_shutdown(connection, error_code, proxy_ud->original_user_data);

    aws_http_proxy_user_data_destroy(user_data);
}

#define DEFAULT_BASIC_AUTH_HEADER_VALUE_SIZE 128

AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_name, "Proxy-Authorization");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_basic_prefix, "Basic ");

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

    size_t required_size = 0;
    if (aws_base64_compute_encoded_len(base64_source_cursor.len, &required_size)) {
        goto done;
    }

    required_size += s_proxy_authorization_header_basic_prefix->len + 1;
    if (aws_byte_buf_init(&header_value, proxy_user_data->allocator, required_size)) {
        goto done;
    }

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

AWS_STATIC_STRING_FROM_LITERAL(s_http_scheme, "http");

static int s_rewrite_uri_for_proxy_request(
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

    struct aws_uri uri;
    if (aws_uri_init_parse(&uri, proxy_user_data->allocator, &path_cursor)) {
        goto done;
    }

    const struct aws_byte_cursor *actual_path_cursor = aws_uri_path(&uri);
    const struct aws_byte_cursor *actual_query_cursor = aws_uri_query_string(&uri);

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

    if (aws_http_message_set_request_path(request, full_target_uri)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_uri_clean_up(&target_uri);
    aws_uri_clean_up(&uri);

    return result;
}

static int s_proxy_http_request_transform(
    struct aws_http_message *request,
    struct aws_allocator *allocator,
    void *user_data) {
    (void)allocator;
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    struct aws_byte_buf auth_header_value;
    AWS_ZERO_STRUCT(auth_header_value);

    int result = AWS_OP_ERR;

    if (proxy_ud->auth_type == AWS_HPAT_BASIC && s_add_basic_proxy_authentication_header(request, proxy_ud)) {
        goto done;
    }

    if (s_rewrite_uri_for_proxy_request(request, proxy_ud)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_byte_buf_clean_up(&auth_header_value);

    return result;
}

static int s_aws_http_client_connect_via_proxy_http(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options->tls_options == NULL);

    struct aws_http_proxy_user_data *proxy_user_data = s_aws_http_proxy_user_data_new(options->allocator, options);
    if (proxy_user_data == NULL) {
        return AWS_OP_ERR;
    }

    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    struct aws_http_client_connection_options options_copy = *options;

    options_copy.proxy_options = NULL;
    options_copy.host_name = options->proxy_options->host;
    options_copy.port = options->proxy_options->port;
    options_copy.request_transform = s_proxy_http_request_transform;
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
    (void)options;

    AWS_FATAL_ASSERT(options->tls_options != NULL);

    /* NYI */

    return AWS_OP_ERR;
}

int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options) {
    AWS_FATAL_ASSERT(options->proxy_options != NULL);

    if (options->tls_options != NULL) {
        return s_aws_http_client_connect_via_proxy_https(options);
    } else {
        return s_aws_http_client_connect_via_proxy_http(options);
    }
}
