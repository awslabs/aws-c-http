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

#include <aws/http/proxy_connection.h>

#include <aws/common/string.h>

#ifdef NEVER

#include <aws/http/request_response.h>

enum connection_with_request_state {
    CONNECTING,
    SENDING_REQUEST,
    SUCCESS,
    SHUTTING_DOWN
};

struct aws_connection_with_request_context {

    struct aws_allocator *allocator;

    struct aws_http_request *request;

    void *user_data;

    aws_http_on_client_connection_setup_fn *on_setup;

    aws_http_on_client_connection_shutdown_fn *on_shutdown;

    enum connection_with_request_state state;

    bool shutdown_received;
    bool request_successful;
};

static struct aws_connection_with_request_context *s_aws_connection_with_request_context_new(struct aws_allocator *allocator, const struct aws_http_client_connection_options *options, struct aws_http_request *request)
{
    struct aws_connection_with_request_context *context = aws_mem_acquire(allocator, sizeof(struct aws_connection_with_request_context));
    if (context == NULL)
    {
        return NULL;
    }

    AWS_ZERO_STRUCT(*context);
    context->allocator = allocator;
    context->request = request;
    context->user_data = options->user_data;
    context->on_setup = options->on_setup;
    context->on_shutdown = options->on_shutdown;
    context->state = CONNECTING;
    context->shutdown_received = false;
    context->request_successful = false;

    return context;
}

static void s_aws_connection_with_request_context_destroy(struct aws_connection_with_request_context *context)
{
    if (context == NULL)
    {
        return;
    }

    aws_http_request_destroy(context->request);

    aws_mem_release(context->allocator, context);
}

static void s_aws_http_on_incoming_headers_connect_with_request(
        struct aws_http_stream *stream,
        const struct aws_http_header *header_array,
        size_t num_headers,
        void *user_data)
{
    (void)stream;
    (void)header_array;
    (void)num_headers;
    (void)user_data;
}

static void s_aws_http_on_incoming_header_block_done_connect_with_request(struct aws_http_stream *stream, bool has_body, void *user_data)
{
    (void)has_body;

    struct aws_connection_with_request_context *context = user_data;
    int status = 0;
    if (aws_http_stream_get_incoming_response_status(stream, &status) == AWS_OP_SUCCESS) {
        context->request_successful = status == 200;
    }
}

static void s_aws_http_on_incoming_body_connect_with_request(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data)
{
    (void)stream;
    (void)data;
    (void)user_data;
}

static void s_aws_http_on_stream_complete_connect_with_request(struct aws_http_stream *stream, int error_code, void *user_data)
{
    struct aws_http_connection *connection =  aws_http_stream_get_connection(stream);
    struct aws_connection_with_request_context *context = user_data;
    if (context->request_successful && error_code == AWS_ERROR_SUCCESS)
    {
        context->state = SUCCESS;
        context->on_setup(connection, AWS_ERROR_SUCCESS, context->user_data);
        return;
    }

    context->on_setup(NULL, error_code, context->user_data);
    context->state = SHUTTING_DOWN;

    aws_http_connection_close(connection);
}

static void s_aws_http_on_client_connection_setup_chained_request(struct aws_http_connection *connection, int error_code, void *user_data)
{
    struct aws_connection_with_request_context *context = user_data;

    AWS_FATAL_ASSERT((error_code == AWS_ERROR_SUCCESS) ^ (connection == NULL));

    if (error_code != AWS_ERROR_SUCCESS)
    {
        context->on_setup(NULL, error_code, context->user_data);
        s_aws_connection_with_request_context_destroy(context);
        return;
    }

    context->state = SENDING_REQUEST;

    struct aws_http_request_options request;
    AWS_ZERO_STRUCT(request);
    request.self_size = sizeof(struct aws_http_request_options);
    request.client_connection = connection;
    request.request = context->request;
    request.user_data = user_data;
    request.on_response_headers = s_aws_http_on_incoming_headers_connect_with_request;
    request.on_response_header_block_done = s_aws_http_on_incoming_header_block_done_connect_with_request;
    request.on_response_body = s_aws_http_on_incoming_body_connect_with_request;
    request.on_complete = s_aws_http_on_stream_complete_connect_with_request;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request);
    if (stream == NULL)
    {
        goto on_error;
    }

    return;

    on_error:

    context->on_setup(NULL, aws_last_error(), context->user_data);
    context->state = SHUTTING_DOWN;
    aws_http_connection_close(connection);
}

static void s_aws_http_on_client_connection_shutdown_chained_request(struct aws_http_connection *connection, int error_code, void *user_data)
{
    struct aws_connection_with_request_context *context = user_data;

    context->shutdown_received = true;

    if (context->state == SUCCESS && context->on_shutdown) {
        context->on_shutdown(connection, error_code, context->user_data);
    }

    aws_http_connection_release(connection);
    s_aws_connection_with_request_context_destroy(context);
}

int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options,
                                      struct aws_http_request *request)
{
    struct aws_http_client_connection_options options_copy = *options;
    struct aws_connection_with_request_context *context = s_aws_connection_with_request_context_new(options->allocator, options, request);

    context = aws_mem_acquire(options->allocator, sizeof(struct aws_connection_with_request_context));
    if (context == NULL)
    {
        goto on_error;
    }
    AWS_ZERO_STRUCT(*context);

    context->request = request;
    context->user_data = options->user_data;
    context->on_setup = options->on_setup;
    context->on_shutdown = options->on_shutdown;

    options_copy.user_data = context;
    options_copy.on_setup = s_aws_http_on_client_connection_setup_chained_request;
    options_copy.on_shutdown = s_aws_http_on_client_connection_shutdown_chained_request;

    if (aws_http_client_connect(&options_copy))
    {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:

    aws_mem_release(options->allocator, context);

    return AWS_OP_ERR;
}

#endif // NEVER


struct aws_http_proxy_user_data {
    struct aws_allocator *allocator;

    struct aws_string *host;
    uint16_t port;

    enum aws_http_proxy_authentication_type auth_type;
    struct aws_string *username;
    struct aws_string *password;

    aws_http_on_client_connection_setup_fn *on_setup;
    aws_http_on_client_connection_shutdown_fn *on_shutdown;
    void *user_data;
};

void aws_http_proxy_user_data_destroy(struct aws_http_proxy_user_data *user_data)
{
    if (user_data == NULL) {
        return;
    }

    aws_string_destroy(user_data->host);
    aws_string_destroy(user_data->username);
    aws_string_destroy(user_data->password);
}

struct aws_http_proxy_user_data *aws_http_proxy_user_data_new(struct aws_allocator *allocator,
                                                              const struct aws_http_client_connection_options *options,
                                                              const struct aws_http_proxy_options *proxy_options)
{
    struct aws_http_proxy_user_data *user_data = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_user_data));
    if (user_data == NULL) {
        return NULL;
    }

    user_data->allocator = allocator;
    user_data->host = aws_string_new_from_array(allocator, options->host_name.ptr, options->host_name.len);
    if (user_data->host == NULL) {
        goto on_error;
    }

    user_data->port = options->port;
    user_data->auth_type = proxy_options->auth.type;
    if (user_data->auth_type == AWS_HPAT_BASIC) {
        const struct aws_byte_cursor *user_name = &proxy_options->auth.type_options.basic_options.user;
        user_data->username = aws_string_new_from_array(allocator, user_name->ptr, user_name->len);
        if (user_data->username == NULL) {
            goto on_error;
        }

        const struct aws_byte_cursor *password = &proxy_options->auth.type_options.basic_options.password;
        user_data->password = aws_string_new_from_array(allocator, password->ptr, password->len);
        if (user_data->password == NULL) {
            goto on_error;
        }
    }

    user_data->on_setup = options->on_setup;
    user_data->on_shutdown = options->on_shutdown;
    user_data->user_data = options->user_data;

    return user_data;

on_error:

    aws_http_proxy_user_data_destroy(user_data);

    return NULL;
}


static void s_aws_http_on_client_connection_http_proxy_setup_fn(struct aws_http_connection *connection, int error_code, void *user_data)
{
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    proxy_ud->on_setup(connection, error_code, proxy_ud->user_data);

    if (error_code != AWS_ERROR_SUCCESS) {
        aws_http_proxy_user_data_destroy(user_data);
    }
}

static void s_aws_http_on_client_connection_http_proxy_shutdown_fn(struct aws_http_connection *connection, int error_code, void *user_data)
{
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    proxy_ud->on_shutdown(connection, error_code, proxy_ud->user_data);

    aws_http_proxy_user_data_destroy(user_data);
}

#define DEFAULT_BASIC_AUTH_HEADER_VALUE_SIZE 128

AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_name, "Proxy-Authorization");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_basic_prefix, "Basic ");

static int s_add_basic_proxy_authentication_header(struct aws_http_request *request, struct aws_http_proxy_user_data *proxy_user_data) {
    struct aws_byte_buf header_value;
    AWS_ZERO_STRUCT(header_value);

    if (aws_byte_buf_init(&header_value, proxy_user_data->allocator, DEFAULT_BASIC_AUTH_HEADER_VALUE_SIZE)) {
        return AWS_OP_ERR;
    }

    int result = AWS_OP_ERR;

    struct aws_byte_cursor basic_prefix = aws_byte_cursor_from_string(s_proxy_authorization_header_basic_prefix);
    if (aws_byte_buf_append_dynamic(&header_value, &basic_prefix)) {
        goto done;
    }

    struct aws_http_header header = {
        .name = aws_byte_cursor_from_string(s_proxy_authorization_header_name),
        .value = aws_byte_cursor_from_array(header_value.buffer, header_value.len)
    };

    if (aws_http_request_add_header(request, header)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_byte_buf_clean_up(&header_value);

    return result;
}

static int s_proxy_http_request_transform(struct aws_http_request *request,
                                          void *user_data)
{
    struct aws_http_proxy_user_data *proxy_ud = user_data;

    struct aws_byte_buf auth_header_value;
    AWS_ZERO_STRUCT(auth_header_value);

    int result = AWS_OP_ERR;

    if (proxy_ud->auth_type == AWS_HPAT_BASIC && s_add_basic_proxy_authentication_header(request, proxy_ud)) {
        goto done;
    }

    ??

done:

    aws_byte_buf_clean_up(&auth_header_value);

    return result;
}

static int s_aws_http_client_connect_via_proxy_http(const struct aws_http_client_connection_options *options,
                                      const struct aws_http_proxy_options *proxy_options)
{
    AWS_FATAL_ASSERT(options->tls_options == NULL);

    struct aws_http_proxy_user_data *proxy_user_data = aws_http_proxy_user_data_new(options->allocator, options, proxy_options);
    if (proxy_user_data == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_http_client_connection_options options_copy = *options;

    options_copy.host_name = proxy_options->host;
    options_copy.port = proxy_options->port;
    options_copy.request_transform = s_proxy_http_request_transform;
    options_copy.user_data = proxy_user_data;
    options_copy.on_setup = s_aws_http_on_client_connection_http_proxy_setup_fn;
    options_copy.on_shutdown = s_aws_http_on_client_connection_http_proxy_shutdown_fn;

    return aws_http_client_connect(&options_copy);
}

static int s_aws_http_client_connect_via_proxy_https(const struct aws_http_client_connection_options *options,
                                      const struct aws_http_proxy_options *proxy_options)
{
    (void)options;
    (void)proxy_options;

    AWS_FATAL_ASSERT(options->tls_options != NULL);

    return AWS_OP_ERR;
}

int aws_http_client_connect_via_proxy(const struct aws_http_client_connection_options *options,
                                      const struct aws_http_proxy_options *proxy_options)
{
    if (options->tls_options != NULL) {
        return s_aws_http_client_connect_via_proxy_http(options, proxy_options);
    } else {
        return s_aws_http_client_connect_via_proxy_https(options, proxy_options);
    }
}