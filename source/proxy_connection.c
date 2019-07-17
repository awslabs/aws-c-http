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

