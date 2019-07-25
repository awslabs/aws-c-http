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

#include <aws/http/connection.h>
#include <aws/http/server.h>

#include <aws/io/logging.h>

#include <aws/testing/aws_test_harness.h>

#include "proxy_test_helper.h"

#ifdef NEVER

static int s_aws_http_on_incoming_headers_test(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)stream;
    (void)user_data;

    for (size_t i = 0; i < num_headers; ++i) {
        const struct aws_byte_cursor *name = &header_array[i].name;
        const struct aws_byte_cursor *value = &header_array[i].value;
        AWS_LOGF_INFO(
            AWS_LS_HTTP_GENERAL, "< " PRInSTR " : " PRInSTR, AWS_BYTE_CURSOR_PRI(*name), AWS_BYTE_CURSOR_PRI(*value));
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_http_on_incoming_header_block_done_test(
    struct aws_http_stream *stream,
    bool has_body,
    void *user_data) {
    (void)has_body;

    struct proxy_tester *context = user_data;
    int status = 0;
    if (aws_http_stream_get_incoming_response_status(stream, &status) == AWS_OP_SUCCESS) {
        context->request_successful = status == 200;
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_http_on_incoming_body_test(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {
    (void)stream;
    (void)user_data;

    AWS_LOGF_INFO(AWS_LS_HTTP_GENERAL, "< " PRInSTR, AWS_BYTE_CURSOR_PRI(*data));

    return AWS_OP_SUCCESS;
}

static void s_aws_http_on_stream_complete_test(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct tester *context = user_data;

    aws_mutex_lock(&context->wait_lock);
    context->request_complete = true;
    aws_mutex_unlock(&context->wait_lock);
    aws_condition_variable_notify_one(&context->wait_cvar);
}

static bool s_tester_request_complete_pred_fn(void *user_data) {
    struct tester *tester = user_data;
    return tester->request_complete || tester->client_connection_is_shutdown;
}

static bool s_tester_tls_complete_pred_fn(void *user_data) {
    struct tester *tester = user_data;
    return tester->tls_finished || tester->client_connection_is_shutdown;
}

static void s_tester_on_tls_negotiation_result(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err_code,
    void *user_data) {

    /* if an error occurred, the user callback will be delivered in shutdown */
    if (err_code) {
        aws_channel_shutdown(slot->channel, err_code);
    }

    size_t window = aws_channel_slot_downstream_read_window(slot);
    aws_channel_slot_increment_read_window(slot, window);

    struct tester *tester = user_data;
    aws_mutex_lock(&tester->wait_lock);
    tester->tls_finished = true;
    tester->tls_successful = err_code == AWS_ERROR_SUCCESS;
    aws_mutex_unlock(&tester->wait_lock);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static int s_test_proxy_connection_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct tester_options options = {.alloc = allocator, .host = aws_byte_cursor_from_c_str("127.0.0.1"), .port = 8080};

    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    aws_tls_init_static_state(tester.alloc);

    aws_tls_ctx_options_init_default_client(&tester.tls_ctx_options, tester.alloc);
    aws_tls_ctx_options_set_alpn_list(&tester.tls_ctx_options, "http/1.1");

    tester.tls_ctx = aws_tls_client_ctx_new(tester.alloc, &tester.tls_ctx_options);

    aws_tls_connection_options_init_from_ctx(&tester.tls_connection_options, tester.tls_ctx);

    struct aws_byte_cursor tls_host = aws_byte_cursor_from_c_str("www.amazon.com");
    aws_tls_connection_options_set_server_name(&tester.tls_connection_options, tester.alloc, &tls_host);

    struct aws_http_request *request = aws_http_request_new(allocator);
    aws_http_request_set_method(request, aws_byte_cursor_from_c_str("CONNECT"));
    aws_http_request_set_path(request, aws_byte_cursor_from_c_str("www.amazon.com:443"));

    struct aws_http_header host = {.name = aws_byte_cursor_from_c_str("Host"),
                                   .value = aws_byte_cursor_from_c_str("www.amazon.com")};
    aws_http_request_add_header(request, host);

    struct aws_http_header keep_alive = {.name = aws_byte_cursor_from_c_str("Proxy-Connection"),
                                         .value = aws_byte_cursor_from_c_str("Keep-Alive")};
    aws_http_request_add_header(request, keep_alive);

    struct aws_http_header auth = {.name = aws_byte_cursor_from_c_str("Proxy-Authorization"),
                                   .value = aws_byte_cursor_from_c_str("Basic ZGVycDpkZXJw")};
    aws_http_request_add_header(request, auth);

    struct aws_http_header accept = {.name = aws_byte_cursor_from_c_str("Accept"),
                                     .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_request_add_header(request, accept);

    struct aws_http_header user_agent = {.name = aws_byte_cursor_from_c_str("User-Agent"),
                                         .value = aws_byte_cursor_from_c_str("derp")};
    aws_http_request_add_header(request, user_agent);

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.client_connection = tester.client_connection;
    request_options.request = request;
    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.user_data = &tester;
    request_options.on_response_headers = s_aws_http_on_incoming_headers_test;
    request_options.on_response_header_block_done = s_aws_http_on_incoming_header_block_done_test;
    request_options.on_response_body = s_aws_http_on_incoming_body_test;
    request_options.on_complete = s_aws_http_on_stream_complete_test;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);
    (void)stream;

    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_request_complete_pred_fn));

    tester.tls_connection_options.on_negotiation_result = s_tester_on_tls_negotiation_result;
    tester.tls_connection_options.user_data = &tester;

    struct aws_channel *channel = aws_http_connection_get_channel(tester.client_connection);
    aws_setup_client_tls(tester.client_bootstrap, &tester.tls_connection_options, channel);

    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_tls_complete_pred_fn));

    aws_http_stream_release(stream);

    aws_http_request_destroy(request);

    aws_mutex_lock(&tester.wait_lock);
    tester.request_complete = false;
    tester.request_successful = false;
    aws_mutex_unlock(&tester.wait_lock);

    struct aws_http_request *get_request = aws_http_request_new(allocator);
    aws_http_request_set_method(get_request, aws_byte_cursor_from_c_str("GET"));
    aws_http_request_set_path(get_request, aws_byte_cursor_from_c_str("/"));

    struct aws_http_header get_host_header = {.name = aws_byte_cursor_from_c_str("Host"),
                                              .value = aws_byte_cursor_from_c_str("www.amazon.com")};
    aws_http_request_add_header(get_request, get_host_header);

    struct aws_http_header get_accept_header = {.name = aws_byte_cursor_from_c_str("Accept"),
                                                .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_request_add_header(get_request, get_accept_header);

    struct aws_http_header get_user_agent_header = {.name = aws_byte_cursor_from_c_str("User-Agent"),
                                                    .value = aws_byte_cursor_from_c_str("derp")};
    aws_http_request_add_header(get_request, get_user_agent_header);

    struct aws_http_request_options get_request_options;
    AWS_ZERO_STRUCT(get_request_options);
    get_request_options.client_connection = tester.client_connection;
    get_request_options.request = get_request;
    get_request_options.self_size = sizeof(struct aws_http_request_options);
    get_request_options.user_data = &tester;
    get_request_options.on_response_headers = s_aws_http_on_incoming_headers_test;
    get_request_options.on_response_header_block_done = s_aws_http_on_incoming_header_block_done_test;
    get_request_options.on_response_body = s_aws_http_on_incoming_body_test;
    get_request_options.on_complete = s_aws_http_on_stream_complete_test;

    stream = aws_http_stream_new_client_request(&get_request_options);
    (void)stream;

    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_request_complete_pred_fn));

    aws_http_stream_release(stream);

    aws_http_request_destroy(get_request);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_proxy_connection_setup_shutdown, s_test_proxy_connection_setup_shutdown);

static int s_test_https(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct tester_options options = {
        .alloc = allocator, .host = aws_byte_cursor_from_c_str("www.amazon.com"), .port = 443, .use_tls = true};
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    struct aws_http_request *request = aws_http_request_new(allocator);
    aws_http_request_set_method(request, aws_byte_cursor_from_c_str("GET"));
    aws_http_request_set_path(request, aws_byte_cursor_from_c_str("/"));

    struct aws_http_header host = {.name = aws_byte_cursor_from_c_str("Host"),
                                   .value = aws_byte_cursor_from_c_str("www.amazon.com")};
    aws_http_request_add_header(request, host);

    struct aws_http_header accept = {.name = aws_byte_cursor_from_c_str("Accept"),
                                     .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_request_add_header(request, accept);

    struct aws_http_header user_agent = {.name = aws_byte_cursor_from_c_str("User-Agent"),
                                         .value = aws_byte_cursor_from_c_str("derp")};
    aws_http_request_add_header(request, user_agent);

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.client_connection = tester.client_connection;
    request_options.request = request;
    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.user_data = &tester;
    request_options.on_response_headers = s_aws_http_on_incoming_headers_test;
    request_options.on_response_header_block_done = s_aws_http_on_incoming_header_block_done_test;
    request_options.on_response_body = s_aws_http_on_incoming_body_test;
    request_options.on_complete = s_aws_http_on_stream_complete_test;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);
    (void)stream;

    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_request_complete_pred_fn));

    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    aws_http_request_destroy(request);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_https, s_test_https);

static int s_aws_http_on_incoming_headers_proxy_test(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)stream;
    (void)user_data;

    for (size_t i = 0; i < num_headers; ++i) {
        const struct aws_byte_cursor *name = &header_array[i].name;
        const struct aws_byte_cursor *value = &header_array[i].value;
        AWS_LOGF_INFO(
            AWS_LS_HTTP_GENERAL, "< " PRInSTR " : " PRInSTR, AWS_BYTE_CURSOR_PRI(*name), AWS_BYTE_CURSOR_PRI(*value));
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_http_on_incoming_header_block_done_proxy_test(
    struct aws_http_stream *stream,
    bool has_body,
    void *user_data) {
    (void)has_body;

    struct proxy_tester *context = user_data;
    int status = 0;
    if (aws_http_stream_get_incoming_response_status(stream, &status) == AWS_OP_SUCCESS) {
        aws_mutex_lock(&context->wait_lock);
        context->request_successful = status == 200;
        aws_mutex_unlock(&context->wait_lock);
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_http_on_incoming_body_proxy_test(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {
    (void)stream;
    (void)user_data;

    AWS_LOGF_INFO(AWS_LS_HTTP_GENERAL, "< " PRInSTR, AWS_BYTE_CURSOR_PRI(*data));

    return AWS_OP_SUCCESS;
}

static void s_aws_http_on_stream_complete_proxy_test(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct proxy_tester *context = user_data;

    aws_mutex_lock(&context->wait_lock);
    context->request_complete = true;
    aws_mutex_unlock(&context->wait_lock);
    aws_condition_variable_notify_one(&context->wait_cvar);
}

static bool s_proxy_tester_request_complete_pred_fn(void *user_data) {
    struct proxy_tester *tester = user_data;
    return tester->request_complete || tester->client_connection_is_shutdown;
}

static int s_test_http_proxy_connection_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_http_proxy_options proxy_options = {.host = aws_byte_cursor_from_c_str("127.0.0.1"), .port = 8080};

    struct proxy_tester_options options = {.alloc = allocator,
                                           .proxy_options = proxy_options,
                                           .host = aws_byte_cursor_from_c_str("www.google.com"),
                                           .port = 80};
    struct proxy_tester tester;
    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_new_destroy, s_test_http_proxy_connection_new_destroy);

static int s_test_http_proxy_connection_get(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_http_proxy_options proxy_options = {.host = aws_byte_cursor_from_c_str("127.0.0.1"), .port = 8080};

    struct proxy_tester_options options = {.alloc = allocator,
                                           .proxy_options = proxy_options,
                                           .host = aws_byte_cursor_from_c_str("www.amazon.com"),
                                           .port = 80};
    struct proxy_tester tester;
    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    struct aws_http_request *request = aws_http_request_new(allocator);
    aws_http_request_set_method(request, aws_byte_cursor_from_c_str("GET"));
    aws_http_request_set_path(request, aws_byte_cursor_from_c_str("/"));

    struct aws_http_header host = {.name = aws_byte_cursor_from_c_str("Host"),
                                   .value = aws_byte_cursor_from_c_str("www.amazon.com")};
    aws_http_request_add_header(request, host);

    struct aws_http_header accept = {.name = aws_byte_cursor_from_c_str("Accept"),
                                     .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_request_add_header(request, accept);

    struct aws_http_header user_agent = {.name = aws_byte_cursor_from_c_str("User-Agent"),
                                         .value = aws_byte_cursor_from_c_str("derp")};
    aws_http_request_add_header(request, user_agent);

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.client_connection = tester.client_connection;
    request_options.request = request;
    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.user_data = &tester;
    request_options.on_response_headers = s_aws_http_on_incoming_headers_proxy_test;
    request_options.on_response_header_block_done = s_aws_http_on_incoming_header_block_done_proxy_test;
    request_options.on_response_body = s_aws_http_on_incoming_body_proxy_test;
    request_options.on_complete = s_aws_http_on_stream_complete_proxy_test;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);
    (void)stream;

    ASSERT_SUCCESS(proxy_tester_wait(&tester, s_proxy_tester_request_complete_pred_fn));

    aws_http_stream_release(stream);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    aws_http_request_destroy(request);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_get, s_test_http_proxy_connection_get);
#endif // NEVER

#ifdef NEVER

#    include <aws/http/request_response.h>

enum connection_with_request_state { CONNECTING, SENDING_REQUEST, SUCCESS, SHUTTING_DOWN };

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

static struct aws_connection_with_request_context *s_aws_connection_with_request_context_new(
    struct aws_allocator *allocator,
    const struct aws_http_client_connection_options *options,
    struct aws_http_request *request) {
    struct aws_connection_with_request_context *context =
        aws_mem_acquire(allocator, sizeof(struct aws_connection_with_request_context));
    if (context == NULL) {
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

static void s_aws_connection_with_request_context_destroy(struct aws_connection_with_request_context *context) {
    if (context == NULL) {
        return;
    }

    aws_http_request_destroy(context->request);

    aws_mem_release(context->allocator, context);
}

static void s_aws_http_on_incoming_headers_connect_with_request(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)stream;
    (void)header_array;
    (void)num_headers;
    (void)user_data;
}

static void s_aws_http_on_incoming_header_block_done_connect_with_request(
    struct aws_http_stream *stream,
    bool has_body,
    void *user_data) {
    (void)has_body;

    struct aws_connection_with_request_context *context = user_data;
    int status = 0;
    if (aws_http_stream_get_incoming_response_status(stream, &status) == AWS_OP_SUCCESS) {
        context->request_successful = status == 200;
    }
}

static void s_aws_http_on_incoming_body_connect_with_request(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {
    (void)stream;
    (void)data;
    (void)user_data;
}

static void s_aws_http_on_stream_complete_connect_with_request(
    struct aws_http_stream *stream,
    int error_code,
    void *user_data) {
    struct aws_http_connection *connection = aws_http_stream_get_connection(stream);
    struct aws_connection_with_request_context *context = user_data;
    if (context->request_successful && error_code == AWS_ERROR_SUCCESS) {
        context->state = SUCCESS;
        context->on_setup(connection, AWS_ERROR_SUCCESS, context->user_data);
        return;
    }

    context->on_setup(NULL, error_code, context->user_data);
    context->state = SHUTTING_DOWN;

    aws_http_connection_close(connection);
}

static void s_aws_http_on_client_connection_setup_chained_request(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {
    struct aws_connection_with_request_context *context = user_data;

    AWS_FATAL_ASSERT((error_code == AWS_ERROR_SUCCESS) ^ (connection == NULL));

    if (error_code != AWS_ERROR_SUCCESS) {
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
    if (stream == NULL) {
        goto on_error;
    }

    return;

on_error:

    context->on_setup(NULL, aws_last_error(), context->user_data);
    context->state = SHUTTING_DOWN;
    aws_http_connection_close(connection);
}

static void s_aws_http_on_client_connection_shutdown_chained_request(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {
    struct aws_connection_with_request_context *context = user_data;

    context->shutdown_received = true;

    if (context->state == SUCCESS && context->on_shutdown) {
        context->on_shutdown(connection, error_code, context->user_data);
    }

    aws_http_connection_release(connection);
    s_aws_connection_with_request_context_destroy(context);
}

int aws_http_client_connect_via_proxy(
    const struct aws_http_client_connection_options *options,
    struct aws_http_request *request) {
    struct aws_http_client_connection_options options_copy = *options;
    struct aws_connection_with_request_context *context =
        s_aws_connection_with_request_context_new(options->allocator, options, request);

    context = aws_mem_acquire(options->allocator, sizeof(struct aws_connection_with_request_context));
    if (context == NULL) {
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

    if (aws_http_client_connect(&options_copy)) {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:

    aws_mem_release(options->allocator, context);

    return AWS_OP_ERR;
}

#endif // NEVER