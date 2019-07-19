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

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/log_writer.h>
#include <aws/common/uuid.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

enum {
    TESTER_TIMEOUT_SEC = 60, /* Give enough time for non-sudo users to enter password */
};

/* Options for setting up `tester` singleton */
struct tester_options {
    struct aws_allocator *alloc;
    struct aws_byte_cursor host;
    uint16_t port;
    bool use_tls;
};

/* Singleton used by tests in this file */
struct tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;
    struct aws_event_loop_group event_loop_group;
    struct aws_host_resolver host_resolver;
    struct aws_client_bootstrap *client_bootstrap;

    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_connection_options tls_connection_options;

    struct aws_byte_cursor host;
    uint16_t port;
    struct aws_http_connection *client_connection;

    bool client_connection_is_shutdown;

    /* If we need to wait for some async process*/
    struct aws_mutex wait_lock;
    struct aws_condition_variable wait_cvar;
    int wait_result;
    bool request_successful;
    bool request_complete;

    bool tls_finished;
    bool tls_successful;
};

static void s_tester_on_client_connection_setup(
        struct aws_http_connection *connection,
        int error_code,
        void *user_data) {

    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    if (error_code) {
        tester->wait_result = error_code;
        goto done;
    }

    tester->client_connection = connection;
done:
    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static void s_tester_on_client_connection_shutdown(
        struct aws_http_connection *connection,
        int error_code,
        void *user_data) {

    (void)connection;
    (void)error_code;
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->client_connection_is_shutdown = true;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static int s_tester_wait(struct tester *tester, bool (*pred)(void *user_data)) {
    ASSERT_SUCCESS(aws_mutex_lock(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
            &tester->wait_cvar,
            &tester->wait_lock,
            pred,
            tester));
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->wait_lock));

    if (tester->wait_result) {
        return aws_raise_error(tester->wait_result);
    }
    return AWS_OP_SUCCESS;
}

static bool s_tester_connection_setup_pred(void *user_data) {
    struct tester *tester = user_data;
    return tester->wait_result || tester->client_connection;
}

static bool s_tester_connection_shutdown_pred(void *user_data) {
    struct tester *tester = user_data;
    return tester->wait_result || tester->client_connection_is_shutdown;
}

static int s_tester_init(struct tester *tester, const struct tester_options *options) {
    AWS_ZERO_STRUCT(*tester);

    tester->alloc = options->alloc;

    aws_load_error_strings();
    aws_common_load_log_subject_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();

    aws_http_library_init(options->alloc);

    tester->host = options->host;
    tester->port = options->port;

    struct aws_logger_standard_options logger_options = {
            .level = AWS_LOG_LEVEL_TRACE,
            .file = stderr,
    };

    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    ASSERT_SUCCESS(aws_mutex_init(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&tester->wait_cvar));

    ASSERT_SUCCESS(aws_event_loop_group_default_init(&tester->event_loop_group, tester->alloc, 1));
    ASSERT_SUCCESS(aws_host_resolver_init_default(&tester->host_resolver, tester->alloc, 8, &tester->event_loop_group));

    struct aws_socket_options socket_options = {
            .type = AWS_SOCKET_STREAM,
            .domain = AWS_SOCKET_IPV4,
            .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    tester->client_bootstrap =
            aws_client_bootstrap_new(tester->alloc, &tester->event_loop_group, &tester->host_resolver, NULL);
    ASSERT_NOT_NULL(tester->client_bootstrap);

    if (options->use_tls)
    {
        aws_tls_init_static_state(tester->alloc);

        aws_tls_ctx_options_init_default_client(&tester->tls_ctx_options, tester->alloc);
        aws_tls_ctx_options_set_alpn_list(&tester->tls_ctx_options, "http/1.1");

        tester->tls_ctx = aws_tls_client_ctx_new(tester->alloc, &tester->tls_ctx_options);

        aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);
        aws_tls_connection_options_set_server_name(&tester->tls_connection_options, tester->alloc, &tester->host);
    }

    /* Connect */
    struct aws_http_client_connection_options client_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    client_options.allocator = tester->alloc;
    client_options.bootstrap = tester->client_bootstrap;
    client_options.host_name = tester->host;
    client_options.port = tester->port;
    client_options.socket_options = &socket_options;
    client_options.tls_options = options->use_tls ? &tester->tls_connection_options : NULL;
    client_options.user_data = tester;
    client_options.on_setup = s_tester_on_client_connection_setup;
    client_options.on_shutdown = s_tester_on_client_connection_shutdown;

    ASSERT_SUCCESS(aws_http_client_connect(&client_options));

    /* Wait for server & client connections to finish setup */
    ASSERT_SUCCESS(s_tester_wait(tester, s_tester_connection_setup_pred));

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    /* If there's a connection, shut down the server and client side. */
    if (tester->client_connection) {
        aws_http_connection_release(tester->client_connection);

        ASSERT_SUCCESS(s_tester_wait(tester, s_tester_connection_shutdown_pred));

        aws_client_bootstrap_release(tester->client_bootstrap);
    }

    aws_host_resolver_clean_up(&tester->host_resolver);
    aws_event_loop_group_clean_up(&tester->event_loop_group);

    if (tester->tls_ctx) {
        aws_tls_connection_options_clean_up(&tester->tls_connection_options);
        aws_tls_ctx_destroy(tester->tls_ctx);
        aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    }

    aws_tls_clean_up_static_state();

    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);

    return AWS_OP_SUCCESS;
}

static void s_aws_http_on_incoming_headers_test(
        struct aws_http_stream *stream,
        const struct aws_http_header *header_array,
        size_t num_headers,
        void *user_data)
{
    (void)stream;
    (void)user_data;

    for (size_t i = 0; i < num_headers; ++i) {
        const struct aws_byte_cursor *name = &header_array[i].name;
        const struct aws_byte_cursor *value = &header_array[i].value;
        AWS_LOGF_INFO(AWS_LS_HTTP_GENERAL, "< " PRInSTR " : " PRInSTR, AWS_BYTE_CURSOR_PRI(*name), AWS_BYTE_CURSOR_PRI(*value));
    }
}

static void s_aws_http_on_incoming_header_block_done_test(struct aws_http_stream *stream, bool has_body, void *user_data)
{
    (void)has_body;

    struct tester *context = user_data;
    int status = 0;
    if (aws_http_stream_get_incoming_response_status(stream, &status) == AWS_OP_SUCCESS) {
        context->request_successful = status == 200;
    }
}

static void s_aws_http_on_incoming_body_test(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data)
{
    (void)stream;
    (void)user_data;

    AWS_LOGF_INFO(AWS_LS_HTTP_GENERAL, "< " PRInSTR, AWS_BYTE_CURSOR_PRI(*data));
}

static void s_aws_http_on_stream_complete_test(struct aws_http_stream *stream, int error_code, void *user_data)
{
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
        return;
    }

    struct tester *tester = user_data;
    aws_mutex_lock(&tester->wait_lock);
    tester->tls_finished = true;
    tester->tls_successful = err_code == AWS_ERROR_SUCCESS;
    aws_mutex_unlock(&tester->wait_lock);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static int s_test_proxy_connection_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct tester_options options = {
            .alloc = allocator,
            .host = aws_byte_cursor_from_c_str("127.0.0.1"),
            .port = 8080
    };

    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    aws_tls_init_static_state(tester.alloc);

    aws_tls_ctx_options_init_default_client(&tester.tls_ctx_options, tester.alloc);
    aws_tls_ctx_options_set_alpn_list(&tester.tls_ctx_options, "http/1.1");

    tester.tls_ctx = aws_tls_client_ctx_new(tester.alloc, &tester.tls_ctx_options);

    aws_tls_connection_options_init_from_ctx(&tester.tls_connection_options, tester.tls_ctx);

    struct aws_byte_cursor tls_host =  aws_byte_cursor_from_c_str("www.amazon.com");
    aws_tls_connection_options_set_server_name(&tester.tls_connection_options, tester.alloc, &tls_host);

    struct aws_http_request *request = aws_http_request_new(allocator);
    aws_http_request_set_method(request, aws_byte_cursor_from_c_str("CONNECT"));
    aws_http_request_set_path(request, aws_byte_cursor_from_c_str("www.amazon.com:443"));

    struct aws_http_header host = { .name = aws_byte_cursor_from_c_str("Host"), .value = aws_byte_cursor_from_c_str("www.amazon.com")};
    aws_http_request_add_header(request, host);

    struct aws_http_header keep_alive = { .name = aws_byte_cursor_from_c_str("Proxy-Connection"), .value = aws_byte_cursor_from_c_str("Keep-Alive")};
    aws_http_request_add_header(request, keep_alive);

    struct aws_http_header auth = { .name = aws_byte_cursor_from_c_str("Proxy-Authorization"), .value = aws_byte_cursor_from_c_str("Basic ZGVycDpkZXJw")};
    aws_http_request_add_header(request, auth);

    struct aws_http_header accept = { .name = aws_byte_cursor_from_c_str("Accept"), .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_request_add_header(request, accept);

    struct aws_http_header user_agent = { .name = aws_byte_cursor_from_c_str("User-Agent"), .value = aws_byte_cursor_from_c_str("derp")};
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

    struct aws_http_header get_host_header = { .name = aws_byte_cursor_from_c_str("Host"), .value = aws_byte_cursor_from_c_str("www.amazon.com")};
    aws_http_request_add_header(get_request, get_host_header);

    struct aws_http_header get_accept_header = { .name = aws_byte_cursor_from_c_str("Accept"), .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_request_add_header(get_request, get_accept_header);

    struct aws_http_header get_user_agent_header = { .name = aws_byte_cursor_from_c_str("User-Agent"), .value = aws_byte_cursor_from_c_str("derp")};
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
            .alloc = allocator,
            .host = aws_byte_cursor_from_c_str("www.amazon.com"),
            .port = 443,
            .use_tls = true
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    struct aws_http_request *request = aws_http_request_new(allocator);
    aws_http_request_set_method(request, aws_byte_cursor_from_c_str("GET"));
    aws_http_request_set_path(request, aws_byte_cursor_from_c_str("/"));

    struct aws_http_header host = { .name = aws_byte_cursor_from_c_str("Host"), .value = aws_byte_cursor_from_c_str("www.amazon.com")};
    aws_http_request_add_header(request, host);

    struct aws_http_header accept = { .name = aws_byte_cursor_from_c_str("Accept"), .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_request_add_header(request, accept);

    struct aws_http_header user_agent = { .name = aws_byte_cursor_from_c_str("User-Agent"), .value = aws_byte_cursor_from_c_str("derp")};
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