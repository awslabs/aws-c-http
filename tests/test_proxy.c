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

#include <aws/http/private/connection_impl.h>
#include <aws/http/private/h1_stream.h>
#include <aws/http/private/proxy_impl.h>

#include "proxy_test_helper.h"

#include <aws/testing/aws_test_harness.h>

static struct proxy_tester tester;

struct aws_http_stream *s_proxy_new_client_request_stream(const struct aws_http_request_options *options) {
    struct aws_h1_stream *h1_stream = aws_h1_stream_new_request(options);

    return &h1_stream->base;
}

struct aws_http_connection_vtable s_mock_proxy_connection_vtable = {
    .new_client_request_stream = s_proxy_new_client_request_stream
};

static void s_aws_http_release_mock_connection(struct aws_http_connection *connection) {
    proxy_tester_on_client_connection_shutdown(connection, AWS_ERROR_SUCCESS, &tester);

    aws_mem_release(connection->alloc, connection);
}

static int s_test_aws_client_bootstrap_new_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data)
{
    (void)bootstrap;
    (void)options;
    (void)setup_callback;
    (void)shutdown_callback;

    aws_mutex_lock(&tester.wait_lock);

    struct aws_byte_cursor host_cursor = aws_byte_cursor_from_c_str(host_name);
    aws_byte_buf_append_dynamic(&tester.connection_host_name, &host_cursor);

    tester.connection_port = port;
    tester.http_bootstrap = user_data;
    aws_mutex_unlock(&tester.wait_lock);

    struct aws_http_connection *connection = aws_mem_calloc(tester.alloc, 1, sizeof(struct aws_http_connection));
    aws_atomic_store_int(&connection->refcount, 1);
    connection->vtable = &s_mock_proxy_connection_vtable;
    connection->alloc = tester.alloc;

    proxy_tester_on_client_connection_setup(connection, AWS_ERROR_SUCCESS, &tester);

    return AWS_OP_SUCCESS;
}

#ifdef NEVER
static int s_test_aws_client_bootstrap_new_tls_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data)
{
    (void)bootstrap;
    (void)host_name;
    (void)port;
    (void)options;
    (void)connection_options;
    (void)setup_callback;
    (void)shutdown_callback;
    (void)user_data;

    return AWS_OP_SUCCESS;
}
#endif

struct aws_http_connection_system_vtable s_connection_target_vtable = {
    .new_socket_channel = s_test_aws_client_bootstrap_new_socket_channel
};

static int s_test_aws_client_bootstrap_new_socket_channel_failure(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data)
{
    (void)bootstrap;
    (void)options;
    (void)setup_callback;
    (void)shutdown_callback;

    aws_mutex_lock(&tester.wait_lock);

    struct aws_byte_cursor host_cursor = aws_byte_cursor_from_c_str(host_name);
    aws_byte_buf_append_dynamic(&tester.connection_host_name, &host_cursor);

    tester.connection_port = port;
    tester.http_bootstrap = user_data;

    tester.wait_result = AWS_ERROR_UNKNOWN;

    aws_mutex_unlock(&tester.wait_lock);

    return AWS_OP_ERR;
}

struct aws_http_connection_system_vtable s_connection_channel_failure_vtable = {
    .new_socket_channel = s_test_aws_client_bootstrap_new_socket_channel_failure
};

static int s_test_aws_client_bootstrap_new_socket_connect_failure(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data)
{
    (void)bootstrap;
    (void)options;
    (void)setup_callback;
    (void)shutdown_callback;

    aws_mutex_lock(&tester.wait_lock);

    struct aws_byte_cursor host_cursor = aws_byte_cursor_from_c_str(host_name);
    aws_byte_buf_append_dynamic(&tester.connection_host_name, &host_cursor);

    tester.connection_port = port;
    tester.http_bootstrap = user_data;
    aws_mutex_unlock(&tester.wait_lock);

    setup_callback(tester.client_bootstrap, AWS_ERROR_UNKNOWN, NULL, user_data);

    return AWS_OP_SUCCESS;
}

struct aws_http_connection_system_vtable s_connection_connect_failure_vtable = {
    .new_socket_channel = s_test_aws_client_bootstrap_new_socket_connect_failure
};

static char *s_host_name = "www.amazon.com";
static uint16_t s_port = 80;

/*
 * If we don't pass in proxy options, verify we try and connect to the actual target
 */
static int s_test_http_proxy_connection_real_target(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_connection_set_system_vtable(&s_connection_target_vtable);

    struct proxy_tester_options options = {
        .alloc = allocator,
        .release_connection = s_aws_http_release_mock_connection,
        .host = aws_byte_cursor_from_c_str(s_host_name),
        .port = s_port
    };

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    ASSERT_BIN_ARRAYS_EQUALS(
        tester.connection_host_name.buffer,
        tester.connection_host_name.len,
        s_host_name,
        strlen(s_host_name),
        "Connection host should have been {%s}, but was {" PRInSTR "}.",
        s_host_name,
        AWS_BYTE_BUF_PRI(tester.connection_host_name));

    ASSERT_TRUE(tester.connection_port == s_port);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_real_target, s_test_http_proxy_connection_real_target);

static char *s_proxy_host_name = "www.myproxy.hmm";
static uint16_t s_proxy_port = 777;

/*
 * If we do pass in proxy options, verify we try and connect to the proxy
 */
static int s_test_http_proxy_connection_proxy_target(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_connection_set_system_vtable(&s_connection_target_vtable);

    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str(s_proxy_host_name),
        .port = s_proxy_port
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str(s_host_name),
        .port = s_port,
        .release_connection = s_aws_http_release_mock_connection
    };

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    ASSERT_BIN_ARRAYS_EQUALS(
        tester.connection_host_name.buffer,
        tester.connection_host_name.len,
        s_proxy_host_name,
        strlen(s_proxy_host_name),
        "Connection host should have been {%s}, but was {" PRInSTR "}.",
        s_proxy_host_name,
        AWS_BYTE_BUF_PRI(tester.connection_host_name));

    ASSERT_TRUE(tester.connection_port == s_proxy_port);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_proxy_target, s_test_http_proxy_connection_proxy_target);

/*
 * If we do pass in proxy options, verify a channel creation failure cleans up properly
 */
static int s_test_http_proxy_connection_channel_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_connection_set_system_vtable(&s_connection_channel_failure_vtable);

    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str(s_proxy_host_name),
        .port = s_proxy_port
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str(s_host_name),
        .port = s_port,
        .release_connection = s_aws_http_release_mock_connection
    };

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    ASSERT_TRUE(tester.wait_result != AWS_ERROR_SUCCESS);
    ASSERT_TRUE(tester.client_connection == NULL);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_channel_failure, s_test_http_proxy_connection_channel_failure);

/*
 * If we do pass in proxy options, verify a connect failure cleans up properly
 */
static int s_test_http_proxy_connection_connect_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_connection_set_system_vtable(&s_connection_connect_failure_vtable);

    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str(s_proxy_host_name),
        .port = s_proxy_port
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str(s_host_name),
        .port = s_port,
        .release_connection = s_aws_http_release_mock_connection
    };

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_connect_failure, s_test_http_proxy_connection_connect_failure);

struct aws_http_request *s_build_http_request(struct aws_allocator *allocator)
{
    struct aws_http_request *request = aws_http_request_new(allocator);
    aws_http_request_set_method(request, aws_byte_cursor_from_c_str("GET"));
    aws_http_request_set_path(request, aws_byte_cursor_from_c_str("/"));

    struct aws_http_header host = { .name = aws_byte_cursor_from_c_str("Host"), .value = aws_byte_cursor_from_c_str("www.amazon.com")};
    aws_http_request_add_header(request, host);

    struct aws_http_header accept = { .name = aws_byte_cursor_from_c_str("Accept"), .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_request_add_header(request, accept);

    struct aws_http_header user_agent = { .name = aws_byte_cursor_from_c_str("User-Agent"), .value = aws_byte_cursor_from_c_str("derp")};
    aws_http_request_add_header(request, user_agent);

    return request;
}

/*
 * If we do pass in proxy options, verify requests get properly transformed
 */
static int s_test_http_proxy_connection_request_transform(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_connection_set_system_vtable(&s_connection_target_vtable);

    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str(s_proxy_host_name),
        .port = s_proxy_port
    };

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str(s_host_name),
        .port = s_port,
        .release_connection = s_aws_http_release_mock_connection
    };

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    struct aws_http_request *request = s_build_http_request(allocator);

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.client_connection = tester.client_connection;
    request_options.request = request;
    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.user_data = &tester;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);

    ASSERT_SUCCESS(proxy_tester_wait(&tester, proxy_tester_request_complete_pred_fn));

    aws_http_stream_release(stream);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_request_transform, s_test_http_proxy_connection_request_transform);
