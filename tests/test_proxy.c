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

#include <aws/io/uri.h>

#include "proxy_test_helper.h"

#include <aws/testing/aws_test_harness.h>

static struct proxy_tester tester;

struct aws_http_stream *s_proxy_new_client_request_stream(const struct aws_http_request_options *options) {
    struct aws_h1_stream *h1_stream = aws_h1_stream_new_request(options);

    return &h1_stream->base;
}

struct aws_http_connection_vtable s_mock_proxy_connection_vtable = {.new_client_request_stream =
                                                                        s_proxy_new_client_request_stream};

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
    void *user_data) {
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
    connection->request_transform = tester.http_bootstrap->request_transform;
    connection->user_data = tester.http_bootstrap->user_data;

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
    void *user_data) {
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
    .new_socket_channel = s_test_aws_client_bootstrap_new_socket_channel};

static int s_test_aws_client_bootstrap_new_socket_channel_failure(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data) {
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
    .new_socket_channel = s_test_aws_client_bootstrap_new_socket_channel_failure};

static int s_test_aws_client_bootstrap_new_socket_connect_failure(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data) {
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
    .new_socket_channel = s_test_aws_client_bootstrap_new_socket_connect_failure};

static char *s_host_name = "www.amazon.com";
static uint16_t s_port = 80;

/*
 * If we don't pass in proxy options, verify we try and connect to the actual target
 */
static int s_test_http_proxy_connection_real_target(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_connection_set_system_vtable(&s_connection_target_vtable);

    struct proxy_tester_options options = {.alloc = allocator,
                                           .release_connection = s_aws_http_release_mock_connection,
                                           .host = aws_byte_cursor_from_c_str(s_host_name),
                                           .port = s_port};

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

    struct aws_http_proxy_options proxy_options = {.host = aws_byte_cursor_from_c_str(s_proxy_host_name),
                                                   .port = s_proxy_port};

    struct proxy_tester_options options = {.alloc = allocator,
                                           .proxy_options = &proxy_options,
                                           .host = aws_byte_cursor_from_c_str(s_host_name),
                                           .port = s_port,
                                           .release_connection = s_aws_http_release_mock_connection};

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

    struct aws_http_proxy_options proxy_options = {.host = aws_byte_cursor_from_c_str(s_proxy_host_name),
                                                   .port = s_proxy_port};

    struct proxy_tester_options options = {.alloc = allocator,
                                           .proxy_options = &proxy_options,
                                           .host = aws_byte_cursor_from_c_str(s_host_name),
                                           .port = s_port,
                                           .release_connection = s_aws_http_release_mock_connection};

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

    struct aws_http_proxy_options proxy_options = {.host = aws_byte_cursor_from_c_str(s_proxy_host_name),
                                                   .port = s_proxy_port};

    struct proxy_tester_options options = {.alloc = allocator,
                                           .proxy_options = &proxy_options,
                                           .host = aws_byte_cursor_from_c_str(s_host_name),
                                           .port = s_port,
                                           .release_connection = s_aws_http_release_mock_connection};

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_connect_failure, s_test_http_proxy_connection_connect_failure);

AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_method, "GET");
AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_path, "/");
AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_host, "www.amazon.com");
AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_username, "SomeUser");
AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_password, "SuperSecret");

struct aws_http_message *s_build_http_request(struct aws_allocator *allocator) {
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    aws_http_message_set_request_method(request, aws_byte_cursor_from_string(s_mock_request_method));
    aws_http_message_set_request_path(request, aws_byte_cursor_from_string(s_mock_request_path));

    struct aws_http_header host = {.name = aws_byte_cursor_from_c_str("Host"),
                                   .value = aws_byte_cursor_from_string(s_mock_request_host)};
    aws_http_message_add_header(request, host);

    struct aws_http_header accept = {.name = aws_byte_cursor_from_c_str("Accept"),
                                     .value = aws_byte_cursor_from_c_str("*/*")};
    aws_http_message_add_header(request, accept);

    struct aws_http_header user_agent = {.name = aws_byte_cursor_from_c_str("User-Agent"),
                                         .value = aws_byte_cursor_from_c_str("derp")};
    aws_http_message_add_header(request, user_agent);

    return request;
}

static bool s_is_header_in_request(struct aws_http_message *request, struct aws_http_header *header) {
    size_t header_count = aws_http_message_get_header_count(request);
    for (size_t i = 0; i < header_count; ++i) {
        struct aws_http_header current_header;
        ASSERT_SUCCESS(aws_http_message_get_header(request, &current_header, i));

        if (aws_byte_cursor_eq_ignore_case(&current_header.name, &header->name) &&
            aws_byte_cursor_eq(&current_header.value, &header->value)) {
            return true;
        }
    }

    return false;
}

AWS_STATIC_STRING_FROM_LITERAL(s_expected_auth_header_name, "Proxy-Authorization");
AWS_STATIC_STRING_FROM_LITERAL(s_expected_auth_header_value, "Basic U29tZVVzZXI6U3VwZXJTZWNyZXQ=");

static int s_verify_transformed_request(
    struct aws_http_message *untransformed_request,
    struct aws_http_message *transformed_request,
    bool used_basic_auth,
    struct aws_allocator *allocator) {

    /* method shouldn't change */
    struct aws_byte_cursor method_cursor;
    ASSERT_SUCCESS(aws_http_message_get_request_method(transformed_request, &method_cursor));

    struct aws_byte_cursor starting_method_cursor;
    ASSERT_SUCCESS(aws_http_message_get_request_method(untransformed_request, &starting_method_cursor));

    ASSERT_TRUE(aws_byte_cursor_eq(&method_cursor, &starting_method_cursor));

    /* path should be the full uri */
    struct aws_byte_cursor path;
    ASSERT_SUCCESS(aws_http_message_get_request_path(transformed_request, &path));

    struct aws_uri uri;
    ASSERT_SUCCESS(aws_uri_init_parse(&uri, allocator, &path));

    struct aws_byte_cursor expected_scheme = aws_byte_cursor_from_c_str("http");
    ASSERT_TRUE(aws_byte_cursor_eq(aws_uri_scheme(&uri), &expected_scheme));

    struct aws_byte_cursor expected_host = aws_byte_cursor_from_string(s_mock_request_host);
    ASSERT_TRUE(aws_byte_cursor_eq(aws_uri_host_name(&uri), &expected_host));

    struct aws_byte_cursor expected_query = aws_byte_cursor_from_c_str("");
    ASSERT_TRUE(aws_byte_cursor_eq(aws_uri_query_string(&uri), &expected_query));

    struct aws_byte_cursor expected_path = aws_byte_cursor_from_c_str("/");
    ASSERT_TRUE(aws_byte_cursor_eq(aws_uri_path(&uri), &expected_path));

    /* all old headers should still be present */
    size_t untransformed_header_count = aws_http_message_get_header_count(untransformed_request);
    ASSERT_TRUE(
        untransformed_header_count + (used_basic_auth ? 1 : 0) ==
        aws_http_message_get_header_count(transformed_request));
    for (size_t i = 0; i < untransformed_header_count; ++i) {
        struct aws_http_header header;
        ASSERT_SUCCESS(aws_http_message_get_header(untransformed_request, &header, i));
        ASSERT_TRUE(s_is_header_in_request(transformed_request, &header));
    }

    /* auth header should be present if basic auth used */
    if (used_basic_auth) {
        struct aws_http_header auth_header;
        auth_header.name = aws_byte_cursor_from_string(s_expected_auth_header_name);
        auth_header.value = aws_byte_cursor_from_string(s_expected_auth_header_value);
        ASSERT_TRUE(s_is_header_in_request(transformed_request, &auth_header));
    }

    aws_uri_clean_up(&uri);

    return AWS_OP_SUCCESS;
}

/*
 * If we do pass in proxy options, verify requests get properly transformed
 */
static int s_test_http_proxy_connection_request_transform(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_connection_set_system_vtable(&s_connection_target_vtable);

    struct aws_http_proxy_options proxy_options = {.host = aws_byte_cursor_from_c_str(s_proxy_host_name),
                                                   .port = s_proxy_port};

    struct proxy_tester_options options = {.alloc = allocator,
                                           .proxy_options = &proxy_options,
                                           .host = aws_byte_cursor_from_c_str(s_host_name),
                                           .port = s_port,
                                           .release_connection = s_aws_http_release_mock_connection};

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    struct aws_http_message *untransformed_request = s_build_http_request(allocator);
    struct aws_http_message *request = s_build_http_request(allocator);

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.client_connection = tester.client_connection;
    request_options.request = request;
    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.user_data = &tester;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);

    s_verify_transformed_request(untransformed_request, request, false, allocator);

    /* double release the stream because the dummy connection doesn't actually process (and release) it */
    aws_http_stream_release(stream);
    aws_http_stream_release(stream);

    aws_http_message_destroy(request);
    aws_http_message_destroy(untransformed_request);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_request_transform, s_test_http_proxy_connection_request_transform);

/*
 * If we do pass in proxy options, verify requests get properly transformed with basic authentication
 */
static int s_test_http_proxy_connection_request_transform_basic_auth(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_connection_set_system_vtable(&s_connection_target_vtable);

    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str(s_proxy_host_name),
        .port = s_proxy_port,
        .auth = {
            .type = AWS_HPAT_BASIC,
            .type_options = {.basic_options = {.user = aws_byte_cursor_from_string(s_mock_request_username),
                                               .password = aws_byte_cursor_from_string(s_mock_request_password)}}}};

    struct proxy_tester_options options = {.alloc = allocator,
                                           .proxy_options = &proxy_options,
                                           .host = aws_byte_cursor_from_c_str(s_host_name),
                                           .port = s_port,
                                           .release_connection = s_aws_http_release_mock_connection};

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    struct aws_http_message *untransformed_request = s_build_http_request(allocator);
    struct aws_http_message *request = s_build_http_request(allocator);

    struct aws_http_request_options request_options;
    AWS_ZERO_STRUCT(request_options);
    request_options.client_connection = tester.client_connection;
    request_options.request = request;
    request_options.self_size = sizeof(struct aws_http_request_options);
    request_options.user_data = &tester;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);

    s_verify_transformed_request(untransformed_request, request, true, allocator);

    /* double release the stream because the dummy connection doesn't actually process (and release) it */
    aws_http_stream_release(stream);
    aws_http_stream_release(stream);

    aws_http_message_destroy(request);
    aws_http_message_destroy(untransformed_request);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    test_http_proxy_connection_request_transform_basic_auth,
    s_test_http_proxy_connection_request_transform_basic_auth);