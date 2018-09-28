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

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>

#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/socket_channel_handler.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/testing/aws_test_harness.h>

#include <mach-o/dyld.h>
#include <unistd.h>

#define aws_byte_cursor_from_str(s) aws_byte_cursor_from_array(s, strlen(s))

static struct aws_http_server_connection *s_server_connection;

static void s_on_request(struct aws_http_server_connection *connection, enum aws_http_method method, void *user_data) {
    (void)connection;
    (void)user_data;
    fprintf(stderr, "Got request. Method: %s\n", aws_http_method_to_str(method));
}

static void s_on_uri(
    struct aws_http_server_connection *connection,
    const struct aws_byte_cursor *uri,
    void *user_data) {
    (void)connection;
    (void)user_data;
    fprintf(stderr, "Got URI: %.*s\n", (int)uri->len, uri->ptr);
}

static void s_on_request_header(
    struct aws_http_server_connection *connection,
    enum aws_http_header_name header_name,
    const struct aws_http_header *header,
    void *user_data) {
    (void)connection;
    (void)header_name;
    (void)user_data;
    fprintf(
        stderr,
        "Got request header: %.*s: %.*s\n",
        (int)header->name.len,
        header->name.ptr,
        (int)header->value.len,
        header->value.ptr);
}

static void s_on_request_body_segment(
    struct aws_http_server_connection *connection,
    const struct aws_byte_cursor *data,
    bool last_segment,
    bool *release_segment,
    void *user_data) {
    (void)connection;
    (void)last_segment;
    (void)user_data;
    *release_segment = true;
    printf("%.*s", (int)data->len, data->ptr);
}

void s_on_connection_created(struct aws_http_server_connection *connection, void *user_data) {
    (void)user_data;
    s_server_connection = connection;
    fprintf(stderr, "Server connection created.\n");
}

void s_on_connection_closed(struct aws_http_server_connection *connection, void *user_data) {
    (void)connection;
    (void)user_data;
    s_server_connection = NULL;
    fprintf(stderr, "Server connection created.\n");
}

static struct aws_http_client_connection *s_client_connection;
static struct aws_mutex s_mutex;
static struct aws_condition_variable s_cv;

static void s_on_connected(struct aws_http_client_connection *connection, void *user_data) {
    (void)user_data;
    s_client_connection = connection;
    fprintf(stderr, "Client connected.\n");

    aws_mutex_lock(&s_mutex);
    aws_condition_variable_notify_one(&s_cv);
    aws_mutex_unlock(&s_mutex);
}

static void s_on_disconnected(struct aws_http_client_connection *connection, void *user_data) {
    (void)connection;
    (void)user_data;
    s_client_connection = NULL;
    fprintf(stderr, "Client disconnected.\n");
}

static void s_request_on_write_body_segment(
    struct aws_http_request *request,
    struct aws_byte_cursor *segment,
    bool *last_segment,
    void *user_data) {
    (void)request;
    *last_segment = true;
    const char *body_data = (const char *)user_data;
    struct aws_byte_cursor data = aws_byte_cursor_from_str(body_data);
    *segment = data;
}

static void s_request_on_response(struct aws_http_request *request, enum aws_http_code code, void *user_data) {
    (void)request;
    (void)user_data;
    fprintf(stderr, "Got response code: %d\n", (int)code);
}

static void s_request_on_response_header(
    struct aws_http_request *request,
    enum aws_http_header_name header_name,
    const struct aws_http_header *header,
    void *user_data) {
    (void)request;
    (void)header_name;
    (void)user_data;
    fprintf(
        stderr,
        "Got response header: %.*s: %.*s\n",
        (int)header->name.len,
        header->name.ptr,
        (int)header->value.len,
        header->value.ptr);
}

void s_request_on_response_body_segment(
    struct aws_http_request *request,
    const struct aws_byte_cursor *data,
    bool last_segment,
    bool *release_segment,
    void *user_data) {
    (void)request;
    (void)last_segment;
    (void)user_data;
    *release_segment = true;
    printf("%.*s", (int)data->len, data->ptr);
}

void s_request_on_request_completed(struct aws_http_request *request, void *user_data) {
    (void)user_data;
    fprintf(stderr, "Request received a response and fully completed.\n");
    aws_http_request_destroy(request);
}

AWS_TEST_CASE(http_test_connection, s_http_test_connection);
static int s_http_test_connection(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_tls_init_static_state(allocator);

    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator, 2));

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.connect_timeout = 3000;
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_LOCAL;

    struct aws_socket_endpoint endpoint;
    AWS_ZERO_STRUCT(endpoint);
    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));
    sprintf(endpoint.socket_name, "testsock%llu.sock", (long long unsigned)timestamp);

    /* Client io setup. */
    struct aws_tls_ctx_options client_tls_ctx_options;
    aws_tls_ctx_options_init_default_client(&client_tls_ctx_options);
    aws_tls_ctx_options_override_default_trust_store(&client_tls_ctx_options, NULL, "./unittests.crt");
    struct aws_tls_ctx *client_tls_ctx = aws_tls_client_ctx_new(allocator, &client_tls_ctx_options);
    ASSERT_NOT_NULL(client_tls_ctx);

    struct aws_tls_connection_options tls_client_conn_options;
    aws_tls_connection_options_init_from_ctx_options(&tls_client_conn_options, &client_tls_ctx_options);

    struct aws_client_bootstrap client_bootstrap;
    ASSERT_SUCCESS(aws_client_bootstrap_init(&client_bootstrap, allocator, &el_group));
    aws_client_bootstrap_set_tls_ctx(&client_bootstrap, client_tls_ctx);

    /* Server io setup. */
    struct aws_tls_ctx_options server_tls_ctx_options;
#ifdef __APPLE__
    aws_tls_ctx_options_init_server_pkcs12(&server_tls_ctx_options, "./unittests.p12", "1234");
#else
    aws_tls_ctx_options_init_default_server(&server_tls_ctx_options, "./unittests.crt", "./unittests.key");
#endif /* __APPLE__ */

    struct aws_tls_ctx *server_tls_ctx = aws_tls_server_ctx_new(allocator, &server_tls_ctx_options);
    ASSERT_NOT_NULL(server_tls_ctx);

    struct aws_tls_connection_options tls_server_conn_options;
    aws_tls_connection_options_init_from_ctx_options(&tls_server_conn_options, &server_tls_ctx_options);

    struct aws_server_bootstrap server_bootstrap;
    ASSERT_SUCCESS(aws_server_bootstrap_init(&server_bootstrap, allocator, &el_group));
    ASSERT_SUCCESS(aws_server_bootstrap_set_tls_ctx(&server_bootstrap, server_tls_ctx));

    /* Setup HTTP connections. */
    struct aws_http_server_callbacks server_callbacks;
    server_callbacks.on_request = s_on_request;
    server_callbacks.on_uri = s_on_uri;
    server_callbacks.on_request_header = s_on_request_header;
    server_callbacks.on_request_body_segment = s_on_request_body_segment;
    server_callbacks.on_connection_created = s_on_connection_created;
    server_callbacks.on_connection_closed = s_on_connection_closed;
    struct aws_http_listener *server_listener = aws_http_listener_new(
        allocator,
        &endpoint,
        &socket_options,
        &tls_server_conn_options,
        &server_bootstrap,
        1024,
        &server_callbacks,
        NULL);
    (void)server_listener;

    struct aws_http_client_callbacks client_callbacks;
    client_callbacks.on_connected = s_on_connected;
    client_callbacks.on_disconnected = s_on_disconnected;
    aws_http_client_connect(
        allocator,
        &endpoint,
        &socket_options,
        &tls_client_conn_options,
        &client_bootstrap,
        1024,
        &client_callbacks,
        NULL);

    while (!s_client_connection) {
        aws_mutex_lock(&s_mutex);
        aws_condition_variable_wait(&s_cv, &s_mutex);
        aws_mutex_unlock(&s_mutex);
    }

    const char *body_data = "The body data.";
    struct aws_http_header headers[] = {
        {.name = aws_byte_cursor_from_str("Host"), .value = aws_byte_cursor_from_str("amazon.com")},
        {.name = aws_byte_cursor_from_str("transfer-encoding"), .value = aws_byte_cursor_from_str("chunked")},
    };
    struct aws_byte_cursor uri = aws_byte_cursor_from_str("/");
    struct aws_http_request_callbacks request_callbacks;
    request_callbacks.on_write_body_segment = s_request_on_write_body_segment;
    request_callbacks.on_response = s_request_on_response;
    request_callbacks.on_response_header = s_request_on_response_header;
    request_callbacks.on_response_body_segment = s_request_on_response_body_segment;
    request_callbacks.on_request_completed = s_request_on_request_completed;
    struct aws_http_request *request = aws_http_request_new(
        s_client_connection,
        AWS_HTTP_METHOD_GET,
        &uri,
        true,
        headers,
        AWS_ARRAY_SIZE(headers),
        &request_callbacks,
        (void *)body_data);
    aws_http_request_send(request);

    while (1) {
    }

    /* Cleanup. */

    aws_client_bootstrap_clean_up(&client_bootstrap);
    aws_event_loop_group_clean_up(&el_group);
    aws_tls_ctx_destroy(client_tls_ctx);
    aws_tls_clean_up_static_state();

    return AWS_OP_SUCCESS;
}
