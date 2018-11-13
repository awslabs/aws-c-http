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

#include <unistd.h>

#if 1
#    define AWS_HTTP_TEST_PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#    define AWS_HTTP_TEST_PRINT(...)
#endif

#define aws_byte_cursor_from_str(s) aws_byte_cursor_from_array(s, strlen(s))

static struct aws_http_server_connection *s_server_connection;
static struct aws_http_client_connection *s_client_connection;
static struct aws_mutex s_mutex;
static struct aws_condition_variable s_cv;
static bool s_server_finished_getting_request;
static bool s_client_received_response;
static enum aws_http_method s_method;
static size_t s_uri_len;
static uint8_t s_uri[128];
static uint8_t s_body_data_memory[128];
static struct aws_byte_buf s_body_data;
static bool s_body_data_init;
int s_header_count;
bool s_headers_ok;
static enum aws_http_code s_code;

static void s_on_request(struct aws_http_server_connection *connection, enum aws_http_method method, void *user_data) {
    (void)connection;
    (void)user_data;
    AWS_HTTP_TEST_PRINT("Got request. Method: %s\n", aws_http_method_to_str(method));
    s_method = method;
}

static void s_on_uri(
    const struct aws_byte_cursor *uri,
    void *user_data) {
    (void)user_data;
    AWS_HTTP_TEST_PRINT("Got URI: %.*s\n", (int)uri->len, uri->ptr);
    assert(uri->len < AWS_ARRAY_SIZE(s_uri));
    memcpy(s_uri, uri->ptr, uri->len);
    s_uri_len = uri->len;
}

static int s_test_header(const char *expected, const struct aws_byte_cursor *got) {
    struct aws_byte_cursor host = aws_byte_cursor_from_str(expected);
    ASSERT_BIN_ARRAYS_EQUALS(host.ptr, host.len, got->ptr, got->len);
    return AWS_OP_SUCCESS;
}

static void s_on_request_header(
    enum aws_http_header_name header_name,
    const struct aws_http_header *header,
    void *user_data) {
    (void)header_name;
    (void)user_data;
    AWS_HTTP_TEST_PRINT(
        "Got request header: %.*s: %.*s\n",
        (int)header->name.len,
        header->name.ptr,
        (int)header->value.len,
        header->value.ptr);

    if (s_header_count == 0) {
        s_headers_ok |= s_test_header("Host", &header->name);
        s_headers_ok |= s_test_header("amazon.com", &header->value);
    } else {
        s_headers_ok |= s_test_header("transfer-encoding", &header->name);
        s_headers_ok |= s_test_header("chunked", &header->value);
    }

    ++s_header_count;
}

static void s_on_request_body_segment(
    const struct aws_byte_cursor *data,
    bool last_segment,
    bool *release_segment,
    void *user_data) {
    (void)last_segment;
    (void)user_data;
    *release_segment = true;
    AWS_HTTP_TEST_PRINT("%.*s", (int)data->len, data->ptr);

    if (last_segment) {
        aws_mutex_lock(&s_mutex);
        s_server_finished_getting_request = true;
        aws_condition_variable_notify_one(&s_cv);
        aws_mutex_unlock(&s_mutex);
        AWS_HTTP_TEST_PRINT("\n");
    }

    if (!s_body_data_init) {
        s_body_data = aws_byte_buf_from_array(s_body_data_memory, AWS_ARRAY_SIZE(s_body_data_memory));
        s_body_data.len = 0;
        s_body_data_init = true;
    }

    if (data->len) {
        struct aws_byte_cursor data_not_const = *data;
        aws_byte_buf_append(&s_body_data, &data_not_const);
    }
}

static void s_on_request_end(int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
}

void s_on_connection_created(struct aws_http_server_connection *connection, void *user_data) {
    (void)user_data;
    s_server_connection = connection;
    AWS_HTTP_TEST_PRINT("Server connection created.\n");
}

void s_on_connection_closed(struct aws_http_server_connection *connection, void *user_data) {
    (void)connection;
    (void)user_data;
    aws_mutex_lock(&s_mutex);
    s_server_connection = NULL;
    aws_condition_variable_notify_one(&s_cv);
    aws_mutex_unlock(&s_mutex);
    AWS_HTTP_TEST_PRINT("Server connection closed.\n");
}

static void s_on_connected(struct aws_http_client_connection *connection, void *user_data) {
    (void)user_data;
    s_client_connection = connection;
    AWS_HTTP_TEST_PRINT("Client connected.\n");

    aws_mutex_lock(&s_mutex);
    aws_condition_variable_notify_one(&s_cv);
    aws_mutex_unlock(&s_mutex);
}

static void s_on_disconnected(struct aws_http_client_connection *connection, void *user_data) {
    (void)connection;
    (void)user_data;
    aws_mutex_lock(&s_mutex);
    s_client_connection = NULL;
    aws_condition_variable_notify_one(&s_cv);
    aws_mutex_unlock(&s_mutex);
    AWS_HTTP_TEST_PRINT("Client disconnected.\n");
}

static void s_request_on_write_body_segment(
    struct aws_byte_buf *segment,
    bool *last_segment,
    void *user_data) {
    *last_segment = true;
    const char *body_data = (const char *)user_data;
    struct aws_byte_buf data = aws_byte_buf_from_c_str(body_data);
    segment->buffer = data.buffer;
    segment->len = data.len;
}

static void s_on_request_sent(int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
}

static void s_request_on_response(struct aws_http_client_connection *connection, enum aws_http_code code, void *user_data) {
    (void)connection;
    (void)user_data;
    AWS_HTTP_TEST_PRINT("Got response code: %d\n", (int)code);
    s_code = code;
}

static void s_request_on_response_header(
    enum aws_http_header_name header_name,
    const struct aws_http_header *header,
    void *user_data) {
    (void)header_name;
    (void)user_data;
    AWS_HTTP_TEST_PRINT(
        "Got response header: %.*s: %.*s\n",
        (int)header->name.len,
        header->name.ptr,
        (int)header->value.len,
        header->value.ptr);
    (void)header;
}

static void s_request_on_response_body_segment(
    const struct aws_byte_cursor *data,
    bool last_segment,
    bool *release_segment,
    void *user_data) {
    (void)last_segment;
    (void)user_data;
    *release_segment = true;
    AWS_HTTP_TEST_PRINT("%.*s", (int)data->len, data->ptr);
    (void)data;
}

static void s_request_on_request_completed(int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
    AWS_HTTP_TEST_PRINT("Request received a response and fully completed.\n");

    aws_mutex_lock(&s_mutex);
    s_client_received_response = true;
    aws_condition_variable_notify_one(&s_cv);
    aws_mutex_unlock(&s_mutex);
}

static void s_on_write_body_segment(
    struct aws_byte_buf *segment,
    bool *last_segment,
    void *user_data) {
    (void)segment;
    (void)user_data;
    *last_segment = true;
}

static void s_on_response_sent(int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
    AWS_HTTP_TEST_PRINT("Response sent.\n");
}

static int s_init_stuff(
    struct aws_allocator *allocator,
    struct aws_event_loop_group *el_group,
    struct aws_socket_options *socket_options,
    struct aws_socket_endpoint *endpoint,
    struct aws_tls_ctx_options *client_tls_ctx_options,
    struct aws_tls_ctx **client_tls_ctx,
    struct aws_tls_connection_options *tls_client_conn_options,
    struct aws_client_bootstrap *client_bootstrap,
    struct aws_tls_ctx_options *server_tls_ctx_options,
    struct aws_tls_ctx **server_tls_ctx,
    struct aws_tls_connection_options *tls_server_conn_options,
    struct aws_server_bootstrap *server_bootstrap) {
    aws_tls_init_static_state(allocator);

    ASSERT_SUCCESS(aws_event_loop_group_default_init(el_group, allocator, 2));

    AWS_ZERO_STRUCT(*socket_options);
    socket_options->connect_timeout_ms = 3000;
    socket_options->type = AWS_SOCKET_STREAM;
    socket_options->domain = AWS_SOCKET_LOCAL;

    AWS_ZERO_STRUCT(*endpoint);
    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));
    sprintf(endpoint->address, "testsock%llu.sock", (long long unsigned)timestamp);

    /* Client io setup. */
    aws_tls_ctx_options_init_default_client(client_tls_ctx_options);
    aws_tls_ctx_options_override_default_trust_store(client_tls_ctx_options, NULL, "./unittests.crt");
    *client_tls_ctx = aws_tls_client_ctx_new(allocator, client_tls_ctx_options);
    ASSERT_NOT_NULL(*client_tls_ctx);

    aws_tls_connection_options_init_from_ctx_options(tls_client_conn_options, client_tls_ctx_options);
    aws_tls_connection_options_set_server_name(tls_client_conn_options, "localhost");

    ASSERT_SUCCESS(aws_client_bootstrap_init(client_bootstrap, allocator, el_group));
    aws_client_bootstrap_set_tls_ctx(client_bootstrap, *client_tls_ctx);

    /* Server io setup. */
#ifdef __APPLE__
    aws_tls_ctx_options_init_server_pkcs12(server_tls_ctx_options, "./unittests.p12", "1234");
#else
    aws_tls_ctx_options_init_default_server(server_tls_ctx_options, "./unittests.crt", "./unittests.key");
#endif /* __APPLE__ */

    *server_tls_ctx = aws_tls_server_ctx_new(allocator, server_tls_ctx_options);
    ASSERT_NOT_NULL(*server_tls_ctx);

    aws_tls_connection_options_init_from_ctx_options(tls_server_conn_options, server_tls_ctx_options);

    ASSERT_SUCCESS(aws_server_bootstrap_init(server_bootstrap, allocator, el_group));
    ASSERT_SUCCESS(aws_server_bootstrap_set_tls_ctx(server_bootstrap, *server_tls_ctx));

    return AWS_OP_SUCCESS;
}

static void s_clean_up_stuff(
    struct aws_tls_ctx *client_tls_ctx,
    struct aws_tls_ctx *server_tls_ctx,
    struct aws_event_loop_group *el_group,
    struct aws_client_bootstrap *client_bootstrap,
    struct aws_server_bootstrap *server_bootstrap,
    struct aws_http_listener *server_listener) {
    aws_http_listener_destroy(server_listener);

    aws_client_bootstrap_clean_up(client_bootstrap);
    aws_server_bootstrap_clean_up(server_bootstrap);

    aws_event_loop_group_clean_up(el_group);
    aws_tls_ctx_destroy(client_tls_ctx);
    aws_tls_ctx_destroy(server_tls_ctx);
    aws_tls_clean_up_static_state();
}

static void s_reset_global_state_for_looped_predicates() {
    s_uri_len = 0;
    s_body_data.len = 0;
    s_server_finished_getting_request = false;
    s_client_received_response = false;
    s_header_count = 0;
}

AWS_TEST_CASE(http_test_connection, s_http_test_connection);
static int s_http_test_connection(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_event_loop_group el_group;
    struct aws_socket_options socket_options;
    struct aws_socket_endpoint endpoint;
    struct aws_tls_ctx_options client_tls_ctx_options;
    struct aws_tls_ctx *client_tls_ctx;
    struct aws_tls_connection_options tls_client_conn_options;
    struct aws_client_bootstrap client_bootstrap;
    struct aws_tls_ctx_options server_tls_ctx_options;
    struct aws_tls_ctx *server_tls_ctx;
    struct aws_tls_connection_options tls_server_conn_options;
    struct aws_server_bootstrap server_bootstrap;

    s_init_stuff(
        allocator,
        &el_group,
        &socket_options,
        &endpoint,
        &client_tls_ctx_options,
        &client_tls_ctx,
        &tls_client_conn_options,
        &client_bootstrap,
        &server_tls_ctx_options,
        &server_tls_ctx,
        &tls_server_conn_options,
        &server_bootstrap);

    /* Setup HTTP connections. */
    struct aws_http_server_callbacks server_callbacks;
    server_callbacks.on_connection_created = s_on_connection_created;
    server_callbacks.on_connection_closed = s_on_connection_closed;
    server_callbacks.write_response_callbacks.on_write_body_segment = s_on_write_body_segment;
    server_callbacks.write_response_callbacks.on_sent = s_on_response_sent;
    server_callbacks.on_request_callbacks.on_request = s_on_request;
    server_callbacks.on_request_callbacks.on_uri = s_on_uri;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_header = s_on_request_header;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_body_segment = s_on_request_body_segment;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_completed = s_on_request_end;

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
    ASSERT_NOT_NULL(server_listener);

    struct aws_http_client_callbacks client_callbacks;
    client_callbacks.on_connected = s_on_connected;
    client_callbacks.on_disconnected = s_on_disconnected;
    client_callbacks.write_request_callbacks.on_write_body_segment = s_request_on_write_body_segment;
    client_callbacks.write_request_callbacks.on_sent = s_on_request_sent;
    client_callbacks.on_response_callbacks.on_response = s_request_on_response;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_header = s_request_on_response_header;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_body_segment = s_request_on_response_body_segment;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_completed = s_request_on_request_completed;

    ASSERT_SUCCESS(aws_http_client_connect(
        allocator,
        &endpoint,
        &socket_options,
        &tls_client_conn_options,
        &client_bootstrap,
        1024,
        &client_callbacks,
        NULL));

    /* Wait for connection to complete setup. */
    aws_mutex_lock(&s_mutex);
    while (!s_client_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    /* Make 10 requests in a row (10 identical ones, just to test a little more end-to-end
     * than performing just a single request/response pair. */
    for (int i = 0; i < 10; ++i) {
        /* Make a request from the client. */
        const char *body_data = "The body data.";
        struct aws_http_header headers[] = {
            {.name = aws_byte_cursor_from_str("Host"), .value = aws_byte_cursor_from_str("amazon.com")},
            {.name = aws_byte_cursor_from_str("transfer-encoding"), .value = aws_byte_cursor_from_str("chunked")},
        };
        struct aws_byte_cursor uri = aws_byte_cursor_from_str("/");
        struct aws_http_request_def request_def;
        request_def.method = AWS_HTTP_METHOD_GET;
        request_def.uri = &uri;
        request_def.is_chunked = true;
        request_def.header_count = AWS_ARRAY_SIZE(headers);
        request_def.headers = headers;
        request_def.userdata = (void *)body_data;
        ASSERT_SUCCESS(aws_http_request_send(s_client_connection, &request_def));

        /* Wait for server to get request. */
        aws_mutex_lock(&s_mutex);
        while (!s_server_finished_getting_request) {
            aws_condition_variable_wait(&s_cv, &s_mutex);
        }
        aws_mutex_unlock(&s_mutex);

        /* Make a response from the server. */
        struct aws_http_response_def response_def;
        response_def.code = AWS_HTTP_CODE_OK;
        response_def.is_chunked = false;
        response_def.header_count = 0;
        response_def.headers = NULL;
        response_def.userdata = NULL;
        ASSERT_SUCCESS(aws_http_response_send(s_server_connection, &response_def));

        /* Wait for until entire response from the server is received and parsed. */
        aws_mutex_lock(&s_mutex);
        while (!s_client_received_response) {
            aws_condition_variable_wait(&s_cv, &s_mutex);
        }
        aws_mutex_unlock(&s_mutex);

        ASSERT_INT_EQUALS(AWS_HTTP_METHOD_GET, s_method);
        ASSERT_TRUE(!strncmp((char *)s_uri, "/", s_uri_len));
        struct aws_byte_cursor body_cursor = aws_byte_cursor_from_str("The body data.");
        ASSERT_BIN_ARRAYS_EQUALS(body_cursor.ptr, body_cursor.len, s_body_data.buffer, s_body_data.len);
        ASSERT_INT_EQUALS(AWS_HTTP_CODE_OK, s_code);
        ASSERT_INT_EQUALS(AWS_OP_SUCCESS, s_headers_ok);

        s_reset_global_state_for_looped_predicates();
    }

    /* Cleanup. */
    if (s_client_connection) {
        aws_http_client_connection_destroy(s_client_connection);
    }
    if (s_server_connection) {
        aws_http_server_connection_destroy(s_server_connection);
    }

    /* Wait until server finishes cleaning itself up. */
    aws_mutex_lock(&s_mutex);
    while (s_server_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    /* Wait until client finishes cleaning itself up. */
    aws_mutex_lock(&s_mutex);
    while (s_client_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    s_clean_up_stuff(client_tls_ctx, server_tls_ctx, &el_group, &client_bootstrap, &server_bootstrap, server_listener);

    ASSERT_PTR_EQUALS(NULL, s_server_connection);
    ASSERT_PTR_EQUALS(NULL, s_client_connection);

    return AWS_OP_SUCCESS;
}

static bool s_server_got_entire_request;

static void s_on_request_end_100_continue(int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
    aws_mutex_lock(&s_mutex);
    s_server_got_entire_request = true;
    aws_mutex_unlock(&s_mutex);
    AWS_HTTP_TEST_PRINT("Entire request received by server.\n");
}

static inline char s_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        c -= ('A' - 'a');
    }
    return c;
}

/* Works like memcmp or strcmp, except is case-agnostic. */
static inline int s_strcmp_case_insensitive(const char *a, size_t len_a, const char *b, size_t len_b) {
    if (len_a != len_b) {
        return 1;
    }

    for (size_t i = 0; i < len_a; ++i) {
        int d = s_lower(a[i]) - s_lower(b[i]);
        if (d) {
            return d;
        }
    }
    return 0;
}

static bool s_server_got_expect_100_continue;

static void s_on_request_header_100_continue(
    enum aws_http_header_name header_name,
    const struct aws_http_header *header,
    void *user_data) {
    (void)header_name;
    (void)header;
    (void)user_data;

    if (header_name == AWS_HTTP_HEADER_EXPECT) {
        if (!s_strcmp_case_insensitive((const char *)header->value.ptr, header->value.len, "100-continue", 12)) {
            aws_mutex_lock(&s_mutex);
            s_server_got_expect_100_continue = true;
            aws_mutex_unlock(&s_mutex);
            AWS_HTTP_TEST_PRINT("Server got the expect: 100-continue.\n");
        }
    }
}

static bool s_client_got_entire_response;

static void s_request_on_request_completed_100_continue(int error_code, void *user_data) {
    (void)user_data;

    aws_mutex_lock(&s_mutex);
    s_client_got_entire_response = true;
    aws_mutex_unlock(&s_mutex);
    AWS_HTTP_TEST_PRINT("Entire response received by client.\n");
}

AWS_TEST_CASE(http_test_100_continue, s_http_test_100_continue);
static int s_http_test_100_continue(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_event_loop_group el_group;
    struct aws_socket_options socket_options;
    struct aws_socket_endpoint endpoint;
    struct aws_tls_ctx_options client_tls_ctx_options;
    struct aws_tls_ctx *client_tls_ctx;
    struct aws_tls_connection_options tls_client_conn_options;
    struct aws_client_bootstrap client_bootstrap;
    struct aws_tls_ctx_options server_tls_ctx_options;
    struct aws_tls_ctx *server_tls_ctx;
    struct aws_tls_connection_options tls_server_conn_options;
    struct aws_server_bootstrap server_bootstrap;

    s_init_stuff(
        allocator,
        &el_group,
        &socket_options,
        &endpoint,
        &client_tls_ctx_options,
        &client_tls_ctx,
        &tls_client_conn_options,
        &client_bootstrap,
        &server_tls_ctx_options,
        &server_tls_ctx,
        &tls_server_conn_options,
        &server_bootstrap);

    /* Setup HTTP connections. */
    struct aws_http_server_callbacks server_callbacks;
    AWS_ZERO_STRUCT(server_callbacks);
    server_callbacks.on_connection_created = s_on_connection_created;
    server_callbacks.on_connection_closed = s_on_connection_closed;
    server_callbacks.on_request_callbacks.on_uri = s_on_uri;
    server_callbacks.on_request_callbacks.on_request = s_on_request;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_header = s_on_request_header_100_continue;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_body_segment = s_on_request_body_segment;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_completed = s_on_request_end_100_continue;
    server_callbacks.write_response_callbacks.on_write_body_segment = s_on_write_body_segment;
    server_callbacks.write_response_callbacks.on_sent = s_on_response_sent;
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
    ASSERT_NOT_NULL(server_listener);

    struct aws_http_client_callbacks client_callbacks;
    AWS_ZERO_STRUCT(client_callbacks);
    client_callbacks.on_connected = s_on_connected;
    client_callbacks.on_disconnected = s_on_disconnected;
    client_callbacks.on_response_callbacks.on_response = s_request_on_response;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_header = s_request_on_response_header;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_body_segment = s_request_on_response_body_segment;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_completed = s_request_on_request_completed_100_continue;
    client_callbacks.write_request_callbacks.on_write_body_segment = s_request_on_write_body_segment;
    client_callbacks.write_request_callbacks.on_sent = NULL;
    ASSERT_SUCCESS(aws_http_client_connect(
        allocator,
        &endpoint,
        &socket_options,
        &tls_client_conn_options,
        &client_bootstrap,
        1024,
        &client_callbacks,
        NULL));

    /* Wait for connection to complete setup. */
    aws_mutex_lock(&s_mutex);
    while (!s_client_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    /* Make 10 requests in a row (10 identical ones, just to test a little more end-to-end
     * than performing just a single request/response pair. */
    for (int i = 0; i < 10; ++i) {
        /* Make a request from the client. */
        const char *body_data = "Here's some body data for you! Hahaha.\n";
        struct aws_http_header headers[] = {
            {.name = aws_byte_cursor_from_str("Host"), .value = aws_byte_cursor_from_str("amazon.com")},
            {.name = aws_byte_cursor_from_str("transfer-encoding"), .value = aws_byte_cursor_from_str("chunked")},
            {.name = aws_byte_cursor_from_str("Expect"), .value = aws_byte_cursor_from_str("100-continue")},
        };
        struct aws_byte_cursor uri = aws_byte_cursor_from_str("/");
        struct aws_http_request_def request_def;
        request_def.method = AWS_HTTP_METHOD_GET;
        request_def.uri = &uri;
        request_def.header_count = AWS_ARRAY_SIZE(headers);
        request_def.headers = headers;
        request_def.userdata = (void *)body_data;
        request_def.is_chunked = true;
        ASSERT_SUCCESS(aws_http_request_send(s_client_connection, &request_def));

        /* Wait until server gets expect: 100-continue. */
        aws_mutex_lock(&s_mutex);
        while (!s_server_got_expect_100_continue) {
            aws_condition_variable_wait(&s_cv, &s_mutex);
        }
        aws_mutex_unlock(&s_mutex);

        /* Say yes to expectations. */
        struct aws_http_response_def response_def;
        response_def.code = AWS_HTTP_CODE_CONTINUE;
        response_def.header_count = 0;
        response_def.headers = NULL;
        response_def.userdata = NULL;
        response_def.is_chunked = false;
        ASSERT_SUCCESS(aws_http_response_send(s_server_connection, &response_def));

        /* Wait for body data from client. */
        aws_mutex_lock(&s_mutex);
        while (!s_server_got_entire_request) {
            aws_condition_variable_wait(&s_cv, &s_mutex);
        }
        aws_mutex_unlock(&s_mutex);

        /* Confirm to client the full request was received. */
        response_def.code = AWS_HTTP_CODE_OK;
        response_def.header_count = 0;
        response_def.headers = NULL;
        response_def.userdata = NULL;
        response_def.is_chunked = false;
        ASSERT_SUCCESS(aws_http_response_send(s_server_connection, &response_def));

        /* Wait for until entire response from the server is received and parsed by the client. */
        aws_mutex_lock(&s_mutex);
        while (!s_client_got_entire_response) {
            aws_condition_variable_wait(&s_cv, &s_mutex);
        }
        aws_mutex_unlock(&s_mutex);

        ASSERT_INT_EQUALS(AWS_HTTP_METHOD_GET, s_method);
        ASSERT_TRUE(!strncmp((char *)s_uri, "/", s_uri_len));
        struct aws_byte_cursor body_cursor = aws_byte_cursor_from_str("Here's some body data for you! Hahaha.\n");
        ASSERT_BIN_ARRAYS_EQUALS(body_cursor.ptr, body_cursor.len, s_body_data.buffer, s_body_data.len);
        ASSERT_INT_EQUALS(AWS_HTTP_CODE_OK, s_code);

        s_reset_global_state_for_looped_predicates();
        s_server_got_entire_request = false;
        s_server_got_expect_100_continue = false;
        s_client_got_entire_response = false;
    }

    /* Cleanup. */
    if (s_client_connection) {
        aws_http_client_connection_destroy(s_client_connection);
    }
    if (s_server_connection) {
        aws_http_server_connection_destroy(s_server_connection);
    }

    /* Wait until server finishes cleaning itself up. */
    aws_mutex_lock(&s_mutex);
    while (s_server_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    /* Wait until client finishes cleaning itself up. */
    aws_mutex_lock(&s_mutex);
    while (s_client_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    s_clean_up_stuff(client_tls_ctx, server_tls_ctx, &el_group, &client_bootstrap, &server_bootstrap, server_listener);

    ASSERT_PTR_EQUALS(NULL, s_server_connection);
    ASSERT_PTR_EQUALS(NULL, s_client_connection);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(http_test_100_continue_failed_expectations, s_http_test_100_continue_failed_expectations);
static int s_http_test_100_continue_failed_expectations(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_event_loop_group el_group;
    struct aws_socket_options socket_options;
    struct aws_socket_endpoint endpoint;
    struct aws_tls_ctx_options client_tls_ctx_options;
    struct aws_tls_ctx *client_tls_ctx;
    struct aws_tls_connection_options tls_client_conn_options;
    struct aws_client_bootstrap client_bootstrap;
    struct aws_tls_ctx_options server_tls_ctx_options;
    struct aws_tls_ctx *server_tls_ctx;
    struct aws_tls_connection_options tls_server_conn_options;
    struct aws_server_bootstrap server_bootstrap;

    s_init_stuff(
        allocator,
        &el_group,
        &socket_options,
        &endpoint,
        &client_tls_ctx_options,
        &client_tls_ctx,
        &tls_client_conn_options,
        &client_bootstrap,
        &server_tls_ctx_options,
        &server_tls_ctx,
        &tls_server_conn_options,
        &server_bootstrap);

    /* Setup HTTP connections. */
    struct aws_http_server_callbacks server_callbacks;
    AWS_ZERO_STRUCT(server_callbacks);
    server_callbacks.on_connection_created = s_on_connection_created;
    server_callbacks.on_connection_closed = s_on_connection_closed;
    server_callbacks.on_request_callbacks.on_uri = s_on_uri;
    server_callbacks.on_request_callbacks.on_request = s_on_request;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_header = s_on_request_header_100_continue;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_body_segment = s_on_request_body_segment;
    server_callbacks.on_request_callbacks.on_message_callbacks.on_completed = s_on_request_end_100_continue;
    server_callbacks.write_response_callbacks.on_write_body_segment = s_on_write_body_segment;
    server_callbacks.write_response_callbacks.on_sent = s_on_response_sent;

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
    ASSERT_NOT_NULL(server_listener);

    struct aws_http_client_callbacks client_callbacks;
    AWS_ZERO_STRUCT(client_callbacks);
    client_callbacks.on_connected = s_on_connected;
    client_callbacks.on_disconnected = s_on_disconnected;
    client_callbacks.on_response_callbacks.on_response = s_request_on_response;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_header = s_request_on_response_header;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_body_segment = s_request_on_response_body_segment;
    client_callbacks.on_response_callbacks.on_message_callbacks.on_completed = s_request_on_request_completed_100_continue;
    client_callbacks.write_request_callbacks.on_write_body_segment = s_request_on_write_body_segment;
    client_callbacks.write_request_callbacks.on_sent = NULL;
    ASSERT_SUCCESS(aws_http_client_connect(
        allocator,
        &endpoint,
        &socket_options,
        &tls_client_conn_options,
        &client_bootstrap,
        1024,
        &client_callbacks,
        NULL));

    /* Wait for connection to complete setup. */
    aws_mutex_lock(&s_mutex);
    while (!s_client_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    /* Make a request from the client. */
    const char *body_data = "This message will never see the light of day.";
    struct aws_http_header headers[] = {
        {.name = aws_byte_cursor_from_str("Host"), .value = aws_byte_cursor_from_str("amazon.com")},
        {.name = aws_byte_cursor_from_str("transfer-encoding"), .value = aws_byte_cursor_from_str("chunked")},
        {.name = aws_byte_cursor_from_str("Expect"), .value = aws_byte_cursor_from_str("100-continue")},
    };
    struct aws_byte_cursor uri = aws_byte_cursor_from_str("/");
    struct aws_http_request_def request_def;
    request_def.method = AWS_HTTP_METHOD_GET;
    request_def.uri = &uri;
    request_def.header_count = AWS_ARRAY_SIZE(headers);
    request_def.headers = headers;
    request_def.userdata = (void *)body_data;
    request_def.is_chunked = true;
    ASSERT_SUCCESS(aws_http_request_send(s_client_connection, &request_def));

    /* Wait until server gets expect: 100-continue. */
    aws_mutex_lock(&s_mutex);
    while (!s_server_got_expect_100_continue) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    /* Say no to expectations. */
    struct aws_http_response_def response_def;
    response_def.code = AWS_HTTP_CODE_EXPECTATION_FAILED;
    response_def.header_count = 0;
    response_def.headers = NULL;
    response_def.userdata = NULL;
    response_def.is_chunked = false;
    ASSERT_SUCCESS(aws_http_response_send(s_server_connection, &response_def));

    /* Wait for until entire response from the server is received and parsed by the client. */
    aws_mutex_lock(&s_mutex);
    while (!s_client_got_entire_response) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    /* Cleanup. */
    if (s_client_connection) {
        aws_http_client_connection_destroy(s_client_connection);
    }
    if (s_server_connection) {
        aws_http_server_connection_destroy(s_server_connection);
    }

    /* Wait until server finishes cleaning itself up. */
    aws_mutex_lock(&s_mutex);
    while (s_server_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    /* Wait until client finishes cleaning itself up. */
    aws_mutex_lock(&s_mutex);
    while (s_client_connection) {
        aws_condition_variable_wait(&s_cv, &s_mutex);
    }
    aws_mutex_unlock(&s_mutex);

    s_clean_up_stuff(client_tls_ctx, server_tls_ctx, &el_group, &client_bootstrap, &server_bootstrap, server_listener);

    ASSERT_PTR_EQUALS(NULL, s_server_connection);
    ASSERT_PTR_EQUALS(NULL, s_client_connection);
    ASSERT_INT_EQUALS(AWS_HTTP_METHOD_GET, s_method);
    ASSERT_TRUE(!strncmp((char *)s_uri, "/", s_uri_len));
    ASSERT_INT_EQUALS(0, s_body_data.len);
    ASSERT_INT_EQUALS(0, s_code);

    return AWS_OP_SUCCESS;
}
