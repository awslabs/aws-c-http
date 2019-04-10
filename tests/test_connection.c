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
#include <aws/common/uuid.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/log_writer.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_FORMAT "\\\\.\\pipe\\testsock-%s"
#else
#    define LOCAL_SOCK_TEST_FORMAT "testsock-%s.sock"
#endif

enum {
    TESTER_TIMEOUT_SEC = 60, /* Give enough time for non-sudo users to enter password */
};

/* Options for setting up `tester` singleton */
struct tester_options {
    struct aws_allocator *alloc;
    bool no_connection; /* don't connect server to client */
};

/* Singleton used by tests in this file */
struct tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;
    struct aws_event_loop_group event_loop_group;
    struct aws_host_resolver host_resolver;
    struct aws_server_bootstrap *server_bootstrap;
    struct aws_http_server *server;
    struct aws_client_bootstrap *client_bootstrap;

    struct aws_http_connection *server_connection;
    struct aws_http_connection *client_connection;

    bool client_connection_is_shutdown;
    bool server_connection_is_shutdown;

    /* If we need to wait for some async process*/
    struct aws_mutex wait_lock;
    struct aws_condition_variable wait_cvar;
    int wait_result;
};

static void s_tester_on_incoming_request(struct aws_http_connection *connection, void *user_data) {
    (void)connection;
    (void)user_data;
}

static void s_tester_on_server_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    (void)connection;
    (void)error_code;
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->server_connection_is_shutdown = true;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static void s_tester_on_server_connection_setup(
    struct aws_http_server *server,
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    (void)server;
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    if (error_code) {
        tester->wait_result = error_code;
        goto done;
    }

    struct aws_http_server_connection_options options = AWS_HTTP_SERVER_CONNECTION_OPTIONS_INIT;
    options.connection_user_data = tester;
    options.on_incoming_request = s_tester_on_incoming_request;
    options.on_shutdown = s_tester_on_server_connection_shutdown;

    int err = aws_http_connection_configure_server(connection, &options);
    if (err) {
        tester->wait_result = aws_last_error();
        goto done;
    }

    tester->server_connection = connection;
done:
    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

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
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &tester->wait_cvar,
        &tester->wait_lock,
        aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL),
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
    return tester->wait_result || (tester->client_connection && tester->server_connection);
}

static bool s_tester_connection_shutdown_pred(void *user_data) {
    struct tester *tester = user_data;
    return tester->wait_result || (tester->client_connection_is_shutdown && tester->server_connection_is_shutdown);
}

static int s_tester_init(struct tester *tester, const struct tester_options *options) {
    AWS_ZERO_STRUCT(*tester);

    tester->alloc = options->alloc;

    aws_load_error_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();

    aws_http_library_init(options->alloc);

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
    tester->server_bootstrap = aws_server_bootstrap_new(tester->alloc, &tester->event_loop_group);
    ASSERT_NOT_NULL(tester->server_bootstrap);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_LOCAL,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };

    /* Generate random address for endpoint */
    struct aws_uuid uuid;
    ASSERT_SUCCESS(aws_uuid_init(&uuid));
    char uuid_str[AWS_UUID_STR_LEN];
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_empty_array(uuid_str, sizeof(uuid_str));
    ASSERT_SUCCESS(aws_uuid_to_str(&uuid, &uuid_buf));
    struct aws_socket_endpoint endpoint;
    AWS_ZERO_STRUCT(endpoint);

    snprintf(endpoint.address, sizeof(endpoint.address), LOCAL_SOCK_TEST_FORMAT, uuid_str);

    /* Create server (listening socket) */
    struct aws_http_server_options server_options = AWS_HTTP_SERVER_OPTIONS_INIT;
    server_options.allocator = tester->alloc;
    server_options.bootstrap = tester->server_bootstrap;
    server_options.endpoint = &endpoint;
    server_options.socket_options = &socket_options;
    server_options.server_user_data = tester;
    server_options.on_incoming_connection = s_tester_on_server_connection_setup;

    tester->server = aws_http_server_new(&server_options);
    ASSERT_NOT_NULL(tester->server);

    /* If test doesn't need a connection, we're done setting up. */
    if (options->no_connection) {
        return AWS_OP_SUCCESS;
    }

    tester->client_bootstrap =
        aws_client_bootstrap_new(tester->alloc, &tester->event_loop_group, &tester->host_resolver, NULL);
    ASSERT_NOT_NULL(tester->client_bootstrap);

    /* Connect */
    struct aws_http_client_connection_options client_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    client_options.allocator = tester->alloc;
    client_options.bootstrap = tester->client_bootstrap;
    client_options.host_name = aws_byte_cursor_from_c_str(endpoint.address);
    client_options.port = endpoint.port;
    client_options.socket_options = &socket_options;
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
        aws_http_connection_release(tester->server_connection);

        ASSERT_SUCCESS(s_tester_wait(tester, s_tester_connection_shutdown_pred));

        aws_client_bootstrap_release(tester->client_bootstrap);
    }

    aws_http_server_destroy(tester->server);
    aws_server_bootstrap_release(tester->server_bootstrap);
    aws_host_resolver_clean_up(&tester->host_resolver);
    aws_event_loop_group_clean_up(&tester->event_loop_group);
    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);

    return AWS_OP_SUCCESS;
}

static int s_test_server_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct tester_options options = {
        .alloc = allocator,
        .no_connection = true,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(server_new_destroy, s_test_server_new_destroy);

static int s_test_connection_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct tester_options options = {
        .alloc = allocator,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(connection_setup_shutdown, s_test_connection_setup_shutdown);
