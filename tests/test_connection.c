/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>
#include <aws/http/private/connection_impl.h>
#include <aws/http/server.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/log_writer.h>
#include <aws/common/thread.h>
#include <aws/common/uuid.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
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
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;
    struct aws_server_bootstrap *server_bootstrap;
    struct aws_http_server *server;
    struct aws_client_bootstrap *client_bootstrap;
    struct aws_http_client_connection_options client_options;

    int server_connection_num;
    int client_connection_num;
    int wait_server_connection_num;
    int wait_client_connection_num;
    struct aws_http_connection *server_connections[10];
    struct aws_http_connection *client_connections[10];

    struct aws_socket_endpoint endpoint;
    struct aws_socket_options socket_options;

    int client_connection_is_shutdown;
    int server_connection_is_shutdown;
    int wait_client_connection_is_shutdown;
    int wait_server_connection_is_shutdown;

    bool server_is_shutdown;
    struct aws_http_connection *new_client_connection;
    bool new_client_shut_down;
    bool new_client_setup_finished;

    /* If we need to wait for some async process*/
    struct aws_mutex wait_lock;
    struct aws_condition_variable wait_cvar;
    /* we need wait result for both server side and client side */
    int server_wait_result;
    int client_wait_result;
};

static struct aws_http_stream *s_tester_on_incoming_request(struct aws_http_connection *connection, void *user_data) {
    (void)connection;
    (void)user_data;
    aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
    return NULL;
}

static void s_tester_http_server_on_destroy(void *user_data) {
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);
    tester->server_is_shutdown = true;
    tester->server = NULL;
    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static void s_tester_on_server_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    (void)connection;
    (void)error_code;
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->server_connection_is_shutdown++;

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
        tester->server_wait_result = error_code;
        goto done;
    }

    struct aws_http_server_connection_options options = AWS_HTTP_SERVER_CONNECTION_OPTIONS_INIT;
    options.connection_user_data = tester;
    options.on_incoming_request = s_tester_on_incoming_request;
    options.on_shutdown = s_tester_on_server_connection_shutdown;

    int err = aws_http_connection_configure_server(connection, &options);
    if (err) {
        tester->server_wait_result = aws_last_error();
        goto done;
    }

    tester->server_connections[tester->server_connection_num++] = connection;
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
        tester->client_wait_result = error_code;
        goto done;
    }

    tester->client_connections[tester->client_connection_num++] = connection;
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

    tester->client_connection_is_shutdown++;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static int s_tester_wait(struct tester *tester, bool (*pred)(void *user_data)) {
    int local_wait_result;
    ASSERT_SUCCESS(aws_mutex_lock(&tester->wait_lock));
    int err = aws_condition_variable_wait_for_pred(
        &tester->wait_cvar,
        &tester->wait_lock,
        aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL),
        pred,
        tester);
    if (tester->server_wait_result) {
        local_wait_result = tester->server_wait_result;
    } else {
        local_wait_result = tester->client_wait_result;
    }
    tester->server_wait_result = 0;
    tester->client_wait_result = 0;
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->wait_lock));
    ASSERT_SUCCESS(err);
    if (local_wait_result) {
        return aws_raise_error(local_wait_result);
    }
    return AWS_OP_SUCCESS;
}

static bool s_tester_connection_setup_pred(void *user_data) {
    struct tester *tester = user_data;
    return (tester->server_wait_result || tester->client_wait_result) ||
           (tester->client_connection_num == tester->wait_client_connection_num &&
            tester->server_connection_num == tester->wait_server_connection_num);
}

static bool s_tester_connection_shutdown_pred(void *user_data) {
    struct tester *tester = user_data;
    return (tester->server_wait_result || tester->client_wait_result) ||
           (tester->client_connection_is_shutdown == tester->wait_client_connection_is_shutdown &&
            tester->server_connection_is_shutdown == tester->wait_server_connection_is_shutdown);
}

static bool s_tester_server_shutdown_pred(void *user_data) {
    struct tester *tester = user_data;
    return tester->server_is_shutdown;
}

static int s_tester_init(struct tester *tester, const struct tester_options *options) {
    AWS_ZERO_STRUCT(*tester);

    tester->alloc = options->alloc;

    aws_http_library_init(options->alloc);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    ASSERT_SUCCESS(aws_logger_init_standard(&tester->logger, tester->alloc, &logger_options));
    aws_logger_set(&tester->logger);

    ASSERT_SUCCESS(aws_mutex_init(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&tester->wait_cvar));

    tester->event_loop_group = aws_event_loop_group_new_default(tester->alloc, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = tester->event_loop_group,
        .max_entries = 8,
    };

    tester->host_resolver = aws_host_resolver_new_default(tester->alloc, &resolver_options);
    tester->server_bootstrap = aws_server_bootstrap_new(tester->alloc, tester->event_loop_group);
    ASSERT_NOT_NULL(tester->server_bootstrap);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_LOCAL,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };
    tester->socket_options = socket_options;
    /* Generate random address for endpoint */
    struct aws_uuid uuid;
    ASSERT_SUCCESS(aws_uuid_init(&uuid));
    char uuid_str[AWS_UUID_STR_LEN];
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_empty_array(uuid_str, sizeof(uuid_str));
    ASSERT_SUCCESS(aws_uuid_to_str(&uuid, &uuid_buf));
    struct aws_socket_endpoint endpoint;
    AWS_ZERO_STRUCT(endpoint);

    snprintf(endpoint.address, sizeof(endpoint.address), LOCAL_SOCK_TEST_FORMAT, uuid_str);
    tester->endpoint = endpoint;
    /* Create server (listening socket) */
    struct aws_http_server_options server_options = AWS_HTTP_SERVER_OPTIONS_INIT;
    server_options.allocator = tester->alloc;
    server_options.bootstrap = tester->server_bootstrap;
    server_options.endpoint = &tester->endpoint;
    server_options.socket_options = &tester->socket_options;
    server_options.server_user_data = tester;
    server_options.on_incoming_connection = s_tester_on_server_connection_setup;
    server_options.on_destroy_complete = s_tester_http_server_on_destroy;

    tester->server = aws_http_server_new(&server_options);
    ASSERT_NOT_NULL(tester->server);

    /* If test doesn't need a connection, we're done setting up. */
    if (options->no_connection) {
        return AWS_OP_SUCCESS;
    }

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = tester->event_loop_group,
        .host_resolver = tester->host_resolver,
    };
    tester->client_bootstrap = aws_client_bootstrap_new(tester->alloc, &bootstrap_options);
    ASSERT_NOT_NULL(tester->client_bootstrap);

    /* Connect */
    struct aws_http_client_connection_options client_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    tester->client_options = client_options;
    tester->client_options.allocator = tester->alloc;
    tester->client_options.bootstrap = tester->client_bootstrap;
    tester->client_options.host_name = aws_byte_cursor_from_c_str(tester->endpoint.address);
    tester->client_options.port = tester->endpoint.port;
    tester->client_options.socket_options = &tester->socket_options;
    tester->client_options.user_data = tester;
    tester->client_options.on_setup = s_tester_on_client_connection_setup;
    tester->client_options.on_shutdown = s_tester_on_client_connection_shutdown;

    tester->server_connection_num = 0;
    tester->client_connection_num = 0;
    ASSERT_SUCCESS(aws_http_client_connect(&tester->client_options));

    /* Wait for server & client connections to finish setup */
    tester->wait_client_connection_num = 1;
    tester->wait_server_connection_num = 1;
    ASSERT_SUCCESS(s_tester_wait(tester, s_tester_connection_setup_pred));

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    if (tester->server) {
        /* server is not shut down by test, let's shut down the server here */
        aws_http_server_release(tester->server);
        /* wait for the server to finish shutdown process */
        ASSERT_SUCCESS(s_tester_wait(tester, s_tester_server_shutdown_pred));
    }
    aws_server_bootstrap_release(tester->server_bootstrap);
    aws_client_bootstrap_release(tester->client_bootstrap);
    aws_host_resolver_release(tester->host_resolver);
    aws_event_loop_group_release(tester->event_loop_group);

    aws_http_library_clean_up();
    aws_logger_clean_up(&tester->logger);
    aws_mutex_clean_up(&tester->wait_lock);

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

void release_all_client_connections(struct tester *tester) {
    for (int i = 0; i < tester->client_connection_num; i++) {
        aws_http_connection_release(tester->client_connections[i]);
    }
    /* wait for all the connections to shutdown */
    tester->wait_client_connection_is_shutdown = tester->client_connection_num;
}

void release_all_server_connections(struct tester *tester) {
    for (int i = 0; i < tester->server_connection_num; i++) {
        aws_http_connection_release(tester->server_connections[i]);
    }
    /* wait for all the connections to shutdown */
    tester->wait_server_connection_is_shutdown = tester->server_connection_num;
}

static int s_test_connection_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct tester_options options = {
        .alloc = allocator,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    release_all_client_connections(&tester);
    release_all_server_connections(&tester);
    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_connection_shutdown_pred));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(connection_setup_shutdown, s_test_connection_setup_shutdown);

static int s_test_connection_destroy_server_with_connection_existing(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct tester_options options = {
        .alloc = allocator,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    aws_http_server_release(tester.server);
    /* wait for all connections to be shut down */
    tester.wait_client_connection_is_shutdown = tester.client_connection_num;
    tester.wait_server_connection_is_shutdown = tester.server_connection_num;
    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_connection_shutdown_pred));

    /* check the server is destroyed */
    ASSERT_TRUE(tester.server_is_shutdown);
    /* release memory */
    release_all_client_connections(&tester);
    release_all_server_connections(&tester);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    connection_destroy_server_with_connection_existing,
    s_test_connection_destroy_server_with_connection_existing);

/* multiple connections */
static int s_test_connection_destroy_server_with_multiple_connections_existing(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct tester_options options = {
        .alloc = allocator,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    /* more connections! */
    int more_connection_num = 1;
    /* set waiting condition */
    tester.wait_client_connection_num += more_connection_num;
    tester.wait_server_connection_num += more_connection_num;
    /* connect */
    for (int i = 0; i < more_connection_num; i++) {
        ASSERT_SUCCESS(aws_http_client_connect(&tester.client_options));
    }
    /* wait for connections */
    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_connection_setup_pred));

    aws_http_server_release(tester.server);
    /* wait for all connections to be shut down */
    tester.wait_client_connection_is_shutdown = tester.client_connection_num;
    tester.wait_server_connection_is_shutdown = tester.server_connection_num;
    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_connection_shutdown_pred));

    /* check the server is destroyed */
    ASSERT_TRUE(tester.server_is_shutdown);
    /* release memory */
    release_all_client_connections(&tester);
    release_all_server_connections(&tester);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    connection_destroy_server_with_multiple_connections_existing,
    s_test_connection_destroy_server_with_multiple_connections_existing);

static void s_block_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    /* sleep for 2 sec */
    struct tester *tester = arg;
    aws_thread_current_sleep(2000000000);
    aws_mem_release(tester->alloc, task);
}

static void s_tester_on_new_client_connection_setup(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);
    tester->new_client_setup_finished = true;
    if (error_code) {
        tester->client_wait_result = error_code;
        goto done;
    }
    tester->new_client_connection = connection;
done:
    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static void s_tester_on_new_client_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    (void)connection;
    (void)error_code;
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->new_client_shut_down = true;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static bool s_tester_new_client_setup_pred(void *user_data) {
    struct tester *tester = user_data;
    return tester->new_client_setup_finished;
}

static bool s_tester_new_client_shutdown_pred(void *user_data) {
    struct tester *tester = user_data;
    return tester->new_client_shut_down;
}

/* when we shutdown the server, no more new connection will be accepted */
static int s_test_connection_server_shutting_down_new_connection_setup_fail(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct tester_options options = {
        .alloc = allocator,
    };
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, &options));

    /* Connect */
    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_LOCAL,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };
    /* create a new eventloop for the new connection and block the new connection. Waiting server to begin shutting
     * down. */
    struct aws_event_loop_group *event_loop_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    /* get the first eventloop, which will be the eventloop for client to connect */
    struct aws_event_loop *current_eventloop = aws_event_loop_group_get_loop_at(event_loop_group, 0);
    struct aws_task *block_task = aws_mem_acquire(allocator, sizeof(struct aws_task));
    aws_task_init(block_task, s_block_task, &tester, "wait_a_bit");
    aws_event_loop_schedule_task_now(current_eventloop, block_task);

    /* get the first eventloop of tester, which will be the eventloop for server listener socket, block the listener
     * socket */
    struct aws_event_loop *server_eventloop = aws_event_loop_group_get_loop_at(tester.event_loop_group, 0);
    struct aws_task *server_block_task = aws_mem_acquire(allocator, sizeof(struct aws_task));
    aws_task_init(server_block_task, s_block_task, &tester, "wait_a_bit");
    aws_event_loop_schedule_task_now(server_eventloop, server_block_task);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = event_loop_group,
        .host_resolver = tester.host_resolver,
    };
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    struct aws_http_client_connection_options client_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    client_options.allocator = tester.alloc;
    client_options.bootstrap = bootstrap;
    client_options.host_name = aws_byte_cursor_from_c_str(tester.endpoint.address);
    client_options.port = tester.endpoint.port;
    client_options.socket_options = &socket_options;
    client_options.user_data = &tester;
    client_options.on_setup = s_tester_on_new_client_connection_setup;
    client_options.on_shutdown = s_tester_on_new_client_connection_shutdown;

    /* new connection will be blocked for 2 sec */
    tester.wait_server_connection_num++;
    ASSERT_SUCCESS(aws_http_client_connect(&client_options));

    /* shutting down the server */
    aws_http_server_release(tester.server);
    /* the server side connection failed with error code, closed */
    ASSERT_FAILS(s_tester_wait(&tester, s_tester_connection_setup_pred));
    /* wait for the client side connection */
    s_tester_wait(&tester, s_tester_new_client_setup_pred);

    if (tester.new_client_connection && !tester.client_connection_is_shutdown) {
        /* wait for it to shut down, we do not need to call shut down, the socket will know */
        ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_new_client_shutdown_pred));
    }

    if (tester.new_client_connection) {
        aws_http_connection_release(tester.new_client_connection);
    }

    /* wait for the old connections to be shut down */
    tester.wait_client_connection_is_shutdown = tester.client_connection_num;
    tester.wait_server_connection_is_shutdown = tester.server_connection_num;
    /* assert the new connection fail to set up in user's perspective */
    ASSERT_TRUE(tester.client_connection_num == 1);
    ASSERT_TRUE(tester.server_connection_num == 1);
    ASSERT_SUCCESS(s_tester_wait(&tester, s_tester_connection_shutdown_pred));

    /* release memory */
    release_all_client_connections(&tester);
    release_all_server_connections(&tester);
    aws_client_bootstrap_release(bootstrap);
    aws_event_loop_group_release(event_loop_group);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    connection_server_shutting_down_new_connection_setup_fail,
    s_test_connection_server_shutting_down_new_connection_setup_fail);
