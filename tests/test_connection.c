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

#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/socket_channel_handler.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/testing/aws_test_harness.h>

#include <mach-o/dyld.h>
#include <unistd.h>

bool s_on_header_stub(
    enum aws_http_header_name name,
    const struct aws_byte_cursor *name_str,
    const struct aws_byte_cursor *value_str,
    void *user_data) {
    (void)name;
    (void)name_str;
    (void)value_str;
    (void)user_data;
    return true;
}

bool s_on_body_stub(const struct aws_byte_cursor *data, bool last_segment, void *user_data) {
    (void)data;
    (void)last_segment;
    (void)user_data;
    return true;
}

/* Embed unit test crt in */

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
    struct aws_http_connection_callbacks callbacks;

    struct aws_http_connection *server_connection = aws_http_server_connection_new(
        allocator, &endpoint, &socket_options, &tls_server_conn_options, &server_bootstrap, &callbacks, 1024, NULL);
    (void)server_connection;

    struct aws_http_connection *client_connection = aws_http_client_connection_new(
        allocator, &endpoint, &socket_options, &tls_client_conn_options, &client_bootstrap, &callbacks, 1024, NULL);
    (void)client_connection;

    /* Cleanup. */

    aws_client_bootstrap_clean_up(&client_bootstrap);
    aws_event_loop_group_clean_up(&el_group);
    aws_tls_ctx_destroy(client_tls_ctx);
    aws_tls_clean_up_static_state();

    return AWS_OP_SUCCESS;
}
