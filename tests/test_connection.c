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

#include <aws/common/uuid.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/testing/aws_test_harness.h>

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_FORMAT "\\\\.\\pipe\\testsock-%s"
#else
#    define LOCAL_SOCK_TEST_FORMAT "testsock-%s.sock"
#endif

static void s_void_on_incoming_connection_fn(
    struct aws_http_server *server,
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {

    (void)server;
    (void)connection;
    (void)error_code;
    (void)user_data;
}

static int s_test_server_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_event_loop_group event_loop_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&event_loop_group, allocator, 1));

    struct aws_server_bootstrap *bootstrap = aws_server_bootstrap_new(allocator, &event_loop_group);
    ASSERT_NOT_NULL(bootstrap);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_LOCAL,
        .connect_timeout_ms = 1000,
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

    struct aws_http_server_options options = {
        .self_size = sizeof(options),
        .allocator = allocator,
        .bootstrap = bootstrap,
        .endpoint = &endpoint,
        .socket_options = &socket_options,
        .on_incoming_connection = s_void_on_incoming_connection_fn,
    };

    struct aws_http_server *server = aws_http_server_new(&options);
    ASSERT_NOT_NULL(server);

    aws_http_server_destroy(server);
    aws_server_bootstrap_destroy(bootstrap);
    aws_event_loop_group_clean_up(&event_loop_group);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(server_new_destroy, s_test_server_new_destroy);
