/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>

#include <aws/http/private/connection_impl.h>
#include <aws/http/private/h1_stream.h>
#include <aws/http/private/proxy_impl.h>

#include <aws/io/uri.h>

#include <aws/common/string.h>

#include <aws/testing/aws_test_harness.h>
#include <aws/testing/io_testing_channel.h>

#include "proxy_test_helper.h"

static struct proxy_tester tester;

static char *s_host_name = "aws.amazon.com";
static uint16_t s_port = 80;
static char *s_proxy_host_name = "www.myproxy.hmm";
static uint16_t s_proxy_port = 777;

AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_method, "GET");
AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_path, "/");
AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_host, "aws.amazon.com");
AWS_STATIC_STRING_FROM_LITERAL(s_expected_auth_header_name, "Proxy-Authorization");
AWS_STATIC_STRING_FROM_LITERAL(s_expected_auth_header_value, "Basic U29tZVVzZXI6U3VwZXJTZWNyZXQ=");
AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_username, "SomeUser");
AWS_STATIC_STRING_FROM_LITERAL(s_mock_request_password, "SuperSecret");

/*
 * Request utility functions
 */
struct aws_http_message *s_build_dummy_http_request(
    struct aws_allocator *allocator,
    struct aws_byte_cursor method,
    struct aws_byte_cursor path,
    struct aws_byte_cursor host) {

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    aws_http_message_set_request_method(request, method);
    aws_http_message_set_request_path(request, path);

    struct aws_http_header host_header = {
        .name = aws_byte_cursor_from_c_str("Host"),
        .value = host,
    };
    aws_http_message_add_header(request, host_header);

    struct aws_http_header accept_header = {
        .name = aws_byte_cursor_from_c_str("Accept"),
        .value = aws_byte_cursor_from_c_str("*/*"),
    };
    aws_http_message_add_header(request, accept_header);

    return request;
}

static struct aws_http_message *s_build_http_request(struct aws_allocator *allocator) {
    return s_build_dummy_http_request(
        allocator,
        aws_byte_cursor_from_string(s_mock_request_method),
        aws_byte_cursor_from_string(s_mock_request_path),
        aws_byte_cursor_from_string(s_mock_request_host));
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

/*
 * TLS mock and vtable
 */
static int s_test_proxy_setup_client_tls(
    struct aws_channel_slot *right_of_slot,
    struct aws_tls_connection_options *tls_options) {

    (void)right_of_slot;

    if (tester.failure_type == PTFT_TLS_NEGOTIATION) {
        tls_options->on_negotiation_result(NULL, NULL, AWS_ERROR_UNKNOWN, tls_options->user_data);
    } else {
        tls_options->on_negotiation_result(NULL, NULL, AWS_ERROR_SUCCESS, tls_options->user_data);
    }

    return AWS_OP_SUCCESS;
}

struct aws_http_proxy_system_vtable s_proxy_table_for_tls = {
    .setup_client_tls = s_test_proxy_setup_client_tls,
};

/*
 * Channel setup mock and vtable
 */
static int s_test_aws_proxy_new_socket_channel(struct aws_socket_channel_bootstrap_options *channel_options) {

    aws_mutex_lock(&tester.wait_lock);

    /*
     * Record where we were trying to connect to
     */
    struct aws_byte_cursor host_cursor = aws_byte_cursor_from_c_str(channel_options->host_name);
    aws_byte_buf_append_dynamic(&tester.connection_host_name, &host_cursor);

    tester.connection_port = channel_options->port;

    /*
     * Conditional failure logic based on how the test was configured to fail
     */
    if (tester.failure_type == PTFT_CHANNEL) {
        tester.wait_result = AWS_ERROR_UNKNOWN;
    } else if (tester.failure_type != PTFT_CONNECTION) {
        tester.http_bootstrap = channel_options->user_data;
        ASSERT_SUCCESS(proxy_tester_create_testing_channel_connection(&tester));
    }

    aws_mutex_unlock(&tester.wait_lock);

    /*
     * More conditional failure logic based on how the test was configured to fail
     */
    if (tester.failure_type == PTFT_CHANNEL) {
        return AWS_OP_ERR;
    }

    if (tester.failure_type == PTFT_CONNECTION) {
        channel_options->setup_callback(tester.client_bootstrap, AWS_ERROR_UNKNOWN, NULL, channel_options->user_data);
        return AWS_OP_SUCCESS;
    }

    /*
     * We're not supposed to fail yet, so let's keep going
     */
    struct aws_http_client_bootstrap *http_bootstrap = channel_options->user_data;
    http_bootstrap->on_setup(tester.client_connection, AWS_ERROR_SUCCESS, http_bootstrap->user_data);

    testing_channel_run_currently_queued_tasks(tester.testing_channel);

    if (tester.test_mode == PTTM_HTTPS) {
        /* For TLS proxies, send the CONNECT request and response */
        ASSERT_SUCCESS(proxy_tester_verify_connect_request(&tester));
        ASSERT_SUCCESS(proxy_tester_send_connect_response(&tester));
    }

    return AWS_OP_SUCCESS;
}

struct aws_http_connection_system_vtable s_proxy_connection_system_vtable = {
    .new_socket_channel = s_test_aws_proxy_new_socket_channel,
};

/*
 * Basic setup common to all mocked proxy tests - set vtables, options, call init, wait for setup completion
 */
static int s_setup_proxy_test(
    struct aws_allocator *allocator,
    enum proxy_tester_test_mode test_mode,
    enum proxy_tester_failure_type failure_type,
    enum aws_http_proxy_authentication_type auth_type) {

    (void)auth_type;

    aws_http_connection_set_system_vtable(&s_proxy_connection_system_vtable);
    aws_http_proxy_system_set_vtable(&s_proxy_table_for_tls);

    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str(s_proxy_host_name),
        .port = s_proxy_port,
    };

    if (auth_type == AWS_HPAT_BASIC) {
        proxy_options.auth_type = AWS_HPAT_BASIC;
        proxy_options.auth_username = aws_byte_cursor_from_string(s_mock_request_username);
        proxy_options.auth_password = aws_byte_cursor_from_string(s_mock_request_password);
    }

    struct proxy_tester_options options = {
        .alloc = allocator,
        .proxy_options = &proxy_options,
        .host = aws_byte_cursor_from_c_str(s_host_name),
        .port = s_port,
        .test_mode = test_mode,
        .failure_type = failure_type,
    };

    ASSERT_SUCCESS(proxy_tester_init(&tester, &options));

    proxy_tester_wait(&tester, proxy_tester_connection_setup_pred);

    return AWS_OP_SUCCESS;
}

/*
 * For plaintext proxy connections:
 * If we do pass in proxy options, verify we try and connect to the proxy
 */
static int s_test_http_proxy_connection_proxy_target(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_setup_proxy_test(allocator, PTTM_HTTP, PTFT_NONE, AWS_HPAT_NONE));

    ASSERT_SUCCESS(proxy_tester_verify_connection_attempt_was_to_proxy(
        &tester, aws_byte_cursor_from_c_str(s_proxy_host_name), s_proxy_port));

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_proxy_target, s_test_http_proxy_connection_proxy_target);

/*
 * For plaintext proxy connections:
 * Verify a channel creation failure cleans up properly
 */
static int s_test_http_proxy_connection_channel_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_setup_proxy_test(allocator, PTTM_HTTP, PTFT_CHANNEL, AWS_HPAT_NONE));

    ASSERT_SUCCESS(proxy_tester_verify_connection_attempt_was_to_proxy(
        &tester, aws_byte_cursor_from_c_str(s_proxy_host_name), s_proxy_port));
    ASSERT_TRUE(tester.wait_result != AWS_ERROR_SUCCESS);
    ASSERT_TRUE(tester.client_connection == NULL);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_channel_failure, s_test_http_proxy_connection_channel_failure);

/*
 * For plaintext proxy connections:
 * Verify a connection establishment failure cleans up properly
 */
static int s_test_http_proxy_connection_connect_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_setup_proxy_test(allocator, PTTM_HTTP, PTFT_CONNECTION, AWS_HPAT_NONE));

    ASSERT_SUCCESS(proxy_tester_verify_connection_attempt_was_to_proxy(
        &tester, aws_byte_cursor_from_c_str(s_proxy_host_name), s_proxy_port));
    ASSERT_TRUE(tester.wait_result != AWS_ERROR_SUCCESS);
    ASSERT_TRUE(tester.client_connection == NULL);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_connection_connect_failure, s_test_http_proxy_connection_connect_failure);

/*
 * For tls-enabled proxy connections:
 * Test the happy path by verifying CONNECT request, tls upgrade attempt
 */
static int s_test_https_proxy_connection_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_setup_proxy_test(allocator, PTTM_HTTPS, PTFT_NONE, AWS_HPAT_NONE));

    ASSERT_SUCCESS(proxy_tester_verify_connection_attempt_was_to_proxy(
        &tester, aws_byte_cursor_from_c_str(s_proxy_host_name), s_proxy_port));
    ASSERT_TRUE(tester.client_connection != NULL);
    ASSERT_TRUE(tester.wait_result == AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_https_proxy_connection_success, s_test_https_proxy_connection_success);

/*
 * For tls-enabled proxy connections:
 * If the CONNECT request fails, verify error propagation and cleanup
 */
static int s_test_https_proxy_connection_failure_connect(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_setup_proxy_test(allocator, PTTM_HTTPS, PTFT_CONNECT_REQUEST, AWS_HPAT_NONE));

    ASSERT_SUCCESS(proxy_tester_verify_connection_attempt_was_to_proxy(
        &tester, aws_byte_cursor_from_c_str(s_proxy_host_name), s_proxy_port));
    ASSERT_TRUE(tester.client_connection == NULL);
    ASSERT_TRUE(tester.wait_result != AWS_ERROR_SUCCESS);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_https_proxy_connection_failure_connect, s_test_https_proxy_connection_failure_connect);

/*
 * For tls-enabled proxy connections:
 * If the TLS upgrade fails, verify error propagation and cleanup
 */
static int s_test_https_proxy_connection_failure_tls(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_setup_proxy_test(allocator, PTTM_HTTPS, PTFT_TLS_NEGOTIATION, AWS_HPAT_NONE));

    ASSERT_SUCCESS(proxy_tester_verify_connection_attempt_was_to_proxy(
        &tester, aws_byte_cursor_from_c_str(s_proxy_host_name), s_proxy_port));
    ASSERT_NULL(tester.client_connection);
    ASSERT_TRUE(AWS_ERROR_SUCCESS != tester.wait_result);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_https_proxy_connection_failure_tls, s_test_https_proxy_connection_failure_tls);

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

static int s_do_http_proxy_request_transform_test(struct aws_allocator *allocator, bool use_basic_auth) {

    ASSERT_SUCCESS(
        s_setup_proxy_test(allocator, PTTM_HTTP, PTFT_NONE, use_basic_auth ? AWS_HPAT_BASIC : AWS_HPAT_NONE));

    struct aws_http_message *untransformed_request = s_build_http_request(allocator);
    struct aws_http_message *request = s_build_http_request(allocator);

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = &tester,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(tester.client_connection, &request_options);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_run_currently_queued_tasks(tester.testing_channel);

    s_verify_transformed_request(untransformed_request, request, use_basic_auth, allocator);

    /* double release the stream because the dummy connection doesn't actually process (and release) it */
    aws_http_stream_release(stream);

    aws_http_message_destroy(request);
    aws_http_message_destroy(untransformed_request);

    ASSERT_SUCCESS(proxy_tester_clean_up(&tester));

    return AWS_OP_SUCCESS;
}

/*
 * If we do pass in proxy options, verify requests get properly transformed
 */
static int s_test_http_proxy_request_transform(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_do_http_proxy_request_transform_test(allocator, false));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_request_transform, s_test_http_proxy_request_transform);

/*
 * If we do pass in proxy options, verify requests get properly transformed with basic authentication
 */
static int s_test_http_proxy_request_transform_basic_auth(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_do_http_proxy_request_transform_test(allocator, true));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_request_transform_basic_auth, s_test_http_proxy_request_transform_basic_auth);

AWS_STATIC_STRING_FROM_LITERAL(s_rewrite_host, "www.uri.com");
AWS_STATIC_STRING_FROM_LITERAL(s_rewrite_path, "/main/index.html?foo=bar");
AWS_STATIC_STRING_FROM_LITERAL(s_expected_rewritten_path, "http://www.uri.com:80/main/index.html?foo=bar");

/*
 * Given some basic request parameters, (method, path, host), builds a simple http request and then applies the proxy
 * transform to it
 *
 * Verifies that the transform's final path matches what was expected
 */
static int s_do_request_rewrite_test(
    struct aws_allocator *allocator,
    const struct aws_string *method,
    const struct aws_string *path,
    const struct aws_string *host,
    const struct aws_string *expected_path) {

    struct aws_http_proxy_options proxy_options = {
        .host = aws_byte_cursor_from_c_str(s_proxy_host_name),
        .port = s_proxy_port,
    };

    struct aws_http_client_connection_options connection_options = {
        .allocator = allocator,
        .host_name = aws_byte_cursor_from_string(s_rewrite_host),
        .port = 80,
        .proxy_options = &proxy_options,
    };

    struct aws_http_proxy_user_data *user_data = aws_http_proxy_user_data_new(allocator, &connection_options);
    struct aws_http_message *request = s_build_dummy_http_request(
        allocator,
        aws_byte_cursor_from_string(method),
        aws_byte_cursor_from_string(path),
        aws_byte_cursor_from_string(host));

    ASSERT_SUCCESS(aws_http_rewrite_uri_for_proxy_request(request, user_data));

    struct aws_byte_cursor expected_rewritten_path = aws_byte_cursor_from_string(expected_path);
    struct aws_byte_cursor rewritten_path;
    ASSERT_SUCCESS(aws_http_message_get_request_path(request, &rewritten_path));

    ASSERT_TRUE(aws_byte_cursor_eq(&rewritten_path, &expected_rewritten_path));

    aws_http_message_destroy(request);
    aws_http_proxy_user_data_destroy(user_data);

    return AWS_OP_SUCCESS;
}

static int s_test_http_proxy_uri_rewrite(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_do_request_rewrite_test(
        allocator, s_mock_request_method, s_rewrite_path, s_rewrite_host, s_expected_rewritten_path));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_uri_rewrite, s_test_http_proxy_uri_rewrite);

AWS_STATIC_STRING_FROM_LITERAL(s_options_request_method, "OPTIONS");
AWS_STATIC_STRING_FROM_LITERAL(s_options_star_path, "*");
AWS_STATIC_STRING_FROM_LITERAL(s_expected_rewritten_options_path, "http://www.uri.com:80");

static int s_test_http_proxy_uri_rewrite_options_star(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_do_request_rewrite_test(
        allocator, s_options_request_method, s_options_star_path, s_rewrite_host, s_expected_rewritten_options_path));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_http_proxy_uri_rewrite_options_star, s_test_http_proxy_uri_rewrite_options_star);
