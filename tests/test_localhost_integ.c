/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/testing/aws_test_harness.h>

#include <aws/http/private/hpack.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/device_random.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>

#include "h2_test_helper.h"

static int s_tester_on_headers(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)stream;
    (void)header_block;
    struct aws_http_headers *received_headers = (struct aws_http_headers *)user_data;

    for (size_t i = 0; i < num_headers; ++i) {
        ASSERT_SUCCESS(aws_http_headers_add_header(received_headers, &header_array[i]));
    }
    return AWS_OP_SUCCESS;
}

static bool s_check_headers_received(
    const struct aws_http_headers *received_headers,
    const struct aws_http_headers *headers_to_check) {
    for (size_t i = 0; i < aws_http_headers_count(headers_to_check); i++) {
        struct aws_http_header header;
        if (aws_http_headers_get_index(headers_to_check, i, &header)) {
            return false;
        }
        struct aws_http_header received_header;
        if (aws_http_headers_get_index(received_headers, i + 1, &received_header)) {
            /* Not found */
            return false;
        }
        if (!aws_byte_cursor_eq(&received_header.value, &header.value) ||
            !aws_byte_cursor_eq(&received_header.name, &header.name)) {
            return false;
        }
    }
    return true;
}

struct tester {
    struct aws_allocator *alloc;

    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;
    struct aws_client_bootstrap *client_bootstrap;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_http_connection *connection;

    struct aws_mutex wait_lock;
    struct aws_condition_variable wait_cvar;

    bool shutdown_finished;
    size_t wait_for_stream_completed_count;
    size_t stream_completed_count;
    size_t stream_complete_errors;
    size_t stream_200_count;
    size_t stream_4xx_count;
    size_t stream_status_not_200_count;

    uint64_t num_sen_received;
    int stream_completed_error_code;
    bool stream_completed_with_200;

    size_t download_body_len;
    size_t content_len;

    int wait_result;
};

static struct tester s_tester;

#define DEFINE_HEADER(NAME, VALUE)                                                                                     \
    { .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(NAME), .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(VALUE), }

enum {
    TESTER_TIMEOUT_SEC = 60, /* Give enough time for non-sudo users to enter password */
};

static void s_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {

    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    if (error_code) {
        tester->wait_result = error_code;
        goto done;
    }
    tester->connection = connection;
done:
    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static void s_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {

    (void)connection;
    (void)error_code;
    struct tester *tester = user_data;
    AWS_FATAL_ASSERT(aws_mutex_lock(&tester->wait_lock) == AWS_OP_SUCCESS);

    tester->shutdown_finished = true;

    AWS_FATAL_ASSERT(aws_mutex_unlock(&tester->wait_lock) == AWS_OP_SUCCESS);
    aws_condition_variable_notify_one(&tester->wait_cvar);
}

static bool s_is_connected(void *context) {
    struct tester *tester = context;

    return tester->connection != NULL;
}

static int s_wait_on_connection_connected(struct tester *tester) {

    ASSERT_SUCCESS(aws_mutex_lock(&tester->wait_lock));
    int signal_error = aws_condition_variable_wait_pred(&tester->wait_cvar, &tester->wait_lock, s_is_connected, tester);
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->wait_lock));
    return signal_error;
}

static bool s_is_shutdown(void *context) {
    struct tester *tester = context;

    return tester->shutdown_finished;
}

static int s_wait_on_connection_shutdown(struct tester *tester) {

    ASSERT_SUCCESS(aws_mutex_lock(&tester->wait_lock));
    int signal_error = aws_condition_variable_wait_pred(&tester->wait_cvar, &tester->wait_lock, s_is_shutdown, tester);
    ASSERT_SUCCESS(aws_mutex_unlock(&tester->wait_lock));
    return signal_error;
}

static bool s_is_stream_completed_count_at_least(void *context) {
    (void)context;
    return s_tester.wait_for_stream_completed_count <= s_tester.stream_completed_count;
}

static int s_wait_on_streams_completed_count(size_t count) {

    ASSERT_SUCCESS(aws_mutex_lock(&s_tester.wait_lock));
    s_tester.wait_for_stream_completed_count = count;
    int signal_error = aws_condition_variable_wait_pred(
        &s_tester.wait_cvar, &s_tester.wait_lock, s_is_stream_completed_count_at_least, &s_tester);
    ASSERT_SUCCESS(aws_mutex_unlock(&s_tester.wait_lock));
    return signal_error;
}

static void s_tester_on_stream_completed(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)user_data;
    (void)stream;
    AWS_FATAL_ASSERT(aws_mutex_lock(&s_tester.wait_lock) == AWS_OP_SUCCESS);
    if (error_code) {
        ++s_tester.stream_complete_errors;
        s_tester.stream_completed_error_code = error_code;
    } else {
        int status = 0;
        if (aws_http_stream_get_incoming_response_status(stream, &status)) {
            ++s_tester.stream_complete_errors;
            s_tester.stream_completed_error_code = aws_last_error();
        } else {
            if (status == 200) {
                s_tester.stream_completed_with_200 = true;
                ++s_tester.stream_200_count;
            } else if (status / 100 == 4) {
            } else {
                ++s_tester.stream_status_not_200_count;
            }
        }
    }
    ++s_tester.stream_completed_count;
    aws_condition_variable_notify_one(&s_tester.wait_cvar);
    AWS_FATAL_ASSERT(aws_mutex_unlock(&s_tester.wait_lock) == AWS_OP_SUCCESS);
}

static struct aws_logger s_logger;

static int s_tester_init(struct tester *tester, struct aws_allocator *allocator, struct aws_byte_cursor host_name) {
    aws_http_library_init(allocator);

    ASSERT_SUCCESS(aws_mutex_init(&tester->wait_lock));
    ASSERT_SUCCESS(aws_condition_variable_init(&tester->wait_cvar));
    tester->event_loop_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = tester->event_loop_group,
        .max_entries = 8,
    };

    tester->host_resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    /* Create http connection */
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = tester->event_loop_group,
        .host_resolver = tester->host_resolver,
    };
    tester->client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    aws_tls_ctx_options_init_default_client(&tester->tls_ctx_options, allocator);
    aws_tls_ctx_options_set_alpn_list(&tester->tls_ctx_options, "h2");
    /* Turn off peer verification as a localhost cert used */
    tester->tls_ctx_options.verify_peer = false;

    tester->tls_ctx = aws_tls_client_ctx_new(allocator, &tester->tls_ctx_options);
    aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);
    aws_tls_connection_options_set_server_name(&tester->tls_connection_options, allocator, &host_name);
    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
        .keep_alive_timeout_sec = 0,
        .keepalive = false,
        .keep_alive_interval_sec = 0,
    };
    struct aws_http_connection_monitoring_options monitor_opt = {
        .allowable_throughput_failure_interval_seconds = 2,
        .minimum_throughput_bytes_per_second = 1000,
    };
    struct aws_http_client_connection_options client_options = {
        .self_size = sizeof(struct aws_http_client_connection_options),
        .allocator = allocator,
        .bootstrap = tester->client_bootstrap,
        .host_name = host_name,
        .port = 3443,
        .socket_options = &socket_options,
        .user_data = tester,
        .tls_options = &tester->tls_connection_options,
        .on_setup = s_on_connection_setup,
        .on_shutdown = s_on_connection_shutdown,
        .monitoring_options = &monitor_opt,
    };
    ASSERT_SUCCESS(aws_http_client_connect(&client_options));
    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_DEBUG, /* We are stress testing, and if this ever failed, the default trace level log is
                                         too much to handle, let's do debug level instead */
        .file = stderr,
    };

    aws_logger_init_standard(&s_logger, allocator, &logger_options);
    aws_logger_set(&s_logger);
    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    aws_http_connection_release(tester->connection);
    ASSERT_SUCCESS(s_wait_on_connection_shutdown(tester));

    aws_tls_connection_options_clean_up(&tester->tls_connection_options);
    aws_tls_ctx_release(tester->tls_ctx);
    aws_tls_ctx_options_clean_up(&tester->tls_ctx_options);
    aws_client_bootstrap_release(tester->client_bootstrap);
    aws_host_resolver_release(tester->host_resolver);
    aws_event_loop_group_release(tester->event_loop_group);

    aws_mutex_clean_up(&tester->wait_lock);
    aws_http_library_clean_up();
    aws_logger_clean_up(&s_logger);
    return AWS_OP_SUCCESS;
}

AWS_STATIC_STRING_FROM_LITERAL(s_http_localhost_env_var, "AWS_TEST_LOCALHOST_HOST");

static int s_test_hpack_stress_helper(struct aws_allocator *allocator, bool compression) {
    /* Test that makes tons of streams with all sorts of headers to stress hpack */
    struct aws_string *http_localhost_host = NULL;
    if (aws_get_environment_value(allocator, s_http_localhost_env_var, &http_localhost_host) ||
        http_localhost_host == NULL) {
        /* The envrionment variable is not set, default to localhost */
        http_localhost_host = aws_string_new_from_c_str(allocator, "localhost");
    }
    struct aws_byte_cursor host_name = aws_byte_cursor_from_string(http_localhost_host);
    ASSERT_SUCCESS(s_tester_init(&s_tester, allocator, host_name));
    /* wait for connection connected */
    ASSERT_SUCCESS(s_wait_on_connection_connected(&s_tester));
    // localhost/echo is an echo server that will return the headers of your request from the body.
    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/echo"),
        {
            .name = aws_byte_cursor_from_c_str(":authority"),
            .value = host_name,
        },
    };

    size_t num_to_acquire = 2000;
    size_t num_headers_to_make = 100;

    /* Use a pool of headers and a pool of values, pick up randomly from both pool to stress hpack */
    size_t headers_pool_size = 500;
    size_t values_pool_size = 66;

    for (size_t i = 0; i < num_to_acquire; i++) {
        struct aws_http_message *request = aws_http2_message_new_request(allocator);
        ASSERT_NOT_NULL(request);
        aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
        struct aws_http_headers *request_headers = aws_http_message_get_headers(request);
        struct aws_http_headers *test_headers =
            aws_http_headers_new(allocator); /* as request headers has the pesudo headers, make a copy of the real
                                                headers to check the result */
        for (size_t j = 0; j < num_headers_to_make; j++) {
            char test_header_str[256];
            uint64_t random_64_bit_num = 0;
            aws_device_random_u64(&random_64_bit_num);

            size_t headers = (size_t)random_64_bit_num % headers_pool_size;
            snprintf(test_header_str, sizeof(test_header_str), "crttest-%zu", headers);
            char test_value_str[256];
            size_t value = (size_t)random_64_bit_num % values_pool_size;
            snprintf(test_value_str, sizeof(test_value_str), "value-%zu", value);

            struct aws_http_header request_header = {
                .compression =
                    compression
                        ? random_64_bit_num % 3
                        : AWS_HTTP_HEADER_COMPRESSION_USE_CACHE, // With random type of compression, make sure it works
                .name = aws_byte_cursor_from_c_str(test_header_str),
                .value = aws_byte_cursor_from_c_str(test_value_str),
            };
            ASSERT_SUCCESS(aws_http_headers_add_header(request_headers, &request_header));
            ASSERT_SUCCESS(aws_http_headers_add_header(test_headers, &request_header));
        }
        struct aws_http_headers *received_headers = aws_http_headers_new(allocator);
        struct aws_http_make_request_options request_options = {
            .self_size = sizeof(request_options),
            .request = request,
            .user_data = received_headers,
            .on_response_headers = s_tester_on_headers,
            .on_complete = s_tester_on_stream_completed,
        };
        struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
        ASSERT_NOT_NULL(stream);
        aws_http_stream_activate(stream);
        aws_http_stream_release(stream);

        /* Wait for the stream to complete */
        ASSERT_SUCCESS(s_wait_on_streams_completed_count(1));
        --s_tester.stream_completed_count;
        ASSERT_TRUE(s_tester.stream_completed_with_200);
        ASSERT_TRUE(s_check_headers_received(received_headers, test_headers));

        aws_http_message_release(request);
        aws_http_headers_release(test_headers);
        aws_http_headers_release(received_headers);
    }

    aws_string_destroy(http_localhost_host);
    const struct aws_socket_endpoint *remote_endpoint = aws_http_connection_get_remote_endpoint(s_tester.connection);
    ASSERT_NOT_NULL(remote_endpoint);
    struct aws_byte_cursor remote_ip = aws_byte_cursor_from_c_str(remote_endpoint->address);
    /* Local host IP should always be 127.0.0.1 */
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&remote_ip, "127.0.0.1"));
    return s_tester_clean_up(&s_tester);
}

AWS_TEST_CASE(localhost_integ_hpack_stress, test_hpack_stress)
static int test_hpack_stress(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_test_hpack_stress_helper(allocator, false /*compression*/);
}

AWS_TEST_CASE(localhost_integ_hpack_compression_stress, test_hpack_compression_stress)
static int test_hpack_compression_stress(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_test_hpack_stress_helper(allocator, true /*compression*/);
}

static int s_tester_on_put_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {

    (void)stream;
    (void)user_data;
    struct aws_string *content_length_header_str = aws_string_new_from_cursor(s_tester.alloc, data);
    s_tester.num_sen_received = (uint64_t)strtoull((const char *)content_length_header_str->bytes, NULL, 10);
    aws_string_destroy(content_length_header_str);

    return AWS_OP_SUCCESS;
}

/* Test that upload a 2.5GB data to local server */
AWS_TEST_CASE(localhost_integ_h2_upload_stress, s_localhost_integ_h2_upload_stress)
static int s_localhost_integ_h2_upload_stress(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_tester.alloc = allocator;

    size_t length = 2500000000UL;
#ifdef AWS_OS_LINUX
    /* Using Python hyper h2 server frame work, met a weird upload performance issue on Linux. Our client against nginx
     * platform has not met the same issue. We assume it's because the server framework implementation.  Use lower
     * number of linux */
    length = 250000000UL;
#endif

    struct aws_string *http_localhost_host = NULL;
    if (aws_get_environment_value(allocator, s_http_localhost_env_var, &http_localhost_host) ||
        http_localhost_host == NULL) {
        /* The envrionment variable is not set, default to localhost */
        http_localhost_host = aws_string_new_from_c_str(allocator, "localhost");
    }
    struct aws_byte_cursor host_name = aws_byte_cursor_from_string(http_localhost_host);
    ASSERT_SUCCESS(s_tester_init(&s_tester, allocator, host_name));
    /* wait for connection connected */
    ASSERT_SUCCESS(s_wait_on_connection_connected(&s_tester));
    char content_length_sprintf_buffer[128] = "";
    snprintf(content_length_sprintf_buffer, sizeof(content_length_sprintf_buffer), "%zu", length);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "PUT"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/upload_test.txt"),
        {
            .name = aws_byte_cursor_from_c_str(":authority"),
            .value = host_name,
        },
        {
            .name = aws_byte_cursor_from_c_str("content_length"),
            .value = aws_byte_cursor_from_c_str(content_length_sprintf_buffer),
        },
    };
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    struct aws_input_stream *body_stream = aws_input_stream_tester_upload_new(allocator, length);
    aws_http_message_set_body_stream(request, body_stream);
    aws_input_stream_release(body_stream);

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .on_complete = s_tester_on_stream_completed,
        .on_response_body = s_tester_on_put_body,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);
    aws_http_stream_release(stream);

    /* Wait for the stream to complete */
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(1));
    ASSERT_UINT_EQUALS(s_tester.num_sen_received, length);
    ASSERT_TRUE(s_tester.stream_completed_with_200);

    aws_http_message_release(request);
    aws_string_destroy(http_localhost_host);
    return s_tester_clean_up(&s_tester);
}

static int s_tester_on_download_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;
    (void)user_data;
    s_tester.download_body_len += data->len;

    return AWS_OP_SUCCESS;
}
/* Test that download a 2.5GB data from local server */
AWS_TEST_CASE(localhost_integ_h2_download_stress, s_localhost_integ_h2_download_stress)
static int s_localhost_integ_h2_download_stress(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_tester.alloc = allocator;
    size_t length = 2500000000UL; /* over int max, which it the max for settings */

    struct aws_string *http_localhost_host = NULL;
    if (aws_get_environment_value(allocator, s_http_localhost_env_var, &http_localhost_host) ||
        http_localhost_host == NULL) {
        /* The envrionment variable is not set, default to localhost */
        http_localhost_host = aws_string_new_from_c_str(allocator, "localhost");
    }
    struct aws_byte_cursor host_name = aws_byte_cursor_from_string(http_localhost_host);
    ASSERT_SUCCESS(s_tester_init(&s_tester, allocator, host_name));
    /* wait for connection connected */
    ASSERT_SUCCESS(s_wait_on_connection_connected(&s_tester));

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/downloadTest"),
        {
            .name = aws_byte_cursor_from_c_str(":authority"),
            .value = host_name,
        },
    };
    struct aws_http_message *request = aws_http2_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .on_complete = s_tester_on_stream_completed,
        .on_response_body = s_tester_on_download_body,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);
    aws_http_stream_release(stream);

    /* Wait for the stream to complete */
    ASSERT_SUCCESS(s_wait_on_streams_completed_count(1));
    ASSERT_UINT_EQUALS(s_tester.download_body_len, length);
    ASSERT_TRUE(s_tester.stream_completed_with_200);

    aws_http_message_release(request);
    aws_string_destroy(http_localhost_host);
    return s_tester_clean_up(&s_tester);
}
