/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/testing/aws_test_harness.h>

#include <aws/http/private/hpack.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/device_random.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* Disable warnings about sprintf() being insecure */
#endif

static bool s_echo_body_has_header(const struct aws_byte_cursor echo_body, const struct aws_http_header *header) {
    char str_to_find[256];
    /* Echo body will capitalize the header name, ignore the first char. I think it's fine */
    struct aws_byte_cursor name_without_first_char = header->name;
    aws_byte_cursor_advance(&name_without_first_char, 1);
    sprintf(
        str_to_find,
        "" PRInSTR "\": \"" PRInSTR "\"",
        AWS_BYTE_CURSOR_PRI(name_without_first_char),
        AWS_BYTE_CURSOR_PRI(header->value));
    struct aws_byte_cursor to_find_cur = aws_byte_cursor_from_c_str(str_to_find);
    struct aws_byte_cursor found;
    if (aws_byte_cursor_find_exact(&echo_body, &to_find_cur, &found)) {
        /* cannot find the value */
        return false;
    }
    return true;
}

static bool s_echo_body_has_headers(const struct aws_byte_cursor echo_body, const struct aws_http_headers *headers) {
    for (size_t i = 0; i < aws_http_headers_count(headers); i++) {
        struct aws_http_header out_header;
        if (aws_http_headers_get_index(headers, i, &out_header)) {
            return false;
        }
        if (!s_echo_body_has_header(echo_body, &out_header)) {
            return false;
        }
    }
    return true;
}

static int s_tester_on_echo_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;
    /**
     * Make request to https://httpbin.org/headers, example response body:
     *"{\r\n"
     *"  \"headers\": {\r\n"
     *"    \"Accept\": \"application/xml\", \r\n"
     *"    \"Host\": \"httpbin.org\", \r\n"
     *"    \"Test0\": \"test0\", \r\n"
     *"    \"User-Agent\": \"elasticurl 1.0, Powered by the AWS Common Runtime.\", \r\n"
     *"    \"X-Amzn-Trace-Id\": \"Root=1-6216d59a-16a92b5622bb49a0352cf9a4\"\r\n"
     *"  }\r\n"
     *"}\r\n"
     */
    struct aws_byte_buf *echo_body = (struct aws_byte_buf *)user_data;
    ASSERT_SUCCESS(aws_byte_buf_append_dynamic(echo_body, data));
    return AWS_OP_SUCCESS;
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
    int stream_completed_error_code;
    bool stream_completed_with_200;

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
    tester->tls_ctx_options.verify_peer = false;

    tester->tls_ctx = aws_tls_client_ctx_new(allocator, &tester->tls_ctx_options);
    aws_tls_connection_options_init_from_ctx(&tester->tls_connection_options, tester->tls_ctx);
    aws_tls_connection_options_set_server_name(&tester->tls_connection_options, allocator, &host_name);
    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms =
            (uint32_t)aws_timestamp_convert(TESTER_TIMEOUT_SEC, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL),
    };
    struct aws_http_client_connection_options client_options = {
        .self_size = sizeof(struct aws_http_client_connection_options),
        .allocator = allocator,
        .bootstrap = tester->client_bootstrap,
        .host_name = host_name,
        .port = 443,
        .socket_options = &socket_options,
        .user_data = tester,
        .tls_options = &tester->tls_connection_options,
        .on_setup = s_on_connection_setup,
        .on_shutdown = s_on_connection_shutdown,
    };
    ASSERT_SUCCESS(aws_http_client_connect(&client_options));
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
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(hpack_stress, test_hpack_stress)
static int test_hpack_stress(struct aws_allocator *allocator, void *ctx) {
    /* Test that makes tons of streams with all sorts of headers to stress hpack */
    (void)ctx;
    struct aws_byte_cursor host_name = aws_byte_cursor_from_c_str("httpbin.org");
    ASSERT_SUCCESS(s_tester_init(&s_tester, allocator, host_name));
    /* wait for connection connected */
    ASSERT_SUCCESS(s_wait_on_connection_connected(&s_tester));
    // httpbin.org/headers is an echo server that will return the headers of your request from the body.
    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        DEFINE_HEADER(":scheme", "https"),
        DEFINE_HEADER(":path", "/headers"),
        DEFINE_HEADER(":authority", "httpbin.org"),
    };
    /* TODO: The initail settings header table size is 4096 octets, not sure about why server response with 400 when we
     * sent a request with around 100 headers */
    size_t num_to_acquire = 1000;
    size_t accpected_error = 50;
    size_t num_headers_to_make = 70; /* will have bad request around 100 */
    size_t error_count = 0;

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
            /**
             * - Don't use _ or - between word, the response will capitalize the first char of every word :(
             * - Don't use _, the response will change it to -. :(
             */
            uint64_t random_64_bit_num = 0;
            aws_device_random_u64(&random_64_bit_num);

            size_t headers = (size_t)random_64_bit_num % headers_pool_size;
            sprintf(test_header_str, "crttest-%zu", headers);
            char test_value_str[256];
            size_t value = (size_t)random_64_bit_num % values_pool_size;
            sprintf(test_value_str, "value-%zu", value);
            struct aws_byte_cursor existed_value;
            if (aws_http_headers_get(test_headers, aws_byte_cursor_from_c_str(test_header_str), &existed_value) ==
                AWS_OP_SUCCESS) {
                /* If the header has the same name already exists in the headers, the response will combine the values
                 * together. Do the same thing for the header to check. */
                char combined_value_str[1024];
                sprintf(combined_value_str, "" PRInSTR ",%s", AWS_BYTE_CURSOR_PRI(existed_value), test_value_str);
                aws_http_headers_set(
                    test_headers,
                    aws_byte_cursor_from_c_str(test_header_str),
                    aws_byte_cursor_from_c_str(combined_value_str));
            } else {
                aws_http_headers_add(
                    test_headers,
                    aws_byte_cursor_from_c_str(test_header_str),
                    aws_byte_cursor_from_c_str(test_value_str));
            }
            aws_http_headers_add(
                request_headers,
                aws_byte_cursor_from_c_str(test_header_str),
                aws_byte_cursor_from_c_str(test_value_str));
        }
        struct aws_byte_buf echo_body;
        ASSERT_SUCCESS(aws_byte_buf_init(&echo_body, allocator, 100));
        struct aws_http_make_request_options request_options = {
            .self_size = sizeof(request_options),
            .request = request,
            .user_data = &echo_body,
            .on_response_body = s_tester_on_echo_body,
            .on_complete = s_tester_on_stream_completed,
        };
        struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &request_options);
        ASSERT_NOT_NULL(stream);
        aws_http_stream_activate(stream);
        aws_http_stream_release(stream);

        /* Wait for the stream to complete */
        ASSERT_SUCCESS(s_wait_on_streams_completed_count(1));
        --s_tester.stream_completed_count;
        /* If we have 4xx error code, which means request was bad */
        ASSERT_UINT_EQUALS(0, s_tester.stream_4xx_count);
        if (!s_tester.stream_completed_with_200) {
            /* If error happens, we make sure it's acceptable */
            ++error_count;
        } else {
            s_tester.stream_completed_with_200 = false; /* reset complete code */
            ASSERT_TRUE(s_echo_body_has_headers(
                aws_byte_cursor_from_buf(&echo_body),
                test_headers)); /* Make sure we have the expected headers when 200 received */
        }

        aws_http_message_release(request);
        aws_http_headers_release(test_headers);
        aws_byte_buf_clean_up(&echo_body);
    }

    ASSERT_TRUE(error_count < accpected_error);
    return s_tester_clean_up(&s_tester);
}
