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

#include <aws/http/private/h2_connection.h>

#include <aws/http/request_response.h>
#include <aws/testing/io_testing_channel.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

/* Singleton used by tests in this file */
struct tester {
    struct aws_allocator *alloc;
    struct aws_http_connection *connection;
    struct testing_channel testing_channel;
} s_tester;

static int s_tester_init(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_http_library_init(alloc);

    s_tester.alloc = alloc;

    struct aws_testing_channel_options options = {.clock_fn = aws_high_res_clock_get_ticks};

    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, alloc, &options));

    s_tester.connection = aws_http_connection_new_http2_client(alloc, SIZE_MAX);
    ASSERT_NOT_NULL(s_tester.connection);

    { /* re-enact marriage vows of http-connection and channel (handled by http-bootstrap in real world) */
        struct aws_channel_slot *slot = aws_channel_slot_new(s_tester.testing_channel.channel);
        ASSERT_NOT_NULL(slot);
        ASSERT_SUCCESS(aws_channel_slot_insert_end(s_tester.testing_channel.channel, slot));
        ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &s_tester.connection->channel_handler));
        s_tester.connection->channel_slot = slot;
        aws_channel_acquire_hold(s_tester.testing_channel.channel);
    }

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(void) {
    aws_http_connection_release(s_tester.connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&s_tester.testing_channel));
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* Test the common setup/teardown used by all tests in this file */
TEST_CASE(h2_client_sanity_check) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));
    return s_tester_clean_up();
}

/* Test that a stream can be created and destroyed. */
TEST_CASE(h2_client_request_create) {
    ASSERT_SUCCESS(s_tester_init(allocator, ctx));

    /* create request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    struct aws_http_header headers[] = {
        {aws_byte_cursor_from_c_str(":method"), aws_byte_cursor_from_c_str("GET")},
        {aws_byte_cursor_from_c_str(":scheme"), aws_byte_cursor_from_c_str("https")},
        {aws_byte_cursor_from_c_str(":path"), aws_byte_cursor_from_c_str("/")},
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(aws_http_message_get_headers(request), headers, AWS_ARRAY_SIZE(headers)));

    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = request,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(s_tester.connection, &options);
    ASSERT_NOT_NULL(stream);

    /* shutdown channel so request can be released */
    aws_channel_shutdown(s_tester.testing_channel.channel, AWS_ERROR_SUCCESS);
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_TRUE(testing_channel_is_shutdown_completed(&s_tester.testing_channel));

    /* release request */
    aws_http_stream_release(stream);
    aws_http_message_release(request);

    return s_tester_clean_up();
}
