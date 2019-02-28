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

#include <aws/http/private/connection_impl.h>
#include <aws/http/request_response.h>
#include <aws/testing/io_testing_channel.h>

#define H1_CLIENT_TEST_CASE(NAME)                                                                                      \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx);                                              \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

struct tester {
    struct aws_allocator *alloc;
    struct testing_channel testing_channel;
    struct aws_http_connection *connection;
};

static int s_tester_init(struct tester *tester, struct aws_allocator *alloc) {
    AWS_ZERO_STRUCT(*tester);

    tester->alloc = alloc;
    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc));

    struct aws_http_client_connection_impl_options options = {
        .alloc = alloc,
        .initial_window_size = SIZE_MAX,
        .user_data = tester,
    };
    tester->connection = aws_http_connection_new_http1_1_client(&options);
    ASSERT_NOT_NULL(tester->connection);

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    tester->connection->channel_slot = slot;
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &tester->connection->channel_handler));

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    ASSERT_SUCCESS(testing_channel_clean_up(&tester->testing_channel));
    return AWS_OP_SUCCESS;
}

/* Check that we can set and tear down the `tester` used by all other tests in this file */
H1_CLIENT_TEST_CASE(h1_client_sanity_check) {
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

/* Send 1 line request, doesn't care about response */
H1_CLIENT_TEST_CASE(h1_client_request_send_1liner) {
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    /* send request */
    struct aws_http_request_options opt = AWS_HTTP_REQUEST_OPTIONS_INIT;
    opt.client_connection = tester.connection;
    opt.method_str = aws_byte_cursor_from_c_str("GET");
    opt.uri = aws_byte_cursor_from_c_str("/");
    struct aws_http_stream *stream = aws_http_stream_new_client_request(&opt);
    ASSERT_NOT_NULL(stream);

    testing_channel_execute_queued_tasks(&tester.testing_channel);

    /* check result */
    struct aws_linked_list *msgs = testing_channel_get_written_message_queue(&tester.testing_channel);
    struct aws_linked_list_node *node = aws_linked_list_front(msgs);
    struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

    const char *expected = "GET / HTTP/1.1\r\n\r\n";
    struct aws_byte_cursor expected_cur = aws_byte_cursor_from_c_str(expected);
    ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&expected_cur, &msg->message_data));

    /* clean up */
    aws_http_stream_release(stream);

    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
