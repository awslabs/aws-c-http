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
#include <aws/http/request_response.h>
#include <aws/http/private/connection_impl.h>
#include <aws/http/private/request_response_impl.h>

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

#include <aws/testing/io_testing_channel.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define TEST_CASE(NAME)                                                                                      \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)


/* get the request from the channel */
struct tester_request {
    struct aws_http_stream *request_handler;

    struct aws_byte_cursor method;
    struct aws_byte_cursor uri;
    struct aws_http_header headers[100];
    size_t num_headers;
    struct aws_byte_cursor body;
};


/* Singleton used by tests in this file */
struct tester {
    struct aws_allocator *alloc;
    struct aws_logger logger;

    struct aws_http_connection *server_connection;
    struct testing_channel testing_channel;

    struct tester_request request;
    bool server_connection_is_shutdown;


} s_tester;


static void s_test_on_complete(struct aws_http_stream *stream, int error_code, void *user_data)
{
    struct tester_request *request = user_data;
    (void)stream;
    struct aws_http_stream *r_handler = request->request_handler;
    struct aws_byte_buf storage_buf;
    size_t storage_size = 0;
    aws_add_size_checked(r_handler->incoming_request_method_str.len
        ,request->request_handler->incoming_request_uri.len, &storage_size);

    aws_byte_buf_init(&storage_buf, s_tester.alloc, storage_size);

    aws_byte_buf_write_from_whole_cursor(&storage_buf, r_handler->incoming_request_method_str);
    request->method = aws_byte_cursor_from_buf(&storage_buf);

    aws_byte_buf_write_from_whole_cursor(&storage_buf, r_handler->incoming_request_uri);
    request->uri = aws_byte_cursor_from_buf(&storage_buf);
    aws_byte_cursor_advance(&request->uri, storage_buf.len - r_handler->incoming_request_uri.len);

    aws_http_stream_release(r_handler);
    aws_byte_buf_clean_up(&storage_buf);
    if (error_code == AWS_ERROR_SUCCESS) {
        /* Body callback should fire if and only if the response was reported to have a body */
        
    }
}

static void s_tester_on_incoming_request(struct aws_http_connection *connection,  struct aws_http_stream *stream, void *user_data) 
{
    struct aws_http_request_handler_options options = AWS_HTTP_REQUEST_HANDLER_OPTIONS_INIT;
    struct tester *test = user_data;
    options.user_data = &test->request;
    options.server_connection = connection;
    test->request.request_handler = stream;
    options.on_complete = s_test_on_complete;
    aws_http_stream_configure_server_request_handler(stream, &options);
    //options.on_request_headers = s_tester_on_request_header;
    //TODO
}

static int s_tester_init(struct aws_allocator *alloc) {
    aws_load_error_strings();
    aws_common_load_log_subject_strings();
    aws_io_load_error_strings();
    aws_io_load_log_subject_strings();
    aws_http_library_init(alloc);

    AWS_ZERO_STRUCT(s_tester);

    s_tester.alloc = alloc;

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };
    ASSERT_SUCCESS(aws_logger_init_standard(&s_tester.logger, s_tester.alloc, &logger_options));
    aws_logger_set(&s_tester.logger);

    ASSERT_SUCCESS(testing_channel_init(&s_tester.testing_channel, alloc));

    s_tester.server_connection = aws_http_connection_new_http1_1_server(alloc, SIZE_MAX);
    ASSERT_NOT_NULL(s_tester.server_connection);
    struct aws_http_server_connection_options options = AWS_HTTP_SERVER_CONNECTION_OPTIONS_INIT;
    options.connection_user_data = &s_tester;
    options.on_incoming_request = s_tester_on_incoming_request;
    
    ASSERT_SUCCESS(aws_http_connection_configure_server(s_tester.server_connection, &options));

    struct aws_channel_slot *slot = aws_channel_slot_new(s_tester.testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    s_tester.server_connection->channel_slot = slot;
    ASSERT_SUCCESS(aws_channel_slot_insert_end(s_tester.testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &s_tester.server_connection->channel_handler));

    aws_channel_acquire_hold(s_tester.testing_channel.channel);

    testing_channel_drain_queued_tasks(&s_tester.testing_channel);

    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up() {
    aws_http_connection_release(s_tester.server_connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&s_tester.testing_channel));
    aws_http_library_clean_up();
    aws_logger_clean_up(&s_tester.logger);
    return AWS_OP_SUCCESS;
}

/* For sending an aws_io_message into the channel, in the write or read direction */
static int s_send_message_ex(struct aws_byte_cursor data) 
{

    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        s_tester.testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, data.len);
    ASSERT_NOT_NULL(msg);

    ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&msg->message_data, data));

    ASSERT_SUCCESS(testing_channel_push_read_message(&s_tester.testing_channel, msg));

    return AWS_OP_SUCCESS;
}

static int s_send_request_str(const char *str) {
    return s_send_message_ex(aws_byte_cursor_from_c_str(str));
}

/* Check that we can set and tear down the `tester` used by all other tests in this file */
TEST_CASE(h1_server_sanity_check) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_recieve_1line_request) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                           "\r\n";
    ASSERT_SUCCESS(s_send_request_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(aws_byte_cursor_eq_c_str(&s_tester.request.method , "GET"));
    ASSERT_SUCCESS(aws_byte_cursor_eq_c_str(&s_tester.request.uri , "/"));

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}

TEST_CASE(h1_server_recieve_headers) {
    (void)ctx;
    ASSERT_SUCCESS(s_tester_init(allocator));

    const char *incoming_request = "GET / HTTP/1.1\r\n"
                                    "Host: example.com\r\n"
                                    "Accept: */*\r\n"
                                    "\r\n";
    ASSERT_SUCCESS(s_send_request_str(incoming_request));
    testing_channel_drain_queued_tasks(&s_tester.testing_channel);
    ASSERT_SUCCESS(aws_byte_cursor_eq_c_str(&s_tester.request.method , "GET"));
    ASSERT_SUCCESS(aws_byte_cursor_eq_c_str(&s_tester.request.uri , "/"));

    ASSERT_SUCCESS(s_tester_clean_up());
    return AWS_OP_SUCCESS;
}
