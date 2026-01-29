/**
 * Test comparing sync vs async body streams through the HTTP layer.
 */

#include <aws/common/clock.h>
#include <aws/common/thread.h>
#include <aws/http/connection.h>
#include <aws/http/private/h1_connection.h>
#include <aws/http/request_response.h>
#include <aws/io/async_stream.h>
#include <aws/io/stream.h>
#include <aws/testing/async_stream_tester.h>
#include <aws/testing/aws_test_harness.h>
#include <aws/testing/io_testing_channel.h>
#include <aws/testing/stream_tester.h>
#include <inttypes.h>
#include <stdio.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

/* ============== TEST SETUP ============== */

struct tester {
    struct aws_allocator *alloc;
    struct testing_channel testing_channel;
    struct aws_http_connection *connection;
};

static int s_tester_init(struct tester *tester, struct aws_allocator *alloc) {
    aws_http_library_init(alloc);
    AWS_ZERO_STRUCT(*tester);
    tester->alloc = alloc;

    struct aws_testing_channel_options test_channel_options = {.clock_fn = aws_high_res_clock_get_ticks};
    ASSERT_SUCCESS(testing_channel_init(&tester->testing_channel, alloc, &test_channel_options));

    struct aws_http1_connection_options http1_options = {0};
    tester->connection = aws_http_connection_new_http1_1_client(alloc, false, 0, &http1_options);
    ASSERT_NOT_NULL(tester->connection);

    struct aws_channel_slot *slot = aws_channel_slot_new(tester->testing_channel.channel);
    ASSERT_NOT_NULL(slot);
    ASSERT_SUCCESS(aws_channel_slot_insert_end(tester->testing_channel.channel, slot));
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, &tester->connection->channel_handler));
    tester->connection->vtable->on_channel_handler_installed(&tester->connection->channel_handler, slot);

    testing_channel_drain_queued_tasks(&tester->testing_channel);
    return AWS_OP_SUCCESS;
}

static int s_tester_clean_up(struct tester *tester) {
    aws_http_connection_release(tester->connection);
    ASSERT_SUCCESS(testing_channel_clean_up(&tester->testing_channel));
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* ============== SLOW SYNC STREAM WRAPPER ============== */

static uint64_t s_slow_sync_delay_ns = 0;
static uint64_t s_slow_sync_next_byte_ready_time = 0;
static uint64_t s_slow_sync_read_count = 0;
static const struct aws_input_stream_vtable *s_original_vtable = NULL;

static int s_slow_sync_read_with_delay(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    s_slow_sync_read_count++;

    uint64_t now;
    aws_high_res_clock_get_ticks(&now);

    if (now < s_slow_sync_next_byte_ready_time) {
        return AWS_OP_SUCCESS; /* Return 0 bytes - not ready */
    }

    /* Call original read */
    size_t prev_len = dest->len;
    int result = s_original_vtable->read(stream, dest);

    /* If we read something, set next delay */
    if (dest->len > prev_len) {
        s_slow_sync_next_byte_ready_time = now + s_slow_sync_delay_ns;
    }

    return result;
}

static struct aws_input_stream_vtable s_slow_sync_vtable;

/* ============== TESTS ============== */

TEST_CASE(slow_body_stream_sync_polling) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    const uint64_t DELAY_NS = 5 * 1000 * 1000; /* 5ms per byte */
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str("ABCD");

    /* Create sync stream that returns 1 byte at a time */
    struct aws_input_stream_tester_options opts = {
        .source_bytes = body_cursor,
        .max_bytes_per_read = 1,
    };
    struct aws_input_stream *slow_stream = aws_input_stream_new_tester(allocator, &opts);
    struct aws_input_stream_tester *stream_impl = (struct aws_input_stream_tester *)slow_stream->impl;

    /* Override vtable to add delay */
    s_slow_sync_delay_ns = DELAY_NS;
    s_slow_sync_next_byte_ready_time = 0;
    s_slow_sync_read_count = 0;
    s_original_vtable = slow_stream->vtable;
    s_slow_sync_vtable = *slow_stream->vtable;
    s_slow_sync_vtable.read = s_slow_sync_read_with_delay;
    slow_stream->vtable = &s_slow_sync_vtable;

    /* Create HTTP request */
    struct aws_http_header headers[] = {{
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("4"),
    }};
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/test")));
    aws_http_message_add_header_array(request, headers, 1);
    aws_http_message_set_body_stream(request, slow_stream);

    struct aws_http_make_request_options opt = {.self_size = sizeof(opt), .request = request};
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    testing_channel_drain_queued_tasks(&tester.testing_channel);

    const char *expected = "PUT /test HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD";
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    printf("\n=== SYNC: read() called %zu times for 4 bytes ===\n", (size_t)s_slow_sync_read_count);

    aws_http_message_destroy(request);
    aws_http_stream_release(stream);
    aws_input_stream_release(slow_stream);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}

TEST_CASE(slow_body_stream_async_no_polling) {
    (void)ctx;
    struct tester tester;
    ASSERT_SUCCESS(s_tester_init(&tester, allocator));

    const uint64_t DELAY_NS = 5 * 1000 * 1000; /* 5ms per byte */
    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_c_str("ABCD");

    /* Create async stream that returns 1 byte at a time, with delay */
    struct aws_async_input_stream_tester_options opts = {
        .base =
            {
                .source_bytes = body_cursor,
                .max_bytes_per_read = 1,
            },
        .completion_strategy = AWS_ASYNC_READ_COMPLETES_ON_ANOTHER_THREAD,
        .read_duration_ns = DELAY_NS,
    };
    struct aws_async_input_stream *slow_stream = aws_async_input_stream_new_tester(allocator, &opts);
    struct aws_async_input_stream_tester *async_impl = (struct aws_async_input_stream_tester *)slow_stream;
    struct aws_input_stream_tester *stream_impl = (struct aws_input_stream_tester *)async_impl->source_stream->impl;

    /* Create HTTP request */
    struct aws_http_header headers[] = {{
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("4"),
    }};
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/test")));
    aws_http_message_add_header_array(request, headers, 1);
    aws_http_message_set_async_body_stream(request, slow_stream);

    struct aws_http_make_request_options opt = {.self_size = sizeof(opt), .request = request};
    struct aws_http_stream *stream = aws_http_connection_make_request(tester.connection, &opt);
    ASSERT_NOT_NULL(stream);
    aws_http_stream_activate(stream);

    /* Wait for async completion */
    uint64_t start_time;
    uint64_t now;
    aws_high_res_clock_get_ticks(&start_time);

    while (stream_impl->total_bytes_read < body_cursor.len) {
        testing_channel_drain_queued_tasks(&tester.testing_channel);
        aws_thread_current_sleep(1000000); /* 1ms */
        aws_high_res_clock_get_ticks(&now);
    }
    testing_channel_drain_queued_tasks(&tester.testing_channel);

    const char *expected = "PUT /test HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD";
    ASSERT_SUCCESS(testing_channel_check_written_messages_str(&tester.testing_channel, allocator, expected));

    printf("\n=== ASYNC: read() called %zu times for 4 bytes ===\n", stream_impl->read_count);

    aws_http_message_destroy(request);
    aws_http_stream_release(stream);
    aws_async_input_stream_release(slow_stream);
    ASSERT_SUCCESS(s_tester_clean_up(&tester));
    return AWS_OP_SUCCESS;
}
