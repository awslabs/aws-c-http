/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>

#include <inttypes.h>

struct app_ctx {
    struct aws_allocator *allocator;
    struct aws_mutex mutex;
    struct aws_condition_variable cv;
    struct aws_http_connection *connection;
    struct aws_http_stream *stream;
    bool connection_completed;
    bool stream_completed;
    int error_code;
    size_t bytes_to_send;
    size_t bytes_sent;
};

static void s_on_write_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    struct app_ctx *ctx = user_data;

    if (error_code) {
        fprintf(stderr, "Write failed with error: %s\n", aws_error_name(error_code));
        return;
    }

    fprintf(stdout, "Write completed successfully\n");
}

static void s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    struct app_ctx *ctx = user_data;

    aws_mutex_lock(&ctx->mutex);
    ctx->stream_completed = true;
    ctx->error_code = error_code;
    aws_mutex_unlock(&ctx->mutex);
    aws_condition_variable_notify_one(&ctx->cv);

    if (error_code) {
        fprintf(stderr, "Stream completed with error: %s\n", aws_error_name(error_code));
    } else {
        fprintf(stdout, "Stream completed successfully\n");
    }
}

static void s_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct app_ctx *ctx = user_data;

    aws_mutex_lock(&ctx->mutex);
    if (error_code) {
        fprintf(stderr, "Connection failed: %s\n", aws_error_name(error_code));
        ctx->connection_completed = true;
        ctx->error_code = error_code;
    } else {
        fprintf(stdout, "Connection established\n");
        ctx->connection = connection;
    }
    aws_mutex_unlock(&ctx->mutex);
    aws_condition_variable_notify_one(&ctx->cv);
}

static void s_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)connection;
    struct app_ctx *ctx = user_data;

    aws_mutex_lock(&ctx->mutex);
    ctx->connection_completed = true;
    if (error_code) {
        fprintf(stderr, "Connection shutdown with error: %s\n", aws_error_name(error_code));
    }
    aws_mutex_unlock(&ctx->mutex);
    aws_condition_variable_notify_one(&ctx->cv);
}

static bool s_connection_ready(void *user_data) {
    struct app_ctx *ctx = user_data;
    return ctx->connection != NULL;
}

static bool s_stream_completed(void *user_data) {
    struct app_ctx *ctx = user_data;
    return ctx->stream_completed;
}

static bool s_connection_completed(void *user_data) {
    struct app_ctx *ctx = user_data;
    return ctx->connection_completed;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    struct aws_allocator *allocator = aws_default_allocator();
    aws_http_library_init(allocator);

    struct app_ctx ctx = {
        .allocator = allocator,
        .bytes_to_send = 1024,
    };
    aws_mutex_init(&ctx.mutex);
    aws_condition_variable_init(&ctx.cv);

    /* Setup event loop */
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 8,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = el_group,
        .host_resolver = resolver,
    };
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    /* Connect to httpbin.org */
    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms = 3000,
    };

    struct aws_http_client_connection_options conn_options = {
        .self_size = sizeof(conn_options),
        .socket_options = &socket_options,
        .allocator = allocator,
        .host_name = aws_byte_cursor_from_c_str("httpbin.org"),
        .port = 80,
        .bootstrap = bootstrap,
        .on_setup = s_on_connection_setup,
        .on_shutdown = s_on_connection_shutdown,
        .user_data = &ctx,
    };

    aws_http_client_connect(&conn_options);

    /* Wait for connection */
    aws_mutex_lock(&ctx.mutex);
    aws_condition_variable_wait_pred(&ctx.cv, &ctx.mutex, s_connection_ready, &ctx);
    aws_mutex_unlock(&ctx.mutex);

    if (!ctx.connection) {
        fprintf(stderr, "Failed to establish connection\n");
        goto cleanup;
    }

    /* Create request with Content-Length */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    if (!request) {
        fprintf(stderr, "Failed to create request\n");
        goto cleanup;
    }
    
    if (aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("POST"))) {
        fprintf(stderr, "Failed to set request method\n");
        aws_http_message_release(request);
        goto cleanup;
    }
    
    if (aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/post"))) {
        fprintf(stderr, "Failed to set request path\n");
        aws_http_message_release(request);
        goto cleanup;
    }

    struct aws_http_header headers[] = {
        {.name = aws_byte_cursor_from_c_str("Host"), .value = aws_byte_cursor_from_c_str("httpbin.org")},
        {.name = aws_byte_cursor_from_c_str("Content-Length"), .value = aws_byte_cursor_from_c_str("1024")},
        {.name = aws_byte_cursor_from_c_str("Content-Type"), .value = aws_byte_cursor_from_c_str("text/plain")},
    };
    for (size_t i = 0; i < AWS_ARRAY_SIZE(headers); ++i) {
        aws_http_message_add_header(request, headers[i]);
    }

    /* Make request with manual data writes */
    /* Note: This minimal example demonstrates sending data but does not read the response */
    struct aws_http_make_request_options options = {
        .self_size = sizeof(options),
        .request = request,
        .use_manual_data_writes = true,
        .on_complete = s_on_stream_complete,
        .user_data = &ctx,
    };

    ctx.stream = aws_http_connection_make_request(ctx.connection, &options);
    if (!ctx.stream) {
        fprintf(stderr, "Failed to create stream\n");
        aws_http_message_release(request);
        goto cleanup;
    }

    aws_http_stream_activate(ctx.stream);
    aws_http_message_release(request);

    /* Write data in chunks */
    uint8_t data[256];
    memset(data, 'A', sizeof(data));

    for (size_t i = 0; i < 4; ++i) {
        struct aws_byte_cursor chunk = aws_byte_cursor_from_array(data, sizeof(data));
        struct aws_input_stream *input_stream = aws_input_stream_new_from_cursor(allocator, &chunk);

        struct aws_http_stream_write_data_options write_options = {
            .data = input_stream,
            .end_stream = (i == 3),
            .on_complete = s_on_write_complete,
            .user_data = &ctx,
        };

        if (aws_http_stream_write_data(ctx.stream, &write_options)) {
            fprintf(stderr, "Failed to write data: %s\n", aws_error_name(aws_last_error()));
            aws_input_stream_release(input_stream);
            break;
        }

        ctx.bytes_sent += sizeof(data);
        fprintf(stdout, "Queued write %zu/%zu bytes\n", ctx.bytes_sent, ctx.bytes_to_send);

        aws_input_stream_release(input_stream);
    }

    /* Wait for stream completion */
    aws_mutex_lock(&ctx.mutex);
    aws_condition_variable_wait_pred(&ctx.cv, &ctx.mutex, s_stream_completed, &ctx);
    aws_mutex_unlock(&ctx.mutex);

    aws_http_stream_release(ctx.stream);

cleanup:
    if (ctx.connection) {
        aws_http_connection_release(ctx.connection);
    }

    /* Wait for connection shutdown */
    aws_mutex_lock(&ctx.mutex);
    aws_condition_variable_wait_pred(&ctx.cv, &ctx.mutex, s_connection_completed, &ctx);
    aws_mutex_unlock(&ctx.mutex);

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_condition_variable_clean_up(&ctx.cv);
    aws_mutex_clean_up(&ctx.mutex);

    aws_http_library_clean_up();

    return ctx.error_code ? 1 : 0;
}
