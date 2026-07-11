/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/http/connection.h>
#include <aws/http/http2_stream_manager.h>
#include <aws/http/request_response.h>

#include <aws/common/clock.h>
#include <aws/common/command_line_parser.h>
#include <aws/common/condition_variable.h>
#include <aws/common/hash_table.h>
#include <aws/common/log_channel.h>
#include <aws/common/log_formatter.h>
#include <aws/common/log_writer.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>

#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#include <inttypes.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4204) /* Declared initializers */
#    pragma warning(disable : 4221) /* Local var in declared initializer */
#endif

#define DEFINE_HEADER(NAME, VALUE)                                                                                     \
    {                                                                                                                  \
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(NAME),                                                           \
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(VALUE),                                                         \
    }

/* TODO: Make those configurable from cmd line */
const struct aws_byte_cursor uri_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("http://localhost:3280/");
const int rate_secs = 30; /* Time interval to collect data */
const int streams_per_connection = 20;
const int max_connections = 8;
const int num_data_to_collect = 5; /* The number of data to collect */
const enum aws_log_level log_level = AWS_LOG_LEVEL_NONE;
const bool direct_connection = false; /* If true, will create one connection and make requests from that connection.
                                       * If false, will use stream manager to acquire streams */

const double rate_threshold =
    4000; /* From the previous tests. All platforms seem to be larger than 4000, but it could various. TODO: Maybe
             gather the number of previous test run, and be platform specific. */

struct aws_http_benchmark_helper {
    struct aws_task task;
    struct aws_event_loop *eventloop;

    int num_collected; /* number of data collected */
    uint64_t rate_ns;  /* Collect data per rate_ns */

    struct aws_atomic_var benchmark_finished;

    double *results;
};

struct benchmark_ctx {
    struct aws_allocator *allocator;
    const char *verb;
    struct aws_uri uri;
    struct aws_mutex mutex;
    struct aws_condition_variable c_var;

    enum aws_log_level log_level;
    struct aws_http_benchmark_helper helper;
    struct aws_event_loop_group *el_group;
    struct aws_http2_stream_manager *manager;

    bool is_shutdown_complete;
    struct aws_atomic_var streams_failed;
    struct aws_atomic_var streams_completed;

    int batch_size;
    struct aws_atomic_var batch_completed;

    struct aws_http_connection *connection;
};

/************************* Data collector ******************************************/

static void s_collect_data_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    (void)task;

    struct benchmark_ctx *app_ctx = arg;
    struct aws_http_benchmark_helper *helper = &app_ctx->helper;

    /* collect data */
    size_t stream_completed = aws_atomic_exchange_int(&app_ctx->streams_completed, 0);

    /* TODO: maybe collect the data somewhere instead of just printing it out. */
    double rate = (double)stream_completed / rate_secs;
    helper->results[helper->num_collected] = rate;
    ++helper->num_collected;
    printf("Loop %d: The stream completed per second is %f\n", helper->num_collected, rate);
    if (helper->num_collected >= num_data_to_collect) {
        /* done */
        double sum = 0;
        for (int i = 0; i < num_data_to_collect; i++) {
            sum += helper->results[i];
        }
        double avg = sum / num_data_to_collect;
        printf("In average, the stream completed per second is %f\n", avg);
        aws_mem_release(app_ctx->allocator, helper->results);
        if (avg < rate_threshold) {

            fprintf(stderr, "The average result is lower than threshold (%f). Failed\n", rate_threshold);
            exit(1);
        }

        aws_atomic_store_int(&helper->benchmark_finished, 1);
    } else {
        /* keep running */
        uint64_t now = 0;
        aws_high_res_clock_get_ticks(&now);
        aws_event_loop_schedule_task_future(helper->eventloop, &helper->task, now + helper->rate_ns);
    }
}

void aws_http_benchmark_helper_init(struct benchmark_ctx *app_ctx, struct aws_http_benchmark_helper *helper) {

    helper->eventloop = aws_event_loop_group_get_next_loop(app_ctx->el_group);
    helper->rate_ns = aws_timestamp_convert(rate_secs, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    aws_atomic_init_int(&helper->benchmark_finished, 0);
    aws_task_init(&helper->task, s_collect_data_task, app_ctx, "data_collector");
    helper->results = aws_mem_calloc(app_ctx->allocator, num_data_to_collect, sizeof(double));
    uint64_t now = 0;
    aws_high_res_clock_get_ticks(&now);

    aws_event_loop_schedule_task_future(helper->eventloop, &helper->task, now + helper->rate_ns);
}

/************************* Stream callbacks ******************************************/

static void s_on_stream_acquired(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    (void)user_data;

    if (error_code) {
        fprintf(stderr, "stream failed to be acquired from stream manager %s\n", aws_error_debug_str(error_code));
        exit(1);
    }
}

static void s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;

    struct benchmark_ctx *app_ctx = user_data;
    aws_mutex_lock(&app_ctx->mutex);
    aws_atomic_fetch_add(&app_ctx->batch_completed, 1);
    if (error_code) {
        fprintf(stderr, "stream failed to complete %s\n", aws_error_debug_str(error_code));
        exit(1);
    } else {
        aws_atomic_fetch_add(&app_ctx->streams_completed, 1);
    }

    aws_mutex_unlock(&app_ctx->mutex);
    aws_http_stream_release(stream);
    aws_condition_variable_notify_one(&app_ctx->c_var);
}

/************************* Stream manager ops ******************************************/

static bool s_are_batch_completed(void *context) {
    struct benchmark_ctx *app_ctx = context;
    size_t completed = aws_atomic_load_int(&app_ctx->batch_completed);
    return (int)completed >= app_ctx->batch_size;
}

static int s_wait_on_batch_complete(struct benchmark_ctx *app_ctx) {

    aws_mutex_lock(&app_ctx->mutex);
    int signal_error =
        aws_condition_variable_wait_pred(&app_ctx->c_var, &app_ctx->mutex, s_are_batch_completed, app_ctx);
    aws_mutex_unlock(&app_ctx->mutex);

    return signal_error;
}

static void s_run_stream_manager_test(struct benchmark_ctx *app_ctx, struct aws_http_message *request) {
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = app_ctx,
        .on_complete = s_on_stream_complete,
    };

    struct aws_http2_stream_manager_acquire_stream_options acquire_stream_option = {
        .options = &request_options,
        .callback = s_on_stream_acquired,
        .user_data = app_ctx,
    };

    bool keep_loop = true;
    while (keep_loop) {
        /* Loop a batch of requests to be made and completed */
        aws_atomic_store_int(&app_ctx->batch_completed, 0);

        for (int i = 0; i < app_ctx->batch_size; ++i) {
            aws_http2_stream_manager_acquire_stream(app_ctx->manager, &acquire_stream_option);
        }
        /* once the data finished collected during waiting, no more data will be collected, still wait for all
        requests
         * made to be completed. */
        s_wait_on_batch_complete(app_ctx);
        size_t streams_failed = aws_atomic_load_int(&app_ctx->streams_failed);
        if (streams_failed > 0) {
            fprintf(
                stderr, "%zu stream failed to complete %s\n", streams_failed, aws_error_debug_str(aws_last_error()));
            exit(1);
        }

        size_t finished = aws_atomic_load_int(&app_ctx->helper.benchmark_finished);
        if (finished) {
            keep_loop = false;
        }
    }
}

static void s_on_shutdown_complete(void *user_data) {
    struct benchmark_ctx *app_ctx = user_data;

    aws_mutex_lock(&app_ctx->mutex);
    app_ctx->is_shutdown_complete = true;
    aws_mutex_unlock(&app_ctx->mutex);
    aws_condition_variable_notify_one(&app_ctx->c_var);
}

/************************* direct connection ops ******************************************/

static void s_run_direct_connection_test(struct benchmark_ctx *app_ctx, struct aws_http_message *request) {
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = app_ctx,
        .on_complete = s_on_stream_complete,
    };

    bool keep_loop = true;
    while (keep_loop) {
        /* Loop a batch of requests to be made and completed */
        aws_atomic_store_int(&app_ctx->batch_completed, 0);

        for (int i = 0; i < app_ctx->batch_size; ++i) {
            struct aws_http_stream *stream = aws_http_connection_make_request(app_ctx->connection, &request_options);
            aws_http_stream_activate(stream);
        }
        /* once the data finished collected during waiting, no more data will be collected, still wait for all
        requests
         * made to be completed. */
        s_wait_on_batch_complete(app_ctx);
        size_t streams_failed = aws_atomic_load_int(&app_ctx->streams_failed);
        if (streams_failed > 0) {
            fprintf(
                stderr, "%zu stream failed to complete %s\n", streams_failed, aws_error_debug_str(aws_last_error()));
            exit(1);
        }

        size_t finished = aws_atomic_load_int(&app_ctx->helper.benchmark_finished);
        if (finished) {
            keep_loop = false;
        }
    }
}

static void s_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)connection;
    (void)error_code;
    struct benchmark_ctx *app_ctx = user_data;

    aws_mutex_lock(&app_ctx->mutex);
    app_ctx->is_shutdown_complete = true;
    aws_mutex_unlock(&app_ctx->mutex);
    aws_condition_variable_notify_one(&app_ctx->c_var);
}

static void s_on_client_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    if (error_code) {
        fprintf(stderr, "Failed to create connection with error %s\n", aws_error_debug_str(aws_last_error()));
        exit(1);
    }
    struct benchmark_ctx *app_ctx = user_data;

    aws_mutex_lock(&app_ctx->mutex);
    app_ctx->connection = connection;
    aws_mutex_unlock(&app_ctx->mutex);
    aws_condition_variable_notify_one(&app_ctx->c_var);
}

static bool s_is_connected(void *context) {
    struct benchmark_ctx *app_ctx = context;
    return app_ctx->connection != NULL;
}

/************************* general ops ******************************************/

static bool s_is_shutdown_complete(void *context) {
    struct benchmark_ctx *app_ctx = context;
    return app_ctx->is_shutdown_complete;
}

static struct aws_http_message *s_create_request(struct benchmark_ctx *app_ctx) {
    struct aws_http_message *request = aws_http2_message_new_request(app_ctx->allocator);

    struct aws_http_header request_headers_src[] = {
        DEFINE_HEADER(":method", "GET"),
        {
            .name = aws_byte_cursor_from_c_str(":scheme"),
            .value = *aws_uri_scheme(&app_ctx->uri),
        },
        {
            .name = aws_byte_cursor_from_c_str(":path"),
            .value = *aws_uri_path(&app_ctx->uri),
        },
        {
            .name = aws_byte_cursor_from_c_str(":authority"),
            .value = *aws_uri_host_name(&app_ctx->uri),
        },
    };
    aws_http_message_add_header_array(request, request_headers_src, AWS_ARRAY_SIZE(request_headers_src));
    return request;
}

static void s_run_benchmark(struct benchmark_ctx *app_ctx) {
    aws_http_benchmark_helper_init(app_ctx, &app_ctx->helper);
    struct aws_http_message *request = s_create_request(app_ctx);

    if (direct_connection) {
        s_run_direct_connection_test(app_ctx, request);
    } else {
        s_run_stream_manager_test(app_ctx, request);
    }

    aws_http_message_release(request);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    struct aws_allocator *allocator = aws_default_allocator();

    aws_http_library_init(allocator);

    struct benchmark_ctx app_ctx;
    AWS_ZERO_STRUCT(app_ctx);
    app_ctx.allocator = allocator;
    app_ctx.batch_size = max_connections * streams_per_connection;
    app_ctx.log_level = log_level;

    aws_mutex_init(&app_ctx.mutex);
    aws_condition_variable_init(&app_ctx.c_var);

    struct aws_logger logger;
    AWS_ZERO_STRUCT(logger);

    if (app_ctx.log_level) {
        struct aws_logger_standard_options options = {
            .level = app_ctx.log_level,
            .file = stderr,
        };

        if (aws_logger_init_standard(&logger, allocator, &options)) {
            fprintf(stderr, "Failed to initialize logger with error %s\n", aws_error_debug_str(aws_last_error()));
            exit(1);
        }

        aws_logger_set(&logger);
    }
    if (aws_uri_init_parse(&app_ctx.uri, allocator, &uri_cursor)) {
        fprintf(stderr, "Failed to create uri %s\n", aws_error_debug_str(aws_last_error()));
        exit(1);
    }

    aws_atomic_store_int(&app_ctx.streams_completed, 0);
    aws_atomic_store_int(&app_ctx.streams_failed, 0);

    bool use_tls = true;
    uint32_t port = 443;

    if (!app_ctx.uri.scheme.len && (app_ctx.uri.port == 80 || app_ctx.uri.port == 8080)) {
        use_tls = false;
    } else {
        if (aws_byte_cursor_eq_c_str_ignore_case(&app_ctx.uri.scheme, "http")) {
            use_tls = false;
        }
    }

    struct aws_tls_ctx *tls_ctx = NULL;
    struct aws_tls_ctx_options tls_ctx_options;
    AWS_ZERO_STRUCT(tls_ctx_options);
    struct aws_tls_connection_options tls_connection_options;
    AWS_ZERO_STRUCT(tls_connection_options);
    struct aws_tls_connection_options *tls_options = NULL;

    if (use_tls) {
        aws_tls_ctx_options_init_default_client(&tls_ctx_options, allocator);
        aws_tls_ctx_options_set_verify_peer(&tls_ctx_options, false);

        if (aws_tls_ctx_options_set_alpn_list(&tls_ctx_options, "h2;http/1.1")) {
            fprintf(stderr, "Failed to load alpn list with error %s.", aws_error_debug_str(aws_last_error()));
            exit(1);
        }

        tls_ctx = aws_tls_client_ctx_new(allocator, &tls_ctx_options);

        if (!tls_ctx) {
            fprintf(stderr, "Failed to initialize TLS context with error %s.", aws_error_debug_str(aws_last_error()));
            exit(1);
        }

        aws_tls_connection_options_init_from_ctx(&tls_connection_options, tls_ctx);
        if (aws_tls_connection_options_set_server_name(&tls_connection_options, allocator, &app_ctx.uri.host_name)) {
            fprintf(stderr, "Failed to set servername with error %s.", aws_error_debug_str(aws_last_error()));
            exit(1);
        }
        tls_options = &tls_connection_options;

        if (app_ctx.uri.port) {
            port = app_ctx.uri.port;
        }
    } else {
        port = 80;
        if (app_ctx.uri.port) {
            port = app_ctx.uri.port;
        }
    }

    app_ctx.el_group = aws_event_loop_group_new_default(allocator, 0, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = app_ctx.el_group,
        .max_entries = 8,
    };

    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = app_ctx.el_group,
        .host_resolver = resolver,
    };
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms = 3000,
        .keep_alive_timeout_sec = 0,
        .keepalive = false,
        .keep_alive_interval_sec = 0,
    };
    if (!direct_connection) {
        struct aws_http2_stream_manager_options sm_options = {
            .bootstrap = bootstrap,
            .socket_options = &socket_options,
            .tls_connection_options = use_tls ? tls_options : NULL,
            .host = app_ctx.uri.host_name,
            .port = port,
            .max_connections = max_connections,
            .max_concurrent_streams_per_connection = streams_per_connection,
            .http2_prior_knowledge = !use_tls,
            .shutdown_complete_user_data = &app_ctx,
            .shutdown_complete_callback = s_on_shutdown_complete,
        };
        app_ctx.manager = aws_http2_stream_manager_new(allocator, &sm_options);
    } else {
        struct aws_http_client_connection_options http_client_options = {
            .self_size = sizeof(struct aws_http_client_connection_options),
            .socket_options = &socket_options,
            .allocator = allocator,
            .port = port,
            .host_name = app_ctx.uri.host_name,
            .bootstrap = bootstrap,
            .initial_window_size = SIZE_MAX,
            .tls_options = tls_options,
            .user_data = &app_ctx,
            .on_setup = s_on_client_connection_setup,
            .on_shutdown = s_on_connection_shutdown,
        };
        if (aws_http_client_connect(&http_client_options)) {
            exit(1);
        }
        aws_mutex_lock(&app_ctx.mutex);
        aws_condition_variable_wait_pred(&app_ctx.c_var, &app_ctx.mutex, s_is_connected, &app_ctx);
        aws_mutex_unlock(&app_ctx.mutex);
    }

    /* Really do the job */
    s_run_benchmark(&app_ctx);

    if (!direct_connection) {
        aws_http2_stream_manager_release(app_ctx.manager);
    } else {
        aws_http_connection_release(app_ctx.connection);
    }

    aws_mutex_lock(&app_ctx.mutex);
    aws_condition_variable_wait_pred(&app_ctx.c_var, &app_ctx.mutex, s_is_shutdown_complete, &app_ctx);
    aws_mutex_unlock(&app_ctx.mutex);

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(app_ctx.el_group);

    if (tls_ctx) {
        aws_tls_connection_options_clean_up(&tls_connection_options);
        aws_tls_ctx_release(tls_ctx);
        aws_tls_ctx_options_clean_up(&tls_ctx_options);
    }

    aws_http_library_clean_up();

    if (app_ctx.log_level) {
        aws_logger_clean_up(&logger);
    }

    aws_uri_clean_up(&app_ctx.uri);

    return 0;
}
