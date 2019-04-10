/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/http/request_response.h>

#include <aws/common/command_line_parser.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>

#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/log_channel.h>
#include <aws/io/log_formatter.h>
#include <aws/io/log_writer.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* Disable warnings about fopen() being insecure */
#    pragma warning(disable : 4204) /* Declared initializers */
#    pragma warning(disable : 4221) /* Local var in declared initializer */
#endif

struct elasticurl_ctx {
    struct aws_allocator *allocator;
    const char *verb;
    struct aws_uri uri;
    struct aws_mutex mutex;
    struct aws_condition_variable c_var;
    bool response_code_written;
    const char *cacert;
    const char *capath;
    const char *cert;
    const char *key;
    int connect_timeout;
    const char *header_lines[10];
    size_t header_line_count;
    struct aws_byte_cursor data;
    FILE *data_file;
    bool include_headers;
    bool insecure;
    FILE *output;
    const char *trace_file;
    enum aws_log_level log_level;
    bool exchange_completed;
};

static void s_usage(void) {

    fprintf(stderr, "usage: elasticurl [options] url\n");
    fprintf(stderr, " url: url to make a request to. The default is a GET request.\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "      --cacert FILE: path to a CA certficate file.\n");
    fprintf(stderr, "      --capath PATH: path to a directory containing CA files.\n");
    fprintf(stderr, "      --cert FILE: path to a PEM encoded certificate to use with mTLS\n");
    fprintf(stderr, "      --key FILE: Path to a PEM encoded private key that matches cert.\n");
    fprintf(stderr, "      --connect-timeout INT: time in milliseconds to wait for a connection.\n");
    fprintf(stderr, "  -H, --header LINE: line to send as a header in format [header-key]: [header-value]\n");
    fprintf(stderr, "  -d, --data STRING: Data to POST or PUT\n");
    fprintf(stderr, "      --data-file FILE: File to read from file and POST or PUT\n");
    fprintf(stderr, "  -M, --method STRING: Http Method verb to use for the request\n");
    fprintf(stderr, "  -G, --get: uses GET for the verb.\n");
    fprintf(stderr, "  -P, --post: uses POST for the verb.\n");
    fprintf(stderr, "  -I, --head: uses HEAD for the verb.\n");
    fprintf(stderr, "  -i, --include: includes headers in output.\n");
    fprintf(stderr, "  -k, --insecure: turns off SSL/TLS validation.\n");
    fprintf(stderr, "  -o, --output FILE: dumps content-body to FILE instead of stdout.\n");
    fprintf(stderr, "  -t, --trace FILE: dumps logs to FILE instead of stderr.\n");
    fprintf(stderr, "  -v, --verbose ERROR|INFO|DEBUG|TRACE: log level to configure. Default is none.\n");
    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(1);
}

static struct aws_cli_option s_long_options[] = {
    {"cacert", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {"capath", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'b'},
    {"cert", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'c'},
    {"key", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'e'},
    {"connect-timeout", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'f'},
    {"header", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'H'},
    {"data", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'd'},
    {"data-file", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'g'},
    {"method", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'M'},
    {"get", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'G'},
    {"post", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'P'},
    {"head", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'I'},
    {"include", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'i'},
    {"insecure", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'k'},
    {"output", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'o'},
    {"trace", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},
    {"verbose", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'v'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    /* Per getopt(3) the last element of the array has to be filled with all zeros */
    {NULL, AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct elasticurl_ctx *ctx) {
    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "a:b:c:e:f:H:d:g:M:GPHiko:t:v:h", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null */
                break;
            case 'a':
                ctx->cacert = aws_cli_optarg;
                break;
            case 'b':
                ctx->capath = aws_cli_optarg;
                break;
            case 'c':
                ctx->cert = aws_cli_optarg;
                break;
            case 'e':
                ctx->key = aws_cli_optarg;
                break;
            case 'f':
                ctx->connect_timeout = atoi(aws_cli_optarg);
                break;
            case 'H':
                if (ctx->header_line_count >= sizeof(ctx->header_lines) / sizeof(const char *)) {
                    fprintf(stderr, "currently only 10 header lines are supported.\n");
                    s_usage();
                }
                ctx->header_lines[ctx->header_line_count++] = aws_cli_optarg;
                break;
            case 'd':
                ctx->data = aws_byte_cursor_from_c_str(aws_cli_optarg);
                break;
            case 'g':

                ctx->data_file = fopen(aws_cli_optarg, "rb");
                if (!ctx->data_file) {
                    fprintf(stderr, "unable to open file %s.\n", aws_cli_optarg);
                    s_usage();
                }
                break;
            case 'M':
                ctx->verb = aws_cli_optarg;
                break;
            case 'G':
                ctx->verb = "GET";
                break;
            case 'P':
                ctx->verb = "POST";
                break;
            case 'I':
                ctx->verb = "HEAD";
                break;
            case 'i':
                ctx->include_headers = true;
                break;
            case 'k':
                ctx->insecure = true;
                break;
            case 'o':
                ctx->output = fopen(aws_cli_optarg, "wb");

                if (!ctx->output) {
                    fprintf(stderr, "unable to open file %s.\n", aws_cli_optarg);
                    s_usage();
                }
                break;
            case 't':
                ctx->trace_file = aws_cli_optarg;
                break;
            case 'v':
                if (!strcmp(aws_cli_optarg, "TRACE")) {
                    ctx->log_level = AWS_LL_TRACE;
                } else if (!strcmp(aws_cli_optarg, "INFO")) {
                    ctx->log_level = AWS_LL_INFO;
                } else if (!strcmp(aws_cli_optarg, "DEBUG")) {
                    ctx->log_level = AWS_LL_DEBUG;
                } else if (!strcmp(aws_cli_optarg, "ERROR")) {
                    ctx->log_level = AWS_LL_ERROR;
                } else {
                    fprintf(stderr, "unsupported log level %s.\n", aws_cli_optarg);
                    s_usage();
                }
                break;
            case 'h':
                s_usage();
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage();
        }
    }

    if (aws_cli_optind < argc) {
        struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str(argv[aws_cli_optind++]);

        if (aws_uri_init_parse(&ctx->uri, ctx->allocator, &uri_cursor)) {
            fprintf(
                stderr,
                "Failed to parse uri %s with error %s\n",
                (char *)uri_cursor.ptr,
                aws_error_debug_str(aws_last_error()));
            s_usage();
        };
    } else {
        fprintf(stderr, "A URI for the request must be supplied.\n");
        s_usage();
    }
}

static void s_on_incoming_body_fn(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    /* NOLINTNEXTLINE(readability-non-const-parameter) */
    size_t *out_window_update_size,
    void *user_data) {

    (void)stream;
    (void)out_window_update_size;
    struct elasticurl_ctx *app_ctx = user_data;

    fwrite(data->ptr, 1, data->len, app_ctx->output);
}

enum aws_http_outgoing_body_state s_stream_outgoing_body_fn(
    struct aws_http_stream *stream,
    struct aws_byte_buf *buf,
    void *user_data) {
    (void)stream;
    struct elasticurl_ctx *app_ctx = user_data;

    if (app_ctx->data.len) {
        size_t max_cpy = buf->len > app_ctx->data.len ? app_ctx->data.len : buf->len;
        struct aws_byte_cursor outgoing_data = aws_byte_cursor_advance(&app_ctx->data, max_cpy);
        aws_byte_buf_append(buf, &outgoing_data);

        /* if any data is left in the buffer, tell the client that we're still in progress,
         * otherwise say we're done. */
        if (app_ctx->data.len) {
            return AWS_HTTP_OUTGOING_BODY_IN_PROGRESS;
        }

        return AWS_HTTP_OUTGOING_BODY_DONE;
    }

    if (app_ctx->data_file) {
#ifdef _WIN32
        size_t read_val = fread(buf->buffer, 1, buf->len, app_ctx->data_file);
        long long read = read_val == 0 ? ferror(app_ctx->data_file) : (long long)read_val;
#else
        ssize_t read = fread(buf->buffer, 1, buf->len, app_ctx->data_file);
#endif

        /* if any data is left in the buffer, tell the client that we're still in progress,
         * otherwise say we're done. */
        if (read > 0) {
            return AWS_HTTP_OUTGOING_BODY_IN_PROGRESS;
        }

        return AWS_HTTP_OUTGOING_BODY_DONE;
    }

    return AWS_HTTP_OUTGOING_BODY_DONE;
}

static void s_on_incoming_headers_fn(
    struct aws_http_stream *stream,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    struct elasticurl_ctx *app_ctx = user_data;
    (void)app_ctx;
    (void)stream;

    if (app_ctx->include_headers) {
        if (!app_ctx->response_code_written) {
            int status = 0;
            aws_http_stream_get_incoming_response_status(stream, &status);
            fprintf(stdout, "Response Status: %d\n", status);
            app_ctx->response_code_written = true;
        }

        for (size_t i = 0; i < num_headers; ++i) {
            fwrite(header_array[i].name.ptr, 1, header_array[i].name.len, stdout);
            fprintf(stdout, ":");
            fwrite(header_array[i].value.ptr, 1, header_array[i].value.len, stdout);
            fprintf(stdout, "\n");
        }
    }
}

static void s_on_incoming_header_block_done_fn(struct aws_http_stream *stream, bool has_body, void *user_data) {
    (void)stream;
    (void)has_body;
    (void)user_data;
}

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
    aws_http_stream_release(stream);
}

static void s_on_client_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct elasticurl_ctx *app_ctx = user_data;

    if (error_code) {
        fprintf(stderr, "Connection failed with error %s\n", aws_error_debug_str(error_code));
        aws_mutex_lock(&app_ctx->mutex);
        app_ctx->exchange_completed = true;
        aws_mutex_unlock(&app_ctx->mutex);
        aws_condition_variable_notify_all(&app_ctx->c_var);
        return;
    }

    struct aws_http_request_options request_options = AWS_HTTP_REQUEST_OPTIONS_INIT;
    request_options.uri = app_ctx->uri.path_and_query;
    request_options.user_data = app_ctx;
    request_options.client_connection = connection;
    request_options.method = aws_byte_cursor_from_c_str(app_ctx->verb);
    request_options.on_response_headers = s_on_incoming_headers_fn;
    request_options.on_response_header_block_done = s_on_incoming_header_block_done_fn;
    request_options.on_response_body = s_on_incoming_body_fn;
    request_options.on_complete = s_on_stream_complete_fn;

    app_ctx->response_code_written = false;

    /* only 10 custom header lines are supported, we send an additional 4 by default (hence 14). */
    struct aws_http_header headers[14];
    AWS_ZERO_ARRAY(headers);
    size_t header_count = 3;
    size_t pre_header_count = 3;

    headers[0].name = aws_byte_cursor_from_c_str("accept");
    headers[0].value = aws_byte_cursor_from_c_str("*/*");
    headers[1].name = aws_byte_cursor_from_c_str("host");
    headers[1].value = app_ctx->uri.host_name;
    headers[2].name = aws_byte_cursor_from_c_str("user-agent");
    headers[2].value = aws_byte_cursor_from_c_str("elasticurl 1.0, Powered by the AWS Common Runtime.");

    size_t data_len;
    if (app_ctx->data.len) {
        data_len = app_ctx->data.len;
    } else {
        if (fseek(app_ctx->data_file, 0L, SEEK_END)) {
            fprintf(stderr, "failed to seek data file.\n");
            exit(1);
        }

        data_len = (size_t)ftell(app_ctx->data_file);
        fseek(app_ctx->data_file, 0L, SEEK_SET);
    }

    char content_length[64];
    AWS_ZERO_ARRAY(content_length);
    sprintf(content_length, "%llu", (unsigned long long)data_len);
    headers[3].name = aws_byte_cursor_from_c_str("content-length");
    headers[3].value = aws_byte_cursor_from_c_str(content_length);
    pre_header_count += 1;
    header_count += 1;
    request_options.stream_outgoing_body = s_stream_outgoing_body_fn;

    assert(app_ctx->header_line_count <= 10);
    for (size_t i = 0; i < app_ctx->header_line_count; ++i) {
        char *delimiter = memchr(app_ctx->header_lines[i], ':', strlen(app_ctx->header_lines[i]));

        if (!delimiter) {
            fprintf(stderr, "invalid header line %s configured.", app_ctx->header_lines[i]);
            exit(1);
        }

        headers[i + pre_header_count].name =
            aws_byte_cursor_from_array(app_ctx->header_lines[i], delimiter - app_ctx->header_lines[i]);
        headers[i + pre_header_count].value = aws_byte_cursor_from_c_str(delimiter + 1);
        header_count++;
    }

    request_options.header_array = headers;
    request_options.num_headers = header_count;

    struct aws_http_stream *stream = aws_http_stream_new_client_request(&request_options);
    if (!stream) {
        fprintf(stderr, "failed to create request.");
        exit(1);
    }

    aws_http_connection_release(connection);
}

static void s_on_client_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)error_code;
    (void)connection;
    struct elasticurl_ctx *app_ctx = user_data;

    aws_mutex_lock(&app_ctx->mutex);
    app_ctx->exchange_completed = true;
    aws_mutex_unlock(&app_ctx->mutex);
    aws_condition_variable_notify_all(&app_ctx->c_var);
}

static bool s_completion_predicate(void *arg) {
    struct elasticurl_ctx *app_ctx = arg;
    return app_ctx->exchange_completed;
}

int main(int argc, char **argv) {
    struct aws_allocator *allocator = aws_default_allocator();

    aws_load_error_strings();
    aws_io_load_error_strings();
    aws_http_library_init(allocator);

    struct elasticurl_ctx app_ctx;
    AWS_ZERO_STRUCT(app_ctx);
    app_ctx.allocator = allocator;
    app_ctx.c_var = (struct aws_condition_variable)AWS_CONDITION_VARIABLE_INIT;
    app_ctx.connect_timeout = 3000;
    app_ctx.output = stdout;
    app_ctx.verb = "GET";
    aws_mutex_init(&app_ctx.mutex);

    s_parse_options(argc, argv, &app_ctx);

    struct aws_logger logger;
    AWS_ZERO_STRUCT(logger);

    if (app_ctx.log_level) {
        aws_io_load_log_subject_strings();

        struct aws_logger_standard_options options = {
            .level = app_ctx.log_level,
        };

        if (app_ctx.trace_file) {
            options.filename = app_ctx.trace_file;
        } else {
            options.file = stderr;
        }

        if (aws_logger_init_standard(&logger, allocator, &options)) {
            fprintf(stderr, "Failed to initialize logger with error %s\n", aws_error_debug_str(aws_last_error()));
            exit(1);
        }

        aws_logger_set(&logger);
    }

    bool use_tls = true;
    uint16_t port = 443;

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
        aws_tls_init_static_state(allocator);

        if (app_ctx.cert && app_ctx.key) {
            if (aws_tls_ctx_options_init_client_mtls_from_path(
                    &tls_ctx_options, allocator, app_ctx.cert, app_ctx.key)) {
                fprintf(
                    stderr,
                    "Failed to load %s and %s with error %s.",
                    app_ctx.cert,
                    app_ctx.key,
                    aws_error_debug_str(aws_last_error()));
                exit(1);
            }
        }
#ifdef _WIN32
        else if (app_ctx.cert && !app_ctx.key) {
            aws_tls_ctx_options_init_client_mtls_from_system_path(&tls_ctx_options, allocator, app_ctx.cert);
        }
#endif
        else {
            aws_tls_ctx_options_init_default_client(&tls_ctx_options, allocator);
        }

        if (app_ctx.capath || app_ctx.cacert) {
            if (aws_tls_ctx_options_override_default_trust_store_from_path(
                    &tls_ctx_options, app_ctx.capath, app_ctx.cacert)) {
                fprintf(
                    stderr,
                    "Failed to load %s and %s with error %s",
                    app_ctx.capath,
                    app_ctx.cacert,
                    aws_error_debug_str(aws_last_error()));
                exit(1);
            }
        }

        if (app_ctx.insecure) {
            aws_tls_ctx_options_set_verify_peer(&tls_ctx_options, false);
        }

        /* "h2;http/1.1", add this back when we have h2 support */
        if (aws_tls_ctx_options_set_alpn_list(&tls_ctx_options, "http/1.1")) {
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

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 1);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 8, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms = (uint32_t)app_ctx.connect_timeout,
        .keep_alive_timeout_sec = 0,
        .keepalive = false,
        .keep_alive_interval_sec = 0,
    };

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
        .on_shutdown = s_on_client_connection_shutdown,
    };

    aws_http_client_connect(&http_client_options);
    aws_mutex_lock(&app_ctx.mutex);
    aws_condition_variable_wait_pred(&app_ctx.c_var, &app_ctx.mutex, s_completion_predicate, &app_ctx);

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    if (tls_ctx) {
        aws_tls_connection_options_clean_up(&tls_connection_options);
        aws_tls_ctx_destroy(tls_ctx);
        aws_tls_ctx_options_clean_up(&tls_ctx_options);
    }

    aws_tls_clean_up_static_state();
    aws_http_library_clean_up();

    if (app_ctx.log_level) {
        aws_logger_clean_up(&logger);
    }

    aws_uri_clean_up(&app_ctx.uri);

    if (app_ctx.output != stdout) {
        fclose(app_ctx.output);
    }

    if (app_ctx.data_file) {
        fclose(app_ctx.data_file);
    }

    return 0;
}
