/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/http/connection.h>
#include <aws/http/request_response.h>

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
#include <aws/io/shared_library.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#include <inttypes.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* Disable warnings about fopen() being insecure */
#    pragma warning(disable : 4204) /* Declared initializers */
#    pragma warning(disable : 4221) /* Local var in declared initializer */
#endif

#define ELASTICURL_VERSION "0.2.0"

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
    FILE *input_file;
    struct aws_input_stream *input_body;
    struct aws_http_message *request;
    struct aws_http_connection *connection;
    const char *signing_library_path;
    struct aws_shared_library signing_library;
    const char *signing_function_name;
    struct aws_hash_table signing_context;
    aws_http_message_transform_fn *signing_function;
    const char *alpn;
    bool include_headers;
    bool insecure;
    FILE *output;
    const char *trace_file;
    enum aws_log_level log_level;
    enum aws_http_version required_http_version;
    bool exchange_completed;
};

static void s_usage(int exit_code) {

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
    fprintf(stderr, "      --signing-lib: path to a shared library with an exported signing function to use\n");
    fprintf(stderr, "      --signing-func: name of the signing function to use within the signing library\n");
    fprintf(
        stderr,
        "      --signing-context: key=value pair to pass to the signing function; may be used multiple times\n");
    fprintf(stderr, "  -o, --output FILE: dumps content-body to FILE instead of stdout.\n");
    fprintf(stderr, "  -t, --trace FILE: dumps logs to FILE instead of stderr.\n");
    fprintf(stderr, "  -v, --verbose: ERROR|INFO|DEBUG|TRACE: log level to configure. Default is none.\n");
    fprintf(stderr, "      --version: print the version of elasticurl.\n");
    fprintf(stderr, "      --http2: HTTP/2 connection required\n");
    fprintf(stderr, "      --http1_1: HTTP/1.1 connection required\n");
    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(exit_code);
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
    {"signing-lib", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'j'},
    {"include", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'i'},
    {"insecure", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'k'},
    {"signing-func", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'l'},
    {"signing-context", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'm'},
    {"output", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'o'},
    {"trace", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},
    {"verbose", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'v'},
    {"version", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'V'},
    {"http2", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'w'},
    {"http1_1", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'W'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    /* Per getopt(3) the last element of the array has to be filled with all zeros */
    {NULL, AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 0},
};

static int s_parse_signing_context(
    struct aws_hash_table *signing_context,
    struct aws_allocator *allocator,
    const char *context_argument) {
    (void)signing_context;
    (void)context_argument;

    char *delimiter = memchr(context_argument, ':', strlen(context_argument));
    if (!delimiter) {
        fprintf(stderr, "invalid signing context line \"%s\".", context_argument);
        exit(1);
    }

    struct aws_string *key =
        aws_string_new_from_array(allocator, (const uint8_t *)context_argument, delimiter - context_argument);
    struct aws_string *value =
        aws_string_new_from_array(allocator, (const uint8_t *)delimiter + 1, strlen(delimiter + 1));
    if (key == NULL || value == NULL) {
        fprintf(stderr, "failure allocating signing context kv pair");
        exit(1);
    }

    aws_hash_table_put(signing_context, key, value, NULL);

    return AWS_OP_SUCCESS;
}

static void s_parse_options(int argc, char **argv, struct elasticurl_ctx *ctx) {
    bool uri_found = false;
    while (true) {
        int option_index = 0;
        int c =
            aws_cli_getopt_long(argc, argv, "a:b:c:e:f:H:d:g:j:l:m:M:GPHiko:t:v:VwWh", s_long_options, &option_index);
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
                    s_usage(1);
                }
                ctx->header_lines[ctx->header_line_count++] = aws_cli_optarg;
                break;
            case 'd': {
                struct aws_byte_cursor data_cursor = aws_byte_cursor_from_c_str(aws_cli_optarg);
                ctx->input_body = aws_input_stream_new_from_cursor(ctx->allocator, &data_cursor);
                break;
            }
            case 'g':
                ctx->input_file = fopen(aws_cli_optarg, "rb");
                ctx->input_body = aws_input_stream_new_from_open_file(ctx->allocator, ctx->input_file);
                if (!ctx->input_file) {
                    fprintf(stderr, "unable to open file %s.\n", aws_cli_optarg);
                    s_usage(1);
                }
                break;
            case 'j':
                ctx->signing_library_path = aws_cli_optarg;
                if (aws_shared_library_init(&ctx->signing_library, aws_cli_optarg)) {
                    fprintf(stderr, "unable to open signing library %s.\n", aws_cli_optarg);
                    s_usage(1);
                }
                break;
            case 'l':
                ctx->signing_function_name = aws_cli_optarg;
                break;
            case 'm':
                if (s_parse_signing_context(&ctx->signing_context, ctx->allocator, aws_cli_optarg)) {
                    fprintf(stderr, "error parsing signing context \"%s\"\n", aws_cli_optarg);
                    s_usage(1);
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
                    s_usage(1);
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
                    s_usage(1);
                }
                break;
            case 'V':
                fprintf(stderr, "elasticurl %s\n", ELASTICURL_VERSION);
                exit(0);
            case 'w':
                ctx->alpn = "h2";
                ctx->required_http_version = AWS_HTTP_VERSION_2;
                break;
            case 'W':
                ctx->alpn = "http/1.1";
                ctx->required_http_version = AWS_HTTP_VERSION_1_1;
                break;
            case 'h':
                s_usage(0);
                break;
            case 0x02: {
                struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str(aws_cli_positional_arg);
                if (aws_uri_init_parse(&ctx->uri, ctx->allocator, &uri_cursor)) {
                    fprintf(
                        stderr,
                        "Failed to parse uri %s with error %s\n",
                        (char *)uri_cursor.ptr,
                        aws_error_debug_str(aws_last_error()));
                    s_usage(1);
                }
                uri_found = true;
            } break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
        }
    }

    if (ctx->signing_function_name != NULL) {
        if (ctx->signing_library_path == NULL) {
            fprintf(
                stderr,
                "To sign a request made by Elasticurl you must supply both a signing library path and a signing "
                "function name\n");
            s_usage(1);
        }

        if (aws_shared_library_find_function(
                &ctx->signing_library, ctx->signing_function_name, (aws_generic_function *)&ctx->signing_function)) {
            fprintf(
                stderr,
                "Unable to find function %s in signing library %s",
                ctx->signing_function_name,
                ctx->signing_library_path);
            s_usage(1);
        }
    }

    if (ctx->input_body == NULL) {
        struct aws_byte_cursor empty_cursor;
        AWS_ZERO_STRUCT(empty_cursor);
        ctx->input_body = aws_input_stream_new_from_cursor(ctx->allocator, &empty_cursor);
    }

    if (!uri_found) {
        fprintf(stderr, "A URI for the request must be supplied.\n");
        s_usage(1);
    }
}

static int s_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {

    (void)stream;
    struct elasticurl_ctx *app_ctx = user_data;

    fwrite(data->ptr, 1, data->len, app_ctx->output);

    return AWS_OP_SUCCESS;
}

static int s_on_incoming_headers_fn(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    struct elasticurl_ctx *app_ctx = user_data;
    (void)app_ctx;
    (void)stream;

    /* Ignore informational headers */
    if (header_block == AWS_HTTP_HEADER_BLOCK_INFORMATIONAL) {
        return AWS_OP_SUCCESS;
    }

    if (app_ctx->include_headers) {
        if (!app_ctx->response_code_written) {
            int status = 0;
            aws_http_stream_get_incoming_response_status(stream, &status);
            fprintf(stdout, "Response Status: %d\n", status);
            app_ctx->response_code_written = true;
        }

        for (size_t i = 0; i < num_headers; ++i) {
            fwrite(header_array[i].name.ptr, 1, header_array[i].name.len, stdout);
            fprintf(stdout, ": ");
            fwrite(header_array[i].value.ptr, 1, header_array[i].value.len, stdout);
            fprintf(stdout, "\n");
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_on_incoming_header_block_done_fn(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    (void)stream;
    (void)header_block;
    (void)user_data;

    return AWS_OP_SUCCESS;
}

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
    aws_http_stream_release(stream);
}

static struct aws_http_message *s_build_http_request(
    struct elasticurl_ctx *app_ctx,
    enum aws_http_version protocol_version) {

    struct aws_http_message *request = protocol_version == AWS_HTTP_VERSION_2
                                           ? aws_http2_message_new_request(app_ctx->allocator)
                                           : aws_http_message_new_request(app_ctx->allocator);
    if (request == NULL) {
        fprintf(stderr, "failed to allocate request\n");
        exit(1);
    }

    aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str(app_ctx->verb));
    if (app_ctx->uri.path_and_query.len != 0) {
        aws_http_message_set_request_path(request, app_ctx->uri.path_and_query);
    } else {
        aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/"));
    }

    if (protocol_version == AWS_HTTP_VERSION_2) {
        struct aws_http_headers *h2_headers = aws_http_message_get_headers(request);
        aws_http2_headers_set_request_scheme(h2_headers, app_ctx->uri.scheme);
        aws_http2_headers_set_request_authority(h2_headers, app_ctx->uri.host_name);
    } else {
        struct aws_http_header host_header = {
            .name = aws_byte_cursor_from_c_str("host"),
            .value = app_ctx->uri.host_name,
        };
        aws_http_message_add_header(request, host_header);
    }
    struct aws_http_header accept_header = {
        .name = aws_byte_cursor_from_c_str("accept"),
        .value = aws_byte_cursor_from_c_str("*/*"),
    };
    aws_http_message_add_header(request, accept_header);
    struct aws_http_header user_agent_header = {
        .name = aws_byte_cursor_from_c_str("user-agent"),
        .value = aws_byte_cursor_from_c_str("elasticurl 1.0, Powered by the AWS Common Runtime."),
    };
    aws_http_message_add_header(request, user_agent_header);

    if (app_ctx->input_body) {
        int64_t data_len = 0;
        if (aws_input_stream_get_length(app_ctx->input_body, &data_len)) {
            fprintf(stderr, "failed to get length of input stream.\n");
            exit(1);
        }

        if (data_len > 0) {
            char content_length[64];
            AWS_ZERO_ARRAY(content_length);
            snprintf(content_length, sizeof(content_length), "%" PRIi64, data_len);
            struct aws_http_header content_length_header = {
                .name = aws_byte_cursor_from_c_str("content-length"),
                .value = aws_byte_cursor_from_c_str(content_length),
            };
            aws_http_message_add_header(request, content_length_header);
            aws_http_message_set_body_stream(request, app_ctx->input_body);
        }
    }

    AWS_ASSERT(app_ctx->header_line_count <= 10);
    for (size_t i = 0; i < app_ctx->header_line_count; ++i) {
        char *delimiter = memchr(app_ctx->header_lines[i], ':', strlen(app_ctx->header_lines[i]));

        if (!delimiter) {
            fprintf(stderr, "invalid header line %s configured.", app_ctx->header_lines[i]);
            exit(1);
        }

        struct aws_http_header custom_header = {
            .name = aws_byte_cursor_from_array(app_ctx->header_lines[i], delimiter - app_ctx->header_lines[i]),
            .value = aws_byte_cursor_from_c_str(delimiter + 1),
        };
        aws_http_message_add_header(request, custom_header);
    }

    return request;
}

static void s_on_signing_complete(struct aws_http_message *request, int error_code, void *user_data);

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

    if (app_ctx->required_http_version) {
        if (aws_http_connection_get_version(connection) != app_ctx->required_http_version) {
            fprintf(stderr, "Error. The requested HTTP version, %s, is not supported by the peer.", app_ctx->alpn);
            exit(1);
        }
    }

    app_ctx->connection = connection;
    app_ctx->request = s_build_http_request(app_ctx, aws_http_connection_get_version(connection));

    /* If async signing function is set, invoke it. It must invoke the signing complete callback when it's done. */
    if (app_ctx->signing_function) {
        app_ctx->signing_function(app_ctx->request, &app_ctx->signing_context, s_on_signing_complete, app_ctx);
    } else {
        /* If no signing function, proceed immediately to next step. */
        s_on_signing_complete(app_ctx->request, AWS_ERROR_SUCCESS, app_ctx);
    }
}

static void s_on_signing_complete(struct aws_http_message *request, int error_code, void *user_data) {
    struct elasticurl_ctx *app_ctx = user_data;

    AWS_FATAL_ASSERT(request == app_ctx->request);

    if (error_code) {
        fprintf(stderr, "Signing failure\n");
        exit(1);
    }

    struct aws_http_make_request_options final_request = {
        .self_size = sizeof(final_request),
        .user_data = app_ctx,
        .request = app_ctx->request,
        .on_response_headers = s_on_incoming_headers_fn,
        .on_response_header_block_done = s_on_incoming_header_block_done_fn,
        .on_response_body = s_on_incoming_body_fn,
        .on_complete = s_on_stream_complete_fn,
    };

    app_ctx->response_code_written = false;

    struct aws_http_stream *stream = aws_http_connection_make_request(app_ctx->connection, &final_request);
    if (!stream) {
        fprintf(stderr, "failed to create request.");
        exit(1);
    }
    aws_http_stream_activate(stream);

    /* Connection will stay alive until stream completes */
    aws_http_connection_release(app_ctx->connection);
    app_ctx->connection = NULL;
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

    aws_http_library_init(allocator);

    struct elasticurl_ctx app_ctx;
    AWS_ZERO_STRUCT(app_ctx);
    app_ctx.allocator = allocator;
    app_ctx.c_var = (struct aws_condition_variable)AWS_CONDITION_VARIABLE_INIT;
    app_ctx.connect_timeout = 3000;
    app_ctx.output = stdout;
    app_ctx.verb = "GET";
    app_ctx.alpn = "h2;http/1.1";
    aws_mutex_init(&app_ctx.mutex);
    aws_hash_table_init(
        &app_ctx.signing_context,
        allocator,
        10,
        aws_hash_string,
        aws_hash_callback_string_eq,
        aws_hash_callback_string_destroy,
        aws_hash_callback_string_destroy);

    s_parse_options(argc, argv, &app_ctx);

    struct aws_logger logger;
    AWS_ZERO_STRUCT(logger);

    if (app_ctx.log_level) {
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

        if (aws_tls_ctx_options_set_alpn_list(&tls_ctx_options, app_ctx.alpn)) {
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
    if (app_ctx.required_http_version == AWS_HTTP_VERSION_2 && !use_tls) {
        /* Use prior knowledge to connect */
        http_client_options.prior_knowledge_http2 = true;
    }
    aws_http_client_connect(&http_client_options);
    aws_mutex_lock(&app_ctx.mutex);
    aws_condition_variable_wait_pred(&app_ctx.c_var, &app_ctx.mutex, s_completion_predicate, &app_ctx);
    aws_mutex_unlock(&app_ctx.mutex);

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

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

    aws_http_message_destroy(app_ctx.request);

    aws_shared_library_clean_up(&app_ctx.signing_library);

    if (app_ctx.output != stdout) {
        fclose(app_ctx.output);
    }

    if (app_ctx.input_body) {
        aws_input_stream_release(app_ctx.input_body);
    }

    if (app_ctx.input_file) {
        fclose(app_ctx.input_file);
    }

    aws_hash_table_clean_up(&app_ctx.signing_context);

    return 0;
}
