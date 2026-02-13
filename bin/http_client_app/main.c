/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/command_line_parser.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/clock.h>
#include <aws/common/error.h>
#include <aws/common/allocator.h>
#include <aws/common/string.h>
#include <aws/common/uri.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/io/socks5.h>
#include <aws/io/logging.h>
#include <aws/http/proxy.h>
#include <aws/http/http.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

struct socks5_proxy_settings {
    char *host;
    char *username;
    char *password;
    uint16_t port;
    bool resolve_host_with_proxy;
};

static void s_socks5_proxy_settings_clean_up(
    struct socks5_proxy_settings *settings,
    struct aws_allocator *allocator) {
    if (!settings) {
        return;
    }
    if (settings->host) {
        aws_mem_release(allocator, settings->host);
    }
    if (settings->username) {
        aws_mem_release(allocator, settings->username);
    }
    if (settings->password) {
        aws_mem_release(allocator, settings->password);
    }
    AWS_ZERO_STRUCT(*settings);
}

static int s_socks5_proxy_settings_init_from_uri(
    struct socks5_proxy_settings *settings,
    struct aws_allocator *allocator,
    const char *proxy_uri) {

    if (!settings || !allocator || !proxy_uri) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Clean up any existing data before reusing the struct */
    s_socks5_proxy_settings_clean_up(settings, allocator);

    struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str(proxy_uri);
    struct aws_uri uri;
    AWS_ZERO_STRUCT(uri);

    if (aws_uri_init_parse(&uri, allocator, &uri_cursor)) {
        fprintf(stderr, "Failed to parse proxy URI \"%s\": %s\n", proxy_uri, aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    const struct aws_byte_cursor *scheme = aws_uri_scheme(&uri);
    if (!scheme || !scheme->len) {
        fprintf(stderr, "Proxy URI \"%s\" must include scheme socks5h://\n", proxy_uri);
        goto on_error;
    }

    if (aws_byte_cursor_eq_c_str_ignore_case(scheme, "socks5h")) {
        settings->resolve_host_with_proxy = true;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(scheme, "socks5")) {
        settings->resolve_host_with_proxy = false;
    } else {
        fprintf(stderr, "Unsupported proxy scheme in \"%s\". Expected socks5h://\n", proxy_uri);
        goto on_error;
    }

    const struct aws_byte_cursor *host = aws_uri_host_name(&uri);
    if (!host || host->len == 0) {
        fprintf(stderr, "Proxy URI \"%s\" must include a host\n", proxy_uri);
        goto on_error;
    }

    settings->host = aws_mem_calloc(allocator, host->len + 1, sizeof(char));
    if (!settings->host) {
        fprintf(stderr, "Failed to allocate memory for proxy host\n");
        goto on_error;
    }
    memcpy(settings->host, host->ptr, host->len);
    settings->host[host->len] = '\0';

    uint32_t parsed_port = aws_uri_port(&uri);
    if (parsed_port == 0) {
        parsed_port = 1080;
    }
    if (parsed_port > UINT16_MAX) {
        fprintf(stderr, "Proxy port %" PRIu32 " exceeds uint16_t range\n", parsed_port);
        goto on_error;
    }
    settings->port = (uint16_t)parsed_port;

    if (uri.user.len > 0) {
        settings->username = aws_mem_calloc(allocator, uri.user.len + 1, sizeof(char));
        if (!settings->username) {
            fprintf(stderr, "Failed to allocate memory for proxy username\n");
            goto on_error;
        }
        memcpy(settings->username, uri.user.ptr, uri.user.len);
        settings->username[uri.user.len] = '\0';
    }

    if (uri.password.len > 0) {
        settings->password = aws_mem_calloc(allocator, uri.password.len + 1, sizeof(char));
        if (!settings->password) {
            fprintf(stderr, "Failed to allocate memory for proxy password\n");
            goto on_error;
        }
        memcpy(settings->password, uri.password.ptr, uri.password.len);
        settings->password[uri.password.len] = '\0';
    }

    aws_uri_clean_up(&uri);
    return AWS_OP_SUCCESS;

on_error:
    aws_uri_clean_up(&uri);
    s_socks5_proxy_settings_clean_up(settings, allocator);
    return AWS_OP_ERR;
}

/*
 * This example demonstrates how to make HTTP requests through a SOCKS5 proxy
 * or directly to the server.
 * 
 * It supports both modes of operation and can be used to test/compare
 * connectivity with and without the proxy.
 */

struct app_ctx {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;
    struct aws_client_bootstrap *bootstrap;
    
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_http_stream *stream;
    
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    
    const char *host_name;
    const char *target_ip;
    uint16_t port;
    const char *path;
    struct socks5_proxy_settings proxy;
    
    bool use_proxy;
    bool use_tls;
    bool verbose;
    
    bool connection_complete;
    int connection_error_code;
    bool stream_complete;
    int stream_error_code;
    
    int response_status;
    struct aws_byte_buf response_body;
    
    /* HTTP Connection Monitoring */
    struct aws_atomic_var pending_requests;
};

static void s_usage(int exit_code) {
    fprintf(stderr, "usage: http_socks5_example [options]\n");
    fprintf(stderr, " --host HOST: Target HTTP host to connect to (default: example.com)\n");
    fprintf(stderr, " --target-ip IP: Target IP address (overrides --host for connection but Host header uses --host)\n");
    fprintf(stderr, " --port PORT: Target port (default: 80 for HTTP, 443 for HTTPS)\n");
    fprintf(stderr, " --path PATH: HTTP request path (default: /)\n");
    fprintf(
        stderr,
        " --proxy URL: SOCKS5 proxy URI (socks5h://... for proxy DNS, socks5://... for local DNS)\n");
    fprintf(stderr, "     TLS is used automatically when the port is set to 443 or 8443\n");
    fprintf(stderr, " --verbose: Print detailed logging\n");
    fprintf(stderr, " --help: Display this message and exit\n");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"host", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'h'},
    {"target-ip", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'i'},
    {"port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'p'},
    {"path", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {"proxy", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"verbose", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'v'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'H'},
    {NULL, 0, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->host_name = "example.com";
    ctx->target_ip = NULL; /* NULL means use host_name for connection */
    ctx->port = 0; /* Will be set later based on whether TLS is enabled */
    ctx->path = "/";
    ctx->use_proxy = false;
    ctx->use_tls = false;
    ctx->verbose = false;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "h:i:p:a:x:vH", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'h':
                ctx->host_name = aws_cli_optarg;
                break;
            case 'i':
                ctx->target_ip = aws_cli_optarg;
                break;
            case 'p':
                ctx->port = (uint16_t)atoi(aws_cli_optarg);
                break;
            case 'a':
                ctx->path = aws_cli_optarg;
                break;
            case 'x':
                if (s_socks5_proxy_settings_init_from_uri(&ctx->proxy, ctx->allocator, aws_cli_optarg)) {
                    s_usage(1);
                }
                ctx->use_proxy = true;
                break;
            case 'v':
                ctx->verbose = true;
                break;
            case 'H':
                s_usage(0);
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", c);
                s_usage(1);
                break;
        }
    }
    
    /* Set default port if not specified */
    if (ctx->port == 0) {
        ctx->port = 80;
    }
    ctx->use_tls = (ctx->port == 443 || ctx->port == 8443);
}

/* Predicate functions for condition variables */
static bool s_connection_completed_predicate(void *arg) {
    struct app_ctx *ctx = arg;
    return ctx->connection_complete;
}

static bool s_stream_completed_predicate(void *arg) {
    struct app_ctx *ctx = arg;
    return ctx->stream_complete;
}

static void s_app_ctx_init(struct app_ctx *ctx, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*ctx);
    ctx->allocator = allocator;
    aws_mutex_init(&ctx->lock);
    aws_condition_variable_init(&ctx->signal);
    aws_atomic_init_int(&ctx->pending_requests, 0);
    aws_byte_buf_init(&ctx->response_body, allocator, 1024); /* Initial buffer capacity */
}

static void s_app_ctx_clean_up(struct app_ctx *ctx) {
    if (ctx->stream) {
        aws_http_stream_release(ctx->stream);
    }
    
    if (ctx->request) {
        aws_http_message_destroy(ctx->request);
    }
    
    if (ctx->connection) {
        aws_http_connection_release(ctx->connection);
    }
    
    if (ctx->bootstrap) {
        aws_client_bootstrap_release(ctx->bootstrap);
    }
    
    if (ctx->host_resolver) {
        aws_host_resolver_release(ctx->host_resolver);
    }
    
    if (ctx->event_loop_group) {
        aws_event_loop_group_release(ctx->event_loop_group);
    }
    
    aws_byte_buf_clean_up(&ctx->response_body);
    s_socks5_proxy_settings_clean_up(&ctx->proxy, ctx->allocator);
    aws_condition_variable_clean_up(&ctx->signal);
    aws_mutex_clean_up(&ctx->lock);
}

/* Callback for HTTP connection setup */
static void s_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct app_ctx *ctx = user_data;
    
    aws_mutex_lock(&ctx->lock);
    
    ctx->connection_complete = true;
    ctx->connection_error_code = error_code;
    
    if (error_code == AWS_ERROR_SUCCESS) {
        ctx->connection = connection;
        if (ctx->verbose) {
            printf("HTTP connection established successfully\n");
        }
    } else {
        fprintf(stderr, "HTTP connection failed: %s\n", aws_error_debug_str(error_code));
    }
    
    aws_condition_variable_notify_one(&ctx->signal);
    aws_mutex_unlock(&ctx->lock);
}

/* Callback for HTTP connection shutdown */
static void s_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct app_ctx *ctx = user_data;
    
    if (error_code != AWS_ERROR_SUCCESS && ctx->verbose) {
        fprintf(stderr, "HTTP connection shutdown with error: %s\n", aws_error_debug_str(error_code));
    } else if (ctx->verbose) {
        printf("HTTP connection closed successfully\n");
    }
    
    /* No need to signal since we'll wait for stream completion instead */
}

/* Callback for HTTP stream completion */
static void s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct app_ctx *ctx = user_data;
    
    aws_mutex_lock(&ctx->lock);
    
    ctx->stream_complete = true;
    ctx->stream_error_code = error_code;
    
    if (error_code != AWS_ERROR_SUCCESS) {
        fprintf(stderr, "HTTP stream failed: %s\n", aws_error_debug_str(error_code));
    } else if (ctx->verbose) {
        printf("HTTP stream completed successfully\n");
    }
    
    aws_atomic_fetch_sub(&ctx->pending_requests, 1);
    aws_condition_variable_notify_one(&ctx->signal);
    aws_mutex_unlock(&ctx->lock);
}

/* Callback for HTTP stream header block completion */
static int s_on_response_headers(struct aws_http_stream *stream, enum aws_http_header_block header_block, const struct aws_http_header *header_array, size_t num_headers, void *user_data) {
    struct app_ctx *ctx = user_data;
    
    /* Get response status code */
    aws_http_stream_get_incoming_response_status(stream, &ctx->response_status);
    
    if (ctx->verbose) {
        printf("\nResponse status: %d\n", ctx->response_status);
        printf("Headers:\n");
        for (size_t i = 0; i < num_headers; i++) {
            printf("  %.*s: %.*s\n",
                (int)header_array[i].name.len, header_array[i].name.ptr,
                (int)header_array[i].value.len, header_array[i].value.ptr);
        }
        printf("\n");
    }
    
    return AWS_OP_SUCCESS;
}

/* Callback for HTTP stream body data */
static int s_on_response_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    struct app_ctx *ctx = user_data;
    
    /* Append response data to our buffer */
    aws_byte_buf_append_dynamic(&ctx->response_body, data);
    
    /* Print data as it arrives if in verbose mode */
    if (ctx->verbose) {
        printf("Received %zu bytes\n", data->len);
    }
    
    return AWS_OP_SUCCESS;
}

/* Create and send HTTP request */
static int s_send_http_request(struct app_ctx *ctx) {
    /* Create the HTTP request */
    ctx->request = aws_http_message_new_request(ctx->allocator);
    
    if (!ctx->request) {
        fprintf(stderr, "Failed to create HTTP request: %s\n", aws_error_debug_str(aws_last_error()));
        return AWS_OP_ERR;
    }
    
    /* Set HTTP method to GET */
    struct aws_byte_cursor method = aws_byte_cursor_from_c_str("GET");
    aws_http_message_set_request_method(ctx->request, method);
    
    /* Set request path */
    struct aws_byte_cursor path = aws_byte_cursor_from_c_str(ctx->path);
    aws_http_message_set_request_path(ctx->request, path);
    
    /* Add host header */
    struct aws_http_header host_header = {
        .name = aws_byte_cursor_from_c_str("Host"),
        .value = aws_byte_cursor_from_c_str(ctx->host_name)
    };
    aws_http_message_add_header(ctx->request, host_header);
    
    /* Add user-agent header */
    struct aws_http_header ua_header = {
        .name = aws_byte_cursor_from_c_str("User-Agent"),
        .value = aws_byte_cursor_from_c_str("aws-crt-http-socks5-example/1.0")
    };
    aws_http_message_add_header(ctx->request, ua_header);
    
    /* Setup stream options */
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = ctx->request,
        .user_data = ctx,
        .on_response_headers = s_on_response_headers,
        .on_response_header_block_done = NULL,
        .on_response_body = s_on_response_body,
        .on_complete = s_on_stream_complete,
    };
    
    /* Send the request */
    aws_atomic_fetch_add(&ctx->pending_requests, 1);
    ctx->stream = aws_http_connection_make_request(ctx->connection, &request_options);
    
    if (!ctx->stream) {
        fprintf(stderr, "Failed to create HTTP stream: %s\n", aws_error_debug_str(aws_last_error()));
        aws_atomic_fetch_sub(&ctx->pending_requests, 1);
        return AWS_OP_ERR;
    }
    
    /* Activate the stream */
    int result = aws_http_stream_activate(ctx->stream);
    if (result) {
        fprintf(stderr, "Failed to activate HTTP stream: %s\n", aws_error_debug_str(aws_last_error()));
        aws_atomic_fetch_sub(&ctx->pending_requests, 1);
        return AWS_OP_ERR;
    }
    
    if (ctx->verbose) {
        printf("HTTP request sent to: %s%s\n", ctx->host_name, ctx->path);
    }
    
    return AWS_OP_SUCCESS;
}

int main(int argc, char **argv) {
    int result = 0;
    struct aws_allocator *allocator = aws_default_allocator();
    /* Create TLS context options if using TLS */
    struct aws_tls_connection_options *tls_connection_options = NULL;
    struct aws_tls_ctx *tls_ctx = NULL;
    struct aws_socks5_proxy_options *socks5_options = NULL;

    aws_common_library_init(allocator);
    aws_io_library_init(allocator);
    aws_http_library_init(allocator);

    struct app_ctx app_ctx;
    s_app_ctx_init(&app_ctx, allocator);

    /* Parse command line arguments */
    s_parse_options(argc, argv, &app_ctx);
    
    // Initialize AWS CRT logger to stderr (or NULL for stdout)
    struct aws_logger logger;
    struct aws_logger_standard_options logger_options = {
        .level = app_ctx.verbose ? AWS_LL_TRACE : AWS_LL_WARN, // Use TRACE for verbose mode
        .file = stderr,        // Use stderr for logs; NULL for stdout
    };
    bool logger_initialized = false;
    if (aws_logger_init_standard(&logger, allocator, &logger_options) == AWS_OP_SUCCESS) {
        aws_logger_set(&logger);
        logger_initialized = true;
        
        if (app_ctx.verbose) {
            printf("Verbose mode enabled, using TRACE log level\n");
        }
    } else {
        result = AWS_OP_ERR;
        fprintf(stderr, "[WARN] Failed to initialize AWS logger, logs will not be shown.\n");
    }
    
    /* Log the configuration */
    printf("HTTP%s request to %s:%d%s\n", 
           app_ctx.use_tls ? "S" : "",
           app_ctx.host_name, 
           app_ctx.port,
           app_ctx.path);
    
    if (app_ctx.use_proxy && app_ctx.proxy.host) {
        printf("Using SOCKS5 proxy at %s:%" PRIu16 "\n", app_ctx.proxy.host, app_ctx.proxy.port);
        if (app_ctx.proxy.username) {
            printf("With proxy authentication: username=%s\n", app_ctx.proxy.username);
        }
    } else {
        printf("Using direct connection (no proxy)\n");
    }
    
    /* Create event loop group */
    app_ctx.event_loop_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    if (!app_ctx.event_loop_group) {
        result = AWS_OP_ERR;
        fprintf(stderr, "Failed to create event loop group: %s\n", aws_error_debug_str(aws_last_error()));
        goto cleanup;
    }
    
    /* Create host resolver */
    struct aws_host_resolver_default_options resolver_options = {
        .max_entries = 8,
        .el_group = app_ctx.event_loop_group
    };
    app_ctx.host_resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    if (!app_ctx.host_resolver) {
        result = AWS_OP_ERR;
        fprintf(stderr, "Failed to create host resolver: %s\n", aws_error_debug_str(aws_last_error()));
        goto cleanup;
    }
    
    /* Create client bootstrap */
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = app_ctx.event_loop_group,
        .host_resolver = app_ctx.host_resolver
    };
    app_ctx.bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    if (!app_ctx.bootstrap) {
        result = AWS_OP_ERR;
        fprintf(stderr, "Failed to create client bootstrap: %s\n", aws_error_debug_str(aws_last_error()));
        goto cleanup;
    }
    
    if (app_ctx.use_tls) {
        /* Initialize default TLS context options */
        struct aws_tls_ctx_options tls_ctx_options;
        aws_tls_ctx_options_init_default_client(&tls_ctx_options, allocator);
        
        /* Create a new TLS context */
        tls_ctx = aws_tls_client_ctx_new(allocator, &tls_ctx_options);
        if (!tls_ctx) {
            result = AWS_OP_ERR;
            fprintf(stderr, "Failed to create TLS context: %s\n", aws_error_debug_str(aws_last_error()));
            aws_tls_ctx_options_clean_up(&tls_ctx_options);
            goto cleanup;
        }
        
        /* Initialize TLS connection options */
        tls_connection_options = aws_mem_calloc(allocator, 1, sizeof(struct aws_tls_connection_options));
        if (!tls_connection_options) {
            result = AWS_OP_ERR;
            fprintf(stderr, "Failed to allocate memory for TLS connection options\n");
            aws_tls_ctx_options_clean_up(&tls_ctx_options);
            aws_tls_ctx_release(tls_ctx);
            goto cleanup;
        }
        
        /* Initialize TLS connection options from context */
        aws_tls_connection_options_init_from_ctx(tls_connection_options, tls_ctx);
        
        /* Set server name for SNI */
        struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str(app_ctx.host_name);
        if (aws_tls_connection_options_set_server_name(tls_connection_options, allocator, 
            &server_name) != AWS_OP_SUCCESS) {
            result = AWS_OP_ERR;
            fprintf(stderr, "Failed to set server name: %s\n", aws_error_debug_str(aws_last_error()));
            goto cleanup;
        }
        
        printf("TLS enabled for connection to %s\n", app_ctx.host_name);
    }
    
    /* Prepare HTTP connection options */
    struct aws_http_client_connection_options http_options;
    AWS_ZERO_STRUCT(http_options);
    http_options.self_size = sizeof(http_options);
    http_options.bootstrap = app_ctx.bootstrap;
    http_options.allocator = allocator;
    http_options.user_data = &app_ctx;

    http_options.host_name = aws_byte_cursor_from_c_str(app_ctx.host_name);
    http_options.port = app_ctx.port;
    http_options.on_setup = s_on_connection_setup;
    http_options.on_shutdown = s_on_connection_shutdown;
    
    /* For TLS connections (both direct and through proxy):
     * - When using TLS directly, we set the TLS options to connect directly to the target
     * - When using TLS through SOCKS5, we'll set TLS options later with the proxy configuration
     *   to ensure the TLS handshake happens AFTER the SOCKS5 tunnel is established
     */
    if (app_ctx.use_tls && !app_ctx.use_proxy) {
        /* Set TLS options for direct connections */
        http_options.tls_options = tls_connection_options;
    }
    
    /* Setup socket options for the connection */
    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4, /* Use IPv4 for better compatibility */
        .connect_timeout_ms = 5000, /* Allow enough time for connection */
    };
    
    http_options.socket_options = &socket_options;
    
    /* Configure proxy options if using proxy */
    
    if (app_ctx.use_proxy && app_ctx.proxy.host) {
        printf("Configuring SOCKS5 proxy %s:%" PRIu16 "\n", app_ctx.proxy.host, app_ctx.proxy.port);
        
        /* Allocate and initialize the SOCKS5 options structure using standard AWS API */
        socks5_options = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_options));
        if (!socks5_options) {
            result = AWS_OP_ERR;
            fprintf(stderr, "Failed to allocate memory for SOCKS5 proxy options\n");
            goto cleanup;
        }
        
        /* Set up SOCKS5-specific options */
        struct aws_byte_cursor proxy_host = aws_byte_cursor_from_c_str(app_ctx.proxy.host);
        
        printf("Using proxy host: %s:%" PRIu16 "\n", app_ctx.proxy.host, app_ctx.proxy.port);
        
        /* Use the standard AWS SOCKS5 initialization function */
        int result = aws_socks5_proxy_options_init(socks5_options, allocator, proxy_host, app_ctx.proxy.port);
        if (result != AWS_OP_SUCCESS) {
            int error_code = aws_last_error();
            result = error_code;
            fprintf(stderr, "Failed to initialize SOCKS5 proxy options: %s (code: %d) result %d\n", 
                    aws_error_debug_str(error_code), error_code, result);
                    
            /* More specific error handling */
            if (error_code == AWS_ERROR_INVALID_ARGUMENT) {
                fprintf(stderr, "Invalid argument provided to init function. Check host and port.\n");
            } else {
                fprintf(stderr, "Unknown error during SOCKS5 proxy options initialization\n");
            }
            
            goto cleanup;
        }
        
        aws_socks5_proxy_options_set_host_resolution_mode(
            socks5_options,
            app_ctx.proxy.resolve_host_with_proxy ? AWS_SOCKS5_HOST_RESOLUTION_PROXY
                                                  : AWS_SOCKS5_HOST_RESOLUTION_CLIENT);

        printf(
            "Successfully initialized SOCKS5 proxy options (destination resolved by %s)\n",
            app_ctx.proxy.resolve_host_with_proxy ? "proxy" : "client");
        
        /* Setup auth if provided */
        if (app_ctx.proxy.username && app_ctx.proxy.password) {
            struct aws_byte_cursor username = aws_byte_cursor_from_c_str(app_ctx.proxy.username);
            struct aws_byte_cursor password = aws_byte_cursor_from_c_str(app_ctx.proxy.password);
            if (aws_socks5_proxy_options_set_auth(socks5_options, allocator, username, password) != AWS_OP_SUCCESS) {
                int error_code = aws_last_error();
                result = error_code;
                fprintf(stderr, "Failed to set SOCKS5 auth: %s (code: %d)\n", 
                        aws_error_debug_str(error_code), error_code);
                goto cleanup;
            }
        }
        
        /* Use target_ip if specified, otherwise use host_name */
        const char* target_host_str = app_ctx.target_ip ? app_ctx.target_ip : app_ctx.host_name;
               
        /*
         * The helper will detect IPv4/IPv6 literals automatically when we pass DOMAIN here,
         * so callers don't need to care about the address family.
         *
         * Note: With SOCKS5, first the TCP connection is established to the proxy,
         * then the SOCKS5 handshake is performed, and finally the TLS handshake
         * happens THROUGH the established SOCKS5 tunnel.
         */
        
        if (app_ctx.verbose) {
            fprintf(stdout, "Connecting to %s using SOCKS5 address type: DOMAIN (with automatic IPv4/IPv6 detection)\n", target_host_str);
        }
        
        /* Target endpoint is taken directly from the connection options (host/port). */
        /* Set additional options */
        socks5_options->connection_timeout_ms = 5000; /* 5 seconds */
        
        /* Set SOCKS5 options directly in the HTTP connection options */
        http_options.socks5_proxy_options = socks5_options;

        /* When using SOCKS5 with TLS, we need to:  
         * 1. Connect to the SOCKS5 proxy first (without TLS)
         * 2. Perform the SOCKS5 handshake to establish the tunnel
         * 3. Then establish TLS through the tunnel to the target server
         * 
         * The AWS HTTP client should handle this sequence correctly when we set
         * both SOCKS5 proxy options and TLS options.
         */
        if (app_ctx.use_tls) {
            if (app_ctx.verbose) {
                printf("TLS will be established through SOCKS5 tunnel to %s\n", app_ctx.host_name);
            }
            
            /* CRITICAL: Set TLS options when using TLS with SOCKS5
             * This tells the AWS HTTP client to establish a TLS connection
             * AFTER the SOCKS5 tunnel is established */
            http_options.tls_options = tls_connection_options;
            
            /* Also ensure the server_name is set correctly for SNI */
            struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str(app_ctx.host_name);
            if (aws_tls_connection_options_set_server_name(tls_connection_options, allocator, &server_name) != AWS_OP_SUCCESS) {
                result = AWS_OP_ERR;
                fprintf(stderr, "Failed to set server name for TLS over SOCKS5: %s\n", aws_error_debug_str(aws_last_error()));
            }
        }
        
        if (app_ctx.verbose) {
            printf("SOCKS5 proxy configured with target %s:%d%s\n", 
                  target_host_str, app_ctx.port, 
                  app_ctx.use_tls ? " (with TLS)" : "");
        }
    }
    
    printf("Starting HTTP connection...\n");
    /* Create HTTP connection */
    if (aws_http_client_connect(&http_options)) {
        fprintf(stderr, "Failed to initiate HTTP connection: %s\n", aws_error_debug_str(aws_last_error()));
        result = aws_last_error();
        goto cleanup;
    }
    printf("HTTP connection initiated, waiting for completion...\n");
    
    /* Wait for connection completion */
    aws_mutex_lock(&app_ctx.lock);
    aws_condition_variable_wait_pred(
        &app_ctx.signal, &app_ctx.lock, s_connection_completed_predicate, &app_ctx);
    aws_mutex_unlock(&app_ctx.lock);
    
    if (app_ctx.connection_error_code != AWS_ERROR_SUCCESS) {
        fprintf(stderr, "HTTP connection failed: %s\n", aws_error_debug_str(app_ctx.connection_error_code));
        result = -1;
        goto cleanup;
    }
    printf("HTTP connection established, sending request...\n");

    /* Send HTTP request */
    if (s_send_http_request(&app_ctx) != AWS_OP_SUCCESS) {
        result = aws_last_error();
        goto cleanup;
    }
    
    printf("HTTP request sent, waiting for response...\n");
    /* Wait for request to complete */
    aws_mutex_lock(&app_ctx.lock);
    aws_condition_variable_wait_pred(
        &app_ctx.signal, &app_ctx.lock, s_stream_completed_predicate, &app_ctx);
    aws_mutex_unlock(&app_ctx.lock);
    
    /* Print the results */
    printf("\nHTTP Response Status: %d\n", app_ctx.response_status);
    if (app_ctx.stream_error_code == AWS_ERROR_SUCCESS) {
        printf("Response Body (%zu bytes):\n", app_ctx.response_body.len);
        printf("------------------------------------\n");
        printf("%.*s\n", (int)app_ctx.response_body.len, app_ctx.response_body.buffer);
        printf("------------------------------------\n");
    } else {
        result = app_ctx.stream_error_code;
        fprintf(stderr, "Request failed: %s\n", aws_error_debug_str(app_ctx.stream_error_code));
    }
    
cleanup:
    /* Cleanup TLS resources if used */
    if (tls_connection_options != NULL) {
        aws_tls_connection_options_clean_up(tls_connection_options);
        aws_mem_release(allocator, tls_connection_options);
    }
    
    if (tls_ctx != NULL) {
        aws_tls_ctx_release(tls_ctx);
    }
    
    /* Clean up proxy options if used */
    if (socks5_options != NULL) {
        aws_socks5_proxy_options_clean_up(socks5_options);
        aws_mem_release(allocator, socks5_options);
    }
    
    /* Clean up the app context */
    s_app_ctx_clean_up(&app_ctx);
    
    /* Clean up libraries */
    aws_http_library_clean_up();
    aws_io_library_clean_up();
    aws_common_library_clean_up();
    
    /* Clean up logger before exit */
    if (logger_initialized) {
        aws_logger_clean_up(&logger);
    }
    return result;
}
