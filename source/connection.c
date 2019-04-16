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

#include <aws/common/string.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

AWS_STATIC_STRING_FROM_LITERAL(s_alpn_protocol_http_1_1, "http/1.1");
AWS_STATIC_STRING_FROM_LITERAL(s_alpn_protocol_http_2, "h2");

struct aws_http_server {
    struct aws_allocator *alloc;
    struct aws_server_bootstrap *bootstrap;
    bool is_using_tls;
    size_t initial_window_size;
    void *user_data;
    aws_http_server_on_incoming_connection_fn *on_incoming_connection;

    struct aws_socket *socket;
};

/* Determine the http-version, create appropriate type of connection, and insert it into the channel. */
static struct aws_http_connection *s_connection_new(
    struct aws_channel *channel,
    bool is_server,
    bool is_using_tls,
    void *options) {

    struct aws_channel_slot *connection_slot = NULL;
    struct aws_http_connection *connection = NULL;

    /* Create slot for connection. */
    connection_slot = aws_channel_slot_new(channel);
    if (!connection_slot) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Failed to create slot in channel %p, error %d (%s).",
            (void *)channel,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    int err = aws_channel_slot_insert_end(channel, connection_slot);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Failed to insert slot into channel %p, error %d (%s).",
            (void *)channel,
            aws_last_error(),
            aws_error_name(aws_last_error()));
        goto error;
    }

    /* Determine HTTP version */
    enum aws_http_version version = AWS_HTTP_VERSION_1_1;

    if (is_using_tls) {
        /* Query TLS channel handler (immediately to left in the channel) for negotiated ALPN protocol */
        if (!connection_slot->adj_left || !connection_slot->adj_left->handler) {
            aws_raise_error(AWS_ERROR_INVALID_STATE);
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION, "static: Failed to find TLS handler in channel %p.", (void *)channel);
            goto error;
        }

        struct aws_channel_slot *tls_slot = connection_slot->adj_left;
        struct aws_channel_handler *tls_handler = tls_slot->handler;
        struct aws_byte_buf protocol = aws_tls_handler_protocol(tls_handler);
        if (protocol.len) {
            if (aws_string_eq_byte_buf(s_alpn_protocol_http_1_1, &protocol)) {
                version = AWS_HTTP_VERSION_1_1;
            } else if (aws_string_eq_byte_buf(s_alpn_protocol_http_2, &protocol)) {
                version = AWS_HTTP_VERSION_2;
            } else {
                AWS_LOGF_WARN(AWS_LS_HTTP_CONNECTION, "static: Unrecognized ALPN protocol. Assuming HTTP/1.1");
                AWS_LOGF_DEBUG(
                    AWS_LS_HTTP_CONNECTION, "static: Unrecognized ALPN protocol " PRInSTR, AWS_BYTE_BUF_PRI(protocol));

                version = AWS_HTTP_VERSION_1_1;
            }
        }
    }

    /* Create connection/handler */
    switch (version) {
        case AWS_HTTP_VERSION_1_1:
            if (is_server) {
                connection = aws_http_connection_new_http1_1_server(options);
            } else {
                connection = aws_http_connection_new_http1_1_client(options);
            }
            break;
        default:
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_CONNECTION,
                "static: Unsupported version " PRInSTR,
                AWS_BYTE_CURSOR_PRI(aws_http_version_to_str(version)));

            aws_raise_error(AWS_ERROR_HTTP_UNSUPPORTED_PROTOCOL);
            goto error;
    }

    if (!connection) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Failed to create " PRInSTR " %s connection object, error %d (%s).",
            AWS_BYTE_CURSOR_PRI(aws_http_version_to_str(version)),
            is_server ? "server" : "client",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    /* Connect handler and slot */
    err = aws_channel_slot_set_handler(connection_slot, &connection->channel_handler);
    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Failed to setting HTTP handler into slot on channel %p, error %d (%s).",
            (void *)channel,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    connection->channel_slot = connection_slot;

    /* Success! Acquire a hold on the channel to prevent its destruction until the user has
     * given the go-ahead via aws_http_connection_release() */
    aws_channel_acquire_hold(channel);

    return connection;

error:
    if (connection_slot) {
        if (!connection_slot->handler && connection) {
            aws_channel_handler_destroy(&connection->channel_handler);
        }

        aws_channel_slot_remove(connection_slot);
    }

    return NULL;
}

void aws_http_connection_close(struct aws_http_connection *connection) {
    assert(connection);
    connection->vtable->close(connection);
}

bool aws_http_connection_is_open(const struct aws_http_connection *connection) {
    assert(connection);
    return connection->vtable->is_open(connection);
}

void aws_http_connection_release(struct aws_http_connection *connection) {
    assert(connection);
    size_t prev_refcount = aws_atomic_fetch_sub(&connection->refcount, 1);
    if (prev_refcount == 1) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Final connection refcount released, shut down if necessary.",
            (void *)connection);

        /* Channel might already be shut down, but make sure */
        aws_channel_shutdown(connection->channel_slot->channel, AWS_ERROR_SUCCESS);

        /* When the channel's refcount reaches 0, it destroys its slots/handlers, which will destroy the connection */
        aws_channel_release_hold(connection->channel_slot->channel);
    } else {
        assert(prev_refcount != 0);
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Connection refcount released, %zu remaining.",
            (void *)connection,
            prev_refcount - 1);
    }
}

/* At this point, the server bootstrapper has accepted an incoming connection from a client and set up a channel.
 * Now we need to create an aws_http_connection and insert it into the channel as a channel-handler. */
static void s_server_bootstrap_on_accept_channel_setup(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    assert(user_data);
    struct aws_http_server *server = user_data;
    bool user_cb_invoked = false;

    if (error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_SERVER,
            "%s:%d: Incoming connection failed with error code %d (%s)",
            server->socket->local_endpoint.address,
            server->socket->local_endpoint.port,
            error_code,
            aws_error_name(error_code));

        goto error;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_HTTP_SERVER,
        "%s:%d: Incoming connection accepted, creating connection object.",
        server->socket->local_endpoint.address,
        server->socket->local_endpoint.port);

    /* Create connection */
    struct aws_http_server_connection_impl_options options = {
        .alloc = server->alloc,
        .initial_window_size = server->initial_window_size,
    };

    struct aws_http_connection *connection = s_connection_new(channel, true, server->is_using_tls, &options);
    if (!connection) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_SERVER,
            "%s:%d: Failed to create connection object, error %d (%s).",
            server->socket->local_endpoint.address,
            server->socket->local_endpoint.port,
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    /* Tell user of successful connection. */
    AWS_LOGF_INFO(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: " PRInSTR " server connection established.",
        (void *)connection,
        AWS_BYTE_CURSOR_PRI(aws_http_version_to_str(connection->http_version)));

    server->on_incoming_connection(server, connection, error_code, server->user_data);
    user_cb_invoked = true;

    /* If user failed to configure the server during callback, shut down the channel. */
    if (!connection->server_data->on_incoming_request) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Caller failed to invoke aws_http_connection_configure_server() during on_incoming_connection "
            "callback, closing connection.",
            (void *)connection);

        aws_raise_error(AWS_ERROR_HTTP_REACTION_REQUIRED);
        goto error;
    }
    return;

error:
    if (!error_code) {
        error_code = aws_last_error();
    }

    if (!user_cb_invoked) {
        server->on_incoming_connection(server, NULL, error_code, server->user_data);
    }

    if (channel) {
        aws_channel_shutdown(channel, error_code);
    }
}

/* At this point, the channel for a server connection has completed shutdown, but hasn't been destroyed yet. */
static void s_server_bootstrap_on_accept_channel_shutdown(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;

    /* No implementation because channel handler currently deals with shutdown logic and user callbacks. */
}

struct aws_http_server *aws_http_server_new(const struct aws_http_server_options *options) {
    aws_http_fatal_assert_library_initialized();

    struct aws_http_server *server = NULL;

    if (!options || options->self_size == 0 || !options->allocator || !options->bootstrap || !options->socket_options ||
        !options->on_incoming_connection || !options->endpoint) {

        AWS_LOGF_ERROR(AWS_LS_HTTP_SERVER, "static: Invalid options, cannot create server.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto error;
    }

    server = aws_mem_acquire(options->allocator, sizeof(struct aws_http_server));
    if (!server) {
        goto error;
    }
    AWS_ZERO_STRUCT(*server);

    server->alloc = options->allocator;
    server->bootstrap = options->bootstrap;
    server->is_using_tls = options->tls_options != NULL;
    server->initial_window_size = options->initial_window_size;
    server->user_data = options->server_user_data;
    server->on_incoming_connection = options->on_incoming_connection;

    if (options->tls_options) {
        server->is_using_tls = true;

        server->socket = aws_server_bootstrap_new_tls_socket_listener(
            options->bootstrap,
            options->endpoint,
            options->socket_options,
            options->tls_options,
            s_server_bootstrap_on_accept_channel_setup,
            s_server_bootstrap_on_accept_channel_shutdown,
            server);
    } else {
        server->socket = aws_server_bootstrap_new_socket_listener(
            options->bootstrap,
            options->endpoint,
            options->socket_options,
            s_server_bootstrap_on_accept_channel_setup,
            s_server_bootstrap_on_accept_channel_shutdown,
            server);
    }

    if (!server->socket) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_SERVER,
            "static: Failed creating new socket listener, error %d (%s). Cannot create server.",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    AWS_LOGF_INFO(
        AWS_LS_HTTP_SERVER,
        "%s:%d: Server setup complete, listening for incoming connections.",
        server->socket->local_endpoint.address,
        server->socket->local_endpoint.port);

    return server;

error:
    if (server) {
        aws_http_server_destroy(server);
    }
    return NULL;
}

void aws_http_server_destroy(struct aws_http_server *server) {
    assert(server);

    if (server->socket) {
        AWS_LOGF_INFO(
            AWS_LS_HTTP_SERVER,
            "%s:%d: Destroying server.",
            server->socket->local_endpoint.address,
            server->socket->local_endpoint.port);

        aws_server_bootstrap_destroy_socket_listener(server->bootstrap, server->socket);
    }

    aws_mem_release(server->alloc, server);
}

/* At this point, the client bootstrapper has established a connection to the server and set up a channel.
 * Now we need to create the aws_http_connection and insert it into the channel as a channel-handler. */
static void s_client_bootstrap_on_channel_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    assert(user_data);
    struct aws_http_client_connection_impl_options *options = user_data;

    if (error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Client connection failed with error %d (%s).",
            error_code,
            aws_error_name(error_code));
        goto error;
    }

    AWS_LOGF_TRACE(AWS_LS_HTTP_CONNECTION, "static: Socket connected, creating client connection object.");

    struct aws_http_connection *connection = s_connection_new(channel, false, options->is_using_tls, options);
    if (!connection) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Failed to create the client connection object, error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    AWS_LOGF_INFO(
        AWS_LS_HTTP_CONNECTION,
        "id=%p: " PRInSTR " client connection established.",
        (void *)connection,
        AWS_BYTE_CURSOR_PRI(aws_http_version_to_str(connection->http_version)));

    /* Tell user of successful connection. */
    options->on_setup(connection, AWS_ERROR_SUCCESS, options->user_data);

    aws_mem_release(options->alloc, options);
    return;

error:
    if (!error_code) {
        error_code = aws_last_error();
    }

    if (channel) {
        aws_channel_shutdown(channel, error_code);
    }

    /* Tell user of failed connection. */
    options->on_setup(NULL, error_code, options->user_data);

    aws_mem_release(options->alloc, options);
}

/* At this point, the channel for a client connection has complete shutdown, but hasn't been destroyed yet. */
static void s_client_bootstrap_on_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;

    /* No implementation because channel handler currently deals with shutdown logic and user callbacks. */
}

int aws_http_client_connect(const struct aws_http_client_connection_options *options) {
    aws_http_fatal_assert_library_initialized();

    struct aws_http_client_connection_impl_options *impl_options = NULL;
    struct aws_string *host_name = NULL;
    int err = 0;

    if (!options || options->self_size == 0 || !options->allocator || !options->bootstrap ||
        options->host_name.len == 0 || !options->socket_options || !options->on_setup) {

        AWS_LOGF_ERROR(AWS_LS_HTTP_CONNECTION, "static: Invalid options, cannot create client connection.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto error;
    }

    /* bootstrap_new() functions requires a null-terminated c-str */
    host_name = aws_string_new_from_array(options->allocator, options->host_name.ptr, options->host_name.len);
    if (!host_name) {
        goto error;
    }

    impl_options = aws_mem_acquire(options->allocator, sizeof(struct aws_http_client_connection_impl_options));
    if (!impl_options) {
        goto error;
    }

    impl_options->alloc = options->allocator;
    impl_options->is_using_tls = options->tls_options != NULL;
    impl_options->initial_window_size = options->initial_window_size;
    impl_options->user_data = options->user_data;
    impl_options->on_setup = options->on_setup;
    impl_options->on_shutdown = options->on_shutdown;

    if (options->tls_options) {
        err = aws_client_bootstrap_new_tls_socket_channel(
            options->bootstrap,
            (const char *)aws_string_bytes(host_name),
            options->port,
            options->socket_options,
            options->tls_options,
            s_client_bootstrap_on_channel_setup,
            s_client_bootstrap_on_channel_shutdown,
            impl_options);
    } else {
        err = aws_client_bootstrap_new_socket_channel(
            options->bootstrap,
            (const char *)aws_string_bytes(host_name),
            options->port,
            options->socket_options,
            s_client_bootstrap_on_channel_setup,
            s_client_bootstrap_on_channel_shutdown,
            impl_options);
    }

    if (err) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "static: Failed to initiate socket channel for new client connection, error %d (%s).",
            aws_last_error(),
            aws_error_name(aws_last_error()));

        goto error;
    }

    aws_string_destroy(host_name);
    return AWS_OP_SUCCESS;

error:
    if (impl_options) {
        aws_mem_release(impl_options->alloc, impl_options);
    }

    if (host_name) {
        aws_string_destroy(host_name);
    }

    return AWS_OP_ERR;
}

enum aws_http_version aws_http_connection_get_version(const struct aws_http_connection *connection) {
    return connection->http_version;
}

int aws_http_connection_configure_server(
    struct aws_http_connection *connection,
    const struct aws_http_server_connection_options *options) {

    if (!connection || !options || !options->on_incoming_request) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_CONNECTION, "id=%p: Invalid server configuration options.", (void *)connection);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (!connection->server_data) {
        AWS_LOGF_WARN(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Server-only function invoked on client, ignoring call.",
            (void *)connection);
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    if (connection->server_data->on_incoming_request) {
        AWS_LOGF_WARN(
            AWS_LS_HTTP_CONNECTION, "id=%p: Connection is already configured, ignoring call.", (void *)connection);
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    connection->user_data = options->connection_user_data;
    connection->server_data->on_incoming_request = options->on_incoming_request;
    connection->server_data->on_shutdown = options->on_shutdown;

    return AWS_OP_SUCCESS;
}
