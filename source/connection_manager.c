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

#include <aws/http/connection_manager.h>

#include <aws/common/atomics.h>
#include <aws/common/hash_table.h>
#include <aws/common/linked_list.h>
#include <aws/common/mutex.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/http/connection.h>

enum aws_connection_return_type {
    AWS_CRT_CONNECTED,
    AWS_CRT_RELEASED
};

struct aws_http_connection_manager {
    struct aws_allocator *allocator;
    struct aws_mutex lock;
    struct aws_hash_table connections;
    struct aws_linked_list pending_acquisitions;
    size_t pending_connection_count;
    struct aws_client_bootstrap *bootstrap;
    size_t initial_window_size;
    struct aws_socket_options socket_options;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_string *host;
    uint16_t port;
    size_t max_connections;
    size_t vended_connection_count;
    struct aws_atomic_var ref_count;
};

struct aws_pending_acquisition {
    struct aws_linked_list_node node;
    acquire_connection_callback_fn *callback;
    void *user_data;
};

static int s_connection_cleanup(void *context, struct aws_hash_element *element) {
    (void)context;

    struct aws_http_connection *connection = (void *)element->key;
    aws_http_connection_close(connection);

    return AWS_OP_SUCCESS;
}

static void s_aws_http_connection_manager_destroy(struct aws_http_connection_manager *manager) {
    if (manager == NULL) {
        return;
    }

    aws_hash_table_foreach(&manager->connections, s_connection_cleanup, NULL);
    aws_hash_table_clean_up(&manager->connections);

    while (!aws_linked_list_empty(&manager->pending_acquisitions)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&manager->pending_acquisitions);
        struct aws_pending_acquisition *pending_acquisition = AWS_CONTAINER_OF(node, struct aws_pending_acquisition, node);

        pending_acquisition->callback(NULL, pending_acquisition->user_data, AWS_OP_ERR);
        aws_mem_release(manager->allocator, pending_acquisition);
    }

    aws_string_destroy(manager->host);
    aws_tls_connection_options_clean_up(&manager->tls_connection_options);
    aws_mutex_clean_up(&manager->lock);

    aws_mem_release(manager->allocator, manager);
}

void aws_http_connection_manager_acquire(struct aws_http_connection_manager *manager) {
    aws_atomic_fetch_add(&manager->ref_count, 1);
}

void aws_http_connection_manager_release(struct aws_http_connection_manager *manager) {
    size_t old_value = aws_atomic_fetch_sub(&manager->ref_count, 1);
    if (old_value == 1) {
        s_aws_http_connection_manager_destroy(manager);
    }
}

struct aws_http_connection_manager *aws_http_connection_manager_new(struct aws_allocator *allocator, struct aws_http_connection_manager_options *options) {
    assert(options);
    assert(options->socket_options);
    assert(options->max_connections > 0);

    struct aws_http_connection_manager *manager = aws_mem_acquire(allocator, sizeof(struct aws_http_connection_manager));
    if (manager == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*manager);
    manager->allocator = allocator;

    if (aws_mutex_init(&manager->lock)) {
        goto on_error;
    }

    if (aws_hash_table_init(&manager->connections, allocator, 2, aws_hash_ptr, aws_ptr_eq, NULL, NULL)) {
        goto on_error;
    }

    aws_linked_list_init(&manager->pending_acquisitions);

    manager->host = aws_string_new_from_array(allocator, options->host.ptr, options->host.len);
    if (manager->host == NULL) {
        goto on_error;
    }

    if (options->tls_connection_options && aws_tls_connection_options_copy(&manager->tls_connection_options, options->tls_connection_options)) {
        goto on_error;
    }

    manager->initial_window_size = options->initial_window_size;
    manager->port = options->port;
    manager->max_connections = options->max_connections;
    manager->socket_options = *options->socket_options;
    manager->bootstrap = options->bootstrap;

    aws_atomic_store_int(&manager->ref_count, 1);

    return manager;

on_error:

    s_aws_http_connection_manager_destroy(manager);

    return NULL;
}

static void s_aws_http_connection_manager_add_connection(struct aws_http_connection_manager *connection_manager, struct aws_http_connection *connection, enum aws_connection_return_type return_type);

static void s_aws_http_connection_manager_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)error_code;

    struct aws_http_connection_manager *manager = user_data;

    if (connection != NULL) {
        s_aws_http_connection_manager_add_connection(manager, connection, AWS_CRT_CONNECTED);
        return;
    }

    aws_mutex_lock(&manager->lock);

    // TODO: implement ??;

    aws_mutex_unlock(&manager->lock);
}

static void s_aws_http_connection_manager_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)connection;
    (void)error_code;
    (void)user_data;

    struct aws_http_connection_manager *manager = user_data;
    aws_mutex_lock(&manager->lock);

    aws_hash_table_remove(&manager->connections, connection, NULL, NULL);

    aws_mutex_unlock(&manager->lock);
}

static int s_aws_http_connection_manager_new_connection(struct aws_http_connection_manager *connection_manager) {
    assert(aws_hash_table_get_entry_count(&connection_manager->connections) == 0);

    if (connection_manager->vended_connection_count + connection_manager->pending_connection_count >= connection_manager->max_connections) {
        return AWS_OP_SUCCESS;
    }

    struct aws_http_client_connection_options options;
    AWS_ZERO_STRUCT(options);
    options.self_size = sizeof(struct aws_http_client_connection_options);
    options.bootstrap = connection_manager->bootstrap;
    options.tls_options = &connection_manager->tls_connection_options;
    options.allocator = connection_manager->allocator;
    options.user_data = connection_manager;
    options.host_name = aws_byte_cursor_from_string(connection_manager->host);
    options.port = connection_manager->port;
    options.initial_window_size = connection_manager->initial_window_size;
    options.socket_options = &connection_manager->socket_options;
    options.on_setup = s_aws_http_connection_manager_on_connection_setup;
    options.on_shutdown = s_aws_http_connection_manager_on_connection_shutdown;

    if (aws_http_client_connect(&options))
    {
        return AWS_OP_ERR;
    }

    ++connection_manager->pending_connection_count;

    return AWS_OP_SUCCESS;
}

static void s_aws_http_connection_manager_pump_acquisitions(struct aws_http_connection_manager *connection_manager) {
    if (!aws_linked_list_empty(&connection_manager->pending_acquisitions)) {
        struct aws_linked_list_node *node = aws_linked_list_front(&connection_manager->pending_acquisitions);
        struct aws_pending_acquisition *pending_acquisition = AWS_CONTAINER_OF(node, struct aws_pending_acquisition, node);

        if (s_aws_http_connection_manager_new_connection(connection_manager)) {

            aws_linked_list_pop_front(&connection_manager->pending_acquisitions);
            pending_acquisition->callback(NULL, pending_acquisition->user_data, AWS_OP_ERR);
            aws_mem_release(connection_manager->allocator, pending_acquisition);
        }
    }
}

void s_aws_http_connection_manager_add_connection(struct aws_http_connection_manager *connection_manager, struct aws_http_connection *connection, enum aws_connection_return_type return_type) {
    assert(connection);

    aws_mutex_lock(&connection_manager->lock);

    if (return_type == AWS_CRT_CONNECTED) {
        assert(connection_manager->pending_connection_count > 0);

        --connection_manager->pending_connection_count;
    } else if (return_type == AWS_CRT_RELEASED) {
        assert(connection_manager->vended_connection_count > 0);

        --connection_manager->vended_connection_count;
    }

    if (!aws_http_connection_is_open(connection)) {
        s_aws_http_connection_manager_pump_acquisitions(connection_manager);
        goto done;
    }

    if (aws_linked_list_empty(&connection_manager->pending_acquisitions)) {
        if (aws_hash_table_put(&connection_manager->connections, &connection, NULL, NULL)) {
            aws_http_connection_close(connection);
        }

        goto done;
    }

    struct aws_linked_list_node *node = aws_linked_list_pop_front(&connection_manager->pending_acquisitions);
    struct aws_pending_acquisition *pending_acquisition = AWS_CONTAINER_OF(node, struct aws_pending_acquisition, node);

    pending_acquisition->callback(connection, pending_acquisition->user_data, AWS_OP_SUCCESS);
    aws_mem_release(connection_manager->allocator, pending_acquisition);

    ++connection_manager->vended_connection_count;

done:

    aws_mutex_unlock(&connection_manager->lock);
}

int aws_http_connection_manager_acquire_connection(struct aws_http_connection_manager *connection_manager, acquire_connection_callback_fn *callback, void *user_data) {
    int result = AWS_OP_ERR;

    aws_mutex_lock(&connection_manager->lock);

    size_t available_connection_count = aws_hash_table_get_entry_count(&connection_manager->connections);
    if (available_connection_count > 0) {
        struct aws_hash_iter iter = aws_hash_iter_begin(&connection_manager->connections);
        struct aws_http_connection *connection = (void *) iter.element.key;

        aws_hash_iter_delete(&iter, false);

        ++connection_manager->vended_connection_count;
        result = AWS_OP_SUCCESS;
        callback(connection, user_data, AWS_OP_SUCCESS);

        goto done;
    }

    struct aws_pending_acquisition *pending_connection = aws_mem_acquire(connection_manager->allocator, sizeof(struct aws_pending_acquisition));
    if (pending_connection == NULL) {
        callback(NULL, user_data, AWS_OP_ERR);
        goto done;
    }

    if (s_aws_http_connection_manager_new_connection(connection_manager)) {
        aws_mem_release(connection_manager->allocator, pending_connection);
        callback(NULL, user_data, AWS_OP_ERR);
        goto done;
    }

    AWS_ZERO_STRUCT(*pending_connection);

    pending_connection->callback = callback;
    pending_connection->user_data = user_data;

    aws_linked_list_push_back(&connection_manager->pending_acquisitions, &pending_connection->node);

done:

    aws_mutex_unlock(&connection_manager->lock);

    return result;
}

int aws_http_connection_manager_release_connection(struct aws_http_connection_manager *connection_manager, struct aws_http_connection *connection) {
    s_aws_http_connection_manager_add_connection(connection_manager, connection, AWS_CRT_RELEASED);

    return AWS_OP_SUCCESS;
}
