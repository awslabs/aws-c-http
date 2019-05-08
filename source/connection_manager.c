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

enum aws_http_connection_accept_type {
    AWS_CAT_NEWLY_CONNECTED,
    AWS_CAT_RELEASED
};

struct aws_http_connection_manager {
    struct aws_allocator *allocator;

    /*
     * Controls access to all mutable state on the connection manager
     */
    struct aws_mutex lock;

    /*
     * The set of all available ready-to-be-used connections
     */
    struct aws_hash_table connections;

    /*
     * The set of all incomplete connection acquisition requests
     */
    struct aws_linked_list pending_acquisitions;

    /*
     * The number of all incomplete connection acquisition requests.  So
     * that we don't have compute the size of a linked list every time.
     */
    size_t pending_acquisition_count;

    /*
     * The number of pending new connection requests we have outstanding to the http
     * layer.  Each pending new connection requests adds one to the connection manager's
     * overall ref count.   Each resolved request subtracts one.
     */
    size_t pending_connects_count;

    /*
     * The number of connections currently being used by external users.
     */
    size_t vended_connection_count;

    /*
     * All the options needed to create an http connection
     */
    struct aws_client_bootstrap *bootstrap;
    size_t initial_window_size;
    struct aws_socket_options socket_options;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_string *host;
    uint16_t port;

    /*
     * The maximum number of connections this manager should ever have at once.
     */
    size_t max_connections;

    /*
     * Lifecycle tracking for the connection manager.  Starts at 1.
     *
     * value = # external refs + # pending connects
     */
    struct aws_atomic_var ref_count;
};

/*
 * A struct that functions as both the pending acquisition tracker and the about-to-complete data.
 *
 * The list in the connection manager is the set of all acquisition requests that we haven't resolved.
 *
 * In order to make sure we never invoke callbacks while holding the manager's lock, in a number of places
 * we build a list of one or more acquisitions to complete while holding the lock.  Once the lock is released
 * we complete all the acquisitions in the list using the data within the struct (hence why we have
 * connection and result members).
 */
struct aws_http_connection_acquisition {
    struct aws_linked_list_node node;
    aws_http_on_client_connection_setup_fn *callback;
    void *user_data;
    struct aws_http_connection *connection;
    int result;
};

/*
 * Only call this outside the scope of the connection manager's lock
 */
static void s_aws_http_connection_manager_complete_acquisitions(struct aws_linked_list *acquisitions, struct aws_allocator *allocator) {
    while (!aws_linked_list_empty(acquisitions)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(acquisitions);
        struct aws_http_connection_acquisition *pending_acquisition = AWS_CONTAINER_OF(node, struct aws_http_connection_acquisition, node);

        pending_acquisition->callback(pending_acquisition->connection, pending_acquisition->result, pending_acquisition->user_data);
        aws_mem_release(allocator, pending_acquisition);
    }
}

/*
 * Moves the first pending connection acquisition into a list.  Call this while holding the lock to
 * build the set of callbacks to be completed once the lock is released.
 *
 * If this was a successful acquisition then connection is non-null
 * If this was a failed acquisition then connection is null
 */
static void s_aws_http_connection_manager_move_front_acquisition(struct aws_http_connection_manager *manager, struct aws_http_connection *connection, int result, struct aws_linked_list *output_list) {
    assert(!aws_linked_list_empty(&manager->pending_acquisitions));
    assert(manager->pending_acquisition_count > 0);

    struct aws_linked_list_node *node = aws_linked_list_pop_front(&manager->pending_acquisitions);
    --manager->pending_acquisition_count;

    struct aws_http_connection_acquisition *pending_acquisition = AWS_CONTAINER_OF(node, struct aws_http_connection_acquisition, node);
    pending_acquisition->connection = connection;
    pending_acquisition->result = result;

    aws_linked_list_push_back(output_list, node);
}

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

    assert(manager->pending_connects_count == 0);

    aws_hash_table_foreach(&manager->connections, s_connection_cleanup, NULL);
    aws_hash_table_clean_up(&manager->connections);

    s_aws_http_connection_manager_complete_acquisitions(&manager->pending_acquisitions, manager->allocator);
    manager->pending_acquisition_count = 0;

    aws_string_destroy(manager->host);
    aws_tls_connection_options_clean_up(&manager->tls_connection_options);
    aws_mutex_clean_up(&manager->lock);

    aws_mem_release(manager->allocator, manager);
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

void aws_http_connection_manager_acquire(struct aws_http_connection_manager *manager) {
    aws_atomic_fetch_add(&manager->ref_count, 1);
}

void aws_http_connection_manager_release(struct aws_http_connection_manager *manager) {
    size_t old_value = aws_atomic_fetch_sub(&manager->ref_count, 1);
    if (old_value == 1) {
        s_aws_http_connection_manager_destroy(manager);
    }
}

static void s_aws_http_connection_manager_accept_connection(struct aws_http_connection_manager *connection_manager,
                                                            struct aws_http_connection *connection,
                                                            enum aws_http_connection_accept_type return_type);

static void s_aws_http_connection_manager_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)error_code;

    struct aws_http_connection_manager *manager = user_data;

    if (connection != NULL) {
        s_aws_http_connection_manager_accept_connection(manager, connection, AWS_CAT_NEWLY_CONNECTED);
        return;
    }

    aws_mutex_lock(&manager->lock);

    assert(manager->pending_connects_count > 0);
    --manager->pending_connects_count;

    /*
     * A nice behavioral optimization.  If we failed to connect now, then we're more likely to fail in the near-future
     * as well.  So if we have an excess of pending acquisitions (beyond the number of pending connects), let's fail
     * all of the excess.
     */
    struct aws_linked_list trimmed_acquisitions;
    aws_linked_list_init(&trimmed_acquisitions);

    while(manager->pending_acquisition_count > manager->pending_connects_count) {
        s_aws_http_connection_manager_move_front_acquisition(manager, NULL, error_code, &trimmed_acquisitions);
    }

    aws_mutex_unlock(&manager->lock);

    s_aws_http_connection_manager_complete_acquisitions(&trimmed_acquisitions, manager->allocator);

    /*
     * Normally paired with pending_connects_count side effect, but let's delay this until the very end on
     * the offchance that someone released the last external ref while there was still a pending connect.
     */
    aws_http_connection_manager_release(manager);
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

    /*
     * Don't create too many
     */
    if (connection_manager->vended_connection_count + connection_manager->pending_connects_count >= connection_manager->max_connections) {
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

    ++connection_manager->pending_connects_count;
    aws_http_connection_manager_acquire(connection_manager);

    return AWS_OP_SUCCESS;
}

/*
 * A utility function that, if there's at least one pending acquisition, attempts to create a new connection for it.
 */
static void s_aws_http_connection_manager_pump_acquisitions(struct aws_http_connection_manager *connection_manager, struct aws_linked_list *to_complete_acquisitions) {
    if (!aws_linked_list_empty(&connection_manager->pending_acquisitions)) {
        if (s_aws_http_connection_manager_new_connection(connection_manager)) {
            s_aws_http_connection_manager_move_front_acquisition(connection_manager, NULL, aws_last_error(), to_complete_acquisitions);
        }
    }
}

/*
 * Shared implementation for
 *   (1) a new connection comes back from the http layer (AWS_CAT_NEWLY_CONNECTED)
 *   (2) an old connection is returned by an external user (AWS_CAT_RELEASED)
 */
void s_aws_http_connection_manager_accept_connection(struct aws_http_connection_manager *connection_manager,
                                                     struct aws_http_connection *connection,
                                                     enum aws_http_connection_accept_type return_type) {
    assert(connection);

    struct aws_linked_list to_complete_acquisitions;
    aws_linked_list_init(&to_complete_acquisitions);

    aws_mutex_lock(&connection_manager->lock);

    if (return_type == AWS_CAT_NEWLY_CONNECTED) {
        assert(connection_manager->pending_connects_count > 0);
        --connection_manager->pending_connects_count;
    } else if (return_type == AWS_CAT_RELEASED) {
        assert(connection_manager->vended_connection_count > 0);
        --connection_manager->vended_connection_count;
    }

    /*
     * If the connection has expired, we should try to replace it with a new one.
     */
    if (!aws_http_connection_is_open(connection)) {
        s_aws_http_connection_manager_pump_acquisitions(connection_manager, &to_complete_acquisitions);
        goto done;
    }

    if (aws_linked_list_empty(&connection_manager->pending_acquisitions)) {
        if (aws_hash_table_put(&connection_manager->connections, &connection, NULL, NULL)) {
            aws_http_connection_close(connection);
        }

        goto done;
    }

    s_aws_http_connection_manager_move_front_acquisition(connection_manager, connection, AWS_ERROR_SUCCESS, &to_complete_acquisitions);

    ++connection_manager->vended_connection_count;

done:

    aws_mutex_unlock(&connection_manager->lock);

    s_aws_http_connection_manager_complete_acquisitions(&to_complete_acquisitions, connection_manager->allocator);

    /*
     * Delay until the very end just in case someone dropped the last external ref while there's a pending connect
     */
    if (return_type == AWS_CAT_NEWLY_CONNECTED) {
        aws_http_connection_manager_release(connection_manager);
    }
}

/*
 * Unlike the other functions, using the to_complete_acquisitions list doesn't make sense here because many
 * of the completion points do not have an aws_http_connection_acquisition structure filled out.  So just
 * do it with local variables (make_callback, callback_connection).
 */
int aws_http_connection_manager_acquire_connection(struct aws_http_connection_manager *connection_manager, aws_http_on_client_connection_setup_fn *callback, void *user_data) {
    int result = AWS_OP_ERR;

    bool make_callback = false;
    struct aws_http_connection *callback_connection = NULL;

    aws_mutex_lock(&connection_manager->lock);

    /*
     * Future: possibly worth evaluating whether LIFO-ordering ready connections gives a performance improvement (cache-wise)
     * Would require moving from hash table to a different data structure
     */
    size_t available_connection_count = aws_hash_table_get_entry_count(&connection_manager->connections);
    if (available_connection_count > 0) {
        struct aws_hash_iter iter = aws_hash_iter_begin(&connection_manager->connections);
        struct aws_http_connection *connection = (void *) iter.element.key;

        aws_hash_iter_delete(&iter, false);

        ++connection_manager->vended_connection_count;
        result = AWS_OP_SUCCESS;

        make_callback = true;
        callback_connection = connection;

        goto done;
    }

    struct aws_http_connection_acquisition *pending_connection = aws_mem_acquire(connection_manager->allocator, sizeof(struct aws_http_connection_acquisition));
    if (pending_connection == NULL) {
        make_callback = true;
        goto done;
    }

    if (s_aws_http_connection_manager_new_connection(connection_manager)) {
        aws_mem_release(connection_manager->allocator, pending_connection);
        make_callback = true;
        goto done;
    }

    AWS_ZERO_STRUCT(*pending_connection);

    pending_connection->callback = callback;
    pending_connection->user_data = user_data;

    aws_linked_list_push_back(&connection_manager->pending_acquisitions, &pending_connection->node);
    ++connection_manager->pending_acquisition_count;

done:

    aws_mutex_unlock(&connection_manager->lock);

    if (make_callback) {
        callback(callback_connection, callback_connection != NULL ? AWS_ERROR_SUCCESS : aws_last_error(), user_data);
    }

    return result;
}

int aws_http_connection_manager_release_connection(struct aws_http_connection_manager *connection_manager, struct aws_http_connection *connection) {
    s_aws_http_connection_manager_accept_connection(connection_manager, connection, AWS_CAT_RELEASED);

    return AWS_OP_SUCCESS;
}
