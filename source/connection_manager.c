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
#include <aws/http/private/connection_manager_function_table.h>

static struct aws_http_connection_manager_function_table s_default_function_table = {
    .create_connection = aws_http_client_connect,
    .release_connection = aws_http_connection_release,
    .close_connection = aws_http_connection_close
};

enum aws_http_connection_manager_state_type {
    AWS_HCMST_READY,
    AWS_HCMST_SHUTTING_DOWN
};

struct aws_http_connection_manager {
    struct aws_allocator *allocator;

    struct aws_http_connection_manager_function_table *functions;

    /*
     * Controls access to all mutable state on the connection manager
     */
    struct aws_mutex lock;

    enum aws_http_connection_manager_state_type state;

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

    size_t open_connection_count;

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
     * While state == ready : value = # external refs + # vended connects
     * While state == shutting_down : value = # of connection shutdown callbacks not yet invoked
     */
    size_t ref_count;
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
    struct aws_http_connection_manager *manager = context;

    struct aws_http_connection *connection = (void *)element->key;
    manager->functions->release_connection(connection);

    return AWS_OP_SUCCESS;
}

static void s_aws_http_connection_manager_destroy(struct aws_http_connection_manager *manager) {
    if (manager == NULL) {
        return;
    }

    assert(manager->pending_connects_count == 0);
    assert(manager->vended_connection_count == 0);
    assert(manager->pending_acquisition_count == 0);
    assert(manager->open_connection_count == 0);
    assert(aws_linked_list_empty(&manager->pending_acquisitions));
    assert(aws_hash_table_get_entry_count(&manager->connections) == 0);

    aws_hash_table_clean_up(&manager->connections);

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

    manager->state = AWS_HCMST_READY;
    manager->initial_window_size = options->initial_window_size;
    manager->port = options->port;
    manager->max_connections = options->max_connections;
    manager->socket_options = *options->socket_options;
    manager->bootstrap = options->bootstrap;
    manager->functions = options->mocks;
    manager->ref_count = 1;
    if (manager->functions == NULL) {
        manager->functions = &s_default_function_table;
    }

    assert(aws_http_connection_manager_function_table_is_valid(manager->functions));

    return manager;

on_error:

    s_aws_http_connection_manager_destroy(manager);

    return NULL;
}

void aws_http_connection_manager_acquire(struct aws_http_connection_manager *manager) {
    aws_mutex_lock(&manager->lock);
    manager->ref_count += 1;
    aws_mutex_unlock(&manager->lock);
}

enum aws_async_release_result {
    AWS_ARR_NONE,
    AWS_ARR_START_SHUT_DOWN,
    AWS_ARR_DELETE
};

static enum aws_async_release_result s_aws_http_connection_manager_release(struct aws_http_connection_manager *manager) {
    AWS_FATAL_ASSERT(manager->ref_count > 0);

    enum aws_async_release_result result = AWS_ARR_NONE;
    manager->ref_count -= 1;

    if (manager->ref_count == 0 && manager->state == AWS_HCMST_READY) {
        assert(manager->vended_connection_count == 0);

        manager->state = AWS_HCMST_SHUTTING_DOWN;
        manager->ref_count = manager->open_connection_count;
        result = manager->ref_count > 0 ? AWS_ARR_START_SHUT_DOWN : AWS_ARR_DELETE;
    }

    if (manager->ref_count == 0 && manager->state == AWS_HCMST_SHUTTING_DOWN) {
        result = AWS_ARR_DELETE;
    }

    return result;
}

void aws_http_connection_manager_release(struct aws_http_connection_manager *manager) {
    aws_mutex_lock(&manager->lock);
    bool start_shutdown_process = s_aws_http_connection_manager_release(manager);
    if (start_shutdown_process) {
        ??;
    }
    aws_mutex_unlock(&manager->lock);
}

static void s_aws_http_connection_manager_build_work_order(struct aws_http_connection_manager *connection_manager,
                                                           struct aws_linked_list *completions, size_t *new_connections) {
    /*
     * Step 1 - If there's free connections, complete acquisition requests
     */
    while(aws_hash_table_get_entry_count(&connection_manager->connections) > 0 && connection_manager->pending_acquisition_count > 0) {
        struct aws_hash_iter iter = aws_hash_iter_begin(&connection_manager->connections);
        struct aws_http_connection *connection = (void *) iter.element.key;

        aws_hash_iter_delete(&iter, false);

        s_aws_http_connection_manager_move_front_acquisition(connection_manager, connection, AWS_ERROR_SUCCESS, completions);
        ++connection_manager->vended_connection_count;
    }

    /*
     * Step 2 - if there's excess pending acquisitions and we have room to make more, make more
     */
    if (connection_manager->pending_acquisition_count > connection_manager->pending_connects_count) {
        *new_connections = connection_manager->pending_acquisition_count - connection_manager->pending_connects_count;

        assert(connection_manager->max_connections >= connection_manager->vended_connection_count + connection_manager->pending_connects_count);
        size_t max_new_connections = connection_manager->max_connections - (connection_manager->vended_connection_count + connection_manager->pending_connects_count);

        if (*new_connections > max_new_connections) {
            *new_connections = max_new_connections;
        }

        connection_manager->pending_connects_count += *new_connections;
    }
}

static void s_aws_http_connection_manager_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data);
static void s_aws_http_connection_manager_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data);

static int s_aws_http_connection_manager_new_connection(struct aws_http_connection_manager *connection_manager) {
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

    if (connection_manager->functions->create_connection(&options))
    {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}


static void s_aws_http_connection_manager_execute_work_order(struct aws_http_connection_manager *connection_manager,
                                                             struct aws_linked_list *completions,
                                                             size_t new_connections) {

    int representative_error = 0;
    size_t new_connection_failures = 0;

    struct aws_array_list errors;
    AWS_ZERO_STRUCT(errors);

    if (!aws_array_list_init_dynamic(&errors, connection_manager->allocator, new_connections, sizeof(int))) {
        for (size_t i = 0; i < new_connections; ++i) {
            if (s_aws_http_connection_manager_new_connection(connection_manager)) {
                representative_error = aws_last_error();
                aws_array_list_push_back(&errors, &representative_error);
            }
        }
    }

    if (new_connection_failures > 0) {
        aws_mutex_lock(&connection_manager->lock);

        connection_manager->pending_connects_count -= new_connection_failures;
        for (size_t i = 0;
             i < new_connection_failures && !aws_linked_list_empty(&connection_manager->pending_acquisitions); ++i) {
            int error = representative_error;
            if (i < aws_array_list_length(&errors)) {
                aws_array_list_get_at(&errors, &error, i);
            }

            s_aws_http_connection_manager_move_front_acquisition(connection_manager, NULL, error, completions);
        }

        aws_mutex_unlock(&connection_manager->lock);
    }

    s_aws_http_connection_manager_complete_acquisitions(completions, connection_manager->allocator);
}

int aws_http_connection_manager_acquire_connection(struct aws_http_connection_manager *connection_manager, aws_http_on_client_connection_setup_fn *callback, void *user_data) {

    struct aws_http_connection_acquisition *request = aws_mem_acquire(connection_manager->allocator, sizeof(struct aws_http_connection_acquisition));
    if (request == NULL) {
        callback(NULL, aws_last_error(), user_data);
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*request);
    request->callback = callback;
    request->user_data = user_data;

    struct aws_linked_list completions;
    aws_linked_list_init(&completions);

    size_t new_connections = 0;

    aws_mutex_lock(&connection_manager->lock);

    AWS_FATAL_ASSERT(connection_manager->state == AWS_HCMST_READY);

    aws_linked_list_push_back(&connection_manager->pending_acquisitions, &request->node);
    ++connection_manager->pending_acquisition_count;

    s_aws_http_connection_manager_build_work_order(connection_manager, &completions, &new_connections);

    aws_mutex_unlock(&connection_manager->lock);

    s_aws_http_connection_manager_execute_work_order(connection_manager, &completions, new_connections);

    return AWS_OP_SUCCESS;
}

int aws_http_connection_manager_release_connection(struct aws_http_connection_manager *connection_manager, struct aws_http_connection *connection) {
    bool should_release = false;

    struct aws_linked_list completions;
    aws_linked_list_init(&completions);

    size_t new_connections = 0;

    aws_mutex_lock(&connection_manager->lock);

    AWS_FATAL_ASSERT(connection_manager->state == AWS_HCMST_READY);

    assert(connection_manager->vended_connection_count > 0);
    --connection_manager->vended_connection_count;

    should_release = aws_http_connection_is_open(connection);
    if (!should_release) {
        if (aws_hash_table_put(&connection_manager->connections, &connection, NULL, NULL)) {
            should_release = true;
        }
    }

    s_aws_http_connection_manager_build_work_order(connection_manager, &completions, &new_connections);

    aws_mutex_unlock(&connection_manager->lock);

    s_aws_http_connection_manager_execute_work_order(connection_manager, &completions, new_connections);

    if (should_release) {
        connection_manager->functions->release_connection(connection);
    }

    return AWS_OP_SUCCESS;
}

static void s_aws_http_connection_manager_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct aws_http_connection_manager *manager = user_data;

    struct aws_linked_list completions;
    aws_linked_list_init(&completions);

    size_t new_connections = 0;

    aws_mutex_lock(&manager->lock);

    assert(manager->pending_connects_count > 0);
    --manager->pending_connects_count;

    bool is_failure = connection == NULL;
    if (connection != NULL) {
        if (aws_hash_table_put(&manager->connections, &connection, NULL, NULL)) {
            is_failure = true;
        }
    }

    if (is_failure) {
        /*
         * A nice behavioral optimization.  If we failed to connect now, then we're more likely to fail in the near-future
         * as well.  So if we have an excess of pending acquisitions (beyond the number of pending connects), let's fail
         * all of the excess.
         */
        while (manager->pending_acquisition_count > manager->pending_connects_count) {
            s_aws_http_connection_manager_move_front_acquisition(manager, NULL, error_code, &completions);
        }
    }

    s_aws_http_connection_manager_build_work_order(manager, &completions, &new_connections);

    aws_mutex_unlock(&manager->lock);

    s_aws_http_connection_manager_execute_work_order(manager, &completions, new_connections);

    if (is_failure && connection) {
        manager->functions->release_connection(connection);
    }
}

static void s_aws_http_connection_manager_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)error_code;

    struct aws_http_connection_manager *manager = user_data;
    aws_mutex_lock(&manager->lock);

    int was_present = 0;
    aws_hash_table_remove(&manager->connections, connection, NULL, &was_present);

    aws_mutex_unlock(&manager->lock);

    if (was_present) {
        manager->functions->release_connection(connection);
    }
}
