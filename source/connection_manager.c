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
#include <aws/http/connection.h>
#include <aws/http/private/connection_manager_function_table.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

/*
 * Function table to use under normal circumstances
 */
static struct aws_http_connection_manager_function_table s_default_function_table = {
    .create_connection = aws_http_client_connect,
    .release_connection = aws_http_connection_release,
    .close_connection = aws_http_connection_close,
    .is_connection_open = aws_http_connection_is_open};

const struct aws_http_connection_manager_function_table *g_aws_http_connection_manager_default_function_table_ptr =
    &s_default_function_table;

enum aws_http_connection_manager_state_type { AWS_HCMST_READY, AWS_HCMST_SHUTTING_DOWN };

struct aws_http_connection_manager {
    struct aws_allocator *allocator;

    /*
     * A union of external downstream dependencies (primarily global http API functions) and
     * internal implementation references.  Selectively overridden by tests in order to
     * enable strong coverage of internal implementation details.
     */
    const struct aws_http_connection_manager_function_table *function_table;

    /*
     * Controls access to all mutable state on the connection manager
     */
    struct aws_mutex lock;

    /*
     * A manager can be in one of two states, READY or SHUTTING_DOWN.  The state transition
     * takes place when ref_count drops to zero.
     */
    enum aws_http_connection_manager_state_type state;

    /*
     * The set of all available, ready-to-be-used connections
     */
    struct aws_array_list connections;

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
     * layer.
     */
    size_t pending_connects_count;

    /*
     * The number of connections currently being used by external users.
     */
    size_t vended_connection_count;

    /*
     * Always equal to # of connection shutdown callbacks not yet invoked
     * or equivalently:
     *
     * # of connections ever created by the manager - # shutdown callbacks received
     */
    size_t open_connection_count;

    /*
     * All the options needed to create an http connection
     */
    struct aws_client_bootstrap *bootstrap;
    size_t initial_window_size;
    struct aws_socket_options socket_options;
    struct aws_tls_connection_options *tls_connection_options;
    struct aws_string *host;
    uint16_t port;

    /*
     * The maximum number of connections this manager should ever have at once.
     */
    size_t max_connections;

    /*
     * Lifecycle tracking for the connection manager.  Starts at 1.
     *
     * Once this drops to zero, the manager state transitions to shutting down
     *
     * The manager is deleted when all other tracking counters have returned to zero.
     *
     * We don't use an atomic here because the shutdown phase wants to check many different
     * values.  You could argue that we could use a sum of everything, but we still need the
     * individual values for proper behavior and error checking during the ready state.  Also,
     * a hybrid atomic/lock solution felt excessively complicated and delicate.
     */
    size_t external_ref_count;
};

/*
 * The manager's lock must be held by the caller.
 */
static bool s_aws_http_connection_manager_should_destroy(struct aws_http_connection_manager *manager) {
    if (manager->state != AWS_HCMST_SHUTTING_DOWN) {
        return false;
    }

    AWS_ASSERT(manager->external_ref_count == 0);

    if (manager->vended_connection_count > 0 || manager->pending_connects_count > 0 ||
        manager->open_connection_count > 0) {
        return false;
    }

    return true;
}

/*
 * A struct that functions as both the pending acquisition tracker and the about-to-complete data.
 *
 * The list in the connection manager is the set of all acquisition requests that we haven't resolved.
 *
 * In order to make sure we never invoke callbacks while holding the manager's lock, in a number of places
 * we build a list of one or more acquisitions to complete.  Once the lock is released
 * we complete all the acquisitions in the list using the data within the struct (hence why we have
 * connection and result members).
 */
struct aws_http_connection_acquisition {
    struct aws_linked_list_node node;
    aws_http_on_client_connection_setup_fn *callback;
    void *user_data;
    struct aws_http_connection *connection;
    int error_code;
};

/*
 * Invokes a set of acquisition completion callbacks.  Only call this outside the scope of the connection manager's
 * lock.
 *
 * Assumes that internal state (like pending_acquisition_count, vended_connection_count, etc...) have already been
 * updated according to the list's contents.
 */
static void s_aws_http_connection_manager_complete_acquisitions(
    struct aws_linked_list *acquisitions,
    struct aws_allocator *allocator) {

    while (!aws_linked_list_empty(acquisitions)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(acquisitions);
        struct aws_http_connection_acquisition *pending_acquisition =
            AWS_CONTAINER_OF(node, struct aws_http_connection_acquisition, node);

        pending_acquisition->callback(
            pending_acquisition->connection, pending_acquisition->error_code, pending_acquisition->user_data);
        aws_mem_release(allocator, pending_acquisition);
    }
}

/*
 * Moves the first pending connection acquisition into a list.  Call this while holding the lock to
 * build the set of callbacks to be completed once the lock is released.
 *
 * If this was a successful acquisition then connection is non-null
 * If this was a failed acquisition then connection is null and error_code is hopefully a useful diagnostic (extreme
 * edge cases exist where it may not be though)
 */
static void s_aws_http_connection_manager_move_front_acquisition(
    struct aws_http_connection_manager *manager,
    struct aws_http_connection *connection,
    int error_code,
    struct aws_linked_list *output_list) {

    AWS_ASSERT(!aws_linked_list_empty(&manager->pending_acquisitions));
    AWS_ASSERT(manager->pending_acquisition_count > 0);

    struct aws_linked_list_node *node = aws_linked_list_pop_front(&manager->pending_acquisitions);
    --manager->pending_acquisition_count;

    struct aws_http_connection_acquisition *pending_acquisition =
        AWS_CONTAINER_OF(node, struct aws_http_connection_acquisition, node);
    pending_acquisition->connection = connection;
    pending_acquisition->error_code = error_code;

    aws_linked_list_push_back(output_list, node);
}

static void s_aws_http_connection_manager_destroy(struct aws_http_connection_manager *manager) {
    if (manager == NULL) {
        return;
    }

    AWS_ASSERT(manager->pending_connects_count == 0);
    AWS_ASSERT(manager->vended_connection_count == 0);
    AWS_ASSERT(manager->pending_acquisition_count == 0);
    AWS_ASSERT(manager->open_connection_count == 0);
    AWS_ASSERT(aws_linked_list_empty(&manager->pending_acquisitions));
    AWS_ASSERT(aws_array_list_length(&manager->connections) == 0);

    aws_array_list_clean_up(&manager->connections);

    aws_string_destroy(manager->host);
    if (manager->tls_connection_options) {
        aws_tls_connection_options_clean_up(manager->tls_connection_options);
        aws_mem_release(manager->allocator, manager->tls_connection_options);
    }

    aws_mutex_clean_up(&manager->lock);

    aws_mem_release(manager->allocator, manager);
}

struct aws_http_connection_manager *aws_http_connection_manager_new(
    struct aws_allocator *allocator,
    struct aws_http_connection_manager_options *options) {

    AWS_ASSERT(options);
    AWS_ASSERT(options->socket_options);
    AWS_ASSERT(options->max_connections > 0);

    struct aws_http_connection_manager *manager =
        aws_mem_acquire(allocator, sizeof(struct aws_http_connection_manager));
    if (manager == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*manager);
    manager->allocator = allocator;

    if (aws_mutex_init(&manager->lock)) {
        goto on_error;
    }

    if (aws_array_list_init_dynamic(
            &manager->connections, allocator, options->max_connections, sizeof(struct aws_http_connection *))) {
        goto on_error;
    }

    aws_linked_list_init(&manager->pending_acquisitions);

    manager->host = aws_string_new_from_array(allocator, options->host.ptr, options->host.len);
    if (manager->host == NULL) {
        goto on_error;
    }

    if (options->tls_connection_options) {
        manager->tls_connection_options = aws_mem_acquire(allocator, sizeof(struct aws_tls_connection_options));
        AWS_ZERO_STRUCT(*manager->tls_connection_options);
        if (aws_tls_connection_options_copy(manager->tls_connection_options, options->tls_connection_options)) {
            goto on_error;
        }
    }

    manager->state = AWS_HCMST_READY;
    manager->initial_window_size = options->initial_window_size;
    manager->port = options->port;
    manager->max_connections = options->max_connections;
    manager->socket_options = *options->socket_options;
    manager->bootstrap = options->bootstrap;
    manager->function_table = options->function_table;
    manager->external_ref_count = 1;
    if (manager->function_table == NULL) {
        manager->function_table = g_aws_http_connection_manager_default_function_table_ptr;
    }

    if (!aws_http_connection_manager_function_table_is_valid(manager->function_table)) {
        goto on_error;
    }

    return manager;

on_error:

    s_aws_http_connection_manager_destroy(manager);

    return NULL;
}

void aws_http_connection_manager_acquire(struct aws_http_connection_manager *manager) {
    aws_mutex_lock(&manager->lock);
    manager->external_ref_count += 1;
    aws_mutex_unlock(&manager->lock);
}

void aws_http_connection_manager_release(struct aws_http_connection_manager *manager) {
    struct aws_array_list connections_to_release;
    AWS_ZERO_STRUCT(connections_to_release);

    struct aws_linked_list pending_acquisitions_to_fail;
    aws_linked_list_init(&pending_acquisitions_to_fail);

    bool should_destroy = false;

    aws_mutex_lock(&manager->lock);

    AWS_FATAL_ASSERT(manager->external_ref_count > 0);
    manager->external_ref_count -= 1;

    if (manager->external_ref_count == 0) {
        manager->state = AWS_HCMST_SHUTTING_DOWN;
        should_destroy = s_aws_http_connection_manager_should_destroy(manager);

        aws_array_list_init_dynamic(
            &connections_to_release, manager->allocator, 0, sizeof(struct aws_http_connection *));
        aws_array_list_swap_contents(&manager->connections, &connections_to_release);
        aws_linked_list_swap_contents(&manager->pending_acquisitions, &pending_acquisitions_to_fail);
    }

    aws_mutex_unlock(&manager->lock);

    size_t connection_count = aws_array_list_length(&connections_to_release);

    for (size_t i = 0; i < connection_count; ++i) {
        struct aws_http_connection *connection = NULL;
        if (aws_array_list_get_at(&connections_to_release, &connection, i)) {
            continue;
        }

        manager->function_table->release_connection(connection);
    }

    aws_array_list_clean_up(&connections_to_release);
    s_aws_http_connection_manager_complete_acquisitions(&pending_acquisitions_to_fail, manager->allocator);

    if (should_destroy) {
        s_aws_http_connection_manager_destroy(manager);
    }
}

static void s_aws_http_connection_manager_build_work_order(
    struct aws_http_connection_manager *connection_manager,
    struct aws_linked_list *completions,
    size_t *new_connections) {
    /*
     * Step 1 - If there's free connections, complete acquisition requests
     */
    while (aws_array_list_length(&connection_manager->connections) > 0 &&
           connection_manager->pending_acquisition_count > 0) {
        struct aws_http_connection *connection = NULL;
        aws_array_list_back(&connection_manager->connections, &connection);

        aws_array_list_pop_back(&connection_manager->connections);

        s_aws_http_connection_manager_move_front_acquisition(
            connection_manager, connection, AWS_ERROR_SUCCESS, completions);
        ++connection_manager->vended_connection_count;
    }

    /*
     * Step 2 - if there's excess pending acquisitions and we have room to make more, make more
     */
    if (connection_manager->pending_acquisition_count > connection_manager->pending_connects_count) {
        AWS_ASSERT(
            connection_manager->max_connections >=
            connection_manager->vended_connection_count + connection_manager->pending_connects_count);

        *new_connections = connection_manager->pending_acquisition_count - connection_manager->pending_connects_count;
        size_t max_new_connections =
            connection_manager->max_connections -
            (connection_manager->vended_connection_count + connection_manager->pending_connects_count);

        if (*new_connections > max_new_connections) {
            *new_connections = max_new_connections;
        }

        connection_manager->pending_connects_count += *new_connections;
    }
}

static void s_aws_http_connection_manager_on_connection_setup(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);
static void s_aws_http_connection_manager_on_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data);

static int s_aws_http_connection_manager_new_connection(struct aws_http_connection_manager *connection_manager) {
    struct aws_http_client_connection_options options;
    AWS_ZERO_STRUCT(options);
    options.self_size = sizeof(struct aws_http_client_connection_options);
    options.bootstrap = connection_manager->bootstrap;
    options.tls_options = connection_manager->tls_connection_options;
    options.allocator = connection_manager->allocator;
    options.user_data = connection_manager;
    options.host_name = aws_byte_cursor_from_string(connection_manager->host);
    options.port = connection_manager->port;
    options.initial_window_size = connection_manager->initial_window_size;
    options.socket_options = &connection_manager->socket_options;
    options.on_setup = s_aws_http_connection_manager_on_connection_setup;
    options.on_shutdown = s_aws_http_connection_manager_on_connection_shutdown;

    if (connection_manager->function_table->create_connection(&options)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_aws_http_connection_manager_execute_work_order(
    struct aws_http_connection_manager *connection_manager,
    struct aws_linked_list *completions,
    size_t new_connections) {

    int representative_error = 0;
    size_t new_connection_failures = 0;

    struct aws_array_list errors;
    AWS_ZERO_STRUCT(errors);

    bool push_errors = aws_array_list_init_dynamic(
                           &errors, connection_manager->allocator, new_connections, sizeof(int)) == AWS_ERROR_SUCCESS;
    for (size_t i = 0; i < new_connections; ++i) {
        if (s_aws_http_connection_manager_new_connection(connection_manager)) {
            ++new_connection_failures;
            representative_error = aws_last_error();
            if (push_errors) {
                aws_array_list_push_back(&errors, &representative_error);
            }
        }
    }

    if (new_connection_failures > 0) {
        aws_mutex_lock(&connection_manager->lock);

        connection_manager->pending_connects_count -= new_connection_failures;
        size_t i = 0;

        /*
         * Rather than failing one acquisition for each connection failure, if there's at least one
         * connection failure, we instead fail all excess acquisitions, since there's no pending
         * connect that will necessarily resolve them.
         *
         * Try to correspond an error with the acquisition failure, but as a fallback just use the
         * representative error
         */
        while (connection_manager->pending_acquisition_count > connection_manager->pending_connects_count) {
            int error = representative_error;
            if (i < aws_array_list_length(&errors)) {
                aws_array_list_get_at(&errors, &error, i);
            }

            s_aws_http_connection_manager_move_front_acquisition(connection_manager, NULL, error, completions);
            ++i;
        }

        aws_mutex_unlock(&connection_manager->lock);
    }

    s_aws_http_connection_manager_complete_acquisitions(completions, connection_manager->allocator);

    aws_array_list_clean_up(&errors);
}

int aws_http_connection_manager_acquire_connection(
    struct aws_http_connection_manager *connection_manager,
    aws_http_on_client_connection_setup_fn *callback,
    void *user_data) {

    struct aws_http_connection_acquisition *request =
        aws_mem_acquire(connection_manager->allocator, sizeof(struct aws_http_connection_acquisition));
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

int aws_http_connection_manager_release_connection(
    struct aws_http_connection_manager *connection_manager,
    struct aws_http_connection *connection) {
    struct aws_linked_list completions;
    aws_linked_list_init(&completions);

    size_t new_connections = 0;

    aws_mutex_lock(&connection_manager->lock);

    AWS_FATAL_ASSERT(connection_manager->state == AWS_HCMST_READY);

    AWS_ASSERT(connection_manager->vended_connection_count > 0);
    --connection_manager->vended_connection_count;

    bool should_release_connection = !connection_manager->function_table->is_connection_open(connection);
    if (!should_release_connection) {
        if (aws_array_list_push_back(&connection_manager->connections, &connection)) {
            should_release_connection = true;
        }
    }

    s_aws_http_connection_manager_build_work_order(connection_manager, &completions, &new_connections);

    aws_mutex_unlock(&connection_manager->lock);

    s_aws_http_connection_manager_execute_work_order(connection_manager, &completions, new_connections);

    if (should_release_connection) {
        connection_manager->function_table->release_connection(connection);
    }

    return AWS_OP_SUCCESS;
}

static void s_aws_http_connection_manager_on_connection_setup(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {
    struct aws_http_connection_manager *manager = user_data;

    struct aws_linked_list completions;
    aws_linked_list_init(&completions);

    size_t new_connections = 0;

    aws_mutex_lock(&manager->lock);

    bool is_shutting_down = manager->state == AWS_HCMST_SHUTTING_DOWN;
    AWS_ASSERT(manager->pending_acquisition_count == 0 || !is_shutting_down);

    AWS_ASSERT(manager->pending_connects_count > 0);
    --manager->pending_connects_count;

    if (connection != NULL) {
        if (!is_shutting_down) {
            /* We reserved enough room for max_connections, this should never fail */
            AWS_FATAL_ASSERT(aws_array_list_push_back(&manager->connections, &connection) == AWS_OP_SUCCESS);
        }
        ++manager->open_connection_count;
    }

    bool should_destroy = s_aws_http_connection_manager_should_destroy(manager);

    if (connection == NULL) {
        /*
         * To be safe, if we have an excess of pending acquisitions (beyond the number of pending
         * connects), we need to fail all of the excess.  Technically, we might be able to try and
         * make a new connection, if there's room, but that could lead to some bad failure loops.
         *
         * This won't happen during shutdown since there are no pending acquisitions at that point.
         */
        while (manager->pending_acquisition_count > manager->pending_connects_count) {
            s_aws_http_connection_manager_move_front_acquisition(manager, NULL, error_code, &completions);
        }
    }

    s_aws_http_connection_manager_build_work_order(manager, &completions, &new_connections);

    aws_mutex_unlock(&manager->lock);

    s_aws_http_connection_manager_execute_work_order(manager, &completions, new_connections);

    if (is_shutting_down && connection != NULL) {
        /*
         * We didn't add the connection to the pool; just release it immediately
         */
        manager->function_table->release_connection(connection);
    }

    if (should_destroy) {
        s_aws_http_connection_manager_destroy(manager);
    }
}

static void s_aws_http_connection_manager_on_connection_shutdown(
    struct aws_http_connection *connection,
    int error_code,
    void *user_data) {
    (void)error_code;

    bool should_release_connection = false;

    struct aws_http_connection_manager *manager = user_data;
    aws_mutex_lock(&manager->lock);

    --manager->open_connection_count;
    bool should_destroy = s_aws_http_connection_manager_should_destroy(manager);

    size_t connection_count = aws_array_list_length(&manager->connections);

    if (connection_count > 0) {
        AWS_ASSERT(manager->state == AWS_HCMST_READY);

        struct aws_http_connection *last_connection = NULL;
        aws_array_list_get_at(&manager->connections, &last_connection, connection_count - 1);

        for (size_t i = 0; i < connection_count; ++i) {
            struct aws_http_connection *current_connection = NULL;
            aws_array_list_get_at(&manager->connections, &current_connection, i);

            if (current_connection == connection) {
                should_release_connection = true;
                aws_array_list_set_at(&manager->connections, &last_connection, i);
                break;
            }
        }

        if (should_release_connection) {
            aws_array_list_pop_back(&manager->connections);
        }
    }

    aws_mutex_unlock(&manager->lock);

    AWS_ASSERT(!should_release_connection || !should_destroy);

    if (should_release_connection) {
        manager->function_table->release_connection(connection);
    }

    if (should_destroy) {
        s_aws_http_connection_manager_destroy(manager);
    }
}
