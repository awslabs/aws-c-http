/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#include <aws/common/device_random.h>
#include <aws/common/mutex.h>
#include <aws/common/ref_count.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/http2_stream_manager.h>
#include <aws/http/request_response.h>

#define STREAM_MANAGER_LOGF(level, stream_manager, text, ...)                                                          \
    AWS_LOGF_##level(AWS_LS_HTTP2_STREAM_MANAGER, "id=%p: " text, (void *)(stream_manager), __VA_ARGS__)
#define STREAM_MANAGER_LOG(level, stream_manager, text) STREAM_MANAGER_LOGF(level, stream_manager, "%s", text)

struct aws_h2_sm_connection {
    struct aws_http_connection *connection;
    uint32_t num_streams_open;
};

struct aws_h2_sm_pending_stream_acquisition {
    struct aws_allocator *allocator;
    struct aws_linked_list_node node;
    struct aws_http_make_request_options options;
    aws_http2_stream_manager_on_stream_acquired_fn *callback;
    void *user_data;
};

/**
 * Vocabulary
 *    Acquisition - a request by a user for a stream
 *    Pending Acquisition - a request by a user for a new stream that has not been completed.  It may be
 *      waiting on connection manager to vend a connection, a release by another user, or the manager itself.
 *    Connection to Acquire - a request of connection needed to be required from connection manager, but has not been
 *      sent yet
 *    Connection Acquiring - a request to the connection manager layer for a new connection that has not been
 *      resolved yet
 *
 * Requirements/Assumptions
 *    (1) Don't invoke user callbacks while holding the internal state lock
 *    (2) Don't invoke downstream connection manager and http calls while holding the internal state lock
 *    (3) Only log unusual or rare events while the lock is held.  Common-path logging should be while it is
 *        not held.
 *    (4) Don't crash or do awful things (leaking resources is ok though) if the interface contract
 *        (ref counting + balanced acquire/release of connections) is violated by the user
 *
 *  In order to fulfill (1) and (2), all side-effecting operations within the connection manager follow a pattern:
 *    (1) Lock
 *    (2) Make state changes based on the operation
 *    (3) Build a set of work (completions, connect calls, releases, self-destruction) as appropriate to the operation
 *    (4) Unlock
 *    (5) Execute the task set
 *
 *   Asynchronous work order failures are handled in the async callback, but immediate failures require
 *   us to relock and update the internal state.  When there's an immediate connect failure, we use a
 *   conservative policy to fail all excess (beyond the # of pending connects) acquisitions; this allows us
 *   to avoid a possible recursive invocation (and potential failures) to connect again.
 *
 * Stream Manager Lifecycle:
 * Our stream manager implementation also has a reasonably complex lifecycle.
 *
 * - Vended Stream Lifecycle:
 *    (1) HTTP level completed callback.
 *    (3) User will keep it alive until calling aws_http2_stream_manager_stream_release or aws_http_stream_release.
 *          Note: Even if aws_http_stream_release called, the stream will die but stream manager will not die until
 *          aws_http2_stream_manager_stream_release called. So, recommend to call
 *          aws_http2_stream_manager_stream_release directly
 *
 * - Internal Connections Lifecycle:
 *    (1) Stream Manager doesn't really control the lifecycle of connections. This's more about when Stream Manager
 *          release holding it.
 *    (2) All streams created from the connection dies, release holding it.
 *    (3) Connection cannot create any new requests, release holding it.
 *
 * - Internal Connection Manager Lifecycle:
 *      Has the exact same Lifecycle as Stream Manager, which means when Stream Manager starts to destroy, Connection
 *      Manager will start its shutdown process. And when Connection Manager finish shutdown, the Stream Manager will
 *      finish shutdown right after it.
 *
 * - Stream Manager Lifecycle:
 *    (1) External refcount
 *    (2) All state around the life cycle is protected by a lock.
 *    (3) Over the course of its lifetime, a stream manager moves through two states:
 *
 *        - READY - streams may be acquired and released.  When the external ref count for the manager
 *          drops to zero, the manager moves to:
 *
 *        - SHUTTING_DOWN - streams may no longer be acquired (how could they if the external
 *          ref count was accurate?) but in case of user ref errors, we simply fail attempts to do so rather
 *          than crash or underflow.  While in this state, we wait for a set of tracking counters to all fall to zero:
 *            - connection_acquiring_count - the # of unresolved calls to the connection manager layer
 *            - open_stream_count - the # of streams for whom the completed callback (from http) has not been invoked
 *            - vended_stream_count - the # of streams held by external users that haven't been released.  Under correct
 *                  usage this should be zero before SHUTTING_DOWN is entered, but we attempt to handle incorrect usage
 *                  gracefully.
 *
 *      In short: No connections acquiring, no streams alive and no streams not released to stream manger. Underlying
 *          logic will be no connections held by stream manager(All streams dies, the connections will be released back
 *          to connection manager). Starting that point, underlying connection manager can die and stream manager will
 *          die right after it finishes shutdown.
 */
struct aws_http2_stream_manager {
    struct aws_allocator *allocator;
    void *shutdown_complete_user_data;
    aws_http2_stream_manager_shutdown_complete_fn *shutdown_complete_callback;
    /**
     * Underlying connection manager. Always has the same life time with the stream manager who owns it.
     */
    struct aws_http_connection_manager *connection_manager;
    struct aws_ref_count ref_count;

    /* Any thread may touch this data, but the lock must be held (unless it's an atomic) */
    struct {
        struct aws_mutex lock;
        /**
         * Array list of aws_h2_sm_connection
         */
        struct aws_array_list connections_list;

        /**
         * The set of all incomplete stream acquisition requests, list of `struct aws_h2_sm_pending_stream_acquisition*`
         */
        struct aws_linked_list pending_acquisitions;

        /**
         * The number of all incomplete stream acquisition requests. So
         * that we don't have compute the size of a linked list every time.
         */
        size_t pending_acquisition_count;

        /**
         * The number of new connections we acquiring from the connection manager.
         */
        size_t connections_acquiring;

        /**
         * Number of max concurrent streams for new connection. We assume the connections we make will have the same
         * concurrent streams.
         */
        size_t assume_max_concurrent_stream;

    } synced_data;
};

/*
 * Encompasses all of the external operations that need to be done for various
 * events:
 *  - User level:
 *   stream manager release
 *   stream release
 *   stream acquire
 *  - Internal eventloop (anther thread):
 *   connection_acquired
 *   stream_completed
 *  - Internal (can happen from any thread):
 *   connection acquire
 *   connection release
 *
 * The transaction is built under the manager's lock (and the internal state is updated optimistically),
 * but then executed outside of it.
 */
struct aws_http2_stream_management_transaction {
    struct aws_http2_stream_manager *stream_manager;
    struct aws_allocator *allocator;
    // struct aws_linked_list completions;
    // struct aws_http_connection_manager_snapshot snapshot;
    // size_t new_connections;
    size_t connection_to_release_index; /* index of connection in the array list to release */
    bool should_destroy_manager;
};

static void s_aws_stream_management_transaction_init() {}
static void s_aws_stream_management_transaction_clean_up() {}
/* *_synced should only be called with LOCK HELD */
static void s_aws_http2_stream_manager_build_transaction_synced() {}
static void s_aws_http2_stream_manager_execute_transaction() {}

static void s_lock_synced_data(struct aws_http2_stream_manager *stream_manager) {
    int err = aws_mutex_lock(&stream_manager->synced_data.lock);
    AWS_ASSERT(!err && "lock failed");
    (void)err;
}

static void s_unlock_synced_data(struct aws_http2_stream_manager *stream_manager) {
    int err = aws_mutex_unlock(&stream_manager->synced_data.lock);
    AWS_ASSERT(!err && "unlock failed");
    (void)err;
}

void s_stream_manager_destroy_final(struct aws_http2_stream_manager *stream_manager) {
    if (!stream_manager) {
        return;
    }

    STREAM_MANAGER_LOG(INFO, stream_manager, "Stream Manager destroying self");
    /* Connection manager has already been cleaned up */
    AWS_FATAL_ASSERT(stream_manager->connection_manager == NULL);
    AWS_FATAL_ASSERT(aws_linked_list_empty(&stream_manager->synced_data.pending_acquisitions));
    aws_mutex_clean_up(&stream_manager->synced_data.lock);
    aws_array_list_clean_up(&stream_manager->synced_data.connections_list);

    if (stream_manager->shutdown_complete_callback) {
        stream_manager->shutdown_complete_callback(stream_manager->shutdown_complete_user_data);
    }
    aws_mem_release(stream_manager->allocator, stream_manager);
}

void s_stream_manager_on_cm_shutdown_complete(void *user_data) {
    struct aws_http2_stream_manager *stream_manager = (struct aws_http2_stream_manager *)user_data;
    STREAM_MANAGER_LOGF(
        TRACE,
        stream_manager,
        "Underlying connection manager (ip=%p) finished shutdown, stream manager can die now",
        (void *)stream_manager->connection_manager);
    stream_manager->connection_manager = NULL;
    s_stream_manager_destroy_final(stream_manager);
}

void s_stream_manager_start_destroy(struct aws_http2_stream_manager *stream_manger) {
    STREAM_MANAGER_LOG(TRACE, stream_manger, "Last refcount released, start to destroy the stream manager");
    aws_http_connection_manager_release(stream_manger->connection_manager);
}

struct aws_http2_stream_manager *aws_http2_stream_manager_new(
    struct aws_allocator *allocator,
    struct aws_http2_stream_manager_options *options) {
    AWS_PRECONDITION(allocator);

    struct aws_http2_stream_manager *stream_manager =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http2_stream_manager));
    if (aws_mutex_init(&stream_manager->synced_data.lock)) {
        goto on_error;
    }
    if (aws_array_list_init_dynamic(
            &stream_manager->synced_data.connections_list,
            allocator,
            options->max_connections,
            sizeof(struct aws_h2_sm_connection))) {
        goto on_error;
    }

    aws_ref_count_init(
        &stream_manager->ref_count, stream_manager, (aws_simple_completion_callback *)s_stream_manager_start_destroy);

    struct aws_http2_setting initial_settings_array[1] = {
        {
            .id = AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
            .value = options->initial_window_size,
        },
    };
    struct aws_http_connection_manager_options cm_options = {
        .bootstrap = options->bootstrap,
        .socket_options = options->socket_options,
        .tls_connection_options = options->tls_connection_options,
        .prior_knowledge_http2 = options->tls_connection_options ? false : true,
        .host = options->host,
        .port = options->port,
        .enable_read_back_pressure = options->enable_read_back_pressure,
        .monitoring_options = options->monitoring_options,
        .proxy_options = options->proxy_options,
        .proxy_ev_settings = options->proxy_ev_settings,
        .max_connections = options->max_connections,
        .shutdown_complete_user_data = stream_manager,
        .shutdown_complete_callback = s_stream_manager_on_cm_shutdown_complete,
        .initial_settings_array = options->initial_window_size ? initial_settings_array : NULL,
        .num_initial_settings = options->initial_window_size ? 1 : 0,
    };
    /* aws_http_connection_manager_new needs to be the last thing that can fail */
    stream_manager->connection_manager = aws_http_connection_manager_new(allocator, &cm_options);
    if (!stream_manager->connection_manager) {
        goto on_error;
    }
    /* Nothing can fail after here */
    stream_manager->shutdown_complete_callback = options->shutdown_complete_callback;
    stream_manager->shutdown_complete_user_data = options->shutdown_complete_user_data;
    /* There is no default settings and no limits (within UINT_32) to the concurrent stream, set it to UINT32_MAX */
    stream_manager->synced_data.assume_max_concurrent_stream = UINT32_MAX;

    aws_linked_list_init(&stream_manager->synced_data.pending_acquisitions);
    return stream_manager;
on_error:
    s_stream_manager_destroy_final(stream_manager);
}

void aws_http2_stream_manager_acquire(struct aws_http2_stream_manager *stream_manager) {
    AWS_PRECONDITION(stream_manager);

    aws_ref_count_acquire(&stream_manager->ref_count);
}

void aws_http2_stream_manager_release(struct aws_http2_stream_manager *stream_manager) {
    if (stream_manager == NULL) {
        return;
    }

    aws_ref_count_release(&stream_manager->ref_count);
}

static struct aws_h2_sm_pending_stream_acquisition *s_new_pending_stream_acquisition(
    struct aws_allocator *allocator,
    const struct aws_http_make_request_options *options,
    aws_http2_stream_manager_on_stream_acquired_fn *callback,
    void *user_data) {
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_sm_pending_stream_acquisition));

    /* Copy the options and keep the underlying message alive */
    pending_acquisition->options = *options;
    aws_http_message_acquire(pending_acquisition->options.request);
    pending_acquisition->callback = callback;
    pending_acquisition->user_data = user_data;
    pending_acquisition->allocator = allocator;
    return pending_acquisition;
}

static void s_pending_stream_acquisition_destroy(struct aws_h2_sm_pending_stream_acquisition *pending_acquisition) {
    if (pending_acquisition == NULL) {
        return;
    }
    aws_http_message_release(pending_acquisition->options.request);
    aws_mem_release(pending_acquisition->allocator, pending_acquisition);
    return;
}

/* *_synced should only be called with LOCK HELD */
static void s_async_acquire_stream_synced(
    struct aws_http2_stream_manager *stream_manager,
    const struct aws_http_make_request_options *options,
    aws_http2_stream_manager_on_stream_acquired_fn *callback,
    void *user_data,
    bool *should_acquire_connection) {
    /* Need to acquire a connection or wait for the connection to be acquired from connection manager. So, acquiring
     * stream will happen async */
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition =
        s_new_pending_stream_acquisition(stream_manager->allocator, options, callback, user_data);
    aws_linked_list_push_back(&stream_manager->synced_data.pending_acquisitions, &pending_acquisition->node);
    stream_manager->synced_data.pending_acquisition_count++;
    /* Check if there is a outstanding pending connection to acquire. And check if the pending streams are too
     * many for one connection to handle */
    size_t connections_needed = stream_manager->synced_data.pending_acquisition_count /
                                    stream_manager->synced_data.assume_max_concurrent_stream +
                                1;
    /* We need connections for all the streams */
    if (connections_needed > stream_manager->synced_data.connections_acquiring) {
        *should_acquire_connection = true;
        stream_manager->synced_data.connections_acquiring++;
    }
}

/* *_synced should only be called with LOCK HELD */
static bool s_check_connection_available_and_clean_up_synced(
    struct aws_h2_sm_connection *sm_connection,
    struct aws_http2_stream_manager *stream_manager,
    bool last_element) {
    if (!sm_connection->connection) {
        return false;
    }
    if (aws_http_connection_new_requests_allowed(sm_connection->connection)) {
        struct aws_http2_setting out_settings[AWS_HTTP2_SETTINGS_COUNT];
        aws_http2_connection_get_remote_settings(sm_connection->connection, out_settings);
        struct aws_http2_setting max_concurrent_stream_setting =
            out_settings[AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS - 1];
        /* The out_settings will have index equals to the id minus one */
        AWS_FATAL_ASSERT(max_concurrent_stream_setting.id == AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
        if (sm_connection->num_streams_open < max_concurrent_stream_setting.value) {
            return true;
        }
    } else {
        /* the connection is not allowed to make any new request, release it back to CM. */
        /* TODO: we are not moving the sm_connection out the list? */
        AWS_FATAL_ASSERT(aws_http_connection_manager_release_connection(
            stream_manager->connection_manager, sm_connection->connection));
        sm_connection->connection = NULL;
        /* For performance, we only remove the connection from the list as it's the last element */
        if (last_element) {
            aws_array_list_pop_back(&stream_manager->synced_data.connections_list);
        }
    }
    return false;
}

/* *_synced should only be called with LOCK HELD. Return AWS_OP_ERROR when it failed to pick a valid connection. */
static int s_pick_valid_connection_from_connections_list_synced(
    struct aws_http2_stream_manager *stream_manager,
    struct aws_h2_sm_connection *sm_connection) {
    size_t num_connections = aws_array_list_length(&stream_manager->synced_data.connections_list);
    /* use the best of two algorithm to select the connection with the lowest load. */
    uint64_t random_64_bit_num = 0;
    aws_device_random_u64(&random_64_bit_num);
    size_t random_num_a = random_64_bit_num % num_connections;
    aws_device_random_u64(&random_64_bit_num);
    size_t random_num_b = random_64_bit_num % num_connections;
    /* TODO... */
}

void aws_http2_stream_manager_acquire_stream(
    struct aws_http2_stream_manager *stream_manager,
    const struct aws_http_make_request_options *options,
    aws_http2_stream_manager_on_stream_acquired_fn *callback,
    void *user_data) {
    AWS_PRECONDITION(stream_manager);

    bool should_acquire_connection = false;
    struct aws_http_stream *new_stream = NULL;
    int error_code = AWS_ERROR_SUCCESS;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        size_t num_connections = aws_array_list_length(&stream_manager->synced_data.connections_list);
        if (num_connections == 0) {
            /* If there is no connection opening, we need to async acquiring a stream */
            s_async_acquire_stream_synced(stream_manager, options, callback, user_data, &should_acquire_connection);
            goto unlock;
        }

        struct aws_h2_sm_connection sm_connection;
        AWS_ZERO_STRUCT(sm_connection);
        if (s_pick_valid_connection_from_connections_list_synced(stream_manager, &sm_connection)) {
            /* No valid connection found, need to async acquiring a stream */
            s_async_acquire_stream_synced(stream_manager, options, callback, user_data, &should_acquire_connection);
            goto unlock;
        }
        /* get at only fails when index is invalid */
        /* TODO: COULD THIS BE DEAD LOCK?????? */
        /* MAYBE COPY THE SIMILAR LOGIC FROM CM */
        new_stream = aws_http_connection_make_request(sm_connection.connection, options);
        if (!new_stream) {
            error_code = aws_last_error();
        }

    unlock:
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    if (should_acquire_connection) {
        aws_http_connection_manager_acquire_connection(
            stream_manager->connection_manager, s_on_connection_acquired, stream_manager);
    }
    /* invoke callback synchronosly */
    if (new_stream) {
        callback(new_stream, error_code, user_data);
    } else if (error_code) {
        callback(new_stream, error_code, user_data);
    }
    return;
}
