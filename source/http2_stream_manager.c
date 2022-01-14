/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#include <aws/common/array_list.h>
#include <aws/common/device_random.h>
#include <aws/common/hash_table.h>
#include <aws/common/logging.h>
#include <aws/common/mutex.h>
#include <aws/common/random_access_set.h>
#include <aws/common/ref_count.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/io/channel.h>

#include <aws/http/http2_stream_manager.h>

#include <inttypes.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

/* Apple toolchains such as xcode and swiftpm define the DEBUG symbol. undef it here so we can actually use the token */
#undef DEBUG

#define STREAM_MANAGER_LOGF(level, stream_manager, text, ...)                                                          \
    AWS_LOGF_##level(AWS_LS_HTTP2_STREAM_MANAGER, "id=%p: " text, (void *)(stream_manager), __VA_ARGS__)
#define STREAM_MANAGER_LOG(level, stream_manager, text) STREAM_MANAGER_LOGF(level, stream_manager, "%s", text)

/**
 * TODO: system vtable for unit test to mock
 */
struct aws_http2_stream_management_transaction;
static void s_stream_manager_start_destroy(struct aws_http2_stream_manager *stream_manager);
static void s_aws_http2_stream_manager_execute_transaction(struct aws_http2_stream_management_transaction *work);

enum aws_http2_stream_manager_state_type {
    AWS_H2SMST_UNINITIALIZED,
    AWS_H2SMST_READY,
    AWS_H2SMST_SHUTTING_DOWN,
};

/* Live with the streams opening, and if there no outstanding pending acquisition and no opening streams on the
 * connection, this structure should die */
struct aws_h2_sm_connection {
    struct aws_http2_stream_manager *stream_manager;
    struct aws_http_connection *connection;
    size_t num_streams_assigned;     /* From a stream assigned to the connection until the stream completed
                                                       or failed to be created from the connection. */
    uint32_t max_concurrent_streams; /* lower bound between user configured and the other side */
};

/* Live from the user request to acquire a stream to the stream completed. */
struct aws_h2_sm_pending_stream_acquisition {
    struct aws_allocator *allocator;
    struct aws_linked_list_node node;
    struct aws_http_make_request_options options;
    struct aws_h2_sm_connection *sm_connection; /* The connection to make request to. Keep
                                               NULL, until find available one and move it to the pending_make_requests
                                               list. */
    struct aws_http_message *request;
    struct aws_channel_task make_request_task;
    aws_http2_stream_manager_on_stream_acquired_fn *callback;
    void *user_data;
};

static struct aws_h2_sm_pending_stream_acquisition *s_new_pending_stream_acquisition(
    struct aws_allocator *allocator,
    const struct aws_http_make_request_options *options,
    aws_http2_stream_manager_on_stream_acquired_fn *callback,
    void *user_data) {
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_h2_sm_pending_stream_acquisition));

    /* Copy the options and keep the underlying message alive */
    pending_acquisition->options = *options;
    pending_acquisition->request = options->request;
    aws_http_message_acquire(pending_acquisition->request);
    pending_acquisition->callback = callback;
    pending_acquisition->user_data = user_data;
    pending_acquisition->allocator = allocator;
    return pending_acquisition;
}

static void s_pending_stream_acquisition_destroy(struct aws_h2_sm_pending_stream_acquisition *pending_acquisition) {
    if (pending_acquisition == NULL) {
        return;
    }
    if (pending_acquisition->request) {
        aws_http_message_release(pending_acquisition->request);
    }
    aws_mem_release(pending_acquisition->allocator, pending_acquisition);
    return;
}

/**
 * Main actions:
 * - Acquire stream from user
 *      - Check a connection to make stream
 *          - Check how many stream the connection made
 *          - Check the connection is still available? (Full or dead)
 *      - Or make a new connection
 *          - Acquiring a new connection and wait until CM to finish.
 * - Stream completed from HTTP
 *      - Update the connection of how many streams opening
 *      - Connection may be back to available.
 * - Connection acquired from CM
 *      - Finishes the pending stream acquiring on this connection as much as possible
 */

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
 *    (2) Don't invoke downstream connection manager and http calls that have callbacks while holding the internal state
 *          lock TODO: this requirement is in doubt, if we can make all the callbacks invoked asyned, we can remvoe
 *          this.
 *          - Channel shutdown will fire task synchronously
 *          - Connection manager will fire callback synchronously on failure
 *    (3) Only log unusual or rare events while the lock is held.  Common-path logging should be while it is not held.
 *    (4) Don't crash or do awful things (leaking resources is ok though) if the interface contract
 *          (ref counting) is violated by the user
 *
 *  In order to fulfill (1) and (2), all side-effecting operations within the stream manager follow a pattern:
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
 *
 * - Internal Connections Lifecycle:
 *    (1) Stream Manager doesn't really control the lifecycle of connections. This's more about when Stream Manager
 *          release holding it.
 *    (2) All streams opened from the connection dies, release holding it.
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
 *        - READY - streams may be acquired.  When the external ref count for the manager
 *          drops to zero, the manager moves to:
 *
 *        - SHUTTING_DOWN - streams may no longer be acquired, while in this state, we wait for a set of tracking
 *              counters to all fall to zero:
 *            - connection_acquiring_count - the # of unresolved calls to the connection manager layer
 *            - open_stream_count - the # of streams for whom the completed callback (from http) has not been invoked,
 *                  which also ensures no connection stream manager still holds.
 *
 *      In short: No connections acquiring, no streams alive. Underlying
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

    /**
     * Default is no limit. 0 will be considered as using the default value.
     * The ideal number of concurrent streams for a connection. Stream manager will try to create a new connection if
     * one connection reaches this number. But, if the max connections reaches, manager will reuse connections to create
     * the acquired steams as much as possible. */
    size_t ideal_concurrent_streams_per_connection;
    /**
     * Default is no limit. 0 will be considered as using the default value.
     * The real number of concurrent streams per connection will be controlled by the minmal value of the setting from
     * other end and the value here.
     */
    size_t max_concurrent_streams_per_connection;
    /**
     * Number of we tolarate the underlying connection acquiring failures
     */
    uint8_t num_connection_acquire_retries;

    /* Any thread may touch this data, but the lock must be held (unless it's an atomic) */
    struct {
        struct aws_mutex lock;
        /*
         * A manager can be in one of two states, READY or SHUTTING_DOWN.  The state transition
         * takes place when ref_count drops to zero.
         */
        enum aws_http2_stream_manager_state_type state;

        /* A set of all available connections to use. Note: there will be connections not in this set, but hold by the
         * stream manager, which can be tracked by the streams created */
        struct aws_random_access_set sm_connection_set;

        /**
         * The set of all incomplete stream acquisition requests (haven't decide what connection to make the request
         * to), list of `struct aws_h2_sm_pending_stream_acquisition*`
         */
        struct aws_linked_list pending_acquisitions;

        /**
         * The number of all incomplete stream acquisition requests (haven't decide what connection to make the request
         * to). So that we don't have compute the size of a linked list every time.
         */
        size_t pending_acquisition_count;

        /**
         * The number of new connections we acquiring from the connection manager.
         */
        size_t connections_acquiring;

        /**
         * The number of streams that opened and not completed yet.
         */
        size_t open_stream_count;

        /**
         * The number of streams that scheduled to be made from a connection yet.
         */
        size_t scheduled_stream_count;

        /**
         * Times the underlying connection acquire failures continuous.
         */
        uint8_t num_connection_acquire_fails;
    } synced_data;
};

/**
 * Encompasses all of the external operations that need to be done for various
 * events:
 *  - User level:
 *   stream manager release
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
    // struct aws_http_connection_manager_snapshot snapshot;
    size_t new_connections;
    struct aws_h2_sm_connection *sm_connection_to_release;
    struct aws_linked_list
        pending_make_requests; /* List of aws_h2_sm_pending_stream_acquisition with chosen connection */
    bool should_destroy_manager;
};

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

/* *_synced should only be called with LOCK HELD or from another synced function */
static bool s_aws_http2_stream_manager_should_destroy_synced(struct aws_http2_stream_manager *stream_manager) {
    if (stream_manager->synced_data.state != AWS_H2SMST_SHUTTING_DOWN) {
        return false;
    }

    if (stream_manager->synced_data.connections_acquiring > 0 || stream_manager->synced_data.open_stream_count > 0 ||
        stream_manager->synced_data.scheduled_stream_count > 0) {
        STREAM_MANAGER_LOGF(
            DEBUG,
            stream_manager,
            "Stream manager is shutting down but waiting for scheduled task and opened stream to finish. Status: "
            "connection acquiring=%zu, streams opening=%zu, stream scheduled=%zu",
            stream_manager->synced_data.connections_acquiring,
            stream_manager->synced_data.open_stream_count,
            stream_manager->synced_data.scheduled_stream_count);
        return false;
    }
    STREAM_MANAGER_LOG(TRACE, stream_manager, "Stream manager should start destroying process");

    /* If there is no outstanding streams, the connections list should be empty. */
    AWS_ASSERT(aws_random_access_set_get_size(&stream_manager->synced_data.sm_connection_set) == 0);

    return true;
}

static void s_aws_stream_management_transaction_init(
    struct aws_http2_stream_management_transaction *work,
    struct aws_http2_stream_manager *stream_manager) {
    AWS_ZERO_STRUCT(*work);

    aws_linked_list_init(&work->pending_make_requests);
    work->stream_manager = stream_manager;
    work->allocator = stream_manager->allocator;
}

static void s_aws_stream_management_transaction_clean_up(struct aws_http2_stream_management_transaction *work) {
    (void)work;
    AWS_ASSERT(aws_linked_list_empty(&work->pending_make_requests));
}

/* *_synced should only be called with LOCK HELD or from another synced function */
static void s_get_sm_connection_synced(
    struct aws_http2_stream_manager *stream_manager,
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition) {

    /**
     * TODO: Soft limits
     */
    if (aws_random_access_set_get_size(&stream_manager->synced_data.sm_connection_set)) {
        /* Use the best two algorithm */
        int re_code = AWS_ERROR_SUCCESS;
        struct aws_h2_sm_connection *sm_connection_a = NULL;
        re_code = aws_random_access_set_random_get_ptr(
            &stream_manager->synced_data.sm_connection_set, (void **)&sm_connection_a);
        struct aws_h2_sm_connection *sm_connection_b = NULL;
        re_code |= aws_random_access_set_random_get_ptr(
            &stream_manager->synced_data.sm_connection_set, (void **)&sm_connection_b);
        struct aws_h2_sm_connection *chosen_connection =
            sm_connection_a->num_streams_assigned > sm_connection_b->num_streams_assigned ? sm_connection_b
                                                                                          : sm_connection_a;

        pending_acquisition->sm_connection = chosen_connection;
        chosen_connection->num_streams_assigned++;

        STREAM_MANAGER_LOGF(
            TRACE,
            stream_manager,
            "Picking connection:%p for acquisition:%p. Streams assigned to the connection=%zu",
            (void *)chosen_connection->connection,
            (void *)pending_acquisition,
            chosen_connection->num_streams_assigned);

        if (chosen_connection->num_streams_assigned >= chosen_connection->max_concurrent_streams) {
            /* It becomes not available for new streams any more, remove it from the set, but still alive (streams
             * created will track the lifetime) */
            re_code |= aws_random_access_set_remove(&stream_manager->synced_data.sm_connection_set, chosen_connection);
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "connection %p reaches max concurrent streams limits. Streams assigned to the connection=%zu, "
                "while limits=%" PRIu32 ". Moving it out of available connections.",
                (void *)chosen_connection->connection,
                chosen_connection->num_streams_assigned,
                chosen_connection->max_concurrent_streams);
        }
        AWS_ASSERT(re_code == AWS_ERROR_SUCCESS && "random access set went wrong");
    }
    return;
}

/**
 * It can be invoked from:
 * - User release last refcount of stream manager
 * - User acquires stream from stream manager
 * - Connection acquired callback from connection manager
 * - Stream compeleted callback from HTTP
 */
/* *_synced should only be called with LOCK HELD or from another synced function */
static void s_aws_http2_stream_manager_build_transaction_synced(struct aws_http2_stream_management_transaction *work) {
    struct aws_http2_stream_manager *stream_manager = work->stream_manager;
    if (stream_manager->synced_data.state == AWS_H2SMST_READY) {

        /* Steps 1: Pending acquisitions of stream */
        while (!aws_linked_list_empty(&stream_manager->synced_data.pending_acquisitions)) {
            struct aws_linked_list_node *node =
                aws_linked_list_pop_back(&stream_manager->synced_data.pending_acquisitions);
            struct aws_h2_sm_pending_stream_acquisition *pending_acquisition =
                AWS_CONTAINER_OF(node, struct aws_h2_sm_pending_stream_acquisition, node);
            s_get_sm_connection_synced(stream_manager, pending_acquisition);
            if (pending_acquisition->sm_connection == NULL) {
                /* Cannot find any connection, push it back and break the loop */
                aws_linked_list_push_back(&stream_manager->synced_data.pending_acquisitions, node);
                STREAM_MANAGER_LOGF(
                    TRACE,
                    stream_manager,
                    "acquisition:%p cannot find any connection to use.",
                    (void *)pending_acquisition);
                break;
            } else {
                /* found connection for the request. Move it to pending make requests and update the count */
                aws_linked_list_push_back(&work->pending_make_requests, node);
                --stream_manager->synced_data.pending_acquisition_count; /* Length of the pending_acquisitions */
                ++stream_manager->synced_data.scheduled_stream_count;
            }
        }

        /* Step 2: Check for new connections needed */
        if (stream_manager->synced_data.pending_acquisition_count) {
            size_t num_connections_needed = stream_manager->synced_data.pending_acquisition_count / UINT32_MAX + 1;
            work->new_connections = num_connections_needed - stream_manager->synced_data.connections_acquiring;
            stream_manager->synced_data.connections_acquiring += work->new_connections;
            STREAM_MANAGER_LOGF(
                TRACE,
                stream_manager,
                "number of acquisition that waiting for connections to use=%zu. connection acquiring=%zu",
                stream_manager->synced_data.pending_acquisition_count,
                stream_manager->synced_data.connections_acquiring);
        }

    } else {
        STREAM_MANAGER_LOG(DEBUG, stream_manager, "Shutting down");
        /* Fail all the acquisitions */
        while (!aws_linked_list_empty(&stream_manager->synced_data.pending_acquisitions)) {
            /* TODO: how to invoke all those callbacks async? */
            struct aws_linked_list_node *node =
                aws_linked_list_pop_back(&stream_manager->synced_data.pending_acquisitions);
            struct aws_h2_sm_pending_stream_acquisition *pending_acquisition =
                AWS_CONTAINER_OF(node, struct aws_h2_sm_pending_stream_acquisition, node);
            /* Make sure no connection assigned. */
            AWS_ASSERT(pending_acquisition->sm_connection == NULL);
            if (pending_acquisition->callback) {
                pending_acquisition->callback(
                    NULL, AWS_ERROR_HTTP_STREAM_MANAGER_SHUTTING_DOWN, pending_acquisition->user_data);
            }
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "acquisition:%p failed due to stream manager shutting down",
                (void *)pending_acquisition);
            s_pending_stream_acquisition_destroy(pending_acquisition);
        }
        stream_manager->synced_data.pending_acquisition_count = 0;
        /* For the stream opening, we just waiting for them to complete. Once all the streams completed, stream manager
         * can die. */
        /* Step 3: Check should destroy the stream manager or not. */
        work->should_destroy_manager = s_aws_http2_stream_manager_should_destroy_synced(stream_manager);
    }
}

static struct aws_h2_sm_connection *s_sm_connection_new(
    struct aws_http2_stream_manager *stream_manager,
    struct aws_http_connection *connection) {
    struct aws_h2_sm_connection *sm_connection =
        aws_mem_calloc(stream_manager->allocator, 1, sizeof(struct aws_h2_sm_connection));
    sm_connection->max_concurrent_streams = stream_manager->max_concurrent_streams_per_connection;
    sm_connection->connection = connection;
    sm_connection->stream_manager = stream_manager;
    return sm_connection;
}

void s_sm_connection_destroy(struct aws_h2_sm_connection *sm_connection) {
    AWS_ASSERT(sm_connection->num_streams_assigned == 0);
    aws_http_connection_manager_release_connection(
        sm_connection->stream_manager->connection_manager, sm_connection->connection);
    aws_mem_release(sm_connection->stream_manager->allocator, sm_connection);
}

static void s_sm_on_connection_acquired(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct aws_http2_stream_manager *stream_manager = user_data;
    struct aws_http2_stream_management_transaction work;
    STREAM_MANAGER_LOGF(TRACE, stream_manager, "connection=%p acquired from connection manager", (void *)connection);
    s_aws_stream_management_transaction_init(&work, stream_manager);
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        --stream_manager->synced_data.connections_acquiring;
        if (error_code || !connection || aws_http_connection_get_version(connection) != AWS_HTTP_VERSION_2) {
            uint8_t connection_failed = ++stream_manager->synced_data.num_connection_acquire_fails;
            STREAM_MANAGER_LOGF(
                WARN,
                stream_manager,
                "connection acquired from connection manager failed, with error: %d(%s)",
                error_code,
                aws_error_str(error_code));
            if (connection_failed >= stream_manager->num_connection_acquire_retries) {
                /* Shutdown the stream manager. */
                STREAM_MANAGER_LOGF(
                    ERROR,
                    stream_manager,
                    "connection acquired from connection manager failed %" PRIu8
                    " times in a row. Shutting the stream manager",
                    connection_failed);
                stream_manager->synced_data.state = AWS_H2SMST_SHUTTING_DOWN;
            }
        } else if (stream_manager->synced_data.state == AWS_H2SMST_SHUTTING_DOWN) {
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "shutting down, release the connection=%p acquired immediately",
                (void *)connection);
            /* Release the acquired connection */
            aws_http_connection_manager_release_connection(stream_manager->connection_manager, connection);
        } else {
            stream_manager->synced_data.num_connection_acquire_fails = 0;
            struct aws_h2_sm_connection *sm_connection = s_sm_connection_new(stream_manager, connection);
            bool added = false;
            aws_random_access_set_add(&stream_manager->synced_data.sm_connection_set, sm_connection, &added);
        }
        s_aws_http2_stream_manager_build_transaction_synced(&work);
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    s_aws_http2_stream_manager_execute_transaction(&work);
}

static int s_on_incoming_headers(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition = user_data;
    if (pending_acquisition->options.on_response_headers) {
        return pending_acquisition->options.on_response_headers(
            stream, header_block, header_array, num_headers, pending_acquisition->options.user_data);
    }
    return AWS_OP_SUCCESS;
}

static int s_on_incoming_header_block_done(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition = user_data;
    if (pending_acquisition->options.on_response_header_block_done) {
        return pending_acquisition->options.on_response_header_block_done(
            stream, header_block, pending_acquisition->options.user_data);
    }
    return AWS_OP_SUCCESS;
}

static int s_on_incoming_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition = user_data;
    if (pending_acquisition->options.on_response_body) {
        return pending_acquisition->options.on_response_body(stream, data, pending_acquisition->options.user_data);
    }
    return AWS_OP_SUCCESS;
}

/**
 * Happens from an acquired stream failed or completed
 * - Decrease the count stream opening
 * - Check the connection can be released or not
 * - Update the max concurrent stream for a connection if needed
 * - Build and execute work
 */
static void s_stream_finishes_internal(
    struct aws_h2_sm_connection *sm_connection,
    struct aws_http2_stream_manager *stream_manager,
    int error_code) {
    /* Reach the max current will still allow new requests, but the new stream will complete with error */
    bool connection_available = aws_http_connection_new_requests_allowed(sm_connection->connection);
    uint32_t remote_max_con_streams = UINT32_MAX;
    if (error_code == AWS_ERROR_HTTP_MAX_CONCURRENT_STREAMS_EXCEEDED) {
        /* Max concurrent stream reached, we need to update the max for the sm_connection */
        struct aws_http2_setting out_settings[AWS_HTTP2_SETTINGS_COUNT];
        /* The setting id equals to the index plus one. */
        aws_http2_connection_get_remote_settings(sm_connection->connection, out_settings);
        remote_max_con_streams = out_settings[AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS - 1].value;
        STREAM_MANAGER_LOGF(
            DEBUG,
            stream_manager,
            "the current max stream limit:%" PRIu32
            " is larger than the setting from the other side. Update the concurrent stream "
            "limit of connection:%p, to limit from other side. which=%" PRIu32 "",
            sm_connection->max_concurrent_streams,
            sm_connection->connection,
            remote_max_con_streams);
    }
    struct aws_http2_stream_management_transaction work;
    int re_error = 0;
    s_aws_stream_management_transaction_init(&work, stream_manager);
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        --stream_manager->synced_data.open_stream_count;
        size_t current_stream_assigned = --sm_connection->num_streams_assigned;
        if (connection_available && (uint32_t)current_stream_assigned == sm_connection->max_concurrent_streams - 1) {
            /* this connection is back from full */
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "connection:%p back to available, assigned stream=%zu, max concurrent streams=%" PRIu32 "",
                sm_connection->connection,
                current_stream_assigned,
                sm_connection->max_concurrent_streams);
            bool added = false;
            re_error |=
                aws_random_access_set_add(&stream_manager->synced_data.sm_connection_set, sm_connection, &added);
            re_error |= !added;
        }
        uint32_t new_max = aws_min_u32(remote_max_con_streams, sm_connection->max_concurrent_streams);
        if (!connection_available || current_stream_assigned >= new_max) {
            /* It might be removed already, but, it's fine */
            re_error |= aws_random_access_set_remove(&stream_manager->synced_data.sm_connection_set, sm_connection);
        }
        sm_connection->max_concurrent_streams = new_max;
        s_aws_http2_stream_manager_build_transaction_synced(&work);
        /* After we build transaction, if the sm_connection still have zero assigned stream, we can kill the
         * sm_connection */
        if (sm_connection->num_streams_assigned == 0) {
            re_error |= aws_random_access_set_remove(&stream_manager->synced_data.sm_connection_set, sm_connection);
            work.sm_connection_to_release = sm_connection;
        }
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    AWS_ASSERT(re_error && "Stream completed failed with random access set failure");
    s_aws_http2_stream_manager_execute_transaction(&work);
}

static void s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition = user_data;
    struct aws_h2_sm_connection *sm_connection = pending_acquisition->sm_connection;
    struct aws_http2_stream_manager *stream_manager = sm_connection->stream_manager;
    /* Reach the max current will still allow new requests, but the new stream will complete with erro */
    if (pending_acquisition->options.on_complete) {
        pending_acquisition->options.on_complete(stream, error_code, pending_acquisition->options.user_data);
    }
    s_pending_stream_acquisition_destroy(pending_acquisition);
    s_stream_finishes_internal(sm_connection, stream_manager, error_code);
}

/* Scheduled to happen from connection's thread */
static void s_make_request_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition = arg;
    struct aws_h2_sm_connection *sm_connection = pending_acquisition->sm_connection;
    struct aws_http2_stream_manager *stream_manager = sm_connection->stream_manager;
    int error_code = AWS_ERROR_SUCCESS;

    STREAM_MANAGER_LOGF(
        TRACE,
        stream_manager,
        "Make request task running for acquisition:%p from connection:%p thread",
        pending_acquisition,
        sm_connection->connection);
    bool is_shutting_down = false;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        is_shutting_down = stream_manager->synced_data.state == AWS_H2SMST_SHUTTING_DOWN;
        --stream_manager->synced_data.scheduled_stream_count;
        ++stream_manager->synced_data.open_stream_count; /* The stream has not open yet, but we increase the count here,
                                                            if anything fails, the count will be decreased */
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    /* this is a channel task. If it is canceled, that means the channel shutdown. In that case, that's equivalent
     * to a closed connection. */
    if (status != AWS_TASK_STATUS_RUN_READY) {
        STREAM_MANAGER_LOGF(
            ERROR, stream_manager, "acquisition:%p failed as the task is cancelled.", pending_acquisition);
        error_code = AWS_ERROR_HTTP_CONNECTION_CLOSED;
        goto error;
    }
    if (is_shutting_down) {
        STREAM_MANAGER_LOGF(
            ERROR,
            stream_manager,
            "acquisition:%p failed as stream manager is shutting down before task runs.",
            pending_acquisition);
        error_code = AWS_ERROR_HTTP_STREAM_MANAGER_SHUTTING_DOWN;
        goto error;
    }
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = pending_acquisition->request,
        .on_response_headers = s_on_incoming_headers,
        .on_response_header_block_done = s_on_incoming_header_block_done,
        .on_response_body = s_on_incoming_body,
        .on_complete = s_on_stream_complete,
        .user_data = pending_acquisition,
    };
    struct aws_http_stream *stream = aws_http_connection_make_request(sm_connection->connection, &request_options);
    if (!stream) {
        error_code = aws_last_error();
        STREAM_MANAGER_LOGF(
            ERROR,
            stream_manager,
            "acquisition:%p failed as HTTP level make request failed with error: %d(%s).",
            pending_acquisition,
            error_code,
            aws_error_str(error_code));
        goto error;
    }
    if (pending_acquisition->callback) {
        /* TODO: If user activate the stream in the callback and the activate failed........... */
        pending_acquisition->callback(stream, error_code, pending_acquisition->user_data);
    }
    if (aws_http_stream_activate(stream)) {
        /* Activate failed, the on_completed callback will NOT be invoked from HTTP, but we already told user about the
         * stream. Invoke the user completed callback here */
        error_code = aws_last_error();
        STREAM_MANAGER_LOGF(
            ERROR,
            stream_manager,
            "acquisition:%p failed as stream activate failed with error: %d(%s).",
            pending_acquisition,
            error_code,
            aws_error_str(error_code));
        if (pending_acquisition->options.on_complete) {
            pending_acquisition->options.on_complete(stream, error_code, pending_acquisition->options.user_data);
            goto activate_failed;
        }
    }
    /* Happy case, the complete callback will be invoked, and we clean things up at the callback, but we can release the
     * request now */
    aws_http_message_release(pending_acquisition->request);
    pending_acquisition->request = NULL;
    return;
error:
    if (pending_acquisition->callback) {
        pending_acquisition->callback(NULL, error_code, pending_acquisition->user_data);
    }
activate_failed:
    s_pending_stream_acquisition_destroy(pending_acquisition);
    /* task should happen after destroy, as the task can trigger the whole stream manager to be destroyed */
    s_stream_finishes_internal(sm_connection, stream_manager, error_code);
}

/* NEVER invoke with lock held */
static void s_aws_http2_stream_manager_execute_transaction(struct aws_http2_stream_management_transaction *work) {

    struct aws_http2_stream_manager *stream_manager = work->stream_manager;
    bool should_destroy = work->should_destroy_manager;

    /* Step1: Release connection */
    if (work->sm_connection_to_release) {
        AWS_ASSERT(work->sm_connection_to_release->num_streams_assigned == 0);
        STREAM_MANAGER_LOGF(
            DEBUG,
            stream_manager,
            "Release connection:%p back to connection manager as no outstanding streams",
            work->sm_connection_to_release->connection);
        s_sm_connection_destroy(work->sm_connection_to_release);
    }

    /* Step2: Make request. The work should know what connection for the request to be made. */
    while (!aws_linked_list_empty(&work->pending_make_requests)) {
        /* The completions can also fail as the connection can be unavilable after the decision made. We just fail
         * the acquisition */
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&work->pending_make_requests);
        struct aws_h2_sm_pending_stream_acquisition *pending_acquisition =
            AWS_CONTAINER_OF(node, struct aws_h2_sm_pending_stream_acquisition, node);

        AWS_ASSERT(
            pending_acquisition->sm_connection &&
            "Stream manager internal bug: connection is not decided before execute transaction");

        STREAM_MANAGER_LOGF(
            TRACE,
            stream_manager,
            "acquisition:%p is scheduled to be made request from connection:%p thread",
            pending_acquisition,
            pending_acquisition->sm_connection->connection);
        /**
         * schedule a task from the connection's event loop to make request, so that:
         * - We can activate the stream for user and then invoked the callback
         * - The callback will happen asynced even the stream failed to be created
         * - We can make sure we will not break the settings
         */
        struct aws_channel *channel = aws_http_connection_get_channel(pending_acquisition->sm_connection->connection);
        aws_channel_task_init(
            &pending_acquisition->make_request_task,
            s_make_request_task,
            pending_acquisition,
            "Stream manager make request task");
        aws_channel_schedule_task_now(channel, &pending_acquisition->make_request_task);
    }

    /* Step 3: Acquire connections if needed */
    if (work->new_connections) {
        STREAM_MANAGER_LOGF(TRACE, stream_manager, "acquiring %zu new connections", work->new_connections);
    }
    for (size_t i = 0; i < work->new_connections; ++i) {
        aws_http_connection_manager_acquire_connection(
            stream_manager->connection_manager, s_sm_on_connection_acquired, stream_manager);
    }

    /*
     * Step 4: destroy the manager if necessary
     */
    if (should_destroy) {
        s_stream_manager_start_destroy(stream_manager);
    }

    /*
     * Step 5: Clean up work.  Do this here rather than at the end of every caller.
     */
    s_aws_stream_management_transaction_clean_up(work);
}

void s_stream_manager_destroy_final(struct aws_http2_stream_manager *stream_manager) {
    if (!stream_manager) {
        return;
    }

    STREAM_MANAGER_LOG(TRACE, stream_manager, "Stream Manager finishes destroying self");
    /* Connection manager has already been cleaned up */
    AWS_FATAL_ASSERT(stream_manager->connection_manager == NULL);
    AWS_FATAL_ASSERT(aws_linked_list_empty(&stream_manager->synced_data.pending_acquisitions));
    aws_mutex_clean_up(&stream_manager->synced_data.lock);
    aws_random_access_set_clean_up(&stream_manager->synced_data.sm_connection_set);

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
        "Underlying connection manager (ip=%p) finished shutdown, stream manager can finish destroying now",
        (void *)stream_manager->connection_manager);
    stream_manager->connection_manager = NULL;
    s_stream_manager_destroy_final(stream_manager);
}

static void s_stream_manager_start_destroy(struct aws_http2_stream_manager *stream_manager) {
    STREAM_MANAGER_LOG(TRACE, stream_manager, "Stream Manager reaches the condition to destroy, start to destroy");
    aws_http_connection_manager_release(stream_manager->connection_manager);
}

void s_stream_manager_on_zero_external_ref(struct aws_http2_stream_manager *stream_manager) {
    STREAM_MANAGER_LOG(
        TRACE,
        stream_manager,
        "Last refcount released, manager stop accpectin new stream request and will start to clean up when not "
        "outstanding tasks remaining.");
    struct aws_http2_stream_management_transaction work;
    s_aws_stream_management_transaction_init(&work, stream_manager);
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        stream_manager->synced_data.state = AWS_H2SMST_SHUTTING_DOWN;
        s_aws_http2_stream_manager_build_transaction_synced(&work);
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    s_aws_http2_stream_manager_execute_transaction(&work);
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
    if (aws_random_access_set_init(
            &stream_manager->synced_data.sm_connection_set,
            allocator,
            aws_hash_ptr,
            aws_ptr_eq,
            NULL /* destroy function */,
            2)) {
        goto on_error;
    }
    aws_ref_count_init(
        &stream_manager->ref_count,
        stream_manager,
        (aws_simple_completion_callback *)s_stream_manager_on_zero_external_ref);

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
    stream_manager->synced_data.state = AWS_H2SMST_READY;
    stream_manager->shutdown_complete_callback = options->shutdown_complete_callback;
    stream_manager->shutdown_complete_user_data = options->shutdown_complete_user_data;
    stream_manager->ideal_concurrent_streams_per_connection = options->ideal_concurrent_streams_per_connection;
    stream_manager->max_concurrent_streams_per_connection = options->max_concurrent_streams_per_connection;
    stream_manager->num_connection_acquire_retries = 3; /* TODO: Configurable? */

    aws_linked_list_init(&stream_manager->synced_data.pending_acquisitions);
    return stream_manager;
on_error:
    s_stream_manager_destroy_final(stream_manager);
    return NULL;
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
/**
 * User will want to have different failure that.
 * - We totally fucked up, we should build a new stream manager. Acquire callback failed
 * - It's just a connection dies (Goaway), stream manager should handle that by creating new connection, and I should
 * just acquire again. Stream completed with error.
 */
void aws_http2_stream_manager_acquire_stream(
    struct aws_http2_stream_manager *stream_manager,
    const struct aws_http2_stream_manager_acquire_stream_options *acquire_stream_option) {
    AWS_PRECONDITION(stream_manager);
    struct aws_http2_stream_management_transaction work;
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition = s_new_pending_stream_acquisition(
        stream_manager->allocator,
        acquire_stream_option->options,
        acquire_stream_option->callback,
        acquire_stream_option->user_data);
    STREAM_MANAGER_LOGF(TRACE, stream_manager, "Stream Manager creates acquisition:%p for user", pending_acquisition);
    s_aws_stream_management_transaction_init(&work, stream_manager);
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        aws_linked_list_push_back(&stream_manager->synced_data.pending_acquisitions, &pending_acquisition->node);
        stream_manager->synced_data.pending_acquisition_count++;

        s_aws_http2_stream_manager_build_transaction_synced(&work);
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    s_aws_http2_stream_manager_execute_transaction(&work);
    return;
}
