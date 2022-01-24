/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/device_random.h>
#include <aws/common/hash_table.h>
#include <aws/common/logging.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>

#include <aws/http/http2_stream_manager.h>
#include <aws/http/private/http2_stream_manager_impl.h>
#include <aws/http/private/request_response_impl.h>

#include <inttypes.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

/* Apple toolchains such as xcode and swiftpm define the DEBUG symbol. undef it here so we can actually use the token */
#undef DEBUG

#define STREAM_MANAGER_LOGF(level, stream_manager, text, ...)                                                          \
    AWS_LOGF_##level(AWS_LS_HTTP_STREAM_MANAGER, "id=%p: " text, (void *)(stream_manager), __VA_ARGS__)
#define STREAM_MANAGER_LOG(level, stream_manager, text) STREAM_MANAGER_LOGF(level, stream_manager, "%s", text)

static void s_stream_manager_start_destroy(struct aws_http2_stream_manager *stream_manager);
static void s_aws_http2_stream_manager_build_transaction_synced(struct aws_http2_stream_management_transaction *work);
static void s_aws_http2_stream_manager_execute_transaction(struct aws_http2_stream_management_transaction *work);

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
}

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
    if (stream_manager->synced_data.state != AWS_H2SMST_DESTROYING) {
        return false;
    }

    if (stream_manager->synced_data.connections_acquiring_count > 0 ||
        stream_manager->synced_data.open_stream_count > 0 ||
        stream_manager->synced_data.pending_make_requests_count > 0 ||
        stream_manager->synced_data.pending_acquisition_count) {
        STREAM_MANAGER_LOGF(
            DEBUG,
            stream_manager,
            "Stream manager is waiting to destroy but waiting for scheduled task and opened stream to finish. Status: "
            "connection acquiring=%zu, streams opening=%zu, stream scheduled=%zu, pending acquisition count=%zu",
            stream_manager->synced_data.connections_acquiring_count,
            stream_manager->synced_data.open_stream_count,
            stream_manager->synced_data.pending_make_requests_count,
            stream_manager->synced_data.pending_acquisition_count);
        return false;
    }

    STREAM_MANAGER_LOG(TRACE, stream_manager, "Stream manager should start destroying process");

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

static struct aws_h2_sm_connection *s_get_best_sm_connection_from_set(struct aws_random_access_set *set) {
    /* Use the best two algorithm */
    int errored = AWS_ERROR_SUCCESS;
    struct aws_h2_sm_connection *sm_connection_a = NULL;
    errored = aws_random_access_set_random_get_ptr(set, (void **)&sm_connection_a);
    struct aws_h2_sm_connection *sm_connection_b = NULL;
    errored |= aws_random_access_set_random_get_ptr(set, (void **)&sm_connection_b);
    struct aws_h2_sm_connection *chosen_connection =
        sm_connection_a->num_streams_assigned > sm_connection_b->num_streams_assigned ? sm_connection_b
                                                                                      : sm_connection_a;
    return errored == AWS_ERROR_SUCCESS ? chosen_connection : NULL;
}

/* *_synced should only be called with LOCK HELD or from another synced function */
static void s_get_sm_connection_synced(
    struct aws_http2_stream_manager *stream_manager,
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition) {

    int errored = 0;
    if (aws_random_access_set_get_size(&stream_manager->synced_data.sm_connection_set)) {
        struct aws_h2_sm_connection *chosen_connection =
            s_get_best_sm_connection_from_set(&stream_manager->synced_data.sm_connection_set);
        AWS_ASSERT(chosen_connection);
        pending_acquisition->sm_connection = chosen_connection;
        chosen_connection->num_streams_assigned++;

        STREAM_MANAGER_LOGF(
            TRACE,
            stream_manager,
            "Picking connection:%p for acquisition:%p. Streams assigned to the connection=%" PRIu32 "",
            (void *)chosen_connection->connection,
            (void *)pending_acquisition,
            chosen_connection->num_streams_assigned);

        if (chosen_connection->num_streams_assigned < chosen_connection->max_concurrent_streams &&
            chosen_connection->num_streams_assigned >= stream_manager->ideal_concurrent_streams_per_connection) {
            /* It meets the soft limit, but still available for new streams, move it to the soft limited set */
            errored |= aws_random_access_set_remove(&stream_manager->synced_data.sm_connection_set, chosen_connection);
            bool added = false;
            errored |= aws_random_access_set_add(
                &stream_manager->synced_data.soft_limited_sm_connection_set, chosen_connection, &added);
            errored |= !added;
            chosen_connection->sim_full = true;
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "connection:%p reaches ideal concurrent streams limits. Streams assigned to the connection=%" PRIu32 ""
                "while ideal limits=%zu. Moving it to soft limited set.",
                (void *)chosen_connection->connection,
                chosen_connection->num_streams_assigned,
                stream_manager->ideal_concurrent_streams_per_connection);
        } else if (chosen_connection->num_streams_assigned >= chosen_connection->max_concurrent_streams) {
            /* It becomes not available for new streams any more, remove it from the set, but still alive (streams
             * created will track the lifetime) */
            chosen_connection->sim_full = false;
            chosen_connection->full = true;
            errored |= aws_random_access_set_remove(&stream_manager->synced_data.sm_connection_set, chosen_connection);
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "connection:%p reaches max concurrent streams limits. Streams assigned to the connection=%" PRIu32 ""
                "while limits=%" PRIu32 ". Moving it out of available connections.",
                (void *)chosen_connection->connection,
                chosen_connection->num_streams_assigned,
                chosen_connection->max_concurrent_streams);
        }
    } else if (aws_random_access_set_get_size(&stream_manager->synced_data.soft_limited_sm_connection_set)) {
        struct aws_h2_sm_connection *chosen_connection =
            s_get_best_sm_connection_from_set(&stream_manager->synced_data.soft_limited_sm_connection_set);
        AWS_ASSERT(chosen_connection);
        pending_acquisition->sm_connection = chosen_connection;
        chosen_connection->num_streams_assigned++;

        STREAM_MANAGER_LOGF(
            TRACE,
            stream_manager,
            "Picking connection:%p for acquisition:%p. Streams assigned to the connection=%" PRIu32 "",
            (void *)chosen_connection->connection,
            (void *)pending_acquisition,
            chosen_connection->num_streams_assigned);

        if (chosen_connection->num_streams_assigned >= chosen_connection->max_concurrent_streams) {
            /* It becomes not available for new streams any more, remove it from the set, but still alive (streams
             * created will track the lifetime) */
            chosen_connection->sim_full = false;
            chosen_connection->full = true;
            errored |= aws_random_access_set_remove(
                &stream_manager->synced_data.soft_limited_sm_connection_set, chosen_connection);
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "connection %p reaches max concurrent streams limits. Streams assigned to the connection=%" PRIu32 ", "
                "while limits=%" PRIu32 ". Moving it out of available connections.",
                (void *)chosen_connection->connection,
                chosen_connection->num_streams_assigned,
                chosen_connection->max_concurrent_streams);
        }
    }
    AWS_ASSERT(errored == 0 && "random access set went wrong");
}

/* This is scheduled to run on a separate event loop to finish pending acquisition asynchronously */
static void s_finish_pending_acquisitions_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    struct aws_http2_stream_manager *stream_manager = arg;
    STREAM_MANAGER_LOG(TRACE, stream_manager, "Stream Manager final task runs");
    struct aws_http2_stream_management_transaction work;
    struct aws_linked_list pending_acquisitions;
    aws_linked_list_init(&pending_acquisitions);
    s_aws_stream_management_transaction_init(&work, stream_manager);
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        AWS_ASSERT(stream_manager->synced_data.state == AWS_H2SMST_DESTROYING);
        /* swap list to avoid callback with lock held. */
        aws_linked_list_swap_contents(&pending_acquisitions, &stream_manager->synced_data.pending_acquisitions);
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    while (!aws_linked_list_empty(&pending_acquisitions)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&pending_acquisitions);
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
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        /* After the callbacks invoked, now we can update the count */
        stream_manager->synced_data.pending_acquisition_count = 0;
        s_aws_http2_stream_manager_build_transaction_synced(&work);

        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    s_aws_http2_stream_manager_execute_transaction(&work);

    aws_mem_release(stream_manager->allocator, task);
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
                aws_linked_list_pop_front(&stream_manager->synced_data.pending_acquisitions);
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
                ++stream_manager->synced_data.pending_make_requests_count;
            }
        }

        /* Step 2: Check for new connections needed */
        if (stream_manager->synced_data.pending_acquisition_count) {
            /* TODO: a better algorithm to check how many connections to acquire, eg: use the ideal if any, else, use
             * 100 or something by default. */
            size_t num_connections_needed = stream_manager->synced_data.pending_acquisition_count / UINT32_MAX + 1;
            work->new_connections = num_connections_needed - stream_manager->synced_data.connections_acquiring_count;
            stream_manager->synced_data.connections_acquiring_count += work->new_connections;
            STREAM_MANAGER_LOGF(
                TRACE,
                stream_manager,
                "number of acquisition that waiting for connections to use=%zu. connection acquiring=%zu",
                stream_manager->synced_data.pending_acquisition_count,
                stream_manager->synced_data.connections_acquiring_count);
        }

    } else {
        /* Stream manager is shutting down */
        if (stream_manager->synced_data.pending_acquisition_count &&
            !stream_manager->synced_data.finish_pending_acquisitions_task_scheduled) {
            /* schedule a task to finish the pending acquisitions if there doesn't have one and needed */
            stream_manager->finish_pending_acquisitions_task_event_loop =
                aws_event_loop_group_get_next_loop(stream_manager->bootstrap->event_loop_group);
            struct aws_task *finish_pending_acquisitions_task =
                aws_mem_calloc(stream_manager->allocator, 1, sizeof(struct aws_task));
            aws_task_init(
                finish_pending_acquisitions_task,
                s_finish_pending_acquisitions_task,
                stream_manager,
                "sm_finish_pending_acquisitions");
            aws_event_loop_schedule_task_now(
                stream_manager->finish_pending_acquisitions_task_event_loop, finish_pending_acquisitions_task);
            stream_manager->synced_data.finish_pending_acquisitions_task_scheduled = true;
        }
        /* Step 3: Check should destroy the stream manager or not. */
        work->should_destroy_manager = s_aws_http2_stream_manager_should_destroy_synced(stream_manager);
    }
}

static struct aws_h2_sm_connection *s_sm_connection_new(
    struct aws_http2_stream_manager *stream_manager,
    struct aws_http_connection *connection) {
    struct aws_h2_sm_connection *sm_connection =
        aws_mem_calloc(stream_manager->allocator, 1, sizeof(struct aws_h2_sm_connection));
    sm_connection->max_concurrent_streams = (uint32_t)stream_manager->max_concurrent_streams_per_connection;
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
    int re_error = 0;
    s_aws_stream_management_transaction_init(&work, stream_manager);
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        --stream_manager->synced_data.connections_acquiring_count;
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
        } else if (stream_manager->synced_data.state != AWS_H2SMST_READY) {
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "shutting down, release the connection=%p acquired immediately",
                (void *)connection);
            /* Release the acquired connection */
            re_error |= aws_http_connection_manager_release_connection(stream_manager->connection_manager, connection);
        } else if (stream_manager->synced_data.pending_acquisition_count == 0) {
            STREAM_MANAGER_LOGF(
                DEBUG,
                stream_manager,
                "No pending acquisition, release the connection=%p acquired immediately",
                (void *)connection);
            /* Release the acquired connection */
            re_error |= aws_http_connection_manager_release_connection(stream_manager->connection_manager, connection);
        } else {
            stream_manager->synced_data.num_connection_acquire_fails = 0;
            struct aws_h2_sm_connection *sm_connection = s_sm_connection_new(stream_manager, connection);
            bool added = false;
            re_error |=
                aws_random_access_set_add(&stream_manager->synced_data.sm_connection_set, sm_connection, &added);
            re_error |= !added;
        }
        s_aws_http2_stream_manager_build_transaction_synced(&work);
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */

    AWS_ASSERT(!re_error && "connection acquired callback fails with programming errors");
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

/* Helper invoked when underlying connections is still aviable and the current stream count has been updated */
static int s_check_sm_connection_set_on_stream_finishes_synced(
    struct aws_h2_sm_connection *sm_connection,
    struct aws_http2_stream_manager *stream_manager) {
    int re_error = 0;
    size_t cur_num = sm_connection->num_streams_assigned;
    size_t ideal_num = stream_manager->ideal_concurrent_streams_per_connection;
    size_t max_num = sm_connection->max_concurrent_streams;
    if (sm_connection->sim_full && cur_num < ideal_num && ideal_num < max_num) {
        /* this connection is back from soft limited to all available */
        bool exist = false;
        (void)exist;
        /* I don't think there is case, the connection is not in the soft limited set at this point */
        AWS_ASSERT(
            aws_random_access_set_exist(
                &stream_manager->synced_data.soft_limited_sm_connection_set, sm_connection, &exist) &&
            exist);
        re_error |=
            aws_random_access_set_remove(&stream_manager->synced_data.soft_limited_sm_connection_set, sm_connection);
        bool added = false;
        re_error |= aws_random_access_set_add(&stream_manager->synced_data.sm_connection_set, sm_connection, &added);
        re_error |= !added;
        sm_connection->sim_full = false;
    }
    if (sm_connection->full && cur_num < max_num) {
        /* this connection is back from full */
        sm_connection->full = false;
        STREAM_MANAGER_LOGF(
            DEBUG,
            stream_manager,
            "connection:%p back to available, assigned stream=%zu, max concurrent streams=%" PRIu32 "",
            (void *)sm_connection->connection,
            cur_num,
            sm_connection->max_concurrent_streams);
        if (cur_num > ideal_num) {
            bool added = false;
            sm_connection->sim_full = true;
            re_error |= aws_random_access_set_add(
                &stream_manager->synced_data.soft_limited_sm_connection_set, sm_connection, &added);
            re_error |= !added;
        } else {
            bool added = false;
            re_error |=
                aws_random_access_set_add(&stream_manager->synced_data.sm_connection_set, sm_connection, &added);
            re_error |= !added;
        }
    }
    return re_error ? AWS_OP_ERR : AWS_OP_SUCCESS;
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
            (void *)sm_connection->connection,
            remote_max_con_streams);
    }
    struct aws_http2_stream_management_transaction work;
    int re_error = 0;
    s_aws_stream_management_transaction_init(&work, stream_manager);
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        --stream_manager->synced_data.open_stream_count;
        size_t current_stream_assigned = --sm_connection->num_streams_assigned;
        sm_connection->max_concurrent_streams =
            aws_min_u32(remote_max_con_streams, sm_connection->max_concurrent_streams);
        if (!connection_available || current_stream_assigned >= sm_connection->max_concurrent_streams) {
            /* It might be removed already, but, it's fine */
            re_error |= aws_random_access_set_remove(&stream_manager->synced_data.sm_connection_set, sm_connection);
            re_error |= aws_random_access_set_remove(
                &stream_manager->synced_data.soft_limited_sm_connection_set, sm_connection);
        } else {
            re_error |= s_check_sm_connection_set_on_stream_finishes_synced(sm_connection, stream_manager);
        }
        s_aws_http2_stream_manager_build_transaction_synced(&work);
        /* After we build transaction, if the sm_connection still have zero assigned stream, we can kill the
         * sm_connection */
        if (sm_connection->num_streams_assigned == 0) {
            re_error |= aws_random_access_set_remove(&stream_manager->synced_data.sm_connection_set, sm_connection);
            work.sm_connection_to_release = sm_connection;
        }
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    AWS_ASSERT(!re_error && "Stream completed failed with random access set failure");
    s_aws_http2_stream_manager_execute_transaction(&work);
}

static void s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition = user_data;
    struct aws_h2_sm_connection *sm_connection = pending_acquisition->sm_connection;
    struct aws_http2_stream_manager *stream_manager = sm_connection->stream_manager;
    /* TODO: Maybe hide some error code and create new error code for this. Let's say if the connection closed or goaway
     * received. The sm user may not be interesting in it */
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
        (void *)pending_acquisition,
        (void *)sm_connection->connection);
    bool is_shutting_down = false;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        is_shutting_down = stream_manager->synced_data.state != AWS_H2SMST_READY;
        --stream_manager->synced_data.pending_make_requests_count;
        ++stream_manager->synced_data.open_stream_count; /* The stream has not open yet, but we increase the count here,
                                                            if anything fails, the count will be decreased */
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    /* this is a channel task. If it is canceled, that means the channel shutdown. In that case, that's equivalent
     * to a closed connection. */
    if (status != AWS_TASK_STATUS_RUN_READY) {
        STREAM_MANAGER_LOGF(
            ERROR, stream_manager, "acquisition:%p failed as the task is cancelled.", (void *)pending_acquisition);
        error_code = AWS_ERROR_HTTP_CONNECTION_CLOSED;
        goto error;
    }
    if (is_shutting_down) {
        STREAM_MANAGER_LOGF(
            ERROR,
            stream_manager,
            "acquisition:%p failed as stream manager is shutting down before task runs.",
            (void *)pending_acquisition);
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
            (void *)pending_acquisition,
            error_code,
            aws_error_str(error_code));
        goto error;
    }
    /* Acquire stream to avoid the case stream is released before or during active */
    /* TODO: expose stream acquire??? */
    aws_atomic_fetch_add(&stream->refcount, 1);
    if (pending_acquisition->callback) {
        /* TODO: If user activate the stream in the callback and the activate failed........... */
        pending_acquisition->callback(stream, error_code, pending_acquisition->user_data);
    }
    /* It's possible that user released stream from callback, check the stream is still alive */
    if (aws_http_stream_activate(stream)) {
        /* Activate failed, the on_completed callback will NOT be invoked from HTTP, but we already told user about
         * the stream. Invoke the user completed callback here */
        error_code = aws_last_error();
        STREAM_MANAGER_LOGF(
            ERROR,
            stream_manager,
            "acquisition:%p failed as stream activate failed with error: %d(%s).",
            (void *)pending_acquisition,
            error_code,
            aws_error_str(error_code));
        if (pending_acquisition->options.on_complete) {
            pending_acquisition->options.on_complete(stream, error_code, pending_acquisition->options.user_data);
        }
        /* Release the stream as we keep it alive before */
        aws_http_stream_release(stream);
        goto after_cb_failed;
    }
    /* Release the stream as we keep it alive before */
    aws_http_stream_release(stream);
    /* Happy case, the complete callback will be invoked, and we clean things up at the callback, but we can release the
     * request now */
    aws_http_message_release(pending_acquisition->request);
    pending_acquisition->request = NULL;
    return;
error:
    if (pending_acquisition->callback) {
        pending_acquisition->callback(NULL, error_code, pending_acquisition->user_data);
    }
after_cb_failed:
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
            (void *)work->sm_connection_to_release->connection);
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
            (void *)pending_acquisition,
            (void *)pending_acquisition->sm_connection->connection);
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
    aws_random_access_set_clean_up(&stream_manager->synced_data.soft_limited_sm_connection_set);
    aws_client_bootstrap_release(stream_manager->bootstrap);

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
    /* If there is no outstanding streams, the connections set should be empty. */
    AWS_ASSERT(aws_random_access_set_get_size(&stream_manager->synced_data.sm_connection_set) == 0);
    AWS_ASSERT(aws_random_access_set_get_size(&stream_manager->synced_data.soft_limited_sm_connection_set) == 0);
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
        stream_manager->synced_data.state = AWS_H2SMST_DESTROYING;
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
    stream_manager->allocator = allocator;
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
    if (aws_random_access_set_init(
            &stream_manager->synced_data.soft_limited_sm_connection_set,
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
    stream_manager->bootstrap = aws_client_bootstrap_acquire(options->bootstrap);
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
    stream_manager->ideal_concurrent_streams_per_connection = options->ideal_concurrent_streams_per_connection
                                                                  ? options->ideal_concurrent_streams_per_connection
                                                                  : UINT32_MAX;
    stream_manager->max_concurrent_streams_per_connection =
        options->max_concurrent_streams_per_connection ? options->max_concurrent_streams_per_connection : UINT32_MAX;
    stream_manager->num_connection_acquire_retries = 3; /* TODO: Configurable? */

    aws_linked_list_init(&stream_manager->synced_data.pending_acquisitions);
    return stream_manager;
on_error:
    s_stream_manager_destroy_final(stream_manager);
    return NULL;
}

struct aws_http2_stream_manager *aws_http2_stream_manager_acquire(struct aws_http2_stream_manager *stream_manager) {
    if (stream_manager) {
        aws_ref_count_acquire(&stream_manager->ref_count);
    }
    return stream_manager;
}

struct aws_http2_stream_manager *aws_http2_stream_manager_release(struct aws_http2_stream_manager *stream_manager) {
    if (stream_manager) {
        aws_ref_count_release(&stream_manager->ref_count);
    }
    return NULL;
}

void aws_http2_stream_manager_acquire_stream(
    struct aws_http2_stream_manager *stream_manager,
    const struct aws_http2_stream_manager_acquire_stream_options *acquire_stream_option) {
    AWS_PRECONDITION(stream_manager);
    AWS_PRECONDITION(acquire_stream_option);
    AWS_PRECONDITION(acquire_stream_option->callback);
    AWS_PRECONDITION(acquire_stream_option->options);
    struct aws_http2_stream_management_transaction work;
    struct aws_h2_sm_pending_stream_acquisition *pending_acquisition = s_new_pending_stream_acquisition(
        stream_manager->allocator,
        acquire_stream_option->options,
        acquire_stream_option->callback,
        acquire_stream_option->user_data);
    STREAM_MANAGER_LOGF(
        TRACE, stream_manager, "Stream Manager creates acquisition:%p for user", (void *)pending_acquisition);
    s_aws_stream_management_transaction_init(&work, stream_manager);
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream_manager);
        /* it's use after free crime */
        AWS_FATAL_ASSERT(stream_manager->synced_data.state != AWS_H2SMST_DESTROYING);
        aws_linked_list_push_back(&stream_manager->synced_data.pending_acquisitions, &pending_acquisition->node);
        stream_manager->synced_data.pending_acquisition_count++;

        s_aws_http2_stream_manager_build_transaction_synced(&work);
        s_unlock_synced_data(stream_manager);
    } /* END CRITICAL SECTION */
    s_aws_http2_stream_manager_execute_transaction(&work);
}
