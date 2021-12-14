/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

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
static bool s_check_connection_available_synced(struct aws_h2_sm_connection *sm_connection) {
    if (aws_http_connection_new_requests_allowed(sm_connection)) {
        struct aws_http2_setting out_settings[AWS_HTTP2_SETTINGS_COUNT];
        aws_http2_connection_get_remote_settings(sm_connection->connection, out_settings);
        struct aws_http2_setting max_concurrent_stream_setting =
            out_settings[AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS - 1];
        /* The out_settings will have index equals to the id minus one */
        AWS_FATAL_ASSERT(max_concurrent_stream_setting.id == AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
        if (sm_connection->num_streams_open < max_concurrent_stream_setting.value) {
            return true;
        }
    }
    return false;
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
        if (aws_array_list_length(&stream_manager->synced_data.connections_list) == 0) {
            /* If there is no connection opening, we need to async acquiring a stream */
            s_async_acquire_stream_synced(stream_manager, options, callback, user_data, &should_acquire_connection);
            goto unlock;
        }
        if (aws_array_list_length(&stream_manager->synced_data.connections_list) == 1) {
            struct aws_h2_sm_connection sm_connection;
            /* get at only fails when index is invalid */
            AWS_FATAL_ASSERT(
                aws_array_list_get_at(&stream_manager->synced_data.connections_list, &sm_connection, 0) &&
                "Failed to fetch connection from stream manager connections_list");
            if (s_check_connection_available_synced(&sm_connection)) {
                new_stream = aws_http_connection_make_request(sm_connection.connection, options);
                if (!new_stream) {
                    error_code = aws_last_error();
                }
                goto unlock;
            }
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
