#ifndef AWS_HTTP2_STREAM_MANAGER_IMPL_H
#define AWS_HTTP2_STREAM_MANAGER_IMPL_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/mutex.h>
#include <aws/common/ref_count.h>
#include <aws/http/http2_stream_manager.h>
#include <aws/http/private/random_access_set.h>

enum aws_h2_sm_state_type {
    AWS_H2SMST_READY,
    AWS_H2SMST_DESTROYING, /* On zero external ref count, can destroy */
};

/* Live with the streams opening, and if there no outstanding pending acquisition and no opening streams on the
 * connection, this structure should die */
struct aws_h2_sm_connection {
    struct aws_http2_stream_manager *stream_manager;
    struct aws_http_connection *connection;
    uint32_t num_streams_assigned;   /* From a stream assigned to the connection until the stream completed
                                                     or failed to be created from the connection. */
    uint32_t max_concurrent_streams; /* lower bound between user configured and the other side */
    bool full;
    bool sim_full;
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

struct aws_http2_stream_manager {
    struct aws_allocator *allocator;
    void *shutdown_complete_user_data;
    aws_http2_stream_manager_shutdown_complete_fn *shutdown_complete_callback;
    /**
     * Underlying connection manager. Always has the same life time with the stream manager who owns it.
     */
    struct aws_http_connection_manager *connection_manager;
    struct aws_ref_count ref_count;
    struct aws_client_bootstrap *bootstrap;

    size_t max_connections;

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
     * Task to invoke pending acquisition callbacks asynchronously if stream manager is shutting.
     */
    struct aws_event_loop *finish_pending_acquisitions_task_event_loop;

    /* Any thread may touch this data, but the lock must be held (unless it's an atomic) */
    struct {
        struct aws_mutex lock;
        /*
         * A manager can be in one of two states, READY or SHUTTING_DOWN.  The state transition
         * takes place when ref_count drops to zero.
         */
        enum aws_h2_sm_state_type state;

        /* A set of all connections that meet all requirement to use. Note: there will be connections not in this set,
         * but hold by the stream manager, which can be tracked by the streams created on it. Set of `struct
         * aws_h2_sm_connection *` */
        struct aws_random_access_set ideal_sm_connection_set;
        /* A set of all available connections that exceed the soft limits set by users. Note: there will be connections
         * not in this set, but hold by the stream manager, which can be tracked by the streams created. Set of `struct
         * aws_h2_sm_connection *` */
        struct aws_random_access_set soft_limited_sm_connection_set;

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
        size_t connections_acquiring_count;

        /**
         * The number of streams that opened and not completed yet.
         */
        size_t open_stream_count;

        /**
         * The number of streams that scheduled to be made from a connection yet.
         */
        size_t pending_make_requests_count;

        /**
         * The number of connections acquired from connection manager and not released yet.
         */
        size_t holding_connections_count;

        bool finish_pending_acquisitions_task_scheduled;
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
    size_t new_connections;
    struct aws_h2_sm_connection *sm_connection_to_release;
    struct aws_linked_list
        pending_make_requests; /* List of aws_h2_sm_pending_stream_acquisition with chosen connection */
    bool should_destroy_manager;
};

#endif /* AWS_HTTP2_STREAM_MANAGER_IMPL_H */