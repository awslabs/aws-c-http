/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/h2_stream.h>

#include <aws/http/private/h2_connection.h>
#include <aws/http/private/strutil.h>
#include <aws/http/status_code.h>
#include <aws/io/channel.h>
#include <aws/io/logging.h>

/* Apple toolchains such as xcode and swiftpm define the DEBUG symbol. undef it here so we can actually use the token */
#undef DEBUG

static void s_stream_destroy(struct aws_http_stream *stream_base);
static void s_stream_update_window(struct aws_http_stream *stream_base, size_t increment_size);
static int s_stream_reset_stream(struct aws_http_stream *stream_base, uint32_t http2_error);
static int s_stream_get_received_error_code(struct aws_http_stream *stream_base, uint32_t *out_http2_error);
static int s_stream_get_sent_error_code(struct aws_http_stream *stream_base, uint32_t *out_http2_error);

static void s_stream_cross_thread_work_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);
static struct aws_h2err s_send_rst_and_close_stream(struct aws_h2_stream *stream, struct aws_h2err stream_error);

struct aws_http_stream_vtable s_h2_stream_vtable = {
    .destroy = s_stream_destroy,
    .update_window = s_stream_update_window,
    .activate = aws_h2_stream_activate,
    .http1_write_chunk = NULL,
    .http2_reset_stream = s_stream_reset_stream,
    .http2_get_received_error_code = s_stream_get_received_error_code,
    .http2_get_sent_error_code = s_stream_get_sent_error_code,
};

const char *aws_h2_stream_state_to_str(enum aws_h2_stream_state state) {
    switch (state) {
        case AWS_H2_STREAM_STATE_IDLE:
            return "IDLE";
        case AWS_H2_STREAM_STATE_RESERVED_LOCAL:
            return "RESERVED_LOCAL";
        case AWS_H2_STREAM_STATE_RESERVED_REMOTE:
            return "RESERVED_REMOTE";
        case AWS_H2_STREAM_STATE_OPEN:
            return "OPEN";
        case AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL:
            return "HALF_CLOSED_LOCAL";
        case AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE:
            return "HALF_CLOSED_REMOTE";
        case AWS_H2_STREAM_STATE_CLOSED:
            return "CLOSED";
        default:
            /* unreachable */
            AWS_ASSERT(0);
            return "*** UNKNOWN ***";
    }
}

static struct aws_h2_connection *s_get_h2_connection(const struct aws_h2_stream *stream) {
    return AWS_CONTAINER_OF(stream->base.owning_connection, struct aws_h2_connection, base);
}

static void s_lock_synced_data(struct aws_h2_stream *stream) {
    int err = aws_mutex_lock(&stream->synced_data.lock);
    AWS_ASSERT(!err && "lock failed");
    (void)err;
}

static void s_unlock_synced_data(struct aws_h2_stream *stream) {
    int err = aws_mutex_unlock(&stream->synced_data.lock);
    AWS_ASSERT(!err && "unlock failed");
    (void)err;
}

#define AWS_PRECONDITION_ON_CHANNEL_THREAD(STREAM)                                                                     \
    AWS_PRECONDITION(aws_channel_thread_is_callers_thread(s_get_h2_connection(STREAM)->base.channel_slot->channel))

static bool s_client_state_allows_frame_type[AWS_H2_STREAM_STATE_COUNT][AWS_H2_FRAME_TYPE_COUNT] = {
    /* State before anything is sent or received */
    [AWS_H2_STREAM_STATE_IDLE] = {0},
    /* Client streams are never in reserved (local) state */
    [AWS_H2_STREAM_STATE_RESERVED_LOCAL] = {0},
    /* Client received push-request via PUSH_PROMISE on another stream.
     * Waiting for push-response to start arriving on this server-initiated stream. */
    [AWS_H2_STREAM_STATE_RESERVED_REMOTE] =
        {
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
        },
    /* Client is sending request and has not received full response yet. */
    [AWS_H2_STREAM_STATE_OPEN] =
        {
            [AWS_H2_FRAME_T_DATA] = true,
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_PUSH_PROMISE] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Client has sent full request (END_STREAM), but has not received full response yet. */
    [AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL] =
        {
            [AWS_H2_FRAME_T_DATA] = true,
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_PUSH_PROMISE] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Client has received full response (END_STREAM), but is still sending request (uncommon). */
    [AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE] =
        {
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Full request sent (END_STREAM) and full response received (END_STREAM).
     * OR sent RST_STREAM. OR received RST_STREAM. */
    [AWS_H2_STREAM_STATE_CLOSED] = {0},
};

static bool s_server_state_allows_frame_type[AWS_H2_STREAM_STATE_COUNT][AWS_H2_FRAME_TYPE_COUNT] = {
    /* State before anything is sent or received, waiting for request headers to arrives and start things off */
    [AWS_H2_STREAM_STATE_IDLE] =
        {
            [AWS_H2_FRAME_T_HEADERS] = true,
        },
    /* Server sent push-request via PUSH_PROMISE on a client-initiated stream,
     * but hasn't started sending the push-response on this server-initiated stream yet. */
    [AWS_H2_STREAM_STATE_RESERVED_LOCAL] =
        {
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Server streams are never in reserved (remote) state */
    [AWS_H2_STREAM_STATE_RESERVED_REMOTE] = {0},
    /* Server is receiving request, and has sent full response yet. */
    [AWS_H2_STREAM_STATE_OPEN] =
        {
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_DATA] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Server has sent full response (END_STREAM), but has not received full response yet (uncommon). */
    [AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL] =
        {
            [AWS_H2_FRAME_T_HEADERS] = true,
            [AWS_H2_FRAME_T_DATA] = true,
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Server has received full request (END_STREAM), and is still sending response. */
    [AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE] =
        {
            [AWS_H2_FRAME_T_RST_STREAM] = true,
            [AWS_H2_FRAME_T_WINDOW_UPDATE] = true,
        },
    /* Full request received (END_STREAM) and full response sent (END_STREAM).
     * OR sent RST_STREAM. OR received RST_STREAM. */
    [AWS_H2_STREAM_STATE_CLOSED] = {0},
};

/* Returns the appropriate Stream Error if given frame not allowed in current state */
static struct aws_h2err s_check_state_allows_frame_type(
    const struct aws_h2_stream *stream,
    enum aws_h2_frame_type frame_type) {

    AWS_PRECONDITION(frame_type < AWS_H2_FRAME_T_UNKNOWN); /* Decoder won't invoke callbacks for unknown frame types */
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    const enum aws_h2_stream_state state = stream->thread_data.state;

    bool allowed;
    if (stream->base.server_data) {
        allowed = s_server_state_allows_frame_type[state][frame_type];
    } else {
        allowed = s_client_state_allows_frame_type[state][frame_type];
    }

    if (allowed) {
        return AWS_H2ERR_SUCCESS;
    }

    /* Determine specific error code */
    enum aws_http2_error_code h2_error_code = AWS_HTTP2_ERR_PROTOCOL_ERROR;

    /* If peer knows the state is closed, then it's a STREAM_CLOSED error */
    if (state == AWS_H2_STREAM_STATE_CLOSED || state == AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        h2_error_code = AWS_HTTP2_ERR_STREAM_CLOSED;
    }

    AWS_H2_STREAM_LOGF(
        ERROR,
        stream,
        "Malformed message, cannot receive %s frame in %s state",
        aws_h2_frame_type_to_str(frame_type),
        aws_h2_stream_state_to_str(state));

    return aws_h2err_from_h2_code(h2_error_code);
}

static int s_stream_send_update_window_frame(struct aws_h2_stream *stream, size_t increment_size) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);
    AWS_PRECONDITION(increment_size <= AWS_H2_WINDOW_UPDATE_MAX);

    struct aws_h2_connection *connection = s_get_h2_connection(stream);
    struct aws_h2_frame *stream_window_update_frame =
        aws_h2_frame_new_window_update(stream->base.alloc, stream->base.id, (uint32_t)increment_size);

    if (!stream_window_update_frame) {
        AWS_H2_STREAM_LOGF(
            ERROR,
            stream,
            "Failed to create WINDOW_UPDATE frame on connection, error %s",
            aws_error_name(aws_last_error()));
        return AWS_OP_ERR;
    }
    aws_h2_connection_enqueue_outgoing_frame(connection, stream_window_update_frame);

    return AWS_OP_SUCCESS;
}

struct aws_h2_stream *aws_h2_stream_new_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {
    AWS_PRECONDITION(client_connection);
    AWS_PRECONDITION(options);

    struct aws_h2_stream *stream = aws_mem_calloc(client_connection->alloc, 1, sizeof(struct aws_h2_stream));
    if (!stream) {
        return NULL;
    }

    /* Initialize base stream */
    stream->base.vtable = &s_h2_stream_vtable;
    stream->base.alloc = client_connection->alloc;
    stream->base.owning_connection = client_connection;
    stream->base.user_data = options->user_data;
    stream->base.on_incoming_headers = options->on_response_headers;
    stream->base.on_incoming_header_block_done = options->on_response_header_block_done;
    stream->base.on_incoming_body = options->on_response_body;
    stream->base.on_complete = options->on_complete;
    stream->base.client_data = &stream->base.client_or_server_data.client;
    stream->base.client_data->response_status = AWS_HTTP_STATUS_CODE_UNKNOWN;

    /* Stream refcount starts at 1, and gets incremented again for the connection upon a call to activate() */
    aws_atomic_init_int(&stream->base.refcount, 1);

    /* Init H2 specific stuff */
    stream->thread_data.state = AWS_H2_STREAM_STATE_IDLE;
    stream->thread_data.outgoing_message = options->request;

    stream->sent_reset_error_code = -1;
    stream->received_reset_error_code = -1;

    stream->synced_data.user_reset_error_code = AWS_HTTP2_ERR_COUNT;
    stream->synced_data.api_state = AWS_H2_STREAM_API_STATE_INIT;
    if (aws_mutex_init(&stream->synced_data.lock)) {
        AWS_H2_STREAM_LOGF(
            ERROR, stream, "Mutex init error %d (%s).", aws_last_error(), aws_error_name(aws_last_error()));
        aws_mem_release(stream->base.alloc, stream);
        return NULL;
    }
    aws_http_message_acquire(stream->thread_data.outgoing_message);
    aws_channel_task_init(
        &stream->cross_thread_work_task, s_stream_cross_thread_work_task, stream, "HTTP/2 stream cross-thread work");
    return stream;
}

static void s_stream_cross_thread_work_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_h2_stream *stream = arg;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto end;
    }

    struct aws_h2_connection *connection = s_get_h2_connection(stream);

    if (aws_h2_stream_get_state(stream) == AWS_H2_STREAM_STATE_CLOSED) {
        /* stream is closed, silently ignoring the requests from user */
        AWS_H2_STREAM_LOG(
            TRACE, stream, "Stream closed before cross thread work task runs, ignoring everything was sent by user.");
        goto end;
    }

    /* Not sending window update at half closed remote state */
    bool ignore_window_update = (aws_h2_stream_get_state(stream) == AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE);
    bool reset_called;
    size_t window_update_size;
    uint32_t user_reset_error_code;

    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream);
        stream->synced_data.is_cross_thread_work_task_scheduled = false;

        /* window_update_size is ensured to be not greater than AWS_H2_WINDOW_UPDATE_MAX */
        window_update_size = stream->synced_data.window_update_size;
        stream->synced_data.window_update_size = 0;
        reset_called = stream->synced_data.reset_called;
        user_reset_error_code = stream->synced_data.user_reset_error_code;

        s_unlock_synced_data(stream);
    } /* END CRITICAL SECTION */

    if (window_update_size > 0 && !ignore_window_update) {
        if (s_stream_send_update_window_frame(stream, window_update_size)) {
            /* Treat this as a connection error */
            aws_h2_connection_shutdown_due_to_write_err(connection, aws_last_error());
        }
    }

    /* The largest legal value will be 2 * max window size, which is way less than INT64_MAX, so if the window_size_self
     * overflows, remote peer will find it out. So just apply the change and ignore the possible overflow.*/
    stream->thread_data.window_size_self += window_update_size;

    if (reset_called) {
        struct aws_h2err h2err;
        h2err.h2_code = user_reset_error_code;
        if (stream->base.server_data && stream->thread_data.state == AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL) {
            /* (RFC-7540 8.1) A server MAY request that the client abort transmission of a request without error by
             * sending a RST_STREAM with an error code of NO_ERROR after sending a complete response */
            h2err.aws_code = AWS_ERROR_SUCCESS;
        } else {
            h2err.aws_code = AWS_ERROR_HTTP_RST_STREAM_SENT;
        }
        struct aws_h2err returned_h2err = s_send_rst_and_close_stream(stream, h2err);
        if (aws_h2err_failed(returned_h2err)) {
            aws_h2_connection_shutdown_due_to_write_err(connection, returned_h2err.aws_code);
        }
    }

    /* It's likely that frames were queued while processing cross-thread work.
     * If so, try writing them now */
    aws_h2_try_write_outgoing_frames(connection);

end:
    aws_http_stream_release(&stream->base);
}

static void s_stream_destroy(struct aws_http_stream *stream_base) {
    AWS_PRECONDITION(stream_base);
    struct aws_h2_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h2_stream, base);

    AWS_H2_STREAM_LOG(DEBUG, stream, "Destroying stream");
    aws_mutex_clean_up(&stream->synced_data.lock);
    aws_http_message_release(stream->thread_data.outgoing_message);

    aws_mem_release(stream->base.alloc, stream);
}

static void s_stream_update_window(struct aws_http_stream *stream_base, size_t increment_size) {
    AWS_PRECONDITION(stream_base);
    struct aws_h2_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h2_stream, base);
    struct aws_h2_connection *connection = s_get_h2_connection(stream);
    if (!increment_size) {
        return;
    }
    if (!connection->base.manual_window_management) {
        /* auto-mode, manual update window is not supported */
        AWS_H2_STREAM_LOG(WARN, stream, "Manual window management is off, update window operations are not supported.");
        return;
    }

    int err = 0;
    bool stream_is_init;
    bool cross_thread_work_should_schedule = false;
    size_t sum_size;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream);

        err |= aws_add_size_checked(stream->synced_data.window_update_size, increment_size, &sum_size);
        err |= sum_size > AWS_H2_WINDOW_UPDATE_MAX;
        stream_is_init = stream->synced_data.api_state == AWS_H2_STREAM_API_STATE_INIT;

        if (!err && !stream_is_init) {
            cross_thread_work_should_schedule = !stream->synced_data.is_cross_thread_work_task_scheduled;
            stream->synced_data.is_cross_thread_work_task_scheduled = true;
            stream->synced_data.window_update_size = sum_size;
        }
        s_unlock_synced_data(stream);
    } /* END CRITICAL SECTION */

    if (cross_thread_work_should_schedule) {
        AWS_H2_STREAM_LOG(TRACE, stream, "Scheduling stream cross-thread work task");
        /* increment the refcount of stream to keep it alive until the task runs */
        aws_atomic_fetch_add(&stream->base.refcount, 1);
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &stream->cross_thread_work_task);
        return;
    }

    if (stream_is_init) {
        AWS_H2_STREAM_LOG(
            ERROR,
            stream,
            "Stream update window failed. Stream is in initialized state, please activate the stream first.");
        aws_raise_error(AWS_ERROR_INVALID_STATE);
        return;
    }

    if (err) {
        /* The increment_size is still not 100% safe, since we cannot control the incoming data frame. So just
         * ruled out the value that is obviously wrong values */
        AWS_H2_STREAM_LOGF(
            ERROR,
            stream,
            "The increment size is too big for HTTP/2 protocol, max flow-control "
            "window size is 2147483647. We got %zu, which will cause the flow-control window to exceed the maximum",
            increment_size);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return;
    }
}

static int s_stream_reset_stream(struct aws_http_stream *stream_base, uint32_t http2_error) {

    struct aws_h2_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h2_stream, base);
    struct aws_h2_connection *connection = s_get_h2_connection(stream);
    bool reset_called;
    bool stream_is_init;
    bool cross_thread_work_should_schedule = false;

    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream);

        reset_called = stream->synced_data.reset_called;
        stream_is_init = stream->synced_data.api_state == AWS_H2_STREAM_API_STATE_INIT;
        if (!reset_called && !stream_is_init) {
            cross_thread_work_should_schedule = !stream->synced_data.is_cross_thread_work_task_scheduled;
            stream->synced_data.reset_called = true;
            stream->synced_data.user_reset_error_code = http2_error;
        }
        s_unlock_synced_data(stream);
    } /* END CRITICAL SECTION */

    if (cross_thread_work_should_schedule) {
        AWS_H2_STREAM_LOG(TRACE, stream, "Scheduling stream cross-thread work task");
        /* increment the refcount of stream to keep it alive until the task runs */
        aws_atomic_fetch_add(&stream->base.refcount, 1);
        aws_channel_schedule_task_now(connection->base.channel_slot->channel, &stream->cross_thread_work_task);
        return AWS_OP_SUCCESS;
    }

    if (stream_is_init) {
        AWS_H2_STREAM_LOG(
            ERROR, stream, "Reset stream failed. Stream is in initialized state, please activate the stream first.");
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    if (reset_called) {
        AWS_H2_STREAM_LOG(DEBUG, stream, "Reset stream ignored. Reset stream has been called already.");
    }

    return AWS_OP_SUCCESS;
}

static int s_stream_get_received_error_code(struct aws_http_stream *stream_base, uint32_t *out_http2_error) {
    struct aws_h2_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h2_stream, base);
    if (stream->received_reset_error_code == -1) {
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }
    *out_http2_error = (uint32_t)stream->received_reset_error_code;
    return AWS_OP_SUCCESS;
}

static int s_stream_get_sent_error_code(struct aws_http_stream *stream_base, uint32_t *out_http2_error) {
    struct aws_h2_stream *stream = AWS_CONTAINER_OF(stream_base, struct aws_h2_stream, base);
    if (stream->sent_reset_error_code == -1) {
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }
    *out_http2_error = (uint32_t)stream->sent_reset_error_code;
    return AWS_OP_SUCCESS;
}

enum aws_h2_stream_state aws_h2_stream_get_state(const struct aws_h2_stream *stream) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);
    return stream->thread_data.state;
}

/* Given a Stream Error, send RST_STREAM frame and close stream.
 * A Connection Error is returned if something goes catastrophically wrong */
static struct aws_h2err s_send_rst_and_close_stream(struct aws_h2_stream *stream, struct aws_h2err stream_error) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);
    AWS_PRECONDITION(stream->thread_data.state != AWS_H2_STREAM_STATE_CLOSED);

    struct aws_h2_connection *connection = s_get_h2_connection(stream);

    stream->thread_data.state = AWS_H2_STREAM_STATE_CLOSED;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream);
        stream->synced_data.api_state = AWS_H2_STREAM_API_STATE_COMPLETE;
        s_unlock_synced_data(stream);
    } /* END CRITICAL SECTION */
    AWS_H2_STREAM_LOGF(
        DEBUG,
        stream,
        "Sending RST_STREAM with error code %s (0x%x). State -> CLOSED",
        aws_http2_error_code_to_str(stream_error.h2_code),
        stream_error.h2_code);

    /* Send RST_STREAM */
    struct aws_h2_frame *rst_stream_frame =
        aws_h2_frame_new_rst_stream(stream->base.alloc, stream->base.id, stream_error.h2_code);
    if (!rst_stream_frame) {
        AWS_H2_STREAM_LOGF(ERROR, stream, "Error creating RST_STREAM frame, %s", aws_error_name(aws_last_error()));
        return aws_h2err_from_last_error();
    }
    aws_h2_connection_enqueue_outgoing_frame(connection, rst_stream_frame); /* connection takes ownership of frame */
    stream->sent_reset_error_code = stream_error.h2_code;

    /* Tell connection that stream is now closed */
    if (aws_h2_connection_on_stream_closed(
            connection, stream, AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_SENT, stream_error.aws_code)) {
        return aws_h2err_from_last_error();
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err aws_h2_stream_window_size_change(struct aws_h2_stream *stream, int32_t size_changed, bool self) {
    if (self) {
        if (stream->thread_data.window_size_self + size_changed > AWS_H2_WINDOW_UPDATE_MAX) {
            return aws_h2err_from_h2_code(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR);
        }
        stream->thread_data.window_size_self += size_changed;
    } else {
        if ((int64_t)stream->thread_data.window_size_peer + size_changed > AWS_H2_WINDOW_UPDATE_MAX) {
            return aws_h2err_from_h2_code(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR);
        }
        stream->thread_data.window_size_peer += size_changed;
    }
    return AWS_H2ERR_SUCCESS;
}

int aws_h2_stream_on_activated(struct aws_h2_stream *stream, bool *out_has_outgoing_data) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    struct aws_h2_connection *connection = s_get_h2_connection(stream);

    /* Create HEADERS frame */
    struct aws_http_message *msg = stream->thread_data.outgoing_message;
    bool has_body_stream = aws_http_message_get_body_stream(msg) != NULL;
    struct aws_http_headers *h2_headers = aws_h2_create_headers_from_request(msg, stream->base.alloc);
    if (!h2_headers) {
        AWS_H2_STREAM_LOGF(
            ERROR, stream, "Failed to create HTTP/2 style headers from request %s", aws_error_name(aws_last_error()));
        goto error;
    }
    struct aws_h2_frame *headers_frame = aws_h2_frame_new_headers(
        stream->base.alloc,
        stream->base.id,
        h2_headers,
        !has_body_stream /* end_stream */,
        0 /* padding - not currently configurable via public API */,
        NULL /* priority - not currently configurable via public API */);

    /* Release refcount of h2_headers here, let frame take the full ownership of it */
    aws_http_headers_release(h2_headers);
    if (!headers_frame) {
        AWS_H2_STREAM_LOGF(ERROR, stream, "Failed to create HEADERS frame: %s", aws_error_name(aws_last_error()));
        goto error;
    }

    /* Initialize the flow-control window size */
    stream->thread_data.window_size_peer =
        connection->thread_data.settings_peer[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE];
    stream->thread_data.window_size_self =
        connection->thread_data.settings_self[AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE];

    if (has_body_stream) {
        /* If stream has DATA to send, put it in the outgoing_streams_list, and we'll send data later */
        stream->thread_data.state = AWS_H2_STREAM_STATE_OPEN;
        AWS_H2_STREAM_LOG(TRACE, stream, "Sending HEADERS. State -> OPEN");
    } else {
        /* If stream has no body, then HEADERS frame marks the end of outgoing data */
        stream->thread_data.state = AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL;
        AWS_H2_STREAM_LOG(TRACE, stream, "Sending HEADERS with END_STREAM. State -> HALF_CLOSED_LOCAL");
    }

    *out_has_outgoing_data = has_body_stream;
    aws_h2_connection_enqueue_outgoing_frame(connection, headers_frame);
    return AWS_OP_SUCCESS;

error:
    return AWS_OP_ERR;
}

int aws_h2_stream_encode_data_frame(
    struct aws_h2_stream *stream,
    struct aws_h2_frame_encoder *encoder,
    struct aws_byte_buf *output,
    int *data_encode_status) {

    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);
    AWS_PRECONDITION(
        stream->thread_data.state == AWS_H2_STREAM_STATE_OPEN ||
        stream->thread_data.state == AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE);
    struct aws_h2_connection *connection = s_get_h2_connection(stream);
    AWS_PRECONDITION(connection->thread_data.window_size_peer > AWS_H2_MIN_WINDOW_SIZE);

    if (stream->thread_data.window_size_peer <= AWS_H2_MIN_WINDOW_SIZE) {
        /* The stream is stalled now */
        *data_encode_status = AWS_H2_DATA_ENCODE_ONGOING_WINDOW_STALLED;
        return AWS_OP_SUCCESS;
    }

    *data_encode_status = AWS_H2_DATA_ENCODE_COMPLETE;
    struct aws_input_stream *body = aws_http_message_get_body_stream(stream->thread_data.outgoing_message);
    AWS_ASSERT(body);

    bool body_complete;
    bool body_stalled;
    if (aws_h2_encode_data_frame(
            encoder,
            stream->base.id,
            body,
            true /*body_ends_stream*/,
            0 /*pad_length*/,
            &stream->thread_data.window_size_peer,
            &connection->thread_data.window_size_peer,
            output,
            &body_complete,
            &body_stalled)) {

        /* Failed to write DATA, treat it as a Stream Error */
        AWS_H2_STREAM_LOGF(ERROR, stream, "Error encoding stream DATA, %s", aws_error_name(aws_last_error()));
        struct aws_h2err returned_h2err = s_send_rst_and_close_stream(stream, aws_h2err_from_last_error());
        if (aws_h2err_failed(returned_h2err)) {
            aws_h2_connection_shutdown_due_to_write_err(connection, returned_h2err.aws_code);
        }
        return AWS_OP_SUCCESS;
    }

    if (body_complete) {
        if (stream->thread_data.state == AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
            /* Both sides have sent END_STREAM */
            stream->thread_data.state = AWS_H2_STREAM_STATE_CLOSED;
            AWS_H2_STREAM_LOG(TRACE, stream, "Sent END_STREAM. State -> CLOSED");
            { /* BEGIN CRITICAL SECTION */
                s_lock_synced_data(stream);
                stream->synced_data.api_state = AWS_H2_STREAM_API_STATE_COMPLETE;
                s_unlock_synced_data(stream);
            } /* END CRITICAL SECTION */
            /* Tell connection that stream is now closed */
            if (aws_h2_connection_on_stream_closed(
                    connection, stream, AWS_H2_STREAM_CLOSED_WHEN_BOTH_SIDES_END_STREAM, AWS_ERROR_SUCCESS)) {
                return AWS_OP_ERR;
            }
        } else {
            /* Else can't close until we receive END_STREAM */
            stream->thread_data.state = AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL;
            AWS_H2_STREAM_LOG(TRACE, stream, "Sent END_STREAM. State -> HALF_CLOSED_LOCAL");
        }
    } else {
        /* Body not complete */
        *data_encode_status = AWS_H2_DATA_ENCODE_ONGOING;
        if (body_stalled) {
            *data_encode_status = AWS_H2_DATA_ENCODE_ONGOING_BODY_STALLED;
        }
        if (stream->thread_data.window_size_peer <= AWS_H2_MIN_WINDOW_SIZE) {
            /* if body and window both stalled, we take the window stalled status, which will take the stream out from
             * outgoing list */
            *data_encode_status = AWS_H2_DATA_ENCODE_ONGOING_WINDOW_STALLED;
        }
    }

    return AWS_OP_SUCCESS;
}

struct aws_h2err aws_h2_stream_on_decoder_headers_begin(struct aws_h2_stream *stream) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    struct aws_h2err stream_err = s_check_state_allows_frame_type(stream, AWS_H2_FRAME_T_HEADERS);
    if (aws_h2err_failed(stream_err)) {
        return s_send_rst_and_close_stream(stream, stream_err);
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err aws_h2_stream_on_decoder_headers_i(
    struct aws_h2_stream *stream,
    const struct aws_http_header *header,
    enum aws_http_header_name name_enum,
    enum aws_http_header_block block_type) {

    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    /* Not calling s_check_state_allows_frame_type() here because we already checked
     * at start of HEADERS frame in aws_h2_stream_on_decoder_headers_begin() */

    bool is_server = stream->base.server_data;

    /* RFC-7540 8.1 - Message consists of:
     * - 0+ Informational 1xx headers (response-only, decoder validates that this only occurs in responses)
     * - 1 main headers with normal request or response.
     * - 0 or 1 trailing headers with no pseudo-headers */
    switch (block_type) {
        case AWS_HTTP_HEADER_BLOCK_INFORMATIONAL:
            if (stream->thread_data.received_main_headers) {
                AWS_H2_STREAM_LOG(
                    ERROR, stream, "Malformed message, received informational (1xx) response after main response");
                goto malformed;
            }
            break;
        case AWS_HTTP_HEADER_BLOCK_MAIN:
            if (stream->thread_data.received_main_headers) {
                AWS_H2_STREAM_LOG(ERROR, stream, "Malformed message, received second set of headers");
                goto malformed;
            }
            break;
        case AWS_HTTP_HEADER_BLOCK_TRAILING:
            if (!stream->thread_data.received_main_headers) {
                /* A HEADERS frame without any pseudo-headers looks like trailing headers to the decoder */
                AWS_H2_STREAM_LOG(ERROR, stream, "Malformed headers lack required pseudo-header fields.");
                goto malformed;
            }
            break;
        default:
            AWS_ASSERT(0);
    }

    if (is_server) {
        return aws_h2err_from_aws_code(AWS_ERROR_UNIMPLEMENTED);

    } else {
        /* Client */
        if (name_enum == AWS_HTTP_HEADER_STATUS) {
            uint64_t status_code;
            int err = aws_strutil_read_unsigned_num(header->value, &status_code);
            AWS_ASSERT(!err && "Invalid :status value. Decoder should have already validated this");
            (void)err;

            stream->base.client_data->response_status = (int)status_code;
        }
    }

    if (stream->base.on_incoming_headers) {
        if (stream->base.on_incoming_headers(&stream->base, block_type, header, 1, stream->base.user_data)) {
            /* #TODO: callback errors should be Stream Errors, not Connection Errors */
            AWS_H2_STREAM_LOGF(
                ERROR, stream, "Incoming header callback raised error, %s", aws_error_name(aws_last_error()));
            return aws_h2err_from_last_error();
        }
    }

    return AWS_H2ERR_SUCCESS;

malformed:
    return s_send_rst_and_close_stream(stream, aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR));
}

struct aws_h2err aws_h2_stream_on_decoder_headers_end(
    struct aws_h2_stream *stream,
    bool malformed,
    enum aws_http_header_block block_type) {

    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    /* Not calling s_check_state_allows_frame_type() here because we already checked
     * at start of HEADERS frame in aws_h2_stream_on_decoder_headers_begin() */

    if (malformed) {
        AWS_H2_STREAM_LOG(ERROR, stream, "Headers are malformed");
        return s_send_rst_and_close_stream(stream, aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR));
    }

    switch (block_type) {
        case AWS_HTTP_HEADER_BLOCK_INFORMATIONAL:
            AWS_H2_STREAM_LOG(TRACE, stream, "Informational 1xx header-block done.");
            break;
        case AWS_HTTP_HEADER_BLOCK_MAIN:
            AWS_H2_STREAM_LOG(TRACE, stream, "Main header-block done.");
            stream->thread_data.received_main_headers = true;
            break;
        case AWS_HTTP_HEADER_BLOCK_TRAILING:
            AWS_H2_STREAM_LOG(TRACE, stream, "Trailing 1xx header-block done.");
            break;
        default:
            AWS_ASSERT(0);
    }

    if (stream->base.on_incoming_header_block_done) {
        if (stream->base.on_incoming_header_block_done(&stream->base, block_type, stream->base.user_data)) {
            AWS_H2_STREAM_LOGF(
                ERROR,
                stream,
                "Incoming-header-block-done callback raised error, %s",
                aws_error_name(aws_last_error()));
            return aws_h2err_from_last_error();
        }
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err aws_h2_stream_on_decoder_push_promise(struct aws_h2_stream *stream, uint32_t promised_stream_id) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    struct aws_h2err stream_err = s_check_state_allows_frame_type(stream, AWS_H2_FRAME_T_PUSH_PROMISE);
    if (aws_h2err_failed(stream_err)) {
        return s_send_rst_and_close_stream(stream, stream_err);
    }

    /* Note: Until we have a need for it, PUSH_PROMISE is not a fully supported feature.
     * Promised streams are automatically rejected in a manner compliant with RFC-7540. */
    AWS_H2_STREAM_LOG(DEBUG, stream, "Automatically rejecting promised stream, PUSH_PROMISE is not fully supported");
    if (aws_h2_connection_send_rst_and_close_reserved_stream(
            s_get_h2_connection(stream), promised_stream_id, AWS_HTTP2_ERR_REFUSED_STREAM)) {
        return aws_h2err_from_last_error();
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err aws_h2_stream_on_decoder_data_begin(
    struct aws_h2_stream *stream,
    uint32_t payload_len,
    bool end_stream) {

    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    struct aws_h2err stream_err = s_check_state_allows_frame_type(stream, AWS_H2_FRAME_T_DATA);
    if (aws_h2err_failed(stream_err)) {
        return s_send_rst_and_close_stream(stream, stream_err);
    }

    if (!stream->thread_data.received_main_headers) {
        AWS_H2_STREAM_LOG(ERROR, stream, "Malformed message, received DATA before main HEADERS");
        return s_send_rst_and_close_stream(stream, aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR));
    }

    /* RFC-7540 6.9.1:
     * The sender MUST NOT send a flow-controlled frame with a length that exceeds
     * the space available in either of the flow-control windows advertised by the receiver.
     * Frames with zero length with the END_STREAM flag set (that is, an empty DATA frame)
     * MAY be sent if there is no available space in either flow-control window. */
    if ((int32_t)payload_len > stream->thread_data.window_size_self && payload_len != 0) {
        AWS_H2_STREAM_LOGF(
            ERROR,
            stream,
            "DATA length=%" PRIu32 " exceeds flow-control window=%" PRIi64,
            payload_len,
            stream->thread_data.window_size_self);
        return s_send_rst_and_close_stream(stream, aws_h2err_from_h2_code(AWS_HTTP2_ERR_FLOW_CONTROL_ERROR));
    }
    stream->thread_data.window_size_self -= payload_len;

    /* send a stream window_update frame to automatically maintain the stream self window size, if
     * manual_window_management is not set */
    if (payload_len != 0 && !end_stream && !stream->base.owning_connection->manual_window_management) {
        struct aws_h2_frame *stream_window_update_frame =
            aws_h2_frame_new_window_update(stream->base.alloc, stream->base.id, payload_len);
        if (!stream_window_update_frame) {
            AWS_H2_STREAM_LOGF(
                ERROR,
                stream,
                "WINDOW_UPDATE frame on stream failed to be sent, error %s",
                aws_error_name(aws_last_error()));
            return aws_h2err_from_last_error();
        }

        aws_h2_connection_enqueue_outgoing_frame(s_get_h2_connection(stream), stream_window_update_frame);
        stream->thread_data.window_size_self += payload_len;
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err aws_h2_stream_on_decoder_data_i(struct aws_h2_stream *stream, struct aws_byte_cursor data) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    /* Not calling s_check_state_allows_frame_type() here because we already checked at start of DATA frame in
     * aws_h2_stream_on_decoder_data_begin() */

    if (stream->base.on_incoming_body) {
        if (stream->base.on_incoming_body(&stream->base, &data, stream->base.user_data)) {
            AWS_H2_STREAM_LOGF(
                ERROR, stream, "Incoming body callback raised error, %s", aws_error_name(aws_last_error()));
            return aws_h2err_from_last_error();
        }
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err aws_h2_stream_on_decoder_window_update(
    struct aws_h2_stream *stream,
    uint32_t window_size_increment,
    bool *window_resume) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    *window_resume = false;

    struct aws_h2err stream_err = s_check_state_allows_frame_type(stream, AWS_H2_FRAME_T_WINDOW_UPDATE);
    if (aws_h2err_failed(stream_err)) {
        return s_send_rst_and_close_stream(stream, stream_err);
    }
    if (window_size_increment == 0) {
        /* flow-control window increment of 0 MUST be treated as error (RFC7540 6.9.1) */
        AWS_H2_STREAM_LOG(ERROR, stream, "Window update frame with 0 increment size");
        return s_send_rst_and_close_stream(stream, aws_h2err_from_h2_code(AWS_HTTP2_ERR_PROTOCOL_ERROR));
    }
    int32_t old_window_size = stream->thread_data.window_size_peer;
    stream_err = (aws_h2_stream_window_size_change(stream, window_size_increment, false /*self*/));
    if (aws_h2err_failed(stream_err)) {
        /* We MUST NOT allow a flow-control window to exceed the max */
        AWS_H2_STREAM_LOG(
            ERROR, stream, "Window update frame causes the stream flow-control window to exceed the maximum size");
        return s_send_rst_and_close_stream(stream, stream_err);
    }
    if (stream->thread_data.window_size_peer > AWS_H2_MIN_WINDOW_SIZE && old_window_size <= AWS_H2_MIN_WINDOW_SIZE) {
        *window_resume = true;
    }
    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err aws_h2_stream_on_decoder_end_stream(struct aws_h2_stream *stream) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    /* Not calling s_check_state_allows_frame_type() here because END_STREAM isn't
     * an actual frame type. It's a flag on DATA or HEADERS frames, and we
     * already checked the legality of those frames in their respective callbacks. */

    if (stream->thread_data.state == AWS_H2_STREAM_STATE_HALF_CLOSED_LOCAL) {
        /* Both sides have sent END_STREAM */
        stream->thread_data.state = AWS_H2_STREAM_STATE_CLOSED;
        AWS_H2_STREAM_LOG(TRACE, stream, "Received END_STREAM. State -> CLOSED");
        { /* BEGIN CRITICAL SECTION */
            s_lock_synced_data(stream);
            stream->synced_data.api_state = AWS_H2_STREAM_API_STATE_COMPLETE;
            s_unlock_synced_data(stream);
        } /* END CRITICAL SECTION */
        /* Tell connection that stream is now closed */
        if (aws_h2_connection_on_stream_closed(
                s_get_h2_connection(stream),
                stream,
                AWS_H2_STREAM_CLOSED_WHEN_BOTH_SIDES_END_STREAM,
                AWS_ERROR_SUCCESS)) {
            return aws_h2err_from_last_error();
        }

    } else {
        /* Else can't close until our side sends END_STREAM */
        stream->thread_data.state = AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
        AWS_H2_STREAM_LOG(TRACE, stream, "Received END_STREAM. State -> HALF_CLOSED_REMOTE");
    }

    return AWS_H2ERR_SUCCESS;
}

struct aws_h2err aws_h2_stream_on_decoder_rst_stream(struct aws_h2_stream *stream, uint32_t h2_error_code) {
    AWS_PRECONDITION_ON_CHANNEL_THREAD(stream);

    /* Check that this state allows RST_STREAM. */
    struct aws_h2err err = s_check_state_allows_frame_type(stream, AWS_H2_FRAME_T_RST_STREAM);
    if (aws_h2err_failed(err)) {
        /* Usually we send a RST_STREAM when the state doesn't allow a frame type, but RFC-7540 5.4.2 says:
         * "To avoid looping, an endpoint MUST NOT send a RST_STREAM in response to a RST_STREAM frame." */
        return err;
    }

    /* RFC-7540 8.1 - a server MAY request that the client abort transmission of a request without error by sending a
     * RST_STREAM with an error code of NO_ERROR after sending a complete response (i.e., a frame with the END_STREAM
     * flag). Clients MUST NOT discard responses as a result of receiving such a RST_STREAM */
    int aws_error_code;
    if (stream->base.client_data && (h2_error_code == AWS_HTTP2_ERR_NO_ERROR) &&
        (stream->thread_data.state == AWS_H2_STREAM_STATE_HALF_CLOSED_REMOTE)) {

        aws_error_code = AWS_ERROR_SUCCESS;

    } else {
        aws_error_code = AWS_ERROR_HTTP_RST_STREAM_RECEIVED;
        AWS_H2_STREAM_LOGF(
            ERROR,
            stream,
            "Peer terminated stream with HTTP/2 RST_STREAM frame, error-code=0x%x(%s)",
            h2_error_code,
            aws_http2_error_code_to_str(h2_error_code));
    }

    stream->thread_data.state = AWS_H2_STREAM_STATE_CLOSED;
    { /* BEGIN CRITICAL SECTION */
        s_lock_synced_data(stream);
        stream->synced_data.api_state = AWS_H2_STREAM_API_STATE_COMPLETE;
        s_unlock_synced_data(stream);
    } /* END CRITICAL SECTION */
    stream->received_reset_error_code = h2_error_code;

    AWS_H2_STREAM_LOGF(
        TRACE,
        stream,
        "Received RST_STREAM code=0x%x(%s). State -> CLOSED",
        h2_error_code,
        aws_http2_error_code_to_str(h2_error_code));

    if (aws_h2_connection_on_stream_closed(
            s_get_h2_connection(stream), stream, AWS_H2_STREAM_CLOSED_WHEN_RST_STREAM_RECEIVED, aws_error_code)) {
        return aws_h2err_from_last_error();
    }

    return AWS_H2ERR_SUCCESS;
}
