#ifndef AWS_HTTP_CONNECTION_H
#define AWS_HTTP_CONNECTION_H

/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/http/http.h>

struct aws_client_bootstrap;
struct aws_socket_options;
struct aws_tls_connection_options;
struct aws_http2_setting;

/**
 * An HTTP connection.
 * This type is used by both server-side and client-side connections.
 * This type is also used by all supported versions of HTTP.
 */
struct aws_http_connection;

/**
 * Invoked when connect completes.
 *
 * If unsuccessful, error_code will be set, connection will be NULL,
 * and the on_shutdown callback will never be invoked.
 *
 * If successful, error_code will be 0 and connection will be valid.
 * The user is now responsible for the connection and must
 * call aws_http_connection_release() when they are done with it.
 *
 * The connection uses one event-loop thread to do all its work.
 * The thread invoking this callback will be the same thread that invokes all
 * future callbacks for this connection and its streams.
 */
typedef void(
    aws_http_on_client_connection_setup_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

/**
 * Invoked when the connection has finished shutting down.
 * Never invoked if on_setup failed.
 * This is always invoked on connection's event-loop thread.
 * Note that the connection is not completely done until on_shutdown has been invoked
 * AND aws_http_connection_release() has been called.
 */
typedef void(
    aws_http_on_client_connection_shutdown_fn)(struct aws_http_connection *connection, int error_code, void *user_data);

/**
 * Invoked when the HTTP/2 settings change is complete.
 * If connection setup successfully this will always be invoked whether settings change successfully or unsuccessfully.
 * If error_code is AWS_ERROR_SUCCESS (0), then the peer has acknowledged the settings and the change has been applied.
 * If error_code is non-zero, then a connection error occurred before the settings could be fully acknowledged and
 * applied. This is always invoked on the connection's event-loop thread.
 */
typedef void(aws_http2_on_change_settings_complete_fn)(
    struct aws_http_connection *http2_connection,
    int error_code,
    void *user_data);

/**
 * Invoked when the HTTP/2 PING completes, whether peer has acknowledged it or not.
 * If error_code is AWS_ERROR_SUCCESS (0), then the peer has acknowledged the PING and round_trip_time_ns will be the
 * round trip time in nano seconds for the connection.
 * If error_code is non-zero, then a connection error occurred before the PING get acknowledgment and round_trip_time_ns
 * will be useless in this case.
 */
typedef void(aws_http2_on_ping_complete_fn)(
    struct aws_http_connection *http2_connection,
    uint64_t round_trip_time_ns,
    int error_code,
    void *user_data);

/**
 * Invoked when an HTTP/2 GOAWAY frame is received from peer.
 * Implies that the peer has initiated shutdown, or encountered a serious error.
 * Once a GOAWAY is received, no further streams may be created on this connection.
 *
 * @param http2_connection This HTTP/2 connection.
 * @param last_stream_id ID of the last locally-initiated stream that peer will
 *      process. Any locally-initiated streams with a higher ID are ignored by
 *      peer, and are safe to retry on another connection.
 * @param http2_error_code The HTTP/2 error code (RFC-7540 section 7) sent by peer.
 *      `enum aws_http2_error_code` lists official codes.
 * @param user_data User-data passed to the callback.
 */

typedef void(aws_http2_on_goaway_received_fn)(
    struct aws_http_connection *http2_connection,
    uint32_t last_stream_id,
    uint32_t http2_error_code,
    void *user_data);

/**
 * Invoked when new HTTP/2 settings from peer have been applied.
 * Settings_array is the array of aws_http2_settings that contains all the settings we just changed in the order we
 * applied (the order settings arrived). Num_settings is the number of elements in that array.
 */
typedef void(aws_http2_on_remote_settings_change_fn)(
    struct aws_http_connection *http2_connection,
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    void *user_data);

/**
 * Configuration options for connection monitoring
 */
struct aws_http_connection_monitoring_options {

    /**
     * minimum required throughput of the connection.  Throughput is only measured against the interval of time where
     * there is actual io to perform.  Read and write throughput are measured and checked independently of one another.
     */
    uint64_t minimum_throughput_bytes_per_second;

    /*
     * amount of time, in seconds, throughput is allowed to drop below the minimum before the connection is shut down
     * as unhealthy.
     */
    uint32_t allowable_throughput_failure_interval_seconds;
};

/**
 * Supported proxy authentication modes
 */
enum aws_http_proxy_authentication_type {
    AWS_HPAT_NONE = 0,
    AWS_HPAT_BASIC,
};

/**
 * Options for http proxy server usage
 */
struct aws_http_proxy_options {

    /**
     * Proxy host to connect to, in lieu of actual target
     */
    struct aws_byte_cursor host;

    /**
     * Port to make the proxy connection to
     */
    uint16_t port;

    /**
     * Optional.
     * TLS configuration for the Local <-> Proxy connection
     * Must be distinct from the the TLS options in the parent aws_http_connection_options struct
     */
    struct aws_tls_connection_options *tls_options;

    /**
     * What type of proxy authentication to use, if any
     */
    enum aws_http_proxy_authentication_type auth_type;

    /**
     * Optional
     * User name to use for authentication, basic only
     */
    struct aws_byte_cursor auth_username;

    /**
     * Optional
     * Password to use for authentication, basic only
     */
    struct aws_byte_cursor auth_password;
};

/**
 * HTTP/2 connection options.
 * Initialize with AWS_HTTP2_CONNECTION_OPTIONS_INIT to set default values.
 */
struct aws_http2_connection_options {
    /**
     * Optional
     * The data of settings to change for initial settings.
     * Note: each setting has its boundary. If settings_array is not set, num_settings has to be 0 to send an empty
     * SETTINGS frame.
     */
    struct aws_http2_setting *initial_settings_array;

    /**
     * Required
     * The num of settings to change.
     */
    size_t num_initial_settings;

    /**
     * Optional.
     * Invoked when the HTTP/2 initial settings change is complete.
     * If failed to setup the connection, this will not be invoked.
     * Otherwise, this will be invoked, whether settings change successfully or unsuccessfully.
     * See `aws_http2_on_change_settings_complete_fn`.
     */
    aws_http2_on_change_settings_complete_fn *on_initial_settings_completed;

    /**
     * Optional
     * The max number of recently-closed streams to remember.
     * A default number is set by AWS_HTTP2_CONNECTION_OPTIONS_INIT.
     *
     * If the connection receives a frame for a closed stream,
     * the frame will be ignored or cause a connection error,
     * depending on the frame type and how the stream was closed.
     * Remembering more streams reduces the chances that a late frame causes
     * a connection error, but costs some memory.
     */
    size_t max_closed_streams;

    /**
     * Optional.
     * Invoked when a valid GOAWAY frame received.
     * See `aws_http2_on_goaway_received_fn`.
     */
    aws_http2_on_goaway_received_fn *on_goaway_received;

    /**
     * Optional.
     * Invoked when new settings from peer have been applied.
     * See `aws_http2_on_remote_settings_change_fn`.
     */
    aws_http2_on_remote_settings_change_fn *on_remote_settings_change;
};

/**
 * Options for creating an HTTP client connection.
 * Initialize with AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT to set default values.
 */
struct aws_http_client_connection_options {
    /**
     * The sizeof() this struct, used for versioning.
     * Set by AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT.
     */
    size_t self_size;

    /**
     * Required.
     * Must outlive the connection.
     */
    struct aws_allocator *allocator;

    /**
     * Required.
     * Must outlive the connection.
     */
    struct aws_client_bootstrap *bootstrap;

    /**
     * Required.
     * aws_http_client_connect() makes a copy.
     */
    struct aws_byte_cursor host_name;

    /**
     * Required.
     */
    uint16_t port;

    /**
     * Required.
     * aws_http_client_connect() makes a copy.
     */
    const struct aws_socket_options *socket_options;

    /**
     * Optional.
     * aws_http_client_connect() deep-copies all contents except the `aws_tls_ctx`,
     * which must outlive the the connection.
     */
    const struct aws_tls_connection_options *tls_options;

    /**
     * Optional
     * Configuration options related to http proxy usage.
     * Relevant fields are copied internally.
     */
    const struct aws_http_proxy_options *proxy_options;

    /**
     * Optional
     * Configuration options related to connection health monitoring
     */
    const struct aws_http_connection_monitoring_options *monitoring_options;

    /**
     * Optional.
     * The initial connection flow-control window size for HTTP/1 connection.
     * Ignored by HTTP/2 connection, since the initial connection flow-control window in HTTP/2 is not configurable.
     * A default size is set by AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT.
     */
    size_t initial_window_size;

    /**
     * User data for callbacks
     * Optional.
     */
    void *user_data;

    /**
     * Invoked when connect completes.
     * Required.
     * See `aws_http_on_client_connection_setup_fn`.
     */
    aws_http_on_client_connection_setup_fn *on_setup;

    /**
     * Invoked when the connection has finished shutting down.
     * Never invoked if setup failed.
     * Optional.
     * See `aws_http_on_client_connection_shutdown_fn`.
     */
    aws_http_on_client_connection_shutdown_fn *on_shutdown;

    /**
     * Set to true to manually manage the read window size.
     *
     * If this is false, the connection will maintain a constant window size.
     *
     * If this is true, the caller must manually increment the window size using aws_http_stream_update_window().
     * If the window is not incremented, it will shrink by the amount of body data received. If the window size
     * reaches 0, no further data will be received.
     **/
    bool manual_window_management;

    /**
     * HTTP/2 connection specific options.
     * Optional.
     * If HTTP/2 connection created, we will use this for some configurations in HTTP/2 connection.
     * If other protocol connection created, this will be ignored.
     */
    struct aws_http2_connection_options *http2_options;
};

/* Predefined settings identifiers (RFC-7540 6.5.2) */
enum aws_http2_settings_id {
    AWS_HTTP2_SETTINGS_BEGIN_RANGE = 0x1, /* Beginning of known values */
    AWS_HTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
    AWS_HTTP2_SETTINGS_ENABLE_PUSH = 0x2,
    AWS_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    AWS_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
    AWS_HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5,
    AWS_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6,
    AWS_HTTP2_SETTINGS_END_RANGE, /* End of known values */
};

/* A HTTP/2 setting and its value, used in SETTINGS frame */
struct aws_http2_setting {
    enum aws_http2_settings_id id;
    uint32_t value;
};

/**
 * HTTP/2: Default value for max closed streams we will keep in memory.
 */
#define AWS_HTTP2_DEFAULT_MAX_CLOSED_STREAMS (32)
/**
 * HTTP/2: The size of payload for HTTP/2 PING frame.
 */
#define AWS_HTTP2_PING_DATA_SIZE (8)
/**
 * Initializes aws_http2_connection_options with default values.
 */
#define AWS_HTTP2_CONNECTION_OPTIONS_INIT                                                                              \
    { .max_closed_streams = AWS_HTTP2_DEFAULT_MAX_CLOSED_STREAMS }
/**
 * Initializes aws_http_client_connection_options with default values.
 */
#define AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT                                                                        \
    { .self_size = sizeof(struct aws_http_client_connection_options), .initial_window_size = SIZE_MAX, }

AWS_EXTERN_C_BEGIN

/**
 * Asynchronously establish a client connection.
 * The on_setup callback is invoked when the operation has created a connection or failed.
 */
AWS_HTTP_API
int aws_http_client_connect(const struct aws_http_client_connection_options *options);

/**
 * Users must release the connection when they are done with it.
 * The connection's memory cannot be reclaimed until this is done.
 * If the connection was not already shutting down, it will be shut down.
 *
 * Users should always wait for the on_shutdown() callback to be called before releasing any data passed to the
 * http_connection (Eg aws_tls_connection_options, aws_socket_options) otherwise there will be race conditions between
 * http_connection shutdown tasks and memory release tasks, causing Segfaults.
 */
AWS_HTTP_API
void aws_http_connection_release(struct aws_http_connection *connection);

/**
 * Begin shutdown sequence of the connection if it hasn't already started. This will schedule shutdown tasks on the
 * EventLoop that may send HTTP/TLS/TCP shutdown messages to peers if necessary, and will eventually cause internal
 * connection memory to stop being accessed and on_shutdown() callback to be called.
 *
 * It's safe to call this function regardless of the connection state as long as you hold a reference to the connection.
 */
AWS_HTTP_API
void aws_http_connection_close(struct aws_http_connection *connection);

/**
 * Returns true unless the connection is closed or closing.
 */
AWS_HTTP_API
bool aws_http_connection_is_open(const struct aws_http_connection *connection);

/**
 * Returns true if this is a client connection.
 */
AWS_HTTP_API
bool aws_http_connection_is_client(const struct aws_http_connection *connection);

/**
 * Increments the connection-wide read window by the value specified.
 */
AWS_HTTP_API
void aws_http_connection_update_window(struct aws_http_connection *connection, size_t increment_size);

AWS_HTTP_API
enum aws_http_version aws_http_connection_get_version(const struct aws_http_connection *connection);

/**
 * Returns the channel hosting the HTTP connection.
 * Do not expose this function to language bindings.
 */
AWS_HTTP_API
struct aws_channel *aws_http_connection_get_channel(struct aws_http_connection *connection);

/**
 * Send a SETTINGS frame (HTTP/2 only).
 * SETTINGS will be applied locally when SETTINGS ACK is received from peer.
 *
 * @param http2_connection HTTP/2 connection.
 * @param settings_array The array of settings to change. Note: each setting has its boundary.
 * @param num_settings The num of settings to change in settings_array.
 * @param on_completed Optional callback, see `aws_http2_on_change_settings_complete_fn`.
 * @param user_data User-data pass to on_completed callback.
 */
AWS_HTTP_API
int aws_http2_connection_change_settings(
    struct aws_http_connection *http2_connection,
    const struct aws_http2_setting *settings_array,
    size_t num_settings,
    aws_http2_on_change_settings_complete_fn *on_completed,
    void *user_data);

/**
 * Send a PING frame (HTTP/2 only).
 * Round-trip-time is calculated when PING ACK is received from peer.
 *
 * @param http2_connection HTTP/2 connection.
 * @param optional_opaque_data Optional payload for PING frame.
 *      Must be NULL, or exactly 8 bytes (AWS_HTTP2_PING_DATA_SIZE).
 *      If NULL, the 8 byte payload will be all zeroes.
 * @param on_completed Optional callback, invoked when PING ACK is received from peer,
 *      or when a connection error prevents the PING ACK from being received.
 *      Callback always fires on the connection's event-loop thread.
 * @param user_data User-data pass to on_completed callback.
 */
AWS_HTTP_API
int aws_http2_connection_ping(
    struct aws_http_connection *http2_connection,
    const struct aws_byte_cursor *optional_opaque_data,
    aws_http2_on_ping_complete_fn *on_completed,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_CONNECTION_H */
