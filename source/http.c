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

#include <aws/http/private/hpack.h>
#include <aws/http/private/http_impl.h>

#include <aws/common/hash_table.h>
#include <aws/io/logging.h>

#include <ctype.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4311) /* 'type cast': pointer truncation from 'void *' to 'int' */
#else
#    pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
#endif

#define AWS_DEFINE_ERROR_INFO_HTTP(CODE, STR) [(CODE)-0x0800] = AWS_DEFINE_ERROR_INFO(CODE, STR, "aws-c-http")

/* clang-format off */
static struct aws_error_info s_errors[] = {
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_UNKNOWN,
        "Encountered an unknown error."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_HEADER_NOT_FOUND,
        "The specified header was not found"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_HEADER_FIELD,
        "Invalid header field, including a forbidden header field."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_HEADER_NAME,
        "Invalid header name."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_HEADER_VALUE,
        "Invalid header value."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_METHOD,
        "Method is invalid."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_PATH,
        "Path is invalid."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_STATUS_CODE,
        "Status code is invalid."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_MISSING_BODY_STREAM,
        "Given the provided headers (ex: Content-Length), a body is expected."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_BODY_STREAM,
        "A body stream provided, but the message does not allow body (ex: response for HEAD Request and 304 response)"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_CONNECTION_CLOSED,
        "The connection has closed or is closing."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_SWITCHED_PROTOCOLS,
        "The connection has switched protocols."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_UNSUPPORTED_PROTOCOL,
        "An unsupported protocol was encountered."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_REACTION_REQUIRED,
        "A necessary function was not invoked from a user callback."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_DATA_NOT_AVAILABLE,
        "This data is not yet available."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT,
        "Amount of data streamed out does not match the previously declared length."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_CALLBACK_FAILURE,
        "A callback has reported failure."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_WEBSOCKET_UPGRADE_FAILURE,
        "Failed to upgrade HTTP connection to Websocket."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_WEBSOCKET_CLOSE_FRAME_SENT,
        "Websocket has sent CLOSE frame, no more data will be sent."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_WEBSOCKET_IS_MIDCHANNEL_HANDLER,
        "Operation cannot be performed because websocket has been converted to a midchannel handler."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_CONNECTION_MANAGER_INVALID_STATE_FOR_ACQUIRE,
        "Acquire called after the connection manager's ref count has reached zero"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_CONNECTION_MANAGER_VENDED_CONNECTION_UNDERFLOW,
        "Release called when the connection manager's vended connection count was zero"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_SERVER_CLOSED,
        "The http server is closed, no more connections will be accepted"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_PROXY_TLS_CONNECT_FAILED,
        "Proxy tls connection establishment failed because the CONNECT call failed"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_CONNECTION_MANAGER_SHUTTING_DOWN,
        "Connection acquisition failed because connection manager is shutting down"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_CHANNEL_THROUGHPUT_FAILURE,
        "Http connection channel shut down due to failure to meet throughput minimum"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_PROTOCOL_ERROR,
        "Protocol rules violated by API call or peer"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_STREAM_CLOSED,
        "Received frame on a closed stream"),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_STREAM_IDS_EXHAUSTED,
        "Connection exhausted all possible stream IDs. Establish a new connection for new streams."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_FRAME_SIZE,
        "Received frame with an illegal frame size"),
    AWS_DEFINE_ERROR_INFO_HTTP(  
        AWS_ERROR_HTTP_COMPRESSION,
        "Error compressing or decompressing HPACK headers"),
};
/* clang-format on */

static struct aws_error_info_list s_error_list = {
    .error_list = s_errors,
    .count = AWS_ARRAY_SIZE(s_errors),
};

static struct aws_log_subject_info s_log_subject_infos[] = {
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_GENERAL, "http", "Misc HTTP logging"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_CONNECTION, "http-connection", "HTTP client or server connection"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_ENCODER, "http-encoder", "HTTP data encoder"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_DECODER, "http-decoder", "HTTP data decoder"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_SERVER, "http-server", "HTTP server socket listening for incoming connections"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_STREAM, "http-stream", "HTTP request-response exchange"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_CONNECTION_MANAGER, "connection-manager", "HTTP connection manager"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_WEBSOCKET, "websocket", "Websocket"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_WEBSOCKET_SETUP, "websocket-setup", "Websocket setup"),

    DEFINE_LOG_SUBJECT_INFO(AWS_LS_HTTP_FRAMES, "http-frames", "HTTP frame library"),
};

static struct aws_log_subject_info_list s_log_subject_list = {
    .subject_list = s_log_subject_infos,
    .count = AWS_ARRAY_SIZE(s_log_subject_infos),
};

/**
 * Given array of aws_byte_cursors, init hashtable where...
 * Key is aws_byte_cursor* (pointing into cursor from array) and comparisons are case-insensitive.
 * Value is the array index cast to a void*.
 */
static void s_init_str_to_enum_hash_table(
    struct aws_hash_table *table,
    struct aws_allocator *alloc,
    struct aws_byte_cursor *str_array,
    int start_index,
    int end_index,
    bool ignore_case) {

    int err = aws_hash_table_init(
        table,
        alloc,
        end_index - start_index,
        ignore_case ? aws_hash_byte_cursor_ptr_ignore_case : aws_hash_byte_cursor_ptr,
        (aws_hash_callback_eq_fn *)(ignore_case ? aws_byte_cursor_eq_ignore_case : aws_byte_cursor_eq),
        NULL,
        NULL);
    AWS_FATAL_ASSERT(!err);

    for (size_t i = start_index; i < (size_t)end_index; ++i) {
        int was_created;
        AWS_FATAL_ASSERT(str_array[i].ptr && "Missing enum string");
        err = aws_hash_table_put(table, &str_array[i], (void *)i, &was_created);
        AWS_FATAL_ASSERT(!err && was_created);
    }
}

/**
 * Given key, get value from table initialized by s_init_str_to_enum_hash_table().
 * Returns -1 if key not found.
 */
static int s_find_in_str_to_enum_hash_table(const struct aws_hash_table *table, struct aws_byte_cursor *key) {
    struct aws_hash_element *elem;
    aws_hash_table_find(table, key, &elem);
    if (elem) {
        return (int)elem->value;
    }
    return -1;
}

/* METHODS */
static struct aws_hash_table s_method_str_to_enum;                         /* for string -> enum lookup */
static struct aws_byte_cursor s_method_enum_to_str[AWS_HTTP_METHOD_COUNT]; /* for enum -> string lookup */

static void s_methods_init(struct aws_allocator *alloc) {
    s_method_enum_to_str[AWS_HTTP_METHOD_GET] = aws_http_method_get;
    s_method_enum_to_str[AWS_HTTP_METHOD_HEAD] = aws_http_method_head;

    s_init_str_to_enum_hash_table(
        &s_method_str_to_enum,
        alloc,
        s_method_enum_to_str,
        AWS_HTTP_METHOD_UNKNOWN + 1,
        AWS_HTTP_METHOD_COUNT,
        false /* DO NOT ignore case of method */);
}

static void s_methods_clean_up(void) {
    aws_hash_table_clean_up(&s_method_str_to_enum);
}

enum aws_http_method aws_http_str_to_method(struct aws_byte_cursor cursor) {
    int method = s_find_in_str_to_enum_hash_table(&s_method_str_to_enum, &cursor);
    if (method >= 0) {
        return (enum aws_http_method)method;
    }
    return AWS_HTTP_METHOD_UNKNOWN;
}

/* VERSIONS */
static struct aws_byte_cursor s_version_enum_to_str[AWS_HTTP_HEADER_COUNT]; /* for enum -> string lookup */

static void s_versions_init(struct aws_allocator *alloc) {
    (void)alloc;
    s_version_enum_to_str[AWS_HTTP_VERSION_UNKNOWN] = aws_byte_cursor_from_c_str("Unknown");
    s_version_enum_to_str[AWS_HTTP_VERSION_1_0] = aws_byte_cursor_from_c_str("HTTP/1.0");
    s_version_enum_to_str[AWS_HTTP_VERSION_1_1] = aws_byte_cursor_from_c_str("HTTP/1.1");
    s_version_enum_to_str[AWS_HTTP_VERSION_2] = aws_byte_cursor_from_c_str("HTTP/2");
}

static void s_versions_clean_up(void) {}

struct aws_byte_cursor aws_http_version_to_str(enum aws_http_version version) {
    if (version < AWS_HTTP_VERSION_UNKNOWN || version >= AWS_HTTP_VERSION_COUNT) {
        version = AWS_HTTP_VERSION_UNKNOWN;
    }

    return s_version_enum_to_str[version];
}

/* HEADERS */
static struct aws_hash_table s_header_str_to_enum;                         /* for string -> enum lookup */
static struct aws_byte_cursor s_header_enum_to_str[AWS_HTTP_HEADER_COUNT]; /* for enum -> string lookup */

static void s_headers_init(struct aws_allocator *alloc) {
    s_header_enum_to_str[AWS_HTTP_HEADER_CONNECTION] = aws_byte_cursor_from_c_str("connection");
    s_header_enum_to_str[AWS_HTTP_HEADER_CONTENT_LENGTH] = aws_byte_cursor_from_c_str("content-length");
    s_header_enum_to_str[AWS_HTTP_HEADER_EXPECT] = aws_byte_cursor_from_c_str("expect");
    s_header_enum_to_str[AWS_HTTP_HEADER_TRANSFER_ENCODING] = aws_byte_cursor_from_c_str("transfer-encoding");

    s_init_str_to_enum_hash_table(
        &s_header_str_to_enum,
        alloc,
        s_header_enum_to_str,
        AWS_HTTP_HEADER_UNKNOWN + 1,
        AWS_HTTP_HEADER_COUNT,
        true /* ignore case */);
}

static void s_headers_clean_up(void) {
    aws_hash_table_clean_up(&s_header_str_to_enum);
}

enum aws_http_header_name aws_http_str_to_header_name(struct aws_byte_cursor cursor) {
    int header = s_find_in_str_to_enum_hash_table(&s_header_str_to_enum, &cursor);
    if (header >= 0) {
        return (enum aws_http_header_name)header;
    }
    return AWS_HTTP_HEADER_UNKNOWN;
}

/* STATUS */
const char *aws_http_status_text(int status_code) {
    /**
     * Data from Internet Assigned Numbers Authority (IANA):
     * https://www.iana.org/assignments/http-status-codes/http-status-codes.txt
     */
    switch (status_code) {
        case 100:
            return "Continue";
        case 101:
            return "Switching Protocols";
        case 102:
            return "Processing";
        case 103:
            return "Early Hints";
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 202:
            return "Accepted";
        case 203:
            return "Non-Authoritative Information";
        case 204:
            return "No Content";
        case 205:
            return "Reset Content";
        case 206:
            return "Partial Content";
        case 207:
            return "Multi-Status";
        case 208:
            return "Already Reported";
        case 226:
            return "IM Used";
        case 300:
            return "Multiple Choices";
        case 301:
            return "Moved Permanently";
        case 302:
            return "Found";
        case 303:
            return "See Other";
        case 304:
            return "Not Modified";
        case 305:
            return "Use Proxy";
        case 307:
            return "Temporary Redirect";
        case 308:
            return "Permanent Redirect";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 402:
            return "Payment Required";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 406:
            return "Not Acceptable";
        case 407:
            return "Proxy Authentication Required";
        case 408:
            return "Request Timeout";
        case 409:
            return "Conflict";
        case 410:
            return "Gone";
        case 411:
            return "Length Required";
        case 412:
            return "Precondition Failed";
        case 413:
            return "Payload Too Large";
        case 414:
            return "URI Too Long";
        case 415:
            return "Unsupported Media Type";
        case 416:
            return "Range Not Satisfiable";
        case 417:
            return "Expectation Failed";
        case 421:
            return "Misdirected Request";
        case 422:
            return "Unprocessable Entity";
        case 423:
            return "Locked";
        case 424:
            return "Failed Dependency";
        case 425:
            return "Too Early";
        case 426:
            return "Upgrade Required";
        case 428:
            return "Precondition Required";
        case 429:
            return "Too Many Requests";
        case 431:
            return "Request Header Fields Too Large";
        case 451:
            return "Unavailable For Legal Reasons";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        case 504:
            return "Gateway Timeout";
        case 505:
            return "HTTP Version Not Supported";
        case 506:
            return "Variant Also Negotiates";
        case 507:
            return "Insufficient Storage";
        case 508:
            return "Loop Detected";
        case 510:
            return "Not Extended";
        case 511:
            return "Network Authentication Required";
        default:
            return "";
    }
}

static bool s_library_initialized = false;
void aws_http_library_init(struct aws_allocator *alloc) {
    if (s_library_initialized) {
        return;
    }
    s_library_initialized = true;

    aws_io_library_init(alloc);
    aws_register_error_info(&s_error_list);
    aws_register_log_subject_info_list(&s_log_subject_list);
    s_methods_init(alloc);
    s_headers_init(alloc);
    s_versions_init(alloc);
    aws_hpack_static_table_init(alloc);
}

void aws_http_library_clean_up(void) {
    if (!s_library_initialized) {
        return;
    }
    s_library_initialized = false;

    aws_unregister_error_info(&s_error_list);
    aws_unregister_log_subject_info_list(&s_log_subject_list);
    s_methods_clean_up();
    s_headers_clean_up();
    s_versions_clean_up();
    aws_hpack_static_table_clean_up();
    aws_io_library_clean_up();
}

void aws_http_fatal_assert_library_initialized() {
    if (!s_library_initialized) {
        AWS_LOGF_FATAL(
            AWS_LS_HTTP_GENERAL,
            "aws_http_library_init() must be called before using any functionality in aws-c-http.");

        AWS_FATAL_ASSERT(s_library_initialized);
    }
}

const struct aws_byte_cursor aws_http_method_get = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("GET");
const struct aws_byte_cursor aws_http_method_head = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("HEAD");
const struct aws_byte_cursor aws_http_method_post = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("POST");
const struct aws_byte_cursor aws_http_method_put = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("PUT");
const struct aws_byte_cursor aws_http_method_delete = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("DELETE");
const struct aws_byte_cursor aws_http_method_connect = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("CONNECT");
const struct aws_byte_cursor aws_http_method_options = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("OPTIONS");
