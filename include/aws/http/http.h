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

#ifndef AWS_HTTP_H
#define AWS_HTTP_H

#include <aws/http/exports.h>

#include <aws/common/common.h>

enum aws_http_version {
    AWS_HTTP_VERSION_UNKNOWN, /* Invalid version. */
    AWS_HTTP_VERSION_1_0,
    AWS_HTTP_VERSION_1_1,
    AWS_HTTP_VERSION_2_0,
};

/* 
 * String representation by a begin and end pointer pair. The `begin` pointer points to the
 * first element in the string, and the `end` pointer points to one beyond the end of the string.
 * For example the string "Hello world!" as an `aws_http_str would be properly setup like so:
 * 
 * const char* s = "Hello world!";
 * struct aws_http_str str;
 * str.begin = s;
 * str.end = s + strlen(s); // Note: no +1 here; `aws_http_str` strings are not NUL-byte terminated.
 */
struct aws_http_str {
    const char* begin;
    const char* end;
};

enum aws_http_request_method {
    AWS_HTTP_REQUEST_METHOD_UNKNOWN, /* Invalid request. */
    AWS_HTTP_REQUEST_METHOD_CONNECT,
    AWS_HTTP_REQUEST_METHOD_DELETE,
    AWS_HTTP_REQUEST_METHOD_GET,
    AWS_HTTP_REQUEST_METHOD_HEAD,
    AWS_HTTP_REQUEST_METHOD_OPTIONS,
    AWS_HTTP_REQUEST_METHOD_PATCH,
    AWS_HTTP_REQUEST_METHOD_POST,
    AWS_HTTP_REQUEST_METHOD_PUT,
    AWS_HTTP_REQUEST_METHOD_TRACE,
};

enum aws_http_request_key {
    /* 
     * Valid request header key, but not mapped to an enum (e.g. uncommon headers are
     * not apart of this enum.
     */
    AWS_HTTP_REQUEST_UNKNOWN,

    AWS_HTTP_REQUEST_ACCEPT,
    AWS_HTTP_REQUEST_ACCEPT_CHARSET,
    AWS_HTTP_REQUEST_ACCEPT_ENCODING,
    AWS_HTTP_REQUEST_ACCEPT_LANGUAGE,
    AWS_HTTP_REQUEST_AUTHORIZATION,
    AWS_HTTP_REQUEST_CACHE_CONTROL,
    AWS_HTTP_REQUEST_CONNECTION,
    AWS_HTTP_REQUEST_CONTENT_LENGTH,
    AWS_HTTP_REQUEST_CONTENT_TYPE,
    AWS_HTTP_REQUEST_COOKIE,
    AWS_HTTP_REQUEST_DATE,
    AWS_HTTP_REQUEST_EXPECT,
    AWS_HTTP_REQUEST_FORWARDED,
    AWS_HTTP_REQUEST_FROM,
    AWS_HTTP_REQUEST_HOST,
    AWS_HTTP_REQUEST_IF_MATCH,
    AWS_HTTP_REQUEST_IF_MODIFIED_SINCE,
    AWS_HTTP_REQUEST_IF_NONE_MATCH,
    AWS_HTTP_REQUEST_IF_RANGE,
    AWS_HTTP_REQUEST_IF_UNMODIFIED_SINCE,
    AWS_HTTP_REQUEST_KEEP_ALIVE,
    AWS_HTTP_REQUEST_MAX_FORWARDS,
    AWS_HTTP_REQUEST_ORIGIN,
    AWS_HTTP_REQUEST_PROXY_AUTHORIZATION,
    AWS_HTTP_REQUEST_RANGE,
    AWS_HTTP_REQUEST_REFERRER,
    AWS_HTTP_REQUEST_USER_AGENT,
    AWS_HTTP_REQUEST_VIA,

    /* Must be last. */
    AWS_HTTP_REQUEST_LAST
};

/*
 * Headers are string key-value pairs. Some keys are pre-mapped to convenience enum values. See
 * \ref aws_http_request_key and \ref aws_http_response_key.
 */
struct aws_http_header {
    int key;
    struct aws_http_str key_str; /* Case insensitive. */
    struct aws_http_str value_str;
};

/* Common structure shared between requests/responses. */
struct aws_http_message_data {
    int header_count;
    struct aws_http_header* headers;
    struct aws_http_str body;
    struct aws_allocator *alloc;
};

struct aws_http_request {
    enum aws_http_request_method method;
    enum aws_http_version version;
    struct aws_http_str target;
    struct aws_http_message_data data;

    /* Used for constant-time lookups for common headers. */
    int header_cache[AWS_HTTP_REQUEST_LAST];
};

enum aws_http_response_status_code_class
{
    AWS_HTTP_RESPONSE_STATUS_CODE_UNKNOWN, /* Invalid status code. */
    AWS_HTTP_RESPONSE_STATUS_CODE_INFORMATIONAL,
    AWS_HTTP_RESPONSE_STATUS_CODE_SUCCESSFUL,
    AWS_HTTP_RESPONSE_STATUS_CODE_REDIRECTION,
    AWS_HTTP_RESPONSE_STATUS_CODE_CLIENT_ERROR,
    AWS_HTTP_RESPONSE_STATUS_CODE_SERVER_ERROR,
};

enum aws_http_response_key {
    /* 
     * Valid response header key, but not mapped to an enum (e.g. uncommon headers are
     * not apart of this enum.
     */
    AWS_HTTP_RESPONSE_UNKNOWN,

    AWS_HTTP_RESPONSE_ACCEPT_RANGES,
    AWS_HTTP_RESPONSE_AGE,
    AWS_HTTP_RESPONSE_ALLOW,
    AWS_HTTP_RESPONSE_CACHE_CONTROL,
    AWS_HTTP_RESPONSE_CONTENT_DISPOSITION,
    AWS_HTTP_RESPONSE_CONTENT_ENCODING,
    AWS_HTTP_RESPONSE_CONTENT_LANGUAGE,
    AWS_HTTP_RESPONSE_CONTENT_LENGTH,
    AWS_HTTP_RESPONSE_CONTENT_LOCATION,
    AWS_HTTP_RESPONSE_CONTENT_RANGE,
    AWS_HTTP_RESPONSE_CONTENT_TYPE,
    AWS_HTTP_RESPONSE_DATE,
    AWS_HTTP_RESPONSE_ETAG,
    AWS_HTTP_RESPONSE_LAST_MODIFIED,
    AWS_HTTP_RESPONSE_LINK,
    AWS_HTTP_RESPONSE_LOCATION,
    AWS_HTTP_RESPONSE_PROXY_AUTHENTICATE,
    AWS_HTTP_RESPONSE_RETRY_AFTER,
    AWS_HTTP_RESPONSE_SERVER,
    AWS_HTTP_RESPONSE_SET_COOKIE,
    AWS_HTTP_RESPONSE_STRICT_TRANSPORT_SECURITY,
    AWS_HTTP_RESPONSE_UPGRADE,
    AWS_HTTP_RESPONSE_VARY,
    AWS_HTTP_RESPONSE_VIA,
    AWS_HTTP_RESPONSE_WWW_AUTHENTICATE,

    /* Must be last. */
    AWS_HTTP_RESPONSE_LAST
};

struct aws_http_response {
    enum aws_http_version version;
    enum aws_http_response_status_code_class status_code_class;
    int status_code;
    struct aws_http_str status_code_reason_phrase;
    struct aws_http_message_data data;

    /* Used for constant-time lookups for common headers. */
    int header_cache[AWS_HTTP_RESPONSE_LAST];
};

enum aws_http_errors {
    AWS_HTTP_ERROR_UNKNOWN = 0x0800,
    AWS_HTTP_ERROR_PARSE,
    AWS_HTTP_ERROR_END_RANGE = 0x0C00,
};

#ifdef __cplusplus
extern "C" {
#endif

// TODO: The host header must be in each requests for http1.1, and a 400 bad request is the response otherwise.

AWS_HTTP_API int aws_http_request_init(struct aws_http_request *request, struct aws_allocator *alloc, const void* buffer, size_t buffer_size);
AWS_HTTP_API void aws_http_request_clean_up(struct aws_http_request *request);

/*
 * Headers are searched the order they are parsed (from top-down), and the first match is returned. These `get`
 * functions do not do any special handling for duplicate headers, and will always naively return the first match found.
 * This function searches for a header given the associated enum value. Not all possible headers have a pre-defined
 * enum value associated with them; only the commons have an enum.
 */
AWS_HTTP_API int aws_http_request_get_header_by_enum(const struct aws_http_request *request, struct aws_http_header *header, enum aws_http_request_key key);

/*
 * Searches for a header given the string representation of the header name. The search is case-insensitive.
 */
AWS_HTTP_API int aws_http_request_get_header_by_str(const struct aws_http_request *request, struct aws_http_header *header, const char *key, size_t key_len);

AWS_HTTP_API int aws_http_response_init(struct aws_http_response *response, struct aws_allocator *alloc, const void* buffer, size_t buffer_size);
AWS_HTTP_API void aws_http_response_clean_up(struct aws_http_response *response);

/*
 * Headers are searched the order they are parsed (from top-down), and the first match is returned. These `get`
 * functions do not do any special handling for duplicate headers, and will always naively return the first match found.
 * This function searches for a header given the associated enum value. Not all possible headers have a pre-defined
 * enum value associated with them; only the commons have an enum.
 */
AWS_HTTP_API int aws_http_response_get_header_by_enum(const struct aws_http_response *response, struct aws_http_header *header, enum aws_http_request_key key);

/*
 * Searches for a header given the string representation of the header name. The search is case-insensitive.
 */
AWS_HTTP_API int aws_http_response_get_header_by_str(const struct aws_http_response *response, struct aws_http_header *header, const char *key, size_t key_len);

AWS_HTTP_API const char *aws_http_request_method_to_str(enum aws_http_request_method method);
AWS_HTTP_API const char *aws_http_request_key_to_str(enum aws_http_request_key key);
AWS_HTTP_API const char *aws_http_response_key_to_str(enum aws_http_request_key key);
AWS_HTTP_API const char *aws_http_version_code_to_str(enum aws_http_version version);

/**
 * Loads error strings for this API so that aws_last_error_str etc. will return useful debug strings.
 */
AWS_HTTP_API void aws_http_load_error_strings(void);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_H */
