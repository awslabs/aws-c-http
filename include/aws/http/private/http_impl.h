#ifndef AWS_HTTP_IMPL_H
#define AWS_HTTP_IMPL_H

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

/**
 * Methods that affect internal processing.
 * This is NOT a definitive list of methods.
 */
enum aws_http_method {
    AWS_HTTP_METHOD_UNKNOWN, /* Unrecognized value. */
    AWS_HTTP_METHOD_GET,
    AWS_HTTP_METHOD_HEAD,
    AWS_HTTP_METHOD_COUNT, /* Number of enums */
};

/**
 * Headers that affect internal processing.
 * This is NOT a definitive list of headers.
 */
enum aws_http_header_name {
    AWS_HTTP_HEADER_UNKNOWN, /* Unrecognized value */
    AWS_HTTP_HEADER_CONNECTION,
    AWS_HTTP_HEADER_CONTENT_LENGTH,
    AWS_HTTP_HEADER_EXPECT,
    AWS_HTTP_HEADER_TRANSFER_ENCODING,
    AWS_HTTP_HEADER_COUNT, /* Number of enums */
};

/**
 * Status codes that affect internal processing.
 * This is NOT a definitive list of codes.
 */
enum aws_http_status {
    AWS_HTTP_STATUS_UNKNOWN = -1, /* Invalid status code. Not using 0 because it's technically a legal value */
    AWS_HTTP_STATUS_100_CONTINUE = 100,
    AWS_HTTP_STATUS_101_SWITCHING_PROTOCOLS = 101,
    AWS_HTTP_STATUS_204_NO_CONTENT = 204,
    AWS_HTTP_STATUS_304_NOT_MODIFIED = 304,
};

struct aws_http_decoded_header {
    /* Name of the header. If the type is `AWS_HTTP_HEADER_NAME_UNKNOWN` then `name_data` must be parsed manually. */
    enum aws_http_header_name name;

    /* Raw buffer storing the header's name. */
    struct aws_byte_cursor name_data;

    /* Raw buffer storing the header's value. */
    struct aws_byte_cursor value_data;

    /* Raw buffer storing the entire header. */
    struct aws_byte_cursor data;
};

/**
 * Called from `aws_h*_decode` when an http header has been received.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 */
typedef int(aws_http_decoder_on_header_fn)(const struct aws_http_decoded_header *header, void *user_data);

/**
 * Called from `aws_h*_decode` when a portion of the http body has been received.
 * `finished` is true if this is the last section of the http body, and false if more body data is yet to be received.
 * All pointers are strictly *read only*; any data that needs to persist must be copied out into user-owned memory.
 */
typedef int(aws_http_decoder_on_body_fn)(const struct aws_byte_cursor *data, bool finished, void *user_data);

typedef int(aws_http_decoder_on_request_fn)(
    enum aws_http_method method_enum,
    const struct aws_byte_cursor *method_str,
    const struct aws_byte_cursor *uri,
    void *user_data);

typedef int(aws_http_decoder_on_response_fn)(int status_code, void *user_data);

typedef int(aws_http_decoder_done_fn)(void *user_data);

struct aws_http_decoder_vtable {
    aws_http_decoder_on_header_fn *on_header;
    aws_http_decoder_on_body_fn *on_body;

    /* Only needed for requests, can be NULL for responses. */
    aws_http_decoder_on_request_fn *on_request;

    /* Only needed for responses, can be NULL for requests. */
    aws_http_decoder_on_response_fn *on_response;

    aws_http_decoder_done_fn *on_done;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API void aws_http_fatal_assert_library_initialized(void);

AWS_HTTP_API struct aws_byte_cursor aws_http_version_to_str(enum aws_http_version version);

AWS_HTTP_API enum aws_http_method aws_http_str_to_method(struct aws_byte_cursor cursor);
AWS_HTTP_API enum aws_http_header_name aws_http_str_to_header_name(struct aws_byte_cursor cursor);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_IMPL_H */
