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
    AWS_HTTP_METHOD_HEAD,
    AWS_HTTP_METHOD_COUNT, /* Number of enums */
};

/**
 * Headers that affect internal processing.
 * This is NOT a definitive list of headers.
 */
enum aws_http_header_name {
    AWS_HTTP_HEADER_UNKNOWN, /* Unrecognized value */
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
    AWS_HTTP_STATUS_CONTINUE = 100,
};

AWS_HTTP_API void aws_http_fatal_assert_library_initialized(void);

AWS_HTTP_API struct aws_byte_cursor aws_http_version_to_str(enum aws_http_version version);

AWS_HTTP_API enum aws_http_method aws_http_str_to_method(struct aws_byte_cursor cursor);
AWS_HTTP_API enum aws_http_header_name aws_http_str_to_header_name(struct aws_byte_cursor cursor);

#endif /* AWS_HTTP_IMPL_H */
