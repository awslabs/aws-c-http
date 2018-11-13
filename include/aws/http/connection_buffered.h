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

#ifndef AWS_HTTP_CONNECTION_BUFFERED_H
#define AWS_HTTP_CONNECTION_BUFFERED_H

#include <aws/http/http.h>
#include <aws/common/common.h>

struct aws_http_request;

#ifdef __cplusplus
extern "C" {
#endif

AWS_HTTP_API enum aws_http_method method_aws_http_request_get_method(struct aws_http_request *request);
AWS_HTTP_API const struct aws_byte_cursor *aws_http_request_get_uri(struct aws_http_request *request);
AWS_HTTP_API void aws_http_request_get_headers(struct aws_http_request *request, const struct aws_http_header **headers, int *count);
AWS_HTTP_API bool aws_http_request_get_chunked(struct aws_http_request *request);
AWS_HTTP_API void *aws_http_request_get_userdata(struct aws_http_request *request);

#ifdef __cplusplus
}
#endif

#endif /* AWS_HTTP_CONNECTION_BUFFERED_H */
