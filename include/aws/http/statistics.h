#ifndef AWS_HTTP_STATISTICS_H
#define AWS_HTTP_STATISTICS_H

/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/common/statistics.h>

enum aws_crt_http_statistics_category {
    AWSCRT_STAT_CAT_HTTP1 = AWS_CRT_STATISTICS_CATEGORY_BEGIN_RANGE(AWS_C_HTTP_PACKAGE_ID),
    AWSCRT_STAT_CAT_HTTP2
};

struct aws_crt_statistics_http1 {
    aws_crt_statistics_category_t category;
    uint64_t pending_read_ms;
    uint64_t pending_write_ms;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
int aws_crt_statistics_http1_init(struct aws_crt_statistics_http1 *stats);

AWS_HTTP_API
void aws_crt_statistics_http1_cleanup(struct aws_crt_statistics_http1 *stats);

AWS_HTTP_API
void aws_crt_statistics_http1_reset(struct aws_crt_statistics_http1 *stats);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_STATISTICS_H */
