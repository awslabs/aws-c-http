#ifndef AWS_HTTP_H2_CONNECTION_H
#define AWS_HTTP_H2_CONNECTION_H

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

#include <aws/common/mutex.h>

#include <aws/http/private/connection_impl.h>

struct aws_h2_connection {
    struct aws_http_connection base;



    /* Only the event-loop thread may touch this data */
    /*
    struct {

    } thread_data;
    */

    /* Any thread may touch this data, but the lock must be held */
    struct {
        struct aws_mutex lock;

    } synced_data;
};

AWS_HTTP_API
uint32_t aws_h2_connection_get_next_stream_id(struct aws_h2_connection *connection);

#endif /* AWS_HTTP_H2_CONNECTION_H */
