/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#include <aws/http/connection_manager.h>
#include <aws/http/http2_stream_manager.h>

struct aws_http2_stream_manager {
    struct aws_allocator *allocator;

    /**
     * Underlying connection manager.
     */
    struct aws_http_connection_manager *connection_manager;
};
