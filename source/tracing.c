/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/tracing.h>
__itt_domain *http_tracing_domain;
__itt_string_handle *tracing_http_write;
__itt_string_handle *tracing_http_read;

void aws_http_tracing_init() {
    http_tracing_domain = __itt_domain_create("aws.c.http");
    tracing_http_write = __itt_string_handle_create("HTTPWrite");
    tracing_http_read = __itt_string_handle_create("HTTPRead");
}