#ifndef AWS_HTTP_TRACING_H
#define AWS_HTTP_TRACING_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/external/ittnotify.h>
#include <aws/io/io.h>

extern __itt_domain *http_tracing_domain;
extern __itt_string_handle *tracing_http_write;
extern __itt_string_handle *tracing_http_read;

AWS_EXTERN_C_BEGIN

AWS_IO_API
void aws_http_tracing_init(void);

AWS_EXTERN_C_END
#endif /* AWS_HTTP_TRACING_H */
