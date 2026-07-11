#ifndef AWS_NO_PROXY_H
#define AWS_NO_PROXY_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/http/http.h>
AWS_PUSH_SANE_WARNING_LEVEL
AWS_EXTERN_C_BEGIN

/*
 * Check if a host should bypass the proxy based on the NO_PROXY environment variable or provided no_proxy value.
 * Since NO_PROXY has no standard yet. Follows the curl implementation from noproxy.c at 8.14.1.
 * https://github.com/curl/curl/blob/curl-8_14_1/lib/noproxy.c
 *
 * NO_PROXY is a comma-separated list of domain names, hostnames, or IP addresses that
 * should bypass the proxy.
 *
 * If no_proxy is NULL, the function will read the NO_PROXY environment variable.
 * If no_proxy is provided, it will be used instead of the environment variable.
 *
 * Returns true if the host should bypass the proxy.
 */
AWS_HTTP_API bool aws_http_host_matches_no_proxy(
    struct aws_allocator *allocator,
    struct aws_byte_cursor host,
    struct aws_string *no_proxy_str);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_NO_PROXY_H */
