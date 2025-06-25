/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/connection.h>
#include <aws/http/proxy.h>

#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/io/uri.h>

#include <aws/http/private/no_proxy.h>
#include <aws/testing/aws_test_harness.h>
#include <aws/testing/io_testing_channel.h>

AWS_STATIC_STRING_FROM_LITERAL(s_http_proxy_env_var, "http_proxy");
AWS_STATIC_STRING_FROM_LITERAL(s_no_proxy_env_var, "no_proxy");

static int s_init_no_proxy_test(struct aws_allocator *allocator, const char *no_proxy_value_str) {

    aws_http_library_init(allocator);

    /* Set up test variables */
    struct aws_string *proxy_value = aws_string_new_from_c_str(allocator, "http://proxy.example.org:8888");
    struct aws_string *no_proxy_value = aws_string_new_from_c_str(allocator, no_proxy_value_str);

    /* Set environment variables for testing */
    ASSERT_SUCCESS(aws_set_environment_value(s_http_proxy_env_var, proxy_value));
    ASSERT_SUCCESS(aws_set_environment_value(s_no_proxy_env_var, no_proxy_value));

    aws_string_destroy(proxy_value);
    aws_string_destroy(no_proxy_value);
    return AWS_OP_SUCCESS;
}

static int s_cleanup_no_proxy_test(void) {
    ASSERT_SUCCESS(aws_unset_environment_value(s_http_proxy_env_var));
    ASSERT_SUCCESS(aws_unset_environment_value(s_no_proxy_env_var));
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}

static int s_test_no_proxy_helper(struct aws_allocator *allocator, const char *host, bool expected_bypass) {
    /* Call the function that checks NO_PROXY */
    ASSERT_UINT_EQUALS(aws_check_no_proxy(allocator, aws_byte_cursor_from_c_str(host)), expected_bypass);
    return AWS_OP_SUCCESS;
}

/**
 * Test subdomain matching with NO_PROXY
 */
static int s_test_no_proxy_subdomain_matching(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *no_proxy_value = ".example.com";

    /* Initialize test with NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test that a subdomain matches when NO_PROXY contains a domain with leading dot */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "sub.example.com", true));
    /* cannot match */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "sub.subexample.com", false));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_subdomain_matching, s_test_no_proxy_subdomain_matching);

/**
 * Test wildcard patterns in NO_PROXY
 */
static int s_test_no_proxy_wildcard_patterns(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *no_proxy_value = "*";

    /* Initialize test with NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test that a wildcard pattern matches all hosts */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "any.example.com", true));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_wildcard_patterns, s_test_no_proxy_wildcard_patterns);

/**
 * Test case insensitivity in NO_PROXY
 */
static int s_test_no_proxy_case_insensitivity(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *no_proxy_value = "example.COM";

    /* Initialize test with NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test that case insensitive matching works for both host and NO_PROXY entries */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "EXAMPLE.com", true));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_case_insensitivity, s_test_no_proxy_case_insensitivity);

/**
 * Test IPv6 addresses
 */
static int s_test_no_proxy_ipv6_address(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Pattern don't allow `[]`, just follows what curl does. */
    const char *no_proxy_value = "2001:db8::1, ::1, [2001:db8::2]";

    /* Initialize test with NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test that an IPv6 address in brackets matches */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db8::1]", true));

    /* Test another IPv6 address format (localhost) */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "::1", true));

    /* Test a non-matching IPv6 address */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db8::2]", false));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_ipv6_address, s_test_no_proxy_ipv6_address);

/**
 * Test multiple patterns in NO_PROXY
 */
static int s_test_no_proxy_multiple_patterns(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Only wildcard support is a single `*`, if it's in the list, it will be ignored. */
    const char *no_proxy_value = "foo.bar,example.com,other.net,*";

    /* Initialize test with NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test that a host matches when it's in the middle of a comma-separated list */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "example.com", true));

    /* Test that another host in the list also matches */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "foo.bar", true));

    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "foo.", false));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_multiple_patterns, s_test_no_proxy_multiple_patterns);

/**
 * Test whitespace handling in NO_PROXY
 */
static int s_test_no_proxy_whitespace_handling(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *no_proxy_value = " example.com , foo.bar ";

    /* Initialize test with NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test that whitespace is properly handled in NO_PROXY entries */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "example.com", true));

    /* Test that another host with whitespace also matches */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "foo.bar", true));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_whitespace_handling, s_test_no_proxy_whitespace_handling);

/**
 * Test IP addresses in NO_PROXY
 */
static int s_test_no_proxy_ip_address(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *no_proxy_value = "192.168.1.1,10.0.0.0";

    /* Initialize test with NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test that IP address matching works */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.1.1", true));

    /* Test that a different IP doesn't match */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.2.1", false));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_ip_address, s_test_no_proxy_ip_address);

/**
 * Test port-specific exclusions in NO_PROXY
 *
 * NOTE: This tests a curl-specific feature where entries like "example.com:8080"
 * can be used to bypass the proxy only for specific ports. The current implementation
 * doesn't support this feature, so this test documents that behavior.
 */
static int s_test_no_proxy_port_specific(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *no_proxy_value = "example.com:8080";

    /* Initialize test with NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Our implementation only does hostname matching and ignores port information.
     * In curl, this would bypass only on port 8080, but in our implementation it
     * bypasses for all ports. */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "example.com", true));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_port_specific, s_test_no_proxy_port_specific);

/**
 * Test CIDR notation in NO_PROXY
 *
 * Tests the CIDR notation support (similar to curl 7.86.0) where "192.168.0.0/16"
 * would match all addresses starting with "192.168".
 */
static int s_test_no_proxy_cidr_notation(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *no_proxy_value_16 = "192.168.0.0/16";

    /* Initialize test with first NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value_16));

    /* Test that an IP address in a CIDR range matches */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.5.10", true));

    /* Test that an IP address outside the CIDR range doesn't match */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "10.0.5.10", false));

    /* Clean up first test */
    ASSERT_SUCCESS(s_cleanup_no_proxy_test());

    /* Test with a more specific subnet mask */
    const char *no_proxy_value_24 = "192.168.5.0/24";

    /* Initialize test with second NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value_24));

    /* Test that an IP address in a more specific CIDR range matches */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.5.10", true));

    /* Test that an IP address outside the specific CIDR range doesn't match */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.6.10", false));

    /* Clean up second test */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_cidr_notation, s_test_no_proxy_cidr_notation);

/**
 * Test IPv6 CIDR notation in NO_PROXY
 *
 * Tests the CIDR notation support for IPv6 addresses where "2001:db8::/32"
 * would match all addresses starting with "2001:db8".
 */
static int s_test_no_proxy_ipv6_cidr_notation(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    const char *no_proxy_value_32 = "2001:db8::/32";

    /* Initialize test with first NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value_32));

    /* Test that an IPv6 address in a CIDR range matches */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db8:1:2::3]", true));

    /* Test that an IPv6 address outside the CIDR range doesn't match */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db9:1:2::3]", false));

    /* Clean up first test */
    ASSERT_SUCCESS(s_cleanup_no_proxy_test());

    /* Test with a more specific prefix length */
    const char *no_proxy_value_64 = "2001:db8:1:2::/64";

    /* Initialize test with second NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value_64));

    /* Test that an IPv6 address in a more specific CIDR range matches */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db8:1:2::3]", true));

    /* Test that an IPv6 address outside the specific CIDR range doesn't match */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db8:1:3::3]", false));

    /* Clean up second test */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_ipv6_cidr_notation, s_test_no_proxy_ipv6_cidr_notation);

/**
 * Test invalid IP addresses and CIDR blocks in NO_PROXY
 *
 * Verifies that the NO_PROXY implementation safely handles and ignores invalid
 * IP addresses and CIDR blocks without crashing.
 */
static int s_test_no_proxy_invalid_patterns(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Test with invalid IP addresses and CIDR notations mixed with valid entries */
    const char *no_proxy_value = "example.com,999.999.999.999,192.168.1.3/33,192.168.b.c,"
                                 "2001:xyz::bad:ipv6,2001:db8::/129,not:a:valid:ip/64,"
                                 "[malformed],192.168.1.2,"
                                 "192.168.1.1/99999999999999999," /* Invalid network bits */
                                 "2001:db8::/999999";             /* Invalid IPv6 prefix */

    /* Initialize test with NO_PROXY value containing invalid patterns */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test that invalid IP addresses and CIDR blocks are safely ignored */
    /* The last valid entry (192.168.1.2) should still match */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.1.2", true));

    /* Test that the valid hostname entry still works */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "example.com", true));

    /* Test with an invalid host address parameter */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.1.1", false));

    /* An invalid IP address will be treated as regular hostname and match as regular hostname. */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "999.999.999.999", true));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "999.999.999.999.999", true));

    /* Clean up the test environment */
    ASSERT_SUCCESS(s_cleanup_no_proxy_test());

    /* Test with only invalid entries */
    const char *invalid_only = "999.999.999.999,192.168.1.1/33,not:an:ip:addr,2001:xyz::bad";

    /* Initialize test with NO_PROXY value containing only invalid patterns */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, invalid_only));

    /* Test that a valid IP doesn't match when NO_PROXY contains only invalid entries */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.1.1", false));

    /* Test with empty host parameter */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "", false));

    /* Test with a very malformed CIDR input that could cause parsing issues */
    const char *malformed_cidr = "192.168.1.1/abcdef,2001:db8::/xyz";

    /* Initialize test with NO_PROXY value containing malformed CIDR notation */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, malformed_cidr));
    /* Malformed CIDR will be taken as the entr */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "2001:db8::", true));

    /* Clean up the test environment */
    ASSERT_SUCCESS(s_cleanup_no_proxy_test());

    /* Test with very large CIDR parts that would be rejected in the buffer size check */
    char large_value[200];
    memset(large_value, 'x', sizeof(large_value) - 1);
    large_value[sizeof(large_value) - 1] = '\0';

    char large_cidr[256];
    snprintf(large_cidr, sizeof(large_cidr), "192.168.1.1/%s", large_value);

    /* Initialize test with NO_PROXY value containing oversized CIDR notation */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, large_cidr));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.1.1", false));

    /* Clean up the test environment */
    ASSERT_SUCCESS(s_cleanup_no_proxy_test());

    /* Clean up and return */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_invalid_patterns, s_test_no_proxy_invalid_patterns);

/**
 * Test invalid host inputs to aws_check_no_proxy
 *
 * Verifies that the aws_check_no_proxy function handles malformed host inputs
 * gracefully without crashing. These tests specifically check the host parameter
 * rather than the NO_PROXY environment variable content.
 */
static int s_test_no_proxy_invalid_host_inputs(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Set up a valid NO_PROXY value for testing */
    const char *no_proxy_value = "example.com,192.168.1.0/24,2001:db8::/32";

    /* Initialize test with valid NO_PROXY value */
    ASSERT_SUCCESS(s_init_no_proxy_test(allocator, no_proxy_value));

    /* Test with invalid IPv4 address */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "999.999.999.999", false));

    /* Test with malformed IPv4 address formats */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.1", false));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168..1", false));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "192.168.1.", false));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, ".192.168.1", false));

    /* Test with invalid IPv6 address variants */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db8::xyz]", false));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db8::]:", false));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "2001:db8:::", false));

    /* Test with malformed IPv6 address brackets */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[2001:db8::1", false));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "2001:db8::1]", false));
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "[[2001:db8::1]]", false));

    /* Test with empty host */
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, "", false));

    /* Test with extremely long host that exceeds buffer sizes */
    char long_host[1024];
    memset(long_host, 'a', sizeof(long_host) - 1);
    long_host[sizeof(long_host) - 1] = '\0';
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, long_host, false));

    /* Test with extremely long IPv4 address that would hit buffer checks */
    char long_ipv4[150] = "192.168.1.1";
    for (int i = 0; i < 130; i++) {
        long_ipv4[11 + i] = '9'; /* Padding with extra digits */
    }
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, long_ipv4, false));

    /* Test with extremely long IPv6 address that would hit buffer checks */
    char long_ipv6[150] = "[2001:db8::1";
    for (int i = 0; i < 130; i++) {
        long_ipv6[11 + i] = '1'; /* Padding with extra digits */
    }
    long_ipv6[141] = ']';
    long_ipv6[142] = '\0';
    ASSERT_SUCCESS(s_test_no_proxy_helper(allocator, long_ipv6, false));

    /* Clean up the test environment */
    return s_cleanup_no_proxy_test();
}
AWS_TEST_CASE(test_no_proxy_invalid_host_inputs, s_test_no_proxy_invalid_host_inputs);

/**
 * Test behavior when NO_PROXY environment variable is unset or empty
 *
 * Verifies that the aws_check_no_proxy function correctly handles cases where
 * the NO_PROXY environment variable is not set or empty.
 */
static int s_test_no_proxy_environment_unset(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);

    /* Test with NO_PROXY unset (only http_proxy set) */
    struct aws_string *proxy_value = aws_string_new_from_c_str(allocator, "http://proxy.example.org:8888");
    ASSERT_SUCCESS(aws_set_environment_value(s_http_proxy_env_var, proxy_value));

    /* Make sure NO_PROXY environment variables are unset */
    ASSERT_SUCCESS(aws_unset_environment_value(s_no_proxy_env_var));
    struct aws_string *uppercase_no_proxy = aws_string_new_from_c_str(allocator, "NO_PROXY");
    ASSERT_SUCCESS(aws_unset_environment_value(uppercase_no_proxy)); /* Upper case version */
    aws_string_destroy(uppercase_no_proxy);

    /* With NO_PROXY unset, aws_check_no_proxy should return false for any host */
    ASSERT_FALSE(aws_check_no_proxy(allocator, aws_byte_cursor_from_c_str("example.com")));
    ASSERT_FALSE(aws_check_no_proxy(allocator, aws_byte_cursor_from_c_str("192.168.1.1")));
    ASSERT_FALSE(aws_check_no_proxy(allocator, aws_byte_cursor_from_c_str("[2001:db8::1]")));

    /* Now test with empty NO_PROXY */
    struct aws_string *empty_no_proxy = aws_string_new_from_c_str(allocator, "");
    ASSERT_SUCCESS(aws_set_environment_value(s_no_proxy_env_var, empty_no_proxy));

    /* With empty NO_PROXY, aws_check_no_proxy should still return false */
    ASSERT_FALSE(aws_check_no_proxy(allocator, aws_byte_cursor_from_c_str("example.com")));

    /* Clean up */
    ASSERT_SUCCESS(aws_unset_environment_value(s_http_proxy_env_var));
    ASSERT_SUCCESS(aws_unset_environment_value(s_no_proxy_env_var));
    aws_string_destroy(proxy_value);
    aws_string_destroy(empty_no_proxy);
    aws_http_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_no_proxy_environment_unset, s_test_no_proxy_environment_unset);
