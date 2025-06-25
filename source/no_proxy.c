/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/environment.h>
#include <aws/http/private/no_proxy.h>

#ifdef _WIN32
#    include <ws2tcpip.h>
#else
#    include <arpa/inet.h>
#endif

static const char *s_no_proxy_env_var = "NO_PROXY";
static const char *s_no_proxy_env_var_low = "no_proxy";

enum hostname_type {
    HOSTNAME_TYPE_IPV4,
    HOSTNAME_TYPE_IPV6,
    HOSTNAME_TYPE_REGULAR,
};

/**
 * Determines whether a host string is an IPv4 address and stores the binary representation.
 * Checks if the string follows IPv4 format
 *
 * @param host The host string to check
 * @param addr_out Optional pointer to store the parsed binary address. Must be at least 4 bytes.
 * @return true if the host is an IPv4 address, false otherwise
 */
static bool s_is_ipv4_address(const struct aws_byte_cursor *host, void *addr_out) {
    if (!host || host->len == 0 || !addr_out) {
        return false;
    }

    char ip_buffer[128] = {'\0'};
    if (host->len >= sizeof(ip_buffer)) {
        /* Too long to be valid IPv4 */
        return false;
    }

    memcpy(ip_buffer, host->ptr, host->len);
    ip_buffer[host->len] = '\0'; /* Null-terminate for inet_pton */

    int result = inet_pton(AF_INET, ip_buffer, addr_out);
    return result == 1;
}

/**
 * Determines whether a host string is an IPv6 address and stores the binary representation.
 * If it contains `[]`, remove them
 *
 * @param host The host string to check
 * @param addr_out Optional pointer to store the parsed binary address. Must be at least 16 bytes.
 * @return true if the host is an IPv6 address, false otherwise
 */
static bool s_is_ipv6_address_and_update_host(struct aws_byte_cursor *host, void *addr_out) {
    if (!host || host->len < 2 || !addr_out) {
        return false;
    }

    /* Check if the address is enclosed in brackets and strip them for validation */
    if (host->ptr[0] == '[' && host->ptr[host->len - 1] == ']') {
        aws_byte_cursor_advance(host, 1);
        host->len--;
    }

    char ip_buffer[128] = {'\0'};
    if (host->len >= sizeof(ip_buffer)) {
        /* Too long to be valid IPv6 */
        return false;
    }

    memcpy(ip_buffer, host->ptr, host->len);
    ip_buffer[host->len] = '\0'; /* Null-terminate for inet_pton */

    int result = inet_pton(AF_INET6, ip_buffer, addr_out);
    return result == 1;
}

/**
 * s_cidr4_match() returns true if the given IPv4 address is within the
 * specified CIDR address range.
 * Based on the curl implementation Curl_cidr4_match().
 *
 * @param bits The number of network bits in the CIDR notation
 * @param network_part The network pattern to match against (e.g., "192.168.0.0")\
 * @param host_addr Pre-parsed binary representation of the host IP, or NULL to parse from host
 * @return true if the IP address matches the CIDR pattern, false otherwise
 */
static bool s_cidr4_match(uint16_t bits, struct aws_byte_cursor network_part, const void *host_addr) {

    uint32_t address = 0;
    uint32_t check = 0;

    /* Check for valid bits parameter */
    if (bits > 32) {
        /* Invalid netmask bits */
        return false;
    }

    /* Parse the host address if not provided */
    AWS_ASSERT(host_addr != NULL);
    /* Use the pre-parsed host address */
    memcpy(&address, host_addr, sizeof(address));

    /* Parse the network pattern */
    char pattern_buffer[128] = {'\0'};

    /* Check buffer size */
    if (network_part.len >= sizeof(pattern_buffer)) {
        /* Too long to be valid IPv4 */
        return false;
    }

    memcpy(pattern_buffer, network_part.ptr, network_part.len);
    pattern_buffer[network_part.len] = '\0';

    /* Convert network pattern to binary */
    if (inet_pton(AF_INET, pattern_buffer, &check) != 1) {
        return false;
    }

    if (bits > 0 && bits < 32) {
        /* Apply the network mask for CIDR comparison */
        uint32_t mask = 0xffffffff << (32 - bits);
        uint32_t host_network = ntohl(address);
        uint32_t check_network = ntohl(check);

        /* Compare the masked addresses */
        return (host_network & mask) == (check_network & mask);
    }

    /* For /32 or no bits specified, use exact match */
    return address == check;
}

/**
 * s_cidr6_match() returns true if the given IPv6 address is within the
 * specified CIDR address range.
 * Based on the curl implementation Curl_cidr6_match().
 *
 * @param bits The number of network bits in the CIDR notation
 * @param network_part The network pattern to match against (e.g., "2001:db8::")
 * @param host_addr Pre-parsed binary representation of the host IP, or NULL to parse from host
 * @return true if the IP address matches the CIDR pattern, false otherwise
 */
static bool s_cidr6_match(uint16_t bits, struct aws_byte_cursor network_part, const void *host_addr) {

    unsigned char address[16] = {0};
    unsigned char check[16] = {0};

    /* If no bits specified, use full 128 bits for IPv6 */
    if (!bits) {
        bits = 128;
    }

    /* Check for valid bits parameter */
    if (bits > 128) {
        return false;
    }

    AWS_ASSERT(host_addr != NULL);
    /* Copy pre-parsed host address if provided */
    memcpy(address, host_addr, sizeof(address));

    /* Parse the network pattern */
    char pattern_buffer[128] = {'\0'};

    /* Check buffer size */
    if (network_part.len >= sizeof(pattern_buffer)) {
        /* Too long to be valid IPv6 */
        return false;
    }

    memcpy(pattern_buffer, network_part.ptr, network_part.len);
    pattern_buffer[network_part.len] = '\0';

    /* Convert network pattern to binary */
    if (inet_pton(AF_INET6, pattern_buffer, check) != 1) {
        return false;
    }

    /* Calculate full bytes and remaining bits in the netmask */
    unsigned int bytes = bits / 8;
    unsigned int rest = bits % 8;

    /* Compare full bytes of the network part */
    if (bytes > 0 && memcmp(address, check, bytes) != 0) {
        return false;
    }

    /* If we have remaining bits, compare the partial byte */
    if (rest > 0 && bytes < 16) {
        /* Create a mask for the remaining bits */
        unsigned char mask = (unsigned char)(0xff << (8 - rest));

        /* Check if the masked bits match */
        if ((address[bytes] & mask) != (check[bytes] & mask)) {
            return false;
        }
    }

    /* All checks passed, addresses match within the CIDR range */
    return true;
}

static bool s_is_dot(uint8_t c) {
    return c == '.';
}

/* The host is expected to be the result from  */
bool aws_check_no_proxy(struct aws_allocator *allocator, struct aws_byte_cursor host) {
    if (host.len == 0) {
        return false;
    }

    struct aws_string *no_proxy_str = aws_get_env_nonempty(allocator, s_no_proxy_env_var_low);
    if (no_proxy_str == NULL) {
        no_proxy_str = aws_get_env_nonempty(allocator, s_no_proxy_env_var);
    }

    if (no_proxy_str == NULL) {
        aws_string_destroy(no_proxy_str);
        return false;
    }

    /* Single "*" wildcard matches all hosts */
    if (aws_string_eq_c_str(no_proxy_str, "*")) {
        AWS_LOGF_DEBUG(AWS_LS_HTTP_CONNECTION, "wildcard no_proxy found, bypassing any proxy");
        aws_string_destroy(no_proxy_str);
        return true;
    }
    bool bypass = false;
    struct aws_byte_cursor no_proxy_cur = aws_byte_cursor_from_string(no_proxy_str);
    struct aws_array_list no_proxy_list;
    if (aws_array_list_init_dynamic(&no_proxy_list, allocator, 10, sizeof(struct aws_byte_cursor))) {
        goto cleanup;
    }
    /* Split the NO_PROXY string by commas */
    if (aws_byte_cursor_split_on_char(&no_proxy_cur, ',', &no_proxy_list)) {
        goto cleanup;
    }

    /* Store parsed binary addresses for reuse */
    unsigned char ipv4_addr[4] = {0};
    unsigned char ipv6_addr[16] = {0};
    void *host_addr_ptr = NULL;

    /* Determine host type and parse address if applicable */
    enum hostname_type type = HOSTNAME_TYPE_REGULAR;
    if (s_is_ipv4_address(&host, ipv4_addr)) {
        type = HOSTNAME_TYPE_IPV4;
        host_addr_ptr = ipv4_addr;
    } else {
        struct aws_byte_cursor host_copy = host;
        if (s_is_ipv6_address_and_update_host(&host_copy, ipv6_addr)) {
            type = HOSTNAME_TYPE_IPV6;
            host_addr_ptr = ipv6_addr;
            /* Update the host */
            host = host_copy;
        } else {
            /* Not an IP address, so it's a regular hostname */
            type = HOSTNAME_TYPE_REGULAR;
            /* Ignore the trailing dot in the hostname */
            host = aws_byte_cursor_right_trim_pred(&host, s_is_dot);
        }
    }

    char bits_buffer[8] = {'\0'};
    for (size_t i = 0; i < aws_array_list_length(&no_proxy_list); i++) {
        struct aws_byte_cursor pattern;
        if (aws_array_list_get_at(&no_proxy_list, &pattern, i)) {
            continue;
        }

        /* Trim whitespace from both ends for the pattern */
        pattern = aws_byte_cursor_trim_pred(&pattern, aws_isspace);
        if (pattern.len == 0) {
            /* If pattern is empty, ignore it. */
            continue;
        }
        switch (type) {
            case HOSTNAME_TYPE_REGULAR: {
                /**
                 * A: example.com matches 'example.com'
                 * B: www.example.com matches 'example.com'
                 * C: nonexample.com DOES NOT match 'example.com'
                 */
                /* Trim dot from both ends for the pattern */
                pattern = aws_byte_cursor_trim_pred(&pattern, s_is_dot);
                if (pattern.len == 0) {
                    /* If pattern is empty, ignore it. */
                    continue;
                }
                if (pattern.len == host.len) {
                    if (aws_byte_cursor_eq_ignore_case(&pattern, &host)) {
                        bypass = true;
                        goto cleanup;
                    } else {
                        continue;
                    }
                } else if (pattern.len < host.len) {
                    /* Check if the pattern is a suffix of the host. All the math is safe since pattern.len < host.len
                     */
                    struct aws_byte_cursor tail_with_extra_byte = host;
                    /* 1. the byte before the tail should be `.` */
                    aws_byte_cursor_advance(&tail_with_extra_byte, host.len - pattern.len - 1);
                    uint8_t var = 0;
                    /* tail_with_extra_byte will be updated to move over the `.` */
                    aws_byte_cursor_read_u8(&tail_with_extra_byte, &var);
                    if (var != '.') {
                        continue;
                    }
                    /* 2. the tail of the host should match the pattern */
                    if (aws_byte_cursor_eq_ignore_case(&pattern, &tail_with_extra_byte)) {
                        bypass = true;
                        goto cleanup;
                    } else {
                        continue;
                    }
                }
            } break;
            case HOSTNAME_TYPE_IPV4:
            case HOSTNAME_TYPE_IPV6: {
                /* Extract network part and bits from CIDR notation */
                struct aws_byte_cursor substr = {0};
                struct aws_byte_cursor network_part = {0};
                /* CIDR found. parse the bits */
                uint16_t network_bits = 0;
                if (aws_byte_cursor_next_split(&pattern, '/', &substr)) {
                    network_part = substr;
                }
                if (aws_byte_cursor_next_split(&pattern, '/', &substr)) {
                    /* This substr will be number of bits. */
                    if (substr.len > 8) {
                        /* Invalid, ignore it. */
                        continue;
                    }
                    memcpy(bits_buffer, substr.ptr, substr.len);
                    bits_buffer[substr.len] = '\0'; /* Null-terminate for atoi */
                    network_bits = (uint16_t)atoi(bits_buffer);
                }
                if (type == HOSTNAME_TYPE_IPV4) {
                    if (s_cidr4_match(network_bits, network_part, host_addr_ptr)) {
                        bypass = true;
                        goto cleanup;
                    }
                } else {
                    if (s_cidr6_match(network_bits, network_part, host_addr_ptr)) {
                        bypass = true;
                        goto cleanup;
                    }
                }
            } break;

            default:
                /* Invalid stage */
                AWS_FATAL_ASSERT(false);
                break;
        }
    }

cleanup:
    aws_array_list_clean_up(&no_proxy_list);
    aws_string_destroy(no_proxy_str);
    return bypass;
}
