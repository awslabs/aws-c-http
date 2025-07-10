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

enum hostname_type {
    HOSTNAME_TYPE_IPV4,
    HOSTNAME_TYPE_IPV6,
    HOSTNAME_TYPE_REGULAR,
};

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
static bool s_cidr4_match(uint64_t bits, struct aws_string *network_part, uint32_t address) {

    uint32_t check = 0;

    /* Check for valid bits parameter */
    if (bits > 32) {
        /* Invalid netmask bits */
        return false;
    }

    /* Convert network pattern to binary */
    if (inet_pton(AF_INET, aws_string_c_str(network_part), &check) != 1) {
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
static bool s_cidr6_match(uint64_t bits, struct aws_string *network_part, uint8_t *address) {
    uint8_t check[16] = {0};

    /* If no bits specified, use full 128 bits for IPv6 */
    if (!bits) {
        bits = 128;
    }

    /* Check for valid bits parameter */
    if (bits > 128) {
        return false;
    }
    /* Convert network pattern to binary */
    if (inet_pton(AF_INET6, aws_string_c_str(network_part), check) != 1) {
        return false;
    }

    /* Calculate full bytes and remaining bits in the netmask */
    uint64_t bytes = bits / 8;
    uint64_t rest = bits % 8;

    /* Compare full bytes of the network part */
    if (bytes > 0 && memcmp(address, check, (size_t)bytes) != 0) {
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

/* The host is expected to be the host result from URL parser. */
bool aws_http_host_matches_no_proxy(
    struct aws_allocator *allocator,
    struct aws_byte_cursor host,
    struct aws_string *no_proxy_str) {
    if (host.len == 0 || no_proxy_str == NULL) {
        return false;
    }
    /* Single "*" wildcard matches all hosts */
    if (aws_string_eq_c_str(no_proxy_str, "*")) {
        AWS_LOGF_DEBUG(AWS_LS_HTTP_CONNECTION, "wildcard no_proxy found, bypassing any proxy");
        return true;
    }
    bool bypass = false;
    struct aws_byte_cursor no_proxy_cur = aws_byte_cursor_from_string(no_proxy_str);
    struct aws_array_list no_proxy_list;
    struct aws_string *host_str = aws_string_new_from_cursor(allocator, &host);

    if (aws_array_list_init_dynamic(&no_proxy_list, allocator, 10, sizeof(struct aws_byte_cursor))) {
        goto cleanup;
    }
    /* Split the NO_PROXY string by commas */
    if (aws_byte_cursor_split_on_char(&no_proxy_cur, ',', &no_proxy_list)) {
        goto cleanup;
    }

    /* Store parsed binary addresses for reuse */
    uint32_t ipv4_addr = 0;
    uint8_t ipv6_addr[16] = {0};

    /* Determine host type and parse address if applicable */
    enum hostname_type type = HOSTNAME_TYPE_REGULAR;
    if (inet_pton(AF_INET, aws_string_c_str(host_str), &ipv4_addr) == 1) {
        type = HOSTNAME_TYPE_IPV4;
    } else {
        struct aws_string *host_str_copy = host_str;
        struct aws_byte_cursor host_copy = host;
        if (host_copy.ptr[0] == '[' && host_copy.ptr[host_copy.len - 1] == ']') {
            /* Check if the address is enclosed in brackets and strip them for validation */
            aws_byte_cursor_advance(&host_copy, 1);
            host_copy.len--;
            host_str_copy = aws_string_new_from_cursor(allocator, &host_copy);
        }

        if (inet_pton(AF_INET6, aws_string_c_str(host_str_copy), ipv6_addr) == 1) {
            /* Update the host str */
            if (host_str != host_str_copy) {
                aws_string_destroy(host_str);
                host_str = host_str_copy;
            }
            type = HOSTNAME_TYPE_IPV6;
        } else {
            /* Not an IP address, so it's a regular hostname */
            type = HOSTNAME_TYPE_REGULAR;
            /* Ignore the trailing dot in the hostname */
            host = aws_byte_cursor_right_trim_pred(&host, s_is_dot);
        }
        if (host_str != host_str_copy) {
            /* clean up the copy, but don't update the str. */
            aws_string_destroy(host_str_copy);
        }
    }

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
                    /* Check if the pattern is a suffix of the host. All the math is safe since pattern.len <
                     * host.len
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
                uint64_t network_bits = 0;
                if (aws_byte_cursor_next_split(&pattern, '/', &substr)) {
                    network_part = substr;
                }
                if (aws_byte_cursor_next_split(&pattern, '/', &substr)) {
                    /* There is a second part of the pattern after `/`. */
                    /* Now, take the rest of the pattern after `/` as the bits */
                    aws_byte_cursor_advance(&pattern, network_part.len + 1);
                    if (aws_byte_cursor_utf8_parse_u64(pattern, &network_bits)) {
                        continue;
                    }
                }
                struct aws_string *network_part_str = aws_string_new_from_cursor(allocator, &network_part);
                if (type == HOSTNAME_TYPE_IPV4) {
                    if (s_cidr4_match(network_bits, network_part_str, ipv4_addr)) {
                        bypass = true;
                        aws_string_destroy(network_part_str);
                        goto cleanup;
                    }
                } else {
                    if (s_cidr6_match(network_bits, network_part_str, ipv6_addr)) {
                        bypass = true;
                        aws_string_destroy(network_part_str);
                        goto cleanup;
                    }
                }
                aws_string_destroy(network_part_str);
            } break;

            default:
                /* Invalid stage */
                AWS_FATAL_ASSERT(false);
                break;
        }
    }

cleanup:
    aws_string_destroy(host_str);
    aws_array_list_clean_up(&no_proxy_list);
    return bypass;
}
