#ifndef AWS_HTTP_STRUTIL_H
#define AWS_HTTP_STRUTIL_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/http/http.h>

AWS_EXTERN_C_BEGIN

/**
 * Read entire cursor as ASCII/UTF-8 unsigned base-10 number.
 * Stricter than strtoull(), which allows whitespace and inputs that start with "0x"
 *
 * Examples:
 * "0" -> 0
 * "123" -> 123
 * "00004" -> 4 // leading zeros ok
 *
 * Rejects things like:
 * "-1" // negative numbers not allowed
 * "1,000" // only characters 0-9 allowed
 * "" // blank string not allowed
 * " 0 " // whitespace not allowed
 * "0x0" // hex not allowed
 * "FF" // hex not allowed
 * "999999999999999999999999999999999999999999" // larger than max u64
 */
AWS_HTTP_API
int aws_strutil_read_unsigned_num(struct aws_byte_cursor cursor, uint64_t *dst);

/**
 * Read entire cursor as ASCII/UTF-8 unsigned base-16 number with NO "0x" prefix.
 *
 * Examples:
 * "F" -> 15
 * "000000ff" -> 255 // leading zeros ok
 * "Ff" -> 255 // mixed case ok
 * "123" -> 291
 * "FFFFFFFFFFFFFFFF" -> 18446744073709551616 // max u64
 *
 * Rejects things like:
 * "0x0" // 0x prefix not allowed
 * "" // blank string not allowed
 * " F " // whitespace not allowed
 * "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" // larger than max u64
 */
AWS_HTTP_API
int aws_strutil_read_unsigned_hex(struct aws_byte_cursor cursor, uint64_t *dst);

/**
 * Return a cursor with all leading and trailing SPACE and TAB characters removed.
 * RFC7230 section 3.2.3 Whitespace
 * Examples:
 * " \t a \t  " -> "a"
 * "a \t a" -> "a \t a"
 */
AWS_HTTP_API
struct aws_byte_cursor aws_strutil_trim_http_whitespace(struct aws_byte_cursor cursor);

/**
 * Return whether this is a valid token, as defined by RFC7230 section 3.2.6:
 *  token          = 1*tchar
 *  tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
 *                 / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
 *                 / DIGIT / ALPHA
 */
AWS_HTTP_API
bool aws_strutil_is_http_token(struct aws_byte_cursor token);

/**
 * Same as aws_strutil_is_http_token_valid(), but uppercase letters are forbidden.
 */
AWS_HTTP_API
bool aws_strutil_is_lowercase_http_token(struct aws_byte_cursor token);

AWS_EXTERN_C_END
#endif /* AWS_HTTP_STRUTIL_H */
