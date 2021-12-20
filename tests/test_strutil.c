/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/http/private/strutil.h>

#include <aws/testing/aws_test_harness.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

AWS_TEST_CASE(strutil_trim_http_whitespace, s_strutil_trim_http_whitespace);
static int s_strutil_trim_http_whitespace(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct test {
        const char *input;
        const char *expected;
    };

    struct test tests[] = {
        {"a", "a"},
        {" a", "a"},
        {"a ", "a"},
        {"  a  ", "a"},
        {"", ""},
        {" ", ""},
        {"         ", ""},
        {"a", "a"},
        {"\t", ""},
        {"\ta", "a"},
        {"a\t", "a"},
        {"\t a \t", "a"},
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(tests); ++i) {
        struct aws_byte_cursor input = aws_byte_cursor_from_c_str(tests[i].input);
        struct aws_byte_cursor expected = aws_byte_cursor_from_c_str(tests[i].expected);
        struct aws_byte_cursor trimmed = aws_strutil_trim_http_whitespace(input);
        ASSERT_TRUE(aws_byte_cursor_eq(&expected, &trimmed));
    }

    return 0;
}

AWS_TEST_CASE(strutil_is_http_token, s_strutil_is_http_token);
static int s_strutil_is_http_token(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* sanity check */
    ASSERT_TRUE(aws_strutil_is_http_token(aws_byte_cursor_from_c_str("A")));
    ASSERT_TRUE(aws_strutil_is_http_token(aws_byte_cursor_from_c_str("Host")));

    /* must be at least 1 character long*/
    ASSERT_FALSE(aws_strutil_is_http_token(aws_byte_cursor_from_c_str("")));

    /* all acceptable characters (RFC-7230 3.2.6 - tchar)*/
    const char *all_acceptable = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t all_acceptable_strlen = strlen(all_acceptable);
    ASSERT_TRUE(aws_strutil_is_http_token(aws_byte_cursor_from_c_str(all_acceptable)));

    /* brute force over every character, and be sure it fails if it's not in the acceptable list */
    for (size_t i = 0; i < 256; ++i) {
        uint8_t c = (uint8_t)i;
        bool is_acceptable = memchr(all_acceptable, c, all_acceptable_strlen) != NULL;
        ASSERT_UINT_EQUALS(is_acceptable, aws_strutil_is_http_token(aws_byte_cursor_from_array(&c, 1)));
    }

    return 0;
}

AWS_TEST_CASE(strutil_is_lowercase_http_token, s_strutil_is_lowercase_http_token);
static int s_strutil_is_lowercase_http_token(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* sanity check */
    ASSERT_TRUE(aws_strutil_is_lowercase_http_token(aws_byte_cursor_from_c_str("a")));
    ASSERT_TRUE(aws_strutil_is_lowercase_http_token(aws_byte_cursor_from_c_str("host")));

    /* must be at least 1 character long*/
    ASSERT_FALSE(aws_strutil_is_lowercase_http_token(aws_byte_cursor_from_c_str("")));

    /* forbidden characters */
    ASSERT_FALSE(aws_strutil_is_lowercase_http_token(aws_byte_cursor_from_c_str("Host")));
    ASSERT_FALSE(aws_strutil_is_lowercase_http_token(aws_byte_cursor_from_c_str(":\"")));

    /* all acceptable characters (RFC-7230 3.2.6 - tchar, but with uppercase removed) */
    const char *all_acceptable = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz";
    const size_t all_acceptable_strlen = strlen(all_acceptable);
    ASSERT_TRUE(aws_strutil_is_lowercase_http_token(aws_byte_cursor_from_c_str(all_acceptable)));

    /* brute force over every character, and be sure it fails if it's not in the acceptable list */
    for (size_t i = 0; i < 256; ++i) {
        uint8_t c = (uint8_t)i;
        bool is_acceptable = memchr(all_acceptable, c, all_acceptable_strlen) != NULL;
        ASSERT_UINT_EQUALS(is_acceptable, aws_strutil_is_lowercase_http_token(aws_byte_cursor_from_array(&c, 1)));
    }

    return 0;
}

AWS_TEST_CASE(strutil_is_http_field_value, s_strutil_is_http_field_value);
static int s_strutil_is_http_field_value(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* sanity check */
    ASSERT_TRUE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("0")));
    ASSERT_TRUE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("en")));

    /* OK to have empty value */
    ASSERT_TRUE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("")));

    /* OK to have whitespace in the middle */
    ASSERT_TRUE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("a b")));
    ASSERT_TRUE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("a\tb")));
    ASSERT_TRUE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("a\t\t  \t\t  b")));

    /* Bad to have whitespace at the start or the end */
    ASSERT_FALSE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str(" 999")));
    ASSERT_FALSE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("999 ")));
    ASSERT_FALSE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("\t999")));
    ASSERT_FALSE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("999\t")));

    /* OK to use UTF-8 */
    ASSERT_TRUE(aws_strutil_is_http_field_value(
        aws_byte_cursor_from_c_str("\xF0\x9F\x91\x81\xF0\x9F\x91\x84\xF0\x9F\x91\x81")));

    /* Bad to have line-folds */
    ASSERT_FALSE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("item1\r\n item2")));
    ASSERT_FALSE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("item1\r item2")));
    ASSERT_FALSE(aws_strutil_is_http_field_value(aws_byte_cursor_from_c_str("item1\n item2")));

    /* The implementation uses a table of valid characters (for speed reasons).
     * Lets test every possible byte value and make sure it lines up with what we expect.
     * We'll put the test byte at index [1] of an otherwise valid string */
    char mutable_str[] = {'a', 'b', 'c'};
    for (size_t i = 0; i < 256; ++i) {
        /* Grammar looks like:
         * field-value    = *( field-content / obs-fold ) ; we're forbidding obs-fold so ignore it
         * field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
         * field-vchar    = VCHAR / obs-text
         * VCHAR          = %x21-7E ; visible (printing) characters
         * obs-text       = %x80-FF
         */
        bool allowed_in_grammar = (/*SP*/ i == ' ') || (/*HTAB*/ i == '\t') || (/*VCHAR*/ i >= 0x21 && i <= 0x7E) ||
                                  (/*obs-text*/ i >= 0x80 && i <= 0xFF);

        mutable_str[1] = (char)i;
        struct aws_byte_cursor cursor = aws_byte_cursor_from_array(mutable_str, AWS_ARRAY_SIZE(mutable_str));
        bool passes = aws_strutil_is_http_field_value(cursor);
        ASSERT_INT_EQUALS(allowed_in_grammar, passes, "failed at character 0x%02X", i);
    }

    return 0;
}

AWS_TEST_CASE(strutil_is_http_reason_phrase, s_strutil_is_http_reason_phrase);
static int s_strutil_is_http_reason_phrase(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* sanity check */
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("OK")));

    /* OK to have empty value */
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("")));

    /* OK to have whitespace in the middle, beginning, or end */
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("Not Found")));
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("Not\tFound")));
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str(" Not Found")));
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("Not Found ")));
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("\t Not\t\t  Found \t")));
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str(" ")));
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("\t")));

    /* OK to use UTF-8 */
    ASSERT_TRUE(aws_strutil_is_http_reason_phrase(
        aws_byte_cursor_from_c_str("\xF0\x9F\x91\x81\xF0\x9F\x91\x84\xF0\x9F\x91\x81")));

    /* Bad to have line-folds or other anything like it*/
    ASSERT_FALSE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("Line\r\nFolds")));
    ASSERT_FALSE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("Line\rFeed")));
    ASSERT_FALSE(aws_strutil_is_http_reason_phrase(aws_byte_cursor_from_c_str("New\nLine")));

    /* The implementation uses a table of valid characters (for speed reasons).
     * Lets test every possible byte value and make sure it lines up with what we expect.
     * We'll put the test byte at index [1] of an otherwise valid string */
    char mutable_str[] = {'a', 'b', 'c'};
    for (size_t i = 0; i < 256; ++i) {
        /* Grammar looks like:
         * reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
         * VCHAR          = %x21-7E ; visible (printing) characters
         * obs-text       = %x80-FF
         */
        bool allowed_in_grammar = (/*SP*/ i == ' ') || (/*HTAB*/ i == '\t') || (/*VCHAR*/ i >= 0x21 && i <= 0x7E) ||
                                  (/*obs-text*/ i >= 0x80 && i <= 0xFF);

        mutable_str[1] = (char)i;
        struct aws_byte_cursor cursor = aws_byte_cursor_from_array(mutable_str, AWS_ARRAY_SIZE(mutable_str));
        bool passes = aws_strutil_is_http_reason_phrase(cursor);
        ASSERT_INT_EQUALS(allowed_in_grammar, passes, "failed at character 0x%02X", i);
    }

    return 0;
}

AWS_TEST_CASE(strutil_is_http_request_target, s_strutil_is_http_request_target);
static int s_strutil_is_http_request_target(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* sanity check */
    ASSERT_TRUE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("/")));

    /* Bad to have empty value */
    ASSERT_FALSE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("")));

    /* Bad to have non-visible ascii */
    ASSERT_FALSE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str(" ")));
    ASSERT_FALSE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("/spaces-are-bad .html")));
    ASSERT_FALSE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("/tabs-are-bad\t.html")));
    ASSERT_FALSE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("/crlf-is-really-bad\r\n.html")));
    ASSERT_FALSE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("/newline-is-bad\n.html")));
    ASSERT_FALSE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("/linefeed-is-bad\r.html")));

    /* OK origin-form */
    ASSERT_TRUE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("/where?q=now")));

    /* OK absolute-form */
    ASSERT_TRUE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("http://www.amazon.com/index.html")));

    /* OK authority-form */
    ASSERT_TRUE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("www.example.com:80")));

    /* OK asterisk-form */
    ASSERT_TRUE(aws_strutil_is_http_request_target(aws_byte_cursor_from_c_str("*")));

    /* TODO: Actually check the complete grammar as defined in RFC7230 5.3 and
     * RFC3986. Currently this just checks whether the sequence is blatantly illegal
     * (ex: contains CR or LF) */

    return 0;
}

AWS_TEST_CASE(strutil_is_http_pseudo_header_name, s_strutil_is_http_pseudo_header_name);
static int s_strutil_is_http_pseudo_header_name(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* sanity check */
    ASSERT_TRUE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str(":method")));
    ASSERT_TRUE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str(":scheme")));
    ASSERT_TRUE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str(":authority")));
    ASSERT_TRUE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str(":path")));
    ASSERT_TRUE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str(":status")));

    /* Bad to have empty value */
    ASSERT_FALSE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str("")));

    /* Bad to have other values */
    ASSERT_FALSE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str("connect")));
    ASSERT_FALSE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str("Method")));
    ASSERT_FALSE(aws_strutil_is_http_pseudo_header_name(aws_byte_cursor_from_c_str("httpCRT")));
    return 0;
}
