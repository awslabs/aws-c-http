/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/string.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/testing/aws_test_harness.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)
#define DEFINE_HEADER(NAME, VALUE)                                                                                     \
    { .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(NAME), .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(VALUE), }

TEST_CASE(message_sanity_check) {
    (void)ctx;
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);
    aws_http_message_destroy(request);

    struct aws_http_message *response = aws_http_message_new_response(allocator);
    ASSERT_NOT_NULL(response);
    aws_http_message_destroy(response);

    return AWS_OP_SUCCESS;
}

TEST_CASE(message_request_path) {
    (void)ctx;
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    /* Assert that query fails when there's no data */
    struct aws_byte_cursor get;
    ASSERT_ERROR(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE, aws_http_message_get_request_path(request, &get));

    /* Test simple set/get */
    char path1[] = "/";
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str(path1)));
    ASSERT_SUCCESS(aws_http_message_get_request_path(request, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, path1));

    /* Mutilate the original string to be sure request wasn't referencing its memory */
    path1[0] = 'z';
    struct aws_byte_cursor path1_repro = aws_byte_cursor_from_c_str("/");
    ASSERT_TRUE(aws_byte_cursor_eq(&path1_repro, &get));

    /* Set a new path */
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/index.html")));
    ASSERT_SUCCESS(aws_http_message_get_request_path(request, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "/index.html"));

    aws_http_message_destroy(request);
    return AWS_OP_SUCCESS;
}
TEST_CASE(message_request_method) {
    (void)ctx;
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    /* Assert that query fails when there's no data */
    struct aws_byte_cursor get;
    ASSERT_ERROR(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE, aws_http_message_get_request_method(request, &get));

    /* Test simple set/get */
    char method1[] = "GET";
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str(method1)));
    ASSERT_SUCCESS(aws_http_message_get_request_method(request, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, method1));

    /* Mutilate the original string to be sure request wasn't referencing its memory */
    method1[0] = 'B';
    ASSERT_TRUE(aws_byte_cursor_eq(&aws_http_method_get, &get));

    /* Set a new method */
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_http_method_post));
    ASSERT_SUCCESS(aws_http_message_get_request_method(request, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "POST"));

    aws_http_message_destroy(request);
    return AWS_OP_SUCCESS;
}

TEST_CASE(message_response_status) {
    (void)ctx;
    struct aws_http_message *response = aws_http_message_new_response(allocator);
    ASSERT_NOT_NULL(response);

    /* Assert that query fails when there's no data */
    int get;
    ASSERT_ERROR(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE, aws_http_message_get_response_status(response, &get));

    /* Test simple set/get */
    ASSERT_SUCCESS(aws_http_message_set_response_status(response, AWS_HTTP_STATUS_CODE_200_OK));
    ASSERT_SUCCESS(aws_http_message_get_response_status(response, &get));
    ASSERT_INT_EQUALS(AWS_HTTP_STATUS_CODE_200_OK, get);

    /* Set a new status */
    ASSERT_SUCCESS(aws_http_message_set_response_status(response, AWS_HTTP_STATUS_CODE_404_NOT_FOUND));
    ASSERT_SUCCESS(aws_http_message_get_response_status(response, &get));
    ASSERT_INT_EQUALS(AWS_HTTP_STATUS_CODE_404_NOT_FOUND, get);

    aws_http_message_destroy(response);
    return AWS_OP_SUCCESS;
}

static struct aws_http_header s_make_header(const char *name, const char *value) {
    return (struct aws_http_header){
        .name = aws_byte_cursor_from_c_str(name),
        .value = aws_byte_cursor_from_c_str(value),
    };
}

static int s_check_headers_eq(struct aws_http_header a, struct aws_http_header b) {
    ASSERT_TRUE(aws_byte_cursor_eq(&a.name, &b.name));
    ASSERT_TRUE(aws_byte_cursor_eq(&a.value, &b.value));
    return AWS_OP_SUCCESS;
}

static int s_check_header_eq(struct aws_http_header header, const char *name, const char *value) {
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&header.name, name));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&header.value, value));
    return AWS_OP_SUCCESS;
}

static int s_check_value_eq(struct aws_byte_cursor cursor, const char *value) {
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&cursor, value));
    return AWS_OP_SUCCESS;
}

TEST_CASE(headers_add) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    char name_src[] = "Host";
    char value_src[] = "example.com";

    ASSERT_SUCCESS(
        aws_http_headers_add(headers, aws_byte_cursor_from_c_str(name_src), aws_byte_cursor_from_c_str(value_src)));

    ASSERT_UINT_EQUALS(1, aws_http_headers_count(headers));

    /* Mutilate source strings to be sure the datastructure isn't referencing their memory */
    name_src[0] = 0;
    value_src[0] = 0;

    /* get-by-index */
    struct aws_http_header get;
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 0, &get));
    ASSERT_SUCCESS(s_check_header_eq(get, "Host", "example.com"));

    /* get-by-name (ignore case) */
    struct aws_byte_cursor value_get;
    ASSERT_SUCCESS(aws_http_headers_get(headers, aws_byte_cursor_from_c_str("host"), &value_get)); /* ignore case */
    ASSERT_SUCCESS(s_check_value_eq(value_get, "example.com"));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(headers_add_array) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    const struct aws_http_header src_headers[] = {
        s_make_header("Cookie", "a=1"),
        s_make_header("COOKIE", "b=2"),
    };

    ASSERT_SUCCESS(aws_http_headers_add_array(headers, src_headers, AWS_ARRAY_SIZE(src_headers)));
    ASSERT_UINT_EQUALS(AWS_ARRAY_SIZE(src_headers), aws_http_headers_count(headers));

    for (size_t i = 0; i < AWS_ARRAY_SIZE(src_headers); ++i) {
        struct aws_http_header get;
        ASSERT_SUCCESS(aws_http_headers_get_index(headers, i, &get));
        ASSERT_SUCCESS(s_check_headers_eq(src_headers[i], get));
    }

    /* check that get-by-name returns first one it sees */
    struct aws_byte_cursor get;
    ASSERT_SUCCESS(aws_http_headers_get(headers, aws_byte_cursor_from_c_str("COOKIE"), &get));
    ASSERT_SUCCESS(s_check_value_eq(get, "a=1"));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(headers_set) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    /* Check that set() can add a new header */
    ASSERT_SUCCESS(
        aws_http_headers_set(headers, aws_byte_cursor_from_c_str("Cookie"), aws_byte_cursor_from_c_str("a=1")));

    struct aws_http_header get;
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 0, &get));
    ASSERT_SUCCESS(s_check_header_eq(get, "Cookie", "a=1"));

    /* Add more headers with same name, then check that set() replaces them ALL */
    const struct aws_http_header src_headers[] = {
        s_make_header("Cookie", "b=2"),
        s_make_header("COOKIE", "c=3"),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(headers, src_headers, AWS_ARRAY_SIZE(src_headers)));

    ASSERT_SUCCESS(
        aws_http_headers_set(headers, aws_byte_cursor_from_c_str("Cookie"), aws_byte_cursor_from_c_str("d=4")));

    ASSERT_UINT_EQUALS(1, aws_http_headers_count(headers));

    struct aws_byte_cursor value_get;
    ASSERT_SUCCESS(aws_http_headers_get(headers, aws_byte_cursor_from_c_str("cookie"), &value_get));
    ASSERT_SUCCESS(s_check_value_eq(value_get, "d=4"));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(headers_erase_index) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    const struct aws_http_header src_headers[] = {
        s_make_header("Cookie", "a=1"),
        s_make_header("Cookie", "b=2"),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(headers, src_headers, AWS_ARRAY_SIZE(src_headers)));

    /* Ensure bad attempts to erase data are detected */
    ASSERT_ERROR(AWS_ERROR_INVALID_INDEX, aws_http_headers_erase_index(headers, 99));

    /* Erase by index */
    ASSERT_SUCCESS(aws_http_headers_erase_index(headers, 0));

    ASSERT_UINT_EQUALS(1, aws_http_headers_count(headers));

    struct aws_http_header get;
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 0, &get));
    ASSERT_SUCCESS(s_check_header_eq(get, "Cookie", "b=2"));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(headers_erase) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    const struct aws_http_header src_headers[] = {
        s_make_header("cookie", "a=1"),
        s_make_header("CoOkIe", "b=2"),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(headers, src_headers, AWS_ARRAY_SIZE(src_headers)));

    /* Ensure bad attempts to erase data are detected */
    ASSERT_ERROR(AWS_ERROR_HTTP_HEADER_NOT_FOUND, aws_http_headers_erase(headers, aws_byte_cursor_from_c_str("asdf")));

    ASSERT_SUCCESS(aws_http_headers_erase(headers, aws_byte_cursor_from_c_str("COOKIE")));

    ASSERT_UINT_EQUALS(0, aws_http_headers_count(headers));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(headers_erase_value) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    const struct aws_http_header src_headers[] = {
        s_make_header("Cookie", "a=1"),
        s_make_header("CoOkIe", "b=2"),
        s_make_header("COOKIE", "b=2"),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(headers, src_headers, AWS_ARRAY_SIZE(src_headers)));

    /* Ensure bad attempts to erase data are detected */
    ASSERT_ERROR(
        AWS_ERROR_HTTP_HEADER_NOT_FOUND,
        aws_http_headers_erase_value(
            headers, aws_byte_cursor_from_c_str("cookie"), aws_byte_cursor_from_c_str("asdf")));

    /* Pluck out the first instance of b=2 */
    ASSERT_SUCCESS(
        aws_http_headers_erase_value(headers, aws_byte_cursor_from_c_str("cookie"), aws_byte_cursor_from_c_str("b=2")));

    ASSERT_UINT_EQUALS(2, aws_http_headers_count(headers));

    struct aws_http_header get;
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 0, &get));
    ASSERT_SUCCESS(s_check_header_eq(get, "Cookie", "a=1"));

    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 1, &get));
    ASSERT_SUCCESS(s_check_header_eq(get, "COOKIE", "b=2"));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(headers_clear) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    const struct aws_http_header src_headers[] = {
        s_make_header("Host", "example.com"),
        s_make_header("Cookie", "a=1"),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(headers, src_headers, AWS_ARRAY_SIZE(src_headers)));

    aws_http_headers_clear(headers);
    ASSERT_UINT_EQUALS(0, aws_http_headers_count(headers));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(headers_get_all) {
    (void)ctx;

    struct aws_http_headers *headers = aws_http_headers_new(allocator);

    /* Check when no such headers exist */
    aws_http_headers_clear(headers);
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("Host"), aws_byte_cursor_from_c_str("example.com"));
    ASSERT_NULL(aws_http_headers_get_all(headers, aws_byte_cursor_from_c_str("X-My-List")));
    ASSERT_INT_EQUALS(AWS_ERROR_HTTP_HEADER_NOT_FOUND, aws_last_error());

    /* Check getting a single value */
    aws_http_headers_clear(headers);
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("Host"), aws_byte_cursor_from_c_str("example.com"));
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("X-My-List"), aws_byte_cursor_from_c_str("A"));
    struct aws_string *value = aws_http_headers_get_all(headers, aws_byte_cursor_from_c_str("X-My-List"));
    ASSERT_NOT_NULL(value);
    ASSERT_TRUE(aws_string_eq_c_str(value, "A"));
    aws_string_destroy(value);

    /* Check getting a blank-string value */
    aws_http_headers_clear(headers);
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("Host"), aws_byte_cursor_from_c_str("example.com"));
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("X-My-List"), aws_byte_cursor_from_c_str(""));
    value = aws_http_headers_get_all(headers, aws_byte_cursor_from_c_str("X-My-List"));
    ASSERT_NOT_NULL(value);
    ASSERT_TRUE(aws_string_eq_c_str(value, ""));
    aws_string_destroy(value);

    /* Check getting multiple values */
    aws_http_headers_clear(headers);
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("Host"), aws_byte_cursor_from_c_str("example.com"));
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("X-My-List"), aws_byte_cursor_from_c_str("A"));
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("X-My-List"), aws_byte_cursor_from_c_str("B"));
    value = aws_http_headers_get_all(headers, aws_byte_cursor_from_c_str("X-My-List"));
    ASSERT_NOT_NULL(value);
    ASSERT_TRUE(aws_string_eq_c_str(value, "A, B"));
    aws_string_destroy(value);

    /* Check more edge cases */
    aws_http_headers_clear(headers);
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("Host"), aws_byte_cursor_from_c_str("example.com"));
    /* some fields have single entry, some fields have multiple entries */
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("X-My-List"), aws_byte_cursor_from_c_str("A, B"));
    /* preserve whitespace within middle of value. also name is different case  */
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("x-my-list"), aws_byte_cursor_from_c_str("C,D"));
    aws_http_headers_add(
        headers, aws_byte_cursor_from_c_str("X-My-List-"), aws_byte_cursor_from_c_str("BAD-EXTRA-DASH"));
    /* name is different case, and blank value*/
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("X-MY-LIST"), aws_byte_cursor_from_c_str(""));
    aws_http_headers_add(headers, aws_byte_cursor_from_c_str("x-my-list"), aws_byte_cursor_from_c_str("E"));
    value = aws_http_headers_get_all(headers, aws_byte_cursor_from_c_str("X-My-List"));
    ASSERT_NOT_NULL(value);
    ASSERT_TRUE(aws_string_eq_c_str(value, "A, B, C,D, , E"));
    aws_string_destroy(value);

    /* Done */
    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_headers_request_pseudos_get_set) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);
    const struct aws_http_header src_headers[] = {
        s_make_header("Host", "example.com"),
        s_make_header("Cookie", "a=1"),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(headers, src_headers, AWS_ARRAY_SIZE(src_headers)));

    ASSERT_SUCCESS(aws_http2_headers_set_request_method(headers, aws_byte_cursor_from_c_str("GET")));
    ASSERT_SUCCESS(aws_http2_headers_set_request_scheme(headers, aws_byte_cursor_from_c_str("https")));
    ASSERT_SUCCESS(aws_http2_headers_set_request_authority(headers, aws_byte_cursor_from_c_str("www.amazon.com")));
    ASSERT_SUCCESS(aws_http2_headers_set_request_path(headers, aws_byte_cursor_from_c_str("/")));

    /* pseudo headers should be in the front of headers */
    struct aws_byte_cursor get;
    ASSERT_SUCCESS(aws_http2_headers_get_request_method(headers, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "GET"));
    ASSERT_SUCCESS(aws_http2_headers_get_request_scheme(headers, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "https"));
    ASSERT_SUCCESS(aws_http2_headers_get_request_authority(headers, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "www.amazon.com"));
    ASSERT_SUCCESS(aws_http2_headers_get_request_path(headers, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "/"));
    /* normal headers should be the end of the headers list */
    struct aws_http_header get_header;
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 4, &get_header));
    ASSERT_SUCCESS(s_check_header_eq(get_header, "Host", "example.com"));
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 5, &get_header));
    ASSERT_SUCCESS(s_check_header_eq(get_header, "Cookie", "a=1"));

    /* overwrite method should not change the normal headers */
    ASSERT_SUCCESS(aws_http2_headers_set_request_method(headers, aws_byte_cursor_from_c_str("PUT")));
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 4, &get_header));
    ASSERT_SUCCESS(s_check_header_eq(get_header, "Host", "example.com"));
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 5, &get_header));
    ASSERT_SUCCESS(s_check_header_eq(get_header, "Cookie", "a=1"));
    ASSERT_SUCCESS(aws_http2_headers_get_request_method(headers, &get));
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "PUT"));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(h2_headers_response_pseudos_get_set) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);
    const struct aws_http_header src_headers[] = {
        s_make_header("Host", "example.com"),
        s_make_header("Cookie", "a=1"),
    };
    ASSERT_SUCCESS(aws_http_headers_add_array(headers, src_headers, AWS_ARRAY_SIZE(src_headers)));

    ASSERT_SUCCESS(aws_http2_headers_set_response_status(headers, 200));

    /* pseudo headers should be in the front of headers */
    int get;
    ASSERT_SUCCESS(aws_http2_headers_get_response_status(headers, &get));
    ASSERT_INT_EQUALS(get, 200);
    /* normal headers should be the end of the headers list */
    struct aws_http_header get_header;
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 1, &get_header));
    ASSERT_SUCCESS(s_check_header_eq(get_header, "Host", "example.com"));
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 2, &get_header));
    ASSERT_SUCCESS(s_check_header_eq(get_header, "Cookie", "a=1"));

    /* overwrite method should not change the normal headers */
    ASSERT_SUCCESS(aws_http2_headers_set_response_status(headers, 404));
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 1, &get_header));
    ASSERT_SUCCESS(s_check_header_eq(get_header, "Host", "example.com"));
    ASSERT_SUCCESS(aws_http_headers_get_index(headers, 2, &get_header));
    ASSERT_SUCCESS(s_check_header_eq(get_header, "Cookie", "a=1"));
    ASSERT_SUCCESS(aws_http2_headers_get_response_status(headers, &get));
    ASSERT_INT_EQUALS(get, 404);

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(message_refcounts) {
    (void)ctx;
    struct aws_http_message *message = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(message);

    struct aws_http_headers *headers = aws_http_message_get_headers(message);
    ASSERT_NOT_NULL(headers);

    /* assert message is still valid after acquire/release */
    aws_http_message_acquire(message);
    aws_http_message_release(message);
    ASSERT_SUCCESS(aws_http_message_set_request_path(message, aws_byte_cursor_from_c_str("PATCH")));

    /* keep headers alive after message is destroyed */
    aws_http_headers_acquire(headers);
    aws_http_message_release(message);
    ASSERT_FALSE(aws_http_headers_has(headers, aws_byte_cursor_from_c_str("Host")));
    ASSERT_SUCCESS(
        aws_http_headers_add(headers, aws_byte_cursor_from_c_str("Host"), aws_byte_cursor_from_c_str("example.com")));
    ASSERT_TRUE(aws_http_headers_has(headers, aws_byte_cursor_from_c_str("Host")));

    aws_http_headers_release(headers);
    return AWS_OP_SUCCESS;
}

TEST_CASE(message_with_existing_headers) {
    (void)ctx;
    struct aws_http_headers *headers = aws_http_headers_new(allocator);
    ASSERT_NOT_NULL(headers);

    struct aws_http_message *message = aws_http_message_new_request_with_headers(allocator, headers);
    ASSERT_NOT_NULL(message);

    ASSERT_PTR_EQUALS(headers, aws_http_message_get_headers(message));

    /* assert message has acquired hold on headers */
    aws_http_headers_release(headers);

    /* still valid, right? */
    struct aws_http_header new_header = {aws_byte_cursor_from_c_str("Host"), aws_byte_cursor_from_c_str("example.com")};
    ASSERT_SUCCESS(aws_http_message_add_header(message, new_header));

    /* clean up*/
    aws_http_message_release(message);
    return AWS_OP_SUCCESS;
}
