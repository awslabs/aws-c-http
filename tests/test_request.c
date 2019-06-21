/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/http/request_response.h>

#include <aws/common/string.h>
#include <aws/testing/aws_test_harness.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

TEST_CASE(request_sanity_check) {
    (void)ctx;
    struct aws_http_request request;
    ASSERT_SUCCESS(aws_http_request_init(&request, allocator));

    aws_http_request_clean_up(&request);
    return AWS_OP_SUCCESS;
}

TEST_CASE(request_method) {
    (void)ctx;
    struct aws_http_request request;
    ASSERT_SUCCESS(aws_http_request_init(&request, allocator));

    /* Assert that an empty byte cursor is returned when no path has been set */
    struct aws_byte_cursor get = aws_http_request_get_path(&request);
    ASSERT_UINT_EQUALS(0, get.len);
    ASSERT_TRUE(aws_byte_cursor_is_valid(&get));

    /* Test simple set/get */
    char path1[] = "/";
    ASSERT_SUCCESS(aws_http_request_set_path(&request, aws_byte_cursor_from_c_str(path1)));
    get = aws_http_request_get_path(&request);
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, path1));

    /* Mutilate the original string to be sure request wasn't referencing its memory */
    path1[0] = 'z';
    struct aws_byte_cursor path1_repro = aws_byte_cursor_from_c_str("/");
    ASSERT_TRUE(aws_byte_cursor_eq(&path1_repro, &get));

    /* Set a new path */
    ASSERT_SUCCESS(aws_http_request_set_path(&request, aws_byte_cursor_from_c_str("/index.html")));
    get = aws_http_request_get_path(&request);
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "/index.html"));

    aws_http_request_clean_up(&request);
    return AWS_OP_SUCCESS;
}

TEST_CASE(request_path) {
    (void)ctx;
    struct aws_http_request request;
    ASSERT_SUCCESS(aws_http_request_init(&request, allocator));

    ASSERT_SUCCESS(aws_http_request_set_method(&request, aws_byte_cursor_from_c_str("GET")));
    struct aws_byte_cursor get = aws_http_request_get_method(&request);
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&get, "GET"));

    /* set_path and set_method use all the same helper functions, so this test is basic */

    aws_http_request_clean_up(&request);
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

TEST_CASE(request_add_headers) {
    (void)ctx;
    struct aws_http_request request;
    ASSERT_SUCCESS(aws_http_request_init(&request, allocator));

    ASSERT_UINT_EQUALS(0, aws_http_request_get_header_count(&request));

    /* Add a header */
    char name_src[] = "Host";
    char value_src[] = "example.com";

    ASSERT_SUCCESS(aws_http_request_add_header(&request, s_make_header(name_src, value_src)));
    ASSERT_UINT_EQUALS(1, aws_http_request_get_header_count(&request));

    /* Mutilate source strings to be sure the request isn't referencing their memory */
    name_src[0] = 0;
    value_src[0] = 0;

    /* Check values */
    struct aws_http_header get = aws_http_request_get_header(&request, 0);
    ASSERT_SUCCESS(s_check_header_eq(get, "Host", "example.com"));

    aws_http_request_clean_up(&request);
    return AWS_OP_SUCCESS;
}

TEST_CASE(request_erase_headers) {
    (void)ctx;
    struct aws_http_request request;
    ASSERT_SUCCESS(aws_http_request_init(&request, allocator));

    struct aws_http_header src_headers[] = {
        s_make_header("NameA", "ValueA"),
        s_make_header("NameB", "ValueB"),
        s_make_header("NameC", "ValueC"),
        s_make_header("NameD", "ValueD"),
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(src_headers); ++i) {
        ASSERT_SUCCESS(aws_http_request_add_header(&request, src_headers[i]));
    }

    for (size_t i = 0; i < AWS_ARRAY_SIZE(src_headers); ++i) {
        struct aws_http_header header_i = aws_http_request_get_header(&request, i);
        ASSERT_SUCCESS(s_check_headers_eq(src_headers[i], header_i));
    }

    /* Remove a middle one and check */
    const size_t kill_i = 1;
    aws_http_request_erase_header(&request, kill_i);
    ASSERT_UINT_EQUALS(AWS_ARRAY_SIZE(src_headers) - 1, aws_http_request_get_header_count(&request));

    for (size_t i = 0; i < aws_http_request_get_header_count(&request); ++i) {
        /* Headers to the right should have shifted over */
        size_t compare_i = (i < kill_i) ? i : (i + 1);

        struct aws_http_header req_header = aws_http_request_get_header(&request, i);
        ASSERT_SUCCESS(s_check_headers_eq(src_headers[compare_i], req_header));
    }

    /* Remove a front and a back header, only "NameC: ValueC" should remain */
    aws_http_request_erase_header(&request, 0);
    aws_http_request_erase_header(&request, aws_http_request_get_header_count(&request) - 1);

    ASSERT_UINT_EQUALS(1, aws_http_request_get_header_count(&request));
    ASSERT_SUCCESS(s_check_header_eq(aws_http_request_get_header(&request, 0), "NameC", "ValueC"));

    /* Ensure that add() still works after remove() */
    ASSERT_SUCCESS(aws_http_request_add_header(&request, s_make_header("Big", "Guy")));
    struct aws_http_header get = aws_http_request_get_header(&request, aws_http_request_get_header_count(&request) - 1);
    ASSERT_SUCCESS(s_check_header_eq(get, "Big", "Guy"));

    aws_http_request_clean_up(&request);
    return AWS_OP_SUCCESS;
}

TEST_CASE(request_do_invalid_stuff) {
    (void)ctx;
    struct aws_http_request request;
    ASSERT_SUCCESS(aws_http_request_init(&request, allocator));

    /* Should be fine to try and erase non-existent headers */
    for (size_t i = 0; i < 10; ++i) {
        aws_http_request_erase_header(&request, i);
    }

    /* Querying non-existent headers should just get you empty data */
    struct aws_http_header get = aws_http_request_get_header(&request, 99);
    ASSERT_SUCCESS(s_check_header_eq(get, "", ""));

    aws_http_request_clean_up(&request);
    return AWS_OP_SUCCESS;
}
