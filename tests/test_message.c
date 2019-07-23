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
#include <aws/testing/aws_test_allocators.h>

#define TEST_CASE(NAME)                                                                                                \
    AWS_TEST_CASE(NAME, s_test_##NAME);                                                                                \
    static int s_test_##NAME(struct aws_allocator *allocator, void *ctx)

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
    ASSERT_SUCCESS(aws_http_message_set_response_status(response, 200));
    ASSERT_SUCCESS(aws_http_message_get_response_status(response, &get));
    ASSERT_INT_EQUALS(200, get);

    /* Set a new status */
    ASSERT_SUCCESS(aws_http_message_set_response_status(response, 404));
    ASSERT_SUCCESS(aws_http_message_get_response_status(response, &get));
    ASSERT_INT_EQUALS(404, get);

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

TEST_CASE(message_add_headers) {
    (void)ctx;
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(request);

    /* Test queries on 0 headers */
    struct aws_http_header get;
    ASSERT_ERROR(AWS_ERROR_INVALID_INDEX, aws_http_message_get_header(request, &get, 0));
    ASSERT_UINT_EQUALS(0, aws_http_message_get_header_count(request));

    /* Add a header */
    char name_src[] = "Host";
    char value_src[] = "example.com";

    ASSERT_SUCCESS(aws_http_message_add_header(request, s_make_header(name_src, value_src)));
    ASSERT_UINT_EQUALS(1, aws_http_message_get_header_count(request));

    /* Mutilate source strings to be sure the request isn't referencing their memory */
    name_src[0] = 0;
    value_src[0] = 0;

    /* Check values */
    ASSERT_SUCCESS(aws_http_message_get_header(request, &get, 0));
    ASSERT_SUCCESS(s_check_header_eq(get, "Host", "example.com"));

    /* Overwrite header and check values */
    ASSERT_SUCCESS(aws_http_message_set_header(request, s_make_header("Connection", "Upgrade"), 0));
    ASSERT_SUCCESS(aws_http_message_get_header(request, &get, 0));
    ASSERT_SUCCESS(s_check_header_eq(get, "Connection", "Upgrade"));

    aws_http_message_destroy(request);
    return AWS_OP_SUCCESS;
}

TEST_CASE(message_erase_headers) {
    (void)ctx;
    struct aws_http_message *message = aws_http_message_new_request(allocator);
    ASSERT_NOT_NULL(message);

    /* Should have no effect to try and erase non-existent headers */
    ASSERT_ERROR(AWS_ERROR_INVALID_INDEX, aws_http_message_erase_header(message, 0));

    /* Add a bunch of headers */
    struct aws_http_header src_headers[] = {
        s_make_header("NameA", "ValueA"),
        s_make_header("NameB", "ValueB"),
        s_make_header("NameC", "ValueC"),
        s_make_header("NameD", "ValueD"),
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(src_headers); ++i) {
        ASSERT_SUCCESS(aws_http_message_add_header(message, src_headers[i]));
    }

    struct aws_http_header get;
    for (size_t i = 0; i < AWS_ARRAY_SIZE(src_headers); ++i) {
        ASSERT_SUCCESS(aws_http_message_get_header(message, &get, i));
        ASSERT_SUCCESS(s_check_headers_eq(src_headers[i], get));
    }

    /* Remove a middle one and check */
    const size_t kill_i = 1;
    ASSERT_SUCCESS(aws_http_message_erase_header(message, kill_i));
    ASSERT_UINT_EQUALS(AWS_ARRAY_SIZE(src_headers) - 1, aws_http_message_get_header_count(message));

    for (size_t i = 0; i < aws_http_message_get_header_count(message); ++i) {
        /* Headers to the right should have shifted over */
        size_t compare_i = (i < kill_i) ? i : (i + 1);

        ASSERT_SUCCESS(aws_http_message_get_header(message, &get, i));
        ASSERT_SUCCESS(s_check_headers_eq(src_headers[compare_i], get));
    }

    /* Removing an invalid index should have no effect */
    ASSERT_ERROR(AWS_ERROR_INVALID_INDEX, aws_http_message_erase_header(message, 99));

    /* Remove a front and a back header, only "NameC: ValueC" should remain */
    ASSERT_SUCCESS(aws_http_message_erase_header(message, 0));
    ASSERT_SUCCESS(aws_http_message_erase_header(message, aws_http_message_get_header_count(message) - 1));

    ASSERT_UINT_EQUALS(1, aws_http_message_get_header_count(message));
    ASSERT_SUCCESS(aws_http_message_get_header(message, &get, 0));
    ASSERT_SUCCESS(s_check_header_eq(get, "NameC", "ValueC"));

    /* Ensure that add() still works after remove() */
    ASSERT_SUCCESS(aws_http_message_add_header(message, s_make_header("Big", "Guy")));
    ASSERT_SUCCESS(aws_http_message_get_header(message, &get, aws_http_message_get_header_count(message) - 1));
    ASSERT_SUCCESS(s_check_header_eq(get, "Big", "Guy"));

    aws_http_message_destroy(message);
    return AWS_OP_SUCCESS;
}

/* Do every operation that involves allocating some memory */
int s_message_handles_oom_attempt(struct aws_http_message *request) {
    ASSERT_NOT_NULL(request);

    /* Set, and then overwrite, method and path */
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("POST")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/")));
    ASSERT_SUCCESS(aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("GET")));
    ASSERT_SUCCESS(aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/chat")));

    /* Add a lot of headers, enough to force the underlying array-list to expand.
     * (just loop through the list above again and again) */
    char name_buf[16];
    char value_buf[16];
    for (size_t i = 0; i < 128; ++i) {
        snprintf(name_buf, sizeof(name_buf), "Name-%zu", i);
        snprintf(name_buf, sizeof(name_buf), "Value-%zu", i);
        struct aws_http_header header = {.name = aws_byte_cursor_from_c_str(name_buf),
                                         .value = aws_byte_cursor_from_c_str(value_buf)};
        ASSERT_SUCCESS(aws_http_message_add_header(request, header));
    }

    /* Overwrite all the headers */
    for (size_t i = 0; i < 128; ++i) {
        snprintf(name_buf, sizeof(name_buf), "New-Name-%zu", i);
        snprintf(name_buf, sizeof(name_buf), "New-Value-%zu", i);
        struct aws_http_header header = {.name = aws_byte_cursor_from_c_str(name_buf),
                                         .value = aws_byte_cursor_from_c_str(value_buf)};
        ASSERT_SUCCESS(aws_http_message_set_header(request, header, i));
    }

    return AWS_OP_SUCCESS;
}

TEST_CASE(message_handles_oom) {
    (void)ctx;
    struct aws_allocator timebomb_alloc;
    ASSERT_SUCCESS(aws_timebomb_allocator_init(&timebomb_alloc, allocator, SIZE_MAX));

    bool test_succeeded = false;
    size_t allocations_until_failure;
    for (allocations_until_failure = 0; allocations_until_failure < 10000; ++allocations_until_failure) {
        /* Allow one more allocation each time we loop. */
        aws_timebomb_allocator_reset_countdown(&timebomb_alloc, allocations_until_failure);

        /* Create a request, then do a bunch of stuff with it. */
        struct aws_http_message *request = aws_http_message_new_request(&timebomb_alloc);
        int err = 0;
        if (request) {
            err = s_message_handles_oom_attempt(request);
            if (err) {
                /* Ensure failure was due to OOM */
                ASSERT_INT_EQUALS(AWS_ERROR_OOM, aws_last_error());
            } else {
                test_succeeded = true;
            }

            aws_http_message_destroy(request);
        } else {
            /* Ensure failure was due to OOM */
            ASSERT_INT_EQUALS(AWS_ERROR_OOM, aws_last_error());
        }

        if (test_succeeded) {
            break;
        }
    }

    ASSERT_TRUE(test_succeeded);
    ASSERT_TRUE(allocations_until_failure > 2); /* Assert that this did fail a few times */

    aws_timebomb_allocator_clean_up(&timebomb_alloc);
    return AWS_OP_SUCCESS;
}
