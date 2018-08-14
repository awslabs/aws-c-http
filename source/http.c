/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/http/http.h>

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/error.h>

#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#define AWS_DEFINE_ERROR_INFO_HTTP(CODE, STR) AWS_DEFINE_ERROR_INFO(CODE, STR, "aws-c-http")

/* clang-format off */
static struct aws_error_info s_errors[] = {
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_HTTP_ERROR_PARSE,
        "Encountered an unexpected form when parsing an http message."),
};
/* clang-format on */

static struct aws_error_info_list s_list = {
    .error_list = s_errors,
    .count = sizeof(s_errors) / sizeof(struct aws_error_info),
};

static bool s_error_strings_loaded = false;

void aws_http_load_error_strings(void) {
    if (!s_error_strings_loaded) {
        s_error_strings_loaded = true;
        aws_register_error_info(&s_list);
    }
}

/* https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function */
static inline uint32_t s_aws_FNV1a(struct aws_byte_cursor str) {
    uint32_t h = (uint32_t)0x811C9DC5;
    while (str.len--) {
        char c = (char)toupper(*str.ptr++);
        h = h ^ (uint32_t)c;
        h = h * (uint32_t)16777619;
    }
    return h;
}

/* Works like memcmp or strcmp, except is case-agonstic. */
static inline int s_aws_http_strcmp_case_insensitive(const char *a, const char *b, size_t key_len) {
    for (size_t i = 0; i < key_len; ++i) {
        int d = toupper(a[i]) - toupper(b[i]);
        if (d) {
            return d;
        }
    }
    return 0;
}

/*
 * The next four functions were generated from a small program in C, that takes a text-file as
 * input, reads in header keys as strings, and their corresponding enums as strings. The program
 * then spits out a nicely formatted switch statement for all the key-value pairs. The hashed sting
 * is included as a comment after each switch case. Here is the hash program:
 */

#if 0
    #define _CRT_SECURE_NO_WARNINGS
    #include <stdio.h>
    #include <stdint.h>
    #include <ctype.h>
    #include <string.h>

    uint32_t s_aws_FNV1a(const char* text) {
        uint32_t h = (uint32_t)0x811C9DC5;
        while (*text) {
            char c = *text++;
            h = h ^ (uint32_t)c;
            h = h * (uint32_t)16777619;
        }
        return h;
    }

    char *s_upper(char *s) {
        char *orig = s;
        while (*s) {
            *s = (char)toupper(*s);
            ++s;
        }
        return orig;
    }

    int main(int argc, char **argv) {
        if (argc < 2) {
            printf("Not enough arguments: %d\n", argc);
            return -1;
        }

        char enum_type[64];
        char buffer[256];
        char *strings[64];
        char *enums[64];

        const char *path = argv[1];
        FILE *fp = fopen(path, "rb");

        fscanf(fp, "%s", enum_type);

        int count = 0;
        while (1) {
            if (feof(fp)) break;
            fscanf(fp, "%s", buffer);
            strings[count] = strdup(s_upper(buffer));
            fscanf(fp, "%s", buffer);
            enums[count] = strdup(s_upper(buffer));
            ++count;
        }

        printf("\n\nstatic enum %s s_aws_http_str_to_enum_type(struct aws_http_str str) {\n", enum_type);
        printf("    uint32_t h = s_aws_FNV1a(str);\n");
        printf("    char *ptr = (char *)str.ptr;\n");
        printf("    size_t len = str.end - str.begin;\n");
        printf("    bool match = false;\n");
        printf("    int ret = 0;\n\n");
        printf("    switch (h) {\n");

        for (int i = 0; i < count; ++i) {
            uint64_t h = s_aws_FNV1a(strings[i]);
            printf("    case %lu:\n", h);
            printf("        match = !s_aws_http_strcmp_case_insensitive(\"%s\", ptr, len);\n", strings[i]);
            printf("        ret = %s;\n", enums[i]);
            printf("        break;%s", i == count - 1 ? "\n" : "\n\n");
        }

        printf("    }\n\n");
        printf("    return match ? (enum %s)ret : AWS_HTTP_REQUEST_METHOD_UNKNOWN;\n", enum_type);
        printf("}");
        fclose(fp);

        return 0;
    }
#endif

enum aws_http_method aws_http_str_to_method(struct aws_byte_cursor str) {
    uint32_t h = s_aws_FNV1a(str);
    char *ptr = (char *)str.ptr;
    size_t len = str.len;
    bool match = false;
    int ret = 0;

    switch (h) {
    case 2016099545:
        match = !s_aws_http_strcmp_case_insensitive("CONNECT", ptr, len);
        ret = AWS_HTTP_METHOD_CONNECT;
        break;

    case 4168191690:
        match = !s_aws_http_strcmp_case_insensitive("DELETE", ptr, len);
        ret = AWS_HTTP_METHOD_DELETE;
        break;

    case 2531704439:
        match = !s_aws_http_strcmp_case_insensitive("GET", ptr, len);
        ret = AWS_HTTP_METHOD_GET;
        break;

    case 811237315:
        match = !s_aws_http_strcmp_case_insensitive("HEAD", ptr, len);
        ret = AWS_HTTP_METHOD_HEAD;
        break;

    case 827600069:
        match = !s_aws_http_strcmp_case_insensitive("OPTIONS", ptr, len);
        ret = AWS_HTTP_METHOD_OPTIONS;
        break;

    case 3498819145:
        match = !s_aws_http_strcmp_case_insensitive("PATCH", ptr, len);
        ret = AWS_HTTP_METHOD_PATCH;
        break;

    case 1929554311:
        match = !s_aws_http_strcmp_case_insensitive("POST", ptr, len);
        ret = AWS_HTTP_METHOD_POST;
        break;

    case 3995708942:
        match = !s_aws_http_strcmp_case_insensitive("PUT", ptr, len);
        ret = AWS_HTTP_METHOD_PUT;
        break;

    case 746199118:
        match = !s_aws_http_strcmp_case_insensitive("TRACE", ptr, len);
        ret = AWS_HTTP_METHOD_TRACE;
        break;
    }

    return match ? (enum aws_http_method)ret : AWS_HTTP_METHOD_UNKNOWN;
}

enum aws_http_version aws_http_str_to_version(struct aws_byte_cursor str) {
    uint32_t h = s_aws_FNV1a(str);
    char *ptr = (char *)str.ptr;
    size_t len = str.len;
    bool match = false;
    int ret = 0;

    switch (h) {
    case 4137103867:
        match = !s_aws_http_strcmp_case_insensitive("HTTP/1.0", ptr, len);
        ret = AWS_HTTP_VERSION_1_0;
        break;

    case 4120326248:
        match = !s_aws_http_strcmp_case_insensitive("HTTP/1.1", ptr, len);
        ret = AWS_HTTP_VERSION_1_1;
        break;

    case 3110833482:
        match = !s_aws_http_strcmp_case_insensitive("HTTP/2.0", ptr, len);
        ret = AWS_HTTP_VERSION_2_0;
        break;
    }

    return match ? (enum aws_http_version)ret : AWS_HTTP_VERSION_UNKNOWN;
}

AWS_HTTP_API enum aws_http_version aws_http_str_to_header_name(struct aws_byte_cursor str) {
    (void)str;
    return AWS_HTTP_HEADER_UNKNOWN;
}

AWS_HTTP_API enum aws_http_code aws_http_int_to_code(int code) {
    (void)code;
    return AWS_HTTP_CODE_UNKNOWN;
}

const char *aws_http_header_name_to_str(enum aws_http_header_name name) {
    (void)name;
    return "AWS_HTTP_HEADER_UNKNOWN";
}

const char *aws_http_request_method_to_str(enum aws_http_method method) {
    switch (method) {
    case AWS_HTTP_METHOD_UNKNOWN: return "AWS_HTTP_METHOD_UNKNOWN";
    case AWS_HTTP_METHOD_CONNECT: return "AWS_HTTP_METHOD_CONNECT";
    case AWS_HTTP_METHOD_DELETE:  return "AWS_HTTP_METHOD_DELETE";
    case AWS_HTTP_METHOD_GET:     return "AWS_HTTP_METHOD_GET";
    case AWS_HTTP_METHOD_HEAD:    return "AWS_HTTP_METHOD_HEAD";
    case AWS_HTTP_METHOD_OPTIONS: return "AWS_HTTP_METHOD_OPTIONS";
    case AWS_HTTP_METHOD_PATCH:   return "AWS_HTTP_METHOD_PATCH";
    case AWS_HTTP_METHOD_POST:    return "AWS_HTTP_METHOD_POST";
    case AWS_HTTP_METHOD_PUT:     return "AWS_HTTP_METHOD_PUT";
    case AWS_HTTP_METHOD_TRACE:   return "AWS_HTTP_METHOD_TRACE";
    default: return NULL;
    }
}

const char *aws_http_version_code_to_str(enum aws_http_version version) {
    switch (version) {
    case AWS_HTTP_VERSION_UNKNOWN: return "AWS_HTTP_VERSION_UNKNOWN";
    case AWS_HTTP_VERSION_1_0:     return "AWS_HTTP_VERSION_1_0";
    case AWS_HTTP_VERSION_1_1:     return "AWS_HTTP_VERSION_1_1";
    case AWS_HTTP_VERSION_2_0:     return "AWS_HTTP_VERSION_2_0";
    default: return NULL;
    }
}
