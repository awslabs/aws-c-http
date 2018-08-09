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
static inline uint32_t s_aws_FNV1a(struct aws_http_str str) {
    uint32_t h = (uint32_t)0x811C9DC5;
    while (str.begin < str.end) {
        char c = (char)toupper(*str.begin++);
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
        printf("    size_t len = str.end - str.begin;\n");
        printf("    bool match = false;\n");
        printf("    int ret = 0;\n\n");
        printf("    switch (h) {\n");

        for (int i = 0; i < count; ++i) {
            uint64_t h = s_aws_FNV1a(strings[i]);
            printf("    case %lu:\n", h);
            printf("        match = !s_aws_http_strcmp_case_insensitive(\"%s\", str.begin, len);\n", strings[i]);
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

static enum aws_http_request_method s_aws_http_str_to_method(struct aws_http_str str) {
    uint32_t h = s_aws_FNV1a(str);
    size_t len = str.end - str.begin;
    bool match = false;
    int ret = 0;

    switch (h) {
    case 2016099545:
        match = !s_aws_http_strcmp_case_insensitive("CONNECT", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_CONNECT;
        break;

    case 4168191690:
        match = !s_aws_http_strcmp_case_insensitive("DELETE", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_DELETE;
        break;

    case 2531704439:
        match = !s_aws_http_strcmp_case_insensitive("GET", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_GET;
        break;

    case 811237315:
        match = !s_aws_http_strcmp_case_insensitive("HEAD", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_HEAD;
        break;

    case 827600069:
        match = !s_aws_http_strcmp_case_insensitive("OPTIONS", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_OPTIONS;
        break;

    case 3498819145:
        match = !s_aws_http_strcmp_case_insensitive("PATCH", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_PATCH;
        break;

    case 1929554311:
        match = !s_aws_http_strcmp_case_insensitive("POST", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_POST;
        break;

    case 3995708942:
        match = !s_aws_http_strcmp_case_insensitive("PUT", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_PUT;
        break;

    case 746199118:
        match = !s_aws_http_strcmp_case_insensitive("TRACE", str.begin, len);
        ret = AWS_HTTP_REQUEST_METHOD_TRACE;
        break;
    }

    return match ? (enum aws_http_request_method)ret : AWS_HTTP_REQUEST_METHOD_UNKNOWN;
}

static enum aws_http_version s_aws_http_str_to_version(struct aws_http_str str) {
    uint32_t h = s_aws_FNV1a(str);
    size_t len = str.end - str.begin;
    bool match = false;
    int ret = 0;

    switch (h) {
    case 4137103867:
        match = !s_aws_http_strcmp_case_insensitive("HTTP/1.0", str.begin, len);
        ret = AWS_HTTP_VERSION_1_0;
        break;

    case 4120326248:
        match = !s_aws_http_strcmp_case_insensitive("HTTP/1.1", str.begin, len);
        ret = AWS_HTTP_VERSION_1_1;
        break;

    case 3110833482:
        match = !s_aws_http_strcmp_case_insensitive("HTTP/2.0", str.begin, len);
        ret = AWS_HTTP_VERSION_2_0;
        break;
    }

    return match ? (enum aws_http_version)ret : AWS_HTTP_REQUEST_METHOD_UNKNOWN;
}

static enum aws_http_request_key s_aws_http_str_to_request_key(struct aws_http_str str) {
    uint32_t h = s_aws_FNV1a(str);
    size_t len = str.end - str.begin;
    bool match = false;
    int ret = 0;

    switch (h) {
    case 547231721:
        match = !s_aws_http_strcmp_case_insensitive("ACCEPT", str.begin, len);
        ret = AWS_HTTP_REQUEST_ACCEPT;
        break;

    case 3107960968:
        match = !s_aws_http_strcmp_case_insensitive("ACCEPT-CHARSET", str.begin, len);
        ret = AWS_HTTP_REQUEST_ACCEPT_CHARSET;
        break;

    case 3161469017:
        match = !s_aws_http_strcmp_case_insensitive("ACCEPT-ENCODING", str.begin, len);
        ret = AWS_HTTP_REQUEST_ACCEPT_ENCODING;
        break;

    case 648286550:
        match = !s_aws_http_strcmp_case_insensitive("ACCEPT-LANGUAGE", str.begin, len);
        ret = AWS_HTTP_REQUEST_ACCEPT_LANGUAGE;
        break;

    case 4194732382:
        match = !s_aws_http_strcmp_case_insensitive("AUTHORIZATION", str.begin, len);
        ret = AWS_HTTP_REQUEST_AUTHORIZATION;
        break;

    case 987353997:
        match = !s_aws_http_strcmp_case_insensitive("CACHE-CONTROL", str.begin, len);
        ret = AWS_HTTP_REQUEST_CACHE_CONTROL;
        break;

    case 707182617:
        match = !s_aws_http_strcmp_case_insensitive("CONNECTION", str.begin, len);
        ret = AWS_HTTP_REQUEST_CONNECTION;
        break;

    case 2630822013:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-LENGTH", str.begin, len);
        ret = AWS_HTTP_REQUEST_CONTENT_LENGTH;
        break;

    case 3945365109:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-TYPE", str.begin, len);
        ret = AWS_HTTP_REQUEST_CONTENT_TYPE;
        break;

    case 453382463:
        match = !s_aws_http_strcmp_case_insensitive("COOKIE", str.begin, len);
        ret = AWS_HTTP_REQUEST_COOKIE;
        break;

    case 3221746841:
        match = !s_aws_http_strcmp_case_insensitive("DATE", str.begin, len);
        ret = AWS_HTTP_REQUEST_DATE;
        break;

    case 40228184:
        match = !s_aws_http_strcmp_case_insensitive("EXPECT", str.begin, len);
        ret = AWS_HTTP_REQUEST_EXPECT;
        break;

    case 1942971925:
        match = !s_aws_http_strcmp_case_insensitive("FOWARDED", str.begin, len);
        ret = AWS_HTTP_REQUEST_FORWARDED;
        break;

    case 2478748789:
        match = !s_aws_http_strcmp_case_insensitive("FROM", str.begin, len);
        ret = AWS_HTTP_REQUEST_FROM;
        break;

    case 3991944751:
        match = !s_aws_http_strcmp_case_insensitive("HOST", str.begin, len);
        ret = AWS_HTTP_REQUEST_HOST;
        break;

    case 4110033290:
        match = !s_aws_http_strcmp_case_insensitive("IF-MATCH", str.begin, len);
        ret = AWS_HTTP_REQUEST_IF_MATCH;
        break;

    case 247469449:
        match = !s_aws_http_strcmp_case_insensitive("IF-MODIFIED-SINCE", str.begin, len);
        ret = AWS_HTTP_REQUEST_IF_MODIFIED_SINCE;
        break;

    case 1929613911:
        match = !s_aws_http_strcmp_case_insensitive("IF-NONE-MATCH", str.begin, len);
        ret = AWS_HTTP_REQUEST_IF_NONE_MATCH;
        break;

    case 2986103070:
        match = !s_aws_http_strcmp_case_insensitive("IF-RANGE", str.begin, len);
        ret = AWS_HTTP_REQUEST_IF_RANGE;
        break;

    case 743147306:
        match = !s_aws_http_strcmp_case_insensitive("IF-UNMODIFIED-SINCE", str.begin, len);
        ret = AWS_HTTP_REQUEST_IF_UNMODIFIED_SINCE;
        break;

    case 1679160352:
        match = !s_aws_http_strcmp_case_insensitive("KEEP-ALIVE", str.begin, len);
        ret = AWS_HTTP_REQUEST_KEEP_ALIVE;
        break;

    case 813576502:
        match = !s_aws_http_strcmp_case_insensitive("MAX-FORWARDS", str.begin, len);
        ret = AWS_HTTP_REQUEST_MAX_FORWARDS;
        break;

    case 1999205135:
        match = !s_aws_http_strcmp_case_insensitive("ORIGIN", str.begin, len);
        ret = AWS_HTTP_REQUEST_ORIGIN;
        break;

    case 2982521275:
        match = !s_aws_http_strcmp_case_insensitive("PROXY-AUTHORIZATION", str.begin, len);
        ret = AWS_HTTP_REQUEST_PROXY_AUTHORIZATION;
        break;

    case 1696719282:
        match = !s_aws_http_strcmp_case_insensitive("RANGE", str.begin, len);
        ret = AWS_HTTP_REQUEST_RANGE;
        break;

    case 3692982486:
        match = !s_aws_http_strcmp_case_insensitive("REFERRER", str.begin, len);
        ret = AWS_HTTP_REQUEST_REFERRER;
        break;

    case 635591758:
        match = !s_aws_http_strcmp_case_insensitive("USER-AGENT", str.begin, len);
        ret = AWS_HTTP_REQUEST_USER_AGENT;
        break;

    case 3958155251:
        match = !s_aws_http_strcmp_case_insensitive("VIA", str.begin, len);
        ret = AWS_HTTP_REQUEST_VIA;
        break;
    }

    return match ? (enum aws_http_request_key)ret : AWS_HTTP_REQUEST_METHOD_UNKNOWN;
}

static enum aws_http_response_key s_aws_http_str_to_response_key(struct aws_http_str str) {
    uint32_t h = s_aws_FNV1a(str);
    size_t len = str.end - str.begin;
    bool match = false;
    int ret = 0;

    switch (h) {
    case 2404564518:
        match = !s_aws_http_strcmp_case_insensitive("ACCEPT-RANGES", str.begin, len);
        ret = AWS_HTTP_RESPONSE_ACCEPT_RANGES;
        break;

    case 1853619452:
        match = !s_aws_http_strcmp_case_insensitive("AGE", str.begin, len);
        ret = AWS_HTTP_RESPONSE_AGE;
        break;

    case 1084331474:
        match = !s_aws_http_strcmp_case_insensitive("ALLOW", str.begin, len);
        ret = AWS_HTTP_RESPONSE_ALLOW;
        break;

    case 987353997:
        match = !s_aws_http_strcmp_case_insensitive("CACHE-CONTROL", str.begin, len);
        ret = AWS_HTTP_RESPONSE_CACHE_CONTROL;
        break;

    case 3098799004:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-DISPOSITION", str.begin, len);
        ret = AWS_HTTP_RESPONSE_CONTENT_DISPOSITION;
        break;

    case 4106027624:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-ENCODING", str.begin, len);
        ret = AWS_HTTP_RESPONSE_CONTENT_ENCODING;
        break;

    case 1167503283:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-LANGUAGE", str.begin, len);
        ret = AWS_HTTP_RESPONSE_CONTENT_LANGUAGE;
        break;

    case 2630822013:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-LENGTH", str.begin, len);
        ret = AWS_HTTP_RESPONSE_CONTENT_LENGTH;
        break;

    case 2246872206:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-LOCATION", str.begin, len);
        ret = AWS_HTTP_RESPONSE_CONTENT_LOCATION;
        break;

    case 2090207370:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-RANGE", str.begin, len);
        ret = AWS_HTTP_RESPONSE_CONTENT_RANGE;
        break;

    case 3945365109:
        match = !s_aws_http_strcmp_case_insensitive("CONTENT-TYPE", str.begin, len);
        ret = AWS_HTTP_RESPONSE_CONTENT_TYPE;
        break;

    case 3221746841:
        match = !s_aws_http_strcmp_case_insensitive("DATE", str.begin, len);
        ret = AWS_HTTP_RESPONSE_DATE;
        break;

    case 3002887936:
        match = !s_aws_http_strcmp_case_insensitive("ETAG", str.begin, len);
        ret = AWS_HTTP_RESPONSE_ETAG;
        break;

    case 3239887275:
        match = !s_aws_http_strcmp_case_insensitive("LAST-MODIFIED", str.begin, len);
        ret = AWS_HTTP_RESPONSE_LAST_MODIFIED;
        break;

    case 187591081:
        match = !s_aws_http_strcmp_case_insensitive("LINK", str.begin, len);
        ret = AWS_HTTP_RESPONSE_LINK;
        break;

    case 697559654:
        match = !s_aws_http_strcmp_case_insensitive("LOCATION", str.begin, len);
        ret = AWS_HTTP_RESPONSE_LOCATION;
        break;

    case 645626959:
        match = !s_aws_http_strcmp_case_insensitive("PROXY-AUTHENTICATE", str.begin, len);
        ret = AWS_HTTP_RESPONSE_PROXY_AUTHENTICATE;
        break;

    case 3631052982:
        match = !s_aws_http_strcmp_case_insensitive("RETRY-AFTER", str.begin, len);
        ret = AWS_HTTP_RESPONSE_RETRY_AFTER;
        break;

    case 3820123666:
        match = !s_aws_http_strcmp_case_insensitive("SERVER", str.begin, len);
        ret = AWS_HTTP_RESPONSE_SERVER;
        break;

    case 1141904942:
        match = !s_aws_http_strcmp_case_insensitive("SER-COOKIE", str.begin, len);
        ret = AWS_HTTP_RESPONSE_SET_COOKIE;
        break;

    case 1516005313:
        match = !s_aws_http_strcmp_case_insensitive("STRICT-TRANSPORT-SECURITY", str.begin, len);
        ret = AWS_HTTP_RESPONSE_STRICT_TRANSPORT_SECURITY;
        break;

    case 1050481221:
        match = !s_aws_http_strcmp_case_insensitive("VARY", str.begin, len);
        ret = AWS_HTTP_RESPONSE_VARY;
        break;

    case 3958155251:
        match = !s_aws_http_strcmp_case_insensitive("VIA", str.begin, len);
        ret = AWS_HTTP_RESPONSE_VIA;
        break;

    case 4075666274:
        match = !s_aws_http_strcmp_case_insensitive("WWW-AUTHENTICATE", str.begin, len);
        ret = AWS_HTTP_RESPONSE_WWW_AUTHENTICATE;
        break;
    }

    return match ? (enum aws_http_response_key)ret : AWS_HTTP_REQUEST_METHOD_UNKNOWN;
}

static bool s_aws_http_eol(char c) {
    switch (c) {
    case '\n': return true;
    case '\r': return true;
    }
    return false;
}

static inline int s_aws_http_skip_space(struct aws_http_str *input) {
    const char *scan = input->begin;
    do
    {
        if (!(scan < input->end)) {
            return AWS_OP_ERR;
        }
    } while (*scan++ == ' ');
    input->begin = scan - 1;
    return AWS_OP_SUCCESS;
}

static inline void s_aws_http_trim_trailing_space(struct aws_http_str *str) {
    assert(str->end >= str->begin);
    const char *end = str->end - 1;
    while (end > str->begin && *end == ' ') {
        end--;
    }
    str->end = end + 1;
}

static int s_aws_http_scan(struct aws_http_str *input, struct aws_http_str *out, char search) {
    const char *scan = input->begin;
    if (!scan) {
        return AWS_OP_ERR;
    }
    char c;
    do {
        c = *scan;
        if (!(scan < input->end) | s_aws_http_eol(c)) {
            return AWS_OP_ERR;
        }
        ++scan;
    } while (c != search);
    out->begin = input->begin;
    out->end = scan - 1;
    input->begin = scan;
    s_aws_http_trim_trailing_space(out);
    return AWS_OP_SUCCESS;
}

static int s_aws_http_scan_for_eol_or_eos(struct aws_http_str *input, struct aws_http_str *out) {
    const char *scan = input->begin;
    if (!scan) {
        return AWS_OP_ERR;
    }
    char c;
    do {
        c = *scan;
        if (!(scan < input->end)) {
            out->begin = input->begin;
            out->end = input->begin = scan;
            return AWS_OP_SUCCESS;
        }
        ++scan;
    } while (!s_aws_http_eol(c));
    if (c == '\r') {
        if (scan < input->end + 1 && *scan++ != '\n') {
            return AWS_OP_ERR;
        }
    }
    out->begin = input->begin;
    out->end = scan - 2;
    input->begin = scan;
    s_aws_http_trim_trailing_space(out);
    return AWS_OP_SUCCESS;
}

static bool s_aws_http_expect_eol(struct aws_http_str *input) {
    if (input->begin < input->end && !s_aws_http_eol(*input->begin++)) return false;
    if (input->begin < input->end && !s_aws_http_eol(*input->begin++)) return false;
    return true;
}

static inline bool s_aws_http_is_end_of_headers(struct aws_http_str *input) {
    if (input->begin < input->end - 1) {
        if (input->begin[0] == '\r' && input->begin[1] == '\n') {
            return true;
        } else {
            return false;
        }
    } else {
        return true;
    }
}

static inline int s_aws_http_read_int(struct aws_http_str str, int* val) {
    char *end;
    *val = strtol(str.begin, &end, 10);
    if (str.begin != end) {
        return AWS_OP_SUCCESS;
    } else {
        return AWS_OP_ERR;
    }
}

static inline int s_aws_http_get_status_code_class(char c, enum aws_http_response_status_code_class *code_class) {
    switch (c) {
    case '1': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_INFORMATIONAL; return AWS_OP_SUCCESS;
    case '2': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_SUCCESSFUL;    return AWS_OP_SUCCESS;
    case '3': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_REDIRECTION;   return AWS_OP_SUCCESS;
    case '4': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_CLIENT_ERROR;  return AWS_OP_SUCCESS;
    case '5': *code_class = AWS_HTTP_RESPONSE_STATUS_CODE_SERVER_ERROR;  return AWS_OP_SUCCESS;
    default: return AWS_OP_ERR;
    }
}

#define AWS_HTTP_CHECK_OP(X) do { if ((X) != AWS_OP_SUCCESS) { goto aws_error; } } while (0)
#define AWS_HTTP_ASSERT(X) do { if (!(X)) { goto aws_error; } } while (0)

static int s_aws_http_read_headers_and_optional_body(struct aws_http_message_data *data, struct aws_http_str *input, struct aws_array_list *headers, int *cache, bool one_request_zero_response) {
    struct aws_http_str str;
    int cache_max_index = one_request_zero_response ? AWS_HTTP_RESPONSE_LAST : AWS_HTTP_REQUEST_LAST;
    int content_length_key = one_request_zero_response ? AWS_HTTP_REQUEST_CONTENT_LENGTH : AWS_HTTP_RESPONSE_CONTENT_LENGTH;

    /* Scan for headers. */
    int content_length = 0;
    while (!s_aws_http_is_end_of_headers(input)) {
        /* Read in header key. */
        struct aws_http_header header_field;
        AWS_HTTP_CHECK_OP(s_aws_http_scan(input, &str, ':'));
        header_field.key_str = str;
        header_field.key = one_request_zero_response ? s_aws_http_str_to_request_key(str) : s_aws_http_str_to_response_key(str);

        if (header_field.key) {
            size_t index = (size_t)header_field.key - 1;
            if (index > cache_max_index) {
                return AWS_OP_ERR;
            }
            cache[index] = (int)aws_array_list_length(headers) + 1;
        }

        bool has_content = false;
        if (header_field.key == content_length_key) {
            has_content = true;
        }

        /* Read in header value string. */
        AWS_HTTP_CHECK_OP(s_aws_http_skip_space(input));
        AWS_HTTP_CHECK_OP(s_aws_http_scan_for_eol_or_eos(input, &str));
        header_field.value_str = str;

        if (has_content) {
            AWS_HTTP_CHECK_OP(s_aws_http_read_int(header_field.value_str, &content_length));
        }

        /* Record header key-value pair. */
        aws_array_list_push_back(headers, &header_field);
    }

    data->headers = (struct aws_http_header *)headers->data;
    data->header_count = headers->length;

    if (content_length) {
        AWS_HTTP_CHECK_OP(s_aws_http_expect_eol(input));

        /* Read in content here. TODO: Handle chunked encoding? */

        data->body.begin = input->begin;
        data->body.end = input->begin + content_length;
    } else {
        data->body.begin = NULL;
        data->body.end = NULL;
    }

    return AWS_OP_SUCCESS;

aws_error:
    return AWS_OP_ERR;
}

#define AWS_HTTP_HEADER_CACHE_INVALID (~0)

static inline void s_aws_http_init_header_cache(int *cache, int count) {
    for (int i = 0; i < count; ++i ) {
        cache[i] = AWS_HTTP_HEADER_CACHE_INVALID;
    }
}

int aws_http_request_init(struct aws_http_request *request, struct aws_allocator *alloc, const void *buffer, size_t buffer_size) {
    struct aws_http_str input;
    struct aws_http_str str;
    struct aws_array_list headers;
    aws_array_list_init_dynamic(&headers, alloc, 16, sizeof(struct aws_http_header));
    AWS_ZERO_STRUCT(*request);
    s_aws_http_init_header_cache(request->header_cache, (int)AWS_HTTP_REQUEST_LAST);
    request->data.alloc = alloc;

    input.begin = (const char *)buffer;
    input.end = input.begin + buffer_size;

    /* Method. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan(&input, &str, ' '));
    request->method = s_aws_http_str_to_method(str);
    AWS_HTTP_ASSERT(request->method != AWS_HTTP_REQUEST_METHOD_UNKNOWN);

    /* Target URI. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan(&input, &str, ' '));
    request->target = str;

    /* HTTP version. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan_for_eol_or_eos(&input, &str));
    request->version = s_aws_http_str_to_version(str);
    AWS_HTTP_ASSERT(request->version != AWS_HTTP_VERSION_UNKNOWN);

    /* Read in headers and optional body data. */
    s_aws_http_read_headers_and_optional_body(&request->data, &input, &headers, request->header_cache, 1);

    return AWS_OP_SUCCESS;

aws_error:
    aws_array_list_clean_up(&headers);
    AWS_ZERO_STRUCT(*request);
    aws_raise_error(AWS_HTTP_ERROR_PARSE);
    return AWS_OP_ERR;
}

void aws_http_request_clean_up(struct aws_http_request *request) {
    assert(request);
    if (request->data.alloc) {
        aws_mem_release(request->data.alloc, request->data.headers);
    }
    AWS_ZERO_STRUCT(*request);
}

int aws_http_request_get_header_by_enum(const struct aws_http_request *request, struct aws_http_header *header, enum aws_http_request_key key) {
    size_t index = (size_t)key - 1;
    if (index > AWS_HTTP_REQUEST_LAST - 1) {
        return AWS_OP_ERR;
    }

    int at = request->header_cache[index];
    if (at != AWS_HTTP_HEADER_CACHE_INVALID) {
        assert(at >= 0 && at < request->data.header_count);
        *header = request->data.headers[at];
        return AWS_OP_SUCCESS;
    }
    return AWS_OP_ERR;
}

static inline int s_aws_http_get_header_by_str(const struct aws_http_message_data *data, struct aws_http_header *header, const char *key, size_t key_len) {
    for (int i = 0; i < data->header_count; ++i) {
        struct aws_http_str str = data->headers[i].key_str;
        size_t len = str.end - str.begin;
        if (len != key_len) {
            continue;
        }
        if (!s_aws_http_strcmp_case_insensitive(str.begin, key, len)) {
            *header = data->headers[i];
            return AWS_OP_SUCCESS;
        }
    }
    return AWS_OP_ERR;
}

int aws_http_request_get_header_by_str(const struct aws_http_request *request, struct aws_http_header *header, const char *key, size_t key_len) {
    return s_aws_http_get_header_by_str(&request->data, header, key, (int)key_len);
}

int aws_http_response_init(struct aws_http_response *response, struct aws_allocator *alloc, const void *buffer, size_t buffer_size) {
    struct aws_http_str input;
    struct aws_http_str str;
    struct aws_array_list headers;
    aws_array_list_init_dynamic(&headers, alloc, 16, sizeof(struct aws_http_header));
    AWS_ZERO_STRUCT(*response);
    s_aws_http_init_header_cache(response->header_cache, (int)AWS_HTTP_RESPONSE_LAST);
    response->data.alloc = alloc;

    input.begin = (const char *)buffer;
    input.end = input.begin + buffer_size;

    /* HTTP version. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan(&input, &str, ' '));
    response->version = s_aws_http_str_to_version(str);
    AWS_HTTP_ASSERT(response->version != AWS_HTTP_VERSION_UNKNOWN);

    /* Integral status code. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan(&input, &str, ' '));
    int status_code;
    AWS_HTTP_CHECK_OP(s_aws_http_read_int(str, &status_code));
    AWS_HTTP_CHECK_OP(s_aws_http_get_status_code_class(str.begin[0], &response->status_code_class));
    response->status_code = status_code;
    response->status_code_reason_phrase = str;

    /* Reason phrase associated with the status code. */
    AWS_HTTP_CHECK_OP(s_aws_http_scan_for_eol_or_eos(&input, &str));

    /* Read in headers and optional body data. */
    s_aws_http_read_headers_and_optional_body(&response->data, &input, &headers, response->header_cache, 0);

    return AWS_OP_SUCCESS;

aws_error:
    aws_array_list_clean_up(&headers);
    AWS_ZERO_STRUCT(*response);
    aws_raise_error(AWS_HTTP_ERROR_PARSE);
    return AWS_OP_ERR;
}

void aws_http_response_clean_up(struct aws_http_response *response) {
    assert(response);
    if (response->data.alloc) {
        aws_mem_release(response->data.alloc, response->data.headers);
    }
    AWS_ZERO_STRUCT(*response);
}

int aws_http_response_get_header_by_enum(const struct aws_http_response *response, struct aws_http_header *header, enum aws_http_request_key key) {
    size_t index = (size_t)key - 1;
    if (index > AWS_HTTP_RESPONSE_LAST - 1) {
        return AWS_OP_ERR;
    }

    int at = response->header_cache[index];
    if (at != AWS_HTTP_HEADER_CACHE_INVALID) {
        assert(at >= 0 && at < response->data.header_count);
        *header = response->data.headers[at];
        return AWS_OP_SUCCESS;
    }
    return AWS_OP_ERR;
}

int aws_http_response_get_header_by_str(const struct aws_http_response *response, struct aws_http_header *header, const char *key, size_t key_len) {
    return s_aws_http_get_header_by_str(&response->data, header, key, (int)key_len);
}

const char *aws_http_request_method_to_str(enum aws_http_request_method method) {
    switch (method) {
    case AWS_HTTP_REQUEST_METHOD_UNKNOWN: return "AWS_HTTP_REQUEST_METHOD_UNKNOWN";
    case AWS_HTTP_REQUEST_METHOD_CONNECT: return "AWS_HTTP_REQUEST_METHOD_CONNECT";
    case AWS_HTTP_REQUEST_METHOD_DELETE:  return "AWS_HTTP_REQUEST_METHOD_DELETE";
    case AWS_HTTP_REQUEST_METHOD_GET:     return "AWS_HTTP_REQUEST_METHOD_GET";
    case AWS_HTTP_REQUEST_METHOD_HEAD:    return "AWS_HTTP_REQUEST_METHOD_HEAD";
    case AWS_HTTP_REQUEST_METHOD_OPTIONS: return "AWS_HTTP_REQUEST_METHOD_OPTIONS";
    case AWS_HTTP_REQUEST_METHOD_PATCH:   return "AWS_HTTP_REQUEST_METHOD_PATCH";
    case AWS_HTTP_REQUEST_METHOD_POST:    return "AWS_HTTP_REQUEST_METHOD_POST";
    case AWS_HTTP_REQUEST_METHOD_PUT:     return "AWS_HTTP_REQUEST_METHOD_PUT";
    case AWS_HTTP_REQUEST_METHOD_TRACE:   return "AWS_HTTP_REQUEST_METHOD_TRACE";
    }
    return NULL;
}

const char *aws_http_request_key_to_str(enum aws_http_request_key key) {
    switch (key) {
    case AWS_HTTP_REQUEST_UNKNOWN:             return "AWS_HTTP_REQUEST_UNKNOWN";
    case AWS_HTTP_REQUEST_ACCEPT:              return "AWS_HTTP_REQUEST_ACCEPT";
    case AWS_HTTP_REQUEST_ACCEPT_CHARSET:      return "AWS_HTTP_REQUEST_ACCEPT_CHARSET";
    case AWS_HTTP_REQUEST_ACCEPT_ENCODING:     return "AWS_HTTP_REQUEST_ACCEPT_ENCODING";
    case AWS_HTTP_REQUEST_ACCEPT_LANGUAGE:     return "AWS_HTTP_REQUEST_ACCEPT_LANGUAGE";
    case AWS_HTTP_REQUEST_AUTHORIZATION:       return "AWS_HTTP_REQUEST_AUTHORIZATION";
    case AWS_HTTP_REQUEST_CACHE_CONTROL:       return "AWS_HTTP_REQUEST_CACHE_CONTROL";
    case AWS_HTTP_REQUEST_CONNECTION:          return "AWS_HTTP_REQUEST_CONNECTION";
    case AWS_HTTP_REQUEST_CONTENT_LENGTH:      return "AWS_HTTP_REQUEST_CONTENT_LENGTH";
    case AWS_HTTP_REQUEST_CONTENT_TYPE:        return "AWS_HTTP_REQUEST_CONTENT_TYPE";
    case AWS_HTTP_REQUEST_COOKIE:              return "AWS_HTTP_REQUEST_COOKIE";
    case AWS_HTTP_REQUEST_DATE:                return "AWS_HTTP_REQUEST_DATE";
    case AWS_HTTP_REQUEST_EXPECT:              return "AWS_HTTP_REQUEST_EXPECT";
    case AWS_HTTP_REQUEST_FORWARDED:           return "AWS_HTTP_REQUEST_FORWARDED";
    case AWS_HTTP_REQUEST_FROM:                return "AWS_HTTP_REQUEST_FROM";
    case AWS_HTTP_REQUEST_HOST:                return "AWS_HTTP_REQUEST_HOST";
    case AWS_HTTP_REQUEST_IF_MATCH:            return "AWS_HTTP_REQUEST_IF_MATCH";
    case AWS_HTTP_REQUEST_IF_MODIFIED_SINCE:   return "AWS_HTTP_REQUEST_IF_MODIFIED_SINCE";
    case AWS_HTTP_REQUEST_IF_NONE_MATCH:       return "AWS_HTTP_REQUEST_IF_NONE_MATCH";
    case AWS_HTTP_REQUEST_IF_RANGE:            return "AWS_HTTP_REQUEST_IF_RANGE";
    case AWS_HTTP_REQUEST_IF_UNMODIFIED_SINCE: return "AWS_HTTP_REQUEST_IF_UNMODIFIED_SINCE";
    case AWS_HTTP_REQUEST_KEEP_ALIVE:          return "AWS_HTTP_REQUEST_KEEP_ALIVE";
    case AWS_HTTP_REQUEST_MAX_FORWARDS:        return "AWS_HTTP_REQUEST_MAX_FORWARDS";
    case AWS_HTTP_REQUEST_ORIGIN:              return "AWS_HTTP_REQUEST_ORIGIN";
    case AWS_HTTP_REQUEST_PROXY_AUTHORIZATION: return "AWS_HTTP_REQUEST_PROXY_AUTHORIZATION";
    case AWS_HTTP_REQUEST_RANGE:               return "AWS_HTTP_REQUEST_RANGE";
    case AWS_HTTP_REQUEST_USER_AGENT:          return "AWS_HTTP_REQUEST_USER_AGENT";
    case AWS_HTTP_REQUEST_VIA:                 return "AWS_HTTP_REQUEST_VIA";
    }
    return NULL;
}

AWS_HTTP_API const char *aws_http_response_key_to_str(enum aws_http_request_key key) {
    switch (key) {
    case AWS_HTTP_RESPONSE_ACCEPT_RANGES:             return "AWS_HTTP_RESPONSE_ACCEPT_RANGES";
    case AWS_HTTP_RESPONSE_AGE:                       return "AWS_HTTP_RESPONSE_AGE";
    case AWS_HTTP_RESPONSE_ALLOW:                     return "AWS_HTTP_RESPONSE_ALLOW";
    case AWS_HTTP_RESPONSE_CACHE_CONTROL:             return "AWS_HTTP_RESPONSE_CACHE_CONTROL";
    case AWS_HTTP_RESPONSE_CONTENT_DISPOSITION:       return "AWS_HTTP_RESPONSE_CONTENT_DISPOSITION";
    case AWS_HTTP_RESPONSE_CONTENT_ENCODING:          return "AWS_HTTP_RESPONSE_CONTENT_ENCODING";
    case AWS_HTTP_RESPONSE_CONTENT_LANGUAGE:          return "AWS_HTTP_RESPONSE_CONTENT_LANGUAGE";
    case AWS_HTTP_RESPONSE_CONTENT_LENGTH:            return "AWS_HTTP_RESPONSE_CONTENT_LENGTH";
    case AWS_HTTP_RESPONSE_CONTENT_LOCATION:          return "AWS_HTTP_RESPONSE_CONTENT_LOCATION";
    case AWS_HTTP_RESPONSE_CONTENT_RANGE:             return "AWS_HTTP_RESPONSE_CONTENT_RANGE";
    case AWS_HTTP_RESPONSE_CONTENT_TYPE:              return "AWS_HTTP_RESPONSE_CONTENT_TYPE";
    case AWS_HTTP_RESPONSE_DATE:                      return "AWS_HTTP_RESPONSE_DATE";
    case AWS_HTTP_RESPONSE_ETAG:                      return "AWS_HTTP_RESPONSE_ETAG";
    case AWS_HTTP_RESPONSE_LAST_MODIFIED:             return "AWS_HTTP_RESPONSE_LAST_MODIFIED";
    case AWS_HTTP_RESPONSE_LINK:                      return "AWS_HTTP_RESPONSE_LINK";
    case AWS_HTTP_RESPONSE_LOCATION:                  return "AWS_HTTP_RESPONSE_LOCATION";
    case AWS_HTTP_RESPONSE_PROXY_AUTHENTICATE:        return "AWS_HTTP_RESPONSE_PROXY_AUTHENTICATE";
    case AWS_HTTP_RESPONSE_RETRY_AFTER:               return "AWS_HTTP_RESPONSE_RETRY_AFTER";
    case AWS_HTTP_RESPONSE_SERVER:                    return "AWS_HTTP_RESPONSE_SERVER";
    case AWS_HTTP_RESPONSE_SET_COOKIE:                return "AWS_HTTP_RESPONSE_SET_COOKIE";
    case AWS_HTTP_RESPONSE_STRICT_TRANSPORT_SECURITY: return "AWS_HTTP_RESPONSE_STRICT_TRANSPORT_SECURITY";
    case AWS_HTTP_RESPONSE_UPGRADE:                   return "AWS_HTTP_RESPONSE_UPGRADE";
    case AWS_HTTP_RESPONSE_VARY:                      return "AWS_HTTP_RESPONSE_VARY";
    case AWS_HTTP_RESPONSE_VIA:                       return "AWS_HTTP_RESPONSE_VIA";
    case AWS_HTTP_RESPONSE_WWW_AUTHENTICATE:          return "AWS_HTTP_RESPONSE_WWW_AUTHENTICATE";
    }
    return NULL;
}

const char *aws_http_version_code_to_str(enum aws_http_version version) {
    switch (version) {
    case AWS_HTTP_VERSION_UNKNOWN: return "AWS_HTTP_VERSION_UNKNOWN";
    case AWS_HTTP_VERSION_1_0:     return "AWS_HTTP_VERSION_1_0";
    case AWS_HTTP_VERSION_1_1:     return "AWS_HTTP_VERSION_1_1";
    case AWS_HTTP_VERSION_2_0:     return "AWS_HTTP_VERSION_2_0";
    }
    return NULL;
}
