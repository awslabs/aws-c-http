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
        AWS_ERROR_HTTP_UNKNOWN,
        "Encountered an unknown error."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_PARSE,
        "Encountered an unexpected form when parsing an http message."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_USER_CALLBACK_EXIT,
        "User forced decoder to early quit by returning false from a callback."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_INVALID_PARSE_STATE,
        "Decoding/parsing was ran while the decoder object was in a poor state -- make sure to properly check for error codes before running the decoder."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_NO_BODY_DATA_BUFFERED,
        "`aws_http_release_body_data` cannot be called if there is no readable data buffered on the http connection."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_END_RANGE,
        "Not a real error and should never be seen."),
    AWS_DEFINE_ERROR_INFO_HTTP(
        AWS_ERROR_HTTP_CONNECTION_CLOSED,
        "Message not sent, as the connection has closed."),
};
/* clang-format on */

static struct aws_error_info_list s_list = {
    .error_list = s_errors,
    .count = AWS_ARRAY_SIZE(s_errors),
};

static bool s_error_strings_loaded = false;

void aws_http_load_error_strings(void) {
    if (!s_error_strings_loaded) {
        s_error_strings_loaded = true;
        aws_register_error_info(&s_list);
    }
}

static char s_upper(char c) {
    if (c >= 'a' && c <= 'z') {
        c += ('A' - 'a');
    }
    return c;
}

/* https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function */
static uint32_t s_aws_FNV1a(struct aws_byte_cursor cursor) {
    uint32_t h = (uint32_t)0x811C9DC5;
    while (cursor.len--) {
        char c = (char)s_upper(*cursor.ptr++);
        h = h ^ (uint32_t)c;
        h = h * (uint32_t)16777619;
    }
    return h;
}

/* Works like memcmp or strcmp, except is case-agonstic. */
static int s_strcmp_case_insensitive(const char *a, const char *b, size_t key_len) {
    for (size_t i = 0; i < key_len; ++i) {
        int d = s_upper(a[i]) - s_upper(b[i]);
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
#    define _CRT_SECURE_NO_WARNINGS
#    include <ctype.h>
#    include <stdint.h>
#    include <stdio.h>
#    include <string.h>

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
        *s = (char)s_upper(*s);
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

    printf("\n\nenum %s s_aws_http_str_to_enum_type(struct aws_byte_cursor cursor) {\n", enum_type);
    printf("    uint32_t h = s_aws_FNV1a(cursor);\n");
    printf("    char *ptr = (char *)cursor.ptr;\n");
    printf("    size_t len = cursor.len;\n");
    printf("    bool match = false;\n");
    printf("    int ret = 0;\n\n");
    printf("    switch (h) {\n");

    for (int i = 0; i < count; ++i) {
        uint64_t h = s_aws_FNV1a(strings[i]);
        printf("    case %lu:\n", h);
        printf("        match = !s_strcmp_case_insensitive(\"%s\", ptr, len);\n", strings[i]);
        printf("        ret = %s;\n", enums[i]);
        printf("        break;%s", i == count - 1 ? "\n" : "\n\n");
    }

    printf("    }\n\n");
    printf("    return match ? (enum %s)ret : AWS_HTTP_HEADER_UNKNOWN;\n", enum_type);
    printf("}");
    fclose(fp);

    return 0;
}
#endif

enum aws_http_method aws_http_str_to_method(struct aws_byte_cursor cursor) {
    uint32_t h = s_aws_FNV1a(cursor);
    char *ptr = (char *)cursor.ptr;
    size_t len = cursor.len;
    bool match = false;
    int ret = 0;

    switch (h) {
        case 2016099545:
            match = !s_strcmp_case_insensitive("CONNECT", ptr, len);
            ret = AWS_HTTP_METHOD_CONNECT;
            break;

        case 4168191690:
            match = !s_strcmp_case_insensitive("DELETE", ptr, len);
            ret = AWS_HTTP_METHOD_DELETE;
            break;

        case 2531704439:
            match = !s_strcmp_case_insensitive("GET", ptr, len);
            ret = AWS_HTTP_METHOD_GET;
            break;

        case 811237315:
            match = !s_strcmp_case_insensitive("HEAD", ptr, len);
            ret = AWS_HTTP_METHOD_HEAD;
            break;

        case 827600069:
            match = !s_strcmp_case_insensitive("OPTIONS", ptr, len);
            ret = AWS_HTTP_METHOD_OPTIONS;
            break;

        case 3498819145:
            match = !s_strcmp_case_insensitive("PATCH", ptr, len);
            ret = AWS_HTTP_METHOD_PATCH;
            break;

        case 1929554311:
            match = !s_strcmp_case_insensitive("POST", ptr, len);
            ret = AWS_HTTP_METHOD_POST;
            break;

        case 3995708942:
            match = !s_strcmp_case_insensitive("PUT", ptr, len);
            ret = AWS_HTTP_METHOD_PUT;
            break;

        case 746199118:
            match = !s_strcmp_case_insensitive("TRACE", ptr, len);
            ret = AWS_HTTP_METHOD_TRACE;
            break;
    }

    return match ? (enum aws_http_method)ret : AWS_HTTP_METHOD_UNKNOWN;
}

enum aws_http_header_name aws_http_str_to_header_name(struct aws_byte_cursor cursor) {
    uint32_t h = s_aws_FNV1a(cursor);
    char *ptr = (char *)cursor.ptr;
    size_t len = cursor.len;
    bool match = false;
    int ret = 0;

    switch (h) {
        case 547231721:
            match = !s_strcmp_case_insensitive("ACCEPT", ptr, len);
            ret = AWS_HTTP_HEADER_ACCEPT;
            break;

        case 3107960968:
            match = !s_strcmp_case_insensitive("ACCEPT-CHARSET", ptr, len);
            ret = AWS_HTTP_HEADER_ACCEPT_CHARSET;
            break;

        case 3161469017:
            match = !s_strcmp_case_insensitive("ACCEPT-ENCODING", ptr, len);
            ret = AWS_HTTP_HEADER_ACCEPT_ENCODING;
            break;

        case 648286550:
            match = !s_strcmp_case_insensitive("ACCEPT-LANGUAGE", ptr, len);
            ret = AWS_HTTP_HEADER_ACCEPT_LANGUAGE;
            break;

        case 2404564518:
            match = !s_strcmp_case_insensitive("ACCEPT-RANGES", ptr, len);
            ret = AWS_HTTP_HEADER_ACCEPT_RANGES;
            break;

        case 2492886444:
            match = !s_strcmp_case_insensitive("ACCESS-CONTROL-ALLOW-ORIGIN", ptr, len);
            ret = AWS_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN;
            break;

        case 1853619452:
            match = !s_strcmp_case_insensitive("AGE", ptr, len);
            ret = AWS_HTTP_HEADER_AGE;
            break;

        case 1084331474:
            match = !s_strcmp_case_insensitive("ALLOW", ptr, len);
            ret = AWS_HTTP_HEADER_ALLOW;
            break;

        case 4194732382:
            match = !s_strcmp_case_insensitive("AUTHORIZATION", ptr, len);
            ret = AWS_HTTP_HEADER_AUTHORIZATION;
            break;

        case 987353997:
            match = !s_strcmp_case_insensitive("CACHE-CONTROL", ptr, len);
            ret = AWS_HTTP_HEADER_CACHE_CONTROL;
            break;

        case 707182617:
            match = !s_strcmp_case_insensitive("CONNECTION", ptr, len);
            ret = AWS_HTTP_HEADER_CONNECTION;
            break;

        case 3098799004:
            match = !s_strcmp_case_insensitive("CONTENT-DISPOSITION", ptr, len);
            ret = AWS_HTTP_HEADER_CONTENT_DISPOSITION;
            break;

        case 4106027624:
            match = !s_strcmp_case_insensitive("CONTENT-ENCODING", ptr, len);
            ret = AWS_HTTP_HEADER_CONTENT_ENCODING;
            break;

        case 1167503283:
            match = !s_strcmp_case_insensitive("CONTENT-LANGUAGE", ptr, len);
            ret = AWS_HTTP_HEADER_CONTENT_LANGUAGE;
            break;

        case 2630822013:
            match = !s_strcmp_case_insensitive("CONTENT-LENGTH", ptr, len);
            ret = AWS_HTTP_HEADER_CONTENT_LENGTH;
            break;

        case 2246872206:
            match = !s_strcmp_case_insensitive("CONTENT-LOCATION", ptr, len);
            ret = AWS_HTTP_HEADER_CONTENT_LOCATION;
            break;

        case 2090207370:
            match = !s_strcmp_case_insensitive("CONTENT-RANGE", ptr, len);
            ret = AWS_HTTP_HEADER_CONTENT_RANGE;
            break;

        case 3945365109:
            match = !s_strcmp_case_insensitive("CONTENT-TYPE", ptr, len);
            ret = AWS_HTTP_HEADER_CONTENT_TYPE;
            break;

        case 453382463:
            match = !s_strcmp_case_insensitive("COOKIE", ptr, len);
            ret = AWS_HTTP_HEADER_COOKIE;
            break;

        case 3221746841:
            match = !s_strcmp_case_insensitive("DATE", ptr, len);
            ret = AWS_HTTP_HEADER_DATE;
            break;

        case 3002887936:
            match = !s_strcmp_case_insensitive("ETAG", ptr, len);
            ret = AWS_HTTP_HEADER_ETAG;
            break;

        case 40228184:
            match = !s_strcmp_case_insensitive("EXPECT", ptr, len);
            ret = AWS_HTTP_HEADER_EXPECT;
            break;

        case 1922461731:
            match = !s_strcmp_case_insensitive("EXPIRES", ptr, len);
            ret = AWS_HTTP_HEADER_EXPIRES;
            break;

        case 2618337227:
            match = !s_strcmp_case_insensitive("FORWARDED", ptr, len);
            ret = AWS_HTTP_HEADER_FORWARDED;
            break;

        case 2478748789:
            match = !s_strcmp_case_insensitive("FROM", ptr, len);
            ret = AWS_HTTP_HEADER_FROM;
            break;

        case 3991944751:
            match = !s_strcmp_case_insensitive("HOST", ptr, len);
            ret = AWS_HTTP_HEADER_HOST;
            break;

        case 4110033290:
            match = !s_strcmp_case_insensitive("IF-MATCH", ptr, len);
            ret = AWS_HTTP_HEADER_IF_MATCH;
            break;

        case 247469449:
            match = !s_strcmp_case_insensitive("IF-MODIFIED-SINCE", ptr, len);
            ret = AWS_HTTP_HEADER_IF_MODIFIED_SINCE;
            break;

        case 1929613911:
            match = !s_strcmp_case_insensitive("IF-NONE-MATCH", ptr, len);
            ret = AWS_HTTP_HEADER_IF_NONE_MATCH;
            break;

        case 2986103070:
            match = !s_strcmp_case_insensitive("IF-RANGE", ptr, len);
            ret = AWS_HTTP_HEADER_IF_RANGE;
            break;

        case 743147306:
            match = !s_strcmp_case_insensitive("IF-UNMODIFIED-SINCE", ptr, len);
            ret = AWS_HTTP_HEADER_IF_UNMODIFIED_SINCE;
            break;

        case 1679160352:
            match = !s_strcmp_case_insensitive("KEEP-ALIVE", ptr, len);
            ret = AWS_HTTP_HEADER_KEEP_ALIVE;
            break;

        case 3239887275:
            match = !s_strcmp_case_insensitive("LAST-MODIFIED", ptr, len);
            ret = AWS_HTTP_HEADER_LAST_MODIFIED;
            break;

        case 187591081:
            match = !s_strcmp_case_insensitive("LINK", ptr, len);
            ret = AWS_HTTP_HEADER_LINK;
            break;

        case 697559654:
            match = !s_strcmp_case_insensitive("LOCATION", ptr, len);
            ret = AWS_HTTP_HEADER_LOCATION;
            break;

        case 813576502:
            match = !s_strcmp_case_insensitive("MAX-FORWARDS", ptr, len);
            ret = AWS_HTTP_HEADER_MAX_FORWARDS;
            break;

        case 1999205135:
            match = !s_strcmp_case_insensitive("ORIGIN", ptr, len);
            ret = AWS_HTTP_HEADER_ORIGIN;
            break;

        case 645626959:
            match = !s_strcmp_case_insensitive("PROXY-AUTHENTICATE", ptr, len);
            ret = AWS_HTTP_HEADER_PROXY_AUTHENTICATE;
            break;

        case 2982521275:
            match = !s_strcmp_case_insensitive("PROXY-AUTHORIZATION", ptr, len);
            ret = AWS_HTTP_HEADER_PROXY_AUTHORIZATION;
            break;

        case 1696719282:
            match = !s_strcmp_case_insensitive("RANGE", ptr, len);
            ret = AWS_HTTP_HEADER_RANGE;
            break;

        case 3692982486:
            match = !s_strcmp_case_insensitive("REFERRER", ptr, len);
            ret = AWS_HTTP_HEADER_REFERRER;
            break;

        case 701237652:
            match = !s_strcmp_case_insensitive("REFRESH", ptr, len);
            ret = AWS_HTTP_HEADER_REFRESH;
            break;

        case 3631052982:
            match = !s_strcmp_case_insensitive("RETRY-AFTER", ptr, len);
            ret = AWS_HTTP_HEADER_RETRY_AFTER;
            break;

        case 3820123666:
            match = !s_strcmp_case_insensitive("SERVER", ptr, len);
            ret = AWS_HTTP_HEADER_SERVER;
            break;

        case 1170440408:
            match = !s_strcmp_case_insensitive("SET-COOKIE", ptr, len);
            ret = AWS_HTTP_HEADER_SET_COOKIE;
            break;

        case 1516005313:
            match = !s_strcmp_case_insensitive("STRICT-TRANSPORT-SECURITY", ptr, len);
            ret = AWS_HTTP_HEADER_STRICT_TRANSPORT_SECURITY;
            break;

        case 2976646412:
            match = !s_strcmp_case_insensitive("TRANSFER-ENCODING", ptr, len);
            ret = AWS_HTTP_HEADER_TRANSFER_ENCODING;
            break;

        case 988952599:
            match = !s_strcmp_case_insensitive("UPGRADE", ptr, len);
            ret = AWS_HTTP_HEADER_UPGRADE;
            break;

        case 635591758:
            match = !s_strcmp_case_insensitive("USER-AGENT", ptr, len);
            ret = AWS_HTTP_HEADER_USER_AGENT;
            break;

        case 1050481221:
            match = !s_strcmp_case_insensitive("VARY", ptr, len);
            ret = AWS_HTTP_HEADER_VARY;
            break;

        case 3958155251:
            match = !s_strcmp_case_insensitive("VIA", ptr, len);
            ret = AWS_HTTP_HEADER_VIA;
            break;

        case 4075666274:
            match = !s_strcmp_case_insensitive("WWW-AUTHENTICATE", ptr, len);
            ret = AWS_HTTP_HEADER_WWW_AUTHENTICATE;
            break;
    }

    return match ? (enum aws_http_header_name)ret : AWS_HTTP_HEADER_UNKNOWN;
}

enum aws_http_version aws_http_str_to_version(struct aws_byte_cursor cursor) {
    uint32_t h = s_aws_FNV1a(cursor);
    char *ptr = (char *)cursor.ptr;
    size_t len = cursor.len;
    bool match = false;
    int ret = 0;

    switch (h) {
        case 4137103867:
            match = !s_strcmp_case_insensitive("HTTP/1.0", ptr, len);
            ret = AWS_HTTP_VERSION_1_0;
            break;

        case 4120326248:
            match = !s_strcmp_case_insensitive("HTTP/1.1", ptr, len);
            ret = AWS_HTTP_VERSION_1_1;
            break;

        case 3110833482:
            match = !s_strcmp_case_insensitive("HTTP/2.0", ptr, len);
            ret = AWS_HTTP_VERSION_2_0;
            break;
    }

    return match ? (enum aws_http_version)ret : AWS_HTTP_VERSION_UNKNOWN;
}

enum aws_http_code aws_http_int_to_code(int code) {
    return (enum aws_http_code)code;
}

#define AWS_HTTP_CHECK_CODE(code)                                                                                      \
    case AWS_HTTP_HEADER_##code:                                                                                       \
        return #code

const char *aws_http_header_name_to_str(enum aws_http_header_name name) {
    switch (name) {
        AWS_HTTP_CHECK_CODE(ACCEPT);
        AWS_HTTP_CHECK_CODE(ACCEPT_CHARSET);
        AWS_HTTP_CHECK_CODE(ACCEPT_ENCODING);
        AWS_HTTP_CHECK_CODE(ACCEPT_LANGUAGE);
        AWS_HTTP_CHECK_CODE(ACCEPT_RANGES);
        AWS_HTTP_CHECK_CODE(ACCESS_CONTROL_ALLOW_ORIGIN);
        AWS_HTTP_CHECK_CODE(AGE);
        AWS_HTTP_CHECK_CODE(ALLOW);
        AWS_HTTP_CHECK_CODE(AUTHORIZATION);
        AWS_HTTP_CHECK_CODE(CACHE_CONTROL);
        AWS_HTTP_CHECK_CODE(CONNECTION);
        AWS_HTTP_CHECK_CODE(CONTENT_DISPOSITION);
        AWS_HTTP_CHECK_CODE(CONTENT_ENCODING);
        AWS_HTTP_CHECK_CODE(CONTENT_LANGUAGE);
        AWS_HTTP_CHECK_CODE(CONTENT_LENGTH);
        AWS_HTTP_CHECK_CODE(CONTENT_LOCATION);
        AWS_HTTP_CHECK_CODE(CONTENT_RANGE);
        AWS_HTTP_CHECK_CODE(CONTENT_TYPE);
        AWS_HTTP_CHECK_CODE(COOKIE);
        AWS_HTTP_CHECK_CODE(DATE);
        AWS_HTTP_CHECK_CODE(ETAG);
        AWS_HTTP_CHECK_CODE(EXPECT);
        AWS_HTTP_CHECK_CODE(EXPIRES);
        AWS_HTTP_CHECK_CODE(FORWARDED);
        AWS_HTTP_CHECK_CODE(FROM);
        AWS_HTTP_CHECK_CODE(HOST);
        AWS_HTTP_CHECK_CODE(IF_MATCH);
        AWS_HTTP_CHECK_CODE(IF_MODIFIED_SINCE);
        AWS_HTTP_CHECK_CODE(IF_NONE_MATCH);
        AWS_HTTP_CHECK_CODE(IF_RANGE);
        AWS_HTTP_CHECK_CODE(IF_UNMODIFIED_SINCE);
        AWS_HTTP_CHECK_CODE(KEEP_ALIVE);
        AWS_HTTP_CHECK_CODE(LAST_MODIFIED);
        AWS_HTTP_CHECK_CODE(LINK);
        AWS_HTTP_CHECK_CODE(LOCATION);
        AWS_HTTP_CHECK_CODE(MAX_FORWARDS);
        AWS_HTTP_CHECK_CODE(ORIGIN);
        AWS_HTTP_CHECK_CODE(PROXY_AUTHENTICATE);
        AWS_HTTP_CHECK_CODE(PROXY_AUTHORIZATION);
        AWS_HTTP_CHECK_CODE(RANGE);
        AWS_HTTP_CHECK_CODE(REFERRER);
        AWS_HTTP_CHECK_CODE(REFRESH);
        AWS_HTTP_CHECK_CODE(RETRY_AFTER);
        AWS_HTTP_CHECK_CODE(SERVER);
        AWS_HTTP_CHECK_CODE(SET_COOKIE);
        AWS_HTTP_CHECK_CODE(STRICT_TRANSPORT_SECURITY);
        AWS_HTTP_CHECK_CODE(TRANSFER_ENCODING);
        AWS_HTTP_CHECK_CODE(UPGRADE);
        AWS_HTTP_CHECK_CODE(USER_AGENT);
        AWS_HTTP_CHECK_CODE(VARY);
        AWS_HTTP_CHECK_CODE(VIA);
        AWS_HTTP_CHECK_CODE(WWW_AUTHENTICATE);
        default:
            return "UNKNOWN";
    }
}

#undef AWS_HTTP_CHECK_CODE

const char *aws_http_method_to_str(enum aws_http_method method) {
    switch (method) {
        case AWS_HTTP_METHOD_UNKNOWN:
            return "UNKNOWN";
        case AWS_HTTP_METHOD_CONNECT:
            return "CONNECT";
        case AWS_HTTP_METHOD_DELETE:
            return "DELETE";
        case AWS_HTTP_METHOD_GET:
            return "GET";
        case AWS_HTTP_METHOD_HEAD:
            return "HEAD";
        case AWS_HTTP_METHOD_OPTIONS:
            return "OPTIONS";
        case AWS_HTTP_METHOD_PATCH:
            return "PATCH";
        case AWS_HTTP_METHOD_POST:
            return "POST";
        case AWS_HTTP_METHOD_PUT:
            return "PUT";
        case AWS_HTTP_METHOD_TRACE:
            return "TRACE";
        default:
            return NULL;
    }
}

const char *aws_http_version_to_str(enum aws_http_version version) {
    switch (version) {
        case AWS_HTTP_VERSION_UNKNOWN:
            return "UNKNOWN";
        case AWS_HTTP_VERSION_1_0:
            return "1.0";
        case AWS_HTTP_VERSION_1_1:
            return "1.1";
        case AWS_HTTP_VERSION_2_0:
            return "2.0";
        default:
            return NULL;
    }
}

const char *aws_http_code_to_str(enum aws_http_code code) {
    switch (code) {
        case AWS_HTTP_CODE_CONTINUE:
            return "Continue";

        case AWS_HTTP_CODE_SWITCHING_PROTOCOLS:
            return "Switching Protocols";

        case AWS_HTTP_CODE_PROCESSING:
            return "Processing";

        case AWS_HTTP_CODE_OK:
            return "OK";

        case AWS_HTTP_CODE_CREATED:
            return "Creaetd";

        case AWS_HTTP_CODE_ACCEPTED:
            return "Accepted";

        case AWS_HTTP_CODE_NON_AUTHORITATIVE_INFORMATION:
            return "Non-Authoritative Information";

        case AWS_HTTP_CODE_NO_CONTENT:
            return "No Content";

        case AWS_HTTP_CODE_RESET_CONTENT:
            return "Reset Content";

        case AWS_HTTP_CODE_PARTIAL_CONTENT:
            return "Partial Content";

        case AWS_HTTP_CODE_MULTI_STATUS:
            return "Multi-Status";

        case AWS_HTTP_CODE_ALREADY_REPORTED:
            return "Already Reported";

        case AWS_HTTP_CODE_IM_USED:
            return "IM Used";

        case AWS_HTTP_CODE_MULTIPLE_CHOICES:
            return "Multiple Choice";

        case AWS_HTTP_CODE_MOVED_PERMANENTLY:
            return "Moved Permantently";

        case AWS_HTTP_CODE_FOUND:
            return "Found";

        case AWS_HTTP_CODE_SEE_OTHER:
            return "See Other";

        case AWS_HTTP_CODE_NOT_MODIFIED:
            return "Not Modified";

        case AWS_HTTP_CODE_USE_PROXY:
            return "Use Proxy";

        case AWS_HTTP_CODE_SWITCH_PROXY:
            return "Switch Proxy";

        case AWS_HTTP_CODE_TEMPORARY_REDIRECT:
            return "Temporary Redirect";

        case AWS_HTTP_CODE_PERMANENT_REDIRECT:
            return "Permament Redirect";

        case AWS_HTTP_CODE_BAD_REQUEST:
            return "Bad Request";

        case AWS_HTTP_CODE_UNAUTHORIZED:
            return "Unauthorized";

        case AWS_HTTP_CODE_PAYMENT_REQUIRED:
            return "Payment Required";

        case AWS_HTTP_CODE_FORBIDDEN:
            return "Forbidden";

        case AWS_HTTP_CODE_NOT_FOUND:
            return "Not Found";

        case AWS_HTTP_CODE_METHOD_NOT_ALLOWED:
            return "Method Not Allowed";

        case AWS_HTTP_CODE_NOT_ACCEPTABLE:
            return "Not Acceptable";

        case AWS_HTTP_CODE_PROXY_AUTHENTICATION_REQUIRED:
            return "Proxy Authentication Required";

        case AWS_HTTP_CODE_REQUEST_TIMEOUT:
            return "Request Timeout";

        case AWS_HTTP_CODE_CONFLICT:
            return "Conflict";

        case AWS_HTTP_CODE_GONE:
            return "Gone";

        case AWS_HTTP_CODE_LENGTH_REQUIRED:
            return "Length Required";

        case AWS_HTTP_CODE_PRECONDITION_FAILED:
            return "Precondition Failed";

        case AWS_HTTP_CODE_REQUEST_ENTITY_TOO_LARGE:
            return "Payload Too Large";

        case AWS_HTTP_CODE_REQUEST_URI_TOO_LONG:
            return "URI Too Long";

        case AWS_HTTP_CODE_UNSUPPORTED_MEDIA_TYPE:
            return "Unsupported Media Type";

        case AWS_HTTP_CODE_REQUESTED_RANGE_NOT_SATISFIABLE:
            return "Request Range Not Satisfiable";

        case AWS_HTTP_CODE_EXPECTATION_FAILED:
            return "Expectation Failed";

        case AWS_HTTP_CODE_IM_A_TEAPOT:
            return "I'm a teapot";

        case AWS_HTTP_CODE_AUTHENTICATION_TIMEOUT:
            return "Authentication Timeout";

        case AWS_HTTP_CODE_METHOD_FAILURE:
            return "Method Failuer";

        case AWS_HTTP_CODE_UNPROCESSABLE_ENTITY:
            return "Unprocessable Entity";

        case AWS_HTTP_CODE_LOCKED:
            return "Locked";

        case AWS_HTTP_CODE_FAILED_DEPENDENCY:
            return "Failed Dependency";

        case AWS_HTTP_CODE_UPGRADE_REQUIRED:
            return "Upgrade Required";

        case AWS_HTTP_CODE_PRECONDITION_REQUIRED:
            return "Precondition Required";

        case AWS_HTTP_CODE_TOO_MANY_REQUESTS:
            return "Too Many Requests";

        case AWS_HTTP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE:
            return "Request Header Fields Too Large";

        case AWS_HTTP_CODE_LOGIN_TIMEOUT:
            return "Login Timeout";

        case AWS_HTTP_CODE_NO_RESPONSE:
            return "No Response";

        case AWS_HTTP_CODE_RETRY_WITH:
            return "Retry With";

        case AWS_HTTP_CODE_BLOCKED:
            return "Blocked";

        case AWS_HTTP_CODE_REDIRECT:
            return "Redirect";

        case AWS_HTTP_CODE_REQUEST_HEADER_TOO_LARGE:
            return "Request Header Too Large";

        case AWS_HTTP_CODE_CERT_ERROR:
            return "Certification Error";

        case AWS_HTTP_CODE_NO_CERT:
            return "No Certification";

        case AWS_HTTP_CODE_HTTP_TO_HTTPS:
            return "HTTP To HTTPS";

        case AWS_HTTP_CODE_CLIENT_CLOSED_TO_REQUEST:
            return "Client Closed To Request";

        case AWS_HTTP_CODE_INTERNAL_SERVER_ERROR:
            return "Internal Server Error";

        case AWS_HTTP_CODE_NOT_IMPLEMENTED:
            return "Not Implemented";

        case AWS_HTTP_CODE_BAD_GATEWAY:
            return "Bad Gateway";

        case AWS_HTTP_CODE_SERVICE_UNAVAILABLE:
            return "Service Unavailable";

        case AWS_HTTP_CODE_GATEWAY_TIMEOUT:
            return "Gateway Timeout";

        case AWS_HTTP_CODE_HTTP_VERSION_NOT_SUPPORTED:
            return "HTTP Version Not Supported";

        case AWS_HTTP_CODE_VARIANT_ALSO_NEGOTIATES:
            return "Variant Also Negotiates";

        case AWS_HTTP_CODE_INSUFFICIENT_STORAGE:
            return "Insufficient Storage";

        case AWS_HTTP_CODE_LOOP_DETECTED:
            return "Loop Detected";

        case AWS_HTTP_CODE_BANDWIDTH_LIMIT_EXCEEDED:
            return "Bandwidth Limit Exceeded";

        case AWS_HTTP_CODE_NOT_EXTENDED:
            return "Not Extended";

        case AWS_HTTP_CODE_NETWORK_AUTHENTICATION_REQUIRED:
            return "Authentication Required";

        case AWS_HTTP_CODE_NETWORK_READ_TIMEOUT:
            return "Read Timeout";

        case AWS_HTTP_CODE_NETWORK_CONNECT_TIMEOUT:
            return "Network Connect Timeout";

        default:
            return NULL;
    }
}
