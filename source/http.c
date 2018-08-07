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

#include <ctype.h>

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/error.h>

#include <aws/http/http.h>

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

static bool s_aws_http_eol(char c) {
    switch (c) {
    case '\n': return true;
    case '\r': return true;
    }
    return false;
}

static inline uint64_t s_aws_FNV1a(struct aws_http_str str) {
    uint64_t h = (uint64_t)14695981039346656037U;
    while (str.begin < str.end) {
        char c = (char)toupper(*str.begin++);
        h = h ^ (uint64_t)c;
        h = h * (uint64_t)1099511628211;
    }
    return h;
}

static enum aws_http_request_method s_aws_http_str_to_method(struct aws_http_str str) {
    uint64_t h = s_aws_FNV1a(str);
    switch (h) {
    default: return AWS_HTTP_REQUEST_METHOD_UNKNOWN;
    case 13878768130668514073U: return AWS_HTTP_REQUEST_METHOD_CONNECT; /* CONNECT */
    case 6688223789818863754U: return AWS_HTTP_REQUEST_METHOD_DELETE; /* DELETE */
    case 16897051813516574231U: return AWS_HTTP_REQUEST_METHOD_GET; /* GET */
    case 5445507090902606211U: return AWS_HTTP_REQUEST_METHOD_HEAD; /* HEAD */
    case 9785202362801442661U: return AWS_HTTP_REQUEST_METHOD_OPTIONS; /* OPTIONS */
    case 13744789256893389385U: return AWS_HTTP_REQUEST_METHOD_PATCH; /* PATCH */
    case 11549668268942925703U: return AWS_HTTP_REQUEST_METHOD_POST; /* POST */
    case 10200565306531135182U: return AWS_HTTP_REQUEST_METHOD_PUT; /* PUT */
    case 9913483816396974670U: return AWS_HTTP_REQUEST_METHOD_TRACE; /* TRACE */
    }
}

static enum aws_http_version s_aws_http_str_to_version(struct aws_http_str str) {
    uint64_t h = s_aws_FNV1a(str);
    switch (h) {
    default: return AWS_HTTP_REQUEST_METHOD_UNKNOWN;
    case 3142066716091816827U: return AWS_HTTP_VERSION_1_0; /* HTTP/1.0 */
    case 3142065616580188616U: return AWS_HTTP_VERSION_1_1; /* HTTP/1.1 */
    case 1284911312185428074U: return AWS_HTTP_VERSION_2_0; /* HTTP/2.0 */
    }
}

static enum aws_http_request_key s_aws_http_str_to_request_key(struct aws_http_str str) {
    uint64_t h = s_aws_FNV1a(str);
    switch (h) {
    default: return AWS_HTTP_REQUEST_METHOD_UNKNOWN;
    case 13730350826456040585U: return AWS_HTTP_REQUEST_KEY_ACCEPT; /* ACCEPT */
    case 11998153583302541512U: return AWS_HTTP_REQUEST_KEY_ACCEPT_CHARSET; /* ACCEPT-CHARSET */
    case 16472008978911737049U: return AWS_HTTP_REQUEST_KEY_ACCEPT_ENCODING; /* ACCEPT-ENCODING */
    case 10881689647198945718U: return AWS_HTTP_REQUEST_KEY_ACCEPT_LANGUAGE; /* ACCEPT-LANGUAGE */
    case 4769608422278259006U: return AWS_HTTP_REQUEST_KEY_AUTHORIZATION; /* AUTHORIZATION */
    case 8404053799361727437U: return AWS_HTTP_REQUEST_KEY_CACHE_CONTROL; /* CACHE-CONTROL */
    case 13363958336066981721U: return AWS_HTTP_REQUEST_KEY_CONNECTION; /* CONNECTION */
    case 2077250306427260445U: return AWS_HTTP_REQUEST_KEY_CONTENT_LENGTH; /* CONTENT-LENGTH */
    case 9038029200640296341U: return AWS_HTTP_REQUEST_KEY_CONTENT_TYPE; /* CONTENT-TYPE */
    case 15778669228840481407U: return AWS_HTTP_REQUEST_KEY_COOKIE; /* COOKIE */
    case 11057272162187349817U: return AWS_HTTP_REQUEST_KEY_DATE; /* DATE */
    case 7073337260905031384U: return AWS_HTTP_REQUEST_KEY_EXPECT; /* EXPECT */
    case 3479755954935787829U: return AWS_HTTP_REQUEST_KEY_FORWARDED; /* FOWARDED */
    case 13566972404832258421U: return AWS_HTTP_REQUEST_KEY_FROM; /* FROM */
    case 9085161059174616367U: return AWS_HTTP_REQUEST_KEY_HOST; /* HOST */
    case 6418037819517172938U: return AWS_HTTP_REQUEST_KEY_IF_MATCH; /* IF-MATCH */
    case 4117785351877396457U: return AWS_HTTP_REQUEST_KEY_IF_MODIFIED_SINCE; /* IF-MODIFIED-SINCE */
    case 8104367861445127735U: return AWS_HTTP_REQUEST_KEY_IF_NONE_MATCH; /* IF-NONE-MATCH */
    case 7240927477939468126U: return AWS_HTTP_REQUEST_KEY_IF_RANGE; /* IF-RANGE */
    case 16642224557580229834U: return AWS_HTTP_REQUEST_KEY_IF_UNMODIFIED_SINCE; /* IF-UNMODIFIED-SINCE */
    case 3496160052878495872U: return AWS_HTTP_REQUEST_KEY_KEEP_ALIVE; /* KEEP-ALIVE */
    case 6343919293466479542U: return AWS_HTTP_REQUEST_KEY_MAX_FORWARDS; /* MAX-FORWARDS */
    case 2258293222208450831U: return AWS_HTTP_REQUEST_KEY_ORIGIN; /* ORIGIN */
    case 4426599689128916827U: return AWS_HTTP_REQUEST_KEY_PROXY_AUTHORIZATION; /* PROXY-AUTHORIZATION */
    case 2758068308593703698U: return AWS_HTTP_REQUEST_KEY_RANGE; /* RANGE */
    case 1987516960552772662U: return AWS_HTTP_REQUEST_KEY_REFERRER; /* REFERRER */
    case 6256811187728553230U: return AWS_HTTP_REQUEST_KEY_USER_AGENT; /* USER-AGENT */
    case 8932950445327619603U: return AWS_HTTP_REQUEST_KEY_VIA; /* VIA */
    }
}

static enum aws_http_response_key s_aws_http_str_to_response_key(struct aws_http_str str) {
    uint64_t h = s_aws_FNV1a(str);
    switch (h) {
    default: return AWS_HTTP_REQUEST_METHOD_UNKNOWN;
    case 10235293050403537958U: return AWS_HTTP_RESPONSE_KEY_ACCEPT_RANGES; /* ACCEPT-RANGES */
    case 18025011105778868284U: return AWS_HTTP_RESPONSE_KEY_AGE; /* AGE */
    case 13991742668690892754U: return AWS_HTTP_RESPONSE_KEY_ALLOW; /* ALLOW */
    case 8404053799361727437U: return AWS_HTTP_RESPONSE_KEY_CACHE_CONTROL; /* CACHE-CONTROL */
    case 7663579564929273116U: return AWS_HTTP_RESPONSE_KEY_CONTENT_DISPOSITION; /* CONTENT-DISPOSITION */
    case 11752469631340170856U: return AWS_HTTP_RESPONSE_KEY_CONTENT_ENCODING; /* CONTENT-ENCODING */
    case 8829838042123945811U: return AWS_HTTP_RESPONSE_KEY_CONTENT_LANGUAGE; /* CONTENT-LANGUAGE */
    case 2077250306427260445U: return AWS_HTTP_RESPONSE_KEY_CONTENT_LENGTH; /* CONTENT-LENGTH */
    case 12653014935277881550U: return AWS_HTTP_RESPONSE_KEY_CONTENT_LOCATION; /* CONTENT-LOCATION */
    case 17600038849846870634U: return AWS_HTTP_RESPONSE_KEY_CONTENT_RANGE; /* CONTENT-RANGE */
    case 9038029200640296341U: return AWS_HTTP_RESPONSE_KEY_CONTENT_TYPE; /* CONTENT-TYPE */
    case 11057272162187349817U: return AWS_HTTP_RESPONSE_KEY_DATE; /* DATE */
    case 316544368650233792U: return AWS_HTTP_RESPONSE_KEY_ETAG; /* ETAG */
    case 2436777764307782475U: return AWS_HTTP_RESPONSE_KEY_LAST_MODIFIED; /* LAST-MODIFIED */
    case 5950553309356616713U: return AWS_HTTP_RESPONSE_KEY_LINK; /* LINK */
    case 18356742770282409510U: return AWS_HTTP_RESPONSE_KEY_LOCATION; /* LOCATION */
    case 6870506677877940815U: return AWS_HTTP_RESPONSE_KEY_PROXY_AUTHENTICATE; /* PROXY-AUTHENTICATE */
    case 694305183914426550U: return AWS_HTTP_RESPONSE_KEY_RETRY_AFTER; /* RETRY-AFTER */
    case 15870971199206770642U: return AWS_HTTP_RESPONSE_KEY_SERVER; /* SERVER */
    case 1899463423072374126U: return AWS_HTTP_RESPONSE_KEY_SET_COOKIE; /* SER-COOKIE */
    case 10109864252571853441U: return AWS_HTTP_RESPONSE_KEY_STRICT_TRANSPORT_SECURITY; /* STRICT-TRANSPORT-SECURITY */
    case 15525098723723187301U: return AWS_HTTP_RESPONSE_KEY_VARY; /* VARY */
    case 8932950445327619603U: return AWS_HTTP_RESPONSE_KEY_VIA; /* VIA */
    case 7594562872792977346U: return AWS_HTTP_RESPONSE_KEY_WWW_AUTHENTICATE; /* WWW-AUTHENTICATE */
    }
}

static inline int s_aws_http_skip_space(struct aws_http_str *input) {
    const char *scan = input->begin;
    do
    {
        if (!(scan < input->end)) {
            return AWS_OP_ERR;
        }
    } while (*scan++ != ' ');
    input->begin = scan;
    return AWS_OP_SUCCESS;
}

static inline void s_aws_http_trim_trailing_space(struct aws_http_str *str) {
    const char *end = str->end - 1;
    while (end > str->begin && *end == ' ') {
        end--;
    }
    str->end = end + 1;
}

static int s_aws_http_scan(struct aws_http_str *input, struct aws_http_str *out, char search) {
    const char *scan = input->begin;
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
    char c;
    do {
        c = *scan;
        if (!(scan < input->end)) {
            out->begin = input->begin;
            out->end = input->begin = scan;
            return AWS_OP_SUCCESS;
        }
        ++scan;
    } while (!isspace(c));
    if (c == '\r') {
        if (scan < input->end + 1 && *scan++ != '\n') {
            return AWS_OP_ERR;
        }
    }
    out->begin = input->begin;
    out->end = scan - 2;
    input->begin = scan;
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

#define AWS_HTTP_CHECK(X) do { if (!(X)) { goto aws_error; } } while (0)

int aws_http_request_init(struct aws_allocator *alloc, struct aws_http_request *request, const void *buffer, size_t size) {
    struct aws_http_str input;
    struct aws_http_str str;
    struct aws_array_list headers;
    aws_array_list_init_dynamic(&headers, alloc, 16, sizeof(struct aws_http_header));
    AWS_ZERO_STRUCT(*request);

    input.begin = (const char *)buffer;
    input.end = input.begin + size;

    /* Method. */
    AWS_HTTP_CHECK(s_aws_http_scan(&input, &str, ' ') == AWS_OP_SUCCESS);
    request->method = s_aws_http_str_to_method(str);
    AWS_HTTP_CHECK(request->method != AWS_HTTP_REQUEST_METHOD_UNKNOWN);

    /* Target URI. */
    AWS_HTTP_CHECK(s_aws_http_scan(&input, &str, ' ') == AWS_OP_SUCCESS);
    request->target = str;

    /* HTTP version. */
    AWS_HTTP_CHECK(s_aws_http_scan_for_eol_or_eos(&input, &str) == AWS_OP_SUCCESS);
    request->version = s_aws_http_str_to_version(str);
    AWS_HTTP_CHECK(request->version != AWS_HTTP_VERSION_UNKNOWN);

    /* Scan for headers. */
    int content_length = 0;
    while (!s_aws_http_is_end_of_headers(&input)) {
        struct aws_http_header header_field;
        AWS_HTTP_CHECK(s_aws_http_scan(&input, &str, ':') == AWS_OP_SUCCESS);
        header_field.key_str = str;
        header_field.key = s_aws_http_str_to_request_key(str);

        bool has_content = false;
        if (header_field.key == AWS_HTTP_REQUEST_KEY_CONTENT_LENGTH) {
            has_content = true;
        }

        AWS_HTTP_CHECK(s_aws_http_skip_space(&input) == AWS_OP_SUCCESS);
        AWS_HTTP_CHECK(s_aws_http_scan_for_eol_or_eos(&input, &str) == AWS_OP_SUCCESS);
        header_field.value_str = str;

        if (has_content) {
            char *end;
            content_length = strtol(header_field.value_str.begin, &end, 10);
            AWS_HTTP_CHECK(header_field.value_str.begin != end);
        }

        aws_array_list_push_back(&headers, &header_field);
    }
    request->headers = (struct aws_http_header *)headers.data;
    request->header_count = headers.length;
    request->alloc = alloc;

    if (content_length) {
        AWS_HTTP_CHECK(s_aws_http_expect_eol(&input));

        /* Read in content here. Handle chunked encoding? */

        request->body.begin = input.begin;
        request->body.end = input.begin + content_length;
    } else {
        request->body.begin = NULL;
        request->body.end = NULL;
    }

    return AWS_OP_SUCCESS;

aws_error:
    aws_raise_error(AWS_HTTP_ERROR_PARSE);
    return AWS_OP_ERR;
}

void aws_http_request_clean_up(struct aws_http_request *request) {
    aws_mem_release(request->alloc, request->headers);
    AWS_ZERO_STRUCT(*request);
}

int aws_http_response_init(struct aws_allocator *alloc, struct aws_http_response *response, const void *buffer, size_t size) {
    (void)alloc;
    (void)response;
    (void)buffer;
    (void)size;
    return 0;
}

int aws_http_response_clean_up(struct aws_http_response *response) {
    (void)response;
    return 0;
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
    case AWS_HTTP_REQUEST_KEY_UNKNOWN:             return "AWS_HTTP_REQUEST_KEY_UNKNOWN";
    case AWS_HTTP_REQUEST_KEY_ACCEPT:              return "AWS_HTTP_REQUEST_KEY_ACCEPT";
    case AWS_HTTP_REQUEST_KEY_ACCEPT_CHARSET:      return "AWS_HTTP_REQUEST_KEY_ACCEPT_CHARSET";
    case AWS_HTTP_REQUEST_KEY_ACCEPT_ENCODING:     return "AWS_HTTP_REQUEST_KEY_ACCEPT_ENCODING";
    case AWS_HTTP_REQUEST_KEY_ACCEPT_LANGUAGE:     return "AWS_HTTP_REQUEST_KEY_ACCEPT_LANGUAGE";
    case AWS_HTTP_REQUEST_KEY_AUTHORIZATION:       return "AWS_HTTP_REQUEST_KEY_AUTHORIZATION";
    case AWS_HTTP_REQUEST_KEY_CACHE_CONTROL:       return "AWS_HTTP_REQUEST_KEY_CACHE_CONTROL";
    case AWS_HTTP_REQUEST_KEY_CONNECTION:          return "AWS_HTTP_REQUEST_KEY_CONNECTION";
    case AWS_HTTP_REQUEST_KEY_CONTENT_LENGTH:      return "AWS_HTTP_REQUEST_KEY_CONTENT_LENGTH";
    case AWS_HTTP_REQUEST_KEY_CONTENT_TYPE:        return "AWS_HTTP_REQUEST_KEY_CONTENT_TYPE";
    case AWS_HTTP_REQUEST_KEY_COOKIE:              return "AWS_HTTP_REQUEST_KEY_COOKIE";
    case AWS_HTTP_REQUEST_KEY_DATE:                return "AWS_HTTP_REQUEST_KEY_DATE";
    case AWS_HTTP_REQUEST_KEY_EXPECT:              return "AWS_HTTP_REQUEST_KEY_EXPECT";
    case AWS_HTTP_REQUEST_KEY_FORWARDED:           return "AWS_HTTP_REQUEST_KEY_FORWARDED";
    case AWS_HTTP_REQUEST_KEY_FROM:                return "AWS_HTTP_REQUEST_KEY_FROM";
    case AWS_HTTP_REQUEST_KEY_HOST:                return "AWS_HTTP_REQUEST_KEY_HOST";
    case AWS_HTTP_REQUEST_KEY_IF_MATCH:            return "AWS_HTTP_REQUEST_KEY_IF_MATCH";
    case AWS_HTTP_REQUEST_KEY_IF_MODIFIED_SINCE:   return "AWS_HTTP_REQUEST_KEY_IF_MODIFIED_SINCE";
    case AWS_HTTP_REQUEST_KEY_IF_NONE_MATCH:       return "AWS_HTTP_REQUEST_KEY_IF_NONE_MATCH";
    case AWS_HTTP_REQUEST_KEY_IF_RANGE:            return "AWS_HTTP_REQUEST_KEY_IF_RANGE";
    case AWS_HTTP_REQUEST_KEY_IF_UNMODIFIED_SINCE: return "AWS_HTTP_REQUEST_KEY_IF_UNMODIFIED_SINCE";
    case AWS_HTTP_REQUEST_KEY_KEEP_ALIVE:          return "AWS_HTTP_REQUEST_KEY_KEEP_ALIVE";
    case AWS_HTTP_REQUEST_KEY_MAX_FORWARDS:        return "AWS_HTTP_REQUEST_KEY_MAX_FORWARDS";
    case AWS_HTTP_REQUEST_KEY_ORIGIN:              return "AWS_HTTP_REQUEST_KEY_ORIGIN";
    case AWS_HTTP_REQUEST_KEY_PROXY_AUTHORIZATION: return "AWS_HTTP_REQUEST_KEY_PROXY_AUTHORIZATION";
    case AWS_HTTP_REQUEST_KEY_RANGE:               return "AWS_HTTP_REQUEST_KEY_RANGE";
    case AWS_HTTP_REQUEST_KEY_USER_AGENT:          return "AWS_HTTP_REQUEST_KEY_USER_AGENT";
    case AWS_HTTP_REQUEST_KEY_VIA:                 return "AWS_HTTP_REQUEST_KEY_VIA";
    }
    return NULL;
}

AWS_HTTP_API const char *aws_http_response_key_to_str(enum aws_http_request_key key) {
    switch (key) {
    case AWS_HTTP_RESPONSE_KEY_ACCEPT_RANGES:             return "AWS_HTTP_RESPONSE_KEY_ACCEPT_RANGES";
    case AWS_HTTP_RESPONSE_KEY_AGE:                       return "AWS_HTTP_RESPONSE_KEY_AGE";
    case AWS_HTTP_RESPONSE_KEY_ALLOW:                     return "AWS_HTTP_RESPONSE_KEY_ALLOW";
    case AWS_HTTP_RESPONSE_KEY_CACHE_CONTROL:             return "AWS_HTTP_RESPONSE_KEY_CACHE_CONTROL";
    case AWS_HTTP_RESPONSE_KEY_CONTENT_DISPOSITION:       return "AWS_HTTP_RESPONSE_KEY_CONTENT_DISPOSITION";
    case AWS_HTTP_RESPONSE_KEY_CONTENT_ENCODING:          return "AWS_HTTP_RESPONSE_KEY_CONTENT_ENCODING";
    case AWS_HTTP_RESPONSE_KEY_CONTENT_LANGUAGE:          return "AWS_HTTP_RESPONSE_KEY_CONTENT_LANGUAGE";
    case AWS_HTTP_RESPONSE_KEY_CONTENT_LENGTH:            return "AWS_HTTP_RESPONSE_KEY_CONTENT_LENGTH";
    case AWS_HTTP_RESPONSE_KEY_CONTENT_LOCATION:          return "AWS_HTTP_RESPONSE_KEY_CONTENT_LOCATION";
    case AWS_HTTP_RESPONSE_KEY_CONTENT_RANGE:             return "AWS_HTTP_RESPONSE_KEY_CONTENT_RANGE";
    case AWS_HTTP_RESPONSE_KEY_CONTENT_TYPE:              return "AWS_HTTP_RESPONSE_KEY_CONTENT_TYPE";
    case AWS_HTTP_RESPONSE_KEY_DATE:                      return "AWS_HTTP_RESPONSE_KEY_DATE";
    case AWS_HTTP_RESPONSE_KEY_ETAG:                      return "AWS_HTTP_RESPONSE_KEY_ETAG";
    case AWS_HTTP_RESPONSE_KEY_LAST_MODIFIED:             return "AWS_HTTP_RESPONSE_KEY_LAST_MODIFIED";
    case AWS_HTTP_RESPONSE_KEY_LINK:                      return "AWS_HTTP_RESPONSE_KEY_LINK";
    case AWS_HTTP_RESPONSE_KEY_LOCATION:                  return "AWS_HTTP_RESPONSE_KEY_LOCATION";
    case AWS_HTTP_RESPONSE_KEY_PROXY_AUTHENTICATE:        return "AWS_HTTP_RESPONSE_KEY_PROXY_AUTHENTICATE";
    case AWS_HTTP_RESPONSE_KEY_RETRY_AFTER:               return "AWS_HTTP_RESPONSE_KEY_RETRY_AFTER";
    case AWS_HTTP_RESPONSE_KEY_SERVER:                    return "AWS_HTTP_RESPONSE_KEY_SERVER";
    case AWS_HTTP_RESPONSE_KEY_SET_COOKIE:                return "AWS_HTTP_RESPONSE_KEY_SET_COOKIE";
    case AWS_HTTP_RESPONSE_KEY_STRICT_TRANSPORT_SECURITY: return "AWS_HTTP_RESPONSE_KEY_STRICT_TRANSPORT_SECURITY";
    case AWS_HTTP_RESPONSE_KEY_UPGRADE:                   return "AWS_HTTP_RESPONSE_KEY_UPGRADE";
    case AWS_HTTP_RESPONSE_KEY_VARY:                      return "AWS_HTTP_RESPONSE_KEY_VARY";
    case AWS_HTTP_RESPONSE_KEY_VIA:                       return "AWS_HTTP_RESPONSE_KEY_VIA";
    case AWS_HTTP_RESPONSE_KEY_WWW_AUTHENTICATE:          return "AWS_HTTP_RESPONSE_KEY_WWW_AUTHENTICATE";
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
