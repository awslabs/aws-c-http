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

#include <aws/http/private/request_response_impl.h>

#include <aws/common/array_list.h>
#include <aws/common/string.h>
#include <aws/http/private/connection_impl.h>
#include <aws/io/logging.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

enum {
    /* Initial capacity for the aws_http_request.headers array-list. */
    AWS_HTTP_REQUEST_NUM_RESERVED_HEADERS = 16,
};

/* Type stored within the aws_http_request.headers array-list.
 * Different from aws_http_header in that it owns its string memory. */
struct aws_http_header_impl {
    struct aws_string *name;
    struct aws_string *value;
};

static int s_set_string_from_cursor(
    struct aws_string **dst,
    struct aws_byte_cursor cursor,
    struct aws_allocator *alloc) {

    /* If the cursor is empty, set dst to NULL */
    struct aws_string *new_str;
    if (cursor.len) {
        new_str = aws_string_new_from_array(alloc, cursor.ptr, cursor.len);
        if (!new_str) {
            return AWS_OP_ERR;
        }
    } else {
        new_str = NULL;
    }

    /* Replace existing value */
    aws_string_destroy(*dst);

    *dst = new_str;
    return AWS_OP_SUCCESS;
}

static struct aws_byte_cursor s_get_cursor_from_string(const struct aws_string *str) {
    AWS_PRECONDITION(!str || aws_string_is_valid(str));

    if (str) {
        return aws_byte_cursor_from_string(str);
    }

    return aws_byte_cursor_from_array(NULL, 0);
}

static void s_header_impl_clean_up(struct aws_http_header_impl *header_impl) {
    aws_string_destroy(header_impl->name);
    aws_string_destroy(header_impl->value);
    AWS_ZERO_STRUCT(*header_impl);
}

static int s_header_impl_init(
    struct aws_http_header_impl *header_impl,
    const struct aws_http_header *header_view,
    struct aws_allocator *alloc) {

    AWS_ZERO_STRUCT(*header_impl);

    int err = s_set_string_from_cursor(&header_impl->name, header_view->name, alloc);
    if (err) {
        goto error;
    }

    err = s_set_string_from_cursor(&header_impl->value, header_view->value, alloc);
    if (err) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    s_header_impl_clean_up(header_impl);
    return AWS_OP_ERR;
}

int aws_http_request_init(struct aws_http_request *request, struct aws_allocator *allocator) {
    AWS_PRECONDITION(request);
    AWS_PRECONDITION(allocator);

    AWS_ZERO_STRUCT(*request);
    request->allocator = allocator;

    int err = aws_array_list_init_dynamic(
        &request->headers, allocator, AWS_HTTP_REQUEST_NUM_RESERVED_HEADERS, sizeof(struct aws_http_header_impl));
    if (err) {
        goto error;
    }

    return AWS_OP_SUCCESS;
error:
    aws_http_request_clean_up(request);
    return AWS_OP_ERR;
}

void aws_http_request_clean_up(struct aws_http_request *request) {
    AWS_PRECONDITION(request);

    aws_string_destroy(request->method);
    aws_string_destroy(request->path);

    const size_t length = aws_array_list_length(&request->headers);
    for (size_t i = 0; i < length; ++i) {
        struct aws_http_header_impl *header_impl;
        aws_array_list_get_at_ptr(&request->headers, (void **)&header_impl, i);
        s_header_impl_clean_up(header_impl);
    }

    aws_array_list_clean_up(&request->headers);

    AWS_ZERO_STRUCT(*request);
}

int aws_http_request_set_method(struct aws_http_request *request, struct aws_byte_cursor method) {
    AWS_PRECONDITION(request);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&method));

    return s_set_string_from_cursor(&request->method, method, request->allocator);
}

struct aws_byte_cursor aws_http_request_get_method(const struct aws_http_request *request) {
    AWS_PRECONDITION(request);

    return s_get_cursor_from_string(request->method);
}

int aws_http_request_set_path(struct aws_http_request *request, struct aws_byte_cursor path) {
    AWS_PRECONDITION(request);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&path));

    return s_set_string_from_cursor(&request->path, path, request->allocator);
}

struct aws_byte_cursor aws_http_request_get_path(const struct aws_http_request *request) {
    AWS_PRECONDITION(request);
    return s_get_cursor_from_string(request->path);
}

void aws_http_request_set_body_stream(struct aws_http_request *request, struct aws_input_stream *body_stream) {
    AWS_PRECONDITION(request);
    request->body_stream = body_stream;
}

struct aws_input_stream *aws_http_request_get_body_stream(const struct aws_http_request *request) {
    AWS_PRECONDITION(request);
    return request->body_stream;
}

struct aws_http_header s_get_header_view_from_impl(struct aws_http_header_impl *impl) {
    struct aws_http_header view = {
        .name = s_get_cursor_from_string(impl->name),
        .value = s_get_cursor_from_string(impl->value),
    };
    return view;
}

int aws_http_request_add_header(struct aws_http_request *request, struct aws_http_header header) {
    AWS_PRECONDITION(request);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&header.name) && aws_byte_cursor_is_valid(&header.value));

    struct aws_http_header_impl header_impl;
    int err = s_header_impl_init(&header_impl, &header, request->allocator);
    if (err) {
        goto error;
    }

    err = aws_array_list_push_back(&request->headers, &header_impl);
    if (err) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    s_header_impl_clean_up(&header_impl);
    return AWS_OP_ERR;
}

int aws_http_request_set_header(struct aws_http_request *request, struct aws_http_header header, size_t index) {
    AWS_PRECONDITION(request);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&header.name) && aws_byte_cursor_is_valid(&header.value));

    struct aws_http_header_impl *header_impl;
    int err = aws_array_list_get_at_ptr(&request->headers, (void **)&header_impl, index);
    if (err) {
        return AWS_OP_ERR;
    }

    /* Prepare new value */
    struct aws_http_header_impl new_impl;
    err = s_header_impl_init(&new_impl, &header, request->allocator);
    if (err) {
        goto error;
    }

    /* Destroy existing strings (if any) */
    aws_string_destroy(header_impl->name);
    aws_string_destroy(header_impl->value);

    /* Overwrite old value */
    *header_impl = new_impl;
    return AWS_OP_SUCCESS;

error:
    s_header_impl_clean_up(&new_impl);
    return AWS_OP_ERR;
}

void aws_http_request_erase_header(struct aws_http_request *request, size_t index) {
    AWS_PRECONDITION(request);

    struct aws_http_header_impl *header_impl;
    int err = aws_array_list_get_at_ptr(&request->headers, (void **)&header_impl, index);
    if (!err) {
        s_header_impl_clean_up(header_impl);
        aws_array_list_erase(&request->headers, index);
    }
}

size_t aws_http_request_get_header_count(const struct aws_http_request *request) {
    AWS_PRECONDITION(request);

    return aws_array_list_length(&request->headers);
}

struct aws_http_header aws_http_request_get_header(const struct aws_http_request *request, size_t index) {
    AWS_PRECONDITION(request);

    struct aws_http_header header_view;
    AWS_ZERO_STRUCT(header_view);

    struct aws_http_header_impl *header_impl;
    int err = aws_array_list_get_at_ptr(&request->headers, (void **)&header_impl, index);
    if (!err) {
        header_view.name = s_get_cursor_from_string(header_impl->name);
        header_view.value = s_get_cursor_from_string(header_impl->value);
    }

    return header_view;
}

struct aws_http_stream *aws_http_stream_new_client_request(const struct aws_http_request_options *options) {
    if (!options || options->self_size == 0 || !options->client_connection) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create client request, options are invalid.",
            (void *)(options ? options->client_connection : NULL));
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    /* Connection owns stream, and must outlive stream */
    aws_atomic_fetch_add(&options->client_connection->refcount, 1);

    struct aws_http_stream *stream = options->client_connection->vtable->new_client_request_stream(options);
    if (!stream) {
        aws_http_connection_release(options->client_connection);
        return NULL;
    }

    return stream;
}

void aws_http_stream_release(struct aws_http_stream *stream) {
    if (!stream) {
        return;
    }

    size_t prev_refcount = aws_atomic_fetch_sub(&stream->refcount, 1);
    if (prev_refcount == 1) {
        AWS_LOGF_TRACE(AWS_LS_HTTP_STREAM, "id=%p: Final stream refcount released.", (void *)stream);

        struct aws_http_connection *owning_connection = stream->owning_connection;
        stream->vtable->destroy(stream);

        /* Connection needed to outlive stream, but it's free to go now */
        aws_http_connection_release(owning_connection);
    } else {
        AWS_ASSERT(prev_refcount != 0);
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_STREAM, "id=%p: Stream refcount released, %zu remaining.", (void *)stream, prev_refcount - 1);
    }
}

struct aws_http_connection *aws_http_stream_get_connection(const struct aws_http_stream *stream) {
    AWS_ASSERT(stream);
    return stream->owning_connection;
}

int aws_http_stream_get_incoming_response_status(const struct aws_http_stream *stream, int *out_status) {
    AWS_ASSERT(stream);

    if (stream->incoming_response_status == (int)AWS_HTTP_STATUS_UNKNOWN) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Status code not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_status = stream->incoming_response_status;
    return AWS_OP_SUCCESS;
}

int aws_http_stream_get_incoming_request_method(
    const struct aws_http_stream *stream,
    struct aws_byte_cursor *out_method) {

    AWS_ASSERT(stream);

    if (!stream->incoming_request_method_str.ptr) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Request method not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_method = stream->incoming_request_method_str;
    return AWS_OP_SUCCESS;
}

int aws_http_stream_get_incoming_request_uri(const struct aws_http_stream *stream, struct aws_byte_cursor *out_uri) {
    AWS_ASSERT(stream);

    if (!stream->incoming_request_uri.ptr) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Request URI not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_uri = stream->incoming_request_uri;
    return AWS_OP_SUCCESS;
}

void aws_http_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    stream->vtable->update_window(stream, increment_size);
}
