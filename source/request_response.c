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
#include <aws/http/server.h>
#include <aws/io/logging.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

enum {
    /* Initial capacity for the aws_http_message.headers array_list. */
    AWS_HTTP_REQUEST_NUM_RESERVED_HEADERS = 16,
};

struct aws_http_message {
    struct aws_allocator *allocator;
    struct aws_array_list headers; /* Contains aws_http_header_impl */
    struct aws_input_stream *body_stream;

    /* Data specific to the request or response subclasses */
    union {
        struct aws_http_message_request_data {
            struct aws_string *method;
            struct aws_string *path;
        } request;
        struct aws_http_message_response_data {
            int status;
        } response;
    } subclass_data;

    struct aws_http_message_request_data *request_data;
    struct aws_http_message_response_data *response_data;
};

/* Type stored within the aws_http_message.headers array_list.
 * Different from aws_http_header in that it owns its string memory. */
struct aws_http_header_impl {
    struct aws_string *name;
    struct aws_string *value;
};

static int s_set_string_from_cursor(
    struct aws_string **dst,
    struct aws_byte_cursor cursor,
    struct aws_allocator *alloc) {

    AWS_PRECONDITION(dst);

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

static void s_header_impl_clean_up(struct aws_http_header_impl *header_impl) {
    AWS_PRECONDITION(header_impl);

    aws_string_destroy(header_impl->name);
    aws_string_destroy(header_impl->value);
    AWS_ZERO_STRUCT(*header_impl);
}

static int s_header_impl_init(
    struct aws_http_header_impl *header_impl,
    const struct aws_http_header *header_view,
    struct aws_allocator *alloc) {

    AWS_PRECONDITION(header_impl);

    AWS_ZERO_STRUCT(*header_impl);

    if (!header_view->name.len) {
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_HEADER_NAME);
    }

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

static struct aws_http_message *s_message_new_common(struct aws_allocator *allocator) {
    struct aws_http_message *message = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_message));
    if (!message) {
        goto error;
    }

    message->allocator = allocator;

    int err = aws_array_list_init_dynamic(
        &message->headers, allocator, AWS_HTTP_REQUEST_NUM_RESERVED_HEADERS, sizeof(struct aws_http_header_impl));
    if (err) {
        goto error;
    }

    return message;
error:
    aws_http_message_destroy(message);
    return NULL;
}

struct aws_http_message *aws_http_message_new_request(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);

    struct aws_http_message *message = s_message_new_common(allocator);
    if (message) {
        message->request_data = &message->subclass_data.request;
    }
    return message;
}

struct aws_http_message *aws_http_message_new_response(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);

    struct aws_http_message *message = s_message_new_common(allocator);
    if (message) {
        message->response_data = &message->subclass_data.response;
        message->response_data->status = AWS_HTTP_STATUS_UNKNOWN;
    }
    return message;
}

void aws_http_message_destroy(struct aws_http_message *message) {
    /* Note that request_destroy() may also used by request_new() to clean up if something goes wrong */
    AWS_PRECONDITION(!message || message->allocator);
    if (!message) {
        return;
    }

    if (message->request_data) {
        aws_string_destroy(message->request_data->method);
        aws_string_destroy(message->request_data->path);
    }

    if (aws_array_list_is_valid(&message->headers)) {
        const size_t length = aws_array_list_length(&message->headers);
        struct aws_http_header_impl *header_impl = NULL;
        for (size_t i = 0; i < length; ++i) {
            aws_array_list_get_at_ptr(&message->headers, (void **)&header_impl, i);
            AWS_ASSERT(header_impl);
            s_header_impl_clean_up(header_impl);
        }
    }
    aws_array_list_clean_up(&message->headers);

    aws_mem_release(message->allocator, message);
}

bool aws_http_message_is_request(const struct aws_http_message *message) {
    AWS_PRECONDITION(message);
    return message->request_data;
}

bool aws_http_message_is_response(const struct aws_http_message *message) {
    AWS_PRECONDITION(message);
    return message->response_data;
}

int aws_http_message_set_request_method(struct aws_http_message *request_message, struct aws_byte_cursor method) {
    AWS_PRECONDITION(request_message);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&method));
    AWS_PRECONDITION(request_message->request_data);

    if (request_message->request_data) {
        return s_set_string_from_cursor(&request_message->request_data->method, method, request_message->allocator);
    }

    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

int aws_http_message_get_request_method(
    const struct aws_http_message *request_message,
    struct aws_byte_cursor *out_method) {

    AWS_PRECONDITION(request_message);
    AWS_PRECONDITION(out_method);
    AWS_PRECONDITION(request_message->request_data);

    if (request_message->request_data && request_message->request_data->method) {
        *out_method = aws_byte_cursor_from_string(request_message->request_data->method);
        return AWS_OP_SUCCESS;
    }

    AWS_ZERO_STRUCT(*out_method);
    return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
}

int aws_http_message_set_request_path(struct aws_http_message *request_message, struct aws_byte_cursor path) {
    AWS_PRECONDITION(request_message);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&path));
    AWS_PRECONDITION(request_message->request_data);

    if (request_message->request_data) {
        return s_set_string_from_cursor(&request_message->request_data->path, path, request_message->allocator);
    }

    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

int aws_http_message_get_request_path(
    const struct aws_http_message *request_message,
    struct aws_byte_cursor *out_path) {

    AWS_PRECONDITION(request_message);
    AWS_PRECONDITION(out_path);
    AWS_PRECONDITION(request_message->request_data);

    if (request_message->request_data && request_message->request_data->path) {
        *out_path = aws_byte_cursor_from_string(request_message->request_data->path);
        return AWS_OP_SUCCESS;
    }

    AWS_ZERO_STRUCT(*out_path);
    return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
}

int aws_http_message_get_response_status(const struct aws_http_message *response_message, int *out_status_code) {
    AWS_PRECONDITION(response_message);
    AWS_PRECONDITION(out_status_code);
    AWS_PRECONDITION(response_message->response_data);

    *out_status_code = AWS_HTTP_STATUS_UNKNOWN;

    if (response_message->response_data && (response_message->response_data->status != AWS_HTTP_STATUS_UNKNOWN)) {
        *out_status_code = response_message->response_data->status;
        return AWS_OP_SUCCESS;
    }

    return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
}

int aws_http_message_set_response_status(struct aws_http_message *response_message, int status_code) {
    AWS_PRECONDITION(response_message);
    AWS_PRECONDITION(response_message->response_data);

    if (response_message->response_data) {
        /* Status code must be printable with exactly 3 digits */
        if (status_code >= 0 && status_code <= 999) {
            response_message->response_data->status = status_code;
            return AWS_OP_SUCCESS;
        }

        return aws_raise_error(AWS_ERROR_HTTP_INVALID_STATUS_CODE);
    }

    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

void aws_http_message_set_body_stream(struct aws_http_message *message, struct aws_input_stream *body_stream) {
    AWS_PRECONDITION(message);
    message->body_stream = body_stream;
}

struct aws_input_stream *aws_http_message_get_body_stream(const struct aws_http_message *message) {
    AWS_PRECONDITION(message);
    return message->body_stream;
}

int aws_http_message_add_header(struct aws_http_message *message, struct aws_http_header header) {
    AWS_PRECONDITION(message);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&header.name) && aws_byte_cursor_is_valid(&header.value));

    struct aws_http_header_impl header_impl;
    int err = s_header_impl_init(&header_impl, &header, message->allocator);
    if (err) {
        return AWS_OP_ERR;
    }

    err = aws_array_list_push_back(&message->headers, &header_impl);
    if (err) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    s_header_impl_clean_up(&header_impl);
    return AWS_OP_ERR;
}

int aws_http_message_add_header_array(
    struct aws_http_message *message,
    const struct aws_http_header *headers,
    size_t num_headers) {

    AWS_PRECONDITION(message);
    AWS_PRECONDITION(headers);
    AWS_PRECONDITION(num_headers > 0);

    const size_t beginning_headers_size = aws_array_list_length(&message->headers);

    for (size_t i = 0; i < num_headers; ++i) {
        if (aws_http_message_add_header(message, headers[i])) {
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    /* Remove all headers we added */
    for (size_t len = aws_array_list_length(&message->headers); len > beginning_headers_size; --len) {
        aws_http_message_erase_header(message, len - 1);
    }

    return AWS_OP_ERR;
}

int aws_http_message_set_header(struct aws_http_message *message, struct aws_http_header header, size_t index) {
    AWS_PRECONDITION(message);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&header.name) && aws_byte_cursor_is_valid(&header.value));

    struct aws_http_header_impl *header_impl;
    int err = aws_array_list_get_at_ptr(&message->headers, (void **)&header_impl, index);
    if (err) {
        return AWS_OP_ERR;
    }

    /* Prepare new value */
    struct aws_http_header_impl new_impl;
    err = s_header_impl_init(&new_impl, &header, message->allocator);
    if (err) {
        return AWS_OP_ERR;
    }

    /* Destroy existing strings (if any) */
    aws_string_destroy(header_impl->name);
    aws_string_destroy(header_impl->value);

    /* Overwrite old value */
    *header_impl = new_impl;
    return AWS_OP_SUCCESS;
}

int aws_http_message_erase_header(struct aws_http_message *message, size_t index) {
    AWS_PRECONDITION(message);

    struct aws_http_header_impl *header_impl;
    int err = aws_array_list_get_at_ptr(&message->headers, (void **)&header_impl, index);
    if (err) {
        return AWS_OP_ERR;
    }

    s_header_impl_clean_up(header_impl);
    aws_array_list_erase(&message->headers, index);
    return AWS_OP_SUCCESS;
}

size_t aws_http_message_get_header_count(const struct aws_http_message *message) {
    AWS_PRECONDITION(message);

    return aws_array_list_length(&message->headers);
}

int aws_http_message_get_header(
    const struct aws_http_message *message,
    struct aws_http_header *out_header,
    size_t index) {

    AWS_PRECONDITION(message);
    AWS_PRECONDITION(out_header);

    AWS_ZERO_STRUCT(*out_header);

    struct aws_http_header_impl *header_impl;
    int err = aws_array_list_get_at_ptr(&message->headers, (void **)&header_impl, index);
    if (err) {
        return AWS_OP_ERR;
    }

    out_header->name = aws_byte_cursor_from_string(header_impl->name);
    if (header_impl->value) {
        out_header->value = aws_byte_cursor_from_string(header_impl->value);
    }
    return AWS_OP_SUCCESS;
}

struct aws_http_stream *aws_http_connection_make_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {

    AWS_PRECONDITION(client_connection);
    AWS_PRECONDITION(aws_http_connection_is_client(client_connection));
    AWS_PRECONDITION(options);
    if (options->self_size == 0 || !options->request || !aws_http_message_is_request(options->request)) {

        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create client request, options are invalid.",
            (void *)client_connection);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    /* Connection owns stream, and must outlive stream */
    aws_http_connection_acquire(client_connection);

    struct aws_http_stream *stream = client_connection->vtable->make_request(client_connection, options);
    if (!stream) {
        aws_http_connection_release(client_connection);
        return NULL;
    }

    return stream;
}

struct aws_http_stream *aws_http_stream_new_server_request_handler(
    const struct aws_http_request_handler_options *options) {
    AWS_PRECONDITION(options);
    if (options->self_size == 0 || !options->server_connection ||
        !aws_http_connection_is_server(options->server_connection)) {

        AWS_LOGF_ERROR(
            AWS_LS_HTTP_CONNECTION,
            "id=%p: Cannot create server request handler stream, options are invalid.",
            (void *)options->server_connection);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    return options->server_connection->vtable->new_server_request_handler_stream(options);
}

int aws_http_stream_send_response(struct aws_http_stream *stream, struct aws_http_message *response) {
    AWS_PRECONDITION(stream);
    AWS_PRECONDITION(response);
    AWS_PRECONDITION(aws_http_message_is_response(response));
    return stream->owning_connection->vtable->stream_send_response(stream, response);
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
    AWS_ASSERT(stream && stream->client_data);

    if (stream->client_data->response_status == (int)AWS_HTTP_STATUS_UNKNOWN) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Status code not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_status = stream->client_data->response_status;
    return AWS_OP_SUCCESS;
}

int aws_http_stream_get_incoming_request_method(
    const struct aws_http_stream *stream,
    struct aws_byte_cursor *out_method) {
    AWS_ASSERT(stream && stream->server_data);

    if (!stream->server_data->request_method_str.ptr) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Request method not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_method = stream->server_data->request_method_str;
    return AWS_OP_SUCCESS;
}

int aws_http_stream_get_incoming_request_uri(const struct aws_http_stream *stream, struct aws_byte_cursor *out_uri) {
    AWS_ASSERT(stream && stream->server_data);

    if (!stream->server_data->request_path.ptr) {
        AWS_LOGF_ERROR(AWS_LS_HTTP_STREAM, "id=%p: Request URI not yet received.", (void *)stream);
        return aws_raise_error(AWS_ERROR_HTTP_DATA_NOT_AVAILABLE);
    }

    *out_uri = stream->server_data->request_path;
    return AWS_OP_SUCCESS;
}

void aws_http_stream_update_window(struct aws_http_stream *stream, size_t increment_size) {
    stream->vtable->update_window(stream, increment_size);
}
