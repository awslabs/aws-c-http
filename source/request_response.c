/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/private/connection_impl.h>
#include <aws/http/private/request_response_impl.h>
#include <aws/http/private/strutil.h>
#include <aws/http/server.h>
#include <aws/http/status_code.h>
#include <aws/io/logging.h>
#include <aws/io/stream.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

enum {
    /* Initial capacity for the aws_http_message.headers array_list. */
    AWS_HTTP_REQUEST_NUM_RESERVED_HEADERS = 16,
};

bool aws_http_header_name_eq(struct aws_byte_cursor name_a, struct aws_byte_cursor name_b) {
    return aws_byte_cursor_eq_ignore_case(&name_a, &name_b);
}

/**
 * -- Datastructure Notes --
 * Headers are stored in a linear array, rather than a hash-table of arrays.
 * The linear array was simpler to implement and may be faster due to having fewer allocations.
 * The API has been designed so we can swap out the implementation later if desired.
 *
 * -- String Storage Notes --
 * We use a single allocation to hold the name and value of each aws_http_header.
 * We could optimize storage by using something like a string pool. If we do this, be sure to maintain
 * the address of existing strings when adding new strings (a dynamic aws_byte_buf would not suffice).
 */
struct aws_http_headers {
    struct aws_allocator *alloc;
    struct aws_array_list array_list; /* Contains aws_http_header */
    struct aws_atomic_var refcount;
};

struct aws_http_headers *aws_http_headers_new(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);

    struct aws_http_headers *headers = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_headers));
    if (!headers) {
        goto alloc_failed;
    }

    headers->alloc = allocator;
    aws_atomic_init_int(&headers->refcount, 1);

    if (aws_array_list_init_dynamic(
            &headers->array_list, allocator, AWS_HTTP_REQUEST_NUM_RESERVED_HEADERS, sizeof(struct aws_http_header))) {
        goto array_list_failed;
    }

    return headers;

array_list_failed:
    aws_mem_release(headers->alloc, headers);
alloc_failed:
    return NULL;
}

void aws_http_headers_release(struct aws_http_headers *headers) {
    AWS_PRECONDITION(!headers || headers->alloc);
    if (!headers) {
        return;
    }

    size_t prev_refcount = aws_atomic_fetch_sub(&headers->refcount, 1);
    if (prev_refcount == 1) {
        aws_http_headers_clear(headers);
        aws_array_list_clean_up(&headers->array_list);
        aws_mem_release(headers->alloc, headers);
    } else {
        AWS_ASSERT(prev_refcount != 0);
    }
}

void aws_http_headers_acquire(struct aws_http_headers *headers) {
    AWS_PRECONDITION(headers);
    aws_atomic_fetch_add(&headers->refcount, 1);
}

int aws_http_headers_add_header(struct aws_http_headers *headers, const struct aws_http_header *header) {
    AWS_PRECONDITION(headers);
    AWS_PRECONDITION(header);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&header->name) && aws_byte_cursor_is_valid(&header->value));

    if (header->name.len == 0) {
        return aws_raise_error(AWS_ERROR_HTTP_INVALID_HEADER_NAME);
    }

    size_t total_len;
    if (aws_add_size_checked(header->name.len, header->value.len, &total_len)) {
        return AWS_OP_ERR;
    }

    struct aws_http_header header_copy = *header;
    /* Store our own copy of the strings.
     * We put the name and value into the same allocation. */
    uint8_t *strmem = aws_mem_acquire(headers->alloc, total_len);
    if (!strmem) {
        return AWS_OP_ERR;
    }

    struct aws_byte_buf strbuf = aws_byte_buf_from_empty_array(strmem, total_len);
    aws_byte_buf_append_and_update(&strbuf, &header_copy.name);
    aws_byte_buf_append_and_update(&strbuf, &header_copy.value);

    if (aws_array_list_push_back(&headers->array_list, &header_copy)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    aws_mem_release(headers->alloc, strmem);
    return AWS_OP_ERR;
}

int aws_http_headers_add(struct aws_http_headers *headers, struct aws_byte_cursor name, struct aws_byte_cursor value) {
    struct aws_http_header header = {.name = name, .value = value};
    return aws_http_headers_add_header(headers, &header);
}

void aws_http_headers_clear(struct aws_http_headers *headers) {
    AWS_PRECONDITION(headers);

    struct aws_http_header *header = NULL;
    const size_t count = aws_http_headers_count(headers);
    for (size_t i = 0; i < count; ++i) {
        aws_array_list_get_at_ptr(&headers->array_list, (void **)&header, i);
        AWS_ASSUME(header);

        /* Storage for name & value is in the same allocation */
        aws_mem_release(headers->alloc, header->name.ptr);
    }

    aws_array_list_clear(&headers->array_list);
}

/* Does not check index */
static void s_http_headers_erase_index(struct aws_http_headers *headers, size_t index) {
    struct aws_http_header *header = NULL;
    aws_array_list_get_at_ptr(&headers->array_list, (void **)&header, index);
    AWS_ASSUME(header);

    /* Storage for name & value is in the same allocation */
    aws_mem_release(headers->alloc, header->name.ptr);

    aws_array_list_erase(&headers->array_list, index);
}

int aws_http_headers_erase_index(struct aws_http_headers *headers, size_t index) {
    AWS_PRECONDITION(headers);

    if (index >= aws_http_headers_count(headers)) {
        return aws_raise_error(AWS_ERROR_INVALID_INDEX);
    }

    s_http_headers_erase_index(headers, index);
    return AWS_OP_SUCCESS;
}

/* Erase entries with name, stop at end_index */
static int s_http_headers_erase(struct aws_http_headers *headers, struct aws_byte_cursor name, size_t end_index) {
    bool erased_any = false;
    struct aws_http_header *header = NULL;

    /* Iterating in reverse is simpler */
    for (size_t n = end_index; n > 0; --n) {
        const size_t i = n - 1;

        aws_array_list_get_at_ptr(&headers->array_list, (void **)&header, i);
        AWS_ASSUME(header);

        if (aws_http_header_name_eq(header->name, name)) {
            s_http_headers_erase_index(headers, i);
            erased_any = true;
        }
    }

    if (!erased_any) {
        return aws_raise_error(AWS_ERROR_HTTP_HEADER_NOT_FOUND);
    }

    return AWS_OP_SUCCESS;
}

int aws_http_headers_erase(struct aws_http_headers *headers, struct aws_byte_cursor name) {
    AWS_PRECONDITION(headers);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&name));

    return s_http_headers_erase(headers, name, aws_http_headers_count(headers));
}

int aws_http_headers_erase_value(
    struct aws_http_headers *headers,
    struct aws_byte_cursor name,
    struct aws_byte_cursor value) {

    AWS_PRECONDITION(headers);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&name) && aws_byte_cursor_is_valid(&value));

    struct aws_http_header *header = NULL;
    const size_t count = aws_http_headers_count(headers);
    for (size_t i = 0; i < count; ++i) {
        aws_array_list_get_at_ptr(&headers->array_list, (void **)&header, i);
        AWS_ASSUME(header);

        if (aws_http_header_name_eq(header->name, name) && aws_byte_cursor_eq(&header->value, &value)) {
            s_http_headers_erase_index(headers, i);
            return AWS_OP_SUCCESS;
        }
    }

    return aws_raise_error(AWS_ERROR_HTTP_HEADER_NOT_FOUND);
}

int aws_http_headers_add_array(struct aws_http_headers *headers, const struct aws_http_header *array, size_t count) {
    AWS_PRECONDITION(headers);
    AWS_PRECONDITION(AWS_MEM_IS_READABLE(array, count));

    const size_t orig_count = aws_http_headers_count(headers);

    for (size_t i = 0; i < count; ++i) {
        if (aws_http_headers_add_header(headers, &array[i])) {
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    /* Erase headers from the end until we're back to our previous state */
    for (size_t new_count = aws_http_headers_count(headers); new_count > orig_count; --new_count) {
        s_http_headers_erase_index(headers, new_count - 1);
    }

    return AWS_OP_ERR;
}

int aws_http_headers_set(struct aws_http_headers *headers, struct aws_byte_cursor name, struct aws_byte_cursor value) {
    AWS_PRECONDITION(headers);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&name) && aws_byte_cursor_is_valid(&value));

    const size_t prev_count = aws_http_headers_count(headers);
    if (aws_http_headers_add(headers, name, value)) {
        return AWS_OP_ERR;
    }

    /* Erase pre-existing headers AFTER add, in case name or value was referencing their memory. */
    s_http_headers_erase(headers, name, prev_count);
    return AWS_OP_SUCCESS;
}

size_t aws_http_headers_count(const struct aws_http_headers *headers) {
    AWS_PRECONDITION(headers);

    return aws_array_list_length(&headers->array_list);
}

int aws_http_headers_get_index(
    const struct aws_http_headers *headers,
    size_t index,
    struct aws_http_header *out_header) {

    AWS_PRECONDITION(headers);
    AWS_PRECONDITION(out_header);

    return aws_array_list_get_at(&headers->array_list, out_header, index);
}

int aws_http_headers_get(
    const struct aws_http_headers *headers,
    struct aws_byte_cursor name,
    struct aws_byte_cursor *out_value) {

    AWS_PRECONDITION(headers);
    AWS_PRECONDITION(out_value);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&name));

    struct aws_http_header *header = NULL;
    const size_t count = aws_http_headers_count(headers);
    for (size_t i = 0; i < count; ++i) {
        aws_array_list_get_at_ptr(&headers->array_list, (void **)&header, i);
        AWS_ASSUME(header);

        if (aws_http_header_name_eq(header->name, name)) {
            *out_value = header->value;
            return AWS_OP_SUCCESS;
        }
    }

    return aws_raise_error(AWS_ERROR_HTTP_HEADER_NOT_FOUND);
}

bool aws_http_headers_has(const struct aws_http_headers *headers, struct aws_byte_cursor name) {

    struct aws_byte_cursor out_value;
    if (aws_http_headers_get(headers, name, &out_value)) {
        return false;
    }
    return true;
}

struct aws_http_message {
    struct aws_allocator *allocator;
    struct aws_http_headers *headers;
    struct aws_input_stream *body_stream;
    struct aws_atomic_var refcount;

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

static int s_set_string_from_cursor(
    struct aws_string **dst,
    struct aws_byte_cursor cursor,
    struct aws_allocator *alloc) {

    AWS_PRECONDITION(dst);

    /* If the cursor is empty, set dst to NULL */
    struct aws_string *new_str;
    if (cursor.len) {
        new_str = aws_string_new_from_cursor(alloc, &cursor);
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
static struct aws_http_message *s_message_new_common(
    struct aws_allocator *allocator,
    struct aws_http_headers *existing_headers) {

    struct aws_http_message *message = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_message));
    if (!message) {
        goto error;
    }

    message->allocator = allocator;
    aws_atomic_init_int(&message->refcount, 1);

    if (existing_headers) {
        message->headers = existing_headers;
        aws_http_headers_acquire(message->headers);
    } else {
        message->headers = aws_http_headers_new(allocator);
        if (!message->headers) {
            goto error;
        }
    }

    return message;
error:
    aws_http_message_destroy(message);
    return NULL;
}

static struct aws_http_message *s_message_new_request_common(
    struct aws_allocator *allocator,
    struct aws_http_headers *existing_headers) {

    struct aws_http_message *message = s_message_new_common(allocator, existing_headers);
    if (message) {
        message->request_data = &message->subclass_data.request;
    }
    return message;
}

struct aws_http_message *aws_http_message_new_request_with_headers(
    struct aws_allocator *allocator,
    struct aws_http_headers *existing_headers) {

    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(existing_headers);

    return s_message_new_request_common(allocator, existing_headers);
}

struct aws_http_message *aws_http_message_new_request(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);
    return s_message_new_request_common(allocator, NULL);
}

struct aws_http_message *aws_http_message_new_response(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);

    struct aws_http_message *message = s_message_new_common(allocator, NULL);
    if (message) {
        message->response_data = &message->subclass_data.response;
        message->response_data->status = AWS_HTTP_STATUS_CODE_UNKNOWN;
    }
    return message;
}

void aws_http_message_destroy(struct aws_http_message *message) {
    aws_http_message_release(message);
}

void aws_http_message_release(struct aws_http_message *message) {
    /* Note that release() may also be used by new() functions to clean up if something goes wrong */
    AWS_PRECONDITION(!message || message->allocator);
    if (!message) {
        return;
    }

    size_t prev_refcount = aws_atomic_fetch_sub(&message->refcount, 1);
    if (prev_refcount == 1) {
        if (message->request_data) {
            aws_string_destroy(message->request_data->method);
            aws_string_destroy(message->request_data->path);
        }

        aws_http_headers_release(message->headers);

        aws_mem_release(message->allocator, message);
    } else {
        AWS_ASSERT(prev_refcount != 0);
    }
}

void aws_http_message_acquire(struct aws_http_message *message) {
    AWS_PRECONDITION(message);
    aws_atomic_fetch_add(&message->refcount, 1);
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

    *out_status_code = AWS_HTTP_STATUS_CODE_UNKNOWN;

    if (response_message->response_data && (response_message->response_data->status != AWS_HTTP_STATUS_CODE_UNKNOWN)) {
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

int aws_http1_stream_write_chunk(struct aws_http_stream *http1_stream, const struct aws_http1_chunk_options *options) {
    AWS_PRECONDITION(http1_stream);
    AWS_PRECONDITION(http1_stream->vtable);
    AWS_PRECONDITION(options);
    if (!http1_stream->vtable->http1_write_chunk) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_STREAM,
            "id=%p: HTTP/1 stream only function invoked on other stream, ignoring call.",
            (void *)http1_stream);
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    return http1_stream->vtable->http1_write_chunk(http1_stream, options);
}

struct aws_input_stream *aws_http_message_get_body_stream(const struct aws_http_message *message) {
    AWS_PRECONDITION(message);
    return message->body_stream;
}

struct aws_http_headers *aws_http_message_get_headers(struct aws_http_message *message) {
    AWS_PRECONDITION(message);
    return message->headers;
}

const struct aws_http_headers *aws_http_message_get_const_headers(const struct aws_http_message *message) {
    AWS_PRECONDITION(message);
    return message->headers;
}

int aws_http_message_add_header(struct aws_http_message *message, struct aws_http_header header) {
    return aws_http_headers_add(message->headers, header.name, header.value);
}

int aws_http_message_add_header_array(
    struct aws_http_message *message,
    const struct aws_http_header *headers,
    size_t num_headers) {

    return aws_http_headers_add_array(message->headers, headers, num_headers);
}

int aws_http_message_erase_header(struct aws_http_message *message, size_t index) {
    return aws_http_headers_erase_index(message->headers, index);
}

size_t aws_http_message_get_header_count(const struct aws_http_message *message) {
    return aws_http_headers_count(message->headers);
}

int aws_http_message_get_header(
    const struct aws_http_message *message,
    struct aws_http_header *out_header,
    size_t index) {

    return aws_http_headers_get_index(message->headers, index, out_header);
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

int aws_http_stream_activate(struct aws_http_stream *stream) {
    AWS_PRECONDITION(stream);
    AWS_PRECONDITION(stream->vtable);
    AWS_PRECONDITION(stream->vtable->activate);
    /* make sure it's actually a client calling us. This is always a programmer bug, so just assert and die. */
    AWS_PRECONDITION(aws_http_connection_is_client(stream->owning_connection));

    return stream->vtable->activate(stream);
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

    if (stream->client_data->response_status == (int)AWS_HTTP_STATUS_CODE_UNKNOWN) {
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

uint32_t aws_http_stream_get_id(const struct aws_http_stream *stream) {
    return stream->id;
}

int aws_http2_stream_reset(struct aws_http_stream *http2_stream, uint32_t http2_error) {
    AWS_PRECONDITION(http2_stream);
    AWS_PRECONDITION(http2_stream->vtable);
    if (!http2_stream->vtable->http2_reset_stream) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_STREAM,
            "id=%p: HTTP/2 stream only function invoked on other stream, ignoring call.",
            (void *)http2_stream);
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    return http2_stream->vtable->http2_reset_stream(http2_stream, http2_error);
}

int aws_http2_stream_get_received_reset_error_code(struct aws_http_stream *http2_stream, uint32_t *out_http2_error) {
    AWS_PRECONDITION(http2_stream);
    AWS_PRECONDITION(http2_stream->vtable);
    AWS_PRECONDITION(out_http2_error);
    if (!http2_stream->vtable->http2_get_received_error_code) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_STREAM,
            "id=%p: HTTP/2 stream only function invoked on other stream, ignoring call.",
            (void *)http2_stream);
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    return http2_stream->vtable->http2_get_received_error_code(http2_stream, out_http2_error);
}

int aws_http2_stream_get_sent_reset_error_code(struct aws_http_stream *http2_stream, uint32_t *out_http2_error) {
    AWS_PRECONDITION(http2_stream);
    AWS_PRECONDITION(http2_stream->vtable);
    AWS_PRECONDITION(out_http2_error);
    if (!http2_stream->vtable->http2_get_sent_error_code) {
        AWS_LOGF_TRACE(
            AWS_LS_HTTP_STREAM,
            "id=%p: HTTP/2 stream only function invoked on other stream, ignoring call.",
            (void *)http2_stream);
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    return http2_stream->vtable->http2_get_sent_error_code(http2_stream, out_http2_error);
}
