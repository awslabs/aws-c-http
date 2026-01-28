# HTTP/1.1 Streaming with Known Content-Length

## Overview

This feature enables HTTP/1.1 clients to stream data with a known Content-Length, where the data is provided incrementally rather than all at once. This is particularly useful for scenarios where the client knows the total size of the data but needs to generate or process it incrementally, and where chunked encoding cannot be used due to intermediary proxy limitations or other constraints.

## API Reference

### Request Configuration

To use incremental Content-Length streaming, set the `use_manual_data_writes` flag in the `aws_http_make_request_options` structure:

```c
struct aws_http_make_request_options options = {
    .self_size = sizeof(options),
    .request = request,
    .use_manual_data_writes = true,
    // ... other options ...
};
```

### Requirements

For HTTP/1.1 connections, the following requirements must be met:

1. The request must have a valid Content-Length header
2. The request must not have a body stream set (aws_http_message_get_body_stream must return NULL)
3. The request must not have a Transfer-Encoding header set

### Data Write API

Once the request is created and activated, use the `aws_http1_stream_write_data` function to incrementally provide data:

```c
/**
 * Write data to an HTTP/1.1 stream with a known Content-Length.
 * The data will be sent without chunked encoding.
 * The total amount of data written must match the Content-Length header value.
 *
 * @param stream The HTTP stream to write data to.
 * @param options Options for the data write operation.
 * @return AWS_OP_SUCCESS if the write was successfully queued, AWS_OP_ERR otherwise.
 */
AWS_HTTP_API
int aws_http1_stream_write_data(
    struct aws_http_stream *stream,
    const struct aws_http_stream_write_data_options *options);
```

### Data Write Options

The `aws_http_stream_write_data_options` structure provides options for the data write operation:

```c
/**
 * Options for writing data to an HTTP/1.1 stream with a known Content-Length.
 */
struct aws_http_stream_write_data_options {
    /**
     * The data to be sent.
     * Required.
     */
    struct aws_input_stream *data;

    /**
     * Set true when it's the last chunk of data to be sent.
     * After a write with end_stream, no more data writes will be accepted.
     */
    bool end_stream;

    /**
     * Invoked when the data stream is no longer in use, whether or not it was successfully sent.
     * Optional.
     */
    aws_http1_stream_write_data_complete_fn *on_complete;

    /**
     * User provided data passed to the on_complete callback on its invocation.
     */
    void *user_data;
};
```

## Usage Examples

### Basic Example

```c
/* Create request with Content-Length header */
struct aws_http_header headers[] = {
    {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("example.com"),
    },
    {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("16"),
    },
    {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Type"),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("text/plain"),
    },
};

struct aws_http_message *request = aws_http_message_new_request(allocator);
aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("POST"));
aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/path"));
aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers));

/* Send request with manual data writes */
struct aws_http_make_request_options request_options = {
    .self_size = sizeof(request_options),
    .request = request,
    .use_manual_data_writes = true,
    // ... other options ...
};

struct aws_http_stream *stream = aws_http_connection_make_request(connection, &request_options);
aws_http_stream_activate(stream);

/* Write first part of the data */
struct aws_byte_cursor data1 = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Hello, ");
struct aws_input_stream *data1_stream = aws_input_stream_new_from_cursor(allocator, &data1);

struct aws_http_stream_write_data_options data1_options = {
    .data = data1_stream,
    .end_stream = false,
    .on_complete = s_destroy_stream_on_complete,
    .user_data = data1_stream,
};

aws_http1_stream_write_data(stream, &data1_options);

/* Write second part of the data */
struct aws_byte_cursor data2 = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("World!");
struct aws_input_stream *data2_stream = aws_input_stream_new_from_cursor(allocator, &data2);

struct aws_http_stream_write_data_options data2_options = {
    .data = data2_stream,
    .end_stream = true, /* This is the last write */
    .on_complete = s_destroy_stream_on_complete,
    .user_data = data2_stream,
};

aws_http1_stream_write_data(stream, &data2_options);
```

### Complete Example with Error Handling

```c
#include <aws/http/connection.h>
#include <aws/http/http.h>
#include <aws/http/request_response.h>
#include <aws/io/stream.h>

/* Callback for when data is no longer in use */
static void s_destroy_stream_on_complete(int error_code, void *user_data) {
    if (error_code != AWS_ERROR_SUCCESS) {
        fprintf(stderr, "Error in data write: %s\n", aws_error_name(error_code));
    }
    struct aws_input_stream *data_stream = user_data;
    aws_input_stream_release(data_stream);
}

/* Callback for when the stream completes */
static void s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)stream;
    bool *stream_complete = user_data;

    if (error_code != AWS_ERROR_SUCCESS) {
        fprintf(stderr, "Stream error: %s\n", aws_error_name(error_code));
    }

    *stream_complete = true;
}

/* Callback for incoming response headers */
static int s_on_incoming_headers(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)stream;
    (void)header_block;
    (void)user_data;

    printf("Received %zu response headers:\n", num_headers);
    for (size_t i = 0; i < num_headers; ++i) {
        printf("  %.*s: %.*s\n",
            (int)header_array[i].name.len, header_array[i].name.ptr,
            (int)header_array[i].value.len, header_array[i].value.ptr);
    }

    return AWS_OP_SUCCESS;
}

/* Callback for incoming response body */
static int s_on_incoming_body(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;
    (void)user_data;

    printf("Received %zu bytes of response body:\n", data->len);
    printf("%.*s\n", (int)data->len, data->ptr);

    return AWS_OP_SUCCESS;
}

int main() {
    struct aws_allocator *allocator = aws_default_allocator();
    aws_http_library_init(allocator);

    /* Set up connection (simplified for example) */
    struct aws_http_connection *connection = /* ... */;

    /* Create request with Content-Length header */
    struct aws_http_header headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("example.com"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("16"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Type"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("text/plain"),
        },
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    if (!request) {
        fprintf(stderr, "Failed to create request: %s\n", aws_error_name(aws_last_error()));
        goto cleanup;
    }

    if (aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("POST")) ||
        aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str("/path")) ||
        aws_http_message_add_header_array(request, headers, AWS_ARRAY_SIZE(headers))) {
        fprintf(stderr, "Failed to set request properties: %s\n", aws_error_name(aws_last_error()));
        goto cleanup;
    }

    /* Send request with manual data writes */
    bool stream_complete = false;
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .user_data = &stream_complete,
        .on_response_headers = s_on_incoming_headers,
        .on_response_body = s_on_incoming_body,
        .on_complete = s_on_stream_complete,
        .use_manual_data_writes = true,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(connection, &request_options);
    if (!stream) {
        fprintf(stderr, "Failed to create stream: %s\n", aws_error_name(aws_last_error()));
        goto cleanup;
    }

    if (aws_http_stream_activate(stream)) {
        fprintf(stderr, "Failed to activate stream: %s\n", aws_error_name(aws_last_error()));
        aws_http_stream_release(stream);
        goto cleanup;
    }

    /* Write first part of the data */
    struct aws_byte_cursor data1 = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Hello, ");
    struct aws_input_stream *data1_stream = aws_input_stream_new_from_cursor(allocator, &data1);
    if (!data1_stream) {
        fprintf(stderr, "Failed to create input stream: %s\n", aws_error_name(aws_last_error()));
        aws_http_stream_release(stream);
        goto cleanup;
    }

    struct aws_http_stream_write_data_options data1_options = {
        .data = data1_stream,
        .end_stream = false,
        .on_complete = s_destroy_stream_on_complete,
        .user_data = data1_stream,
    };

    if (aws_http1_stream_write_data(stream, &data1_options)) {
        fprintf(stderr, "Failed to write data: %s\n", aws_error_name(aws_last_error()));
        aws_input_stream_release(data1_stream);
        aws_http_stream_release(stream);
        goto cleanup;
    }

    /* Write second part of the data */
    struct aws_byte_cursor data2 = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("World!");
    struct aws_input_stream *data2_stream = aws_input_stream_new_from_cursor(allocator, &data2);
    if (!data2_stream) {
        fprintf(stderr, "Failed to create input stream: %s\n", aws_error_name(aws_last_error()));
        aws_http_stream_release(stream);
        goto cleanup;
    }

    struct aws_http_stream_write_data_options data2_options = {
        .data = data2_stream,
        .end_stream = true, /* This is the last write */
        .on_complete = s_destroy_stream_on_complete,
        .user_data = data2_stream,
    };

    if (aws_http1_stream_write_data(stream, &data2_options)) {
        fprintf(stderr, "Failed to write data: %s\n", aws_error_name(aws_last_error()));
        aws_input_stream_release(data2_stream);
        aws_http_stream_release(stream);
        goto cleanup;
    }

    /* Wait for stream to complete (simplified for example) */
    while (!stream_complete) {
        /* In a real application, you would use event loop or other mechanism */
        aws_thread_current_sleep(1000000000); /* 1 second */
    }

    aws_http_stream_release(stream);

cleanup:
    aws_http_message_destroy(request);
    /* Clean up connection and other resources */
    aws_http_library_clean_up();

    return 0;
}
```

### Example with Dynamic Content Generation

This example demonstrates how to use incremental Content-Length streaming with dynamically generated content:

```c
/* Custom input stream that generates data on demand */
struct dynamic_content_stream {
    struct aws_input_stream base;
    struct aws_allocator *allocator;
    size_t total_size;
    size_t bytes_read;
    void *user_data;
    int (*generator_fn)(void *user_data, uint8_t *buffer, size_t buffer_size, size_t *bytes_written);
};

static int s_dynamic_content_read(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    struct dynamic_content_stream *impl = AWS_CONTAINER_OF(stream, struct dynamic_content_stream, base);

    size_t remaining = impl->total_size - impl->bytes_read;
    if (remaining == 0) {
        /* End of stream */
        return AWS_OP_SUCCESS;
    }

    size_t space_available = dest->capacity - dest->len;
    size_t to_read = remaining < space_available ? remaining : space_available;

    size_t bytes_written = 0;
    int result = impl->generator_fn(impl->user_data, dest->buffer + dest->len, to_read, &bytes_written);
    if (result != AWS_OP_SUCCESS) {
        return result;
    }

    dest->len += bytes_written;
    impl->bytes_read += bytes_written;

    return AWS_OP_SUCCESS;
}

static int s_dynamic_content_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    struct dynamic_content_stream *impl = AWS_CONTAINER_OF(stream, struct dynamic_content_stream, base);

    status->is_end_of_stream = (impl->bytes_read >= impl->total_size);
    status->is_valid = true;

    if (status->is_end_of_stream) {
        status->len = 0;
    } else {
        status->len = impl->total_size - impl->bytes_read;
    }

    return AWS_OP_SUCCESS;
}

static int s_dynamic_content_get_length(struct aws_input_stream *stream, int64_t *out_length) {
    struct dynamic_content_stream *impl = AWS_CONTAINER_OF(stream, struct dynamic_content_stream, base);

    *out_length = impl->total_size;
    return AWS_OP_SUCCESS;
}

static void s_dynamic_content_destroy(struct aws_input_stream *stream) {
    struct dynamic_content_stream *impl = AWS_CONTAINER_OF(stream, struct dynamic_content_stream, base);
    aws_mem_release(impl->allocator, impl);
}

static struct aws_input_stream_vtable s_dynamic_content_vtable = {
    .seek = NULL, /* No seeking support */
    .read = s_dynamic_content_read,
    .get_status = s_dynamic_content_get_status,
    .get_length = s_dynamic_content_get_length,
    .destroy = s_dynamic_content_destroy,
};

/* Example generator function that produces sequential numbers */
static int s_number_generator(void *user_data, uint8_t *buffer, size_t buffer_size, size_t *bytes_written) {
    int *counter = user_data;

    size_t i;
    for (i = 0; i < buffer_size; i++) {
        char digit = '0' + (*counter % 10);
        buffer[i] = digit;
        (*counter)++;
    }

    *bytes_written = i;
    return AWS_OP_SUCCESS;
}

/* Create a dynamic content stream */
static struct aws_input_stream *create_dynamic_content_stream(
    struct aws_allocator *allocator,
    size_t total_size,
    int (*generator_fn)(void *, uint8_t *, size_t, size_t *),
    void *user_data) {

    struct dynamic_content_stream *impl = aws_mem_calloc(allocator, 1, sizeof(struct dynamic_content_stream));
    if (!impl) {
        return NULL;
    }

    impl->allocator = allocator;
    impl->total_size = total_size;
    impl->bytes_read = 0;
    impl->generator_fn = generator_fn;
    impl->user_data = user_data;

    impl->base.vtable = &s_dynamic_content_vtable;

    return &impl->base;
}

/* Example usage */
int example_with_dynamic_content() {
    struct aws_allocator *allocator = aws_default_allocator();

    /* Create request with Content-Length header */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    /* ... set up request headers including Content-Length: 1024 ... */

    /* Send request with manual data writes */
    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .request = request,
        .use_manual_data_writes = true,
        /* ... other options ... */
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(connection, &request_options);
    aws_http_stream_activate(stream);

    /* Write data in chunks of 256 bytes */
    const size_t chunk_size = 256;
    const size_t total_size = 1024;
    int counter = 0;

    for (size_t offset = 0; offset < total_size; offset += chunk_size) {
        size_t current_chunk_size = (offset + chunk_size > total_size) ? (total_size - offset) : chunk_size;
        bool is_last_chunk = (offset + current_chunk_size >= total_size);

        /* Create a dynamic content stream for this chunk */
        struct aws_input_stream *data_stream = create_dynamic_content_stream(
            allocator, current_chunk_size, s_number_generator, &counter);

        struct aws_http_stream_write_data_options data_options = {
            .data = data_stream,
            .end_stream = is_last_chunk,
            .on_complete = s_destroy_stream_on_complete,
            .user_data = data_stream,
        };

        aws_http1_stream_write_data(stream, &data_options);
    }

    /* ... wait for stream to complete ... */

    aws_http_stream_release(stream);
    aws_http_message_destroy(request);

    return 0;
}
```

## Error Handling

The following error codes may be returned by `aws_http1_stream_write_data`:

- `AWS_ERROR_INVALID_ARGUMENT`: If the options or data stream is invalid.
- `AWS_ERROR_HTTP_STREAM_NOT_ACTIVATED`: If the stream has not been activated.
- `AWS_ERROR_HTTP_STREAM_HAS_COMPLETED`: If the stream has already completed.
- `AWS_ERROR_INVALID_STATE`: If the stream is not in a state where data can be written.
- `AWS_ERROR_HTTP_OUTGOING_STREAM_LENGTH_INCORRECT`: If the data would exceed the Content-Length or if the final data write does not match the Content-Length.

## Compatibility

This feature is compatible with HTTP/1.1 servers that support standard Content-Length handling. It has been tested with various HTTP servers including:

- httpbin.org
- postman-echo.com
- httpstat.us

## Limitations

- The total amount of data written must exactly match the Content-Length header value.
- Once a data write with `end_stream = true` is submitted, no more data writes can be submitted.
- This feature is only available for HTTP/1.1 connections. For HTTP/2 connections, use the `aws_http2_stream_write_data` function instead.
