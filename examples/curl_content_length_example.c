/*
 * Example demonstrating curl's streaming capabilities with Content-Length for HTTP/1.1 requests
 *
 * This example shows how to:
 * 1. Stream data to a server using HTTP/1.1 POST with Content-Length header
 * 2. Provide data incrementally through a read callback
 * 3. Handle both upload and download streaming simultaneously
 *
 * Key difference from chunked encoding:
 * - Content-Length: Total size must be known upfront, sent in header
 * - Chunked: Size unknown, data sent in chunks with length prefixes
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Structure to hold streaming data */
struct streaming_data {
    char *data;
    size_t size;
    size_t position;
};

/* Structure for upload streaming */
struct upload_stream {
    const char **chunks;
    size_t chunk_count;
    size_t current_chunk;
    size_t chunk_position;
};

/* Callback function for reading data to upload (streaming upload) */
static size_t read_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    struct upload_stream *stream = (struct upload_stream *)userdata;
    size_t buffer_size = size * nitems;

    if (stream->current_chunk >= stream->chunk_count) {
        return 0; /* End of data */
    }

    const char *current_data = stream->chunks[stream->current_chunk];
    size_t current_len = strlen(current_data);
    size_t remaining = current_len - stream->chunk_position;

    if (remaining == 0) {
        /* Move to next chunk */
        stream->current_chunk++;
        stream->chunk_position = 0;

        if (stream->current_chunk >= stream->chunk_count) {
            return 0; /* End of data */
        }

        current_data = stream->chunks[stream->current_chunk];
        current_len = strlen(current_data);
        remaining = current_len;
    }

    size_t to_copy = (remaining < buffer_size) ? remaining : buffer_size;
    memcpy(buffer, current_data + stream->chunk_position, to_copy);
    stream->chunk_position += to_copy;

    printf("Uploading chunk: %.*s", (int)to_copy, buffer);
    return to_copy;
}

/* Callback function for writing received data (streaming download) */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct streaming_data *mem = (struct streaming_data *)userdata;

    printf("Received %zu bytes: %.*s\n", realsize, (int)realsize, (char *)contents);

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

/* Progress callback for monitoring transfer */
static int progress_callback(
    void *clientp,
    curl_off_t dltotal,
    curl_off_t dlnow,
    curl_off_t ultotal,
    curl_off_t ulnow) {
    if (ultotal > 0) {
        printf("Upload progress: %lld/%lld bytes (%.1f%%)\n", ulnow, ultotal, (double)ulnow / ultotal * 100.0);
    }
    if (dltotal > 0) {
        printf("Download progress: %lld/%lld bytes (%.1f%%)\n", dlnow, dltotal, (double)dlnow / dltotal * 100.0);
    }
    return 0;
}

/* Helper function to calculate total size of all chunks */
static size_t calculate_total_size(const char **chunks, size_t chunk_count) {
    size_t total = 0;
    for (size_t i = 0; i < chunk_count; i++) {
        total += strlen(chunks[i]);
    }
    return total;
}

/* Example 1: Streaming upload with Content-Length header */
int example_content_length_upload(const char *url) {
    CURL *curl;
    CURLcode res;

    printf("\n=== Example 1: Streaming Upload with Content-Length ===\n");

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return 1;
    }

    /* Data to stream in chunks */
    const char *chunks[] = {
        "This is the first chunk of data\n",
        "This is the second chunk of data\n",
        "This is the third chunk of data\n",
        "This is the final chunk of data\n"};

    struct upload_stream stream = {
        .chunks = chunks, .chunk_count = sizeof(chunks) / sizeof(chunks[0]), .current_chunk = 0, .chunk_position = 0};

    /* Calculate total size upfront - REQUIRED for Content-Length */
    size_t total_size = 120;
    printf("Total upload size: %zu bytes\n", total_size);

    struct streaming_data response = {0};

    /* Configure curl for streaming upload with Content-Length */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    /* Set headers - Content-Length instead of Transfer-Encoding: chunked */
    struct curl_slist *headers = NULL;
    char content_length_header[64];
    // snprintf(content_length_header, sizeof(content_length_header), "Content-Length: %zu", total_size);
    headers = curl_slist_append(headers, content_length_header);
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* KEY: Set the content length - tells curl the exact size */
    // curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)total_size);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &stream);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    /* Enable progress monitoring */
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);

    /* Force HTTP/1.1 */
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    /* Perform the request */
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
        printf("Upload completed successfully\n");
        printf("Server response: %s\n", response.data ? response.data : "(no response)");
    }

    /* Cleanup */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (response.data) {
        free(response.data);
    }

    return (res == CURLE_OK) ? 0 : 1;
}

/* Example 2: Comparison with chunked encoding */
int example_chunked_upload(const char *url) {
    CURL *curl;
    CURLcode res;

    printf("\n=== Example 2: Streaming Upload with Chunked Encoding (for comparison) ===\n");

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return 1;
    }

    /* Same data as Example 1 */
    const char *chunks[] = {
        "This is the first chunk of data\n",
        "This is the second chunk of data\n",
        "This is the third chunk of\n",
        "This is the final chunk of data\n"};

    struct upload_stream stream = {
        .chunks = chunks, .chunk_count = sizeof(chunks) / sizeof(chunks[0]), .current_chunk = 0, .chunk_position = 0};

    struct streaming_data response = {0};

    /* Configure curl for chunked encoding */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &stream);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    /* Use chunked encoding - no size specified */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Enable progress monitoring */
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);

    /* Force HTTP/1.1 */
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    /* Perform the request */
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
        printf("Upload completed successfully\n");
        printf("Server response: %s\n", response.data ? response.data : "(no response)");
    }

    /* Cleanup */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (response.data) {
        free(response.data);
    }

    return (res == CURLE_OK) ? 0 : 1;
}

/* Example 3: Bidirectional streaming with Content-Length */
int example_bidirectional_content_length(const char *url) {
    CURL *curl;
    CURLcode res;

    printf("\n=== Example 3: Bidirectional Streaming with Content-Length ===\n");

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return 1;
    }

    /* JSON data chunks */
    const char *chunks[] = {
        "{\"message\": \"Hello from streaming client\", \"chunk\": 1}\n",
        "{\"message\": \"This is chunk 2\", \"chunk\": 2}\n",
        "{\"message\": \"Final chunk\", \"chunk\": 3}\n"};

    struct upload_stream stream = {
        .chunks = chunks, .chunk_count = sizeof(chunks) / sizeof(chunks[0]), .current_chunk = 0, .chunk_position = 0};

    /* Calculate total size */
    size_t total_size = calculate_total_size(chunks, stream.chunk_count);
    printf("Total upload size: %zu bytes\n", total_size);

    struct streaming_data response = {0};

    /* Configure curl for bidirectional streaming with Content-Length */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)total_size);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &stream);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    /* Set headers for JSON with Content-Length */
    struct curl_slist *headers = NULL;
    char content_length_header[64];
    snprintf(content_length_header, sizeof(content_length_header), "Content-Length: %zu", total_size);
    headers = curl_slist_append(headers, content_length_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Enable progress monitoring */
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);

    /* Force HTTP/1.1 */
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    /* Perform the request */
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
        printf("Bidirectional streaming completed successfully\n");
        printf("Server response: %s\n", response.data ? response.data : "(no response)");
    }

    /* Cleanup */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (response.data) {
        free(response.data);
    }

    return (res == CURLE_OK) ? 0 : 1;
}

void print_usage(const char *program_name) {
    printf("Usage: %s [URL]\n", program_name);
    printf("\nExamples:\n");
    printf("  %s http://httpbin.org/post\n", program_name);
    printf("  %s http://localhost:8080/upload\n", program_name);
    printf("\nThis example demonstrates:\n");
    printf("  - Streaming upload with Content-Length header\n");
    printf("  - Incremental data provision through read callback\n");
    printf("  - Comparison with chunked transfer encoding\n");
    printf("\nKey points:\n");
    printf("  - Content-Length: Total size MUST be known upfront\n");
    printf("  - Chunked: Size can be unknown, data sent with chunk markers\n");
    printf("  - Both use the same read callback mechanism\n");
    printf("  - Content-Length is cleaner protocol (no chunk framing overhead)\n");
}

int main(int argc, char *argv[]) {
    const char *upload_url = "http://httpbin.org/post";

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        upload_url = argv[1];
    }

    /* Initialize curl globally */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    printf("Curl Streaming Examples - Content-Length vs Chunked\n");
    printf("===================================================\n");
    printf("Target URL: %s\n", upload_url);

    /* Run examples */
    int result = 0;
    result |= example_content_length_upload(upload_url);
    // result |= example_chunked_upload(upload_url);
    // result |= example_bidirectional_content_length(upload_url);

    /* Cleanup curl globally */
    curl_global_cleanup();

    printf("\n=== Summary ===\n");
    printf("All examples completed with result: %d\n", result);
    printf("\nKey Takeaways:\n");
    printf("1. Content-Length requires knowing total size upfront\n");
    printf("2. Both approaches use the same read_callback mechanism\n");
    printf("3. Data is provided incrementally in both cases\n");
    printf("4. Content-Length has less protocol overhead\n");
    printf("5. Chunked is more flexible when size is unknown\n");

    return result;
}
