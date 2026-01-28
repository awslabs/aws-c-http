/*
 * Example demonstrating curl's streaming capabilities for HTTP/1.1 requests
 *
 * This example shows how to:
 * 1. Stream data to a server using HTTP/1.1 POST with chunked transfer encoding
 * 2. Stream data from a server response
 * 3. Handle both upload and download streaming simultaneously
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

    printf("Uploading chunk: %.*s\n", (int)to_copy, buffer);
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

/* Example 1: Streaming upload with chunked transfer encoding */
int example_streaming_upload(const char *url) {
    CURL *curl;
    CURLcode res;

    printf("\n=== Example 1: Streaming Upload ===\n");

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

    struct streaming_data response = {0};

    /* Configure curl for streaming upload */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &stream);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    /* Enable chunked transfer encoding for streaming */
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

/* Example 2: Streaming download */
int example_streaming_download(const char *url) {
    CURL *curl;
    CURLcode res;

    printf("\n=== Example 2: Streaming Download ===\n");

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return 1;
    }

    struct streaming_data response = {0};

    /* Configure curl for streaming download */
    curl_easy_setopt(curl, CURLOPT_URL, url);
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
        printf("Download completed successfully\n");
        printf("Total received: %zu bytes\n", response.size);
    }

    /* Cleanup */
    curl_easy_cleanup(curl);
    if (response.data) {
        free(response.data);
    }

    return (res == CURLE_OK) ? 0 : 1;
}

/* Example 3: Bidirectional streaming (upload and download simultaneously) */
int example_bidirectional_streaming(const char *url) {
    CURL *curl;
    CURLcode res;

    printf("\n=== Example 3: Bidirectional Streaming ===\n");

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return 1;
    }

    /* Data to stream */
    const char *chunks[] = {
        "{\"message\": \"Hello from streaming client\", \"chunk\": 1}\n",
        "{\"message\": \"This is chunk 2\", \"chunk\": 2}\n",
        "{\"message\": \"Final chunk\", \"chunk\": 3}\n"};

    struct upload_stream stream = {
        .chunks = chunks, .chunk_count = sizeof(chunks) / sizeof(chunks[0]), .current_chunk = 0, .chunk_position = 0};

    struct streaming_data response = {0};

    /* Configure curl for bidirectional streaming */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &stream);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    /* Set headers for JSON streaming */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
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

int main(int argc, char *argv[]) {
    const char *upload_url = "http://httpbin.org/post";
    const char *download_url = "http://httpbin.org/stream/10";
    const char *bidirectional_url = "http://httpbin.org/post";

    if (argc > 1) {
        upload_url = download_url = bidirectional_url = argv[1];
    }

    /* Initialize curl globally */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    printf("Curl Streaming Examples for HTTP/1.1\n");
    printf("====================================\n");

    /* Run examples */
    int result = 0;
    result |= example_streaming_upload(upload_url);
    result |= example_streaming_download(download_url);
    result |= example_bidirectional_streaming(bidirectional_url);

    /* Cleanup curl globally */
    curl_global_cleanup();

    printf("\nAll examples completed with result: %d\n", result);
    return result;
}
