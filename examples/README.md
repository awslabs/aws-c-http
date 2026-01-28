# Curl HTTP/1.1 Streaming Examples

This directory contains comprehensive examples demonstrating curl's streaming capabilities for HTTP/1.1 requests, including both upload and download streaming scenarios.

## Overview

**Yes, curl fully supports streaming for HTTP/1.1 requests!** This is accomplished through:

* **Upload streaming**: Using `CURLOPT_READFUNCTION` with chunked transfer encoding (`Transfer-Encoding: chunked`)
* **Download streaming**: Using `CURLOPT_WRITEFUNCTION` to process data as it arrives
* **Bidirectional streaming**: Combining both upload and download streaming simultaneously
* **Progress monitoring**: Using `CURLOPT_XFERINFOFUNCTION` to track transfer progress

## Files

* `curl_streaming_example.c` - Complete C example with chunked transfer encoding
* `curl_content_length_example.c` - Complete C example with Content-Length header
* `test_server.py` - Python HTTP server for testing streaming functionality
* `Makefile` - Build system with test targets
* `README.md` - This documentation

## Key Features Demonstrated

### 1. Content-Length vs Chunked Encoding

**Two Approaches for Streaming:**

**Content-Length Streaming** ( `curl_content_length_example.c` ):
* Uses `CURLOPT_READFUNCTION` callback to provide data incrementally
* Requires knowing total size upfront - set via `CURLOPT_POSTFIELDSIZE_LARGE`
* Sets `Content-Length` header explicitly
* Server knows total size immediately
* Cleaner protocol with less overhead
* Better for scenarios where size is known in advance

**Chunked Transfer Encoding** ( `curl_streaming_example.c` ):
* Uses `CURLOPT_READFUNCTION` callback to provide data incrementally
* Enables chunked transfer encoding with `Transfer-Encoding: chunked` header
* Forces HTTP/1.1 protocol with `CURL_HTTP_VERSION_1_1`
* Streams data without knowing total size in advance
* More flexible for dynamic content generation

### 2. Download Streaming

* Uses `CURLOPT_WRITEFUNCTION` callback to process received data
* Handles chunked responses from server
* Processes data as it arrives (real-time streaming)

### 3. Bidirectional Streaming

* Combines upload and download streaming in a single request
* Useful for interactive protocols and real-time communication
* Demonstrates simultaneous data flow in both directions

### 4. Progress Monitoring

* Uses `CURLOPT_XFERINFOFUNCTION` to track transfer progress
* Provides real-time feedback on upload/download status
* Useful for user interfaces and debugging

## Building and Running

### Prerequisites

* libcurl development headers
* GCC or compatible C compiler
* Python 3 (for test server)

### Quick Start

```bash
# Check dependencies
make check-deps

# Build the examples
make

# Run Content-Length streaming example
./curl_content_length_example http://httpbin.org/post

# Run chunked encoding streaming example
./curl_streaming_example http://httpbin.org/post

# With test server (in one terminal)
make test-server

# Run streaming tests (in another terminal)
make test-all
```

### Individual Tests

```bash
# Test chunked upload streaming
make test-upload

# Test download streaming
make test-download

# Test bidirectional streaming
make test-bidirectional

# Test with curl command line
make test-curl
```

## Example Output

### Content-Length Upload Streaming

```
=== Example 1: Streaming Upload with Content-Length ===
Total upload size: 129 bytes
Uploading chunk: This is the first chunk of data
Uploading chunk: This is the second chunk of data
Uploading chunk: This is the third chunk of data
Uploading chunk: This is the final chunk of data
Upload completed successfully
Server response: {
  "headers": {
    "Content-Length": "129",
    "Content-Type": "text/plain"
  },
  "data": "This is the first chunk of data\n..."
}
```

### Chunked Upload Streaming

```
=== Example 1: Streaming Upload ===
Uploading chunk: This is the first chunk of data
Uploading chunk: This is the second chunk of data
Uploading chunk: This is the third chunk of data
Uploading chunk: This is the final chunk of data
Upload completed successfully
Server response: {
  "status": "success",
  "received_bytes": 129,
  "content_preview": "This is the first chunk of data\n...",
  "headers": {
    "Transfer-Encoding": "chunked",
    "Content-Type": "text/plain"
  }
}
```

### Download Streaming

```
=== Example 2: Streaming Download ===
Received 45 bytes: Chunk 1/3: 16:20:16
Received 45 bytes: Chunk 2/3: 16:20:17
Received 45 bytes: Chunk 3/3: 16:20:17
Download completed successfully
Total received: 135 bytes
```

## Technical Details

### HTTP/1.1 Streaming Support

Curl provides excellent HTTP/1.1 streaming support through:

1. **Callback Architecture**:
   - `CURLOPT_READFUNCTION` for upload streaming
   - `CURLOPT_WRITEFUNCTION` for download streaming
   - `CURLOPT_XFERINFOFUNCTION` for progress monitoring

2. **Two Streaming Approaches**:

   **Content-Length Method**:
   - Total size must be known upfront
   - Set via `CURLOPT_POSTFIELDSIZE_LARGE`

   - Data still provided incrementally via callback
   - Server receives total size in initial headers
   - No chunk encoding overhead
   - Use when: Size is known, cleaner protocol needed

   **Chunked Transfer Encoding**:
   - Automatic handling of `Transfer-Encoding: chunked`

   - No need to know content length in advance
   - Efficient for real-time data streaming
   - Each chunk prefixed with size
   - Use when: Size unknown, dynamic content

3. **Protocol Control**:
   - `CURL_HTTP_VERSION_1_1` forces HTTP/1.1
   - Full control over headers and request methods
   - Support for custom headers and content types

### Memory Management

The examples demonstrate proper memory management:
* Dynamic buffer allocation for received data
* Proper cleanup of curl handles and headers
* Safe handling of realloc operations

### Error Handling

Comprehensive error handling includes:
* Curl operation result checking
* Memory allocation failure handling
* Network error reporting
* Server response validation

## Test Server Endpoints

The included test server provides several endpoints for testing:

* `GET /status` - Server status and endpoint information
* `GET /stream?chunks=N&delay=S` - Streaming response with N chunks and S second delays
* `POST /upload` - Accepts chunked uploads and returns metadata
* `POST /echo` - Echoes received data back as chunked response

## Documentation References

* [libcurl Documentation](https://curl.se/libcurl/)
* [CURLOPT_READFUNCTION](https://curl.se/libcurl/c/CURLOPT_READFUNCTION.html)
* [CURLOPT_WRITEFUNCTION](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html)
* [CURLOPT_XFERINFOFUNCTION](https://curl.se/libcurl/c/CURLOPT_XFERINFOFUNCTION.html)
* [CURLOPT_POSTFIELDSIZE_LARGE](https://curl.se/libcurl/c/CURLOPT_POSTFIELDSIZE_LARGE.html)
* [HTTP/1.1 Chunked Transfer Encoding](https://tools.ietf.org/html/rfc7230#section-4.1)
* [HTTP/1.1 Content-Length](https://tools.ietf.org/html/rfc7230#section-3.3.2)

## Troubleshooting

### Build Issues

* Ensure libcurl development headers are installed
* On macOS: `brew install curl`
* On Ubuntu/Debian: `sudo apt-get install libcurl4-openssl-dev`

### Runtime Issues

* Check that test server is running on correct port (8081)
* Verify network connectivity to test endpoints
* Check curl version supports required features

### Port Conflicts

* Test server uses port 8081 by default
* Modify `test_server.py` if port is in use
* Update Makefile test targets accordingly

## License

This example code is provided for educational purposes and demonstrates curl's streaming capabilities for HTTP/1.1 requests.
