#!/usr/bin/env python3
"""
Simple HTTP test server for testing curl streaming functionality.
Supports chunked uploads and provides streaming responses.
"""

import http.server
import socketserver
import json
import time
import threading
from urllib.parse import urlparse, parse_qs

class StreamingHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Override to add timestamps to log messages"""
        print(f"[{time.strftime('%H:%M:%S')}] {format % args}")

    def do_POST(self):
        """Handle POST requests - supports chunked uploads"""
        path = urlparse(self.path).path

        if path == '/upload':
            self.handle_upload()
        elif path == '/echo':
            self.handle_echo()
        else:
            self.send_error(404, "Not Found")

    def do_GET(self):
        """Handle GET requests - provides streaming responses"""
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)

        if path == '/stream':
            chunks = int(query.get('chunks', ['10'])[0])
            delay = float(query.get('delay', ['0.5'])[0])
            self.handle_stream_response(chunks, delay)
        elif path == '/status':
            self.handle_status()
        else:
            self.send_error(404, "Not Found")

    def handle_upload(self):
        """Handle chunked upload endpoint"""
        content_length = self.headers.get('Content-Length')
        transfer_encoding = self.headers.get('Transfer-Encoding')

        self.log_message(f"Upload request - Content-Length: {content_length}, Transfer-Encoding: {transfer_encoding}")

        # Read the request body
        if transfer_encoding and 'chunked' in transfer_encoding.lower():
            # Handle chunked encoding
            body = self.read_chunked_body()
            self.log_message(f"Received chunked data: {len(body)} bytes")
        elif content_length:
            # Handle regular content-length
            body = self.rfile.read(int(content_length))
            self.log_message(f"Received data: {len(body)} bytes")
        else:
            body = b""

        # Send response
        response_data = {
            "status": "success",
            "received_bytes": len(body),
            "content_preview": body[:100].decode('utf-8', errors='ignore') if body else "",
            "headers": dict(self.headers)
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response_data, indent=2).encode())

    def handle_echo(self):
        """Echo back the received data with streaming response"""
        content_length = self.headers.get('Content-Length')
        transfer_encoding = self.headers.get('Transfer-Encoding')

        # Read request body
        if transfer_encoding and 'chunked' in transfer_encoding.lower():
            body = self.read_chunked_body()
        elif content_length:
            body = self.rfile.read(int(content_length))
        else:
            body = b""

        # Send chunked response
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()

        # Echo back in chunks
        chunk_size = 64
        for i in range(0, len(body), chunk_size):
            chunk = body[i:i+chunk_size]
            self.send_chunk(chunk)
            time.sleep(0.1)  # Small delay to simulate streaming

        self.send_chunk(b"")  # End chunked response

    def handle_stream_response(self, chunks, delay):
        """Provide a streaming response with specified number of chunks"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()

        for i in range(chunks):
            chunk_data = f"Chunk {i+1}/{chunks}: {time.strftime('%H:%M:%S.%f')[:-3]}\n"
            self.send_chunk(chunk_data.encode())
            if i < chunks - 1:  # Don't delay after the last chunk
                time.sleep(delay)

        self.send_chunk(b"")  # End chunked response

    def handle_status(self):
        """Simple status endpoint"""
        status_data = {
            "server": "curl-streaming-test-server",
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "endpoints": {
                "/upload": "POST - accepts chunked uploads",
                "/echo": "POST - echoes back received data as chunked response",
                "/stream": "GET - provides streaming response (params: chunks, delay)",
                "/status": "GET - this status page"
            }
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(status_data, indent=2).encode())

    def read_chunked_body(self):
        """Read HTTP chunked request body"""
        body = b""
        while True:
            # Read chunk size line
            size_line = self.rfile.readline().strip()
            if not size_line:
                break

            try:
                chunk_size = int(size_line.decode(), 16)
            except ValueError:
                break

            if chunk_size == 0:
                # End of chunks, read trailing headers if any
                while True:
                    line = self.rfile.readline()
                    if line in (b'\r\n', b'\n', b''):
                        break
                break

            # Read chunk data + CRLF
            chunk_data = self.rfile.read(chunk_size)
            self.rfile.read(2)  # Read trailing CRLF
            body += chunk_data

        return body

    def send_chunk(self, data):
        """Send a chunk in HTTP chunked encoding"""
        if data:
            chunk_size = hex(len(data))[2:].encode()
            self.wfile.write(chunk_size + b'\r\n')
            self.wfile.write(data + b'\r\n')
        else:
            # End chunk
            self.wfile.write(b'0\r\n\r\n')
        self.wfile.flush()

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """HTTP Server that handles requests in separate threads"""
    allow_reuse_address = True

def main():
    port = 8081
    server_address = ('localhost', port)

    print(f"Starting curl streaming test server on http://localhost:{port}")
    print("Available endpoints:")
    print("  GET  /status          - Server status and endpoint list")
    print("  GET  /stream          - Streaming response (params: chunks=10, delay=0.5)")
    print("  POST /upload          - Accept chunked uploads")
    print("  POST /echo            - Echo received data as chunked response")
    print("\nPress Ctrl+C to stop the server")

    try:
        with ThreadedHTTPServer(server_address, StreamingHTTPRequestHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")

if __name__ == '__main__':
    main()
