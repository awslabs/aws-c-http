# Makefile for curl streaming examples
# Requires libcurl development headers to be installed

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LIBS = -lcurl

# Default target
all: curl_streaming_example

# Build the streaming example
curl_streaming_example: curl_streaming_example.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Clean build artifacts
clean:
	rm -f curl_streaming_example

# Test targets
test-server:
	@echo "Starting test server on http://localhost:8081"
	@echo "Press Ctrl+C to stop"
	python3 test_server.py

test-upload: curl_streaming_example
	@echo "Testing chunked upload streaming..."
	./curl_streaming_example upload

test-download: curl_streaming_example
	@echo "Testing download streaming..."
	./curl_streaming_example download

test-bidirectional: curl_streaming_example
	@echo "Testing bidirectional streaming..."
	./curl_streaming_example bidirectional

test-all: curl_streaming_example
	@echo "Running all streaming tests..."
	@echo "Make sure test server is running in another terminal: make test-server"
	@echo ""
	@echo "1. Testing upload streaming..."
	./curl_streaming_example upload
	@echo ""
	@echo "2. Testing download streaming..."
	./curl_streaming_example download
	@echo ""
	@echo "3. Testing bidirectional streaming..."
	./curl_streaming_example bidirectional

# Quick test with curl command line (requires test server running)
test-curl:
	@echo "Testing with curl command line tools..."
	@echo ""
	@echo "1. Testing chunked upload:"
	@echo "Hello from curl!" | curl -X POST -H "Transfer-Encoding: chunked" --data-binary @- http://localhost:8080/upload
	@echo ""
	@echo "2. Testing streaming download:"
	curl -N http://localhost:8080/stream?chunks=5&delay=0.3
	@echo ""
	@echo "3. Testing echo endpoint:"
	@echo "Echo test data" | curl -X POST -H "Transfer-Encoding: chunked" --data-binary @- http://localhost:8080/echo

# Check if libcurl is installed
check-deps:
	@echo "Checking dependencies..."
	@which curl > /dev/null || (echo "ERROR: curl not found. Please install curl." && exit 1)
	@which python3 > /dev/null || (echo "ERROR: python3 not found. Please install Python 3." && exit 1)
	@pkg-config --exists libcurl || (echo "ERROR: libcurl development headers not found. Please install libcurl-dev or libcurl-devel." && exit 1)
	@echo "All dependencies found!"

# Install dependencies (Ubuntu/Debian)
install-deps-ubuntu:
	sudo apt-get update
	sudo apt-get install -y libcurl4-openssl-dev build-essential python3

# Install dependencies (macOS with Homebrew)
install-deps-macos:
	brew install curl python3

# Help target
help:
	@echo "Available targets:"
	@echo "  all              - Build the curl streaming example (default)"
	@echo "  clean            - Remove build artifacts"
	@echo "  check-deps       - Check if required dependencies are installed"
	@echo "  install-deps-*   - Install dependencies for specific platforms"
	@echo ""
	@echo "Test targets:"
	@echo "  test-server      - Start the test HTTP server"
	@echo "  test-upload      - Test chunked upload streaming"
	@echo "  test-download    - Test download streaming"
	@echo "  test-bidirectional - Test bidirectional streaming"
	@echo "  test-all         - Run all streaming tests"
	@echo "  test-curl        - Test with curl command line tools"
	@echo ""
	@echo "Usage:"
	@echo "  1. Start test server: make test-server"
	@echo "  2. In another terminal: make test-all"

.PHONY: all clean test-server test-upload test-download test-bidirectional test-all test-curl check-deps install-deps-ubuntu install-deps-macos help
