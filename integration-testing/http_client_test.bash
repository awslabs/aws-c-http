#!/bin/bash

declare -a TEST_NAMES
declare -a TEST_RESULTS
declare -a TEST_CODES

# Hosts and ports
LOCAL_HOST=localhost
REMOTE_HOST=httpbin.org
PORT_HTTP=80
PORT_HTTPS=443
PATH=/headers
PROXY_HOST=localhost
PROXY_PORT=1080
PROXY_URI="socks5h://testuser:testpass@${PROXY_HOST}:${PROXY_PORT}"
EXECUTABLE=./bin/http_client_app/http_client_app

run_case() {
	echo ""
	echo ""
	local test_title="$1"
	echo "===== $test_title ====="
	shift
	"$@"
	local status=$?
	TEST_NAMES+=("$test_title")
	TEST_RESULTS+=("$status")
	TEST_CODES+=("$status")
}

print_summary() {
	GREEN='\033[0;32m'
	RED='\033[0;31m'
	NC='\033[0m' # No Color
	echo "===================="
	echo "Test Summary:"
	pass_count=0
	fail_count=0
	for i in "${!TEST_NAMES[@]}"; do
		name="${TEST_NAMES[$i]}"
		result="${TEST_RESULTS[$i]}"
		if [ "$result" -eq 0 ]; then
			echo -e "${GREEN}[PASS]${NC} $name"
			((pass_count++))
		else
			echo -e "${RED}[FAIL]${NC} $name (exit code ${TEST_CODES[$i]})"
			((fail_count++))
		fi
	done
	echo "--------------------"
	echo "Total: $((pass_count+fail_count)), Passed: $pass_count, Failed: $fail_count"
	echo "===================="
}

# Test case functions
test_direct_http() {
	run_case "Direct HTTP (no proxy, no TLS)" \
		$EXECUTABLE --host $HOST --port $PORT_HTTP --path $PATH
}

test_direct_https() {
	run_case "Direct HTTPS (no proxy, TLS)" \
		$EXECUTABLE --host $HOST --port $PORT_HTTPS --path $PATH
}

test_proxy_http() {
	run_case "Proxy HTTP (SOCKS5, no TLS)" \
		$EXECUTABLE --host $HOST --port $PORT_HTTP --path $PATH \
		--proxy "$PROXY_URI"
}

test_proxy_https() {
	run_case "Proxy HTTPS (SOCKS5, TLS)" \
		$EXECUTABLE --host $HOST --port $PORT_HTTPS --path $PATH \
		--proxy "$PROXY_URI"
}

# Call all test cases

# Local cases
HOST=$LOCAL_HOST
# Enable local http server
#test_direct_http
#test_direct_https
#test_proxy_http
#test_proxy_https

# Remote cases
HOST=$REMOTE_HOST
test_direct_http
test_direct_https
test_proxy_http
test_proxy_https

print_summary
