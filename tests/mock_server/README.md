# HTTP2 Local server

Local server based on [python-hyper/h2](https://github.com/python-hyper/h2).

## How to run the server

Python 3.5+ required.

* Install hyper h2 python module. `python3 -m pip install h2`

### TLS server

* The code is based the [example](https://github.com/python-hyper/h2/blob/master/examples/asyncio/asyncio-server.py) from hyper h2 server.
* Have the cert/key ready. The script now using `../resources/unittests.crt`, you can either just run the script within this directory, which will find the certificates and key from the related path, or you can use your own and change the code coordinately.
* Run python. `python3 ./server.py`.

#### Endpoint

##### `/echo` - Echo endpoint (default)

Echoes back request headers and body as JSON.

```bash
curl -k -v -H "foo:bar" https://localhost:3443/echo
```
#### Special headers

##### `/echo` with `x-repeat-data` header - Download test

Sends repeated test pattern of specified size (in bytes).

```bash
# Download 1MB of repeated data
curl -k -v -H "x-repeat-data: 1000000" https://localhost:3443/echo
```

##### `/echo` with `x-repeat-data` + `x-slow-response` headers - Slow connection test

Sends repeated data throttled to ~900 bytes/sec (for timeout testing).

```bash
# Download 5MB slowly at default speed (900 bytes/sec)
curl -k -v -H "x-repeat-data: 5000000" -H "x-slow-response: true" https://localhost:3443/echo
```

##### `/echo` with custom throughput - Custom speed test

Override default throughput with `x-throughput-bps` header.

```bash
# Download 5MB at 500 bytes/sec
curl -k -v -H "x-repeat-data: 5000000" -H "x-slow-response: true" -H "x-throughput-bps: 500" https://localhost:3443/echo
```

##### `/echo` with `x-upload-test` header - Upload test

Returns the byte count of the uploaded body without echoing the body content.

```bash
# Upload data and get byte count
curl -k -v -X PUT -H "x-upload-test: true" -d "test data" https://localhost:3443/echo
```

##### `/echo` with `x-expect-status` header - Custom status code

Returns the specified HTTP status code.

```bash
# Get a 500 status code
curl -k -v -H "x-expect-status: 500" https://localhost:3443/echo
```

##### Any other path

Returns 404 Not Found.

### Non-TLS server

- The code is based the non-tls [example](http://python-hyper.org/projects/h2/en/stable/basic-usage.html) from hyper h2 server.
- Run python. `python3 ./non_tls_server.py`.
- To test the server runs correctly, you can do `curl -v --http2-prior-knowledge http://localhost:3280` and check the result.

# HTTP1.1 Local server

## Requirements

Install the required Python dependencies:

```bash
pip install trio h11
```

Or using pip3:

```bash
pip3 install trio h11
```

## Running the Server

### Basic Usage (HTTP + HTTPS)

Run both HTTP (port 80) and HTTPS (port 443) servers:

```bash
sudo python3 mock_server.py
```

Note: `sudo` is required for ports 80 and 443 on most systems.

### Test Mode (Custom Port)

Run on a custom port without sudo:

```bash
TEST_PORT=8080 python3 mock_server.py
```

**Important**: Since this uses a self-signed certificate, clients must disable peer verification.

## Endpoints

- **Any path**: Echoes request body as JSON
- **/response-headers?HeaderName=value**: Adds custom headers to the response based on query parameters

## Stopping the Server

Press `Ctrl+C` to gracefully shut down the server.
