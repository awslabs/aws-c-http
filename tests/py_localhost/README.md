# Local server

Local server based on [python-hyper/h2](https://github.com/python-hyper/h2).

## How to run the server

Python 3.5+ required.

- Install hyper h2 python module. `python3 -m pip install h2`

### TLS server

- The code is based the [example](https://github.com/python-hyper/h2/blob/master/examples/asyncio/asyncio-server.py) from hyper h2 server.
- Have the cert/key ready. The script now using `../resources/unittests.crt`, you can either just run the script within this directory, which will find the certificates and key from the related path, or you can use your own and change the code coordinately.
- Run python. `python3 ./server.py`.

#### Echo

- Minor changed based on the example to response the headers of requests back within the headers from `/echo`.
- To test the server runs correctly, you can do `curl -k -v -H "foo:bar" https://localhost:3443/echo` and check the result.

#### Download test

- To test download, when `:path` is `/downloadTest`, server will response a repeated string with length `self.download_test_length`, which is 2,500,000,000 now. It will be repeats of sting "This is CRT HTTP test."
- To test the server runs correctly, you can do `curl -k -v -H "foo:bar" https://localhost:3443/downloadTest` and check the result.

#### Slow Connection Test

- Simulate a slow connection when `:path` is `/slowConnTest`. The speed is controlled by `out_bytes_per_second`. Default speed is 900 B/s, which will send 900 bytes of data and wait a sec to send new 900 bytes of data.

#### Upload test

- To test upload, when `:method` is `POST` or `PUT`, server will response the length received from response body
- To test the server runs correctly, you can do `curl -k -X POST -F'data=@upload_test.txt' https://localhost:3443/upload_test` where `upload_test.txt` is file to upload.

### Non-TLS server

- The code is based the non-tls [example](http://python-hyper.org/projects/h2/en/stable/basic-usage.html) from hyper h2 server.
- Run python. `python3 ./non_tls_server.py`.
- To test the server runs correctly, you can do `curl -v --http2-prior-knowledge http://localhost:3280` and check the result.
