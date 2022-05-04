# Local server

Local server based on [python-hyper/h2](https://github.com/python-hyper/h2).

## How to run the server

Python 3.5+ required. Command here works for OSX and linux.

- Install hyper h2 python module. `python3 -m pip install h2`

### TLS echo server

- The code is based the [example](https://github.com/python-hyper/h2/blob/master/examples/asyncio/asyncio-server.py) from hyper h2 server. Minor changed based on the example to response the headers of requests back within the headers from `/echo`.
- Have the cert/key ready. The script now using `../resources/unittests.crt`, you can either just run the script within this directory, which will find the certificates and key from the related path, or you can use your own and change the code coordinately.
- Run python. `python3 ./server.py`.
- To test the server runs correctly, you can do `curl -k -v -H "foo:bar" https://localhost:8443/echo` and check the result.

### Non-TLS server

- The code is based the non-tls [example](http://python-hyper.org/projects/h2/en/stable/basic-usage.html) from hyper h2 server.
- Run python. `python3 ./non_tls_server.py`.
- To test the server runs correctly, you can do `curl -v --http2-prior-knowledge http://localhost:8080` and check the result.
