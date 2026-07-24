#!/usr/bin/env python3
import json
from itertools import count
import os
from urllib.parse import quote

import trio
import h11

MAX_RECV = 2**16
TIMEOUT = 10


class TrioHTTPWrapper:
    _next_id = count()

    def __init__(self, stream):
        self.stream = stream
        self.conn = h11.Connection(h11.SERVER)
        self._obj_id = next(TrioHTTPWrapper._next_id)

    async def send(self, event):
        assert type(event) is not h11.ConnectionClosed
        data = self.conn.send(event)
        try:
            await self.stream.send_all(data)
        except BaseException:
            self.conn.send_failed()
            raise

    async def _read_from_peer(self):
        if self.conn.they_are_waiting_for_100_continue:
            self.info("Sending 100 Continue")
            go_ahead = h11.InformationalResponse(
                status_code=100, headers=self.basic_headers()
            )
            await self.send(go_ahead)
        try:
            data = await self.stream.receive_some(MAX_RECV)
            # URL-encode non-ASCII characters in the request line
            if data and b'\r\n' in data:
                request_line_end = data.index(b'\r\n')
                request_line = data[:request_line_end]
                rest = data[request_line_end:]
                
                try:
                    # Try to decode and check if there are non-ASCII chars
                    request_line_str = request_line.decode('ascii')
                except UnicodeDecodeError:
                    # Has non-ASCII, need to URL-encode
                    parts = request_line.split(b' ')
                    if len(parts) == 3:
                        method, target, version = parts
                        # URL-encode the target
                        target_str = target.decode('utf-8', errors='replace')
                        # Only encode the path part, preserve the structure
                        if '?' in target_str:
                            path, query = target_str.split('?', 1)
                            # Encode each query parameter value
                            encoded_query_parts = []
                            for param in query.split('&'):
                                if '=' in param:
                                    key, value = param.split('=', 1)
                                    encoded_value = quote(value, safe='')
                                    encoded_query_parts.append(f"{key}={encoded_value}")
                                else:
                                    encoded_query_parts.append(param)
                            target_str = path + '?' + '&'.join(encoded_query_parts)
                        
                        request_line = b' '.join([method, target_str.encode('ascii'), version])
                        data = request_line + rest
        except (ConnectionError, trio.BrokenResourceError, trio.ClosedResourceError):
            data = b""
        self.conn.receive_data(data)

    async def next_event(self):
        while True:
            event = self.conn.next_event()
            if event is h11.NEED_DATA:
                await self._read_from_peer()
                continue
            return event

    async def shutdown_and_clean_up(self):
        try:
            if hasattr(self.stream, 'send_eof'):
                await self.stream.send_eof()
        except (trio.BrokenResourceError, AttributeError):
            pass
        
        with trio.move_on_after(TIMEOUT):
            try:
                while True:
                    got = await self.stream.receive_some(MAX_RECV)
                    if not got:
                        break
            except (trio.BrokenResourceError, trio.ClosedResourceError):
                pass
        
        try:
            await self.stream.aclose()
        except (trio.BrokenResourceError, trio.ClosedResourceError):
            pass

    def basic_headers(self):
        return [("Server", "echo-server")]

    def info(self, *args):
        print(f"{self._obj_id}:", *args)


async def http_serve(stream):
    wrapper = TrioHTTPWrapper(stream)
    wrapper.info("Got new connection")
    while True:
        assert wrapper.conn.states == {h11.CLIENT: h11.IDLE, h11.SERVER: h11.IDLE}

        try:
            with trio.fail_after(TIMEOUT):
                wrapper.info("Server main loop waiting for request")
                event = await wrapper.next_event()
                wrapper.info("Server main loop got event:", event)
                if type(event) is h11.Request:
                    await send_echo_response(wrapper, event)
        except Exception as exc:
            wrapper.info(f"Error during response handler: {exc!r}")
            await maybe_send_error_response(wrapper, exc)

        if wrapper.conn.our_state is h11.MUST_CLOSE:
            wrapper.info("connection is not reusable, so shutting down")
            await wrapper.shutdown_and_clean_up()
            return
        else:
            try:
                wrapper.info("trying to re-use connection")
                wrapper.conn.start_next_cycle()
            except h11.ProtocolError:
                states = wrapper.conn.states
                wrapper.info("unexpected state", states, "-- bailing out")
                await maybe_send_error_response(
                    wrapper, RuntimeError(f"unexpected state {states}")
                )
                await wrapper.shutdown_and_clean_up()
                return


async def send_simple_response(wrapper, status_code, content_type, body):
    wrapper.info("Sending", status_code, "response with", len(body), "bytes")
    headers = wrapper.basic_headers()
    headers.append(("Content-Type", content_type))
    headers.append(("Content-Length", str(len(body))))
    res = h11.Response(status_code=status_code, headers=headers)
    await wrapper.send(res)
    await wrapper.send(h11.Data(data=body))
    await wrapper.send(h11.EndOfMessage())


async def maybe_send_error_response(wrapper, exc):
    wrapper.info("trying to send error response...")
    if wrapper.conn.our_state not in {h11.IDLE, h11.SEND_RESPONSE}:
        wrapper.info("...but I can't, because our state is", wrapper.conn.our_state)
        return
    try:
        if isinstance(exc, h11.RemoteProtocolError):
            status_code = exc.error_status_hint
        elif isinstance(exc, trio.TooSlowError):
            status_code = 408
        else:
            status_code = 500
        body = str(exc).encode("utf-8")
        await send_simple_response(
            wrapper, status_code, "text/plain; charset=utf-8", body
        )
    except Exception as exc:
        wrapper.info("error while sending error response:", exc)


async def send_echo_response(wrapper, request):
    wrapper.info("Preparing echo response")
    
    body_data = b""
    while True:
        event = await wrapper.next_event()
        if type(event) is h11.EndOfMessage:
            break
        assert type(event) is h11.Data
        body_data += event.data
    
    target = request.target if isinstance(request.target, bytes) else request.target.encode()
    target_str = target.decode("utf-8", errors="replace")
    
    # Check if this is the /404 endpoint
    if target_str.startswith("/404"):
        status_code = 404
    else:
        status_code = 200
    
    response_json = {"data": body_data.decode("utf-8")}
    response_body = json.dumps(response_json, indent=4).encode("utf-8")
    
    headers = wrapper.basic_headers()
    headers.append(("Content-Type", "application/json; charset=utf-8"))
    headers.append(("Content-Length", str(len(response_body))))
    
    for header_name, header_value in request.headers:
        echo_name = b"Echo-" + header_name if isinstance(header_name, bytes) else f"Echo-{header_name}".encode()
        echo_value = header_value if isinstance(header_value, bytes) else str(header_value).encode()
        headers.append((echo_name, echo_value))
    
    res = h11.Response(status_code=status_code, headers=headers)
    await wrapper.send(res)
    await wrapper.send(h11.Data(data=response_body))
    await wrapper.send(h11.EndOfMessage())


async def serve(port):
    print(f"listening on http://localhost:{port}")
    try:
        await trio.serve_tcp(http_serve, port)
    except KeyboardInterrupt:
        print("KeyboardInterrupt - shutting down")


async def serve_ssl(port, cert_file=os.path.join(os.path.dirname(__file__),
                          "../resources/unittests.crt"), key_file=os.path.join(os.path.dirname(__file__),
                          "../resources/unittests.key")):
    import ssl
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(script_dir, cert_file)
    key_path = os.path.join(script_dir, key_file)
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"Warning: SSL certificates not found at {cert_path} and {key_path}")
        print(f"Skipping HTTPS server on port {port}")
        print(f"To enable HTTPS, run: openssl req -x509 -newkey rsa:2048 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj '/C=US/ST=WA/L=Seattle/O=Test/CN=localhost'")
        return
    
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(cert_path, key_path)
    
    print(f"listening on https://localhost:{port}")
    try:
        await trio.serve_ssl_over_tcp(http_serve, port, ssl_context)
    except KeyboardInterrupt:
        print("KeyboardInterrupt - shutting down")


async def main():
    http_port = os.environ.get('HTTP_PORT')
    https_port = os.environ.get('HTTPS_PORT')
    
    async with trio.open_nursery() as nursery:
        nursery.start_soon(serve, 8081 if not http_port else int(http_port))
        nursery.start_soon(serve_ssl, 8082 if not https_port else int(https_port))


if __name__ == "__main__":
    trio.run(main)
