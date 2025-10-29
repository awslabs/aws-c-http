# -*- coding: utf-8 -*-
# Minor change based on the example from hyper h2 server
# https://github.com/python-hyper/h2/blob/master/examples/asyncio/asyncio-server.py

"""
asyncio-server.py
~~~~~~~~~~~~~~~~~

A fully-functional HTTP/2 server using asyncio. Requires Python 3.5+.

Supported endpoints:

1. GET /echo (default)
   - Echoes back request headers and body as JSON

2. GET /echo with x-repeat-data header
   - x-repeat-data: <bytes> - Sends repeated test pattern of specified size
   - Example: x-repeat-data: 1000000 (sends 1MB)

3. GET /echo with x-repeat-data + x-slow-response headers
   - x-slow-response: true - Throttles response to ~900 bytes/sec (for timeout testing)
   - x-throughput-bps: <number> - Optional: Override throughput (default 900)
   - Example: x-repeat-data: 5000000, x-slow-response: true, x-throughput-bps: 500

4. Any other path
   - Returns 404 Not Found
"""
import asyncio
import io
import json
import ssl
import time
import os
import collections
from typing import List, Tuple

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    ConnectionTerminated, DataReceived, RemoteSettingsChanged,
    RequestReceived, StreamEnded, StreamReset, WindowUpdated
)
from h2.errors import ErrorCodes
from h2.exceptions import ProtocolError, StreamClosedError
from h2.settings import SettingCodes


RequestData = collections.namedtuple('RequestData', ['headers', 'data'])


class H2Protocol(asyncio.Protocol):
    def __init__(self):
        config = H2Configuration(client_side=False, header_encoding='utf-8')
        self.conn = H2Connection(config=config)
        self.transport = None
        self.stream_data = {}
        self.flow_control_futures = {}
        self.file_path = None
        self.num_sentence_received = {}
        self.raw_headers = None
        self.download_test_length = 2500000000
        self.out_bytes_per_second = 900

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        self.conn.initiate_connection()
        # Increase the window to large enough to avoid blocking on the window limits.
        self.conn.increment_flow_control_window(int(2147483647/2))
        self.transport.write(self.conn.data_to_send())

    def connection_lost(self, exc):
        for future in self.flow_control_futures.values():
            future.cancel()
        self.flow_control_futures = {}

    def data_received(self, data: bytes):
        try:
            events = self.conn.receive_data(data)
        except ProtocolError as e:
            self.transport.write(self.conn.data_to_send())
            self.transport.close()
        else:
            self.transport.write(self.conn.data_to_send())
            for event in events:
                if isinstance(event, RequestReceived):
                    self.request_received(event.headers, event.stream_id)
                elif isinstance(event, DataReceived):
                    self.receive_data(event.data, event.stream_id,
                                      event.flow_controlled_length)
                elif isinstance(event, StreamEnded):
                    self.stream_complete(event.stream_id)
                elif isinstance(event, ConnectionTerminated):
                    self.transport.close()
                elif isinstance(event, StreamReset):
                    self.stream_reset(event.stream_id)
                elif isinstance(event, WindowUpdated):
                    self.window_updated(event.stream_id, event.delta)
                elif isinstance(event, RemoteSettingsChanged):
                    if SettingCodes.INITIAL_WINDOW_SIZE in event.changed_settings:
                        self.window_updated(None, 0)

                self.transport.write(self.conn.data_to_send())

    def request_received(self, headers: List[Tuple[str, str]], stream_id: int):
        # Bump the flow control window to large enough to avoid blocking on the window limits.
        self.conn.increment_flow_control_window(
            int(2147483647/2), stream_id)
        self.raw_headers = headers
        headers = collections.OrderedDict(headers)

        # Store off the request data.
        request_data = RequestData(headers, io.BytesIO())
        self.stream_data[stream_id] = request_data

    def handle_request_echo(self, stream_id: int, request_data: RequestData):
        """
        Handle /echo endpoint with optional special headers:
        - x-repeat-data: <bytes> - Triggers send_repeat_data() with specified length
        - x-slow-response: true - Triggers send_slow_repeat_data() instead (requires x-repeat-data)
        - x-throughput-bps: <number> - Override throughput for slow response (default 900)
        
        Without special headers, echoes request headers and body as JSON.
        """
        headers_dict = dict(self.raw_headers)

        expect_status = headers_dict.get('x-expect-status')
        if expect_status:
            response_headers = [(':status', expect_status)]
            self.conn.send_headers(stream_id, response_headers, end_stream=True)
            return
        
        # Check for x-repeat-data header
        repeat_data_header = headers_dict.get('x-repeat-data')
        if repeat_data_header:
            try:
                length = int(repeat_data_header)
                response_headers = [(':status', '200')]
                self.conn.send_headers(stream_id, response_headers, end_stream=False)
                
                # Check for slow response
                if headers_dict.get('x-slow-response') == 'true':
                    # Check for custom throughput
                    throughput_header = headers_dict.get('x-throughput-bps')
                    if throughput_header:
                        self.out_bytes_per_second = int(throughput_header)
                    asyncio.ensure_future(self.send_slow_repeat_data(length, stream_id))
                else:
                    asyncio.ensure_future(self.send_repeat_data(length, stream_id))
                return
            except ValueError:
                pass  # Fall through to echo behavior
        
        # Check for upload test (don't echo body, just return byte count)
        if headers_dict.get('x-upload-test') == 'true':
            body_bytes = request_data.data.getvalue()
            data = json.dumps({"bytes": len(body_bytes)}, indent=4).encode("utf8")
            response_headers = [(':status', '200'), ('content-length', str(len(data)))]
            self.conn.send_headers(stream_id, response_headers, end_stream=False)
            asyncio.ensure_future(self.send_data(data, stream_id))
            return
        
        # Default echo behavior
        response_headers = [(':status', '200')]
        # Filter out headers that shouldn't be echoed back
        skip_headers = {'content-length', 'content-encoding', 'transfer-encoding'}
        for i in self.raw_headers:
            # Response headers back and exclude pseudo headers and problematic headers
            if i[0][0] != ':' and i[0].lower() not in skip_headers:
                response_headers.append(i)
        
        body_bytes = request_data.data.getvalue()
        
        body = body_bytes.decode('utf-8')

        data = json.dumps(
            {"body": body, "bytes": len(body_bytes)}, indent=4,
        ).encode("utf8")
        
        # Add correct content-length for our response
        response_headers.append(('content-length', str(len(data))))
        
        self.conn.send_headers(stream_id, response_headers, end_stream=False)
        asyncio.ensure_future(self.send_data(data, stream_id))

    def stream_complete(self, stream_id: int):
        """
        When a stream is complete, we can send our response.
        """
        try:
            request_data = self.stream_data[stream_id]
        except KeyError:
            # Just return, we probably 405'd this already
            return

        path = request_data.headers[':path']
        if path == '/echo':
            self.handle_request_echo(stream_id, request_data)
        else:
            self.conn.send_headers(stream_id, [(':status', '404')], end_stream=False)
            asyncio.ensure_future(self.send_data(b"Not Found", stream_id))

    def receive_data(self, data: bytes, stream_id: int, flow_controlled_length: int):
        """
        We've received some data on a stream. If that stream is one we're
        expecting data on, save it off. Otherwise, reset the stream.
        """
        try:
            if flow_controlled_length > 0:
                # We need to update the flow control window for the stream
                # and the connection. And the function only accepts value > 0.
                self.conn.increment_flow_control_window(
                    flow_controlled_length)
                self.conn.increment_flow_control_window(
                    flow_controlled_length, stream_id)
            stream_data = self.stream_data[stream_id]
        except KeyError:
            self.conn.reset_stream(
                stream_id, error_code=ErrorCodes.PROTOCOL_ERROR
            )
        else:
            stream_data.data.write(data)

    def stream_reset(self, stream_id):
        """
        A stream reset was sent. Stop sending data.
        """
        if stream_id in self.flow_control_futures:
            future = self.flow_control_futures.pop(stream_id)
            future.cancel()

    async def send_data(self, data, stream_id):
        """
        Send data according to the flow control rules.
        """
        while data:
            while self.conn.local_flow_control_window(stream_id) < 1:
                try:
                    await self.wait_for_flow_control(stream_id)
                except asyncio.CancelledError:
                    return

            chunk_size = min(
                self.conn.local_flow_control_window(stream_id),
                len(data),
                self.conn.max_outbound_frame_size,
            )

            try:
                self.conn.send_data(
                    stream_id,
                    data[:chunk_size],
                    end_stream=(chunk_size == len(data))
                )
            except (StreamClosedError, ProtocolError):
                # The stream got closed and we didn't get told. We're done
                # here.
                break

            self.transport.write(self.conn.data_to_send())
            data = data[chunk_size:]

    async def send_repeat_data(self, length, stream_id):
        """
        Send repeated test pattern data of specified length.
        Respects HTTP/2 flow control rules.
        Triggered by x-repeat-data header on /echo endpoint.
        """
        while length > 0:
            while self.conn.local_flow_control_window(stream_id) < 1:
                try:
                    await self.wait_for_flow_control(stream_id)
                except asyncio.CancelledError:
                    return

            chunk_size = min(
                self.conn.local_flow_control_window(stream_id),
                length,
                self.conn.max_outbound_frame_size,
            )
            repeated = b"This is CRT HTTP test."
            data = int(chunk_size/len(repeated)) * repeated + \
                repeated[:chunk_size % len(repeated)]

            try:
                self.conn.send_data(
                    stream_id,
                    data,
                    end_stream=(chunk_size == length)
                )
            except (StreamClosedError, ProtocolError):
                # The stream got closed and we didn't get told. We're done
                # here.
                break

            self.transport.write(self.conn.data_to_send())
            length = length - chunk_size

    async def send_slow_repeat_data(self, length, stream_id):
        """
        Send repeated test pattern data slowly (throttled to out_bytes_per_second, default 900).
        Used for timeout and slow connection testing.
        Triggered by x-repeat-data + x-slow-response headers on /echo endpoint.
        """
        while length > 0:
            while self.conn.local_flow_control_window(stream_id) < 1:
                try:
                    await self.wait_for_flow_control(stream_id)
                except asyncio.CancelledError:
                    return

            chunk_size = min(
                self.conn.local_flow_control_window(stream_id),
                length,
                self.conn.max_outbound_frame_size,
                self.out_bytes_per_second
            )
            repeated = b"This is CRT HTTP test."
            data = int(chunk_size/len(repeated)) * repeated + \
                repeated[:chunk_size % len(repeated)]

            try:
                # Sleep for a sec to make the out bytes per second slower than the expected
                time.sleep(1)
                self.conn.send_data(
                    stream_id,
                    data,
                    end_stream=(chunk_size == length)
                )
            except (StreamClosedError, ProtocolError):
                # The stream got closed and we didn't get told. We're done
                # here.
                break

            self.transport.write(self.conn.data_to_send())
            length = length - chunk_size

    async def wait_for_flow_control(self, stream_id):
        """
        Waits for a Future that fires when the flow control window is opened.
        """
        f = asyncio.Future()
        self.flow_control_futures[stream_id] = f
        await f

    def window_updated(self, stream_id, delta):
        """
        A window update frame was received. Unblock some number of flow control
        Futures.
        """
        if stream_id and stream_id in self.flow_control_futures:
            f = self.flow_control_futures.pop(stream_id)
            f.set_result(delta)
        elif not stream_id:
            for f in self.flow_control_futures.values():
                f.set_result(delta)

            self.flow_control_futures = {}


ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.options |= (ssl.OP_NO_COMPRESSION)
ssl_context.load_cert_chain(
    certfile=os.path.join(os.path.dirname(__file__),
                          "../resources/unittests.crt"),
    keyfile=os.path.join(os.path.dirname(__file__), "../resources/unittests.key"))
ssl_context.set_alpn_protocols(["h2"])

loop = asyncio.new_event_loop()
# Each client connection will create a new protocol instance
coro = loop.create_server(H2Protocol, '127.0.0.1', 3443, ssl=ssl_context)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
