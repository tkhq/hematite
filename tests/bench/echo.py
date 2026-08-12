#!/usr/bin/env python3
"""TLS echo upstream for the bench conformance suite (alias stream.test).

Reflects method/path/headers as JSON. Task 6 adds /sse and /ws so the
conformance suite can check unbuffered streaming through each proxy.
"""
import base64
import hashlib
import json
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self):
        body = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k: v for k, v in self.headers.items()},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/sse":
            return self._sse()
        if self.path == "/ws":
            return self._ws()
        self._reply()

    def _sse(self):
        # Three events 0.5s apart. An unbuffered proxy delivers the first
        # one immediately; a buffering proxy delivers all three at ~1.0s.
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for i in range(3):
            self.wfile.write(f"data: event-{i}\n\n".encode())
            self.wfile.flush()
            if i < 2:
                time.sleep(0.5)
        self.close_connection = True

    def _ws(self):
        # Minimal RFC6455 echo: accept the upgrade, read one masked text
        # frame, echo it unmasked, close. Matches scripts/stream_client.py.
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()
        ).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        hdr = self.rfile.read(2)
        length = hdr[1] & 0x7F
        mask = self.rfile.read(4)
        masked = self.rfile.read(length)
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(masked))
        self.wfile.write(bytes([0x81, len(payload)]) + payload)
        self.wfile.flush()
        self.close_connection = True

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        self._reply()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/echo.fullchain.crt", "/certs/echo.key")
    server = ThreadingHTTPServer(("0.0.0.0", 443), Echo)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
