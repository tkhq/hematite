#!/usr/bin/env python3
"""TLS echo upstream for the bench conformance suite (alias stream.test).

Reflects method/path/headers as JSON. Task 6 adds /sse and /ws so the
conformance suite can check unbuffered streaming through each proxy.
"""
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


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
        self._reply()

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
