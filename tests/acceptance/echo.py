#!/usr/bin/env python3
"""A tiny TLS echo upstream standing in for httpbin.org (Appendix A).

Serves HTTPS on :443 with the mounted leaf and reflects the request's
method, path, and headers as a JSON body — enough for the acceptance test to
assert header stripping and secret swapping at the upstream boundary.
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
