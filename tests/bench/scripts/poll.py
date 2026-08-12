#!/usr/bin/env python3
"""Cold-start poller. Phase 1: wait for the (old) proxy to stop answering.
Phase 2: poll every 10ms until a full proxied request succeeds; print the
epoch-ms of that first success. Run me BEFORE restarting the proxy."""
import socket
import ssl
import sys
import time

proxy_host, proxy_port = sys.argv[1].split(":")


def attempt():
    try:
        s = socket.create_connection((proxy_host, int(proxy_port)), timeout=0.25)
        s.sendall(b"CONNECT upstream.test:443 HTTP/1.1\r\nHost: upstream.test:443\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                return False
            buf += chunk
        if b" 200" not in buf.split(b"\r\n")[0]:
            return False
        ctx = ssl.create_default_context(cafile="/certs/ca.crt")
        t = ctx.wrap_socket(s, server_hostname="upstream.test")
        t.settimeout(0.5)
        t.sendall(b"GET /1k.json HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n")
        return t.recv(64).startswith((b"HTTP/1.1 200", b"HTTP/1.0 200"))
    except OSError:
        return False


while attempt():          # phase 1: old proxy still up
    time.sleep(0.01)
while not attempt():      # phase 2: wait for the restarted proxy
    time.sleep(0.01)
print(int(time.time() * 1000), flush=True)
