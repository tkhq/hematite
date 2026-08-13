#!/usr/bin/env python3
"""Cold-start poller. Phase 1: wait for the (old) proxy to stop answering.
Phase 2: poll every 10ms until a full proxied request succeeds; print the
epoch-ms of that first success. Run me BEFORE restarting the proxy.

Measurement granularity: each failed connect attempt blocks up to the connect
timeout (~50ms worst case while the proxy is down), so cold_start_ms resolution
is bounded by ~50ms even though the poll interval is 10ms.

Overall deadline: 60s (monotonic). Exits with code 2 if the proxy never
recovers within that window."""
import socket
import ssl
import sys
import time

proxy_host, proxy_port = sys.argv[1].split(":")

DEADLINE = time.monotonic() + 60.0


def attempt():
    try:
        # Connect timeout kept short (0.05s) so failed attempts while the proxy
        # is down cost at most ~50ms each, bounding measurement granularity.
        # Once TCP connects, remaining latency is genuine proxy work and must be
        # counted, so the post-connect TLS/read timeout is left at 0.5s.
        s = socket.create_connection((proxy_host, int(proxy_port)), timeout=0.05)
        s.sendall(b"CONNECT upstream.test:443 HTTP/1.1\r\nHost: upstream.test:443\r\n\r\n")
        buf = b""
        s.settimeout(0.5)
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
    if time.monotonic() >= DEADLINE:
        print("poll.py: deadline exceeded waiting for proxy to go down", file=sys.stderr)
        sys.exit(2)
    time.sleep(0.01)

while not attempt():      # phase 2: wait for the restarted proxy
    if time.monotonic() >= DEADLINE:
        print("poll.py: deadline exceeded waiting for proxy to come back", file=sys.stderr)
        sys.exit(2)
    time.sleep(0.01)

print(int(time.time() * 1000), flush=True)
