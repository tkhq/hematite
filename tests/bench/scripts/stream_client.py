#!/usr/bin/env python3
"""SSE/WebSocket conformance client. Establishes a CONNECT tunnel through
the proxy under test, then speaks TLS to stream.test directly.

Usage: stream_client.py <sse|ws> <proxy-host:port>   (exit 0 = PASS)
"""
import base64
import os
import socket
import ssl
import sys
import time

mode, proxy = sys.argv[1], sys.argv[2]
phost, pport = proxy.split(":")

s = socket.create_connection((phost, int(pport)), timeout=10)
s.sendall(b"CONNECT stream.test:443 HTTP/1.1\r\nHost: stream.test:443\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf:
    buf += s.recv(4096)
assert b" 200" in buf.split(b"\r\n")[0], f"CONNECT failed: {buf!r}"
ctx = ssl.create_default_context(cafile="/certs/ca.crt")
t = ctx.wrap_socket(s, server_hostname="stream.test")
t.settimeout(10)

if mode == "sse":
    t.sendall(b"GET /sse HTTP/1.1\r\nHost: stream.test\r\nAccept: text/event-stream\r\n\r\n")
    start = time.monotonic()
    first = None
    data = b""
    while data.count(b"data:") < 3:
        chunk = t.recv(4096)
        if not chunk:
            break
        data += chunk
        if first is None and b"data:" in data:
            first = time.monotonic() - start
    total = time.monotonic() - start
    ok = data.count(b"data:") >= 3 and first is not None and first < 0.5 and total >= 0.9
    print(f"sse first_event_s={first} total_s={total:.2f} events={data.count(b'data:')}")
    sys.exit(0 if ok else 1)

if mode == "ws":
    key = base64.b64encode(os.urandom(16)).decode()
    t.sendall(
        (
            "GET /ws HTTP/1.1\r\nHost: stream.test\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += t.recv(4096)
    assert b" 101" in buf.split(b"\r\n")[0], f"upgrade failed: {buf!r}"
    payload = b"ping-bench"
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    t.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
    hdr = t.recv(2)
    length = hdr[1] & 0x7F
    echoed = b""
    while len(echoed) < length:
        echoed += t.recv(length - len(echoed))
    print(f"ws echoed={echoed!r}")
    sys.exit(0 if echoed == payload else 1)

sys.exit(2)
