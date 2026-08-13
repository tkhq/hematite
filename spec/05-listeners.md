# Part 05 — Listeners

*Depends on: Parts 00–03. Conformance: §1–§2 and §6 at L1; §3–§5 at L2.*

Listeners adapt sockets into `RequestSummary` values, invoke the kernel, and
carry allowed traffic to the dialer (Part 07). Four listeners: HTTP, HTTPS,
tunnel, DNS (Part 06). Each is enabled by its config `listen` address.

## 1. Common request handling

For every HTTP-shaped request, in order:

1. Take `summary.host` from the `Host` header: lowercase the hostname and
   split off any port. Missing or empty host → 400.
2. Reject paths containing `.` or `..` segments, checked on the
   percent-decoded segments → 400 (Part 01 §1).
3. On TLS connections, the SNI hostname MUST equal the `Host` hostname
   (ports ignored); mismatch → 400 (threat T6).
4. Wrap the body per Part 01 §4; run the pipeline; emit audit (INV-3).

## 2. HTTP listener (L1)

- Cleartext HTTP/1.1 on `proxy.http_listen` (default `:80`).
- Serves both origin-form requests (transparent interception via DNS) and
  absolute-form proxy requests (`GET http://host/path`); for absolute-form,
  the target host comes from the request-target and MUST agree with the
  `Host` header, else 400.
- `mode: "http"`.

## 3. HTTPS listener — TLS MITM (L2)

- TLS on `proxy.https_listen` (default `:443`). ALPN offers `h2` and
  `http/1.1`; both HTTP/1.1 and HTTP/2 MUST be served.
- **Leaf certificates** are minted per SNI hostname, signed by the operator's
  CA (`tls.ca_cert`/`tls.ca_key`):
  - ECDSA P-256 key; random ≥64-bit serial; CN and single dNSName = the SNI
    hostname; NotBefore = now − 1 min (clock skew); NotAfter = now +
    `leaf_cert_expiry_hours` (default 72); KeyUsage digitalSignature; EKU
    serverAuth. The served chain includes the CA certificate.
  - Cache: LRU keyed by hostname, capacity `cert_cache_size` (default 1000);
    concurrent misses for one hostname MUST mint once (single-flight —
    threat T8: mint floods).
- A ClientHello without SNI → close the connection and emit an audit record
  (`action: reject`, `rejected_by: "listener"`, `host: ""`). Because RFC 6066
  forbids IP-literal SNI, TLS to IP-literal destinations is reachable only
  through the tunnel listener (§4), where the target is explicit.
- `mode: "https"`; upstream scheme https.

## 4. Tunnel listener (L2)

One port (`proxy.tunnel_listen`, disabled when unset) speaking three client
protocols, dispatched on the first byte:

- `0x05` → SOCKS5. `'A'..'Z'` → HTTP (CONNECT or absolute-form). Anything
  else → close.

### 4.1 CONNECT

Parse `CONNECT host:port` (default port 443). Build a **synthetic CONNECT
summary**: `method: "CONNECT"`, host/port from the target, empty path/query/
body, headers = the CONNECT request's headers, `mode: "tunnel"`. Run the
pipeline on it. Reject → `403` and close. Continue → reply
`HTTP/1.1 200 Connection Established` and go to §4.3.

### 4.2 SOCKS5

No-auth only (method `0x00`; otherwise reply `0xFF`). Command `0x01`
(CONNECT) only → else reply `0x07`. Address types: IPv4 `0x01`, domain
`0x03`, IPv6 `0x04` → else `0x08`. Build the same synthetic CONNECT summary
(empty header set). Reject → reply `0x02` and close. Continue → success
reply (`05 00 00 01` + zero addr + port), then §4.3.

### 4.3 Inner-protocol sniffing

Peek the first byte after the handshake:

- `0x16` → TLS. Terminate as in §3, minting the leaf for the **CONNECT
  target**: a dNSName SAN for a hostname, an iPAddress SAN for an IP literal
  (ALPN h2 + http/1.1). Serve the inner requests through the full pipeline;
  each inner request re-runs the pipeline independently. If the inner
  ClientHello carries an SNI that differs from the CONNECT target hostname,
  close the connection (threat T6: the policy identity and the TLS identity
  must agree). Inner requests keep `mode: "tunnel"` and carry the tunnel
  handshake's traces for audit attribution (Part 08 §2). The upstream port is
  the CONNECT target's port.
- `'A'..'Z'` → plain HTTP served as §2.
- Else → close.

SNI peeking MUST cap buffered ClientHello bytes (16 KiB) and time out (5 s)
against slow clients (threat T8).

### 4.4 Passthrough

A CONNECT or SOCKS5 target whose hostname matches a
`proxy.tunnel_passthrough_domains` glob (Part 02 §2 semantics) is spliced,
not bumped: after the policy decision and a successful upstream dial, the
listener copies bytes in both directions without TLS interception.

Order of operations, each mandatory:

1. The synthetic CONNECT summary runs the request pipeline as in §4.1. A
   non-`Continue` outcome rejects the tunnel before any dial.
2. The upstream dial consumes the pipeline's proof and applies the guard
   (Part 07 §2) to the address actually dialed. A denial or dial failure
   fails the CONNECT (HTTP 502 / SOCKS5 failure); the success reply is sent
   only after the dial completes.
3. When the first buffered client bytes are a TLS ClientHello, its SNI MUST
   equal the CONNECT target hostname (case-insensitive); on mismatch the
   tunnel closes before any byte reaches the upstream (threat T6). The scan
   reuses the §4.3 caps. Non-TLS bytes, an absent SNI, and a scan timeout
   pass through: the CONNECT-target policy already applied.
4. Exactly one audit record is emitted per passthrough tunnel when it
   closes: `method: "CONNECT"`, `mode: "tunnel"`, the handshake traces, the
   observed SNI when present, and `tunnel.passthrough: true` (Part 08 §2).

Because the proxy never sees plaintext, per-request transforms cannot apply
inside a passthrough tunnel. A configuration in which any transform rule's
`host` overlaps a passthrough glob (in either match direction) MUST be
rejected at load (Part 09 §3): a policy that cannot run is a configuration
error, not a warning. The `allowlist` transform is exempt — it governs the
CONNECT itself.

Passthrough requires no `tls` section: it operates at L1 capability on the
tunnel listener.

## 5. Streaming (L2)

- **WebSocket**: a request with a valid `Upgrade: websocket` handshake that
  passes the request pipeline is forwarded. On an upstream `101`, the proxy
  switches to bidirectional byte copy. Response transforms do not run on
  frames. The audit action reflects the handshake result.
- **SSE**: a response with `Content-Type: text/event-stream` MUST be streamed
  with a flush after each chunk, never buffered end-to-end. Response
  transforms that would force full buffering MUST NOT match SSE responses in
  v1 (only `body_capture` reads bodies, and it is request-only).

## 6. Failure behavior

- Pipeline error → 502 (Part 03 §3). Upstream dial/timeout failure → 502.
- Client disconnect mid-request → no response; audit action `client_cancel`,
  INFO (not an upstream error).
- All listener-level rejections (400s, SNI-less closes) MUST also emit audit
  records with action `reject`, `rejected_by: "listener"`, and the observed
  status code. When the failure precedes host extraction, `host` is the
  empty string (the one case the schema permits it).
