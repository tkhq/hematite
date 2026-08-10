# Part 07 — Upstream Dialing and the Guard

*Depends on: Parts 00–03, 05. Conformance: L1.*

## 1. Upstream determination

After the pipeline continues (INV-2: the dialer consumes the verdict proof):

- Host, port, path, query = the possibly-rewritten request's values.
- Scheme: https when the client leg was TLS-terminated, else http.
- Percent-encoded path bytes not rewritten by a transform MUST be forwarded
  as received (`%2F` stays `%2F`); `secrets.match_path` substitutes
  percent-encoded bytes in place without re-encoding the rest (Part 04
  §3.2).
- Resolution uses a real resolver (OS or `dns.upstream_resolver`) — never
  hematite's own intercepting DNS server, which would loop.

## 2. The guard (deny CIDRs)

`proxy.upstream_deny_cidrs` is enforced **after** name resolution, at the
moment of connection, against the exact IP being dialed. This placement — not
at match time — is what closes DNS rebinding (threat T2): an allowlisted
hostname whose A record points at IMDS still fails at the socket.

- Default deny set (applies when the key is absent): `169.254.169.254/32`,
  `fd00:ec2::254/128`, `fd20:ce::254/128` (cloud metadata), `127.0.0.0/8`,
  `::1/128` (loopback). RFC 1918 ranges are deliberately not defaulted —
  corporate upstreams are legitimate.
- An explicitly empty list (`upstream_deny_cidrs: []`) disables the guard;
  the distinction between "absent" and "empty" MUST be preserved by the
  config loader.
- A denied dial fails the request with 502 and audits as a policy denial,
  not an error: `action: reject`, `rejected_by: "guard"`,
  `status_code: 502`, WARN level (Part 08 §2). The record carries a `guard`
  group naming the denial: `{ "denied_addr": "169.254.169.254",
  "prefix": "169.254.169.254/32" }`.
- The guard applies to every upstream connection hematite makes on behalf of
  a workload, including tunneled and WebSocket connections.

## 3. Header hygiene

Before forwarding, the proxy MUST strip hop-by-hop headers (RFC 7230 §6.1):
`Connection`, `Proxy-Connection`, `Keep-Alive`, `Proxy-Authenticate`,
`Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` — plus
every header named in any `Connection` value (comma-separated tokens).
Exceptions: `TE: trailers` is preserved when the client sent it (gRPC over
HTTP/1.1), and `Upgrade`/`Connection` survive on a WebSocket handshake
(Part 05 §5). Vectors: Appendix C §3.

hematite MUST NOT add `Via`, `X-Forwarded-For`, or any header revealing the
workload's address — the boundary is intentionally anonymous toward
upstreams.

## 4. Connection management

- Dial timeout 30 s; TLS ≥ 1.2 with certificate verification against the
  system roots (no option to disable in v1); TLS handshake timeout 10 s.
- Response header timeout `proxy.upstream_response_header_timeout`
  (default 30 s) → 502 on expiry.
- HTTP/2 to upstreams via ALPN when available; idle connection pooling
  (≈100 conns, 90 s idle) is quality-of-implementation, not conformance.

## 5. Egress proxy chaining

`proxy.http_proxy` / `https_proxy` / `no_proxy` (config keys; standard env
vars override them) route hematite's own upstream connections through a
corporate forward proxy. The guard still applies to the address actually
dialed (the chained proxy's).
