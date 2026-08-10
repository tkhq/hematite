# Appendix C — Test Vectors (normative)

Two independent implementations MUST agree on every row. Vectors live as data
files under `spec/vectors/` (JSON) consumed by the conformance runner; this
appendix is their human-readable form. A spec without test vectors is a
suggestion.

## §1 Matching (Part 02) — L0

Domain globs (`pattern`, `host` → `match?`):

| pattern | host | match |
|---|---|---|
| `example.com` | `example.com` | ✅ |
| `example.com` | `a.example.com` | ❌ |
| `*.example.com` | `example.com` | ✅ |
| `*.example.com` | `a.example.com` | ✅ |
| `*.example.com` | `a.b.example.com` | ✅ |
| `*.example.com` | `notexample.com` | ❌ |
| `*.example.com` | `example.com.evil.io` | ❌ |
| `*.EXAMPLE.com` | `foo.example.COM` | ✅ |
| `ex*.com` | (config load) | reject: `*` not leading label |

CIDRs (`cidr`, `host` → `match?`):

| cidr | host | match |
|---|---|---|
| `10.0.0.0/8` | `10.1.2.3` | ✅ |
| `10.0.0.0/8` | `11.0.0.1` | ❌ |
| `10.0.0.0/8` | `internal.corp` | ❌ (hostnames never match CIDRs) |
| `169.254.169.254/32` | `169.254.169.254` | ✅ |
| `10.0.0.1` (no prefix) | (config load) | reject |

Path globs:

| pattern | path | match |
|---|---|---|
| `/v1/*` | `/v1/messages` | ✅ |
| `/v1/*` | `/v1/a/b` | ✅ (`*` crosses `/`) |
| `/v1/*` | `/v2/messages` | ❌ |
| `/v1/messages` | `/v1/Messages` | ❌ (case-sensitive) |
| `/bot*/send` | `/bot123/send` | ✅ |

Header-name entries:

| entry | request header | match |
|---|---|---|
| `Authorization` | `authorization` | ✅ (forwarded casing preserved) |
| `/^x-.*-key$/` | `X-Api-Key` | ✅ |
| `/^x-.*-key$/` | `X-Api-Keys` | ❌ |

## §2 Secrets swap (Part 04 §3) — L3

Resolver stubbed: `OPENAI_API_KEY → "sk-real"`. Proxy value
`proxy-tok`.

| # | input location | input value | output |
|---|---|---|---|
| 1 | `Authorization` header, `match_headers: ["Authorization"]` | `Bearer proxy-tok` | `Bearer sk-real`; `swapped: [{secret: "OPENAI_API_KEY", locations: ["header:Authorization"]}]` |
| 2 | `Authorization` header | `Basic cHJveHktdG9rOng=` (`proxy-tok:x`) | `Basic c2stcmVhbDp4` (`sk-real:x`) — decoded, swapped, re-encoded |
| 3 | two headers via `match_headers: []` | `X-A: proxy-tok`, `X-B: say-proxy-tok-twice-proxy-tok` | both swapped, all occurrences; locations `["header:X-A","header:X-B"]` |
| 4 | query, `match_query: true` | `?token=proxy-tok&q=hi` | `?token=sk-real&q=hi`; location `query` |
| 5 | path, `match_path: true` | `/botproxy-tok/send` | `/botsk-real/send`; location `path` |
| 6 | body, `match_body: true` | `{"key":"proxy-tok"}` | `{"key":"sk-real"}`; location `body`; Content-Length recomputed |
| 7 | `require: true`, token absent | any matching request | verdict `Reject`; trace `verdict: reject` |
| 8 | `require: false`, resolver fails | any matching request | `Continue`; `secret_unavailable: ["OPENAI_API_KEY"]`; no value in any field |

## §3 Hop-by-hop stripping (Part 07 §3) — L1

Input headers → forwarded headers:

| input | forwarded |
|---|---|
| `Connection: keep-alive` | (removed) |
| `Connection: close, X-Custom` + `X-Custom: 1` | both removed |
| `TE: trailers` | kept |
| `TE: gzip, trailers` | `TE: trailers` only |
| `Transfer-Encoding: chunked` | removed (framing re-derived) |
| `Proxy-Authorization: Basic …` | removed |
| `Upgrade: websocket` + valid handshake | kept (WebSocket path) |

## §4 Decision traces (Parts 01/03/08) — reject vector at L0; full-pipeline vector at L3

Vector records are compared **after removing `duration_ms` fields** (the one
nondeterministic datum, INV-4); the normative JSON Schema applies to complete
live records (Appendix A step 10), not to these stripped forms. Record
fields outside the traces (`status_code`, `sni`, `mode`) are filled by the
conformance harness from the summary and the outcome (403 for a pipeline
reject, Part 01 §2) — the kernel itself produces the verdict and traces.

Full-pipeline vector (L3 — uses `secrets`): the Appendix B config (resolver
stubbed), summary `GET https://httpbin.org/headers` with `Authorization:
Bearer proxy-openai-abc123`, must produce byte-for-byte:

```json
{
  "host": "httpbin.org",
  "method": "GET",
  "path": "/headers",
  "mode": "https",
  "sni": "httpbin.org",
  "action": "allow",
  "request_transforms": [
    { "name": "allowlist", "verdict": "continue" },
    { "name": "annotate", "verdict": "continue" },
    { "name": "body_capture", "verdict": "continue" },
    { "name": "secrets", "verdict": "continue",
      "annotations": { "swapped": [ { "secret": "OPENAI_API_KEY",
                                      "locations": ["header:Authorization"] } ] } },
    { "name": "header_allowlist", "verdict": "continue" }
  ],
  "response_transforms": []
}
```

And the negative half: serializing every structure above with the real secret
resolved MUST NOT contain the byte string `sk-real` anywhere. (In the
reference implementation this is unrepresentable — INV-1 — but the vector
keeps other implementations honest.)

Rejection vector (L0): same config with the `secrets` transform removed,
`GET https://example.com/` →

```json
{ "host": "example.com", "method": "GET", "path": "/", "mode": "https",
  "sni": "example.com", "action": "reject", "rejected_by": "allowlist",
  "status_code": 403,
  "request_transforms": [ { "name": "allowlist", "verdict": "reject" } ],
  "response_transforms": [] }
```
