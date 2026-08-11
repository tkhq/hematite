# Part 04 — Built-in Transforms

*Depends on: Parts 00–03. Conformance: §1–§2, §4–§6 at L0; §3 at L3.*

Each section defines one transform: its config block, request/response
behavior, annotation keys, and rejection conditions. Worked config: Appendix
B. Vectors: Appendix C §2–§4.

## 1. `allowlist`

Default-deny destination filter. A config with no `allowlist` transform MUST
fail validation — default-deny is structural, not a lint (threat T1). The
transform SHOULD be first in the pipeline; validation MUST warn when it is
present but not first.

```yaml
- name: allowlist
  config:
    domains: ["api.openai.com", "*.anthropic.com"]
    cidrs: ["10.0.0.0/8"]
    warn: false
```

- Request: `Continue` if `summary.host` matches any domain glob, or is an IP
  literal inside any CIDR (Part 02). Otherwise `Reject` (403).
- Warn mode: on a would-be rejection, return `Continue` and annotate
  `warn: true`. Nothing else changes.
- Response: always `Continue`, no annotations.
- Annotation keys: `warn` (only value: `true`).
- At least one of `domains`/`cidrs` MUST be non-empty.

## 2. `annotate`

Observation-only header capture for audit enrichment. Never rejects.

```yaml
- name: annotate
  config:
    annotations:
      - rules: [{ host: "api.openai.com", methods: ["POST"], paths: ["/v1/*"] }]
        headers: ["x-request-id"]
```

- `headers` entries are literal names only (Part 02 §5). For each group whose
  rules match, each named header present on the request is recorded as
  annotation `header:<Canonical-Name>` → value. When a header appears more
  than once, the **first** occurrence in wire order is recorded.
- Captured values land in the audit log in plain text; the config docs MUST
  carry the operator warning to never annotate headers holding real secrets.
  (Proxy tokens are fine — they are worthless outside the boundary.)
- Response: `Continue`, no annotations.

## 3. `secrets` (L3)

Boundary-level credential custody: the workload sends proxy tokens; hematite
swaps in real values at egress. This is the transform INV-1 exists for.

```yaml
- name: secrets
  config:
    secrets:
      - source: { type: env, var: OPENAI_API_KEY }        # or type: file, path, ttl, failure_ttl
        proxy_value: "proxy-openai-abc123"
        match_headers: ["Authorization"]   # [] = all headers; /regex/ allowed
        match_body: false
        match_query: false
        match_path: false
        require: false
        rules: [{ host: "api.openai.com" }]
```

### 3.1 Sources

- **`env`** — read once at pipeline build from the proxy's environment.
  Missing/empty var is a build-time validation error.
- **`file`** — the exact file contents, with no trimming; the writer controls
  trailing whitespace. The file is read at pipeline build and re-read, when
  `ttl` is set, on cache expiry. `ttl` (default: cache forever) caches
  success. `failure_ttl` (default 1m) caches failure, so a broken backend
  does not stall every request and a long `ttl` never delays recovery. When a
  refresh fails after a prior success, the transform MUST serve the stale
  value and schedule a retry at `ttl/2`.
- Every source accepts an optional `json_key`: parse the resolved value as a
  JSON object and extract the named top-level string field. Anything else —
  non-JSON, a missing key, a non-string value — is a resolution failure.
- Resolution failures follow `require` (§3.3); the error text MUST name the
  source, never the value (INV-1).

### 3.2 Scan and swap

For each configured secret whose `rules` match the request, scan the opted-in
locations for occurrences of `proxy_value` and replace **every** occurrence
with the resolved secret:

- **Headers** (`match_headers`): scan values of matching headers (Part 02
  §5). Special case: a syntactically valid `Authorization: Basic <b64>` value
  is base64-decoded, swapped, and re-encoded. Wire casing of header names is
  preserved.
- **Query** (`match_query`): parse the query string, replace within values
  only, re-encode; the resolved secret is percent-encoded per RFC 3986 when
  substituted. Off by default — query strings leak into access logs.
- **Path** (`match_path`): byte-literal replace-all of `proxy_value` on the
  **raw** path; the resolved secret is percent-encoded when substituted.
  Untouched bytes are never re-encoded (Part 07 §1). When `match_path` is
  set, validation MUST require `proxy_value` to consist only of RFC 3986
  unreserved characters — this guarantees the raw-path scan cannot miss a
  percent-encoded form of the token. Off by default, for the same log-leak
  reason as query.
- **Body** (`match_body`): byte-level replace-all within the buffered body.
  Reading the body forces buffering (Part 01 §4). If the body exceeds
  `max_request_body_bytes`, the swap cannot be applied soundly; when the
  request matches this secret's `rules`, the transform MUST fail as a
  transform error (Part 01 §4 — over-cap bodies are read-only, fail closed).

### 3.3 `require`

When `require: true`, the request matched `rules`, and either **no** opted-in
location contained `proxy_value` or the source failed to resolve: return
`Reject`. This stops a compromised workload from bypassing custody with its
own credentials. When `require: false`: return `Continue` and, on a
resolution failure, annotate `secret_unavailable` (§3.4).

### 3.4 Annotations

- `swapped`: list of `{ "secret": "<source name>", "locations": ["header:Authorization", …] }`. Location kinds: `header:<Name>`, `query`, `path`, `body`.
- `secret_unavailable`: list of source names that failed to resolve (only when `require: false`).

The *source name* (env var name, file path) appears in audit; the value never
can (INV-1).

## 4. `header_allowlist`

Default-deny request-header filter.

```yaml
- name: header_allowlist
  config:
    headers: ["Authorization", "Content-Type", "User-Agent", "Accept", "/^x-trace-.*$/"]
    rules: [{ host: "api.openai.com" }]   # optional; absent = all requests
```

- The transform removes every request header whose canonical name matches no
  entry (Part 02 §5) before the request goes upstream. Hop-by-hop stripping
  (Part 07 §3) happens later, and happens whether or not this transform is
  configured.
- Never rejects. When at least one header is removed, annotate
  `stripped_headers`: sorted list of removed canonical names.
- Ordering note (documented, not enforced): place `header_allowlist` after
  `secrets` and after `annotate`, so that injected credentials survive
  filtering and `annotate` sees the original headers.

## 5. `body_capture`

Observation-only request-body recording.

```yaml
- name: body_capture
  config:
    max_request_body_bytes: 16384        # capture cap, independent of the global cap
    rules: [{ host: "api.anthropic.com", methods: ["POST"], paths: ["/v1/messages"] }]
```

- `rules` is required and MUST be non-empty: body capture is opt-in per
  destination, never global. (Unlike `header_allowlist`, an absent `rules`
  is a config validation error, not "all requests".)
- The transform's `max_request_body_bytes` is its own capture cap; it shares
  a name with the global `proxy.max_request_body_bytes` (Part 09) but is
  independent of it.
- On match, read the body (forcing buffering) up to the capture cap and
  attach it to the audit record's `body_capture` group (Part 08 §2):
  `request_body` (UTF-8 lossy) and `request_body_truncated` (bool).
- Trace annotations: `captured_bytes` (int), `truncated` (bool) — the trace
  records *that* a capture happened without duplicating the bytes.
- Never rejects; a body read error is annotated (`error` key in annotations),
  not fatal.
- Response bodies are not captured (SSE would stall; Part 10).
- Ordering note: place `body_capture` **before** any `secrets` entry that has
  `match_body: true`, so the log holds proxy tokens, not real credentials.

## 6. Ordering summary (informative)

Recommended order: `allowlist`, `annotate`, `body_capture`, `secrets`,
`header_allowlist`. Validation MUST warn when `body_capture` follows a
`secrets` entry that has `match_body: true`.
