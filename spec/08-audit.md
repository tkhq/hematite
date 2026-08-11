# Part 08 — Audit Log

*Depends on: Parts 00–03. Conformance: schema (§2) at L0; emission at L1.*

The audit log is the product's second output. Design rule: **an operator must
be able to reconstruct every policy decision from the record alone** — which
transforms ran, in what order, what each decided, and why.

## 1. Emission

- Exactly one record per request (INV-3), emitted when the request completes,
  fails, or is cancelled. Tunnel handshakes that die before any inner request
  emit one record for the handshake itself.
- Transport: one JSON object per line on stderr, alongside (not interleaved
  with) operational logs.
- Levels: `allow`, `stub`, `client_cancel` → INFO; `reject` → WARN; `error`
  → ERROR.

## 2. Record schema

```json
{
  "host": "httpbin.org",
  "method": "GET",
  "path": "/headers",
  "remote_addr": "172.20.0.4:49152",
  "sni": "httpbin.org",
  "mode": "https",
  "action": "allow",
  "status_code": 200,
  "duration_ms": 142.3,
  "rejected_by": "allowlist",
  "stubbed_by": "…",
  "error": "…",
  "request_transforms": [ { "name": "...", "verdict": "...", "duration_ms": 0.0, "annotations": {} } ],
  "response_transforms": [ ],
  "tunnel": { "target": "httpbin.org:443", "request_transforms": [ ] },
  "guard": { "denied_addr": "169.254.169.254", "prefix": "169.254.169.254/32" },
  "body_capture": { "request_body": "…", "request_body_truncated": false }
}
```

Field rules:

- `action` ∈ `allow` | `reject` | `stub` | `error` | `client_cancel`.
- `rejected_by` / `stubbed_by` / `error`: present only for the matching
  action. `rejected_by` names the rejecting transform, or `"listener"` for
  pre-pipeline rejections (400s, SNI-less closes — status code as observed),
  or `"guard"` for deny-CIDR dial denials (status 502, with the `guard`
  group; Part 07 §2). All rejections log at WARN.
- `host` is the empty string only when the failure precedes host extraction
  (`rejected_by: "listener"`); it is non-empty everywhere else.
- `sni` present only on TLS legs; `tunnel` only for in-tunnel requests
  (holding the handshake's traces); `guard` only on guard denials;
  `body_capture` only when captured.
- Traces are Part 01 §3 objects, in execution order, request and response
  paths separately.
- Optional fields are omitted, not null. Unknown fields MUST NOT appear —
  the published JSON Schema (`spec/schema/audit-record.schema.json`, with
  `additionalProperties: false`) is normative and the acceptance test
  validates against it.

## 3. Secret safety

No record field may contain a resolved secret value (INV-1). Secrets are
referred to only by source name. This is compile-time-enforced in the
reference implementation (Appendix E) and behaviorally checked by Appendix C
§4 and acceptance step 10.

## 4. Export

OTEL export is out of scope for v1 (Part 10). The one-line-JSON format is the
stable interface; exporters are downstream consumers of it.

## 5. Telemetry redaction rule

Anything not permitted in an audit record is not permitted in a span
attribute, metric label, or log field. Concretely: resolved secret values
MUST NOT appear in OTLP span attributes, Prometheus metric labels, or
structured log fields, for the same reason they must not appear in audit
records (§3). The `Secret` type's absence of `Display`, `Serialize`, and
`Clone`-into-`String` enforces this at compile time in the reference
implementation (Appendix E), exactly as it does for audit records today.
See Part 09 §5 for the operational telemetry layer that this rule governs.
