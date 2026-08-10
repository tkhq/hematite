# Part 03 — Pipeline

*Depends on: Parts 00–02. Conformance: L0.*

## 1. Structure

A pipeline is the ordered list of transforms named in `transforms:` in the
config, in file order. Order is semantic and operator-controlled; hematite
MUST NOT reorder transforms. The pipeline is immutable once built. Reload
(Part 09 §4) builds a new pipeline and swaps it atomically. A single pipeline
instance MUST process each request start-to-finish — never half-old,
half-new (threat T9).

## 2. Transform contract

Each transform implements two operations:

```
transform_request(ctx, request)  → verdict
transform_response(ctx, request, response) → verdict
```

- Transforms run sequentially, in order, on the request path; then — after
  the upstream responds — in the **same** order on the response path.
- Transforms share one mutable request: header, path, query, and body edits
  made by transform *n* are visible to transform *n+1* and to the dialer.
- After each transform returns, the body is rewound (Part 01 §4).
- A transform that does not match the request MUST return `Continue` with no
  trace annotations beyond what its part specifies.

## 3. Short-circuit and errors

- `Reject` or `Stub` stops the pipeline immediately; later transforms MUST
  NOT run. The stopping transform's trace is the last trace.
- A transform error (I/O failure, malformed internal state) stops the
  pipeline; the proxy MUST return HTTP 502, record trace `verdict: "error"`
  with the error message, and set audit action `error`. Errors MUST NOT fail
  open.
- Response-path `Reject`/`Stub` replaces the upstream response with the
  transform-supplied one (or an empty 403 for a bare `Reject`).

## 4. Annotations

A transform annotates through the context (`ctx.annotate(key, value)`).
Annotations are drained into that transform's trace when the transform
returns; other transforms cannot see them. Keys are flat strings, namespaced
by convention (`swapped`, `stripped_headers`, …). Each transform's part
enumerates its keys exhaustively, and an implementation MUST NOT invent
additional keys. Operators can therefore rely on a closed vocabulary when
querying records (Part 08 §2).

## 5. Registry and extension seam

v1 defines exactly five transforms (Part 04): `allowlist`, `secrets`,
`header_allowlist`, `annotate`, `body_capture`. A config naming any other
transform MUST fail validation. Future extensions (judge, MCP — Part 10)
enter as new registry entries with their own parts. The transform contract in
this part is that seam, and it is expected to remain stable.

## 6. Determinism (INV-4)

Given the same built pipeline and the same `RequestSummary`, evaluation MUST
produce identical verdicts, identical traces (excluding `duration_ms`), and
an identically rewritten request. Transforms with request-time I/O (`secrets`
with a `file` source) are deterministic relative to the resolver's returned
value; Appendix C vectors stub the resolver.
