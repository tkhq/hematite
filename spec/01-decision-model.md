# Part 01 — Decision Model

*Depends on: Part 00. Conformance: L0.*

The policy kernel is a pure function. This part defines the kernel's input,
output, and intermediate types. These types are the complete universe a
transform can observe or produce: if a datum is not in them, a transform
cannot depend on it.

## 1. RequestSummary (kernel input)

The kernel never sees sockets. Listeners (Part 05) reduce every client
interaction to a `RequestSummary`:

| Field | Type | Notes |
|-------|------|-------|
| `mode` | enum `http` \| `https` \| `tunnel` | How the request reached the proxy. Requests inside a tunnel keep `tunnel` (Part 05 §4.3). |
| `method` | string | Uppercase HTTP method. `CONNECT` for synthetic tunnel requests. |
| `host` | string | Hostname only, lowercase, no port. MUST be non-empty (Part 05 §1). |
| `port` | u16 | Effective destination port. |
| `path` | string | Raw (still percent-encoded) path. Empty for synthetic CONNECT. |
| `query` | string | Raw query string, no leading `?`. |
| `headers` | ordered multimap | Preserves wire order and original casing of names. |
| `body` | buffered body handle | See §4. |
| `sni` | optional string | TLS SNI when `mode` ≠ `http`. |
| `remote_addr` | IP:port | The workload's socket address. |

Rules match against the **raw** path. To keep raw-path matching sound,
listeners MUST reject (HTTP 400) any request whose path contains a `.` or
`..` segment, before the kernel runs. The check runs on the
**percent-decoded** segments, so `/%2e%2e/` is rejected too (threat T6,
Appendix D). Matching itself always uses the raw path.

## 2. Verdict

Every transform invocation returns exactly one verdict:

- **`Continue`** — pass the (possibly rewritten) request to the next transform, or to the dialer if last.
- **`Reject`** — stop the pipeline. For a pipeline rejection the proxy MUST return HTTP 403 with an empty body, unless the transform supplies a response. Audit action `reject`, WARN level. Non-pipeline rejections (listener 400s, guard dial denials) reuse audit action `reject` with their own status codes; see Parts 05 §6 and 07 §2.
- **`Stub`** — stop the pipeline and return the transform-supplied response *as if it were the upstream's*. Audit action `stub`, INFO level. `Stub` exists so intentional proxy-served responses are distinguishable from denials.

There is no `Allow` verdict at the transform level: allowing is the absence of
rejection at the end of the pipeline. There is also no verdict that skips
later transforms without terminating — ordering is total (Part 03).

`warn` is not a verdict. A transform in warn mode returns `Continue` and
annotates `warn: true` in its trace (Part 04 §1).

## 3. Trace

One trace per transform invocation, in execution order:

```json
{
  "name": "allowlist",
  "verdict": "continue",        // "continue" | "reject" | "stub" | "error"
  "duration_ms": 0.041,
  "error": "…",                 // present only when verdict = "error"
  "annotations": { }            // omitted when empty
}
```

The trace field is named `verdict` — `action` is reserved for the
whole-request outcome (Part 00 §3). `error` is not a verdict a transform
returns; it records that the transform failed (Part 03 §3).

Annotation values MUST be JSON-serializable scalars, arrays, or objects.
Annotations MUST NOT contain a secret value (INV-1); the type system makes a
secret-bearing annotation unrepresentable, and the vectors in Appendix C §4
check the same property behaviorally. Traces from a tunnel handshake are
recorded separately from traces of requests inside the tunnel (Part 08 §2).
Each in-tunnel request gets an independent copy of the tunnel's annotations,
so sibling requests cannot observe each other's state.

## 4. Buffered body

Bodies are streamed by default and buffered only on demand:

- If no transform reads the body, the proxy MUST forward the original byte
  stream unmodified (zero-copy path), preserving the client's framing
  (`Content-Length` or chunked).
- The first read by any transform MUST buffer the entire body eagerly, up to
  `max_request_body_bytes` (response side: `max_response_body_bytes`).
- After each transform runs, the body MUST be rewound to offset 0 so the next
  transform reads from the start.
- A body that fits the cap and was buffered (or replaced) by a transform is
  forwarded as the buffered bytes with an exact `Content-Length`. This
  converts chunked framing to fixed-length framing.
- A body that **exceeds** the cap is read-only: transforms observe the
  truncated prefix, but the proxy MUST forward the original byte stream with
  the client's framing. A transform that attempts to modify an over-cap body
  MUST fail the pipeline as a transform error (fail closed — Part 03 §3,
  Part 04 §3.2). The proxy MUST NOT forward a half-rewritten body.

## 5. Kernel signature

Conceptually (Rust binding in Appendix E):

```
evaluate(pipeline, summary) → PipelineOutcome
PipelineOutcome = { verdict: Continue(proof) | Reject{by, response?} | Stub{by, response},
                    traces: [Trace] }
```

`Continue(proof)` carries the value the dialer consumes (INV-2). The kernel
performs no I/O. A transform that needs I/O at request time (secret sources,
Part 04 §3) performs it through a resolver interface injected at pipeline
build time; the resolver's behavior is specified so that vectors can stub it.
