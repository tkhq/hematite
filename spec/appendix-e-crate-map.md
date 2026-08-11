# Appendix E — Rust Crate Map (informative; the reference implementation's shape)

The workspace mirrors the conformance levels: each level is a crate boundary,
so "conforms at L0" literally means "depends only on `hematite-kernel`."

```
hematite/
  crates/
    hematite-kernel/      # L0 — Parts 01–03, 08 §2. Pure. No tokio, no I/O.
    hematite-transforms/  # L0/L3 — Part 04. Depends: kernel.
    hematite-proxy/       # L1/L2 — Parts 05, 07. hyper/tower/rustls. Depends: kernel, transforms.
    hematite-dns/         # L2 — Part 06. hickory-proto. Depends: kernel (globs).
    hematite/             # the binary — Part 09 config, wiring, management API.
  spec/                   # this document
  tests/acceptance/       # Appendix A, docker-compose harness
  spec/vectors/           # Appendix C data files; conformance runner in kernel's tests
```

## The type-enforced invariants, concretely

**INV-1 — `Secret` opacity** (`hematite-kernel::secret`):

```rust
pub struct Secret(zeroize::Zeroizing<Box<[u8]>>);
// Deliberately absent: Display, Debug*, Serialize, Clone-into-String.
// *Debug is implemented as `Secret(<redacted>)` so structs holding one stay derivable.

impl Secret {
    /// The ONLY escape hatch: consumed by the swap engine, which returns
    /// rewritten wire bytes, never the secret itself.
    pub(crate) fn expose_for_swap(&self, f: impl FnOnce(&[u8]) -> SwappedBytes) -> SwappedBytes { … }
}
```

`AuditRecord` and all annotation types are plain `serde` data containing only
`String`/numbers — a `Secret` cannot be placed in one; the program does not
compile.

**INV-2 — policy before dial** (`hematite-proxy::dial`):

```rust
/// Only the kernel can construct this (private field, non-Clone).
pub struct AllowProof { _sealed: () }

pub async fn dial_upstream(proof: AllowProof, target: Target, guard: &Guard) -> Result<Conn> { … }
```

Every code path to the network passes through `dial_upstream`; the only
source of an `AllowProof` is `PipelineOutcome::Continue`.

**INV-3 — audit totality** (`hematite-proxy::audit`):

```rust
/// Constructed at accept time; emits on Drop if not already emitted.
pub struct PendingAudit { … }   // Drop impl logs action="error" as a backstop
```

**INV-4 — kernel purity**: `hematite-kernel` has `#![forbid(unsafe_code)]`
and no async runtime, filesystem, or clock dependencies; `duration_ms` is
supplied by the caller. Secret sources enter as `dyn SecretResolver`, so
vector tests stub them:

```rust
pub trait SecretResolver: Send + Sync {
    fn resolve(&self, source: &SourceRef) -> Result<Secret, ResolveError>;
}
```

## Dependency budget (a decision, not a suggestion)

tokio, hyper, tower, rustls + rcgen (leaf minting), hickory-proto (DNS),
serde/serde_yaml, regex (RE2-class by construction), zeroize, lru,
jsonschema (dev-dependency, acceptance only). Anything beyond this list is a
spec-change-sized conversation — the boundary must stay auditable
(thesis: the boundary is more trustworthy than the workload).

### Amendment: observability stack

The following crates were added as part of the observability feature (Part 09 §5):

- **`tracing`** — structured instrumentation API; all operational log events
  and request spans are emitted through this facade. Zero-cost when no
  subscriber is installed.
- **`tracing-subscriber`** (features: `json`, `env-filter`, `fmt`, `registry`)
  — renders `tracing` events to stdout as newline-delimited JSON or compact
  text, and filters by level; the only crate that writes structured
  operational logs.
- **`tracing-opentelemetry`** — bridges `tracing` spans into the OpenTelemetry
  SDK; allows one subscriber registry to serve both the fmt layer and the OTLP
  export layer without duplicating instrumentation.
- **`opentelemetry`** (feature: `trace`) — the OpenTelemetry API crate: tracer
  interfaces and context types. The kernel crate remains dependency-free and
  does not import this.
- **`opentelemetry_sdk`** (features: `trace`, `rt-tokio`,
  `experimental_async_runtime`,
  `experimental_trace_batch_span_processor_with_async_runtime`) — the SDK
  implementation: sampler, batch span processor, and tracer provider. The
  `experimental_async_runtime` + `rt-tokio` features are required because the
  hyper HTTP client used by the OTLP exporter needs to run within a Tokio
  reactor context; the synchronous batch processor runs in a dedicated OS
  thread that has no reactor, which would prevent the exporter from making
  progress.
- **`opentelemetry-otlp`** (features: `trace`, `http-proto`, `hyper-client`;
  no `tonic`, no gRPC) — the OTLP exporter over HTTP/protobuf. Uses hyper
  directly (the same stack as the proxy's own HTTP client). `reqwest` is
  explicitly absent from the normal dependency graph; it appears only
  transitively through the pre-existing `jsonschema` dev-dependency.
- **`opentelemetry-http`** (feature: `hyper`) — adapts hyper as the HTTP
  client for `opentelemetry-otlp`.
- **`prost`** — protobuf encoding/decoding, pulled in transitively by
  `opentelemetry-otlp`'s `http-proto` feature. Not a direct production
  dependency; direct dev-dependency of `crates/hematite` for OTLP integration
  test decoding.
- **`opentelemetry-proto`** — dev-dependency only; used in OTLP integration
  tests to decode exported protobuf payloads and assert span attributes.

No `tonic` (gRPC not used). No `reqwest` in the production dependency graph.
