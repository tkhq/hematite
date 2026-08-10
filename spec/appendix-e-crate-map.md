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
