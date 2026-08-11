//! Part 00 §5 INV-1 — the `Secret` type, and the resolver seam (Part 01 §5).
//!
//! `Secret` deliberately implements neither `Display` nor `Serialize`, is
//! not `Clone`, and its `Debug` is value-free. A program that formats a
//! secret into a log line or audit record does not compile.

use std::fmt;
use zeroize::Zeroizing;

/// An opaque secret value. Constructible from bytes; observable only by the
/// swap engine via `expose_for_swap`.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(Zeroizing::new(bytes))
    }

    /// The ONLY escape hatch (INV-1): consumed by the swap engine, which
    /// returns rewritten wire bytes, never the secret itself.
    #[allow(dead_code)] // used by the secrets transform (Part 04 §3, L3)
    pub(crate) fn expose_for_swap<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0)
    }
}

impl fmt::Debug for Secret {
    // Value-free so structs holding a Secret stay derivable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Where a secret comes from (Part 04 §3.1). The `name` — env var or file
/// path — is the only form in which a secret is ever referred to in traces,
/// errors, or audit records (Part 04 §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    Env { var: String },
    File { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    pub kind: SourceKind,
    /// Optional: parse the resolved value as JSON and take this top-level
    /// string field (Part 04 §3.1).
    pub json_key: Option<String>,
    /// Success cache lifetime (Part 04 §3.1). `None` = cache forever. The
    /// kernel carries this as a value; the resolver enforces it.
    pub ttl: Option<std::time::Duration>,
    /// Failure cache lifetime. `None` = the resolver's default (1m).
    pub failure_ttl: Option<std::time::Duration>,
}

impl SourceRef {
    /// The audit-safe name of the source.
    pub fn name(&self) -> &str {
        match &self.kind {
            SourceKind::Env { var } => var,
            SourceKind::File { path } => path,
        }
    }
}

/// A resolution failure. Carries the source name and a reason — never the
/// value (INV-1).
#[derive(Debug, Clone)]
pub struct ResolveError {
    pub source: SourceRef,
    pub reason: String,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "secret source {:?} failed to resolve: {}",
            self.source.name(),
            self.reason
        )
    }
}

/// Part 01 §5 — request-time I/O enters the kernel only through this
/// interface, injected at pipeline build time so vectors can stub it.
pub trait SecretResolver: Send + Sync {
    fn resolve(&self, source: &SourceRef) -> Result<Secret, ResolveError>;
}
