//! Part 04 §3.1 — the concrete secret sources: `env` (the proxy's
//! environment) and `file`. The kernel resolves through this at pipeline
//! build time (Part 01 §5); it is the only I/O the L3 policy path performs.
//!
//! TTL/failure-TTL caching (Part 04 §3.1) is a runtime refinement layered
//! above build-time resolution and is not yet implemented; env and file are
//! read once at build. This is flagged as a known gap.

use hematite_kernel::secret::{ResolveError, Secret, SecretResolver, SourceKind, SourceRef};

/// Resolves `env` from the process environment and `file` from disk.
pub struct EnvFileResolver;

impl EnvFileResolver {
    fn apply_json_key(
        value: Vec<u8>,
        source: &SourceRef,
    ) -> Result<Secret, ResolveError> {
        match &source.json_key {
            None => Ok(Secret::new(value)),
            Some(key) => {
                let parsed: serde_json::Value = serde_json::from_slice(&value).map_err(|_| {
                    ResolveError { source: source.clone(), reason: "value is not JSON".into() }
                })?;
                match parsed.get(key).and_then(|v| v.as_str()) {
                    Some(s) => Ok(Secret::new(s.as_bytes().to_vec())),
                    None => Err(ResolveError {
                        source: source.clone(),
                        reason: format!("json_key {key:?} missing or not a string"),
                    }),
                }
            }
        }
    }
}

impl SecretResolver for EnvFileResolver {
    fn resolve(&self, source: &SourceRef) -> Result<Secret, ResolveError> {
        match &source.kind {
            SourceKind::Env { var } => match std::env::var(var) {
                Ok(v) if !v.is_empty() => Self::apply_json_key(v.into_bytes(), source),
                _ => Err(ResolveError {
                    source: source.clone(),
                    reason: "env var unset or empty".into(),
                }),
            },
            SourceKind::File { path } => match std::fs::read(path) {
                // Exact file contents, no trimming (Part 04 §3.1).
                Ok(bytes) => Self::apply_json_key(bytes, source),
                Err(e) => Err(ResolveError {
                    source: source.clone(),
                    reason: format!("cannot read file: {e}"),
                }),
            },
        }
    }
}
