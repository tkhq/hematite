//! Part 04 §3.1 — the concrete secret sources: `env` (the proxy's
//! environment) and `file`. The kernel's secrets transform resolves through
//! this at request time (Part 01 §5); it is the only I/O the L3 policy path
//! performs, and it caches with per-source TTLs so a file secret can rotate
//! without a reload.
//!
//! Caching rules (Part 04 §3.1):
//! - success is cached for `ttl` (default: forever); env is always forever.
//! - failure is cached for `failure_ttl` (default 1m) so a broken backend
//!   does not stall every request.
//! - on a refresh failure after a prior success, the stale value is served
//!   and a retry is scheduled at `ttl/2`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hematite_kernel::secret::{ResolveError, Secret, SecretResolver, SourceKind, SourceRef};
use zeroize::Zeroizing;

const DEFAULT_FAILURE_TTL: Duration = Duration::from_secs(60);

/// A monotonic clock in milliseconds, injectable for tests.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// The real clock: milliseconds since resolver construction.
pub struct MonotonicClock(Instant);

impl Default for MonotonicClock {
    fn default() -> Self {
        MonotonicClock(Instant::now())
    }
}

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}

/// The cache key: the full identity of a source, not just its name. Two
/// secrets reading different `json_key`s from one file are different
/// secrets; keying on the path alone would serve one secret's value for
/// the other. The kind tag keeps an env var distinct from a file path
/// that spells the same string.
fn cache_key(source: &SourceRef) -> String {
    let base = match &source.kind {
        SourceKind::Env { var } => format!("env:{var}"),
        SourceKind::File { path } => format!("file:{path}"),
    };
    match &source.json_key {
        Some(key) => format!("{base}\u{0}{key}"),
        None => base,
    }
}

/// One cache entry per source identity (`cache_key`).
struct Entry {
    /// The last successfully resolved value, if any (kept for stale-serve).
    /// Zeroized on drop so a rotated-out credential does not linger in the
    /// cache's freed heap (mirrors `Secret`'s own `Zeroizing`).
    value: Option<Zeroizing<Vec<u8>>>,
    /// When the current cached state was recorded (ms).
    stamp: u64,
    /// True if the last resolution succeeded.
    ok: bool,
}

/// Resolves `env` from the process environment and `file` from disk, with
/// per-source TTL caching.
pub struct EnvFileResolver {
    cache: Mutex<HashMap<String, Entry>>,
    clock: Box<dyn Clock>,
}

impl Default for EnvFileResolver {
    fn default() -> Self {
        EnvFileResolver {
            cache: Mutex::new(HashMap::new()),
            clock: Box::new(MonotonicClock::default()),
        }
    }
}

impl EnvFileResolver {
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        EnvFileResolver {
            cache: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Read the raw source value (no caching), applying `json_key`. The
    /// result is zeroized on drop; intermediate plaintext buffers are too.
    fn read(source: &SourceRef) -> Result<Zeroizing<Vec<u8>>, ResolveError> {
        let raw = Zeroizing::new(match &source.kind {
            SourceKind::Env { var } => match std::env::var(var) {
                Ok(v) if !v.is_empty() => Zeroizing::new(v).as_bytes().to_vec(),
                _ => {
                    return Err(ResolveError {
                        source: source.clone(),
                        reason: "env var unset or empty".into(),
                    })
                }
            },
            SourceKind::File { path } => std::fs::read(path).map_err(|e| ResolveError {
                source: source.clone(),
                reason: format!("cannot read file: {e}"),
            })?,
        });
        apply_json_key(raw, source)
    }
}

fn apply_json_key(
    value: Zeroizing<Vec<u8>>,
    source: &SourceRef,
) -> Result<Zeroizing<Vec<u8>>, ResolveError> {
    match &source.json_key {
        None => Ok(value),
        Some(key) => {
            let parsed: serde_json::Value =
                serde_json::from_slice(&value).map_err(|_| ResolveError {
                    source: source.clone(),
                    reason: "value is not JSON".into(),
                })?;
            match parsed.get(key).and_then(|v| v.as_str()) {
                Some(s) => Ok(Zeroizing::new(s.as_bytes().to_vec())),
                None => Err(ResolveError {
                    source: source.clone(),
                    reason: format!("json_key {key:?} missing or not a string"),
                }),
            }
        }
    }
}

impl SecretResolver for EnvFileResolver {
    fn resolve(&self, source: &SourceRef) -> Result<Secret, ResolveError> {
        let now = self.clock.now_ms();
        let name = cache_key(source);
        let ttl_ms = source.ttl.map(|d| d.as_millis() as u64);
        let failure_ttl_ms = source
            .failure_ttl
            .unwrap_or(DEFAULT_FAILURE_TTL)
            .as_millis() as u64;

        let mut cache = self.cache.lock().expect("resolver cache");
        if let Some(entry) = cache.get(&name) {
            if entry.ok {
                let fresh = ttl_ms.is_none_or(|ttl| now.saturating_sub(entry.stamp) < ttl);
                if fresh {
                    return Ok(Secret::new(
                        entry.value.clone().unwrap_or_default().to_vec(),
                    ));
                }
                // Expired: attempt a refresh.
                match Self::read(source) {
                    Ok(bytes) => {
                        cache.insert(
                            name,
                            Entry {
                                value: Some(bytes.clone()),
                                stamp: now,
                                ok: true,
                            },
                        );
                        return Ok(Secret::new(bytes.to_vec()));
                    }
                    Err(_) => {
                        // Refresh failed after a prior success: serve the
                        // stale value and schedule the next retry at ttl/2.
                        let stale = entry.value.clone().unwrap_or_default();
                        let retry_stamp =
                            ttl_ms.map(|ttl| now.saturating_sub(ttl / 2)).unwrap_or(now);
                        cache.insert(
                            name,
                            Entry {
                                value: Some(stale.clone()),
                                stamp: retry_stamp,
                                ok: true,
                            },
                        );
                        return Ok(Secret::new(stale.to_vec()));
                    }
                }
            } else {
                // Cached failure: hold it until failure_ttl elapses.
                if now.saturating_sub(entry.stamp) < failure_ttl_ms {
                    return Err(ResolveError {
                        source: source.clone(),
                        reason: "cached failure".into(),
                    });
                }
            }
        }

        // No entry, or a failure cache that has expired: read fresh.
        match Self::read(source) {
            Ok(bytes) => {
                cache.insert(
                    name,
                    Entry {
                        value: Some(bytes.clone()),
                        stamp: now,
                        ok: true,
                    },
                );
                Ok(Secret::new(bytes.to_vec()))
            }
            Err(e) => {
                cache.insert(
                    name,
                    Entry {
                        value: None,
                        stamp: now,
                        ok: false,
                    },
                );
                Err(e)
            }
        }
    }
}
