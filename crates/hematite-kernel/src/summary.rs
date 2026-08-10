//! Part 01 §1 — `RequestSummary`, the kernel's input, and the buffered body.

use serde::{Deserialize, Serialize};

/// How the request reached the proxy (Part 01 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Http,
    Https,
    Tunnel,
}

/// Ordered header multimap. Preserves wire order and original casing of
/// names (Part 01 §1); lookups compare canonical lowercase names.
#[derive(Debug, Clone, Default)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    pub fn new(pairs: Vec<(String, String)>) -> Self {
        Headers(pairs)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// First value whose name equals `name` case-insensitively.
    pub fn first(&self, name: &str) -> Option<&str> {
        let want = name.to_ascii_lowercase();
        self.0
            .iter()
            .find(|(n, _)| n.to_ascii_lowercase() == want)
            .map(|(_, v)| v.as_str())
    }

    /// In-place value rewrite; wire casing of names is preserved.
    pub fn map_values(&mut self, mut f: impl FnMut(&str, &str) -> Option<String>) {
        for (n, v) in &mut self.0 {
            if let Some(new) = f(n, v) {
                *v = new;
            }
        }
    }

    /// Keep only headers for which `keep` returns true; returns the
    /// canonical names of the removed headers in wire order.
    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) -> Vec<String> {
        let mut removed = Vec::new();
        self.0.retain(|(n, _)| {
            if keep(n) {
                true
            } else {
                removed.push(crate::matcher::canonical_name(n));
                false
            }
        });
        removed
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Part 01 §4 — the buffered body, as the kernel sees it.
///
/// The kernel receives bytes already buffered by the listener up to the
/// configured cap. `over_cap: true` means the original stream exceeded the
/// cap: transforms observe the truncated prefix and the body is read-only —
/// a rewrite attempt is a transform error (fail closed).
#[derive(Debug, Clone, Default)]
pub struct Body {
    bytes: Vec<u8>,
    over_cap: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverCapError;

impl Body {
    pub fn new(bytes: Vec<u8>, over_cap: bool) -> Self {
        Body { bytes, over_cap }
    }

    /// Reading always starts at offset 0 (the pipeline rewinds after each
    /// transform, Part 01 §4).
    pub fn read(&self) -> &[u8] {
        &self.bytes
    }

    pub fn over_cap(&self) -> bool {
        self.over_cap
    }

    /// Replace the buffered bytes. Fails on an over-cap body (Part 01 §4:
    /// over-cap bodies are read-only).
    pub fn replace(&mut self, bytes: Vec<u8>) -> Result<(), OverCapError> {
        if self.over_cap {
            return Err(OverCapError);
        }
        self.bytes = bytes;
        Ok(())
    }
}

/// Part 01 §1 — the pure-data description of a request.
///
/// Transforms mutate this value in place (Part 03 §2); the dialer forwards
/// the possibly-rewritten fields (Part 07 §1).
#[derive(Debug, Clone)]
pub struct RequestSummary {
    pub mode: Mode,
    /// Uppercase HTTP method; `CONNECT` for synthetic tunnel requests.
    pub method: String,
    /// Hostname only, lowercase, no port. Non-empty (Part 05 §1).
    pub host: String,
    pub port: u16,
    /// Raw (still percent-encoded) path. Empty for synthetic CONNECT.
    pub path: String,
    /// Raw query string, no leading `?`.
    pub query: String,
    pub headers: Headers,
    pub body: Body,
    /// TLS SNI when `mode` is not `http`.
    pub sni: Option<String>,
    /// The workload's socket address, when known.
    pub remote_addr: Option<String>,
}
