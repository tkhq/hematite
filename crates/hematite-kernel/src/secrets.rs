//! Part 04 §3 — the `secrets` transform (L3): boundary-level credential
//! custody. The workload sends proxy tokens; hematite swaps in real values
//! at egress. This is the transform INV-1 exists for.
//!
//! Vectors: Appendix C §2 (`spec/vectors/secrets-swap.json`) and the
//! full-pipeline vector in Appendix C §4.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::codec::{base64_decode, base64_encode, percent_encode, replace_all};
use crate::matcher::{any_rule_matches, canonical_name, HeaderNameEntry, Rule};
use crate::pipeline::{Ctx, Transform, TransformError};
use crate::secret::{SecretResolver, SourceRef};
use crate::summary::RequestSummary;
use crate::verdict::Verdict;

/// One configured secret. Resolution happens at request time through the
/// injected resolver (Part 01 §5, Appendix E), so a file source with a TTL
/// can refresh without rebuilding the pipeline (Part 04 §3.1).
struct ConfiguredSecret {
    source: SourceRef,
    source_name: String,
    proxy_value: Vec<u8>,
    /// `None` = scan all headers (`match_headers: []`).
    match_headers: Option<Vec<HeaderNameEntry>>,
    match_query: bool,
    match_path: bool,
    match_body: bool,
    require: bool,
    rules: Vec<Rule>,
}

pub struct Secrets {
    secrets: Vec<ConfiguredSecret>,
    resolver: Arc<dyn SecretResolver>,
}

/// The build-time spec of one secret (parsed from config, before
/// resolution). `crate::config` constructs these from JSON.
pub struct SecretSpec {
    pub source: SourceRef,
    pub proxy_value: String,
    pub match_headers: Option<Vec<HeaderNameEntry>>,
    pub match_query: bool,
    pub match_path: bool,
    pub match_body: bool,
    pub require: bool,
    pub rules: Vec<Rule>,
}

impl Secrets {
    /// Build the transform, holding the resolver for request-time
    /// resolution. The resolver caches and refreshes per source TTL
    /// (Part 04 §3.1); the kernel stays clock-free (INV-4 holds relative to
    /// the resolver's returned value, Part 03 §6).
    pub fn build(specs: Vec<SecretSpec>, resolver: Arc<dyn SecretResolver>) -> Self {
        let secrets = specs
            .into_iter()
            .map(|s| ConfiguredSecret {
                source_name: s.source.name().to_string(),
                source: s.source,
                proxy_value: s.proxy_value.into_bytes(),
                match_headers: s.match_headers,
                match_query: s.match_query,
                match_path: s.match_path,
                match_body: s.match_body,
                require: s.require,
                rules: s.rules,
            })
            .collect();
        Secrets { secrets, resolver }
    }
}

/// The result of scanning one secret's opted-in locations.
struct ScanResult {
    locations: Vec<String>,
}

impl Transform for Secrets {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn on_request(
        &self,
        ctx: &mut Ctx,
        req: &mut RequestSummary,
    ) -> Result<Verdict, TransformError> {
        let mut swapped: Vec<Value> = Vec::new();
        let mut unavailable: Vec<String> = Vec::new();

        for secret in &self.secrets {
            if !any_rule_matches(&secret.rules, &req.host, &req.method, &req.path) {
                continue;
            }

            // Resolve at request time through the resolver's cache.
            let resolved = match self.resolver.resolve(&secret.source) {
                Ok(s) => s,
                Err(_) => {
                    // Part 04 §3.3: require + unavailable → Reject.
                    if secret.require {
                        return Ok(Verdict::Reject(None));
                    }
                    unavailable.push(secret.source_name.clone());
                    continue;
                }
            };
            let resolved = &resolved;

            // Over-cap body cannot be rewritten soundly (Part 01 §4).
            if secret.match_body && req.body.over_cap() {
                return Err(TransformError(format!(
                    "secret {:?}: cannot swap in an over-cap body",
                    secret.source_name
                )));
            }

            // The secret's bytes never leave this closure (INV-1).
            let scan = resolved.expose_for_swap(|secret_bytes| {
                scan_and_swap(req, secret, secret_bytes)
            });

            // Part 04 §3.3: require + rules matched but nothing swapped
            // (the proxy token was absent) → Reject.
            if secret.require && scan.locations.is_empty() {
                return Ok(Verdict::Reject(None));
            }
            if !scan.locations.is_empty() {
                swapped.push(json!({
                    "secret": secret.source_name,
                    "locations": scan.locations,
                }));
            }
        }

        if !swapped.is_empty() {
            ctx.annotate("swapped", Value::Array(swapped));
        }
        if !unavailable.is_empty() {
            ctx.annotate("secret_unavailable", json!(unavailable));
        }
        Ok(Verdict::Continue)
    }
}

/// Scan every opted-in location of one secret and swap in place. Returns
/// the ordered list of locations where at least one occurrence was
/// replaced (`header:<Name>`, `query`, `path`, `body`).
fn scan_and_swap(
    req: &mut RequestSummary,
    secret: &ConfiguredSecret,
    secret_bytes: &[u8],
) -> ScanResult {
    let proxy = &secret.proxy_value;
    let mut locations = Vec::new();

    // Headers. `match_headers: []`/absent scans all; a populated list
    // scans only matching names (Part 02 §5). Wire casing is preserved.
    req.headers.map_values(|name, value| {
        let selected = match &secret.match_headers {
            None => true,
            Some(entries) => entries.iter().any(|e| e.matches(name)),
        };
        if !selected {
            return None;
        }
        let (new_value, swapped) = swap_header_value(value, proxy, secret_bytes);
        if swapped {
            locations.push(format!("header:{}", canonical_name(name)));
            Some(new_value)
        } else {
            None
        }
    });

    // Query: replace within values only; the secret is percent-encoded.
    if secret.match_query && !req.query.is_empty() {
        if let Some(new_query) = swap_query(&req.query, proxy, secret_bytes) {
            req.query = new_query;
            locations.push("query".to_string());
        }
    }

    // Path: byte-literal replace-all on the raw path; secret percent-
    // encoded (Part 04 §3.2).
    if secret.match_path {
        let repl = percent_encode(secret_bytes).into_bytes();
        let (new_path, n) = replace_all(req.path.as_bytes(), proxy, &repl);
        if n > 0 {
            req.path = String::from_utf8_lossy(&new_path).into_owned();
            locations.push("path".to_string());
        }
    }

    // Body: byte replace-all in the buffered body.
    if secret.match_body {
        let (new_body, n) = replace_all(req.body.read(), proxy, secret_bytes);
        if n > 0 {
            // Over-cap was rejected before this call; replace succeeds.
            let _ = req.body.replace(new_body);
            locations.push("body".to_string());
        }
    }

    ScanResult { locations }
}

/// Swap within one header value. A syntactically valid
/// `Authorization: Basic <b64>` value is base64-decoded, swapped, and
/// re-encoded (Part 04 §3.2). Returns (new value, swapped?).
fn swap_header_value(value: &str, proxy: &[u8], secret: &[u8]) -> (String, bool) {
    if let Some(b64) = value.strip_prefix("Basic ") {
        if let Some(decoded) = base64_decode(b64) {
            let (new_decoded, n) = replace_all(&decoded, proxy, secret);
            if n > 0 {
                return (format!("Basic {}", base64_encode(&new_decoded)), true);
            }
            return (value.to_string(), false);
        }
    }
    let (new, n) = replace_all(value.as_bytes(), proxy, secret);
    if n > 0 {
        (String::from_utf8_lossy(&new).into_owned(), true)
    } else {
        (value.to_string(), false)
    }
}

/// Replace `proxy` within query *values* only, re-encoding the secret.
fn swap_query(query: &str, proxy: &[u8], secret: &[u8]) -> Option<String> {
    let repl = percent_encode(secret);
    let mut any = false;
    let rebuilt = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => {
                let (new_v, n) = replace_all(v.as_bytes(), proxy, repl.as_bytes());
                if n > 0 {
                    any = true;
                }
                format!("{k}={}", String::from_utf8_lossy(&new_v))
            }
            None => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    if any {
        Some(rebuilt)
    } else {
        None
    }
}
