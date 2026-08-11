//! Shared conformance-runner plumbing: vector loading, summary
//! construction, and duration_ms stripping (spec/vectors/README.md).

// Each test binary compiles this module separately; not all use every item.
#![allow(dead_code)]

use std::path::PathBuf;

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::Value;

use hematite_kernel::secret::{ResolveError, Secret, SecretResolver, SourceRef};
use hematite_kernel::summary::{Body, Headers, Mode, RequestSummary};

pub fn load_vector(file: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(file);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read vector file {}: {e}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("vector file {} is not JSON: {e}", path.display()))
}

/// The `summary` object of a decision-trace vector.
#[derive(Deserialize)]
pub struct VectorSummary {
    pub mode: Mode,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    #[serde(default)]
    pub sni: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl VectorSummary {
    pub fn into_summary(self) -> RequestSummary {
        RequestSummary {
            mode: self.mode,
            method: self.method,
            host: self.host,
            port: self.port,
            path: self.path,
            query: self.query,
            headers: Headers::new(self.headers),
            body: Body::new(self.body.into_bytes(), false),
            sni: self.sni,
            remote_addr: None,
        }
    }
}

/// A stub resolver built from a vector's `resolver` map: source name →
/// resolved value. Names in `failing` resolve to an error (Appendix C §2
/// case 8, `resolver_fails`).
pub struct MapResolver {
    map: HashMap<String, String>,
    failing: HashSet<String>,
}

impl MapResolver {
    pub fn new(map: HashMap<String, String>, failing: HashSet<String>) -> Self {
        MapResolver { map, failing }
    }

    /// From a vector `{ "NAME": "value", ... }` object.
    pub fn from_value(value: &Value) -> Self {
        let map = value
            .as_object()
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        MapResolver { map, failing: HashSet::new() }
    }

    pub fn with_failing(mut self, name: &str) -> Self {
        self.failing.insert(name.to_string());
        self
    }
}

impl SecretResolver for MapResolver {
    fn resolve(&self, source: &SourceRef) -> Result<Secret, ResolveError> {
        let name = source.name();
        if self.failing.contains(name) {
            return Err(ResolveError { source: source.clone(), reason: "stubbed failure".into() });
        }
        match self.map.get(name) {
            Some(v) => Ok(Secret::new(v.clone().into_bytes())),
            None => Err(ResolveError { source: source.clone(), reason: "not in stub map".into() }),
        }
    }
}

/// Records are compared after removing every `duration_ms` field — the one
/// nondeterministic datum (INV-4).
pub fn strip_duration_ms(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("duration_ms");
            for v in map.values_mut() {
                strip_duration_ms(v);
            }
        }
        Value::Array(items) => {
            for v in items {
                strip_duration_ms(v);
            }
        }
        _ => {}
    }
}
