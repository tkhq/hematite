//! Part 01 §2–§3 — Verdict and Trace.

use serde::Serialize;
use serde_json::{Map, Value};

/// A transform-supplied response (for `Reject` with a body, or `Stub`).
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Part 01 §2 — every transform invocation returns exactly one verdict.
/// There is no `Allow`: allowing is the absence of rejection at the end of
/// the pipeline.
#[derive(Debug)]
pub enum Verdict {
    Continue,
    /// `None` → the proxy returns HTTP 403 with an empty body.
    Reject(Option<Response>),
    /// Proxy-served response, distinguishable from a denial.
    Stub(Response),
}

/// The `verdict` field of a trace. `Error` is not returnable by a
/// transform; it records that the transform failed (Part 03 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceVerdict {
    Continue,
    Reject,
    Stub,
    Error,
}

/// Part 01 §3 — one trace per transform invocation, in execution order.
#[derive(Debug, Clone, Serialize)]
pub struct Trace {
    pub name: String,
    pub verdict: TraceVerdict,
    /// Supplied by the caller (INV-4); the kernel writes 0.0.
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub annotations: Map<String, Value>,
}
