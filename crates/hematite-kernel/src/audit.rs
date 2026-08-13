//! Part 08 §2 — the audit record schema (L0), and the conformance-harness
//! record builder used by the Appendix C §4 vectors.
//!
//! `AuditRecord` and everything reachable from it is plain serde data
//! (strings, numbers, bools): a `Secret` cannot be placed in one — the
//! program does not compile (INV-1).

use serde::Serialize;

use crate::pipeline::{BodyCapture, Outcome, PipelineOutcome};
use crate::summary::{Mode, RequestSummary};
use crate::verdict::Trace;

/// The whole-request outcome (Part 00 §3 "action").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Reject,
    Stub,
    Error,
    ClientCancel,
}

/// Audit group for guard denials (Part 07 §2).
#[derive(Debug, Clone, Serialize)]
pub struct GuardDenial {
    pub denied_addr: String,
    pub prefix: String,
}

/// Audit group for in-tunnel requests (Part 08 §2).
#[derive(Debug, Clone, Serialize)]
pub struct TunnelGroup {
    pub target: String,
    pub request_transforms: Vec<Trace>,
    /// Part 05 §4.4 — true when the tunnel was spliced without TLS
    /// interception. Omitted (false) for bumped tunnels.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(default)]
    pub passthrough: bool,
}

/// Part 08 §2 — the one JSON object emitted per request. Optional fields
/// are omitted, never null; unknown fields never appear
/// (`schema/audit-record.schema.json` is normative).
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub host: String,
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub mode: Mode,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Filled by the caller from a real clock; the kernel writes nothing
    /// truthful here (INV-4) and vector comparison strips it.
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stubbed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub request_transforms: Vec<Trace>,
    pub response_transforms: Vec<Trace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<GuardDenial>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_capture: Option<BodyCapture>,
}

/// Build the record the conformance harness compares (Appendix C §4): the
/// kernel produces the verdict and traces; this fills the fields outside
/// the traces from the summary and the outcome (403 for a pipeline reject,
/// Part 01 §2; 502 for a transform error, Part 03 §3).
pub fn conformance_record(summary: &RequestSummary, outcome: &PipelineOutcome) -> AuditRecord {
    let (action, status_code, rejected_by, stubbed_by, error) = match &outcome.outcome {
        Outcome::Continue(_) => (Action::Allow, None, None, None, None),
        Outcome::Reject { by, response } => (
            Action::Reject,
            Some(response.as_ref().map(|r| r.status).unwrap_or(403)),
            Some(by.clone()),
            None,
            None,
        ),
        Outcome::Stub { by, response } => (
            Action::Stub,
            Some(response.status),
            None,
            Some(by.clone()),
            None,
        ),
        Outcome::Error { by: _, message } => {
            (Action::Error, Some(502), None, None, Some(message.clone()))
        }
    };

    AuditRecord {
        host: summary.host.clone(),
        method: summary.method.clone(),
        path: summary.path.clone(),
        remote_addr: summary.remote_addr.clone(),
        sni: summary.sni.clone(),
        mode: summary.mode,
        action,
        status_code,
        duration_ms: 0.0,
        rejected_by,
        stubbed_by,
        error,
        request_transforms: outcome.request_traces.clone(),
        response_transforms: Vec::new(),
        tunnel: None,
        guard: None,
        body_capture: outcome.body_capture.clone(),
    }
}
