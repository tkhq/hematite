//! Part 08 §2 — every emitted audit-record shape validates against the
//! normative JSON Schema, and the schema rejects malformed records.

mod common;

use hematite_kernel::audit::{Action, AuditRecord, GuardDenial, TunnelGroup};
use hematite_kernel::pipeline::BodyCapture;
use hematite_kernel::summary::Mode;
use hematite_kernel::verdict::{Trace, TraceVerdict};
use serde_json::{json, Map};

fn trace(name: &str, verdict: TraceVerdict) -> Trace {
    Trace {
        name: name.into(),
        verdict,
        duration_ms: 0.4,
        error: None,
        annotations: Map::new(),
    }
}

fn base(action: Action) -> AuditRecord {
    AuditRecord {
        host: "api.example.com".into(),
        method: "GET".into(),
        path: "/v1/x".into(),
        remote_addr: Some("10.0.0.4:5000".into()),
        sni: Some("api.example.com".into()),
        mode: Mode::Https,
        action,
        status_code: Some(200),
        duration_ms: 12.5,
        rejected_by: None,
        stubbed_by: None,
        error: None,
        request_transforms: vec![trace("allowlist", TraceVerdict::Continue)],
        response_transforms: vec![],
        tunnel: None,
        guard: None,
        body_capture: None,
    }
}

#[test]
fn every_action_variant_validates() {
    common::assert_valid_record(&base(Action::Allow));

    let mut reject = base(Action::Reject);
    reject.status_code = Some(403);
    reject.rejected_by = Some("allowlist".into());
    reject.request_transforms = vec![trace("allowlist", TraceVerdict::Reject)];
    common::assert_valid_record(&reject);

    let mut stub = base(Action::Stub);
    stub.stubbed_by = Some("annotate".into());
    common::assert_valid_record(&stub);

    let mut error = base(Action::Error);
    error.status_code = Some(502);
    error.error = Some("upstream response header timeout".into());
    common::assert_valid_record(&error);

    let mut cancel = base(Action::ClientCancel);
    cancel.status_code = None;
    common::assert_valid_record(&cancel);
}

#[test]
fn optional_groups_validate() {
    // Guard denial.
    let mut guard = base(Action::Reject);
    guard.status_code = Some(502);
    guard.rejected_by = Some("guard".into());
    guard.guard = Some(GuardDenial {
        denied_addr: "169.254.169.254".into(),
        prefix: "169.254.169.254/32".into(),
    });
    common::assert_valid_record(&guard);

    // In-tunnel request carrying the handshake traces.
    let mut tunnel = base(Action::Allow);
    tunnel.mode = Mode::Tunnel;
    tunnel.tunnel = Some(TunnelGroup {
        target: "api.example.com:443".into(),
        request_transforms: vec![trace("allowlist", TraceVerdict::Continue)],
    });
    common::assert_valid_record(&tunnel);

    // Body capture group.
    let mut captured = base(Action::Allow);
    captured.body_capture = Some(BodyCapture {
        request_body: "{\"k\":\"v\"}".into(),
        request_body_truncated: false,
    });
    common::assert_valid_record(&captured);
}

#[test]
fn schema_rejects_malformed_records() {
    // A reject without rejected_by (conditional required).
    common::assert_invalid(&json!({
        "host": "x", "method": "GET", "path": "/", "mode": "https",
        "action": "reject", "duration_ms": 1.0,
        "request_transforms": [], "response_transforms": []
    }));
    // An unknown field (additionalProperties: false).
    common::assert_invalid(&json!({
        "host": "x", "method": "GET", "path": "/", "mode": "https",
        "action": "allow", "duration_ms": 1.0,
        "request_transforms": [], "response_transforms": [],
        "surprise": true
    }));
    // An unknown mode.
    common::assert_invalid(&json!({
        "host": "x", "method": "GET", "path": "/", "mode": "ftp",
        "action": "allow", "duration_ms": 1.0,
        "request_transforms": [], "response_transforms": []
    }));
}
