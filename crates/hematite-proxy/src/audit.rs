//! Part 08 — audit emission. One JSON object per line on stderr; exactly
//! one record per accepted request (INV-3), backstopped by `PendingAudit`'s
//! `Drop`.

use std::io::Write;
use std::sync::Arc;

use hematite_kernel::audit::{Action, AuditRecord};
use hematite_kernel::summary::Mode;

/// Part 08 §1 — the log level of a record, derived from its action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

pub fn level_for(action: Action) -> Level {
    match action {
        Action::Allow | Action::Stub | Action::ClientCancel => Level::Info,
        Action::Reject => Level::Warn,
        Action::Error => Level::Error,
    }
}

/// Where records go. The binary uses stderr; tests collect in memory.
pub trait AuditSink: Send + Sync {
    fn emit(&self, record: &AuditRecord, level: Level);
}

/// One JSON line per record on stderr (Part 08 §1). Line-buffered writes so
/// records are not interleaved.
pub struct StderrSink;

impl AuditSink for StderrSink {
    fn emit(&self, record: &AuditRecord, _level: Level) {
        // The record schema is closed (additionalProperties: false); the
        // level is derivable from `action` and is not an in-band field.
        if let Ok(line) = serde_json::to_string(record) {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "{line}");
        }
    }
}

/// INV-3 backstop (Appendix E): constructed at accept time, emits on `Drop`
/// if the handler never emitted — so a panicked or short-circuited path
/// still produces exactly one record, with `action: error`.
pub struct PendingAudit {
    sink: Arc<dyn AuditSink>,
    emitted: bool,
    remote_addr: Option<String>,
}

impl PendingAudit {
    pub fn new(sink: Arc<dyn AuditSink>, remote_addr: Option<String>) -> Self {
        PendingAudit {
            sink,
            emitted: false,
            remote_addr,
        }
    }

    pub fn emit(&mut self, record: &AuditRecord) {
        self.sink.emit(record, level_for(record.action));
        self.emitted = true;
    }
}

impl Drop for PendingAudit {
    fn drop(&mut self) {
        if self.emitted {
            return;
        }
        let record = AuditRecord {
            host: String::new(),
            method: String::new(),
            path: String::new(),
            remote_addr: self.remote_addr.clone(),
            sni: None,
            mode: Mode::Http,
            action: Action::Error,
            status_code: None,
            duration_ms: 0.0,
            rejected_by: None,
            stubbed_by: None,
            error: Some("request handler terminated without emitting audit".into()),
            request_transforms: Vec::new(),
            response_transforms: Vec::new(),
            tunnel: None,
            guard: None,
            body_capture: None,
        };
        self.sink.emit(&record, Level::Error);
    }
}
