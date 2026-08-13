//! Part 03 — pipeline structure, transform contract, short-circuit,
//! and the INV-2 proof value.

use serde_json::{Map, Value};

use crate::summary::RequestSummary;
use crate::verdict::{Response, Trace, TraceVerdict, Verdict};

/// INV-2 — only the kernel can construct this (private field, non-Clone).
/// The dialer's entry point consumes it; no proof, no socket.
pub struct AllowProof {
    _sealed: (),
}

/// The whole-request outcome of the request path.
pub enum Outcome {
    Continue(AllowProof),
    Reject {
        by: String,
        response: Option<Response>,
    },
    Stub {
        by: String,
        response: Response,
    },
    /// A transform failed (Part 03 §3). The proxy returns 502; errors MUST
    /// NOT fail open.
    Error {
        by: String,
        message: String,
    },
}

/// Audit-record group filled by `body_capture` (Part 04 §5, Part 08 §2).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BodyCapture {
    pub request_body: String,
    pub request_body_truncated: bool,
}

/// What `evaluate_request` returns: the outcome plus the request-path
/// traces, in execution order.
pub struct PipelineOutcome {
    pub outcome: Outcome,
    pub request_traces: Vec<Trace>,
    pub body_capture: Option<BodyCapture>,
    /// The request path as the client sent it, snapshotted before any
    /// transform ran. Audit records MUST use this, never the post-pipeline
    /// summary path: a `match_path` secrets swap rewrites the resolved
    /// credential into the wire path (Part 08 §3, INV-1).
    pub request_path: String,
}

/// Per-invocation context handed to a transform (Part 03 §4). Annotations
/// are drained into the transform's own trace when it returns; other
/// transforms cannot see them.
#[derive(Default)]
pub struct Ctx {
    annotations: Map<String, Value>,
    body_capture: Option<BodyCapture>,
}

impl Ctx {
    pub fn annotate(&mut self, key: &str, value: Value) {
        self.annotations.insert(key.to_string(), value);
    }

    /// `body_capture` only: attach captured bytes to the audit record.
    pub fn set_body_capture(&mut self, capture: BodyCapture) {
        self.body_capture = Some(capture);
    }
}

/// A transform error (I/O failure, malformed internal state, over-cap
/// rewrite). Stops the pipeline; never fails open.
#[derive(Debug)]
pub struct TransformError(pub String);

/// Part 03 §2 — the transform contract. The registry (Part 03 §5) is
/// closed: v1 is exactly the five transforms in `crate::transforms`.
pub trait Transform: Send + Sync {
    fn name(&self) -> &'static str;

    fn on_request(
        &self,
        ctx: &mut Ctx,
        req: &mut RequestSummary,
    ) -> Result<Verdict, TransformError>;

    /// Response path runs later, in the same order (Part 03 §2). All five
    /// v1 transforms are `Continue` no-ops on the response path.
    fn on_response(
        &self,
        _ctx: &mut Ctx,
        _req: &RequestSummary,
    ) -> Result<Verdict, TransformError> {
        Ok(Verdict::Continue)
    }
}

/// The ordered, immutable pipeline (Part 03 §1). Built by
/// `crate::config::build_pipeline`; reload builds a new one and swaps
/// atomically outside the kernel.
pub struct Pipeline {
    transforms: Vec<Box<dyn Transform>>,
}

impl Pipeline {
    pub(crate) fn new(transforms: Vec<Box<dyn Transform>>) -> Self {
        Pipeline { transforms }
    }

    pub fn transform_names(&self) -> Vec<&'static str> {
        self.transforms.iter().map(|t| t.name()).collect()
    }

    /// The request path: run every transform in order on the shared mutable
    /// request; short-circuit on `Reject`/`Stub`/error (Part 03 §3).
    /// Deterministic (INV-4): `duration_ms` is written as 0.0.
    pub fn evaluate_request(&self, req: &mut RequestSummary) -> PipelineOutcome {
        let mut traces = Vec::with_capacity(self.transforms.len());
        let mut body_capture = None;
        // Snapshotted before any transform can rewrite it (INV-1).
        let request_path = req.path.clone();

        for t in &self.transforms {
            let mut ctx = Ctx::default();
            let result = t.on_request(&mut ctx, req);
            // Bodies rewind implicitly: reads always start at offset 0
            // (Part 01 §4; summary::Body).
            if ctx.body_capture.is_some() {
                body_capture = ctx.body_capture.take();
            }
            match result {
                Ok(Verdict::Continue) => {
                    traces.push(trace(
                        t.name(),
                        TraceVerdict::Continue,
                        None,
                        ctx.annotations,
                    ));
                }
                Ok(Verdict::Reject(response)) => {
                    traces.push(trace(t.name(), TraceVerdict::Reject, None, ctx.annotations));
                    return PipelineOutcome {
                        outcome: Outcome::Reject {
                            by: t.name().to_string(),
                            response,
                        },
                        request_traces: traces,
                        body_capture,
                        request_path,
                    };
                }
                Ok(Verdict::Stub(response)) => {
                    traces.push(trace(t.name(), TraceVerdict::Stub, None, ctx.annotations));
                    return PipelineOutcome {
                        outcome: Outcome::Stub {
                            by: t.name().to_string(),
                            response,
                        },
                        request_traces: traces,
                        body_capture,
                        request_path,
                    };
                }
                Err(TransformError(message)) => {
                    traces.push(trace(
                        t.name(),
                        TraceVerdict::Error,
                        Some(message.clone()),
                        ctx.annotations,
                    ));
                    return PipelineOutcome {
                        outcome: Outcome::Error {
                            by: t.name().to_string(),
                            message,
                        },
                        request_traces: traces,
                        body_capture,
                        request_path,
                    };
                }
            }
        }

        PipelineOutcome {
            outcome: Outcome::Continue(AllowProof { _sealed: () }),
            request_traces: traces,
            body_capture,
            request_path,
        }
    }
}

fn trace(
    name: &str,
    verdict: TraceVerdict,
    error: Option<String>,
    annotations: Map<String, Value>,
) -> Trace {
    Trace {
        name: name.to_string(),
        verdict,
        duration_ms: 0.0,
        error,
        annotations,
    }
}

/// What the response path decided (Part 03 §2–§3).
pub enum ResponseAction {
    /// Relay the upstream response.
    Forward,
    /// Response-path `Reject`/`Stub` replaces the upstream response with
    /// the transform-supplied one (an empty 403 for a bare `Reject`).
    Replace {
        by: String,
        response: Response,
        stub: bool,
    },
    /// A response transform failed; the proxy returns 502 (fail closed).
    Error { by: String, message: String },
}

pub struct ResponseOutcome {
    pub traces: Vec<Trace>,
    pub action: ResponseAction,
}

impl Pipeline {
    /// The response path: after the upstream responds, run every transform
    /// in the **same** order (Part 03 §2); short-circuit as on the request
    /// path. All five v1 transforms are no-ops here.
    pub fn evaluate_response(&self, req: &RequestSummary) -> ResponseOutcome {
        let mut traces = Vec::with_capacity(self.transforms.len());
        for t in &self.transforms {
            let mut ctx = Ctx::default();
            match t.on_response(&mut ctx, req) {
                Ok(Verdict::Continue) => {
                    traces.push(trace(
                        t.name(),
                        TraceVerdict::Continue,
                        None,
                        ctx.annotations,
                    ));
                }
                Ok(Verdict::Reject(response)) => {
                    traces.push(trace(t.name(), TraceVerdict::Reject, None, ctx.annotations));
                    let response = response.unwrap_or(Response {
                        status: 403,
                        headers: Vec::new(),
                        body: Vec::new(),
                    });
                    return ResponseOutcome {
                        traces,
                        action: ResponseAction::Replace {
                            by: t.name().to_string(),
                            response,
                            stub: false,
                        },
                    };
                }
                Ok(Verdict::Stub(response)) => {
                    traces.push(trace(t.name(), TraceVerdict::Stub, None, ctx.annotations));
                    return ResponseOutcome {
                        traces,
                        action: ResponseAction::Replace {
                            by: t.name().to_string(),
                            response,
                            stub: true,
                        },
                    };
                }
                Err(TransformError(message)) => {
                    traces.push(trace(
                        t.name(),
                        TraceVerdict::Error,
                        Some(message.clone()),
                        ctx.annotations,
                    ));
                    return ResponseOutcome {
                        traces,
                        action: ResponseAction::Error {
                            by: t.name().to_string(),
                            message,
                        },
                    };
                }
            }
        }
        ResponseOutcome {
            traces,
            action: ResponseAction::Forward,
        }
    }
}
