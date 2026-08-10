//! Part 04 — the policy logic of the built-in transforms.
//!
//! L0 scope: `allowlist` (§1), `annotate` (§2), `header_allowlist` (§4),
//! `body_capture` (§5). The `secrets` transform (§3) is L3 and lands in a
//! later phase; naming it in a config is a build error until then.

use serde_json::{json, Value};

use crate::matcher::{any_rule_matches, canonical_name, Cidr, DomainGlob, HeaderNameEntry, Rule};
use crate::pipeline::{BodyCapture, Ctx, Transform, TransformError};
use crate::summary::RequestSummary;
use crate::verdict::Verdict;

/// Part 04 §1 — default-deny destination filter.
pub struct Allowlist {
    pub(crate) domains: Vec<DomainGlob>,
    pub(crate) cidrs: Vec<Cidr>,
    pub(crate) warn: bool,
}

impl Transform for Allowlist {
    fn name(&self) -> &'static str {
        "allowlist"
    }

    fn on_request(
        &self,
        ctx: &mut Ctx,
        req: &mut RequestSummary,
    ) -> Result<Verdict, TransformError> {
        let allowed = self.domains.iter().any(|g| g.matches(&req.host))
            || self.cidrs.iter().any(|c| c.matches_host(&req.host));
        if allowed {
            Ok(Verdict::Continue)
        } else if self.warn {
            ctx.annotate("warn", json!(true));
            Ok(Verdict::Continue)
        } else {
            Ok(Verdict::Reject(None))
        }
    }
}

/// One group in the `annotate` config: rules plus literal header names.
pub struct AnnotateGroup {
    pub(crate) rules: Vec<Rule>,
    /// Lowercase literal names (regex entries are a config error here,
    /// Part 02 §5).
    pub(crate) headers: Vec<String>,
}

/// Part 04 §2 — observation-only header capture. Never rejects.
pub struct Annotate {
    pub(crate) groups: Vec<AnnotateGroup>,
}

impl Transform for Annotate {
    fn name(&self) -> &'static str {
        "annotate"
    }

    fn on_request(
        &self,
        ctx: &mut Ctx,
        req: &mut RequestSummary,
    ) -> Result<Verdict, TransformError> {
        for group in &self.groups {
            if !any_rule_matches(&group.rules, &req.host, &req.method, &req.path) {
                continue;
            }
            for name in &group.headers {
                if let Some(value) = req.headers.first(name) {
                    ctx.annotate(&format!("header:{}", canonical_name(name)), json!(value));
                }
            }
        }
        Ok(Verdict::Continue)
    }
}

/// Part 04 §4 — default-deny request-header filter. Never rejects.
pub struct HeaderAllowlist {
    pub(crate) entries: Vec<HeaderNameEntry>,
    /// `None` = all requests (Part 04 §4: rules optional).
    pub(crate) rules: Option<Vec<Rule>>,
}

impl Transform for HeaderAllowlist {
    fn name(&self) -> &'static str {
        "header_allowlist"
    }

    fn on_request(
        &self,
        ctx: &mut Ctx,
        req: &mut RequestSummary,
    ) -> Result<Verdict, TransformError> {
        if let Some(rules) = &self.rules {
            if !any_rule_matches(rules, &req.host, &req.method, &req.path) {
                return Ok(Verdict::Continue);
            }
        }
        let mut removed = req
            .headers
            .retain(|name| self.entries.iter().any(|e| e.matches(name)));
        if !removed.is_empty() {
            removed.sort();
            removed.dedup();
            ctx.annotate("stripped_headers", json!(removed));
        }
        Ok(Verdict::Continue)
    }
}

/// Part 04 §5 — observation-only request-body recording. Never rejects.
pub struct BodyCaptureTransform {
    /// The capture cap — independent of the global request-body cap.
    pub(crate) max_request_body_bytes: usize,
    pub(crate) rules: Vec<Rule>,
}

impl Transform for BodyCaptureTransform {
    fn name(&self) -> &'static str {
        "body_capture"
    }

    fn on_request(
        &self,
        ctx: &mut Ctx,
        req: &mut RequestSummary,
    ) -> Result<Verdict, TransformError> {
        if !any_rule_matches(&self.rules, &req.host, &req.method, &req.path) {
            return Ok(Verdict::Continue);
        }
        let bytes = req.body.read();
        let cap = self.max_request_body_bytes.min(bytes.len());
        let truncated = bytes.len() > self.max_request_body_bytes || req.body.over_cap();
        ctx.annotate("captured_bytes", Value::from(cap as u64));
        ctx.annotate("truncated", json!(truncated));
        ctx.set_body_capture(BodyCapture {
            request_body: String::from_utf8_lossy(&bytes[..cap]).into_owned(),
            request_body_truncated: truncated,
        });
        Ok(Verdict::Continue)
    }
}
