//! Part 09 — metrics registry with Prometheus text exposition.
//!
//! Design: hand-rolled, std-only, no external metrics crate.
//! Each counter family is a `Mutex<BTreeMap<String, u64>>` keyed by
//! the rendered label string — deterministic output order for free.
//! Histograms use the same BTreeMap approach for bucket/sum/count storage.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hematite_kernel::audit::{Action, AuditRecord};
use hematite_kernel::summary::Mode;
use hematite_kernel::verdict::TraceVerdict;

use crate::audit::{AuditSink, Level};

// ---------------------------------------------------------------------------
// Enums for point-counter labels
// ---------------------------------------------------------------------------

/// Result of an upstream dial attempt.
#[derive(Debug, Clone, Copy)]
pub enum DialResult {
    Ok,
    GuardDenied,
    DnsError,
    ConnectError,
    TlsError,
}

impl DialResult {
    fn as_str(self) -> &'static str {
        match self {
            DialResult::Ok => "ok",
            DialResult::GuardDenied => "guard-denied",
            DialResult::DnsError => "dns-error",
            DialResult::ConnectError => "connect-error",
            DialResult::TlsError => "tls-error",
        }
    }
}

/// Outcome of a DNS query.
#[derive(Debug, Clone, Copy)]
pub enum DnsOutcome {
    Intercept,
    Static,
    Passthrough,
    Error,
}

impl DnsOutcome {
    fn as_str(self) -> &'static str {
        match self {
            DnsOutcome::Intercept => "intercept",
            DnsOutcome::Static => "static",
            DnsOutcome::Passthrough => "passthrough",
            DnsOutcome::Error => "error",
        }
    }
}

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

const BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

struct Histogram {
    /// Counts per bucket (parallel to BUCKETS).
    counts: [u64; 12],
    sum: f64,
    count: u64,
}

impl Histogram {
    fn new() -> Self {
        Histogram {
            counts: [0u64; 12],
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, value: f64) {
        // Store per-band (not cumulative) so render_histogram can produce the
        // correct cumulative sum without double-counting.
        for (i, &bound) in BUCKETS.iter().enumerate() {
            if value <= bound {
                self.counts[i] += 1;
                break;
            }
        }
        self.sum += value;
        self.count += 1;
    }
}

// ---------------------------------------------------------------------------
// Metrics registry
// ---------------------------------------------------------------------------

/// Central metrics registry. All state under fine-grained mutexes; render
/// takes them one family at a time so counters and histograms are never
/// blocked together.
pub struct Metrics {
    version: String,

    // hematite_requests_total{mode, action, rejected_by}
    requests: Mutex<BTreeMap<String, u64>>,

    // hematite_request_duration_seconds histogram keyed by "mode, action" label string
    duration: Mutex<BTreeMap<String, Histogram>>,

    // hematite_secrets_swaps_total{result}
    secrets: Mutex<BTreeMap<String, u64>>,

    // hematite_upstream_dials_total{result}
    dials: Mutex<BTreeMap<String, u64>>,

    // hematite_dns_queries_total{outcome}
    dns: Mutex<BTreeMap<String, u64>>,

    // hematite_tls_leaf_cache_events_total{event}
    tls_cache: Mutex<BTreeMap<String, u64>>,

    // hematite_config_reloads_total{result}
    reloads: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    pub fn new(version: &str) -> Arc<Metrics> {
        Arc::new(Metrics {
            version: version.to_string(),
            requests: Mutex::new(BTreeMap::new()),
            duration: Mutex::new(BTreeMap::new()),
            secrets: Mutex::new(BTreeMap::new()),
            dials: Mutex::new(BTreeMap::new()),
            dns: Mutex::new(BTreeMap::new()),
            tls_cache: Mutex::new(BTreeMap::new()),
            reloads: Mutex::new(BTreeMap::new()),
        })
    }

    /// Derive request metrics from an audit record.
    pub fn observe_record(&self, record: &AuditRecord) {
        let mode = mode_label(record.mode);
        let action = action_label(record.action);
        let rejected_by = record.rejected_by.as_deref().unwrap_or("").to_string();

        // hematite_requests_total
        let req_key = format!(
            r#"mode="{}",action="{}",rejected_by="{}""#,
            escape_label(mode),
            escape_label(action),
            escape_label(&rejected_by),
        );
        *self
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(req_key)
            .or_insert(0) += 1;

        // hematite_request_duration_seconds
        let dur_key = format!(
            r#"mode="{}",action="{}""#,
            escape_label(mode),
            escape_label(action),
        );
        let seconds = record.duration_ms / 1000.0;
        self.duration
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(dur_key)
            .or_insert_with(Histogram::new)
            .observe(seconds);

        // hematite_secrets_swaps_total — walk request_transforms for "secrets" trace
        for trace in &record.request_transforms {
            if trace.name != "secrets" {
                continue;
            }
            // swapped count
            if let Some(arr) = trace.annotations.get("swapped").and_then(|v| v.as_array()) {
                let n = arr.len() as u64;
                if n > 0 {
                    let key = r#"result="swapped""#.to_string();
                    *self
                        .secrets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .entry(key)
                        .or_insert(0) += n;
                }
            }
            // source-error count
            if let Some(arr) = trace
                .annotations
                .get("secret_unavailable")
                .and_then(|v| v.as_array())
            {
                let n = arr.len() as u64;
                if n > 0 {
                    let key = r#"result="source-error""#.to_string();
                    *self
                        .secrets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .entry(key)
                        .or_insert(0) += n;
                }
            }
            // missing-required: secrets trace whose record.rejected_by == Some("secrets")
            if record.rejected_by.as_deref() == Some("secrets")
                && trace.verdict == TraceVerdict::Reject
            {
                let key = r#"result="missing-required""#.to_string();
                *self
                    .secrets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(key)
                    .or_insert(0) += 1;
            }
        }
    }

    /// Increment the upstream dial counter.
    pub fn inc_dial(&self, result: DialResult) {
        let key = format!(r#"result="{}""#, escape_label(result.as_str()));
        *self
            .dials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert(0) += 1;
    }

    /// Increment the DNS query counter.
    pub fn inc_dns(&self, outcome: DnsOutcome) {
        let key = format!(r#"outcome="{}""#, escape_label(outcome.as_str()));
        *self
            .dns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert(0) += 1;
    }

    /// Increment the TLS leaf cache hit/miss counter.
    pub fn inc_tls_cache(&self, hit: bool) {
        let event = if hit { "hit" } else { "miss" };
        let key = format!(r#"event="{}""#, escape_label(event));
        *self
            .tls_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert(0) += 1;
    }

    /// Increment the config reload counter.
    pub fn inc_reload(&self, ok: bool) {
        let result = if ok { "ok" } else { "error" };
        let key = format!(r#"result="{}""#, escape_label(result));
        *self
            .reloads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert(0) += 1;
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);

        // hematite_build_info
        out.push_str("# TYPE hematite_build_info gauge\n");
        out.push_str(&format!(
            "hematite_build_info{{version=\"{}\"}} 1\n",
            escape_label(&self.version)
        ));

        // hematite_requests_total
        out.push_str("# TYPE hematite_requests_total counter\n");
        for (labels, count) in self
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push_str(&format!("hematite_requests_total{{{labels}}} {count}\n"));
        }

        // hematite_request_duration_seconds histogram
        out.push_str("# TYPE hematite_request_duration_seconds histogram\n");
        for (labels, hist) in self
            .duration
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            render_histogram(&mut out, "hematite_request_duration_seconds", labels, hist);
        }

        // hematite_secrets_swaps_total
        out.push_str("# TYPE hematite_secrets_swaps_total counter\n");
        for (labels, count) in self
            .secrets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push_str(&format!(
                "hematite_secrets_swaps_total{{{labels}}} {count}\n"
            ));
        }

        // hematite_upstream_dials_total
        out.push_str("# TYPE hematite_upstream_dials_total counter\n");
        for (labels, count) in self.dials.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            out.push_str(&format!(
                "hematite_upstream_dials_total{{{labels}}} {count}\n"
            ));
        }

        // hematite_dns_queries_total
        out.push_str("# TYPE hematite_dns_queries_total counter\n");
        for (labels, count) in self.dns.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            out.push_str(&format!("hematite_dns_queries_total{{{labels}}} {count}\n"));
        }

        // hematite_tls_leaf_cache_events_total
        out.push_str("# TYPE hematite_tls_leaf_cache_events_total counter\n");
        for (labels, count) in self
            .tls_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push_str(&format!(
                "hematite_tls_leaf_cache_events_total{{{labels}}} {count}\n"
            ));
        }

        // hematite_config_reloads_total
        out.push_str("# TYPE hematite_config_reloads_total counter\n");
        for (labels, count) in self
            .reloads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push_str(&format!(
                "hematite_config_reloads_total{{{labels}}} {count}\n"
            ));
        }

        out
    }
}

// ---------------------------------------------------------------------------
// MetricsSink decorator
// ---------------------------------------------------------------------------

/// Decorator that derives request metrics from each audit record, then
/// delegates to the inner sink.
pub struct MetricsSink {
    pub inner: Arc<dyn AuditSink>,
    pub metrics: Arc<Metrics>,
}

impl AuditSink for MetricsSink {
    fn emit(&self, record: &AuditRecord, level: Level) {
        self.metrics.observe_record(record);
        self.inner.emit(record, level);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Http => "http",
        Mode::Https => "https",
        Mode::Tunnel => "tunnel",
    }
}

fn action_label(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Reject => "reject",
        Action::Stub => "stub",
        Action::Error => "error",
        Action::ClientCancel => "client-cancel",
    }
}

/// Prometheus label-value escaping: `\` → `\\`, `"` → `\"`, newline → `\n`.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Render a single histogram family entry.
fn render_histogram(out: &mut String, name: &str, labels: &str, hist: &Histogram) {
    // Cumulative bucket counts
    let mut cumulative: u64 = 0;
    for (i, &bound) in BUCKETS.iter().enumerate() {
        cumulative += hist.counts[i];
        out.push_str(&format!(
            "{name}_bucket{{{labels},le=\"{bound}\"}} {cumulative}\n"
        ));
    }
    // +Inf bucket = total count
    out.push_str(&format!(
        "{name}_bucket{{{labels},le=\"+Inf\"}} {}\n",
        hist.count
    ));
    out.push_str(&format!("{name}_sum{{{labels}}} {}\n", hist.sum));
    out.push_str(&format!("{name}_count{{{labels}}} {}\n", hist.count));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hematite_kernel::audit::{Action, AuditRecord};
    use hematite_kernel::summary::Mode;

    fn record(
        mode: Mode,
        action: Action,
        rejected_by: Option<&str>,
        duration_ms: f64,
    ) -> AuditRecord {
        // Build via the record's public constructor/Default the way audit.rs tests do;
        // set host to "httpbin.org" to prove hosts never reach the exposition.
        AuditRecord {
            host: "httpbin.org".into(),
            method: "GET".into(),
            path: "/".into(),
            remote_addr: None,
            sni: None,
            mode,
            action,
            status_code: None,
            duration_ms,
            rejected_by: rejected_by.map(String::from),
            stubbed_by: None,
            error: None,
            request_transforms: vec![],
            response_transforms: vec![],
            tunnel: None,
            guard: None,
            body_capture: None,
        }
    }

    #[test]
    fn requests_counter_and_histogram() {
        let m = Metrics::new("1.2.3");
        m.observe_record(&record(Mode::Https, Action::Allow, None, 42.0));
        m.observe_record(&record(Mode::Https, Action::Reject, Some("allowlist"), 1.0));
        let out = m.render();
        assert!(out
            .contains(r#"hematite_requests_total{mode="https",action="allow",rejected_by=""} 1"#));
        assert!(out.contains(
            r#"hematite_requests_total{mode="https",action="reject",rejected_by="allowlist"} 1"#
        ));
        // 42 ms = 0.042 s falls in the le="0.05" band; cumulative invariant:
        // every bucket at or above 0.05 must equal 1, and +Inf == count == 1.
        assert!(out.contains(
            r#"hematite_request_duration_seconds_bucket{mode="https",action="allow",le="0.05"} 1"#
        ));
        assert!(out.contains(
            r#"hematite_request_duration_seconds_bucket{mode="https",action="allow",le="0.1"} 1"#
        ));
        assert!(out.contains(
            r#"hematite_request_duration_seconds_bucket{mode="https",action="allow",le="30"} 1"#
        ));
        assert!(out.contains(
            r#"hematite_request_duration_seconds_bucket{mode="https",action="allow",le="+Inf"} 1"#
        ));
        assert!(out
            .contains(r#"hematite_request_duration_seconds_count{mode="https",action="allow"} 1"#));
        assert!(out.contains("hematite_request_duration_seconds_sum"));
        assert!(out.contains(r#"hematite_build_info{version="1.2.3"} 1"#));
        assert!(out.contains("# TYPE hematite_requests_total counter"));
    }

    #[test]
    fn no_host_in_exposition() {
        let m = Metrics::new("0");
        m.observe_record(&record(Mode::Http, Action::Allow, None, 5.0));
        assert!(!m.render().contains("httpbin"));
    }

    #[test]
    fn point_counters_render() {
        let m = Metrics::new("0");
        m.inc_dial(DialResult::GuardDenied);
        m.inc_dns(DnsOutcome::Passthrough);
        m.inc_tls_cache(true);
        m.inc_reload(false);
        let out = m.render();
        assert!(out.contains(r#"hematite_upstream_dials_total{result="guard-denied"} 1"#));
        assert!(out.contains(r#"hematite_dns_queries_total{outcome="passthrough"} 1"#));
        assert!(out.contains(r#"hematite_tls_leaf_cache_events_total{event="hit"} 1"#));
        assert!(out.contains(r#"hematite_config_reloads_total{result="error"} 1"#));
    }

    #[test]
    fn label_values_escaped() {
        // rejected_by could someday carry quotes/backslashes; exposition must escape " \ and \n.
        let m = Metrics::new("0");
        m.observe_record(&record(Mode::Http, Action::Reject, Some("a\"b\\c"), 1.0));
        assert!(m.render().contains(r#"rejected_by="a\"b\\c""#));
    }
}
