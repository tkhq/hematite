# Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prometheus `/metrics` on the management listener, structured JSON operational logs on stdout, and opt-in OTLP/HTTP trace export — per `docs/superpowers/specs/2026-08-11-observability-design.md`.

**Architecture:** A hand-rolled metrics registry in `hematite-proxy` fed primarily by an `AuditSink` decorator (every request metric derives from the audit record at its single emission choke point), plus targeted counters at the dial/TLS-cache/DNS/reload sites. `tracing` replaces `eprintln!` for operational logs; a `tracing-subscriber` stack adds an optional `tracing-opentelemetry` layer exporting OTLP/HTTP-protobuf. The kernel crate is untouched; `hematite-dns` stays dependency-free via a callback hook.

**Tech Stack:** Rust (edition 2021), tracing, tracing-subscriber (json + env-filter), opentelemetry, opentelemetry_sdk, opentelemetry-otlp (http-proto, no tonic/reqwest), opentelemetry-proto (dev-dep, test decoding). No prometheus crate.

**Spec:** `docs/superpowers/specs/2026-08-11-observability-design.md`

## Global Constraints

- The telemetry redaction rule: anything not permitted in an audit record must not appear in a span attribute, metric label, or log field. Never add a per-host or per-secret-name metric label.
- `crates/hematite-kernel` gains no dependencies and no code changes. `crates/hematite-dns` gains no external dependencies (callback hook only).
- Audit records keep their exclusive claim on stderr, byte-for-byte unchanged. Operational logs go to stdout.
- Config defaults: `observability.metrics.enabled: true`, `observability.log.format: "json"`, `observability.otlp.enabled: false`, `otlp.sample_ratio: 1.0`, `otlp.service_name: "hematite"`. Validation errors: `otlp.enabled` without `endpoint`; `sample_ratio` outside [0.0, 1.0].
- `GET /metrics` on the management listener is exempt from bearer auth; every other management route keeps auth.
- Metric names/labels exactly as the spec table (`hematite_requests_total{mode,action,rejected_by}` etc.). Histogram buckets: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30` seconds.
- Commit convention `type: summary`. `cargo fmt` + `clippy -D warnings` must stay clean (CI gates).
- OTLP crates: pin to current releases with `default-features = false`; NO `tonic`, `grpc-tonic`, or `reqwest` features anywhere in the tree (`cargo tree | grep -E 'tonic|reqwest'` must be empty). If a named feature/API below has drifted in the current crate versions, adapt to the current API and record the deviation in your report — do not add the forbidden transports to work around it.
- Run all commands from the repo root.

---

### Task 1: Config — `observability` section + N-segment env overrides

**Files:**
- Modify: `crates/hematite-proxy/src/config.rs` (RawConfig ~line 26, sections ~line 124, ENV_KEYS ~line 198, `apply_env_overrides` ~line 225, validation + `Config` struct plumbing)
- Test: unit tests in the same file's existing `#[cfg(test)]` module (follow the file's current test style)

**Interfaces:**
- Produces (used by Tasks 2–5):

```rust
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ObservabilitySection {
    pub metrics: MetricsSection,
    pub log: ObsLogSection,
    pub otlp: OtlpSection,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsSection { pub enabled: bool }          // Default: true
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ObsLogSection { pub format: String }          // Default: "json"; allowed: "json" | "text"
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OtlpSection {
    pub enabled: bool,                                   // Default: false
    pub endpoint: Option<String>,
    pub sample_ratio: f64,                               // Default: 1.0
    pub service_name: String,                            // Default: "hematite"
}
```

- The loaded `Config` struct carries `pub observability: ObservabilitySection` (defaulted when the YAML section is absent).
- ENV_KEYS gains: `observability.metrics.enabled`, `observability.log.format`, `observability.otlp.enabled`, `observability.otlp.endpoint`, `observability.otlp.sample_ratio`, `observability.otlp.service_name`.

- [ ] **Step 1: Write the failing tests** (in `config.rs`'s test module; adapt helper names to the module's existing test helpers for loading YAML strings)

```rust
#[test]
fn observability_defaults_when_absent() {
    let c = load_str("proxy:\n  http_listen: \":80\"\ntransforms:\n  - name: allowlist\n    config: { domains: [] }\n", &|_| None).unwrap();
    assert!(c.observability.metrics.enabled);
    assert_eq!(c.observability.log.format, "json");
    assert!(!c.observability.otlp.enabled);
    assert!((c.observability.otlp.sample_ratio - 1.0).abs() < f64::EPSILON);
    assert_eq!(c.observability.otlp.service_name, "hematite");
}

#[test]
fn otlp_enabled_requires_endpoint() {
    let yaml = "proxy:\n  http_listen: \":80\"\ntransforms:\n  - name: allowlist\n    config: { domains: [] }\nobservability:\n  otlp:\n    enabled: true\n";
    assert!(load_str(yaml, &|_| None).is_err());
}

#[test]
fn otlp_sample_ratio_range_validated() {
    let yaml = "proxy:\n  http_listen: \":80\"\ntransforms:\n  - name: allowlist\n    config: { domains: [] }\nobservability:\n  otlp:\n    enabled: true\n    endpoint: \"http://c:4318\"\n    sample_ratio: 1.5\n";
    assert!(load_str(yaml, &|_| None).is_err());
}

#[test]
fn log_format_validated() {
    let yaml = "proxy:\n  http_listen: \":80\"\ntransforms:\n  - name: allowlist\n    config: { domains: [] }\nobservability:\n  log:\n    format: \"xml\"\n";
    assert!(load_str(yaml, &|_| None).is_err());
}

#[test]
fn three_segment_env_override() {
    let env = |k: &str| (k == "HEMATITE_OBSERVABILITY_OTLP_ENDPOINT").then(|| "http://collector:4318".to_string());
    let yaml = "proxy:\n  http_listen: \":80\"\ntransforms:\n  - name: allowlist\n    config: { domains: [] }\nobservability:\n  otlp:\n    enabled: true\n";
    let c = load_str(yaml, &env).unwrap();
    assert_eq!(c.observability.otlp.endpoint.as_deref(), Some("http://collector:4318"));
}

#[test]
fn two_segment_env_override_still_works() {
    let env = |k: &str| (k == "HEMATITE_LOG_LEVEL").then(|| "debug".to_string());
    let yaml = "proxy:\n  http_listen: \":80\"\ntransforms:\n  - name: allowlist\n    config: { domains: [] }\n";
    let c = load_str(yaml, &env).unwrap();
    assert_eq!(c.log_level, "debug");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p hematite-proxy observability -- --nocapture` (and the two env tests by name)
Expected: compile errors (`observability` field absent) — that counts as failing.

- [ ] **Step 3: Implement**

1. Add the four section structs above with `Default` impls producing the spec defaults (`impl Default for MetricsSection { fn default() -> Self { MetricsSection { enabled: true } } }`, etc.).
2. `RawConfig` gains `#[serde(default)] pub observability: ObservabilitySection`; thread through to the loaded `Config`.
3. Generalize `apply_env_overrides`: replace the two-segment destructure with a loop that walks all `.`-separated segments, descending/creating `serde_yaml::Value::Mapping` nodes for every segment but the last, then inserts the typed scalar at the leaf. Keep the existing bool→u64→string typing; `sample_ratio` needs an added f64 parse attempt between u64 and string (`raw.parse::<f64>()` → `serde_yaml::Value::Number(serde_yaml::Number::from(f))`).
4. Add the six new ENV_KEYS entries.
5. Validation (with the existing validation errors' style): `otlp.enabled && otlp.endpoint.is_none()` → error `"observability.otlp.endpoint is required when observability.otlp.enabled"`; `!(0.0..=1.0).contains(&sample_ratio)` → error `"observability.otlp.sample_ratio must be within 0.0..=1.0"`; `log.format` not in {"json","text"} → error `"observability.log.format must be \"json\" or \"text\""`.

- [ ] **Step 4: Run the full crate tests**

Run: `cargo test -p hematite-proxy && cargo clippy -p hematite-proxy --all-targets -- -D warnings && cargo fmt --all --check`
Expected: all green (existing env-override tests must still pass — the N-segment walker must not change two-segment behavior).

- [ ] **Step 5: Commit**

```bash
git add crates/hematite-proxy/src/config.rs
git commit -m "feat: observability config section + N-segment env overrides"
```

---

### Task 2: Metrics registry + audit-derived request metrics

**Files:**
- Create: `crates/hematite-proxy/src/metrics.rs`
- Modify: `crates/hematite-proxy/src/lib.rs` (add `pub mod metrics;`)
- Test: `#[cfg(test)]` module inside `metrics.rs`

**Interfaces:**
- Produces (used by Tasks 3–4):

```rust
pub struct Metrics { /* internal: Mutex<HashMap<LabelKey, u64>> per family + histogram state + build version */ }
impl Metrics {
    pub fn new(version: &str) -> Arc<Metrics>;
    pub fn observe_record(&self, record: &AuditRecord);         // requests_total, duration histogram, secrets_swaps
    pub fn inc_dial(&self, result: DialResult);                 // enum: Ok, GuardDenied, DnsError, ConnectError, TlsError
    pub fn inc_dns(&self, outcome: DnsOutcome);                 // enum: Intercept, Static, Passthrough, Error
    pub fn inc_tls_cache(&self, hit: bool);
    pub fn inc_reload(&self, ok: bool);
    pub fn render(&self) -> String;                             // Prometheus text exposition
}
pub struct MetricsSink { pub inner: Arc<dyn AuditSink>, pub metrics: Arc<Metrics> }
impl AuditSink for MetricsSink { /* observe_record(record) then inner.emit(record, level) */ }
```

- Label derivation from `AuditRecord` (fields per `hematite-kernel/src/audit.rs`): `mode` → `"http" | "https" | "tunnel"` (lowercase of the `Mode` enum); `action` → `"allow" | "reject" | "stub" | "error" | "client-cancel"`; `rejected_by` → the record's `rejected_by` or `""`. Duration seconds = `duration_ms / 1000.0`.
- Secrets derivation (no kernel change): walk `record.request_transforms` for a `Trace` with `name == "secrets"`; count `annotations["swapped"]` array length as `result="swapped"` increments; `annotations["secret_unavailable"]` array length as `result="source-error"`; a `secrets` trace whose verdict is a reject (`record.rejected_by == Some("secrets")`) increments `result="missing-required"` once.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use hematite_kernel::audit::{Action, AuditRecord};
    use hematite_kernel::summary::Mode;

    fn record(mode: Mode, action: Action, rejected_by: Option<&str>, duration_ms: f64) -> AuditRecord {
        // Build via the record's public constructor/Default the way audit.rs tests do;
        // set host to "httpbin.org" to prove hosts never reach the exposition.
        let mut r = AuditRecord::default();
        r.host = "httpbin.org".into();
        r.mode = mode;
        r.action = action;
        r.rejected_by = rejected_by.map(String::from);
        r.duration_ms = duration_ms;
        r
    }

    #[test]
    fn requests_counter_and_histogram() {
        let m = Metrics::new("1.2.3");
        m.observe_record(&record(Mode::Https, Action::Allow, None, 42.0));
        m.observe_record(&record(Mode::Https, Action::Reject, Some("allowlist"), 1.0));
        let out = m.render();
        assert!(out.contains(r#"hematite_requests_total{mode="https",action="allow",rejected_by=""} 1"#));
        assert!(out.contains(r#"hematite_requests_total{mode="https",action="reject",rejected_by="allowlist"} 1"#));
        assert!(out.contains(r#"hematite_request_duration_seconds_bucket{mode="https",action="allow",le="0.05"} 1"#));
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
```

(If `AuditRecord` has no `Default`, construct it the way `audit.rs`'s own tests do — mirror that exact pattern; do not add a `Default` impl to the kernel.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p hematite-proxy metrics` → compile error (module missing).

- [ ] **Step 3: Implement `metrics.rs`**

Design (keep it this simple):
- `type Labels = Vec<(&'static str, String)>;` families stored as `Mutex<BTreeMap<String, u64>>` keyed by the rendered label string (e.g. `mode="https",action="allow",rejected_by=""`) — deterministic exposition order for free.
- Histogram: per `(mode, action)` key, fixed bucket array `[0.005,0.01,0.025,0.05,0.1,0.25,0.5,1.0,2.5,5.0,10.0,30.0]` of `u64` counts plus `sum: f64`, `count: u64`, in the same map-under-mutex style. Render emits `_bucket` lines (cumulative, plus `le="+Inf"`), `_sum`, `_count`.
- `render()` emits, per family: `# TYPE <name> <type>` then the series lines, families in a fixed order; label values escaped (`\` → `\\`, `"` → `\"`, newline → `\n`).
- `observe_record` derives labels as specified in Interfaces (secrets derivation included).
- `MetricsSink` decorator: `observe_record` then delegate. Lock scope: take each mutex only for the increment; render takes them one family at a time.

- [ ] **Step 4: Run** — `cargo test -p hematite-proxy metrics && cargo clippy -p hematite-proxy --all-targets -- -D warnings && cargo fmt --all --check` → PASS.

- [ ] **Step 5: Commit** — `git add -A crates/hematite-proxy && git commit -m "feat: metrics registry with Prometheus exposition and audit-derived request metrics"`

---

### Task 3: Wire metrics through the proxy + `GET /metrics` + acceptance step

**Files:**
- Modify: `crates/hematite-proxy/src/state.rs` (Runtime field), `crates/hematite-proxy/src/config.rs` (`build_runtime`), `crates/hematite-proxy/src/dial.rs`, `crates/hematite-proxy/src/tls.rs` (CertCache), `crates/hematite-proxy/src/management.rs` (route), `crates/hematite-dns/src/server.rs` (+ its lib) for the decision hook, `crates/hematite/src/main.rs` (construct + wire + DNS closure)
- Modify: `tests/acceptance/run.sh` (new step 12)
- Test: route test in `management.rs` test module (if present) or a new integration test `crates/hematite-proxy/tests/metrics_endpoint.rs`; acceptance harness run

**Interfaces:**
- Consumes: `Metrics`, `MetricsSink`, `DialResult`, `DnsOutcome` from Task 2 (exact signatures in Task 2's Interfaces).
- Produces: `Runtime.metrics: Arc<Metrics>` (always present — a registry is cheap; `observability.metrics.enabled: false` only disables the HTTP route); `serve_management(...)` signature gains `metrics: Arc<Metrics>, metrics_enabled: bool`; `hematite-dns` `serve` gains `on_decision: Option<Arc<dyn Fn(DnsDecisionKind) + Send + Sync>>` where `DnsDecisionKind` is a new dep-free enum in hematite-dns: `Intercept | Static | Passthrough | Error`.

- [ ] **Step 1: Wire-up implementation** (mechanical; test cycle is Step 2–3)

1. `Runtime` gains `pub metrics: Arc<Metrics>`; `build_runtime` constructs `Metrics::new(env!("CARGO_PKG_VERSION"))`. On reload, `reload()` must REUSE the previous runtime's registry (counters survive reload): pass the old `state.current().metrics` into the rebuilt Runtime — add a `build_runtime_with_metrics(&Config, Arc<Metrics>)` variant; `build_runtime` calls it with a fresh registry.
2. `main.rs`: wrap the sink — `let sink: Arc<dyn AuditSink> = Arc::new(MetricsSink { inner: Arc::new(StderrSink), metrics: state.current().metrics.clone() });`
3. `dial.rs` `connect_upstream`: increment via `runtime.metrics` — `Ok` → `DialResult::Ok`; guard branch → `GuardDenied`; resolution-failure branches → `DnsError`; connect timeout/refused → `ConnectError`; TLS branches → `TlsError`.
4. `tls.rs` `CertCache`: add `metrics: Mutex<Option<Arc<Metrics>>>` set via `pub fn set_metrics(&self, m: Arc<Metrics>)` called from `build_runtime_with_metrics` (cache is constructed there); `get()` increments hit at the line-185 hit return, miss at both Role assignments (Mint and Await each count one miss).
5. `hematite-dns`: define `DnsDecisionKind`, map `Decision::Answer` from static records → `Static`, intercept answers → `Intercept`, `Decision::Passthrough` → `Passthrough`, send/forward errors → `Error`; invoke the callback where the decision is made in the server loop. `main.rs` passes `Some(Arc::new(move |k| metrics.inc_dns(k.into())))` with a `From<DnsDecisionKind> for DnsOutcome` impl in the proxy crate (or an inline match).
6. `management.rs`: BEFORE the auth check — `if req.method() == hyper::Method::GET && req.uri().path() == "/metrics" { if !metrics_enabled { return Ok(text(StatusCode::NOT_FOUND, "not found")); } return Ok(text(StatusCode::OK, &metrics.render())); }`. `reload()` outcome increments `inc_reload(status == 200)`.
7. `main.rs` threads `metrics` + `config.observability.metrics.enabled` into `serve_management`.

- [ ] **Step 2: Integration test** `crates/hematite-proxy/tests/metrics_endpoint.rs` — follow the existing in-process acceptance test's setup style (`crates/hematite-proxy/tests/acceptance_inproc.rs`) to boot a management listener with a registry, then assert:

```rust
// GET /metrics with no Authorization header -> 200, body contains "hematite_build_info"
// POST /v1/reload with no Authorization header -> 401 (auth intact)
// GET /metrics when metrics_enabled=false -> 404
```

(Write real hyper client calls the way `acceptance_inproc.rs` makes them; if it uses plain TcpStream + raw HTTP strings, mirror that.)

- [ ] **Step 3: Run** — `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check` → PASS.

- [ ] **Step 4: Acceptance step 12** — append to `tests/acceptance/run.sh` before the final PASS/FAIL block:

```bash
step 12 "metrics: unauthenticated scrape, counts, no hostnames"
metrics=$(curl -s http://"$PROXY":9092/metrics)
echo "$metrics" | grep -q 'hematite_requests_total{mode="https",action="reject",rejected_by="allowlist"}' \
  && ok "reject count present" || bad "missing reject counter"
echo "$metrics" | grep -q 'httpbin' && bad "hostname leaked into metrics" || ok "no hostnames"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST http://"$PROXY":9092/v1/reload)
[ "$code" = 401 ] && ok "reload still requires auth" || bad "expected 401, got $code"
```

- [ ] **Step 5: Run the compose acceptance suite** — `cd tests/acceptance && ./gen-certs.sh && docker compose up --build --abort-on-container-exit --exit-code-from client; cd ../..` → `ACCEPTANCE: PASS` including step 12. (k3s harness inherits the step; no change there.)

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat: wire metrics through proxy, unauthenticated GET /metrics, acceptance step 12"`

---

### Task 4: Structured operational logs

**Files:**
- Modify: root `Cargo.toml` (workspace deps: `tracing = "0.1"`, `tracing-subscriber = { version = "0.3", features = ["json", "env-filter", "fmt"] }`), `crates/hematite/Cargo.toml`, `crates/hematite-proxy/Cargo.toml` (tracing only)
- Modify: `crates/hematite/src/main.rs` (subscriber init + all 17 `eprintln!` conversions), `crates/hematite-proxy/src/management.rs`, `crates/hematite-proxy/src/listen.rs`, `crates/hematite-proxy/src/http.rs` (any operational `eprintln!`/silent errors worth an event — convert only existing messages, add nothing new)
- Test: manual verification via acceptance harness + one unit test

**Interfaces:**
- Consumes: `Config.observability.log.format`, `Config.log_level` (Task 1).
- Produces: `hematite::telemetry::init_logging(format: &str, level: &str)` in a new `crates/hematite/src/telemetry.rs` module — installs the global subscriber (fmt layer → stdout; JSON when `format == "json"`, compact plain otherwise; `EnvFilter` built from `level`). Returns the registry handle shape Task 5 needs: implement as `fn init_telemetry(format: &str, level: &str, otlp: &OtlpSection) -> TelemetryGuard` in ONE function from the start, with the OTLP branch left un-implemented in this task as a plain no-op `if otlp.enabled {}` block (Task 5 fills it). `TelemetryGuard` is a struct whose `Drop`/`shutdown()` is a no-op for now.

- [ ] **Step 1: Add deps and `telemetry.rs`**; init order in `main()`: parse args → read+load config (pre-subscriber errors stay `eprintln!` — document with a comment: "logging config comes from the config file; errors before it loads go to bare stderr") → `let _guard = telemetry::init_telemetry(&config.observability.log.format, &config.log_level, &config.observability.otlp);` → everything after uses `tracing`.

- [ ] **Step 2: Convert the messages.** Every operational `eprintln!` after init becomes a leveled event with fields, e.g.:

```rust
tracing::info!(listener = %config.listen.http, "http listener bound");
tracing::error!(listener = %listen, error = %e, "bind https failed");
tracing::warn!(%warning, "config warning");
tracing::info!("shutting down");
```

Level mapping: bind/setup failures → `error!`; config warnings → `warn!`; listener-bound/startup/shutdown → `info!`. The pre-init messages (usage, config read/parse errors at main.rs lines ~78–103) stay `eprintln!`.

- [ ] **Step 3: Unit test** in `telemetry.rs`: with `tracing_subscriber::fmt().json().with_writer(...)` writing into a `Vec<u8>` test writer, emit one event and assert the output line parses as JSON with `"level"` and `"message"`-bearing `fields`. (Use a local subscriber via `tracing::subscriber::with_default`, not the global init, so tests don't fight over the global.)

- [ ] **Step 4: Run** — `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`; then the compose acceptance suite again — it must still PASS (audit stream unchanged on stderr; step-12 metrics unaffected). Manually eyeball one JSON log line in the compose output for shape.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: structured operational logs via tracing (json/text, stdout)"`

---

### Task 5: OTLP trace export

**Files:**
- Modify: root `Cargo.toml` + crate Cargo.tomls — add `tracing-opentelemetry`, `opentelemetry`, `opentelemetry_sdk` (features: `["trace", "rt-tokio"]`), `opentelemetry-otlp` (`default-features = false`, features `["trace", "http-proto"]`), `opentelemetry-http` (hyper-based client feature); dev-dep `opentelemetry-proto` (decode in tests). Current crate versions; if feature names have drifted, adapt per Global Constraints.
- Modify: `crates/hematite/src/telemetry.rs` (fill the OTLP branch), `crates/hematite/src/main.rs` (shutdown flush), `crates/hematite-proxy/src/http.rs` (root + child spans), `crates/hematite-proxy/src/dial.rs`, `crates/hematite-proxy/src/listen.rs` (tls.mitm span)
- Test: `crates/hematite/tests/otlp_export.rs` (in-process collector)

**Interfaces:**
- Consumes: `OtlpSection` (Task 1), `TelemetryGuard`/`init_telemetry` (Task 4).
- Produces: `TelemetryGuard::shutdown(self)` — flushes the span processor with a 5s cap; called after the ctrl_c await in `main` (wrap: `let guard = ...; tokio::signal::ctrl_c().await; tracing::info!("shutting down"); guard.shutdown();`).

- [ ] **Step 1: Exporter init** (inside `init_telemetry`'s OTLP branch): build an OTLP/HTTP-protobuf span exporter pointed at `{endpoint}/v1/traces` using a hyper-based HTTP client (opentelemetry-http's hyper client; wire hematite's existing hyper/hyper-util stack if the crate needs a client instance). SDK tracer provider: batch processor with the tokio runtime, `Sampler::TraceIdRatioBased(sample_ratio)` wrapped in `ParentBased` (fresh roots make ParentBased equivalent to the ratio sampler; use plain ratio if simpler), resource `service.name = service_name`. Layer: `tracing_opentelemetry::layer().with_tracer(tracer)` added to the same registry as the fmt layer. `TelemetryGuard` holds the provider; `shutdown()` calls the provider's shutdown inside `tokio::time::timeout(Duration::from_secs(5), …)` (or the blocking equivalent the SDK offers — adapt, report). Exporter errors must be logged throttled: install the SDK's error handler to a `tracing::warn!` capped by a simple `AtomicU64` counter that logs every Nth (N=100) failure.

- [ ] **Step 2: Spans.** In `http.rs` `handle()` (the fn that owns `PendingAudit`): create the root — `let span = tracing::info_span!("hematite.request", otel.name = "hematite.request", method = %summary.method, host = %summary.host, port = summary.port, path = %summary.path, mode = ?summary.mode, action = tracing::field::Empty, rejected_by = tracing::field::Empty, status = tracing::field::Empty);` — enter it for the request's duration (`.instrument()` on the async block or explicit `enter` in sync sections; async code MUST use `Instrument::instrument`, never hold a span guard across `.await`). At each `pending.emit(&record)` call site the record is final: `span.record("action", …); span.record("rejected_by", …); span.record("status", …)` just before emit (add a tiny helper `fn record_outcome(span: &tracing::Span, record: &AuditRecord)` in http.rs to avoid 15 duplicates). Child spans: `tracing::info_span!("dial", host = %host, port)` instrumenting `connect_upstream`'s body; `tracing::info_span!("upstream")` around send-request→first-byte in http.rs; `tracing::info_span!("tls.mitm", target = %mint_target)` around `cert_cache.get()` in listen.rs. NO other attributes — the redaction rule (Global Constraints) governs; never record headers, bodies, or query strings.
- Incoming `traceparent`: do nothing — no extractor is installed, so roots are always fresh; likewise no injector, so nothing is added upstream. Add one test-visible comment stating this is by design (spec: trust model).

- [ ] **Step 3: In-process collector test** (`crates/hematite/tests/otlp_export.rs`): start a hyper server on an ephemeral port capturing POST bodies to `/v1/traces` into a `Mutex<Vec<Vec<u8>>>`. Init telemetry with `otlp.enabled=true, endpoint=http://127.0.0.1:{port}, sample_ratio=1.0`. Emit a span carrying attributes `host="httpbin.org"` and a fake proxy token string constant `proxy-test-XYZ` in a variable that is deliberately NOT recorded on the span. Flush via `guard.shutdown()`. Assert: at least one body decodes via `opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest::decode` — NOTE: the `tonic` module path in opentelemetry-proto is just the codegen namespace and pulls prost, not tonic-the-transport; if the current crate offers a non-tonic-named proto module, prefer it — with a span named `hematite.request`-or-the-test-span-name and the `host` attribute present; and no captured body's bytes contain `proxy-test-XYZ` (`!body.windows(len).any(...)`). Also assert with `otlp.enabled=false` that no request ever arrives (collector Vec stays empty after emitting + dropping the guard).

- [ ] **Step 4: Run everything** — `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`; `cargo tree | grep -E 'tonic|reqwest'` → MUST print nothing (prost is expected and fine; tonic/reqwest are not); compose acceptance suite → PASS (otlp defaults off; nothing changes).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: OTLP/HTTP trace export with per-request spans"`

---

### Task 6: Spec + docs

**Files:**
- Modify: `spec/09-config.md` (observability section schema + validation + defaults table rows), `spec/08-audit.md` (add the telemetry redaction rule as a short cross-referenced subsection: "anything not permitted in an audit record is not permitted in a span attribute, metric label, or log field"), `spec/appendix-e-crate-map.md` (dependency budget amendment: add tracing, tracing-subscriber, tracing-opentelemetry, opentelemetry, opentelemetry_sdk, opentelemetry-otlp (http-proto; explicitly no tonic/reqwest), prost (transitive), opentelemetry-proto (dev-dep) — one sentence of rationale each), and the management-API section of `spec/09-config.md` (`GET /metrics`, auth-exempt, gated by `observability.metrics.enabled`)
- Modify: `docs/configuration.md` (observability section reference, matching the shipped defaults and env-override names), `docs/kubernetes.md` (metrics ride the management Service port; example `observability` block; note that a locked-down client can reach `/metrics` when the management port is exposed — aggregates only, no per-host data), `spec/appendix-a-acceptance.md` (step 12)
- Test: accuracy cross-check

**Interfaces:**
- Consumes: everything shipped in Tasks 1–5; the design doc `docs/superpowers/specs/2026-08-11-observability-design.md` is the content source.

- [ ] **Step 1: Write the spec changes.** Match each file's existing structure and tone (normative MUST/SHOULD style in spec/, reference style in docs/). The Part 09 schema must list exact keys, defaults, and the three validation errors as implemented in Task 1. The metric table from the design doc goes into docs/configuration.md (it is operational reference, not normative spec) — copy the table as shipped, including `hematite_tls_leaf_cache_events_total`.

- [ ] **Step 2: Accuracy pass.** Every config key, default, metric name, and label in the docs must match the code exactly — grep the implementation for each name as you write it. Every env var mentioned must appear in ENV_KEYS.

- [ ] **Step 3: Run the full local gate** — `cargo test --workspace && tests/chart/render-test.sh` → PASS (docs-only change; this is the regression tripwire).

- [ ] **Step 4: Commit** — `git add spec docs && git commit -m "docs: observability spec (Part 09, Part 08 redaction rule, Appendix E budget) and operator docs"`
