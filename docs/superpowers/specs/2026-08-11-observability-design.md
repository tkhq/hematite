# Observability — design

Date: 2026-08-11
Status: approved for planning

## Goal

Give hematite production observability: Prometheus metrics, structured
operational logs, and OTLP trace export. The audit stream (Part 08) is
already the structured record of every request; this work adds the
operational layer around it without touching it.

## Decisions

| Decision | Choice |
|---|---|
| Metrics endpoint | `GET /metrics` on the existing management listener, exempt from bearer auth (the rest of the management API keeps auth). No management listener → no metrics. |
| Structured logs | Convert operational `eprintln!` output to `tracing` JSON events on stdout. The audit stream on stderr is untouched — it is normative and schema-closed. |
| OTLP stack | opentelemetry SDK over OTLP/HTTP-protobuf via a hyper-based client. No tonic (gRPC), no reqwest. |
| Trace context | Always fresh root spans. Incoming `traceparent` is ignored (the client is the adversary — forged context must not bias operator telemetry), and hematite injects no `traceparent` upstream. |
| Prometheus dependency | None — hand-rolled registry (fixed metric set, atomics + text exposition, ~150 lines, unit-tested). The dependency budget is spent on the OTLP stack instead. |
| Dependency budget | Appendix E amended in the same PR: add `tracing`, `tracing-subscriber` (json), `tracing-opentelemetry`, `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp` (http-proto), transitively `prost`. One sentence of rationale per crate. The kernel crate stays dependency-free. |

## Config (Part 09 gains an optional `observability` section)

```yaml
observability:
  metrics:
    enabled: true            # default true
  log:
    format: json             # json | text; default json. log.level unchanged.
  otlp:
    enabled: false           # default off
    endpoint: "http://collector:4318"   # OTLP/HTTP base URL; required when enabled
    sample_ratio: 1.0        # head sampling, 0.0–1.0, default 1.0
    service_name: "hematite" # resource attribute service.name
```

Env overrides follow the existing `HEMATITE_<SECTION>_<KEY>` mechanism
(`HEMATITE_OBSERVABILITY_OTLP_ENDPOINT`, …). The current override
walker only handles two-segment paths; it is generalized to N segments
as part of this work (behavior for existing two-segment keys unchanged). Validation fails fast at
boot: `otlp.enabled` without `endpoint` is an error; `sample_ratio`
outside [0,1] is an error.

## The telemetry redaction rule (normative, cross-referenced from Part 08)

Anything not permitted in an audit record is not permitted in a span
attribute, metric label, or log field. The `Secret` type's
no-Display/no-Serialize guarantees enforce this at compile time, exactly
as they do for audit today.

## Metrics

Hand-rolled registry in `hematite-proxy` (`observability.rs`):
counters and histograms on atomics, Prometheus text exposition format
(`# TYPE` lines, label escaping), served by the management listener.

Fixed metric set — all values derived from data already at the audit
emission point (no new plumbing through the kernel):

| Metric | Type | Labels |
|---|---|---|
| `hematite_requests_total` | counter | `mode` (http / https / tunnel), `action`, `rejected_by` (transform name, "listener", "guard", or `""`) |
| `hematite_request_duration_seconds` | histogram | `mode`, `action`; buckets 0.005–30s (fixed) |
| `hematite_upstream_dials_total` | counter | `result`: ok / guard-denied / dns-error / connect-error / tls-error |
| `hematite_dns_queries_total` | counter | `outcome`: intercept / static / passthrough / error |
| `hematite_tls_leaf_cache_events_total` | counter | `event`: hit / miss |
| `hematite_secrets_swaps_total` | counter | `result`: swapped / missing-required / source-error. No secret-name label. |
| `hematite_config_reloads_total` | counter | `result`: ok / error |
| `hematite_build_info` | gauge (1) | `version` |

Every label is a closed enum or the fixed transform list — cardinality
is bounded by construction. Deliberately absent: per-host labels
(unbounded cardinality; leaks allowlist traffic patterns through an
unauthenticated endpoint — per-host data lives in the audit stream).

## Structured logs

- All operational `eprintln!` calls (startup, binds, reload, shutdown,
  warnings — in `main.rs`, listeners, management) become `tracing`
  events with structured fields.
- A `tracing-subscriber` layer renders one JSON object per line on
  **stdout**: `{"ts","level","target","message",...fields}`. `log.level`
  filters; `log.format: text` keeps a human-readable single-line format
  for local dev.
- Audit records keep their exclusive claim on **stderr**, byte-for-byte
  as today. Acceptance step 10's "grep every log for the secret" sweeps
  both streams.

## Tracing

- One root span per accepted request: `hematite.request`, created at
  the listener. Child spans: `dial` (resolve + guard + connect),
  `tls.mitm` (leaf mint/cache), `upstream` (request → first response
  byte).
- Span attributes mirror the audit record's non-secret fields only:
  method, host, port, path, mode, action, rejected_by, status.
- Fresh roots always; no traceparent in, no traceparent out. Header
  handling stays exactly as Part 04 specifies.
- Export path: `tracing-opentelemetry` layer → batch span processor →
  OTLP/HTTP-protobuf to `otlp.endpoint`. Head sampling at
  `sample_ratio`; sampled-out requests skip span creation.
- Exporter failure is logged (throttled) and never affects request
  handling. Shutdown flushes with a 5-second cap.
- When `otlp.enabled: false` (default), no exporter, no batch task, no
  per-request span overhead beyond the tracing layer's filtered no-op.

## Testing

- Unit: metrics registry (increment → exposition golden test), label
  derivation from audit records, JSON log format via a captured
  subscriber, sampler edges (0.0 / 1.0), config validation errors.
- Acceptance (compose + k3s inherit via the shared `run.sh`): a new
  step curls `/metrics` after the existing steps and asserts (a)
  `hematite_requests_total` counts reflect the run (e.g. a nonzero
  `action="reject"` count), (b) no hostname string appears anywhere in
  the exposition output, (c) `/v1/reload` still requires auth while
  `/metrics` does not.
- OTLP: in-process integration test with a local hyper server as a
  stand-in collector — asserts protobuf-decodable spans with expected
  attributes, and that a secret proxy-token never appears in exported
  payload bytes. The docker/k3s harnesses stay collector-free
  (`otlp.enabled` defaults off).

## Docs and chart

- `docs/configuration.md`: the `observability` section.
- `docs/kubernetes.md`: `/metrics` rides the management Service port
  (`service.management.enabled`); example `observability` block; note
  that a locked-down client can reach `/metrics` when the management
  port is exposed (aggregates only, no per-host data — see the metrics
  cardinality rationale).
- Chart: no template changes needed (`values.config` passthrough).

## Spec changes (same PR as the implementation, per repo convention)

- Part 09: `observability` section schema + validation rules.
- Part 09 §4 (management API): `GET /metrics`, auth exemption.
- Part 08: unchanged, plus the cross-referenced telemetry redaction
  rule above.
- Appendix E: dependency budget amendment.

## Out of scope

- Honoring or propagating W3C trace context (could be a config flag
  later; the trust model argues against it).
- Per-host or per-secret metric labels.
- Metrics for the kernel crate itself (stays dependency-free).
- Grafana dashboards / alert rules (ship raw metrics first).
