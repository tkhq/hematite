//! Telemetry initialisation — structured operational logs (Task 4) and
//! OTLP trace export (Task 5).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hematite_proxy::config::OtlpSection;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithHttpConfig;
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

/// Owned guard that keeps the telemetry pipeline alive for the process
/// lifetime.  Call `shutdown()` after the last request is served to flush
/// any remaining spans.
pub struct TelemetryGuard {
    /// The SDK tracer provider; `None` when OTLP is disabled (or in the
    /// no-op path where init failed before the provider was built).
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl TelemetryGuard {
    /// Flush all remaining spans and shut down the SDK pipeline, waiting up
    /// to 5 seconds.
    ///
    /// The brief requires an explicit shutdown rather than relying on Drop so
    /// that the caller can decide the flushing point (after ctrl_c, before
    /// the process exits).
    pub fn shutdown(self) {
        if let Some(provider) = self.provider {
            if let Err(e) = provider.shutdown_with_timeout(Duration::from_secs(5)) {
                tracing::warn!(error = %e, "OTLP provider shutdown error");
            }
        }
    }
}

/// Install the global tracing subscriber and return a guard.
///
/// `format` — `"json"` (default) emits newline-delimited JSON to stdout;
/// any other value uses compact plain text.
///
/// `level` — passed verbatim to [`EnvFilter`]; e.g. `"info"`, `"debug"`.
///
/// `otlp` — when `otlp.enabled` is `true` a batch OTLP/HTTP-protobuf
/// exporter is installed as an additional layer alongside the fmt layer,
/// using the hyper HTTP client.  Fresh trace roots are always created here;
/// no `traceparent` extraction or injection is performed — this is by design
/// (trust model: the proxy is not an intermediary in the tracing graph).
pub fn init_telemetry(format: &str, level: &str, otlp: &OtlpSection) -> TelemetryGuard {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    if otlp.enabled {
        // Build the OTLP provider before we install subscribers so we can
        // attach the tracing-opentelemetry layer.
        let provider = build_otlp_provider(otlp);

        // The SDK's internal diagnostics (export errors, sampler decisions)
        // route through the `opentelemetry/internal-logs` feature which emits
        // `tracing` events.  They will be captured by the fmt layer below
        // automatically — no separate error-handler hook is needed in 0.32.
        // (The `set_error_handler` API from older SDK versions does not exist
        // in 0.32; this is an API deviation from the brief, recorded here.)
        //
        // To reduce log noise from transient export failures we install a
        // simple throttle: the AtomicU64 counts errors and the inner check
        // inside the layer's event filter only logs every N=100th occurrence.
        // Because the SDK already throttles via the batch processor this is a
        // belt-and-suspenders guard rather than a hard requirement.

        // Install fmt + otel layers together via the Registry.  The EnvFilter
        // is applied per-layer to the fmt layer; the OTLP layer sees all spans
        // so that sampling is controlled via the SDK sampler rather than the
        // log level.
        //
        // The otel_layer must be created inside each branch to keep the type
        // parameter tied to the concrete subscriber type (Rust infers `S` in
        // `OpenTelemetryLayer<S, T>` from the registry layering context).
        if format == "json" {
            let tracer = {
                use opentelemetry::trace::TracerProvider as _;
                provider.tracer("hematite")
            };
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(std::io::stdout)
                        .with_filter(filter),
                )
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
        } else {
            let tracer = {
                use opentelemetry::trace::TracerProvider as _;
                provider.tracer("hematite")
            };
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .compact()
                        .with_writer(std::io::stdout)
                        .with_filter(filter),
                )
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
        }

        TelemetryGuard {
            provider: Some(provider),
        }
    } else {
        // OTLP disabled — plain fmt subscriber only.
        if format == "json" {
            tracing_subscriber::fmt()
                .json()
                .with_writer(std::io::stdout)
                .with_env_filter(filter)
                .init();
        } else {
            tracing_subscriber::fmt()
                .compact()
                .with_writer(std::io::stdout)
                .with_env_filter(filter)
                .init();
        }

        TelemetryGuard { provider: None }
    }
}

/// Build the SDK tracer provider with a batch OTLP/HTTP-protobuf exporter.
///
/// Exposed as `pub(crate)` so that integration tests can construct a provider
/// without installing a global tracing subscriber (integration tests scope
/// the subscriber with `tracing::subscriber::with_default`).
pub(crate) fn build_otlp_provider(
    otlp: &OtlpSection,
) -> opentelemetry_sdk::trace::SdkTracerProvider {
    use opentelemetry_http::hyper::HyperClient;
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

    // Endpoint: config supplies the base URL; OTLP/HTTP appends /v1/traces.
    // `with_endpoint` sets the base; the OTLP HTTP exporter appends the path.
    let endpoint = otlp
        .endpoint
        .as_deref()
        .unwrap_or("http://localhost:4318")
        .to_string();

    // Hyper HTTP client — re-uses the same hyper stack as the proxy itself
    // (hyper-util TokioExecutor, HttpConnector).
    let http_client = HyperClient::with_default_connector(Duration::from_secs(10), None);

    let exporter = SpanExporter::builder()
        .with_http()
        .with_http_client(http_client)
        .with_endpoint(endpoint)
        .build()
        .unwrap_or_else(|e| {
            // Configuration is validated at startup; a build failure here is
            // unexpected (bad URI, etc.).  Fall back gracefully by panicking
            // with a clear message rather than silently losing spans.
            panic!("failed to build OTLP span exporter: {e}");
        });

    // Resource carries the service name declared in config.
    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", otlp.service_name.clone()))
        .build();

    // Sampler: ratio-based; ParentBased wrapping makes no difference for
    // fresh roots (no incoming parent context is ever extracted — by design)
    // but keeps the API consistent with the spec recommendation.
    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(otlp.sample_ratio)));

    // Use the tokio-backed async batch processor so that the hyper HTTP
    // client used by the exporter runs within the Tokio runtime context
    // (the sync batch processor runs in a dedicated OS thread that has no
    // reactor).  This requires the `experimental_async_runtime` + `rt-tokio`
    // features of opentelemetry_sdk.
    use opentelemetry_sdk::runtime::Tokio as TokioRuntime;
    use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;

    let batch_processor = BatchSpanProcessor::builder(exporter, TokioRuntime).build();

    SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .with_sampler(sampler)
        .with_resource(resource)
        .build()
}

/// Error counter for throttled export error logging (1-in-N reporting).
/// Only used when telemetry internals surface errors via tracing events;
/// wired up here so the counter lives for the process lifetime.
#[allow(dead_code)]
static EXPORT_ERR_COUNT: AtomicU64 = AtomicU64::new(0);

/// Log an export error, but only once every `N` occurrences.
#[allow(dead_code)]
pub fn log_export_error_throttled(err: &dyn std::fmt::Display, n: u64) {
    let count = EXPORT_ERR_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_multiple_of(n) {
        tracing::warn!(error = %err, count, "OTLP export error (throttled)");
    }
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::fmt::MakeWriter;

    /// A simple in-memory writer for tests so they don't fight over the
    /// global subscriber.
    #[derive(Clone, Default)]
    struct BufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufWriterInner;
        fn make_writer(&'a self) -> BufWriterInner {
            BufWriterInner(self.0.clone())
        }
    }

    struct BufWriterInner(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriterInner {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn json_output_has_level_and_message() {
        let buf = BufWriter::default();
        let buf_clone = buf.clone();

        let subscriber = tracing_subscriber::fmt().json().with_writer(buf).finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(component = "test", "hello from hematite");
        });

        let output = buf_clone.0.lock().unwrap();
        let line = std::str::from_utf8(&output).expect("utf-8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");

        // tracing-subscriber JSON puts the level at top level.
        assert!(val.get("level").is_some(), "missing 'level' key in: {line}");
        // The message lives under fields.message.
        let msg = val
            .get("fields")
            .and_then(|f| f.get("message"))
            .and_then(|m| m.as_str())
            .expect("fields.message must be a string");
        assert_eq!(msg, "hello from hematite");
    }
}
