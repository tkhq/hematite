//! Telemetry initialisation — structured operational logs (Task 4) and
//! OTLP trace export (Task 5, no-op placeholder here).

use hematite_proxy::config::OtlpSection;
use tracing_subscriber::EnvFilter;

/// Owned guard that keeps the telemetry pipeline alive for the process
/// lifetime.  Drop is intentionally a no-op until Task 5 wires in an
/// OTLP exporter that needs explicit shutdown.
pub struct TelemetryGuard {
    // Task 5 will add an opentelemetry SDK handle here so that
    // `shutdown()` / `Drop` can flush the exporter.
    _priv: (),
}

impl TelemetryGuard {
    /// Explicit shutdown (no-op until Task 5).
    #[allow(dead_code)]
    pub fn shutdown(self) {
        // Task 5: flush OTLP exporter.
    }
}

/// Install the global tracing subscriber and return a guard.
///
/// `format` — `"json"` (default) emits newline-delimited JSON to stdout;
/// any other value uses compact plain text.
///
/// `level` — passed verbatim to [`EnvFilter`]; e.g. `"info"`, `"debug"`.
///
/// `otlp` — Task 5 fills this branch; the `enabled` guard is here so the
/// call-site signature doesn't change when OTLP is wired in.
pub fn init_telemetry(format: &str, level: &str, otlp: &OtlpSection) -> TelemetryGuard {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

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

    // OTLP branch — no-op until Task 5.
    if otlp.enabled {
        // Task 5: initialise opentelemetry-otlp exporter here.
    }

    TelemetryGuard { _priv: () }
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
