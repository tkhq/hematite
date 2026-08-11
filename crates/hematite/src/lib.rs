//! Library face of the hematite crate — used exclusively by integration tests
//! in `tests/`.  The binary target at `src/main.rs` is the entry point for
//! production use.

pub mod telemetry;

/// Test-only helpers.  Exposed via the lib target so integration tests can
/// reach them without going through the binary's `main`.
pub mod telemetry_for_test {
    use hematite_proxy::config::OtlpSection;
    use opentelemetry_sdk::trace::SdkTracerProvider;

    /// Build an OTLP tracer provider without installing any global tracing
    /// subscriber.  The returned provider can be used with
    /// `tracing::subscriber::with_default` in tests that need span isolation.
    pub fn build_provider_for_test(otlp: &OtlpSection) -> SdkTracerProvider {
        crate::telemetry::build_otlp_provider(otlp)
    }

    /// Re-export `TelemetryGuard` so test files can name the type.
    pub use crate::telemetry::TelemetryGuard;
}
