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
    ///
    /// Returns an error string if the exporter cannot be built (e.g. invalid
    /// endpoint URI). Must be called within a tokio runtime context.
    pub fn build_provider_for_test(otlp: &OtlpSection) -> Result<SdkTracerProvider, String> {
        crate::telemetry::build_otlp_provider(otlp)
    }

    /// Exercises the production `enabled` decision path: returns `Ok(Some)` when
    /// `otlp.enabled = true` and `Ok(None)` when `false`.  Used by the disabled-case
    /// integration test to verify the real code path, not a bare registry.
    pub fn build_provider_if_enabled_for_test(
        otlp: &OtlpSection,
    ) -> Result<Option<SdkTracerProvider>, String> {
        crate::telemetry::build_otlp_provider_if_enabled(otlp)
    }

    /// Wrap an existing provider in a `TelemetryGuard` so tests can exercise
    /// `TelemetryGuard::shutdown` directly.
    pub fn guard_from_provider(provider: SdkTracerProvider) -> TelemetryGuard {
        TelemetryGuard::from_provider(provider)
    }

    /// Re-export `TelemetryGuard` so test files can name the type.
    pub use crate::telemetry::TelemetryGuard;
}
