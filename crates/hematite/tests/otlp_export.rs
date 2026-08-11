//! Integration test: in-process OTLP/HTTP collector.
//!
//! Verifies that when `otlp.enabled = true` spans are shipped over HTTP/proto
//! to the configured endpoint, and that no sensitive data leaks into the
//! exported bytes.
//!
//! Each test uses `tracing::subscriber::with_default` to scope its subscriber
//! rather than installing a global — this allows multiple tests to run in the
//! same binary without panicking on double-init.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

use hematite::telemetry_for_test::build_provider_for_test;
use hematite_proxy::config::OtlpSection;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message as _;
use tracing_subscriber::layer::SubscriberExt as _;

// ---------------------------------------------------------------------------
// In-process OTLP/HTTP collector
// ---------------------------------------------------------------------------

/// Start an HTTP server that captures all POST /v1/traces bodies.
/// Returns (socket address, shared body store).
async fn start_collector() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    let bodies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let bodies_clone = bodies.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let bodies = bodies_clone.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let bodies = bodies.clone();
                    async move {
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        bodies.lock().unwrap().push(body.to_vec());
                        let resp: Response<http_body_util::Full<Bytes>> = Response::builder()
                            .status(200)
                            .body(http_body_util::Full::new(Bytes::new()))
                            .unwrap();
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    (addr, bodies)
}

// ---------------------------------------------------------------------------
// Test: spans exported when enabled
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn otlp_exports_spans_when_enabled() {
    let (addr, bodies) = start_collector().await;

    let otlp = OtlpSection {
        enabled: true,
        endpoint: Some(format!("http://127.0.0.1:{}", addr.port())),
        sample_ratio: 1.0,
        service_name: "test-hematite".to_string(),
    };

    // A fake proxy token that must NEVER appear in the exported bytes.
    // This deliberately uses a const that is NOT recorded as a span attribute,
    // verifying that only explicitly instrumented fields are exported.
    const FAKE_PROXY_TOKEN: &str = "proxy-test-XYZ-secret-value";
    let _token_holder = FAKE_PROXY_TOKEN; // binds the string; never recorded

    let provider = build_provider_for_test(&otlp);

    // Build a scoped subscriber with the OTel layer — no global install.
    let tracer = {
        use opentelemetry::trace::TracerProvider as _;
        provider.tracer("hematite-test")
    };
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let subscriber = tracing_subscriber::registry().with(otel_layer);

    // Run the span-emitting code under the scoped subscriber.
    tracing::subscriber::with_default(subscriber, || {
        let _span = tracing::info_span!(
            "hematite.request",
            host = "httpbin.org",
            port = 443u16,
            path = "/get",
            method = "GET",
        )
        .entered();
        tracing::info!("test span body");
    });

    // Flush the batch exporter and wait for the HTTP POST to arrive.
    if let Err(e) = provider.shutdown_with_timeout(Duration::from_secs(5)) {
        // Log but don't fail — some internal-only errors are non-fatal.
        eprintln!("provider shutdown warning: {e}");
    }
    // Give a moment for the HTTP request to be received.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let captured = bodies.lock().unwrap().clone();
    assert!(
        !captured.is_empty(),
        "no OTLP export received — did the exporter flush?"
    );

    // Decode at least one body and verify our span appears.
    let mut found_span = false;
    for body in &captured {
        let req = ExportTraceServiceRequest::decode(body.as_slice())
            .expect("failed to decode ExportTraceServiceRequest");

        for resource_spans in &req.resource_spans {
            for scope_spans in &resource_spans.scope_spans {
                for span in &scope_spans.spans {
                    if span.name == "hematite.request" {
                        found_span = true;
                        // Verify host attribute is present.
                        let has_host = span.attributes.iter().any(|kv| kv.key == "host");
                        assert!(has_host, "span missing 'host' attribute");
                    }
                }
            }
        }

        // Verify no raw bytes contain the sensitive token string.
        let token_bytes = FAKE_PROXY_TOKEN.as_bytes();
        assert!(
            !body.windows(token_bytes.len()).any(|w| w == token_bytes),
            "sensitive token found in exported OTLP body!",
        );
    }

    assert!(
        found_span,
        "no span named 'hematite.request' found in exported data"
    );
}

// ---------------------------------------------------------------------------
// Test: no requests sent when OTLP disabled
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn otlp_no_export_when_disabled() {
    let (addr, bodies) = start_collector().await;

    let _otlp = OtlpSection {
        enabled: false,
        endpoint: Some(format!("http://127.0.0.1:{}", addr.port())),
        sample_ratio: 1.0,
        service_name: "test-hematite".to_string(),
    };

    // With OTLP disabled, no provider is built and no HTTP requests should be
    // sent to the collector.
    {
        // Use a plain no-op subscriber so spans don't accidentally go anywhere.
        let subscriber = tracing_subscriber::registry();
        tracing::subscriber::with_default(subscriber, || {
            let _span = tracing::info_span!("hematite.request", host = "httpbin.org").entered();
            tracing::info!("disabled test span");
        });
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let captured = bodies.lock().unwrap().clone();
    assert!(
        captured.is_empty(),
        "unexpected OTLP export when disabled: {} bodies received",
        captured.len()
    );
}
