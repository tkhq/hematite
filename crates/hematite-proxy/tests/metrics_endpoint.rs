//! Integration test for the management server's `GET /metrics` route.
//!
//! Boots a real in-process management listener via `serve_management`, then
//! drives it with raw HTTP/1.1 over a plain TcpStream (mirroring the style
//! of `acceptance_inproc.rs`).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use hematite_proxy::config::{build_runtime, load_str};
use hematite_proxy::management::serve_management;
use hematite_proxy::metrics::Metrics;
use hematite_proxy::state::SharedState;

fn no_env(_: &str) -> Option<String> {
    None
}

/// Boot the management listener and return the ephemeral port.
async fn spawn_management(metrics: Arc<Metrics>, metrics_enabled: bool, api_key: &str) -> u16 {
    let api_key_owned = api_key.to_string();
    // We need a real config/state to satisfy serve_management.
    let config = load_str(
        "transforms:\n  - name: allowlist\n    config:\n      domains: [\"example.com\"]\n",
        &no_env,
    )
    .unwrap();
    let runtime = build_runtime(&config).unwrap();
    let state = SharedState::new(runtime);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(serve_management(
        listener,
        state,
        api_key_owned,
        std::path::PathBuf::from("/dev/null"),
        config.listen,
        metrics,
        metrics_enabled,
    ));
    // Brief yield so the spawned server has time to enter its accept loop.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    port
}

/// Send a raw HTTP/1.1 request; return the response as a String.
async fn raw_http(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    // Don't call shutdown() — let hyper close the connection when it sees
    // Connection: close, then we read until EOF.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

/// Extract the HTTP status line (first line of response).
fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("")
}

#[tokio::test(flavor = "multi_thread")]
async fn get_metrics_returns_200_with_build_info() {
    let metrics = Metrics::new("test-version");
    let port = spawn_management(metrics, true, "test-key").await;

    let response = raw_http(
        port,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        status_line(&response).starts_with("HTTP/1.1 200"),
        "expected 200, got: {response}"
    );
    assert!(
        response.contains("hematite_build_info"),
        "missing build_info in body: {response}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_metrics_no_auth_required() {
    // GET /metrics must succeed WITHOUT an Authorization header.
    let metrics = Metrics::new("test-version");
    let port = spawn_management(metrics, true, "secret-key").await;

    let response = raw_http(
        port,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        status_line(&response).starts_with("HTTP/1.1 200"),
        "expected 200 without auth, got: {response}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn post_reload_without_auth_returns_401() {
    // Auth must remain intact on all non-metrics routes.
    let metrics = Metrics::new("test-version");
    let port = spawn_management(metrics, true, "secret-key").await;

    let response = raw_http(
        port,
        "POST /v1/reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        status_line(&response).starts_with("HTTP/1.1 401"),
        "expected 401 without auth, got: {response}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_metrics_when_disabled_returns_404() {
    // metrics_enabled=false → 404 for GET /metrics.
    let metrics = Metrics::new("test-version");
    let port = spawn_management(metrics, false, "secret-key").await;

    let response = raw_http(
        port,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        status_line(&response).starts_with("HTTP/1.1 404"),
        "expected 404 when disabled, got: {response}"
    );
}
