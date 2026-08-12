//! Part 02 §5 / Part 01 §1 — the wire casing of forwarded header names is
//! preserved. A raw upstream inspects the literal request bytes (a hyper
//! echo would re-lowercase them), so this observes what actually egresses.

use std::sync::Arc;

use hematite_kernel::config::{build_pipeline, TransformSpec};
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::http::serve_http;
use hematite_proxy::state::{Guard, Runtime, SharedState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct NullSink;
impl AuditSink for NullSink {
    fn emit(&self, _record: &hematite_kernel::audit::AuditRecord, _level: Level) {}
}

/// A raw upstream: reads the request head and returns it verbatim as the
/// response body, so the caller can inspect the exact bytes forwarded.
async fn spawn_raw_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    head.len(),
                    head
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarded_header_name_casing_is_preserved() {
    let upstream_port = spawn_raw_upstream().await;

    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "cidrs": ["127.0.0.1/32"] } },
        { "name": "header_allowlist",
          "config": { "headers": ["Host", "X-CaMeL-Case", "Connection"] } }
    ]))
    .unwrap();
    let runtime = Runtime {
        pipeline: build_pipeline(&specs).unwrap().pipeline,
        guard: Guard::new(&[]).unwrap(),
        max_request_body_bytes: 1 << 20,
        upstream_response_header_timeout: std::time::Duration::from_secs(5),
        dial_timeout: std::time::Duration::from_secs(5),
        upstream_tls: hematite_proxy::state::native_upstream_config().unwrap(),
        cert_cache: None,
        metrics: hematite_proxy::metrics::Metrics::new("test"),
        pool: hematite_proxy::pool::Pool::new(),
    };
    let state = SharedState::new(runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_http(listener, state, Arc::new(NullSink)));

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         X-CaMeL-Case: hi\r\n\
         Connection: close\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();

    assert!(response.contains("HTTP/1.1 200"), "resp: {response}");
    // The upstream saw the original mixed casing, not a lowercased name.
    assert!(
        response.contains("X-CaMeL-Case:"),
        "forwarded header name was not preserved: {response}"
    );
    assert!(
        !response.contains("x-camel-case:"),
        "header name reached upstream lowercased: {response}"
    );
}
