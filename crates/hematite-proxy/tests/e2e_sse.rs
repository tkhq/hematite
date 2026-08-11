//! Part 05 §5 — an SSE (text/event-stream) response is streamed with a
//! flush per chunk, never buffered end-to-end. A raw upstream emits one
//! event, pauses, then a second; the client must receive the first well
//! before the stream closes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hematite_kernel::config::{build_pipeline, TransformSpec};
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::http::serve_http;
use hematite_proxy::state::{Guard, Runtime, SharedState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct NullSink;
impl AuditSink for NullSink {
    fn emit(&self, _r: &hematite_kernel::audit::AuditRecord, _l: Level) {}
}

const GAP: Duration = Duration::from_millis(300);

/// Raw SSE upstream: header, "one", flush, pause GAP, "two", close.
async fn spawn_sse_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut tmp = [0u8; 1024];
                let _ = s.read(&mut tmp).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = s.write_all(b"data: one\n\n").await;
                let _ = s.flush().await;
                tokio::time::sleep(GAP).await;
                let _ = s.write_all(b"data: two\n\n").await;
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_streams_incrementally() {
    let upstream_port = spawn_sse_upstream().await;
    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "cidrs": ["127.0.0.1/32"] } }
    ]))
    .unwrap();
    let runtime = Runtime {
        pipeline: build_pipeline(&specs).unwrap().pipeline,
        guard: Guard::new(&[]).unwrap(),
        max_request_body_bytes: 1 << 20,
        upstream_response_header_timeout: Duration::from_secs(5),
        dial_timeout: Duration::from_secs(5),
        upstream_tls: hematite_proxy::state::native_upstream_config().unwrap(),
        cert_cache: None,
    };
    let state = SharedState::new(runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_http(listener, state, Arc::new(NullSink)));

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{upstream_port}/events HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();

    // Read until we see the first event; record when.
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 512];
    let mut first_event_at = None;
    loop {
        let n = client.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if first_event_at.is_none() && buf.windows(9).any(|w| w == b"data: one") {
            first_event_at = Some(start.elapsed());
        }
        if buf.windows(9).any(|w| w == b"data: two") {
            break;
        }
    }
    let total = start.elapsed();
    let text = String::from_utf8_lossy(&buf);

    assert!(text.contains("text/event-stream"), "content-type not forwarded: {text}");
    assert!(text.contains("data: one") && text.contains("data: two"), "events missing: {text}");
    let first = first_event_at.expect("first event received");
    // The first event arrived well before the second was even sent — proof
    // the body was not buffered end-to-end.
    assert!(
        total - first >= GAP / 2,
        "stream appears buffered: first at {first:?}, total {total:?}"
    );
}
