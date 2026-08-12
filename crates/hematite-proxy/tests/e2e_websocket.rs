//! Part 05 §5 — a WebSocket handshake that passes the pipeline is forwarded;
//! on the upstream 101 the proxy switches to bidirectional byte copy. The
//! proxy does not interpret frames, so a raw upstream (dummy 101 + echo)
//! exercises the full path.

use std::sync::{Arc, Mutex};

use hematite_kernel::audit::{Action, AuditRecord};
use hematite_kernel::config::{build_pipeline, TransformSpec};
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::http::serve_http;
use hematite_proxy::state::{Guard, Runtime, SharedState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Default)]
struct TestSink(Mutex<Vec<AuditRecord>>);
impl AuditSink for TestSink {
    fn emit(&self, r: &AuditRecord, _l: Level) {
        self.0.lock().unwrap().push(r.clone());
    }
}

/// Raw WebSocket-ish upstream: replies 101, then echoes bytes with a `>`
/// prefix so the client can tell the round trip happened.
async fn spawn_ws_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // Read the handshake request head.
                let mut head = Vec::new();
                let mut tmp = [0u8; 512];
                loop {
                    let n = s.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&tmp[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                s.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();
                // Echo post-upgrade bytes with a prefix.
                loop {
                    let n = s.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let mut out = b">".to_vec();
                    out.extend_from_slice(&tmp[..n]);
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_upgrade_and_byte_copy() {
    let upstream_port = spawn_ws_upstream().await;
    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "cidrs": ["127.0.0.1/32"] } }
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
    let sink = Arc::new(TestSink::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_http(listener, state, sink.clone()));

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let handshake = format!(
        "GET http://127.0.0.1:{upstream_port}/ws HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    client.write_all(handshake.as_bytes()).await.unwrap();

    // Read the 101 response head.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = client.read(&mut tmp).await.unwrap();
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    assert!(head.contains("101 Switching Protocols"), "no 101: {head}");

    // Post-upgrade: bytes flow through the byte copy both ways.
    client.write_all(b"hello").await.unwrap();
    let mut echoed = [0u8; 16];
    let n = client.read(&mut echoed).await.unwrap();
    assert_eq!(&echoed[..n], b">hello", "byte copy did not round-trip");

    // Audit reflects the handshake result.
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let records = sink.0.lock().unwrap().clone();
    let ws = records.iter().find(|r| r.path == "/ws").expect("ws record");
    assert_eq!(ws.action, Action::Allow);
    assert_eq!(ws.status_code, Some(101));
}
