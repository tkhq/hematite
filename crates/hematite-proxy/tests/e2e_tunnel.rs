//! Part 05 §4 end-to-end: the tunnel listener over real sockets. CONNECT to
//! an allowlisted host with a plain-HTTP inner request, and a CONNECT to a
//! blocked host rejected at the handshake.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use hematite_kernel::audit::{Action, AuditRecord};
use hematite_kernel::config::{build_pipeline, TransformSpec};
use hematite_kernel::summary::Mode;
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::listen::serve_tunnel;
use hematite_proxy::state::{Guard, Runtime, SharedState};

#[derive(Default)]
struct TestSink(Mutex<Vec<AuditRecord>>);
impl AuditSink for TestSink {
    fn emit(&self, record: &AuditRecord, _level: Level) {
        self.0.lock().unwrap().push(record.clone());
    }
}
impl TestSink {
    fn records(&self) -> Vec<AuditRecord> {
        self.0.lock().unwrap().clone()
    }
}

async fn spawn_http_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(
                        format!("echo:{}", req.uri().path()),
                    ))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .half_close(true)
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    port
}

async fn spawn_tunnel_proxy(pipeline: hematite_kernel::pipeline::Pipeline) -> (u16, Arc<TestSink>) {
    let runtime = Runtime {
        pipeline,
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
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_tunnel(listener, state, sink.clone()));
    (port, sink)
}

fn pipeline_allowing(host: &str) -> hematite_kernel::pipeline::Pipeline {
    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "domains": [host], "cidrs": ["127.0.0.1/32"] } }
    ]))
    .unwrap();
    build_pipeline(&specs).unwrap().pipeline
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_tunnel_plain_http_inner() {
    let upstream_port = spawn_http_upstream().await;
    let (proxy_port, sink) = spawn_tunnel_proxy(pipeline_allowing("127.0.0.1")).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    // CONNECT handshake.
    let connect = format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).await.unwrap();
    let established = String::from_utf8_lossy(&buf[..n]);
    assert!(
        established.starts_with("HTTP/1.1 200"),
        "CONNECT reply: {established}"
    );

    // Inner plain-HTTP request over the established tunnel.
    stream
        .write_all(b"GET /inner HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "inner response: {text}");
    assert!(text.contains("echo:/inner"));

    // The inner request's record is mode=tunnel and carries the tunnel group.
    let records = sink.records();
    let inner = records
        .iter()
        .find(|r| r.path == "/inner")
        .expect("inner record");
    assert_eq!(inner.mode, Mode::Tunnel);
    assert_eq!(inner.action, Action::Allow);
    let tunnel = inner.tunnel.as_ref().expect("tunnel group");
    assert_eq!(tunnel.target, format!("127.0.0.1:{upstream_port}"));
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_to_blocked_host_rejected_at_handshake() {
    let (proxy_port, sink) = spawn_tunnel_proxy(pipeline_allowing("allowed.example")).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    stream
        .write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).await.unwrap();
    let reply = String::from_utf8_lossy(&buf[..n]);
    assert!(
        reply.starts_with("HTTP/1.1 403"),
        "expected 403, got: {reply}"
    );

    let records = sink.records();
    let rec = records
        .iter()
        .find(|r| r.host == "blocked.example")
        .expect("reject record");
    assert_eq!(rec.action, Action::Reject);
    assert_eq!(rec.rejected_by.as_deref(), Some("allowlist"));
    assert_eq!(rec.method, "CONNECT");
    assert_eq!(rec.mode, Mode::Tunnel);
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_connect_plain_http_inner() {
    let upstream_port = spawn_http_upstream().await;
    let (proxy_port, sink) = spawn_tunnel_proxy(pipeline_allowing("127.0.0.1")).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    // Greeting: version 5, 1 method, no-auth.
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00], "no-auth selected");

    // Request: CONNECT to 127.0.0.1:upstream_port (IPv4).
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&upstream_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 success");

    // Inner plain-HTTP request.
    stream
        .write_all(b"GET /viasocks HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).contains("echo:/viasocks"));

    let records = sink.records();
    assert!(records
        .iter()
        .any(|r| r.path == "/viasocks" && r.mode == Mode::Tunnel));
}
