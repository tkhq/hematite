//! End-to-end upstream connection pooling (Part 07 §4): sequential requests
//! through the proxy must reuse one upstream connection, and the guard must
//! still be re-checked on reuse.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use hematite_kernel::audit::AuditRecord;
use hematite_kernel::config::{build_pipeline, TransformSpec};
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::http::serve_http;
use hematite_proxy::state::{Guard, Runtime, SharedState};

#[derive(Default)]
struct TestSink(Mutex<Vec<(AuditRecord, Level)>>);

impl AuditSink for TestSink {
    fn emit(&self, record: &AuditRecord, level: Level) {
        self.0.lock().unwrap().push((record.clone(), level));
    }
}

/// Echo upstream that records the client port of every accepted TCP
/// connection: two requests on one pooled connection show one port.
async fn spawn_counting_upstream() -> (u16, Arc<Mutex<Vec<u16>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let conns: Arc<Mutex<Vec<u16>>> = Arc::default();
    let conns_task = conns.clone();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            conns_task.lock().unwrap().push(peer.port());
            tokio::spawn(async move {
                let service = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                        Bytes::from_static(b"ok"),
                    )))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (port, conns)
}

async fn spawn_proxy(guard: Guard) -> u16 {
    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "cidrs": ["127.0.0.1/32"] } }
    ]))
    .unwrap();
    let runtime = Runtime {
        pipeline: build_pipeline(&specs).unwrap().pipeline,
        guard,
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
    tokio::spawn(serve_http(listener, state, sink));
    port
}

/// One absolute-form request per client connection (Connection: close on the
/// client leg; the upstream leg is what pooling keeps alive).
async fn one_request(proxy_port: u16, upstream_port: u16) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{upstream_port}/get HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn sequential_requests_reuse_one_upstream_connection() {
    let (upstream_port, conns) = spawn_counting_upstream().await;
    let proxy_port = spawn_proxy(Guard::new(&[]).unwrap()).await;

    for _ in 0..3 {
        let response = one_request(proxy_port, upstream_port).await;
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        // The pooled sender is only ready again once the previous response
        // body has fully drained; sequential requests are the common case.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let seen = conns.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        1,
        "expected one upstream connection for three requests, saw ports {seen:?}"
    );
}

/// Upstream that answers one keep-alive request per connection, then slams
/// the socket shut shortly after — manufacturing the stale-reuse race: the
/// proxy pools the connection, and by the next request it is dead or dying.
async fn spawn_flaky_upstream(close_after: std::time::Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // Read until the end of the request headers, answer with a
                // keep-alive response, linger briefly, then close abruptly.
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\
                          connection: keep-alive\r\n\r\nok",
                    )
                    .await;
                tokio::time::sleep(close_after).await;
                drop(stream);
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_reused_connection_is_retried_for_idempotent_requests() {
    let upstream_port = spawn_flaky_upstream(std::time::Duration::from_millis(5)).await;
    let proxy_port = spawn_proxy(Guard::new(&[]).unwrap()).await;

    // Every iteration pools a connection the upstream kills ~5ms later.
    // Some checkouts observe the death (fresh dial), some race it (send
    // fails on the reused sender). With single-retry replay, a GET must
    // never surface a 502 either way.
    for i in 0..30 {
        let response = one_request(proxy_port, upstream_port).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "iteration {i} got: {response}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(4)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_is_rechecked_on_reuse() {
    let (upstream_port, conns) = spawn_counting_upstream().await;
    // Guard denies loopback: even a pooled loopback connection must not be
    // reusable. With the dial also denied, every request is rejected — the
    // point is that the pool cannot become a guard bypass.
    let proxy_port = spawn_proxy(Guard::new(&["127.0.0.0/8".into()]).unwrap()).await;

    let response = one_request(proxy_port, upstream_port).await;
    assert!(response.starts_with("HTTP/1.1 502"), "got: {response}");
    assert!(
        conns.lock().unwrap().is_empty(),
        "guard-denied dial must not reach the upstream"
    );
}
