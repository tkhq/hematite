//! End-to-end L1 tests over real localhost sockets: proxy in front of an
//! echo upstream, driven by raw absolute-form HTTP/1.1.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use hematite_kernel::audit::{Action, AuditRecord};
use hematite_kernel::config::{build_pipeline, TransformSpec};
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::http::serve_http;
use hematite_proxy::state::{Guard, Runtime, SharedState};

/// Collects records in memory for assertions.
#[derive(Default)]
struct TestSink(Mutex<Vec<(AuditRecord, Level)>>);

impl AuditSink for TestSink {
    fn emit(&self, record: &AuditRecord, level: Level) {
        self.0.lock().unwrap().push((record.clone(), level));
    }
}

impl TestSink {
    fn records(&self) -> Vec<(AuditRecord, Level)> {
        self.0.lock().unwrap().clone()
    }
}

/// Echo upstream: replies 200 with a JSON body listing received headers in
/// wire order.
async fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let headers: Vec<(String, String)> = req
                        .headers()
                        .iter()
                        .map(|(n, v)| {
                            (n.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                        })
                        .collect();
                    let body = serde_json::to_vec(&serde_json::json!({
                        "path": req.uri().path(),
                        "headers": headers,
                    }))
                    .unwrap();
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(
                        Full::new(Bytes::from(body)),
                    ))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    port
}

fn pipeline_allowing(cidr: &str) -> hematite_kernel::pipeline::Pipeline {
    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "cidrs": [cidr] } },
        { "name": "header_allowlist",
          "config": { "headers": ["Host", "Accept", "Content-Type", "Content-Length"] } }
    ]))
    .unwrap();
    build_pipeline(&specs).unwrap().pipeline
}

async fn spawn_proxy(pipeline: hematite_kernel::pipeline::Pipeline, guard: Guard) -> (u16, Arc<TestSink>) {
    let runtime = Runtime {
        pipeline,
        guard,
        max_request_body_bytes: 1 << 20,
        upstream_response_header_timeout: std::time::Duration::from_secs(5),
        dial_timeout: std::time::Duration::from_secs(5),
    };
    let state = SharedState::new(runtime);
    let sink = Arc::new(TestSink::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_http(listener, state, sink.clone()));
    (port, sink)
}

/// Send one raw request through the proxy; return the full response text.
async fn raw_request(proxy_port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

fn no_guard() -> Guard {
    Guard::new(&[]).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_request_forwards_and_audits() {
    let upstream_port = spawn_upstream().await;
    let (proxy_port, sink) = spawn_proxy(pipeline_allowing("127.0.0.1/32"), no_guard()).await;

    let response = raw_request(
        proxy_port,
        &format!(
            "GET http://127.0.0.1:{upstream_port}/get HTTP/1.1\r\n\
             Host: 127.0.0.1:{upstream_port}\r\n\
             Accept: */*\r\n\
             Connection: close, X-Doomed\r\n\
             X-Doomed: 1\r\n\
             X-Tracking: nope\r\n\r\n"
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
    // Hop-by-hop (Connection, its named X-Doomed) stripped by hygiene;
    // X-Tracking stripped by header_allowlist.
    assert!(!response.contains("x-doomed"), "connection-named header reached upstream");
    assert!(!response.contains("x-tracking"), "header_allowlist failed");
    assert!(response.contains("\"path\":\"/get\""));

    let records = sink.records();
    assert_eq!(records.len(), 1);
    let (record, level) = &records[0];
    assert_eq!(record.action, Action::Allow);
    assert_eq!(record.status_code, Some(200));
    assert_eq!(record.host, "127.0.0.1");
    assert_eq!(*level, Level::Info);
    assert_eq!(record.request_transforms.len(), 2);
    assert_eq!(record.response_transforms.len(), 2, "response path traced");
    // header_allowlist annotated the strips.
    let strip_trace = &record.request_transforms[1];
    assert!(strip_trace.annotations.contains_key("stripped_headers"));
}

#[tokio::test(flavor = "multi_thread")]
async fn non_allowlisted_host_rejected_403() {
    let (proxy_port, sink) = spawn_proxy(pipeline_allowing("10.9.9.9/32"), no_guard()).await;

    let response = raw_request(
        proxy_port,
        "GET http://127.0.0.1:1/x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 403"), "got: {response}");
    let records = sink.records();
    assert_eq!(records.len(), 1);
    let (record, level) = &records[0];
    assert_eq!(record.action, Action::Reject);
    assert_eq!(record.rejected_by.as_deref(), Some("allowlist"));
    assert_eq!(record.status_code, Some(403));
    assert_eq!(*level, Level::Warn, "rejects log at WARN (Part 08 §1)");
    assert!(record.response_transforms.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_denies_post_resolution_dial() {
    // Allowlisted at match time, denied at the socket (threat T2 shape).
    let guard = Guard::new(&["127.0.0.0/8".to_string()]).unwrap();
    let (proxy_port, sink) = spawn_proxy(pipeline_allowing("127.0.0.1/32"), guard).await;

    let response = raw_request(
        proxy_port,
        "GET http://127.0.0.1:9/x HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 502"), "got: {response}");
    let records = sink.records();
    assert_eq!(records.len(), 1);
    let (record, level) = &records[0];
    assert_eq!(record.action, Action::Reject, "guard denial is a policy denial, not an error");
    assert_eq!(record.rejected_by.as_deref(), Some("guard"));
    assert_eq!(record.status_code, Some(502));
    assert_eq!(*level, Level::Warn);
    let guard_group = record.guard.as_ref().expect("guard group present");
    assert_eq!(guard_group.denied_addr, "127.0.0.1");
    assert_eq!(guard_group.prefix, "127.0.0.0/8");
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_segments_rejected_400() {
    let (proxy_port, sink) = spawn_proxy(pipeline_allowing("127.0.0.1/32"), no_guard()).await;

    for path in ["/a/../b", "/%2e%2e/etc", "/a/./b"] {
        let response = raw_request(
            proxy_port,
            &format!("GET http://127.0.0.1:1{path} HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"), "path {path}: {response}");
    }

    let records = sink.records();
    assert_eq!(records.len(), 3);
    for (record, _) in &records {
        assert_eq!(record.action, Action::Reject);
        assert_eq!(record.rejected_by.as_deref(), Some("listener"));
        assert_eq!(record.status_code, Some(400));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn absolute_form_host_mismatch_rejected_400() {
    let (proxy_port, sink) = spawn_proxy(pipeline_allowing("127.0.0.1/32"), no_guard()).await;

    let response = raw_request(
        proxy_port,
        "GET http://127.0.0.1:1/x HTTP/1.1\r\nHost: evil.example\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 400"), "got: {response}");
    let (record, _) = &sink.records()[0];
    assert_eq!(record.rejected_by.as_deref(), Some("listener"));
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_down_maps_to_502_error() {
    // Port 1 on loopback: allowlisted, guard disabled, nothing listening.
    let (proxy_port, sink) = spawn_proxy(pipeline_allowing("127.0.0.1/32"), no_guard()).await;

    let response = raw_request(
        proxy_port,
        "GET http://127.0.0.1:1/x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 502"), "got: {response}");
    let (record, level) = &sink.records()[0];
    assert_eq!(record.action, Action::Error);
    assert_eq!(record.status_code, Some(502));
    assert!(record.error.is_some());
    assert_eq!(*level, Level::Error);
}
