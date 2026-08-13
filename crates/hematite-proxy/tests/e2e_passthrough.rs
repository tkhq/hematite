//! Part 05 §4.4 — tunnel passthrough: policy-approved CONNECT targets are
//! spliced without TLS interception. Proven end to end by running TLS
//! through the proxy under a CA the proxy has never seen: if the proxy
//! bumped, the client's handshake would fail.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use hematite_kernel::audit::{Action, AuditRecord};
use hematite_kernel::config::{build_pipeline, TransformSpec};
use hematite_kernel::matcher::DomainGlob;
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::listen::serve_tunnel;
use hematite_proxy::state::{Guard, Runtime, SharedState};
use hematite_proxy::tls::install_crypto_provider;

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

/// A private CA and a TLS echo upstream for `name` signed by it. The proxy
/// never learns this CA, so only an unbumped tunnel can complete TLS.
struct PrivateUpstream {
    port: u16,
    roots: rustls::RootCertStore,
}

async fn spawn_private_tls_upstream(name: &str) -> PrivateUpstream {
    // Tests run in parallel; whichever touches rustls first must have
    // installed the process provider (idempotent).
    install_crypto_provider();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "passthrough test CA");
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut leaf_params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    let chain = vec![leaf.der().clone(), ca_cert.der().clone()];
    let key = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let body = format!("private-echo:{}", req.uri().path());
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(
                        body,
                    ))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    PrivateUpstream { port, roots }
}

fn pipeline_allowing(host: &str) -> hematite_kernel::pipeline::Pipeline {
    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "domains": [host] } }
    ]))
    .unwrap();
    build_pipeline(&specs).unwrap().pipeline
}

async fn spawn_passthrough_proxy(
    pipeline: hematite_kernel::pipeline::Pipeline,
    guard: Guard,
    passthrough: &str,
) -> (u16, Arc<TestSink>) {
    install_crypto_provider();
    let runtime = Runtime {
        pipeline,
        guard,
        max_request_body_bytes: 1 << 20,
        upstream_response_header_timeout: std::time::Duration::from_secs(5),
        dial_timeout: std::time::Duration::from_secs(5),
        upstream_tls: hematite_proxy::state::native_upstream_config().unwrap(),
        // Deliberately no cert cache: passthrough must not need MITM state.
        cert_cache: None,
        metrics: hematite_proxy::metrics::Metrics::new("test"),
        tunnel_passthrough: vec![DomainGlob::parse(passthrough).unwrap()],
    };
    let state = SharedState::new(runtime);
    let sink = Arc::new(TestSink::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_tunnel(listener, state, sink.clone()));
    (port, sink)
}

/// CONNECT through the proxy; return the stream after asserting the reply.
async fn connect(proxy_port: u16, authority: &str, expect: &str) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await.unwrap();
    let reply = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(reply.starts_with(expect), "CONNECT reply: {reply}");
    stream
}

#[tokio::test(flavor = "multi_thread")]
async fn passthrough_splices_end_to_end_tls() {
    let upstream = spawn_private_tls_upstream("localhost").await;
    let (proxy_port, sink) = spawn_passthrough_proxy(
        pipeline_allowing("localhost"),
        Guard::new(&[]).unwrap(),
        "localhost",
    )
    .await;

    let stream = connect(
        proxy_port,
        &format!("localhost:{}", upstream.port),
        "HTTP/1.1 200",
    )
    .await;

    // TLS end to end under the private CA: succeeds only if unbumped.
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(upstream.roots.clone())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .expect("end-to-end TLS must succeed through a spliced tunnel");
    tls.write_all(b"GET /secret HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("private-echo:/secret"), "got: {text}");

    // Exactly one audit record for the tunnel: allow, passthrough-marked,
    // with the observed SNI, and no plaintext anywhere near the proxy.
    drop(tls);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let records = sink.records();
    assert_eq!(records.len(), 1, "records: {records:?}");
    let record = &records[0].0;
    assert!(matches!(record.action, Action::Allow));
    assert_eq!(record.method, "CONNECT");
    assert_eq!(record.sni.as_deref(), Some("localhost"));
    let tunnel = record.tunnel.as_ref().expect("tunnel group");
    assert!(tunnel.passthrough, "record must be marked passthrough");
}

#[tokio::test(flavor = "multi_thread")]
async fn passthrough_rejects_sni_mismatch() {
    let upstream = spawn_private_tls_upstream("localhost").await;
    let (proxy_port, sink) = spawn_passthrough_proxy(
        pipeline_allowing("localhost"),
        Guard::new(&[]).unwrap(),
        "localhost",
    )
    .await;

    let stream = connect(
        proxy_port,
        &format!("localhost:{}", upstream.port),
        "HTTP/1.1 200",
    )
    .await;

    // The client asks for a different name than it CONNECTed to (threat
    // T6, domain fronting): the tunnel must be torn down mid-handshake.
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(upstream.roots.clone())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let result = connector
        .connect(ServerName::try_from("evil.test").unwrap(), stream)
        .await;
    assert!(result.is_err(), "fronted handshake must not complete");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let records = sink.records();
    assert_eq!(records.len(), 1, "records: {records:?}");
    let record = &records[0].0;
    assert!(matches!(record.action, Action::Reject));
    assert_eq!(record.rejected_by.as_deref(), Some("listener"));
    assert_eq!(record.sni.as_deref(), Some("evil.test"));
}

#[tokio::test(flavor = "multi_thread")]
async fn passthrough_target_still_faces_the_allowlist() {
    let (proxy_port, sink) = spawn_passthrough_proxy(
        pipeline_allowing("allowed.test"),
        Guard::new(&[]).unwrap(),
        "denied.test",
    )
    .await;

    let _ = connect(proxy_port, "denied.test:443", "HTTP/1.1 403").await;

    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert!(matches!(records[0].0.action, Action::Reject));
    assert_eq!(records[0].0.rejected_by.as_deref(), Some("allowlist"));
}

#[tokio::test(flavor = "multi_thread")]
async fn passthrough_dial_still_faces_the_guard() {
    let upstream = spawn_private_tls_upstream("localhost").await;
    // Loopback denied: the allowlist admits the name, the guard refuses
    // the address it resolves to — before any success reply.
    let (proxy_port, sink) = spawn_passthrough_proxy(
        pipeline_allowing("localhost"),
        Guard::new(&["127.0.0.0/8".into()]).unwrap(),
        "localhost",
    )
    .await;

    let _ = connect(
        proxy_port,
        &format!("localhost:{}", upstream.port),
        "HTTP/1.1 502",
    )
    .await;

    let records = sink.records();
    assert_eq!(records.len(), 1);
    let record = &records[0].0;
    assert!(matches!(record.action, Action::Reject));
    assert_eq!(record.rejected_by.as_deref(), Some("guard"));
    assert!(record.guard.is_some());
    assert!(record.tunnel.as_ref().unwrap().passthrough);
}
