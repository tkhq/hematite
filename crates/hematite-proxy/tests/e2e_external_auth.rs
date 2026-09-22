//! Enabled external-authorization coverage at real listener and dial boundaries.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use hematite_kernel::audit::AuditRecord;
use hematite_kernel::config::{build_pipeline, TransformSpec};
use hematite_kernel::matcher::DomainGlob;
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::external_auth::ExternalAuthorizer;
use hematite_proxy::listen::serve_tunnel;
use hematite_proxy::state::{ExternalAuthorization, Guard, Runtime, SharedState};
use hematite_proxy::tls::{install_crypto_provider, CertCache, SigningCa};

type Counter = Arc<AtomicUsize>;
type Seen = Arc<Mutex<Vec<serde_json::Value>>>;

#[derive(Default)]
struct Sink(Mutex<Vec<AuditRecord>>);
impl AuditSink for Sink {
    fn emit(&self, record: &AuditRecord, _: Level) {
        self.0.lock().unwrap().push(record.clone());
    }
}

struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}
impl TestCa {
    fn new() -> Self {
        install_crypto_provider();
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }
    fn client(&self) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.der().clone()).unwrap();
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }
    fn server(&self, name: &str) -> Arc<rustls::ServerConfig> {
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![name.into()])
            .unwrap()
            .signed_by(&key, &self.cert, &self.key)
            .unwrap();
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone(), self.cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
                )
                .unwrap(),
        )
    }
}

async fn spawn_callback(ca: &TestCa, mode: Counter, seen: Seen) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(ca.server("127.0.0.1"));
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let mode = mode.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let mode = mode.load(Ordering::SeqCst);
                    let seen = seen.clone();
                    async move {
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let id = value["request_id"].as_str().unwrap().to_string();
                        seen.lock().unwrap().push(value);
                        if mode == 2 {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        let body = if mode == 3 {
                            serde_json::json!({"version":"1","request_id":"wrong","decision":"allow","decision_id":"d","reason_code":"invalid"})
                        } else {
                            serde_json::json!({"version":"1","request_id":id,"decision":if mode == 1 {"deny"} else {"allow"},"decision_id":"d","reason_code":"test"})
                        };
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .header(hyper::header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(body.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    port
}

async fn spawn_upstream(tls: Option<Arc<rustls::ServerConfig>>, dials: Counter) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            dials.fetch_add(1, Ordering::SeqCst);
            let tls = tls.clone();
            tokio::spawn(async move {
                let io: Box<dyn hematite_proxy::dial::Io> = match tls {
                    Some(config) => Box::new(TlsAcceptor::from(config).accept(tcp).await.unwrap()),
                    None => Box::new(tcp),
                };
                let service = service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(
                        "ok",
                    ))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .half_close(true)
                    .serve_connection(TokioIo::new(io), service)
                    .await;
            });
        }
    });
    port
}

fn pipeline() -> hematite_kernel::pipeline::Pipeline {
    let specs: Vec<TransformSpec> = serde_json::from_str(
        r#"[{"name":"allowlist","config":{"domains":["localhost"],"cidrs":["127.0.0.1/32"]}}]"#,
    )
    .unwrap();
    build_pipeline(&specs).unwrap().pipeline
}

async fn setup(
    ca: &TestCa,
    passthrough: Vec<DomainGlob>,
) -> (SharedState, Arc<Sink>, Counter, Seen) {
    let mode = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let callback = spawn_callback(ca, mode.clone(), seen.clone()).await;
    let token = std::env::temp_dir().join(format!("hematite-authz-{callback}"));
    std::fs::write(&token, "test-token").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    let metrics = hematite_proxy::metrics::Metrics::new("test");
    let auth = ExternalAuthorizer::new(
        &format!("https://127.0.0.1:{callback}/v1/authorize"),
        token.to_str().unwrap(),
        "session".into(),
        "workload".into(),
        Duration::from_millis(30),
        ca.client(),
        metrics.clone(),
    )
    .unwrap();
    let signer = Arc::new(SigningCa::from_pem(&ca.cert.pem(), &ca.key.serialize_pem(), 1).unwrap());
    let runtime = Runtime {
        pipeline: pipeline(),
        guard: Guard::new(&[]).unwrap(),
        external_authorization: ExternalAuthorization::Configured(Arc::new(auth)),
        max_request_body_bytes: 1 << 20,
        upstream_response_header_timeout: Duration::from_secs(2),
        dial_timeout: Duration::from_secs(2),
        upstream_tls: ca.client(),
        cert_cache: Some(Arc::new(CertCache::new(signer, 10))),
        metrics,
        tunnel_passthrough: passthrough,
    };
    let sink = Arc::new(Sink::default());
    (SharedState::new(runtime), sink, mode, seen)
}

async fn raw(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn host_hygiene_and_closed_outcomes_prevent_unauthorized_dials() {
    let ca = TestCa::new();
    let (state, sink, mode, seen) = setup(&ca, Vec::new()).await;
    let dials = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(None, dials.clone()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap().port();
    tokio::spawn(hematite_proxy::http::serve_http(
        listener,
        state,
        sink.clone(),
    ));
    let absolute = format!("http://127.0.0.1:{upstream}/x");
    let bad = [
        format!("GET {absolute} HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\nHost: 127.0.0.1:{upstream}\r\n\r\n").into_bytes(),
        [format!("GET {absolute} HTTP/1.1\r\nHost: ").as_bytes(), &[0xff], b"\r\n\r\n"].concat(),
        format!("GET {absolute} HTTP/1.1\r\nHost: 127.\t0.0.1:{upstream}\r\n\r\n").into_bytes(),
        format!("GET {absolute} HTTP/1.1\r\nHost: evil.example\r\n\r\n").into_bytes(),
    ];
    for request in bad {
        let response = raw(proxy, &request).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400"),
            "unexpected rejection: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(dials.load(Ordering::SeqCst), 0);
    }

    let valid = format!(
        "GET {absolute} HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\nConnection: close\r\n\r\n"
    );
    assert!(raw(proxy, valid.as_bytes())
        .await
        .starts_with(b"HTTP/1.1 200"));
    for (next_mode, status) in [(1, 403), (2, 502), (3, 502)] {
        mode.store(next_mode, Ordering::SeqCst);
        let response = raw(proxy, valid.as_bytes()).await;
        assert!(response.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
    }
    assert_eq!(seen.lock().unwrap().len(), 4);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    let records = sink.0.lock().unwrap();
    let authorized: Vec<_> = records
        .iter()
        .filter_map(|r| r.authorization.as_ref())
        .collect();
    assert_eq!(authorized.len(), 4);
    assert_eq!(
        authorized
            .iter()
            .map(|a| &a.request_id)
            .collect::<HashSet<_>>()
            .len(),
        4
    );
    assert!(!serde_json::to_string(&*records)
        .unwrap()
        .contains("test-token"));
}

#[tokio::test(flavor = "multi_thread")]
async fn all_listener_dials_are_target_bound_and_authorized_once() {
    let ca = TestCa::new();
    let (state, sink, _, seen) = setup(&ca, vec![DomainGlob::parse("127.0.0.1").unwrap()]).await;
    let plain_dials = Arc::new(AtomicUsize::new(0));
    let plain = spawn_upstream(None, plain_dials.clone()).await;
    let tls_dials = Arc::new(AtomicUsize::new(0));
    let tls_port = spawn_upstream(Some(ca.server("localhost")), tls_dials.clone()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap().port();
    tokio::spawn(serve_tunnel(listener, state, sink.clone()));

    let mut connect = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    connect
        .write_all(
            format!("CONNECT 127.0.0.1:{plain} HTTP/1.1\r\nHost: 127.0.0.1:{plain}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut reply = [0; 64];
    let n = connect.read(&mut reply).await.unwrap();
    assert!(String::from_utf8_lossy(&reply[..n]).starts_with("HTTP/1.1 200"));
    connect
        .write_all(
            format!(
                "GET /connect HTTP/1.1\r\nHost: 127.0.0.1:{plain}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    connect.shutdown().await.unwrap();
    let mut ignored = Vec::new();
    connect.read_to_end(&mut ignored).await.unwrap();

    let mut socks = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    socks.write_all(&[5, 1, 0]).await.unwrap();
    let mut selection = [0; 2];
    socks.read_exact(&mut selection).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&plain.to_be_bytes());
    socks.write_all(&request).await.unwrap();
    let mut socks_reply = [0; 10];
    socks.read_exact(&mut socks_reply).await.unwrap();
    assert_eq!(socks_reply[1], 0);
    socks
        .write_all(
            format!("GET /socks HTTP/1.1\r\nHost: 127.0.0.1:{plain}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    socks.shutdown().await.unwrap();
    socks.read_to_end(&mut ignored).await.unwrap();

    let mut bumped = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    bumped
        .write_all(
            format!("CONNECT localhost:{tls_port} HTTP/1.1\r\nHost: localhost:{tls_port}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let n = bumped.read(&mut reply).await.unwrap();
    assert!(String::from_utf8_lossy(&reply[..n]).starts_with("HTTP/1.1 200"));
    let mut tls = TlsConnector::from(ca.client())
        .connect(ServerName::try_from("localhost").unwrap(), bumped)
        .await
        .unwrap();
    tls.write_all(
        format!("GET /bumped HTTP/1.1\r\nHost: localhost:{tls_port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    tls.read_to_end(&mut ignored).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(plain_dials.load(Ordering::SeqCst), 2);
    assert_eq!(tls_dials.load(Ordering::SeqCst), 1);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen[0]["destination"],
        serde_json::json!({"scheme":"connect","protocol":"tcp","host":"127.0.0.1","port":plain})
    );
    assert_eq!(
        seen[1]["destination"],
        serde_json::json!({"scheme":"connect","protocol":"tcp","host":"127.0.0.1","port":plain})
    );
    assert_eq!(
        seen[2]["destination"],
        serde_json::json!({"scheme":"https","protocol":"tcp","host":"localhost","port":tls_port})
    );
    let records = sink.0.lock().unwrap();
    assert_eq!(records.len(), 3, "one safe audit per authorized dial");
    assert_eq!(
        records
            .iter()
            .filter_map(|record| record.authorization.as_ref())
            .map(|audit| &audit.request_id)
            .collect::<HashSet<_>>()
            .len(),
        3
    );
    assert!(!serde_json::to_string(&*records)
        .unwrap()
        .contains("test-token"));
}
