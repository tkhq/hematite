//! Part 05 §3 end-to-end: a TLS client → the HTTPS MITM listener → a TLS
//! upstream. Exercises SNI-driven minting, termination, the pipeline over
//! the inner request, upstream TLS dialing, and `mode: https` audit.

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
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::listen::serve_https;
use hematite_proxy::state::{Guard, Runtime, SharedState};
use hematite_proxy::tls::{install_crypto_provider, CertCache, SigningCa};

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

/// A CA (cert PEM, key PEM) plus the rcgen KeyPair for signing leaves.
struct Ca {
    cert_pem: String,
    key_pem: String,
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
}

fn make_ca(cn: &str) -> Ca {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.clone().self_signed(&key).unwrap();
    Ca {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        params,
        key,
    }
}

/// A TLS echo upstream serving `name`, signed by `ca`. Returns its port.
async fn spawn_tls_upstream(ca: &Ca, name: &str) -> u16 {
    // Leaf for `name` signed by the CA.
    let mut leaf_params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let ca_cert = ca.params.clone().self_signed(&ca.key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca_cert, &ca.key).unwrap();

    let chain = vec![leaf.der().clone(), ca_cert.der().clone()];
    let key = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

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
                    let body = format!("echo:{}", req.uri().path());
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
    port
}

/// A root store trusting `ca`, as an upstream client config.
fn upstream_config_trusting(ca: &Ca) -> Arc<rustls::ClientConfig> {
    let ca_der = ca
        .params
        .clone()
        .self_signed(&ca.key)
        .unwrap()
        .der()
        .clone();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn https_mitm_terminates_and_forwards() {
    install_crypto_provider();

    // One CA both mints leaves (proxy) and signs the upstream — so the test
    // client and the proxy's upstream dialer share a trust root. The
    // upstream is addressed by an allowlisted hostname that resolves to
    // loopback via /etc/hosts-free trickery: we use "localhost".
    let ca = make_ca("hematite test CA");
    let upstream_name = "localhost";
    let upstream_port = spawn_tls_upstream(&ca, upstream_name).await;

    // Pipeline: allow the upstream host, strip a tracking header.
    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "domains": [upstream_name] } },
        { "name": "header_allowlist",
          "config": { "headers": ["Host", "Accept"] } }
    ]))
    .unwrap();
    let pipeline = build_pipeline(&specs).unwrap().pipeline;

    let ca_signer = Arc::new(SigningCa::from_pem(&ca.cert_pem, &ca.key_pem, 72).unwrap());
    let runtime = Runtime {
        pipeline,
        guard: Guard::new(&[]).unwrap(),
        max_request_body_bytes: 1 << 20,
        upstream_response_header_timeout: std::time::Duration::from_secs(5),
        dial_timeout: std::time::Duration::from_secs(5),
        upstream_tls: upstream_config_trusting(&ca),
        cert_cache: Some(Arc::new(CertCache::new(ca_signer, 100))),
        metrics: hematite_proxy::metrics::Metrics::new("test"),
        tunnel_passthrough: Vec::new(),
    };
    let state = SharedState::new(runtime);
    let sink = Arc::new(TestSink::default());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_https(listener, state, sink.clone()));

    // The proxy dials `upstream_name:upstream_port`; point that name's dial
    // at the loopback upstream by using the real resolver for "localhost".
    // The request's Host carries the upstream port so the proxy dials it.
    let host_with_port = format!("{upstream_name}:{upstream_port}");

    // TLS client trusting the CA (the proxy mints a leaf under it).
    let client_config = upstream_config_trusting(&ca);
    let connector = TlsConnector::from(client_config);
    let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let server_name = ServerName::try_from(upstream_name.to_string()).unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let req = format!(
        "GET /hello HTTP/1.1\r\nHost: {host_with_port}\r\nAccept: */*\r\nX-Tracking: 1\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);

    assert!(text.starts_with("HTTP/1.1 200"), "got: {text}");
    assert!(text.contains("echo:/hello"), "upstream not reached: {text}");

    let records = sink.records();
    assert_eq!(records.len(), 1, "one audit record");
    let (record, level) = &records[0];
    assert_eq!(record.action, Action::Allow);
    assert_eq!(record.mode, hematite_kernel::summary::Mode::Https);
    assert_eq!(record.sni.as_deref(), Some(upstream_name));
    assert_eq!(*level, Level::Info);
    // header_allowlist stripped X-Tracking on the request path.
    let strip = &record.request_transforms[1];
    assert!(strip.annotations.contains_key("stripped_headers"));
}

#[tokio::test(flavor = "multi_thread")]
async fn https_no_sni_is_rejected() {
    install_crypto_provider();
    let ca = make_ca("hematite test CA");
    let specs: Vec<TransformSpec> = serde_json::from_value(serde_json::json!([
        { "name": "allowlist", "config": { "domains": ["example.com"] } }
    ]))
    .unwrap();
    let ca_signer = Arc::new(SigningCa::from_pem(&ca.cert_pem, &ca.key_pem, 72).unwrap());
    let runtime = Runtime {
        pipeline: build_pipeline(&specs).unwrap().pipeline,
        guard: Guard::new(&[]).unwrap(),
        max_request_body_bytes: 1 << 20,
        upstream_response_header_timeout: std::time::Duration::from_secs(5),
        dial_timeout: std::time::Duration::from_secs(5),
        upstream_tls: upstream_config_trusting(&ca),
        cert_cache: Some(Arc::new(CertCache::new(ca_signer, 100))),
        metrics: hematite_proxy::metrics::Metrics::new("test"),
        tunnel_passthrough: Vec::new(),
    };
    let state = SharedState::new(runtime);
    let sink = Arc::new(TestSink::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_https(listener, state, sink.clone()));

    // Connect with an IP-literal server name → no SNI in the ClientHello.
    let connector = TlsConnector::from(upstream_config_trusting(&ca));
    let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let handshake = connector.connect(name, tcp).await;
    assert!(handshake.is_err(), "no-SNI ClientHello must be refused");

    // A no-SNI rejection is audited (Part 05 §3).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0.action, Action::Reject);
    assert_eq!(records[0].0.rejected_by.as_deref(), Some("listener"));
}
