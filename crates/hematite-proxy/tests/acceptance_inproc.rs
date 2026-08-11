//! In-process acceptance: boot the real config→runtime path (Part 09) with
//! a full five-transform pipeline including a live secret swap (L3), then
//! drive the HTTPS MITM listener end-to-end. This is the verifiable
//! counterpart to the docker Appendix A harness (which needs a container
//! runtime); it exercises the same code paths short of DNS steering.

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
use hematite_proxy::audit::{AuditSink, Level};
use hematite_proxy::config::{build_runtime, load_str, os_env};
use hematite_proxy::listen::serve_https;
use hematite_proxy::state::SharedState;
use hematite_proxy::tls::install_crypto_provider;

mod common;

#[derive(Default, Clone)]
struct TestSink(Arc<Mutex<Vec<AuditRecord>>>);
impl AuditSink for TestSink {
    fn emit(&self, record: &AuditRecord, _level: Level) {
        self.0.lock().unwrap().push(record.clone());
    }
}

struct Ca {
    cert_pem: String,
    key_pem: String,
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
}
fn make_ca() -> Ca {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "hematite acceptance CA");
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

/// A TLS echo upstream for `localhost` that reflects the request's method,
/// path, and Authorization header as a JSON body.
async fn spawn_tls_echo(ca: &Ca) -> u16 {
    let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    leaf.distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let ca_cert = ca.params.clone().self_signed(&ca.key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca.key).unwrap();
    let chain = vec![leaf_cert.der().clone(), ca_cert.der().clone()];
    let key = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

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
                let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let body =
                        serde_json::json!({ "path": req.uri().path(), "authorization": auth });
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(
                        serde_json::to_vec(&body).unwrap(),
                    ))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    port
}

/// One MITM'd request through the proxy; returns (response text, ()).
async fn https_request(
    proxy_port: u16,
    client_cfg: Arc<rustls::ClientConfig>,
    req: &str,
) -> String {
    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let name = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn full_pipeline_over_https_with_live_secret_swap() {
    install_crypto_provider();

    let dir = std::env::temp_dir().join(format!("hematite-accept-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = make_ca();
    let ca_cert_path = dir.join("ca.crt");
    let ca_key_path = dir.join("ca.key");
    std::fs::write(&ca_cert_path, &ca.cert_pem).unwrap();
    std::fs::write(&ca_key_path, &ca.key_pem).unwrap();
    let token_path = dir.join("internal-token");
    std::fs::write(&token_path, "internal-real").unwrap();

    // The env secret the swap injects (Part 04 §3.1: read from the proxy env).
    std::env::set_var("HEMATITE_ACCEPT_OPENAI", "sk-real-acceptance");

    let upstream_port = spawn_tls_echo(&ca).await;
    // The allowlisted, minted, dialed host is "localhost"; the request Host
    // carries the upstream port so the proxy dials the echo.
    let host = format!("localhost:{upstream_port}");

    let yaml = format!(
        r#"
proxy:
  https_listen: ":443"
  upstream_deny_cidrs: []
tls:
  ca_cert: "{ca_cert}"
  ca_key: "{ca_key}"
transforms:
  - name: allowlist
    config:
      domains: ["localhost"]
  - name: annotate
    config:
      annotations:
        - rules: [{{ host: "localhost" }}]
          headers: ["x-request-id"]
  - name: body_capture
    config:
      max_request_body_bytes: 16384
      rules: [{{ host: "localhost", methods: ["POST"], paths: ["/anything*"] }}]
  - name: secrets
    config:
      secrets:
        - source: {{ type: env, var: HEMATITE_ACCEPT_OPENAI }}
          proxy_value: "proxy-openai-abc123"
          match_headers: ["Authorization"]
          require: true
          rules: [{{ host: "localhost", paths: ["/headers"] }}]
        - source: {{ type: file, path: "{token}" }}
          proxy_value: "proxy-internal-tok"
          match_headers: []
          rules: [{{ host: "localhost" }}]
  - name: header_allowlist
    config:
      headers: ["Authorization", "Accept", "Host", "/^x-request-.*$/"]
      rules: [{{ host: "localhost" }}]
"#,
        ca_cert = ca_cert_path.display(),
        ca_key = ca_key_path.display(),
        token = token_path.display(),
    );

    let config = load_str(&yaml, &os_env).expect("acceptance config loads");
    let mut runtime = build_runtime(&config).expect("runtime builds");
    // Point upstream TLS trust at the test CA (stands in for system roots).
    runtime.upstream_tls = upstream_config_trusting(&ca);
    let state = SharedState::new(runtime);
    let sink = TestSink::default();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_https(listener, state, Arc::new(sink.clone())));

    let client_cfg = upstream_config_trusting(&ca);

    // Step 1 — allowlisted GET → 200 with all five request traces.
    let r1 = https_request(
        proxy_port,
        client_cfg.clone(),
        &format!("GET /get HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(r1.starts_with("HTTP/1.1 200"), "step1: {r1}");

    // Step 3 — secret swap: upstream sees the real key, never the proxy token.
    let r3 = https_request(
        proxy_port,
        client_cfg.clone(),
        &format!(
            "GET /headers HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer proxy-openai-abc123\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(
        r3.contains("Bearer sk-real-acceptance"),
        "upstream did not see the real secret: {r3}"
    );
    assert!(
        !r3.contains("proxy-openai-abc123"),
        "proxy token leaked upstream"
    );

    // Step 4 — require:true, token absent → 403 by secrets.
    let r4 = https_request(
        proxy_port,
        client_cfg.clone(),
        &format!(
            "GET /headers HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(r4.starts_with("HTTP/1.1 403"), "step4: {r4}");

    // Give the audit sink a moment to collect.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let records = sink.0.lock().unwrap().clone();

    // Step 1 record: allow with the full five-trace request list.
    let allow = records
        .iter()
        .find(|r| r.path == "/get")
        .expect("allow record");
    assert_eq!(allow.action, Action::Allow);
    assert_eq!(
        allow
            .request_transforms
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "allowlist",
            "annotate",
            "body_capture",
            "secrets",
            "header_allowlist"
        ],
    );
    assert_eq!(allow.mode, hematite_kernel::summary::Mode::Https);

    // Step 3 record: swapped annotation names the source, never the value.
    let swap = records
        .iter()
        .find(|r| r.path == "/headers" && r.action == Action::Allow)
        .unwrap();
    let secrets_trace = swap
        .request_transforms
        .iter()
        .find(|t| t.name == "secrets")
        .unwrap();
    assert!(secrets_trace.annotations.contains_key("swapped"));

    // Step 4 record: rejected by secrets.
    let reject = records
        .iter()
        .find(|r| r.path == "/headers" && r.action == Action::Reject)
        .expect("reject record");
    assert_eq!(reject.rejected_by.as_deref(), Some("secrets"));

    // Step 10 — every emitted record validates against the normative JSON
    // Schema, and none contains the real secret value (INV-1).
    assert!(!records.is_empty(), "records were emitted");
    for record in &records {
        common::assert_valid_record(record);
    }
    let all_json = serde_json::to_string(&records).unwrap();
    assert!(
        !all_json.contains("sk-real-acceptance"),
        "a record leaked the real secret"
    );
    assert!(
        !all_json.contains("internal-real"),
        "a record leaked the file secret"
    );

    std::env::remove_var("HEMATITE_ACCEPT_OPENAI");
    std::fs::remove_dir_all(&dir).ok();
}
