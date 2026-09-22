//! Fixed, fail-closed external authorization immediately before workload DNS.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hematite_kernel::audit::ExternalAuthorizationAudit;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::destination::CanonicalDestination;
use crate::metrics::{AuthorizationResult, Metrics};

const MAX_BODY: usize = 4096;
const MAX_SAFE: usize = 128;
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct AuthorizationToken(Zeroizing<Vec<u8>>);

impl AuthorizationToken {
    pub fn load(path: &str) -> Result<Self, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("external authorization token file: {e}"))?;
        if !metadata.is_file() {
            return Err("external authorization token source is not a file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o222 != 0 {
                return Err("external authorization token file must be read-only".into());
            }
        }
        let value =
            std::fs::read(path).map_err(|e| format!("external authorization token file: {e}"))?;
        if value.is_empty()
            || value.len() > MAX_BODY
            || value.contains(&b'\n')
            || value.contains(&b'\r')
        {
            return Err("external authorization token file has invalid contents".into());
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0)
    }
}

impl fmt::Debug for AuthorizationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizationToken(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthorizationKey {
    pub endpoint: String,
    pub token_file: String,
    pub session_id: String,
    pub workload_id: String,
}

pub struct ExternalAuthorizer {
    endpoint: Endpoint,
    token: AuthorizationToken,
    session_id: String,
    workload_id: String,
    timeout: Duration,
    tls: Arc<rustls::ClientConfig>,
    metrics: Arc<Metrics>,
}

#[derive(Clone)]
struct Endpoint {
    host: String,
    port: u16,
    authority: String,
}

impl Endpoint {
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.contains('#') || raw.contains('?') || raw.contains('@') {
            return Err(
                "external_authorization.endpoint may not contain userinfo, query, or fragment"
                    .into(),
            );
        }
        let uri: Uri = raw
            .parse()
            .map_err(|_| "external_authorization.endpoint is invalid")?;
        if uri.scheme_str() != Some("https") || uri.path() != "/v1/authorize" {
            return Err(
                "external_authorization.endpoint must be https with path /v1/authorize".into(),
            );
        }
        let authority = uri
            .authority()
            .ok_or("external_authorization.endpoint needs an authority")?;
        let canonical = CanonicalDestination::parse_authority(
            authority.as_str(),
            crate::destination::Scheme::Https,
        )
        .map_err(|e| format!("external_authorization.endpoint: {e}"))?;
        Ok(Self {
            host: canonical.host().to_string(),
            port: canonical.port(),
            authority: authority.as_str().to_string(),
        })
    }
}

impl ExternalAuthorizer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: &str,
        token_file: &str,
        session_id: String,
        workload_id: String,
        timeout: Duration,
        tls: Arc<rustls::ClientConfig>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        validate_safe("session_id", &session_id)?;
        validate_safe("workload_id", &workload_id)?;
        Ok(Self {
            endpoint: Endpoint::parse(endpoint)?,
            token: AuthorizationToken::load(token_file)?,
            session_id,
            workload_id,
            timeout,
            tls,
            metrics,
        })
    }

    pub(crate) async fn authorize(
        &self,
        destination: &CanonicalDestination,
    ) -> AuthorizationOutcome {
        let request_id = request_id();
        let started = Instant::now();
        let result = tokio::time::timeout(self.timeout, self.call(&request_id, destination)).await;
        let (result, decision_id, reason_code, error) = match result {
            Err(_) => (AuthorizationResult::Timeout, None, None, Some("timeout")),
            Ok(Err(kind)) => (kind.metric(), None, None, Some(kind.as_str())),
            Ok(Ok(response)) if response.decision == "allow" => (
                AuthorizationResult::Allow,
                Some(response.decision_id),
                Some(response.reason_code),
                None,
            ),
            Ok(Ok(response)) => (
                AuthorizationResult::Deny,
                Some(response.decision_id),
                Some(response.reason_code),
                None,
            ),
        };
        self.metrics.inc_authorization(result);
        let audit = ExternalAuthorizationAudit {
            request_id,
            decision: result.as_str().to_string(),
            decision_id,
            reason_code,
            duration_ms: started.elapsed().as_secs_f64() * 1000.0,
            error: error.map(str::to_string),
        };
        if matches!(result, AuthorizationResult::Allow) {
            AuthorizationOutcome::Allowed(
                ExternalProof {
                    destination: destination.clone(),
                },
                audit,
            )
        } else if matches!(result, AuthorizationResult::Deny) {
            AuthorizationOutcome::Denied(audit)
        } else {
            AuthorizationOutcome::Failed(audit)
        }
    }

    async fn call(
        &self,
        request_id: &str,
        destination: &CanonicalDestination,
    ) -> Result<AuthResponse, FailureKind> {
        let body = serde_json::to_vec(&AuthRequest {
            version: "1",
            request_id,
            service: "egress",
            action: "connect",
            subject: Subject {
                session_id: &self.session_id,
                workload_id: &self.workload_id,
            },
            destination: Destination {
                scheme: destination.scheme().as_str(),
                protocol: destination.protocol(),
                host: destination.host(),
                port: destination.port(),
            },
        })
        .map_err(|_| FailureKind::Invalid)?;
        if body.len() > MAX_BODY {
            return Err(FailureKind::Invalid);
        }

        // Dedicated direct client: no proxy environment, no workload dialer,
        // no redirects, one connection and one request.
        let tcp = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .map_err(|_| FailureKind::Transport)?;
        let name =
            ServerName::try_from(self.endpoint.host.clone()).map_err(|_| FailureKind::Transport)?;
        let tls = TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|_| FailureKind::Transport)?;
        let (mut sender, conn) = http1::Builder::new()
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| FailureKind::Transport)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let bearer = self
            .token
            .expose(|token| {
                let mut value = Zeroizing::new(b"Bearer ".to_vec());
                value.extend_from_slice(token);
                hyper::header::HeaderValue::from_bytes(&value)
            })
            .map_err(|_| FailureKind::Invalid)?;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/authorize")
            .header(hyper::header::HOST, &self.endpoint.authority)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::ACCEPT, "application/json")
            .header(hyper::header::AUTHORIZATION, bearer)
            .header(hyper::header::CONNECTION, "close")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| FailureKind::Invalid)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| FailureKind::Transport)?;
        if response.status().is_redirection() {
            return Err(FailureKind::Invalid);
        }
        if response.status() != StatusCode::OK {
            return Err(FailureKind::Transport);
        }
        if response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
        {
            return Err(FailureKind::Invalid);
        }
        let mut incoming = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| FailureKind::Transport)?;
            if let Some(data) = frame.data_ref() {
                if bytes.len() + data.len() > MAX_BODY {
                    return Err(FailureKind::Invalid);
                }
                bytes.extend_from_slice(data);
            }
        }
        let parsed: AuthResponse =
            serde_json::from_slice(&bytes).map_err(|_| FailureKind::Invalid)?;
        if parsed.version != "1"
            || parsed.request_id != request_id
            || !matches!(parsed.decision.as_str(), "allow" | "deny")
        {
            return Err(FailureKind::Invalid);
        }
        validate_safe("decision_id", &parsed.decision_id).map_err(|_| FailureKind::Invalid)?;
        validate_safe("reason_code", &parsed.reason_code).map_err(|_| FailureKind::Invalid)?;
        Ok(parsed)
    }
}

pub(crate) enum AuthorizationOutcome {
    Allowed(ExternalProof, ExternalAuthorizationAudit),
    Denied(ExternalAuthorizationAudit),
    Failed(ExternalAuthorizationAudit),
}

pub(crate) struct ExternalProof {
    destination: CanonicalDestination,
}
impl ExternalProof {
    pub(crate) fn exact_for(&self, destination: &CanonicalDestination) -> bool {
        self.destination == *destination
    }
}

#[derive(Debug, Clone, Copy)]
enum FailureKind {
    Transport,
    Invalid,
}
impl FailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Invalid => "invalid",
        }
    }
    fn metric(self) -> AuthorizationResult {
        match self {
            Self::Transport => AuthorizationResult::Transport,
            Self::Invalid => AuthorizationResult::Invalid,
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AuthRequest<'a> {
    version: &'static str,
    request_id: &'a str,
    service: &'static str,
    action: &'static str,
    subject: Subject<'a>,
    destination: Destination<'a>,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Subject<'a> {
    session_id: &'a str,
    workload_id: &'a str,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Destination<'a> {
    scheme: &'a str,
    protocol: &'static str,
    host: &'a str,
    port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthResponse {
    version: String,
    request_id: String,
    decision: String,
    decision_id: String,
    reason_code: String,
}

pub fn validate_config(endpoint: &str, session_id: &str, workload_id: &str) -> Result<(), String> {
    Endpoint::parse(endpoint)?;
    validate_safe("session_id", session_id)?;
    validate_safe("workload_id", workload_id)
}

fn validate_safe(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_SAFE
        || !value
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
    {
        Err(format!(
            "external_authorization.{name} must be 1..={MAX_SAFE} safe ASCII characters"
        ))
    } else {
        Ok(())
    }
}

fn request_id() -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let count = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{time:032x}-{count:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_is_closed() {
        assert!(Endpoint::parse("https://auth.test/v1/authorize").is_ok());
        for bad in [
            "http://auth.test/v1/authorize",
            "https://u@auth.test/v1/authorize",
            "https://auth.test/other",
            "https://auth.test/v1/authorize?q=x",
            "https://auth.test/v1/authorize#x",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn response_rejects_unknown_and_missing_fields() {
        assert!(serde_json::from_str::<AuthResponse>(r#"{"version":"1","request_id":"x","decision":"allow","decision_id":"d","reason_code":"r","extra":1}"#).is_err());
        assert!(serde_json::from_str::<AuthResponse>(
            r#"{"version":"1","request_id":"x","decision":"allow"}"#
        )
        .is_err());
    }
    #[test]
    fn token_debug_is_redacted() {
        let token = AuthorizationToken(Zeroizing::new(b"canary-secret".to_vec()));
        assert!(!format!("{token:?}").contains("canary"));
    }

    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    async fn callback_server(
        mode: Arc<AtomicUsize>,
    ) -> (
        u16,
        Arc<rustls::ClientConfig>,
        Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        crate::tls::install_crypto_provider();
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), ca.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_task = seen.clone();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let mode = mode.clone();
                let seen = seen_task.clone();
                tokio::spawn(async move {
                    let tls = acceptor.accept(tcp).await.unwrap();
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let mode = mode.load(AtomicOrdering::SeqCst);
                            let seen = seen.clone();
                            async move {
                                let token = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                                    .to_string();
                                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                                let value: serde_json::Value =
                                    serde_json::from_slice(&bytes).unwrap();
                                assert_eq!(token, "Bearer canary-secret");
                                seen.lock().unwrap().push(value.clone());
                                let id = value["request_id"].as_str().unwrap();
                                if mode == 7 {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                                let (status, content_type, body) = match mode {
                                0 => (200, "application/json", serde_json::json!({"version":"1","request_id":id,"decision":"allow","decision_id":"d1","reason_code":"ok"}).to_string()),
                                1 => (200, "application/json", serde_json::json!({"version":"1","request_id":id,"decision":"deny","decision_id":"d2","reason_code":"policy"}).to_string()),
                                2 => (200, "application/json", "{".into()),
                                3 => (200, "application/json", serde_json::json!({"version":"1","request_id":"wrong","decision":"allow","decision_id":"d","reason_code":"ok"}).to_string()),
                                4 => (302, "application/json", "{}".into()),
                                5 => (503, "application/json", "{}".into()),
                                6 => (200, "application/json", "x".repeat(MAX_BODY + 1)),
                                _ => (200, "text/plain", "{}".into()),
                            };
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(status)
                                        .header(hyper::header::CONTENT_TYPE, content_type)
                                        .body(Full::new(Bytes::from(body)))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        (port, client, seen)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn closed_callback_outcomes_no_cache_and_minimal_payload() {
        let mode = Arc::new(AtomicUsize::new(0));
        let (port, tls, seen) = callback_server(mode.clone()).await;
        let dir = std::env::temp_dir().join(format!("hematite-authz-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let token = dir.join("token");
        std::fs::write(&token, "canary-secret").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1");
        let auth = ExternalAuthorizer::new(
            &format!("https://localhost:{port}/v1/authorize"),
            token.to_str().unwrap(),
            "session-1".into(),
            "workload-1".into(),
            Duration::from_millis(30),
            tls,
            Metrics::new("test"),
        )
        .unwrap();
        let destination = CanonicalDestination::parse_authority(
            "EXAMPLE.COM.:443",
            crate::destination::Scheme::Https,
        )
        .unwrap();
        assert!(matches!(
            auth.authorize(&destination).await,
            AuthorizationOutcome::Allowed(..)
        ));
        assert!(
            matches!(
                auth.authorize(&destination).await,
                AuthorizationOutcome::Allowed(..)
            ),
            "no decision cache"
        );
        mode.store(1, AtomicOrdering::SeqCst);
        assert!(matches!(
            auth.authorize(&destination).await,
            AuthorizationOutcome::Denied(_)
        ));
        for invalid in [2, 3, 4, 5, 6, 8] {
            mode.store(invalid, AtomicOrdering::SeqCst);
            assert!(
                matches!(
                    auth.authorize(&destination).await,
                    AuthorizationOutcome::Failed(_)
                ),
                "mode {invalid}"
            );
        }
        mode.store(7, AtomicOrdering::SeqCst);
        let AuthorizationOutcome::Failed(audit) = auth.authorize(&destination).await else {
            panic!("timeout allowed")
        };
        assert_eq!(audit.error.as_deref(), Some("timeout"));
        let calls = seen.lock().unwrap();
        assert_eq!(calls.len(), 10);
        let request = &calls[0];
        assert_eq!(
            request["destination"],
            serde_json::json!({"scheme":"https","protocol":"tcp","host":"example.com","port":443})
        );
        let text = request.to_string();
        for forbidden in [
            "headers", "path", "query", "body", "sni", "resolved", "client",
        ] {
            assert!(!text.contains(forbidden));
        }
        std::env::remove_var("HTTPS_PROXY");
        std::fs::remove_dir_all(dir).ok();
    }
}
