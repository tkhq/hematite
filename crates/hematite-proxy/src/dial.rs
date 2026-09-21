//! Target-bound authorization, workload DNS, resolved-IP guard, and dial.

use std::net::IpAddr;

use hematite_kernel::audit::{ExternalAuthorizationAudit, GuardDenial};
use hematite_kernel::pipeline::AllowProof;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::destination::{CanonicalDestination, Scheme};
use crate::external_auth::{AuthorizationOutcome, ExternalProof};
use crate::metrics::DialResult;
use crate::state::{ExternalAuthorization, Runtime};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub enum AuthorizationError {
    Denied(Box<ExternalAuthorizationAudit>),
    Failed(Box<ExternalAuthorizationAudit>),
}

pub enum DialError {
    Denied(GuardDenial),
    Failed(String),
}

enum ExternalAuthorizationProof {
    Disabled,
    Allowed(ExternalProof),
}

/// Proxy-private and non-cloneable. The only dial entry point consumes it and
/// derives every network parameter from its immutable destination.
pub(crate) struct TargetProof {
    _pipeline: AllowProof,
    destination: CanonicalDestination,
    _external: ExternalAuthorizationProof,
}

/// Bind the pipeline verdict to one canonical target. Configured mode can
/// return a proof only after the exact callback response strictly allows it.
pub(crate) async fn authorize_target(
    pipeline: AllowProof,
    destination: CanonicalDestination,
    runtime: &Runtime,
) -> Result<(TargetProof, Option<ExternalAuthorizationAudit>), AuthorizationError> {
    match &runtime.external_authorization {
        ExternalAuthorization::Disabled => Ok((
            TargetProof {
                _pipeline: pipeline,
                destination,
                _external: ExternalAuthorizationProof::Disabled,
            },
            None,
        )),
        ExternalAuthorization::Configured(authorizer) => {
            match authorizer.authorize(&destination).await {
                AuthorizationOutcome::Allowed(external, audit) => {
                    assert!(
                        external.exact_for(&destination),
                        "external proof target mismatch"
                    );
                    Ok((
                        TargetProof {
                            _pipeline: pipeline,
                            destination,
                            _external: ExternalAuthorizationProof::Allowed(external),
                        },
                        Some(audit),
                    ))
                }
                AuthorizationOutcome::Denied(audit) => {
                    Err(AuthorizationError::Denied(Box::new(audit)))
                }
                AuthorizationOutcome::Failed(audit) => {
                    Err(AuthorizationError::Failed(Box::new(audit)))
                }
            }
        }
    }
}

/// Consume one target-bound permit. It covers this one dial operation and all
/// of its address candidates; it cannot be cloned or reused.
pub(crate) async fn connect_upstream(
    proof: TargetProof,
    runtime: &Runtime,
) -> Result<Box<dyn Io>, DialError> {
    let TargetProof {
        destination,
        _external: external,
        ..
    } = proof;
    if let ExternalAuthorizationProof::Allowed(external) = external {
        assert!(
            external.exact_for(&destination),
            "target-bound proof mismatch"
        );
    }
    let host = destination.host();
    let port = destination.port();
    let scheme_https = destination.scheme() == Scheme::Https;

    let addrs: Vec<std::net::SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![(ip, port).into()]
    } else {
        match tokio::net::lookup_host((host, port)).await {
            Ok(iter) => iter.collect(),
            Err(e) => {
                runtime.metrics.inc_dial(DialResult::DnsError);
                return Err(DialError::Failed(format!(
                    "resolution failed for {host:?}: {e}"
                )));
            }
        }
    };
    if addrs.is_empty() {
        runtime.metrics.inc_dial(DialResult::DnsError);
        return Err(DialError::Failed(format!("no addresses for {host:?}")));
    }

    let mut last_err = None;
    for addr in addrs {
        if let Err(denial) = runtime.guard.check(addr.ip()) {
            runtime.metrics.inc_dial(DialResult::GuardDenied);
            return Err(DialError::Denied(denial));
        }
        let tcp = match tokio::time::timeout(runtime.dial_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                last_err = Some(format!("connect {addr}: {e}"));
                continue;
            }
            Err(_) => {
                last_err = Some(format!("connect {addr}: dial timeout"));
                continue;
            }
        };
        if !scheme_https {
            runtime.metrics.inc_dial(DialResult::Ok);
            return Ok(Box::new(tcp));
        }
        let connector = TlsConnector::from(runtime.upstream_tls.clone());
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| DialError::Failed(format!("invalid upstream server name {host:?}")))?;
        match connector.connect(server_name, tcp).await {
            Ok(tls) => {
                runtime.metrics.inc_dial(DialResult::Ok);
                return Ok(Box::new(tls));
            }
            Err(e) => {
                runtime.metrics.inc_dial(DialResult::TlsError);
                return Err(DialError::Failed(format!("upstream TLS: {e}")));
            }
        }
    }
    runtime.metrics.inc_dial(DialResult::ConnectError);
    Err(DialError::Failed(
        last_err.unwrap_or_else(|| "dial failed".into()),
    ))
}
