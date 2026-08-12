//! Part 07 §1–§2, §4 — upstream dialing, the guard, and upstream TLS.
//!
//! INV-2: `connect_upstream` is the only path to an upstream socket, and it
//! consumes the pipeline's `AllowProof`.

use std::net::IpAddr;

use hematite_kernel::audit::GuardDenial;
use hematite_kernel::pipeline::AllowProof;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::metrics::DialResult;
use crate::state::Runtime;

/// Any bidirectional upstream stream (plaintext TCP or TLS).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub enum DialError {
    /// Guard denial: audits as a policy denial (`rejected_by: "guard"`,
    /// status 502), not an error (Part 07 §2).
    Denied(GuardDenial),
    /// Resolution or connection failure → 502, action `error`.
    Failed(String),
}

/// Resolve, apply the guard, connect, and — when `scheme_https` — complete
/// an upstream TLS handshake verified against the configured roots
/// (Part 07 §4). Returns a unified stream and the peer address actually
/// dialed (the pool re-checks the guard against it on reuse).
pub async fn connect_upstream(
    proof: AllowProof,
    host: &str,
    port: u16,
    scheme_https: bool,
    runtime: &Runtime,
) -> Result<(Box<dyn Io>, std::net::IpAddr), DialError> {
    // The proof is consumed by value: no proof, no socket (INV-2).
    let _ = proof;

    // Resolution uses a real resolver (the OS's) — never hematite's own
    // intercepting DNS server, which would loop (Part 07 §1).
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
        // Guard is enforced against the exact IP being dialed; a denial
        // fails the request (no fall-through past a denied address).
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
            return Ok((Box::new(tcp), addr.ip()));
        }
        let connector = TlsConnector::from(runtime.upstream_tls.clone());
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| DialError::Failed(format!("invalid upstream server name {host:?}")))?;
        match connector.connect(server_name, tcp).await {
            Ok(tls) => {
                runtime.metrics.inc_dial(DialResult::Ok);
                return Ok((Box::new(tls), addr.ip()));
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
