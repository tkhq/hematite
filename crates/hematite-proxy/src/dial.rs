//! Part 07 §1–§2 — upstream dialing and the guard.
//!
//! INV-2: `dial_upstream` is the only path to an upstream socket, and it
//! consumes the pipeline's `AllowProof`.

use std::net::IpAddr;

use hematite_kernel::audit::GuardDenial;
use hematite_kernel::pipeline::AllowProof;
use tokio::net::TcpStream;

use crate::state::Runtime;

pub enum DialError {
    /// Guard denial: audits as a policy denial (`rejected_by: "guard"`,
    /// status 502), not an error (Part 07 §2).
    Denied(GuardDenial),
    /// Resolution or connection failure → 502, action `error`.
    Failed(String),
}

/// Resolve and connect. The guard is enforced after name resolution,
/// against the exact IP being dialed; a denied dial fails the request —
/// hematite does not fall through to other resolved addresses.
pub async fn dial_upstream(
    proof: AllowProof,
    host: &str,
    port: u16,
    runtime: &Runtime,
) -> Result<TcpStream, DialError> {
    // The proof is consumed by taking it by value; no proof, no socket.
    let _ = proof;

    // Resolution uses a real resolver (the OS's at L1) — never hematite's
    // own intercepting DNS server, which would loop (Part 07 §1).
    let addrs: Vec<std::net::SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![(ip, port).into()]
    } else {
        tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| DialError::Failed(format!("resolution failed for {host:?}: {e}")))?
            .collect()
    };
    if addrs.is_empty() {
        return Err(DialError::Failed(format!("no addresses for {host:?}")));
    }

    let mut last_err = None;
    for addr in addrs {
        runtime.guard.check(addr.ip()).map_err(DialError::Denied)?;
        match tokio::time::timeout(runtime.dial_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(format!("connect {addr}: {e}")),
            Err(_) => last_err = Some(format!("connect {addr}: dial timeout")),
        }
    }
    Err(DialError::Failed(last_err.unwrap_or_else(|| "dial failed".into())))
}
