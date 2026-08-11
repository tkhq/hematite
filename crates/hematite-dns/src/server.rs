//! Part 06 — the UDP and TCP DNS server. Serves static/intercept answers
//! locally and forwards passthrough queries to the upstream resolver with a
//! 5 s timeout (SERVFAIL on failure).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::resolve::{resolve, Decision, DnsConfig};
use crate::wire::{build_empty_noerror, build_response, build_servfail, parse_query};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a DNS decision, for metrics instrumentation.
/// Defined here (no proxy-crate dependency) and converted to `DnsOutcome`
/// on the proxy side via `From<DnsDecisionKind>`.
#[derive(Debug, Clone, Copy)]
pub enum DnsDecisionKind {
    /// Query answered from an operator-configured static record.
    Static,
    /// Query intercepted and answered with the proxy's IP (or EmptyNoError).
    Intercept,
    /// Query forwarded to the upstream resolver (passthrough zone).
    Passthrough,
    /// Forward or send error (SERVFAIL sent to client).
    Error,
}

pub struct DnsServer {
    config: Arc<DnsConfig>,
    upstream_resolver: SocketAddr,
    on_decision: Option<Arc<dyn Fn(DnsDecisionKind) + Send + Sync>>,
}

impl DnsServer {
    pub fn new(config: DnsConfig, upstream_resolver: SocketAddr) -> Self {
        DnsServer {
            config: Arc::new(config),
            upstream_resolver,
            on_decision: None,
        }
    }

    /// Attach a decision callback for metrics instrumentation. Called once
    /// per resolved query (after the decision is made, before I/O).
    pub fn with_on_decision(mut self, cb: Arc<dyn Fn(DnsDecisionKind) + Send + Sync>) -> Self {
        self.on_decision = Some(cb);
        self
    }

    /// Produce the response bytes for a request, performing passthrough
    /// forwarding when needed. `None` means "drop" (unparseable request).
    pub async fn respond(&self, request: &[u8]) -> Option<Vec<u8>> {
        let query = parse_query(request)?;
        match resolve(&self.config, &query) {
            Decision::Answer(answers) => {
                // Distinguish static records from intercept answers.
                let kind = if self
                    .config
                    .records
                    .contains_key(query.name.strip_suffix('.').unwrap_or(&query.name))
                {
                    DnsDecisionKind::Static
                } else {
                    DnsDecisionKind::Intercept
                };
                if let Some(cb) = &self.on_decision {
                    cb(kind);
                }
                Some(build_response(&query, &answers, true))
            }
            Decision::EmptyNoError => {
                // EmptyNoError is emitted for both static and intercept paths.
                let kind = if self
                    .config
                    .records
                    .contains_key(query.name.strip_suffix('.').unwrap_or(&query.name))
                {
                    DnsDecisionKind::Static
                } else {
                    DnsDecisionKind::Intercept
                };
                if let Some(cb) = &self.on_decision {
                    cb(kind);
                }
                Some(build_empty_noerror(&query, true))
            }
            Decision::Passthrough => match self.forward(request).await {
                Some(response) => {
                    if let Some(cb) = &self.on_decision {
                        cb(DnsDecisionKind::Passthrough);
                    }
                    Some(response)
                }
                None => {
                    if let Some(cb) = &self.on_decision {
                        cb(DnsDecisionKind::Error);
                    }
                    Some(build_servfail(&query))
                }
            },
        }
    }

    /// Forward the raw query to the upstream resolver over UDP and relay
    /// the answer (Part 06 §2–§3).
    async fn forward(&self, request: &[u8]) -> Option<Vec<u8>> {
        let sock = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
        sock.connect(self.upstream_resolver).await.ok()?;
        sock.send(request).await.ok()?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(UPSTREAM_TIMEOUT, sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// Serve UDP on `addr` until the socket errors.
    pub async fn serve_udp(self: Arc<Self>, socket: UdpSocket) -> std::io::Result<()> {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;
            let request = buf[..n].to_vec();
            let server = self.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                if let Some(response) = server.respond(&request).await {
                    let _ = socket.send_to(&response, peer).await;
                }
            });
        }
    }

    /// Serve TCP on `listener` (RFC 1035 §4.2.2: 2-byte length prefix).
    pub async fn serve_tcp(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (mut stream, _peer) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut request = vec![0u8; len];
                if stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                if let Some(response) = server.respond(&request).await {
                    let framed_len = (response.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&framed_len).await;
                    let _ = stream.write_all(&response).await;
                }
            });
        }
    }
}
