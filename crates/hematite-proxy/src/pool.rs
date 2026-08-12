//! Part 07 §4 — idle upstream connection pooling (quality-of-implementation,
//! not conformance; the spec suggests ≈100 conns, 90 s idle — we cap idle age
//! at 30 s, well under common upstream keep-alive timeouts, to shrink the
//! stale-reuse window).
//!
//! INV-2 is preserved by construction: [`acquire`] is the only way to obtain
//! an upstream sender and it consumes the pipeline's `AllowProof`. It either
//! reuses a connection that was itself created through
//! `dial::connect_upstream` (proof-gated at creation) or dials a fresh one
//! through it. Reusing under this request's proof is sound because the
//! pipeline returned `Continue` for this exact request; the proof gates the
//! *decision to reach the upstream*, not the socket's identity.
//!
//! The guard is re-checked against the connection's actual peer address on
//! every checkout — belt-and-braces: the pool dies with its `Runtime` on
//! config reload (a reload starts with an empty pool), so a new deny CIDR can
//! never be bypassed by a pooled connection, but the re-check keeps that
//! property local and visible instead of depending on reload semantics.
//!
//! Known trade-off (documented, accepted for v1): there is no post-send
//! retry. A reused connection the upstream closed between our readiness
//! check and the write surfaces as a 502. The 30 s idle cap plus the
//! `is_closed`/`poll_ready` checkout gate make this rare; before pooling,
//! sustained load produced mass 502s from ephemeral-port exhaustion instead.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hematite_kernel::pipeline::AllowProof;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;

use crate::dial::{connect_upstream, DialError};
use crate::metrics::DialResult;
use crate::state::Runtime;

/// Boxed error type shared with the HTTP handler.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// The body type sent to upstreams (buffered bytes or a streamed chain).
pub type UpstreamBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// Idle age cap. Deliberately below common upstream keep-alive timeouts
/// (nginx 75 s, Go 60 s) so we usually drop a connection before the
/// upstream does.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle connections kept per (host, port, scheme) key.
const MAX_IDLE_PER_KEY: usize = 8;
/// Idle connections kept across all keys (spec's ≈100).
const MAX_IDLE_TOTAL: usize = 100;

type Key = (String, u16, bool);

struct IdleEntry {
    sender: SendRequest<UpstreamBody>,
    peer: IpAddr,
    expires: Instant,
}

/// A checked-out upstream sender. Return it with [`Pool::checkin`] after a
/// plain (non-upgrade) exchange; drop it on error or after a 101.
pub struct PooledSender {
    pub sender: SendRequest<UpstreamBody>,
    peer: IpAddr,
    key: Key,
}

/// Idle-connection pool. Lives inside a `Runtime`, so a config reload swaps
/// in an empty pool and in-flight handlers drain the old one.
#[derive(Default)]
pub struct Pool {
    idle: Mutex<HashMap<Key, Vec<IdleEntry>>>,
}

impl Pool {
    pub fn new() -> Self {
        Pool::default()
    }

    /// Pop a live idle sender for `key`, dropping expired, closed, guard-
    /// denied, and not-ready entries along the way. LIFO: the most recently
    /// used connection is the least likely to have been closed upstream.
    fn checkout(&self, key: &Key, runtime: &Runtime) -> Option<PooledSender> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let entries = idle.get_mut(key)?;
        let now = Instant::now();
        while let Some(mut entry) = entries.pop() {
            if entry.expires <= now
                || runtime.guard.check(entry.peer).is_err()
                || entry.sender.is_closed()
                || !ready_now(&mut entry.sender)
            {
                // Not reusable now. A pending-ready sender is usually still
                // draining a previous response body; dropping it (rather
                // than re-queueing) keeps checkout O(len) and bounded.
                continue;
            }
            return Some(PooledSender {
                sender: entry.sender,
                peer: entry.peer,
                key: key.clone(),
            });
        }
        None
    }

    /// Return a sender to the idle set with a fresh expiry. Sweeps expired
    /// entries pool-wide (lazy eviction; caps bound memory and sockets).
    pub fn checkin(&self, pooled: PooledSender) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        for entries in idle.values_mut() {
            entries.retain(|e| e.expires > now && !e.sender.is_closed());
        }
        idle.retain(|_, v| !v.is_empty());

        let total: usize = idle.values().map(Vec::len).sum();
        let entries = idle.entry(pooled.key).or_default();
        if entries.len() >= MAX_IDLE_PER_KEY || total >= MAX_IDLE_TOTAL {
            // Oldest-first eviction within the key; drop the new sender
            // instead when the global cap is the binding one.
            if entries.len() >= MAX_IDLE_PER_KEY {
                entries.remove(0);
            } else {
                return;
            }
        }
        entries.push(IdleEntry {
            sender: pooled.sender,
            peer: pooled.peer,
            expires: now + IDLE_TIMEOUT,
        });
    }
}

/// One poll of `SendRequest::ready` with a no-op waker: `true` only when the
/// connection can take a request right now.
fn ready_now(sender: &mut SendRequest<UpstreamBody>) -> bool {
    let mut cx = Context::from_waker(Waker::noop());
    matches!(
        std::pin::pin!(sender.ready()).poll(&mut cx),
        Poll::Ready(Ok(()))
    )
}

use std::future::Future;

/// The only path to an upstream sender (INV-2). Consumes the proof; reuses
/// an idle pooled connection when one is live, otherwise dials through
/// `connect_upstream` and completes the HTTP/1.1 handshake.
///
/// Returns the sender and whether it was reused (for metrics/diagnostics).
pub async fn acquire(
    proof: AllowProof,
    host: &str,
    port: u16,
    scheme_https: bool,
    runtime: &Runtime,
) -> Result<(PooledSender, bool), DialError> {
    let key: Key = (host.to_ascii_lowercase(), port, scheme_https);
    if let Some(pooled) = runtime.pool.checkout(&key, runtime) {
        // The proof authorized reaching this upstream; the socket it rides
        // on was proof-gated when it was created. See module docs.
        let _ = proof;
        runtime.metrics.inc_dial(DialResult::Reused);
        return Ok((pooled, true));
    }
    let (stream, peer) = connect_upstream(proof, host, port, scheme_https, runtime).await?;
    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http1::Builder::new()
        // Replay the original header-name casing recorded on the request
        // parts (Part 02 §5).
        .preserve_header_case(true)
        .handshake(io)
        .await
        .map_err(|e| DialError::Failed(format!("upstream handshake: {e}")))?;
    // with_upgrades so a 101 hands the upstream socket to `upgrade::on`
    // for the WebSocket byte copy (Part 05 §5). The task serves the
    // connection for as long as it lives, across every pooled reuse.
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok((PooledSender { sender, peer, key }, false))
}
