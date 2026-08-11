//! Part 05 §3–§4 — the L2 listeners: HTTPS (TLS MITM) and the tunnel
//! (CONNECT / SOCKS5), including inner-protocol sniffing. Each reduces a
//! connection to a stream that `http::serve_io` drives through the pipeline.

use std::sync::Arc;

use hematite_kernel::audit::{Action, AuditRecord};
use hematite_kernel::summary::{Body, Headers, Mode, RequestSummary};
use hematite_kernel::verdict::Trace;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::LazyConfigAcceptor;

use crate::audit::{AuditSink, PendingAudit};
use crate::http::{serve_io, ConnCtx};
use crate::state::SharedState;
use crate::tunnel::{
    dispatch, parse_connect, parse_socks5_methods, parse_socks5_request, sniff_inner,
    ClientProtocol, ConnectTarget, InnerProtocol, Socks5Method, socks5_failure, SOCKS5_SUCCESS,
};

const SNIFF_CAP: usize = 16 * 1024;
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Emit a listener-level rejection record (Part 05 §6, Part 08 §2).
fn emit_listener_reject(sink: &Arc<dyn AuditSink>, remote: &str, host: &str, status: u16, mode: Mode) {
    let mut pending = PendingAudit::new(sink.clone(), Some(remote.to_string()));
    let mut record = AuditRecord {
        host: host.to_string(),
        method: String::new(),
        path: String::new(),
        remote_addr: Some(remote.to_string()),
        sni: None,
        mode,
        action: Action::Reject,
        status_code: Some(status),
        duration_ms: 0.0,
        rejected_by: Some("listener".into()),
        stubbed_by: None,
        error: None,
        request_transforms: Vec::new(),
        response_transforms: Vec::new(),
        tunnel: None,
        guard: None,
        body_capture: None,
    };
    pending.emit(&record);
    let _ = &mut record;
}

// ---- HTTPS listener (Part 05 §3) --------------------------------------

/// Serve the HTTPS listener: terminate TLS with a per-SNI minted leaf, then
/// run inner requests through the pipeline with `mode: https`.
pub async fn serve_https(
    listener: TcpListener,
    state: SharedState,
    sink: Arc<dyn AuditSink>,
) -> std::io::Result<()> {
    loop {
        let (stream, remote) = listener.accept().await?;
        let state = state.clone();
        let sink = sink.clone();
        tokio::spawn(async move {
            terminate_and_serve(stream, remote.to_string(), state, sink, None).await;
        });
    }
}

/// Terminate TLS on `stream` and serve inner requests. `forced` is set for
/// the tunnel-TLS path (CONNECT target + handshake traces); `None` for the
/// origin HTTPS listener.
async fn terminate_and_serve(
    stream: TcpStream,
    remote: String,
    state: SharedState,
    sink: Arc<dyn AuditSink>,
    forced: Option<(ConnectTarget, Vec<Trace>)>,
) {
    let runtime = state.current();
    let Some(cert_cache) = runtime.cert_cache.clone() else {
        return; // TLS not configured; nothing to serve
    };

    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let handshake = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor).await {
        Ok(Ok(h)) => h,
        _ => return,
    };
    let client_hello = handshake.client_hello();
    let sni = client_hello.server_name().map(|s| s.to_string());

    // Choose the mint target: the CONNECT target for tunnels, else the SNI.
    let (mint_target, expected_host) = match &forced {
        Some((target, _)) => (target.host.clone(), Some(target.host.clone())),
        None => match &sni {
            Some(sni) => (sni.clone(), None),
            None => {
                // No-SNI ClientHello → close + audit (Part 05 §3).
                emit_listener_reject(&sink, &remote, "", 0, Mode::Https);
                return;
            }
        },
    };

    // Tunnel: inner SNI must agree with the CONNECT target (threat T6).
    if let (Some(expected), Some(sni)) = (&expected_host, &sni) {
        if !sni.eq_ignore_ascii_case(expected) {
            emit_listener_reject(&sink, &remote, expected, 0, Mode::Tunnel);
            return;
        }
    }

    let config = match cert_cache.get(&mint_target).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let tls_stream = match handshake.into_stream(config).await {
        Ok(s) => s,
        Err(_) => return,
    };

    let (mode, forced_upstream, tunnel_target, tunnel_traces) = match forced {
        Some((target, traces)) => (
            Mode::Tunnel,
            Some((target.host.clone(), target.port)),
            Some(format!("{}:{}", target.host, target.port)),
            traces,
        ),
        None => (Mode::Https, None, None, Vec::new()),
    };
    let ctx = Arc::new(ConnCtx {
        state,
        sink,
        remote_addr: remote,
        mode,
        sni,
        scheme_https: true,
        forced_upstream,
        tunnel_target,
        tunnel_traces,
    });
    serve_io(tls_stream, ctx).await;
}

// ---- Tunnel listener (Part 05 §4) -------------------------------------

/// Serve the tunnel listener: dispatch on the first byte to CONNECT or
/// SOCKS5, run the synthetic CONNECT summary through the pipeline, and on
/// `Continue` sniff the inner protocol and serve it.
pub async fn serve_tunnel(
    listener: TcpListener,
    state: SharedState,
    sink: Arc<dyn AuditSink>,
) -> std::io::Result<()> {
    loop {
        let (stream, remote) = listener.accept().await?;
        let state = state.clone();
        let sink = sink.clone();
        tokio::spawn(async move {
            let _ = handle_tunnel(stream, remote.to_string(), state, sink).await;
        });
    }
}

async fn handle_tunnel(
    mut stream: TcpStream,
    remote: String,
    state: SharedState,
    sink: Arc<dyn AuditSink>,
) -> std::io::Result<()> {
    // Peek the first byte for protocol dispatch without consuming it.
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }

    let target = match dispatch(first[0]) {
        ClientProtocol::Http => match read_connect(&mut stream).await? {
            Some(t) => t,
            None => return Ok(()), // not a CONNECT (absolute-form is L1's job)
        },
        ClientProtocol::Socks5 => match socks5_handshake(&mut stream).await? {
            Some(t) => t,
            None => return Ok(()),
        },
        ClientProtocol::Unknown => return Ok(()),
    };

    // Run the pipeline on the synthetic CONNECT summary (Part 05 §4.1).
    let runtime = state.current();
    let mut summary = synthetic_connect_summary(&target, &remote);
    let outcome = runtime.pipeline.evaluate_request(&mut summary);
    let traces = outcome.request_traces.clone();

    let allowed = matches!(
        outcome.outcome,
        hematite_kernel::pipeline::Outcome::Continue(_)
    );
    // Reply per protocol.
    let is_socks = matches!(dispatch(first[0]), ClientProtocol::Socks5);
    if !allowed {
        emit_tunnel_reject(&sink, &remote, &target, &outcome);
        if is_socks {
            let _ = stream.write_all(&socks5_failure(0x02)).await;
        } else {
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        }
        return Ok(());
    }
    if is_socks {
        stream.write_all(&SOCKS5_SUCCESS).await?;
    } else {
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    }

    // Inner-protocol sniffing (Part 05 §4.3): peek the first inner byte.
    let mut inner = [0u8; 1];
    let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut inner))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    if n == 0 {
        // The handshake itself is a complete audit event (Part 08 §1).
        emit_tunnel_handshake(&sink, &remote, &target, &traces);
        return Ok(());
    }

    match sniff_inner(inner[0]) {
        InnerProtocol::Tls => {
            terminate_and_serve(stream, remote, state, sink, Some((target, traces))).await;
        }
        InnerProtocol::Http => {
            let ctx = Arc::new(ConnCtx {
                state,
                sink,
                remote_addr: remote,
                mode: Mode::Tunnel,
                sni: None,
                scheme_https: false,
                forced_upstream: Some((target.host.clone(), target.port)),
                tunnel_target: Some(format!("{}:{}", target.host, target.port)),
                tunnel_traces: traces,
            });
            serve_io(stream, ctx).await;
        }
        InnerProtocol::Unknown => {}
    }
    Ok(())
}

/// Read a CONNECT request head (through the blank line), capped.
async fn read_connect(stream: &mut TcpStream) -> std::io::Result<Option<ConnectTarget>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() > SNIFF_CAP {
            return Ok(None);
        }
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    Ok(parse_connect(&head))
}

/// Perform the SOCKS5 negotiation and return the CONNECT target.
async fn socks5_handshake(stream: &mut TcpStream) -> std::io::Result<Option<ConnectTarget>> {
    // Version + greeting: [0x05][nmethods][methods...].
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Ok(None);
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    match parse_socks5_methods(&{
        let mut rest = vec![nmethods as u8];
        rest.extend_from_slice(&methods);
        rest
    }) {
        Some(Socks5Method::NoAuth) => stream.write_all(&[0x05, 0x00]).await?,
        _ => {
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Ok(None);
        }
    }

    // Request: [ver][cmd][rsv][atyp][addr][port]. Read the fixed head then
    // the address by type.
    let mut fixed = [0u8; 4];
    stream.read_exact(&mut fixed).await?;
    let atyp = fixed[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            // Rebuild the request with the domain length byte in place.
            let dlen = len[0] as usize;
            let mut rest = vec![0u8; dlen + 2];
            stream.read_exact(&mut rest).await?;
            let mut req = fixed.to_vec();
            req.push(len[0]);
            req.extend_from_slice(&rest);
            return Ok(match parse_socks5_request(&req) {
                Ok(t) => Some(t),
                Err(reject) => {
                    let _ = stream.write_all(&socks5_failure(reject.reply_code())).await;
                    None
                }
            });
        }
        _ => {
            let _ = stream.write_all(&socks5_failure(0x08)).await;
            return Ok(None);
        }
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await?;
    let mut req = fixed.to_vec();
    req.extend_from_slice(&rest);
    Ok(match parse_socks5_request(&req) {
        Ok(t) => Some(t),
        Err(reject) => {
            let _ = stream.write_all(&socks5_failure(reject.reply_code())).await;
            None
        }
    })
}

fn synthetic_connect_summary(target: &ConnectTarget, remote: &str) -> RequestSummary {
    RequestSummary {
        mode: Mode::Tunnel,
        method: "CONNECT".into(),
        host: target.host.clone(),
        port: target.port,
        path: String::new(),
        query: String::new(),
        headers: Headers::new(Vec::new()),
        body: Body::new(Vec::new(), false),
        sni: None,
        remote_addr: Some(remote.to_string()),
    }
}

fn emit_tunnel_reject(
    sink: &Arc<dyn AuditSink>,
    remote: &str,
    target: &ConnectTarget,
    outcome: &hematite_kernel::pipeline::PipelineOutcome,
) {
    let rejected_by = match &outcome.outcome {
        hematite_kernel::pipeline::Outcome::Reject { by, .. } => by.clone(),
        _ => "listener".to_string(),
    };
    let mut pending = PendingAudit::new(sink.clone(), Some(remote.to_string()));
    let mut record = base_tunnel_record(remote, target, &outcome.request_traces);
    record.action = Action::Reject;
    record.rejected_by = Some(rejected_by);
    record.status_code = Some(403);
    pending.emit(&record);
}

fn emit_tunnel_handshake(sink: &Arc<dyn AuditSink>, remote: &str, target: &ConnectTarget, traces: &[Trace]) {
    let mut pending = PendingAudit::new(sink.clone(), Some(remote.to_string()));
    let mut record = base_tunnel_record(remote, target, traces);
    record.action = Action::Allow;
    record.status_code = Some(200);
    pending.emit(&record);
}

fn base_tunnel_record(remote: &str, target: &ConnectTarget, traces: &[Trace]) -> AuditRecord {
    AuditRecord {
        host: target.host.clone(),
        method: "CONNECT".into(),
        path: String::new(),
        remote_addr: Some(remote.to_string()),
        sni: None,
        mode: Mode::Tunnel,
        action: Action::Allow,
        status_code: None,
        duration_ms: 0.0,
        rejected_by: None,
        stubbed_by: None,
        error: None,
        request_transforms: traces.to_vec(),
        response_transforms: Vec::new(),
        tunnel: None,
        guard: None,
        body_capture: None,
    }
}
