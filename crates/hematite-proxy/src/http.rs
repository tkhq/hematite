//! Part 05 §1–§5 and §6 — common request handling; the HTTP, HTTPS-MITM,
//! and tunnel listeners; WebSocket/SSE streaming; and failure behavior.
//!
//! Header-name wire casing is preserved end to end via hyper's
//! `preserve_header_case` on both the inbound server and the upstream
//! client, with the case map riding on the request parts' extensions.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HyperBody, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use hematite_kernel::audit::{Action, AuditRecord, TunnelGroup};
use hematite_kernel::pipeline::{Outcome, PipelineOutcome, ResponseAction};
use hematite_kernel::summary::{Body, Headers, Mode, RequestSummary};
use hematite_kernel::verdict::Trace;

use tracing::Instrument as _;

use crate::audit::{AuditSink, PendingAudit};
use crate::dial::{connect_upstream, DialError};
use crate::hop::strip_hop_by_hop;
use crate::state::SharedState;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

fn empty_body() -> OutBody {
    Full::new(Bytes::new()).map_err(|e| match e {}).boxed()
}

fn bytes_body(bytes: Vec<u8>) -> OutBody {
    Full::new(Bytes::from(bytes))
        .map_err(|e| match e {})
        .boxed()
}

/// Per-connection context: what the listener knows that the request itself
/// does not. Shared by every request served on one connection.
pub struct ConnCtx {
    pub state: SharedState,
    pub sink: Arc<dyn AuditSink>,
    pub remote_addr: String,
    /// `http`, `https`, or `tunnel` (Part 01 §1).
    pub mode: Mode,
    /// Client SNI when the leg was TLS-terminated.
    pub sni: Option<String>,
    /// Upstream scheme: https when the client leg was TLS-terminated
    /// (Part 07 §1).
    pub scheme_https: bool,
    /// Tunnel listeners fix the upstream (CONNECT target) and carry the
    /// handshake traces + `tunnel.target` for audit (Part 05 §4.3).
    pub forced_upstream: Option<(String, u16)>,
    pub tunnel_target: Option<String>,
    pub tunnel_traces: Vec<Trace>,
}

/// Serve one accepted connection (plaintext or TLS) over hyper's automatic
/// HTTP/1.1-or-HTTP/2 server, dispatching every request to `handle`.
pub async fn serve_io<IO>(io: IO, ctx: Arc<ConnCtx>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| handle(req, ctx.clone()));
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        // Keep serving after the client half-closes its write side, so a
        // request-then-shutdown client still receives the response.
        .half_close(true)
        // Record the wire casing of header names so it can be reproduced
        // toward the upstream (Part 01 §1, Part 02 §5).
        .preserve_header_case(true);
    // with_upgrades so a WebSocket handshake can switch to byte copy
    // (Part 05 §5).
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(io), service)
        .await;
}

/// Serve the plain-HTTP listener until the socket closes (Part 05 §2, L1).
pub async fn serve_http(
    listener: TcpListener,
    state: SharedState,
    sink: Arc<dyn AuditSink>,
) -> std::io::Result<()> {
    loop {
        let (stream, remote) = listener.accept().await?;
        let ctx = Arc::new(ConnCtx {
            state: state.clone(),
            sink: sink.clone(),
            remote_addr: remote.to_string(),
            mode: Mode::Http,
            sni: None,
            scheme_https: false,
            forced_upstream: None,
            tunnel_target: None,
            tunnel_traces: Vec::new(),
        });
        tokio::spawn(serve_io(stream, ctx));
    }
}

/// `host[:port]` → (lowercase hostname, port). Handles bracketed IPv6.
fn split_host_port(s: &str) -> (String, Option<u16>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_ascii_lowercase();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok());
            return (host, port);
        }
    }
    match s.rsplit_once(':') {
        // A second ':' means an unbracketed IPv6 literal, not a port.
        Some((h, p)) if !h.contains(':') => (h.to_ascii_lowercase(), p.parse().ok()),
        _ => (s.to_ascii_lowercase(), None),
    }
}

/// Percent-decode one path segment (invalid escapes pass through).
fn percent_decode(segment: &str) -> Vec<u8> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(hex) = bytes.get(i + 1..i + 3) {
                if let Ok(byte) = u8::from_str_radix(std::str::from_utf8(hex).unwrap_or("zz"), 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Part 01 §1 / Part 05 §1 step 2 — reject `.` / `..` segments, checked on
/// the percent-decoded segments (threat T6).
fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|seg| {
        let decoded = percent_decode(seg);
        decoded == b"." || decoded == b".."
    })
}

/// Forward body: the buffered prefix chained with the unread remainder of
/// the client stream (the over-cap path of Part 01 §4).
struct ChainBody {
    prefix: Option<Bytes>,
    inner: Pin<Box<Incoming>>,
}

impl HyperBody for ChainBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        self.inner
            .as_mut()
            .poll_frame(cx)
            .map(|opt| opt.map(|res| res.map_err(|e| Box::new(e) as BoxError)))
    }
}

struct Target {
    host: String,
    port: u16,
    path: String,
    query: String,
}

enum TargetError {
    /// 400 with the given reason; `host` may be empty (pre-extraction).
    Bad { reason: &'static str, host: String },
}

/// Resolve the upstream target for a request. A tunnel fixes host/port to
/// the CONNECT target (path/query still from the inner request-target); a
/// TLS leg additionally requires SNI to equal the Host hostname
/// (Part 05 §1 step 3, threat T6).
fn resolve_target(req: &Request<Incoming>, ctx: &ConnCtx) -> Result<Target, TargetError> {
    if let Some((host, port)) = &ctx.forced_upstream {
        let uri = req.uri();
        return Ok(Target {
            host: host.clone(),
            port: *port,
            path: uri.path().to_string(),
            query: uri.query().unwrap_or("").to_string(),
        });
    }
    let default_port = if ctx.scheme_https { 443 } else { 80 };
    let target = extract_target(req, default_port)?;
    if let Some(sni) = &ctx.sni {
        // SNI == Host (ports ignored) for the origin-form HTTPS listener.
        let sni_host = split_host_port(sni).0;
        if sni_host != target.host {
            return Err(TargetError::Bad {
                reason: "SNI does not match Host",
                host: target.host,
            });
        }
    }
    Ok(target)
}

fn extract_target(req: &Request<Incoming>, default_port: u16) -> Result<Target, TargetError> {
    let uri = req.uri();
    let host_header = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(split_host_port);
    // HTTP/2 and absolute-form both carry the authority in the URI; the
    // `:authority` pseudo-header is the host when no `Host` header is sent.
    let authority = uri
        .authority()
        .map(|a| (a.host().to_ascii_lowercase(), a.port_u16()));

    let (host, port) = match (authority, &host_header) {
        // Both present: they must agree (hostnames compared, ports ignored).
        (Some((ah, ap)), Some((hh, _))) => {
            if ah != *hh {
                return Err(TargetError::Bad {
                    reason: "request-target authority disagrees with Host header",
                    host: ah,
                });
            }
            (ah, ap.unwrap_or(default_port))
        }
        // Authority only (HTTP/2, or absolute-form without a Host header).
        (Some((ah, ap)), None) => (ah, ap.unwrap_or(default_port)),
        // Origin-form: host from the Host header.
        (None, Some((hh, hp))) if !hh.is_empty() => (hh.clone(), hp.unwrap_or(default_port)),
        _ => {
            return Err(TargetError::Bad {
                reason: "missing or empty Host / authority",
                host: String::new(),
            })
        }
    };

    Ok(Target {
        host,
        port,
        path: uri.path().to_string(),
        query: uri.query().unwrap_or("").to_string(),
    })
}

fn base_record(ctx: &ConnCtx, host: &str, method: &str, path: &str, action: Action) -> AuditRecord {
    AuditRecord {
        host: host.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        remote_addr: Some(ctx.remote_addr.clone()),
        sni: ctx.sni.clone(),
        mode: ctx.mode,
        action,
        status_code: None,
        duration_ms: 0.0,
        rejected_by: None,
        stubbed_by: None,
        error: None,
        request_transforms: Vec::new(),
        response_transforms: Vec::new(),
        // In-tunnel requests carry the handshake's traces (Part 08 §2).
        tunnel: ctx.tunnel_target.as_ref().map(|target| TunnelGroup {
            target: target.clone(),
            request_transforms: ctx.tunnel_traces.clone(),
            passthrough: false,
        }),
        guard: None,
        body_capture: None,
    }
}

/// A valid WebSocket upgrade handshake (Part 05 §5): GET with
/// `Upgrade: websocket` and `Connection` listing `upgrade`.
fn is_websocket(req: &Request<Incoming>) -> bool {
    if req.method() != hyper::Method::GET {
        return false;
    }
    let upgrade = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = req
        .headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    upgrade && connection
}

async fn handle(
    mut req: Request<Incoming>,
    ctx: Arc<ConnCtx>,
) -> Result<Response<OutBody>, BoxError> {
    let runtime = ctx.state.current();
    let started = Instant::now();
    let mut pending = PendingAudit::new(ctx.sink.clone(), Some(ctx.remote_addr.clone()));
    let method = req.method().as_str().to_string();

    // A WebSocket handshake takes the byte-copy path after the pipeline
    // approves it; capture the client upgrade future before decomposing.
    let is_ws = is_websocket(&req);
    let client_upgrade = if is_ws {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    // Part 05 §1 steps 1–2. A tunnel fixes the upstream to the CONNECT
    // target; the path/query still come from the inner request-target.
    let target = match resolve_target(&req, &ctx) {
        Ok(t) => t,
        Err(TargetError::Bad { reason, host }) => {
            let mut record = base_record(&ctx, &host, &method, req.uri().path(), Action::Reject);
            record.rejected_by = Some("listener".into());
            record.status_code = Some(400);
            record.error = None;
            record.duration_ms = ms_since(started);
            pending.emit(&record);
            let _ = reason;
            return Ok(status_response(StatusCode::BAD_REQUEST));
        }
    };
    if has_dot_segment(&target.path) {
        let mut record = base_record(&ctx, &target.host, &method, &target.path, Action::Reject);
        record.rejected_by = Some("listener".into());
        record.status_code = Some(400);
        record.duration_ms = ms_since(started);
        pending.emit(&record);
        return Ok(status_response(StatusCode::BAD_REQUEST));
    }

    // Root span for this request.  Created after resolving the target so we
    // have host/port/path available as span attributes.
    //
    // Incoming `traceparent`: no extractor is installed, so roots are always
    // fresh — this is by design (trust model: the proxy does not propagate
    // upstream tracing context from clients into its own spans or onwards).
    // No injector is installed either, so nothing is added to upstream
    // requests.
    let span = tracing::info_span!(
        "hematite.request",
        otel.name = "hematite.request",
        method = %method,
        host = %target.host,
        port = target.port,
        path = %target.path,
        mode = ?ctx.mode,
        action = tracing::field::Empty,
        rejected_by = tracing::field::Empty,
        status = tracing::field::Empty,
    );

    // Headers, wire order preserved (names arrive lowercased from hyper).
    let header_pairs: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();

    // Part 01 §4 — buffer up to the cap; over-cap bodies keep the unread
    // remainder for streaming forward.
    let cap = runtime.max_request_body_bytes;
    // Keep the request parts: their extensions carry hyper's original
    // header-case map, which the upstream client replays (Part 02 §5).
    let (mut parts, mut incoming) = req.into_parts();
    let mut buffered: Vec<u8> = Vec::new();
    let mut over_cap = false;
    loop {
        if buffered.len() > cap {
            over_cap = true;
            break;
        }
        match incoming.frame().await {
            None => break,
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    buffered.extend_from_slice(data);
                }
            }
            Some(Err(_)) => {
                // Client disconnect mid-request (Part 05 §6): no usable
                // response; audit `client_cancel`.
                let mut record = base_record(
                    &ctx,
                    &target.host,
                    &method,
                    &target.path,
                    Action::ClientCancel,
                );
                record.action = Action::ClientCancel;
                record.duration_ms = ms_since(started);
                record_outcome(&span, &record);
                pending.emit(&record);
                return Ok(status_response(StatusCode::BAD_REQUEST));
            }
        }
    }

    let kernel_body = if over_cap {
        Body::new(buffered[..cap.min(buffered.len())].to_vec(), true)
    } else {
        Body::new(buffered.clone(), false)
    };

    let mut summary = RequestSummary {
        mode: ctx.mode,
        method: method.clone(),
        host: target.host.clone(),
        port: target.port,
        path: target.path.clone(),
        query: target.query.clone(),
        headers: Headers::new(header_pairs),
        body: kernel_body,
        sni: ctx.sni.clone(),
        remote_addr: Some(ctx.remote_addr.clone()),
    };

    // Part 05 §1 step 4 — run the pipeline.
    let PipelineOutcome {
        outcome,
        request_traces,
        body_capture,
        request_path,
    } = runtime.pipeline.evaluate_request(&mut summary);

    // A record template carrying everything the request path produced. The
    // path is the pre-transform snapshot: a match_path secrets swap writes
    // the real credential into summary.path (Part 08 §3, INV-1).
    let mut record = base_record(&ctx, &summary.host, &method, &request_path, Action::Allow);
    record.request_transforms = request_traces;
    record.body_capture = body_capture;

    let proof = match outcome {
        Outcome::Reject { by, response } => {
            record.action = Action::Reject;
            record.status_code = Some(response.as_ref().map(|r| r.status).unwrap_or(403));
            record.rejected_by = Some(by);
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            return Ok(match response {
                Some(r) => build_response(r),
                None => status_response(StatusCode::FORBIDDEN),
            });
        }
        Outcome::Stub { by, response } => {
            record.action = Action::Stub;
            record.status_code = Some(response.status);
            record.stubbed_by = Some(by);
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            return Ok(build_response(response));
        }
        Outcome::Error { by: _, message } => {
            record.action = Action::Error;
            record.status_code = Some(502);
            record.error = Some(message);
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            return Ok(status_response(StatusCode::BAD_GATEWAY));
        }
        Outcome::Continue(proof) => proof,
    };

    // Part 07 — dial with the guard. Tunnels dial the CONNECT target, not
    // a rewritten host; the scheme follows the client leg.
    let (dial_host, dial_port) = match &ctx.forced_upstream {
        Some((h, p)) => (h.clone(), *p),
        None => (summary.host.clone(), summary.port),
    };
    let dial_span = tracing::info_span!(
        parent: &span,
        "dial",
        host = %dial_host,
        port = dial_port,
    );
    let stream = match connect_upstream(proof, &dial_host, dial_port, ctx.scheme_https, &runtime)
        .instrument(dial_span)
        .await
    {
        Ok(s) => s,
        Err(DialError::Denied(denial)) => {
            record.action = Action::Reject;
            record.rejected_by = Some("guard".into());
            record.status_code = Some(502);
            record.guard = Some(denial);
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            return Ok(status_response(StatusCode::BAD_GATEWAY));
        }
        Err(DialError::Failed(message)) => {
            record.action = Action::Error;
            record.status_code = Some(502);
            record.error = Some(message);
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            return Ok(status_response(StatusCode::BAD_GATEWAY));
        }
    };

    // Part 07 §3 — header hygiene. A WebSocket handshake keeps Upgrade /
    // Connection so the switch survives to the upstream (Part 05 §5).
    let mut out_headers: Vec<(String, String)> = summary
        .headers
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    strip_hop_by_hop(&mut out_headers, is_ws);
    if !over_cap {
        // Buffered body forwards with an exact Content-Length re-derived
        // from the (possibly rewritten) bytes (Part 01 §4).
        out_headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-length"));
    }

    let path_and_query = if summary.query.is_empty() {
        summary.path.clone()
    } else {
        format!("{}?{}", summary.path, summary.query)
    };
    let out_body: OutBody = if over_cap {
        ChainBody {
            prefix: Some(Bytes::from(buffered)),
            inner: Box::pin(incoming),
        }
        .boxed()
    } else {
        bytes_body(summary.body.read().to_vec())
    };

    // Rebuild the upstream request on the preserved parts, so their
    // extensions (hyper's original header-case map) ride along and the
    // client replays the wire casing of names (Part 02 §5). Body drops to
    // http/1.1 toward the upstream.
    let build = (|| -> Result<Request<OutBody>, BoxError> {
        parts.method = hyper::Method::from_bytes(summary.method.as_bytes())?;
        parts.uri = path_and_query.parse()?;
        parts.version = hyper::Version::HTTP_11;
        let mut headers = hyper::HeaderMap::new();
        for (name, value) in &out_headers {
            let n = hyper::header::HeaderName::from_bytes(name.as_bytes())?;
            let v = hyper::header::HeaderValue::from_bytes(value.as_bytes())?;
            headers.append(n, v);
        }
        parts.headers = headers;
        Ok(Request::from_parts(parts, out_body))
    })();
    let upstream_req = match build {
        Ok(r) => r,
        Err(e) => {
            record.action = Action::Error;
            record.status_code = Some(502);
            record.error = Some(format!("building upstream request: {e}"));
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            return Ok(status_response(StatusCode::BAD_GATEWAY));
        }
    };

    // Send; the response-header timeout covers time-to-headers (Part 07 §4).
    let upstream_span = tracing::info_span!(parent: &span, "upstream");
    let mut upstream_response = match send_upstream(
        stream,
        upstream_req,
        runtime.upstream_response_header_timeout,
    )
    .instrument(upstream_span)
    .await
    {
        Ok(r) => r,
        Err(message) => {
            record.action = Action::Error;
            record.status_code = Some(502);
            record.error = Some(message);
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            return Ok(status_response(StatusCode::BAD_GATEWAY));
        }
    };

    // Part 05 §5 — WebSocket: on an upstream 101, bridge the two upgraded
    // connections with a bidirectional byte copy. Response transforms do
    // not run on frames; the audit reflects the handshake result.
    if is_ws && upstream_response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
        if let Some(client_upgrade) = client_upgrade {
            tokio::spawn(async move {
                if let (Ok(client), Ok(upstream)) = (client_upgrade.await, upstream_upgrade.await) {
                    let mut client = TokioIo::new(client);
                    let mut upstream = TokioIo::new(upstream);
                    let _ = copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
        record.action = Action::Allow;
        record.status_code = Some(101);
        record.duration_ms = ms_since(started);
        record_outcome(&span, &record);
        pending.emit(&record);

        // Return the upstream's 101 to the client (keep Upgrade/Connection)
        // so hyper performs the client-side switch.
        let (mut parts, _body) = upstream_response.into_parts();
        let mut resp_headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        strip_hop_by_hop(&mut resp_headers, true);
        parts.headers.clear();
        for (name, value) in &resp_headers {
            if let (Ok(n), Ok(v)) = (
                hyper::header::HeaderName::from_bytes(name.as_bytes()),
                hyper::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                parts.headers.append(n, v);
            }
        }
        return Ok(Response::from_parts(parts, empty_body()));
    }

    // Response path (Part 03 §2) — all v1 transforms are no-ops, but the
    // traces are recorded and Reject/Stub/error semantics hold.
    let response_outcome = runtime.pipeline.evaluate_response(&summary);
    record.response_transforms = response_outcome.traces;
    match response_outcome.action {
        ResponseAction::Forward => {
            let status = upstream_response.status();
            record.action = Action::Allow;
            record.status_code = Some(status.as_u16());
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);

            let (mut parts, body) = upstream_response.into_parts();
            let mut resp_headers: Vec<(String, String)> = parts
                .headers
                .iter()
                .map(|(n, v)| {
                    (
                        n.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect();
            strip_hop_by_hop(&mut resp_headers, false);
            parts.headers.clear();
            for (name, value) in &resp_headers {
                if let (Ok(n), Ok(v)) = (
                    hyper::header::HeaderName::from_bytes(name.as_bytes()),
                    hyper::header::HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    parts.headers.append(n, v);
                }
            }
            Ok(Response::from_parts(
                parts,
                body.map_err(|e| Box::new(e) as BoxError).boxed(),
            ))
        }
        ResponseAction::Replace { by, response, stub } => {
            record.action = if stub { Action::Stub } else { Action::Reject };
            record.status_code = Some(response.status);
            if stub {
                record.stubbed_by = Some(by);
            } else {
                record.rejected_by = Some(by);
            }
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            Ok(build_response(response))
        }
        ResponseAction::Error { by: _, message } => {
            record.action = Action::Error;
            record.status_code = Some(502);
            record.error = Some(message);
            record.duration_ms = ms_since(started);
            record_outcome(&span, &record);
            pending.emit(&record);
            Ok(status_response(StatusCode::BAD_GATEWAY))
        }
    }
}

async fn send_upstream<IO>(
    stream: IO,
    req: Request<OutBody>,
    header_timeout: std::time::Duration,
) -> Result<Response<Incoming>, String>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        // Replay the original header-name casing recorded on the request
        // parts (Part 02 §5).
        .preserve_header_case(true)
        .handshake(io)
        .await
        .map_err(|e| format!("upstream handshake: {e}"))?;
    // with_upgrades so a 101 hands the upstream socket to `upgrade::on`
    // for the WebSocket byte copy (Part 05 §5).
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    match tokio::time::timeout(header_timeout, sender.send_request(req)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(format!("upstream request: {e}")),
        Err(_) => Err("upstream response header timeout".into()),
    }
}

fn ms_since(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn status_response(status: StatusCode) -> Response<OutBody> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .expect("static response")
}

/// Record the outcome fields on the root span just before emitting the audit
/// record.  Kept as a helper to avoid duplicating field names at each of the
/// many emit call-sites in `handle`.
fn record_outcome(span: &tracing::Span, record: &hematite_kernel::audit::AuditRecord) {
    span.record("action", tracing::field::debug(&record.action));
    if let Some(rb) = &record.rejected_by {
        span.record("rejected_by", rb.as_str());
    }
    if let Some(sc) = record.status_code {
        span.record("status", sc);
    }
}

fn build_response(r: hematite_kernel::verdict::Response) -> Response<OutBody> {
    let mut builder = Response::builder().status(r.status);
    for (name, value) in &r.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(bytes_body(r.body))
        .unwrap_or_else(|_| status_response(StatusCode::BAD_GATEWAY))
}
