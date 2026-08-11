//! Part 09 §4 — the management API: `POST /v1/reload`, bearer-authenticated
//! with a constant-time comparison. Reload builds a complete new runtime
//! and swaps it atomically; in-flight requests finish on the old one.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::config::{build_runtime, load_str, ListenKeys};
use crate::state::SharedState;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

fn text(status: StatusCode, body: &str) -> Response<OutBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())).map_err(|e| match e {}).boxed())
        .expect("static response")
}

/// Constant-time equality; length difference folds into the accumulator.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

/// The reload decision, separated from HTTP for testability.
/// Returns (status, message).
pub fn reload(
    config_path: &std::path::Path,
    current_listen: &ListenKeys,
    state: &SharedState,
    env: &dyn Fn(&str) -> Option<String>,
) -> (u16, String) {
    // Other failures → 500 (Part 09 §4): the file being unreadable is not
    // a validation error.
    let yaml = match std::fs::read_to_string(config_path) {
        Ok(y) => y,
        Err(e) => return (500, format!("cannot read config: {e}")),
    };
    // Invalid new config → 422; the old config keeps serving untouched.
    let config = match load_str(&yaml, env) {
        Ok(c) => c,
        Err(e) => return (422, e.to_string()),
    };
    if config.listen != *current_listen {
        return (422, "listener addresses are not reloadable in v1 (Part 09 §4)".into());
    }
    match build_runtime(&config) {
        Ok(runtime) => {
            state.swap(runtime);
            (200, "reloaded".into())
        }
        Err(e) => (422, e.to_string()),
    }
}

/// Serve the management listener. `api_key` was validated non-empty at
/// boot (Part 09 §3).
pub async fn serve_management(
    listener: TcpListener,
    state: SharedState,
    api_key: String,
    config_path: PathBuf,
    current_listen: ListenKeys,
) -> std::io::Result<()> {
    let api_key = Arc::new(api_key);
    let current_listen = Arc::new(current_listen);
    let config_path = Arc::new(config_path);
    loop {
        let (stream, _remote) = listener.accept().await?;
        let state = state.clone();
        let api_key = api_key.clone();
        let current_listen = current_listen.clone();
        let config_path = config_path.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let state = state.clone();
                let api_key = api_key.clone();
                let current_listen = current_listen.clone();
                let config_path = config_path.clone();
                async move {
                    if req.method() != hyper::Method::POST || req.uri().path() != "/v1/reload" {
                        return Ok::<_, std::convert::Infallible>(text(StatusCode::NOT_FOUND, "not found"));
                    }
                    let authorized = req
                        .headers()
                        .get(hyper::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.strip_prefix("Bearer "))
                        .map(|token| constant_time_eq(token.as_bytes(), api_key.as_bytes()))
                        .unwrap_or(false);
                    if !authorized {
                        return Ok(text(StatusCode::UNAUTHORIZED, "unauthorized"));
                    }
                    // Spawned so the reload completes even if the client
                    // disconnects (Part 09 §4).
                    let handle = tokio::spawn(async move {
                        reload(&config_path, &current_listen, &state, &crate::config::os_env)
                    });
                    let (status, message) = match handle.await {
                        Ok(r) => r,
                        Err(_) => (500, "reload task failed".to_string()),
                    };
                    Ok(text(
                        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        &message,
                    ))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}
