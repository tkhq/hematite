//! agentbench — realistic AI-agent traffic for the hematite vs iron-proxy
//! bench.
//!
//! Two modes, one binary:
//!   agentbench serve  --cert C --key K [--bind 0.0.0.0:443]
//!       Mock LLM upstream: POST /v1/chat streams SSE chunks at the cadence
//!       the request body asks for; GET /tool answers small JSON.
//!   agentbench attack --target NAME [--proxy URL] --ca /certs/ca.crt
//!                     --out results/agent-NAME.json
//!       Replays "agent sessions" open-loop (Poisson arrivals): an optional
//!       denied request (10%), one chat POST (8-32KB body, proxy token in
//!       Authorization) whose SSE response is consumed chunk-by-chunk, then
//!       a burst of 6 parallel tool GETs. Phase 1 steady, phase 2 burst.
//!
//! Metrics per phase and class: p50/p99 latency, chat TTFT (time to first
//! SSE chunk) and max inter-chunk stall, error counts. Open-loop arrival
//! means a slow proxy queues sessions instead of throttling the generator,
//! which is what keeps p99 honest.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls;

// ---------------------------------------------------------------------------
// Small deterministic-enough RNG (no rand dependency).
// ---------------------------------------------------------------------------

struct XorShift(u64);

impl XorShift {
    fn seeded() -> Self {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        XorShift(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// Uniform float in [0, 1).
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Uniform integer in [lo, hi].
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
    /// Exponential inter-arrival for a Poisson process at `rate_hz`.
    fn exp_interval(&mut self, rate_hz: f64) -> Duration {
        let u = self.f64().max(1e-12);
        Duration::from_secs_f64(-u.ln() / rate_hz)
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Series {
    values_ms: Vec<f64>,
    errors: u64,
}

#[derive(Serialize)]
struct SeriesOut {
    count: usize,
    errors: u64,
    p50_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

impl Series {
    fn out(&self) -> SeriesOut {
        let mut v = self.values_ms.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        SeriesOut {
            count: v.len(),
            errors: self.errors,
            p50_ms: percentile(&v, 0.50),
            p99_ms: percentile(&v, 0.99),
            max_ms: v.last().copied().unwrap_or(0.0),
        }
    }
}

/// Per-phase recorder; class name -> series.
#[derive(Default)]
struct Recorder {
    series: Mutex<HashMap<&'static str, Series>>,
}

impl Recorder {
    fn record(&self, class: &'static str, ms: f64) {
        self.series
            .lock()
            .unwrap()
            .entry(class)
            .or_default()
            .values_ms
            .push(ms);
    }
    fn error(&self, class: &'static str) {
        self.series.lock().unwrap().entry(class).or_default().errors += 1;
    }
    fn out(&self) -> HashMap<&'static str, SeriesOut> {
        self.series
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.out()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize)]
struct Profile {
    steady_secs: u64,
    steady_sessions_per_min: f64,
    burst_secs: u64,
    burst_multiplier: f64,
    tool_calls_per_session: u64,
    chat_body_bytes_min: u64,
    chat_body_bytes_max: u64,
    sse_chunks_min: u64,
    sse_chunks_max: u64,
    sse_interval_ms: u64,
    denied_probability: f64,
}

impl Profile {
    fn from_env() -> Self {
        let env_u64 = |k: &str, d: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let env_f64 = |k: &str, d: f64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        Profile {
            steady_secs: env_u64("AGENT_STEADY_SECS", 90),
            steady_sessions_per_min: env_f64("AGENT_STEADY_RATE_PER_MIN", 30.0),
            burst_secs: env_u64("AGENT_BURST_SECS", 30),
            burst_multiplier: env_f64("AGENT_BURST_MULT", 10.0),
            tool_calls_per_session: env_u64("AGENT_TOOL_CALLS", 6),
            chat_body_bytes_min: env_u64("AGENT_CHAT_BODY_MIN", 8 * 1024),
            chat_body_bytes_max: env_u64("AGENT_CHAT_BODY_MAX", 32 * 1024),
            // 4-12s of streaming at 40 chunks/s.
            sse_chunks_min: env_u64("AGENT_SSE_CHUNKS_MIN", 160),
            sse_chunks_max: env_u64("AGENT_SSE_CHUNKS_MAX", 480),
            sse_interval_ms: env_u64("AGENT_SSE_INTERVAL_MS", 25),
            denied_probability: env_f64("AGENT_DENIED_PROB", 0.10),
        }
    }
}

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

// ---------------------------------------------------------------------------
// serve mode — mock LLM upstream
// ---------------------------------------------------------------------------

fn install_ring() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

async fn serve() -> std::io::Result<()> {
    let cert_path = arg("--cert").unwrap_or_else(|| "/certs/echo.fullchain.crt".into());
    let key_path = arg("--key").unwrap_or_else(|| "/certs/echo.key".into());
    let bind = arg("--bind").unwrap_or_else(|| "0.0.0.0:443".into());

    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(
        &cert_path,
    )?))
    .collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(
        &key_path,
    )?))?
    .expect("private key");
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server tls config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("agentbench serve: listening on {bind}");
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            // Keep-alive loop: serve requests until the peer closes.
            loop {
                let Some((path, body)) = read_request(&mut tls).await else {
                    return;
                };
                if path.starts_with("/v1/chat") {
                    let (chunks, interval_ms) = serde_json::from_slice::<serde_json::Value>(&body)
                        .ok()
                        .map(|v| {
                            (
                                v["chunks"].as_u64().unwrap_or(200),
                                v["interval_ms"].as_u64().unwrap_or(25),
                            )
                        })
                        .unwrap_or((200, 25));
                    let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                                cache-control: no-cache\r\nconnection: close\r\n\r\n";
                    if tls.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for i in 0..chunks {
                        let event = format!("data: {{\"tok\":{i}}}\n\n");
                        if tls.write_all(event.as_bytes()).await.is_err() {
                            return;
                        }
                        if tls.flush().await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                    }
                    let _ = tls.shutdown().await;
                    return; // connection: close
                } else if path.starts_with("/tool") {
                    let body = br#"{"result":"ok","items":[1,2,3],"pad":"xxxxxxxxxxxxxxxx"}"#;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\n\r\n",
                        body.len()
                    );
                    if tls.write_all(head.as_bytes()).await.is_err()
                        || tls.write_all(body).await.is_err()
                    {
                        return;
                    }
                } else {
                    let head = "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";
                    if tls.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                }
            }
        });
    }
}

/// Read one HTTP/1.1 request (headers + content-length body) off the stream.
/// Returns (path, body), or None on close/parse failure.
async fn read_request<S: AsyncReadExt + Unpin>(s: &mut S) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_headers_end(&buf) {
            break pos;
        }
        match s.read(&mut tmp).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.len() > 128 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let path = request_line.split_whitespace().nth(1)?.to_string();
    let content_length: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        match s.read(&mut tmp).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(content_length);
    Some((path, body))
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

// ---------------------------------------------------------------------------
// attack mode — client
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Target {
    /// `Some(host, port)` = CONNECT through this proxy; `None` = direct.
    proxy: Option<(String, u16)>,
    tls: Arc<rustls::ClientConfig>,
}

fn client_tls(ca_path: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(ca_path).expect("ca file"),
    ))
    .collect::<Result<_, _>>()
    .expect("parse ca");
    for c in certs {
        roots.add(c).expect("add root");
    }
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

enum Reach {
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// CONNECT was refused by the proxy (the denied-class success case).
    ConnectRefused,
}

/// Reach `authority` (host:port): direct, or via CONNECT when proxied.
async fn reach(target: &Target, host: &str, port: u16) -> std::io::Result<Reach> {
    let tcp = match &target.proxy {
        None => timeout_connect(host, port).await?,
        Some((phost, pport)) => {
            let mut tcp = timeout_connect(phost, *pport).await?;
            let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
            tcp.write_all(req.as_bytes()).await?;
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            while find_headers_end(&buf).is_none() {
                let n = tcp.read(&mut tmp).await?;
                if n == 0 {
                    return Ok(Reach::ConnectRefused);
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let status_ok = buf
                .split(|&b| b == b' ')
                .nth(1)
                .map(|s| s.starts_with(b"200"))
                .unwrap_or(false);
            if !status_ok {
                return Ok(Reach::ConnectRefused);
            }
            tcp
        }
    };
    let connector = tokio_rustls::TlsConnector::from(target.tls.clone());
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| std::io::Error::other("bad server name"))?;
    let tls = connector.connect(name, tcp).await?;
    Ok(Reach::Tls(Box::new(tls)))
}

async fn timeout_connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
        .await
        .map_err(|_| std::io::Error::other("connect timeout"))?
}

struct ChatOutcome {
    total_ms: f64,
    ttft_ms: f64,
    max_stall_ms: f64,
}

/// POST /v1/chat and consume the SSE stream chunk-by-chunk.
async fn chat(
    target: &Target,
    llm_host: &str,
    llm_port: u16,
    body: String,
    expect_chunks: u64,
) -> Result<ChatOutcome, String> {
    let started = Instant::now();
    let stream = reach(target, llm_host, llm_port)
        .await
        .map_err(|e| e.to_string())?;
    let Reach::Tls(mut tls) = stream else {
        return Err("chat CONNECT refused".into());
    };
    let req = format!(
        "POST /v1/chat HTTP/1.1\r\nHost: {llm_host}\r\n\
         Authorization: Bearer proxy-bench-token-123\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut ttft: Option<f64> = None;
    let mut last_chunk = Instant::now();
    let mut max_stall = 0.0f64;
    let mut chunks_seen: u64 = 0;
    let mut headers_done = false;
    let deadline = started + Duration::from_secs(120);
    loop {
        let n = tokio::time::timeout_at(deadline.into(), tls.read(&mut tmp))
            .await
            .map_err(|_| "chat deadline".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if !headers_done {
            if let Some(pos) = find_headers_end(&buf) {
                let head = String::from_utf8_lossy(&buf[..pos]);
                if !head.starts_with("HTTP/1.1 200") {
                    return Err(format!(
                        "chat status: {}",
                        head.lines().next().unwrap_or("?")
                    ));
                }
                headers_done = true;
                buf.drain(..pos + 4);
            } else {
                continue;
            }
        }
        // Count SSE events as they arrive; each read that carries data is a
        // "chunk arrival" for stall accounting.
        let events = buf.windows(2).filter(|w| w == b"\n\n").count() as u64;
        if events > chunks_seen {
            let now = Instant::now();
            if ttft.is_none() {
                ttft = Some((now - started).as_secs_f64() * 1000.0);
            } else {
                max_stall = max_stall.max((now - last_chunk).as_secs_f64() * 1000.0);
            }
            last_chunk = now;
            chunks_seen = events;
        }
        // Proxies may keep the client leg alive after the chunked response
        // ends, so end-of-stream is detected by count, not EOF.
        if chunks_seen >= expect_chunks {
            break;
        }
    }
    if chunks_seen < expect_chunks {
        return Err(format!(
            "chat truncated: {chunks_seen}/{expect_chunks} chunks"
        ));
    }
    Ok(ChatOutcome {
        total_ms: started.elapsed().as_secs_f64() * 1000.0,
        ttft_ms: ttft.unwrap_or(0.0),
        max_stall_ms: max_stall,
    })
}

/// One small GET /tool round-trip on a fresh connection.
async fn tool_call(target: &Target, llm_host: &str, llm_port: u16) -> Result<f64, String> {
    let started = Instant::now();
    let stream = reach(target, llm_host, llm_port)
        .await
        .map_err(|e| e.to_string())?;
    let Reach::Tls(mut tls) = stream else {
        return Err("tool CONNECT refused".into());
    };
    let req = format!("GET /tool HTTP/1.1\r\nHost: {llm_host}\r\n\r\n");
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    // Read headers + exactly content-length body bytes; the server keeps the
    // connection open (keep-alive), so waiting for EOF would hang.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    let header_end = loop {
        if let Some(pos) = find_headers_end(&buf) {
            break pos;
        }
        let n = tokio::time::timeout_at(deadline.into(), tls.read(&mut tmp))
            .await
            .map_err(|_| "tool timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("tool early close".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    if !buf.starts_with(b"HTTP/1.1 200") {
        return Err("tool non-200".into());
    }
    let content_length: usize = String::from_utf8_lossy(&buf[..header_end])
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + 4 + content_length {
        let n = tokio::time::timeout_at(deadline.into(), tls.read(&mut tmp))
            .await
            .map_err(|_| "tool timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("tool truncated".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

/// A request the policy must reject; success = fast, definitive refusal.
async fn denied_request(target: &Target, denied_host: &str, port: u16) -> Result<f64, String> {
    let started = Instant::now();
    match reach(target, denied_host, port).await {
        Ok(Reach::ConnectRefused) => Ok(started.elapsed().as_secs_f64() * 1000.0),
        Ok(Reach::Tls(_)) => Err("denied host was reachable".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Clone)]
struct Endpoints {
    llm_host: String,
    llm_port: u16,
    denied_host: String,
    denied_port: u16,
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    target: Target,
    profile: Profile,
    ep: Endpoints,
    with_denied: bool,
    body_bytes: u64,
    chunks: u64,
    recorder: Arc<Recorder>,
) {
    if with_denied {
        match denied_request(&target, &ep.denied_host, ep.denied_port).await {
            Ok(ms) => recorder.record("denied", ms),
            Err(e) => {
                eprintln!("session error [denied]: {e}");
                recorder.error("denied");
            }
        }
    }
    let pad = "x".repeat(body_bytes as usize);
    let body = format!(
        "{{\"chunks\":{chunks},\"interval_ms\":{},\"messages\":[{{\"role\":\"user\",\"content\":\"{pad}\"}}]}}",
        profile.sse_interval_ms
    );
    match chat(&target, &ep.llm_host, ep.llm_port, body, chunks).await {
        Ok(o) => {
            recorder.record("chat", o.total_ms);
            recorder.record("chat_ttft", o.ttft_ms);
            recorder.record("chat_stall", o.max_stall_ms);
        }
        Err(e) => {
            eprintln!("session error [chat]: {e}");
            recorder.error("chat");
        }
    }
    let mut tools = Vec::new();
    for _ in 0..profile.tool_calls_per_session {
        let t = target.clone();
        let e = ep.clone();
        tools.push(tokio::spawn(async move {
            tool_call(&t, &e.llm_host, e.llm_port).await
        }));
    }
    for t in tools {
        match t.await {
            Ok(Ok(ms)) => recorder.record("tool", ms),
            _ => recorder.error("tool"),
        }
    }
}

#[derive(Serialize)]
struct PhaseOut {
    start_epoch_ms: u128,
    end_epoch_ms: u128,
    sessions_launched: u64,
    classes: HashMap<&'static str, SeriesOut>,
}

async fn run_phase(
    rate_per_sec: f64,
    duration: Duration,
    target: &Target,
    profile: &Profile,
    ep: &Endpoints,
    rng: &mut XorShift,
) -> PhaseOut {
    let recorder = Arc::new(Recorder::default());
    let start_epoch_ms = epoch_ms();
    let started = Instant::now();
    let mut handles = Vec::new();
    let mut launched = 0u64;
    while started.elapsed() < duration {
        let wait = rng.exp_interval(rate_per_sec);
        tokio::time::sleep(wait.min(duration.saturating_sub(started.elapsed()))).await;
        if started.elapsed() >= duration {
            break;
        }
        launched += 1;
        // Denied-class requests only make sense through a policy boundary;
        // the baseline target has none.
        let with_denied = target.proxy.is_some() && rng.f64() < profile.denied_probability;
        let body_bytes = rng.range(profile.chat_body_bytes_min, profile.chat_body_bytes_max);
        let chunks = rng.range(profile.sse_chunks_min, profile.sse_chunks_max);
        handles.push(tokio::spawn(run_session(
            target.clone(),
            profile.clone(),
            ep.clone(),
            with_denied,
            body_bytes,
            chunks,
            recorder.clone(),
        )));
    }
    // Drain: sessions run to completion so the tail is measured, not cut.
    for h in handles {
        let _ = h.await;
    }
    PhaseOut {
        start_epoch_ms,
        end_epoch_ms: epoch_ms(),
        sessions_launched: launched,
        classes: recorder.out(),
    }
}

fn split_authority(s: &str) -> (String, u16) {
    match s.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().unwrap_or(443))
        }
        _ => (s.to_string(), 443),
    }
}

fn epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

#[derive(Serialize)]
struct AttackOut {
    target: String,
    profile: Profile,
    steady: PhaseOut,
    burst: PhaseOut,
}

async fn attack() -> std::io::Result<()> {
    let target_name = arg("--target").expect("--target required");
    let proxy = arg("--proxy").filter(|p| !p.is_empty()).map(|p| {
        let p = p.trim_start_matches("http://");
        let (h, port) = p.split_once(':').expect("proxy host:port");
        (h.to_string(), port.trim_end_matches('/').parse().unwrap())
    });
    let ca = arg("--ca").unwrap_or_else(|| "/certs/ca.crt".into());
    let out_path = arg("--out").unwrap_or_else(|| format!("agent-{target_name}.json"));
    // host or host:port (port defaults to 443).
    let (llm_host, llm_port) = split_authority(&arg("--llm").unwrap_or_else(|| "llm.test".into()));
    let (denied_host, denied_port) =
        split_authority(&arg("--denied").unwrap_or_else(|| "denied.test".into()));

    let profile = Profile::from_env();
    let target = Target {
        proxy,
        tls: client_tls(&ca),
    };
    let mut rng = XorShift::seeded();

    let steady_rate = profile.steady_sessions_per_min / 60.0;
    eprintln!(
        "agentbench attack [{target_name}]: steady {}s @ {}/min",
        profile.steady_secs, profile.steady_sessions_per_min
    );
    let ep = Endpoints {
        llm_host,
        llm_port,
        denied_host,
        denied_port,
    };
    let steady = run_phase(
        steady_rate,
        Duration::from_secs(profile.steady_secs),
        &target,
        &profile,
        &ep,
        &mut rng,
    )
    .await;
    eprintln!(
        "agentbench attack [{target_name}]: burst {}s @ {}x",
        profile.burst_secs, profile.burst_multiplier
    );
    let burst = run_phase(
        steady_rate * profile.burst_multiplier,
        Duration::from_secs(profile.burst_secs),
        &target,
        &profile,
        &ep,
        &mut rng,
    )
    .await;

    let out = AttackOut {
        target: target_name,
        profile,
        steady,
        burst,
    };
    std::fs::write(&out_path, serde_json::to_vec_pretty(&out).unwrap())?;
    eprintln!("agentbench attack: wrote {out_path}");
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    install_ring();
    match std::env::args().nth(1).as_deref() {
        Some("serve") => serve().await,
        Some("attack") => attack().await,
        _ => {
            eprintln!("usage: agentbench <serve|attack> [flags]");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_picks_expected_ranks() {
        let v: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        assert_eq!(percentile(&v, 0.50), 51.0);
        assert_eq!(percentile(&v, 0.99), 99.0);
        assert_eq!(percentile(&[], 0.99), 0.0);
    }

    #[test]
    fn exp_interval_mean_is_roughly_inverse_rate() {
        let mut rng = XorShift(42);
        let n = 20_000;
        let total: f64 = (0..n).map(|_| rng.exp_interval(2.0).as_secs_f64()).sum();
        let mean = total / n as f64;
        assert!((mean - 0.5).abs() < 0.05, "mean {mean}");
    }

    #[test]
    fn request_parser_handles_split_reads() {
        // find_headers_end drives the serve-side reader; verify boundaries.
        // Returns the start of the terminator; callers slice head=..pos and
        // body=pos+4.. ("GET / HTTP/1.1" is 14 bytes).
        assert_eq!(find_headers_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_headers_end(b"partial\r\n"), None);
    }
}
