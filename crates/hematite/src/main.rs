//! hematite — one YAML file, one flag (Part 09 §1). L1: serves the
//! plain-HTTP listener and the management API; L2 listeners configured in
//! the file are warned about and skipped.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use hematite_dns::resolve::{DnsConfig, StaticRecord};
use hematite_dns::{DnsDecisionKind, DnsServer};
use hematite_kernel::matcher::DomainGlob;
use hematite_proxy::audit::StderrSink;
use hematite_proxy::config::{build_runtime, load_str, os_env, DnsResolved};
use hematite_proxy::metrics::{DnsOutcome, MetricsSink};
use hematite_proxy::state::SharedState;

/// Build and spawn the DNS server (UDP + TCP) from resolved config.
async fn spawn_dns(
    dns: &DnsResolved,
    on_decision: Option<std::sync::Arc<dyn Fn(DnsDecisionKind) + Send + Sync>>,
) -> Result<(), String> {
    use std::collections::HashMap;
    let mut records = HashMap::new();
    for (name, rtype, value) in &dns.records {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let record = match rtype.as_str() {
            "A" => StaticRecord::A(
                value
                    .parse()
                    .map_err(|_| format!("bad A value {value:?}"))?,
            ),
            "CNAME" => StaticRecord::Cname(value.trim_end_matches('.').to_ascii_lowercase()),
            other => return Err(format!("unsupported record type {other:?}")),
        };
        records.insert(name, record);
    }
    let passthrough = dns
        .passthrough
        .iter()
        .map(|g| DomainGlob::parse(g).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let config = DnsConfig {
        proxy_ip: dns.proxy_ip,
        passthrough,
        records,
        ttl: 60,
    };
    let upstream = dns
        .upstream_resolver
        .parse()
        .map_err(|_| format!("bad upstream_resolver {:?}", dns.upstream_resolver))?;
    let mut server = DnsServer::new(config, upstream);
    if let Some(cb) = on_decision {
        server = server.with_on_decision(cb);
    }
    let server = std::sync::Arc::new(server);

    let udp = tokio::net::UdpSocket::bind(listen_addr(&dns.listen))
        .await
        .map_err(|e| format!("bind dns udp {}: {e}", dns.listen))?;
    let tcp = tokio::net::TcpListener::bind(listen_addr(&dns.listen))
        .await
        .map_err(|e| format!("bind dns tcp {}: {e}", dns.listen))?;
    eprintln!("hematite: dns server on {}", dns.listen);
    tokio::spawn(server.clone().serve_udp(udp));
    tokio::spawn(server.serve_tcp(tcp));
    Ok(())
}

fn listen_addr(key: &str) -> String {
    // ":80" → "0.0.0.0:80"
    if key.starts_with(':') {
        format!("0.0.0.0{key}")
    } else {
        key.to_string()
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let config_path = match (args.next().as_deref(), args.next()) {
        (Some("-config") | Some("--config"), Some(path)) => PathBuf::from(path),
        _ => {
            eprintln!("usage: hematite -config <path.yaml>");
            return ExitCode::from(2);
        }
    };

    let yaml = match std::fs::read_to_string(&config_path) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("hematite: cannot read {}: {e}", config_path.display());
            return ExitCode::FAILURE;
        }
    };
    let config = match load_str(&yaml, &os_env) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hematite: {e}");
            return ExitCode::FAILURE;
        }
    };
    for warning in &config.warnings {
        eprintln!("hematite: warning: {warning}");
    }
    let runtime = match build_runtime(&config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hematite: {e}");
            return ExitCode::FAILURE;
        }
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hematite: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        // The metrics registry lives for the process lifetime; reused on reload.
        // Extract it before moving `runtime` into `SharedState`.
        let metrics = runtime.metrics.clone();
        let state = SharedState::new(runtime);
        let sink: Arc<dyn hematite_proxy::audit::AuditSink> = Arc::new(MetricsSink {
            inner: Arc::new(StderrSink),
            metrics: metrics.clone(),
        });

        let http = match tokio::net::TcpListener::bind(listen_addr(&config.listen.http)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hematite: bind {}: {e}", config.listen.http);
                return ExitCode::FAILURE;
            }
        };
        eprintln!("hematite: http listener on {}", config.listen.http);
        tokio::spawn(hematite_proxy::http::serve_http(
            http,
            state.clone(),
            sink.clone(),
        ));

        // HTTPS MITM listener (L2), served only when TLS is configured.
        if let Some(listen) = &config.listen.https {
            if state.current().cert_cache.is_some() {
                match tokio::net::TcpListener::bind(listen_addr(listen)).await {
                    Ok(l) => {
                        eprintln!("hematite: https (MITM) listener on {listen}");
                        tokio::spawn(hematite_proxy::listen::serve_https(
                            l,
                            state.clone(),
                            sink.clone(),
                        ));
                    }
                    Err(e) => eprintln!("hematite: bind https {listen}: {e}"),
                }
            }
        }

        // Tunnel listener (L2): CONNECT / SOCKS5.
        if let Some(listen) = &config.listen.tunnel {
            match tokio::net::TcpListener::bind(listen_addr(listen)).await {
                Ok(l) => {
                    eprintln!("hematite: tunnel listener on {listen}");
                    tokio::spawn(hematite_proxy::listen::serve_tunnel(
                        l,
                        state.clone(),
                        sink.clone(),
                    ));
                }
                Err(e) => eprintln!("hematite: bind tunnel {listen}: {e}"),
            }
        }

        // DNS server (L2) — wire in the metrics callback.
        if let Some(dns) = &config.dns {
            let m = metrics.clone();
            let on_decision: Option<Arc<dyn Fn(DnsDecisionKind) + Send + Sync>> =
                Some(Arc::new(move |k: DnsDecisionKind| {
                    let outcome = match k {
                        DnsDecisionKind::Static => DnsOutcome::Static,
                        DnsDecisionKind::Intercept => DnsOutcome::Intercept,
                        DnsDecisionKind::Passthrough => DnsOutcome::Passthrough,
                        DnsDecisionKind::Error => DnsOutcome::Error,
                    };
                    m.inc_dns(outcome);
                }));
            if let Err(e) = spawn_dns(dns, on_decision).await {
                eprintln!("hematite: dns: {e}");
            }
        }

        if let (Some(listen), Some(api_key)) =
            (&config.listen.management, &config.management_api_key)
        {
            let mgmt = match tokio::net::TcpListener::bind(listen_addr(listen)).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("hematite: bind management {listen}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            eprintln!("hematite: management API on {listen}");
            tokio::spawn(hematite_proxy::management::serve_management(
                mgmt,
                state.clone(),
                api_key.clone(),
                config_path.clone(),
                config.listen.clone(),
                metrics.clone(),
                config.observability.metrics.enabled,
            ));
        }

        let _ = tokio::signal::ctrl_c().await;
        eprintln!("hematite: shutting down");
        ExitCode::SUCCESS
    })
}
