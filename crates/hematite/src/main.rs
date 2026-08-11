//! hematite — one YAML file, one flag (Part 09 §1). L1: serves the
//! plain-HTTP listener and the management API; L2 listeners configured in
//! the file are warned about and skipped.

#![forbid(unsafe_code)]

mod telemetry;

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
    tracing::info!(listen = %dns.listen, "dns server listening");
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
            // logging config comes from the config file; errors before it
            // loads go to bare stderr
            eprintln!("usage: hematite -config <path.yaml>");
            return ExitCode::from(2);
        }
    };

    let yaml = match std::fs::read_to_string(&config_path) {
        Ok(y) => y,
        Err(e) => {
            // logging config comes from the config file; errors before it
            // loads go to bare stderr
            eprintln!("hematite: cannot read {}: {e}", config_path.display());
            return ExitCode::FAILURE;
        }
    };
    let config = match load_str(&yaml, &os_env) {
        Ok(c) => c,
        Err(e) => {
            // logging config comes from the config file; errors before it
            // loads go to bare stderr
            eprintln!("hematite: {e}");
            return ExitCode::FAILURE;
        }
    };

    for warning in &config.warnings {
        // warnings emitted pre-tracing; use bare stderr like other pre-init messages
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

    // Install the global tracing subscriber AFTER the tokio runtime is created
    // and inside an rt.enter() guard.  BatchSpanProcessor::build() (when OTLP
    // is enabled) calls tokio::spawn internally, which panics if invoked
    // outside a tokio context.  We drop the enter guard before block_on so
    // that block_on's own context takes over cleanly.
    let guard = {
        let _enter = rt.enter();
        match telemetry::init_telemetry(
            &config.observability.log.format,
            &config.log_level,
            &config.observability.otlp,
        ) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("hematite: telemetry init failed: {e}");
                return ExitCode::FAILURE;
            }
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
                tracing::error!(listener = %config.listen.http, error = %e, "bind http failed");
                return ExitCode::FAILURE;
            }
        };
        tracing::info!(listener = %config.listen.http, "http listener bound");
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
                        tracing::info!(listener = %listen, "https (MITM) listener bound");
                        tokio::spawn(hematite_proxy::listen::serve_https(
                            l,
                            state.clone(),
                            sink.clone(),
                        ));
                    }
                    Err(e) => tracing::error!(listener = %listen, error = %e, "bind https failed"),
                }
            }
        }

        // Tunnel listener (L2): CONNECT / SOCKS5.
        if let Some(listen) = &config.listen.tunnel {
            match tokio::net::TcpListener::bind(listen_addr(listen)).await {
                Ok(l) => {
                    tracing::info!(listener = %listen, "tunnel listener bound");
                    tokio::spawn(hematite_proxy::listen::serve_tunnel(
                        l,
                        state.clone(),
                        sink.clone(),
                    ));
                }
                Err(e) => tracing::error!(listener = %listen, error = %e, "bind tunnel failed"),
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
                tracing::error!(error = %e, "dns server failed to start");
            }
        }

        if let (Some(listen), Some(api_key)) =
            (&config.listen.management, &config.management_api_key)
        {
            let mgmt = match tokio::net::TcpListener::bind(listen_addr(listen)).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(listener = %listen, error = %e, "bind management failed");
                    return ExitCode::FAILURE;
                }
            };
            tracing::info!(listener = %listen, "management API bound");
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
        tracing::info!("shutting down");
        guard.shutdown().await;
        ExitCode::SUCCESS
    })
}
