//! hematite — one YAML file, one flag (Part 09 §1). L1: serves the
//! plain-HTTP listener and the management API; L2 listeners configured in
//! the file are warned about and skipped.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use hematite_proxy::audit::StderrSink;
use hematite_proxy::config::{build_runtime, load_str, os_env};
use hematite_proxy::state::SharedState;

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
        let state = SharedState::new(runtime);
        let sink = Arc::new(StderrSink);

        let http = match tokio::net::TcpListener::bind(listen_addr(&config.listen.http)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hematite: bind {}: {e}", config.listen.http);
                return ExitCode::FAILURE;
            }
        };
        eprintln!("hematite: http listener on {}", config.listen.http);
        tokio::spawn(hematite_proxy::http::serve_http(http, state.clone(), sink));

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
            ));
        }

        let _ = tokio::signal::ctrl_c().await;
        eprintln!("hematite: shutting down");
        ExitCode::SUCCESS
    })
}
