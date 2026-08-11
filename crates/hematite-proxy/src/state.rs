//! The atomically-swappable runtime state (Part 03 §1, Part 09 §4) and the
//! guard (Part 07 §2).

use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hematite_kernel::audit::GuardDenial;
use hematite_kernel::matcher::Cidr;
use hematite_kernel::pipeline::Pipeline;
use rustls::ClientConfig;

use crate::tls::CertCache;

/// Part 07 §2 — the post-resolution deny-CIDR check at the dialer.
pub struct Guard {
    /// (compiled prefix, its config string for the audit `guard` group).
    deny: Vec<(Cidr, String)>,
}

impl Guard {
    /// The default deny set, applied when `upstream_deny_cidrs` is absent:
    /// cloud metadata + loopback. RFC 1918 is deliberately not defaulted.
    pub const DEFAULT_DENY: &'static [&'static str] = &[
        "169.254.169.254/32",
        "fd00:ec2::254/128",
        "fd20:ce::254/128",
        "127.0.0.0/8",
        "::1/128",
    ];

    pub fn new(prefixes: &[String]) -> Result<Self, String> {
        let deny = prefixes
            .iter()
            .map(|p| Cidr::parse(p).map(|c| (c, p.clone())).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Guard { deny })
    }

    pub fn default_set() -> Self {
        Guard::new(&Self::DEFAULT_DENY.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("default deny set compiles")
    }

    /// An explicitly empty list disables the guard (Part 07 §2); that is
    /// simply a `Guard` with no prefixes.
    pub fn check(&self, ip: IpAddr) -> Result<(), GuardDenial> {
        for (cidr, prefix) in &self.deny {
            if cidr.contains(ip) {
                return Err(GuardDenial { denied_addr: ip.to_string(), prefix: prefix.clone() });
            }
        }
        Ok(())
    }
}

/// Everything a request handler needs, built once per config load. Reload
/// builds a complete new `Runtime` and swaps it; in-flight requests keep
/// their `Arc` to the old one (Part 03 §1, threat T9).
pub struct Runtime {
    pub pipeline: Pipeline,
    pub guard: Guard,
    pub max_request_body_bytes: usize,
    pub upstream_response_header_timeout: Duration,
    pub dial_timeout: Duration,
    /// Client config for dialing https upstreams, verified against the
    /// configured roots (Part 07 §4).
    pub upstream_tls: Arc<ClientConfig>,
    /// Per-hostname leaf cache for the MITM listeners (L2); `None` at L1.
    pub cert_cache: Option<Arc<CertCache>>,
}

/// Build an upstream TLS client config trusting the OS root store
/// (Part 07 §4: verified against the system roots).
pub fn native_upstream_config() -> Result<Arc<ClientConfig>, String> {
    // Building a rustls config needs a process crypto provider; ensure one
    // (idempotent) so direct callers don't have to.
    crate::tls::install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    if result.certs.is_empty() {
        return Err(format!("no system root certificates: {:?}", result.errors));
    }
    for cert in result.certs {
        let _ = roots.add(cert);
    }
    let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(config))
}

/// The swap point. Handlers `current()` exactly once per request so a
/// single pipeline instance processes it start-to-finish.
#[derive(Clone)]
pub struct SharedState(Arc<RwLock<Arc<Runtime>>>);

impl SharedState {
    pub fn new(runtime: Runtime) -> Self {
        SharedState(Arc::new(RwLock::new(Arc::new(runtime))))
    }

    pub fn current(&self) -> Arc<Runtime> {
        self.0.read().expect("state lock").clone()
    }

    pub fn swap(&self, runtime: Runtime) {
        *self.0.write().expect("state lock") = Arc::new(runtime);
    }
}
