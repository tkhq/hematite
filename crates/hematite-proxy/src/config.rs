//! Part 09 — configuration: shape, load order (parse → env overrides →
//! defaults → validate), and validation. Reject-at-boot, never at request
//! time.
//!
//! L1 note: the `dns` and `tls` sections and the `https_listen` /
//! `tunnel_listen` keys are parsed and schema-checked, but their listeners
//! are L2 and are not served here; configuring them yields a warning, not
//! an error, so one config file can serve both levels.

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

use hematite_kernel::config::{build_pipeline, ConfigError, TransformSpec};

use crate::state::{Guard, Runtime};

/// Raw YAML shape. Unknown keys fail parsing at every level (threat T9:
/// typos must not silently no-op).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    #[serde(default)]
    pub dns: Option<DnsSection>,
    #[serde(default)]
    pub proxy: ProxySection,
    #[serde(default)]
    pub tls: Option<TlsSection>,
    #[serde(default)]
    pub transforms: Vec<TransformSpecYaml>,
    #[serde(default)]
    pub management: Option<ManagementSection>,
    #[serde(default)]
    pub log: Option<LogSection>,
}

/// `transforms:` entries arrive as YAML; the kernel builder takes JSON
/// values, so `config` converts on the boundary.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformSpecYaml {
    pub name: String,
    #[serde(default)]
    pub config: serde_yaml::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub proxy_ip: Option<String>,
    #[serde(default)]
    pub upstream_resolver: Option<String>,
    #[serde(default)]
    pub passthrough: Vec<String>,
    #[serde(default)]
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySection {
    #[serde(default)]
    pub http_listen: Option<String>,
    #[serde(default)]
    pub https_listen: Option<String>,
    #[serde(default)]
    pub tunnel_listen: Option<String>,
    #[serde(default)]
    pub max_request_body_bytes: Option<usize>,
    #[serde(default)]
    pub max_response_body_bytes: Option<usize>,
    #[serde(default)]
    pub upstream_response_header_timeout: Option<String>,
    #[serde(default)]
    pub upstream_deny_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub http_proxy: Option<String>,
    #[serde(default)]
    pub https_proxy: Option<String>,
    #[serde(default)]
    pub no_proxy: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub ca_cert: String,
    pub ca_key: String,
    #[serde(default)]
    pub cert_cache_size: Option<usize>,
    #[serde(default)]
    pub leaf_cert_expiry_hours: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementSection {
    pub listen: String,
    #[serde(default)]
    pub api_key_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    #[serde(default)]
    pub level: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug)]
pub struct LoadError(pub String);

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ConfigError> for LoadError {
    fn from(e: ConfigError) -> Self {
        LoadError(e.to_string())
    }
}

/// The listener addresses, kept for the reload comparison: a changed
/// `listen` key is a 422 (Part 09 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenKeys {
    pub http: String,
    pub https: Option<String>,
    pub tunnel: Option<String>,
    pub dns: Option<String>,
    pub management: Option<String>,
}

/// The resolved configuration after defaults.
pub struct Config {
    pub listen: ListenKeys,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    pub upstream_response_header_timeout: Duration,
    /// `None` = key absent = the default deny set; `Some([])` = guard
    /// explicitly disabled (Part 07 §2: absent and empty differ).
    pub upstream_deny_cidrs: Option<Vec<String>>,
    pub management_api_key: Option<String>,
    pub log_level: String,
    pub transforms: Vec<TransformSpec>,
    pub warnings: Vec<String>,
}

/// Env-overridable scalar keys (Part 09 §2 step 2). The env name is the
/// path uppercased and `_`-joined with the `HEMATITE_` prefix.
const ENV_KEYS: &[&str] = &[
    "dns.enabled",
    "dns.listen",
    "dns.proxy_ip",
    "dns.upstream_resolver",
    "proxy.http_listen",
    "proxy.https_listen",
    "proxy.tunnel_listen",
    "proxy.max_request_body_bytes",
    "proxy.max_response_body_bytes",
    "proxy.upstream_response_header_timeout",
    "proxy.http_proxy",
    "proxy.https_proxy",
    "proxy.no_proxy",
    "tls.ca_cert",
    "tls.ca_key",
    "tls.cert_cache_size",
    "tls.leaf_cert_expiry_hours",
    "management.listen",
    "management.api_key_env",
    "log.level",
];

fn env_name(path: &str) -> String {
    format!("HEMATITE_{}", path.to_ascii_uppercase().replace('.', "_"))
}

fn apply_env_overrides(
    value: &mut serde_yaml::Value,
    env: &dyn Fn(&str) -> Option<String>,
) {
    for path in ENV_KEYS {
        let Some(raw) = env(&env_name(path)) else { continue };
        let mut segments = path.split('.');
        let (section, key) = (segments.next().unwrap(), segments.next().unwrap());

        let root = match value {
            serde_yaml::Value::Mapping(m) => m,
            _ => return,
        };
        let section_value = root
            .entry(serde_yaml::Value::String(section.to_string()))
            .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
        if let serde_yaml::Value::Mapping(section_map) = section_value {
            // Scalars keep their YAML types: try bool, then integer,
            // then string.
            let typed = if let Ok(b) = raw.parse::<bool>() {
                serde_yaml::Value::Bool(b)
            } else if let Ok(n) = raw.parse::<u64>() {
                serde_yaml::Value::Number(n.into())
            } else {
                serde_yaml::Value::String(raw)
            };
            section_map.insert(serde_yaml::Value::String(key.to_string()), typed);
        }
    }
}

/// Parse a duration key: bare seconds, or `<n>ms`/`<n>s`/`<n>m`.
fn parse_duration(s: &str) -> Result<Duration, LoadError> {
    let s = s.trim();
    let (digits, unit): (&str, &str) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => s.split_at(i),
        None => (s, "s"),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| LoadError(format!("invalid duration: {s:?}")))?;
    match unit {
        "ms" => Ok(Duration::from_millis(n)),
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_secs(n * 60)),
        _ => Err(LoadError(format!("invalid duration unit: {s:?}"))),
    }
}

fn yaml_to_json(v: &serde_yaml::Value) -> Result<serde_json::Value, LoadError> {
    serde_json::to_value(v).map_err(|e| LoadError(format!("transform config: {e}")))
}

/// Part 09 §2 — the full load order, with the environment injectable for
/// tests. Returns the resolved config; `build_runtime` compiles it.
pub fn load_str(
    yaml: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Config, LoadError> {
    // 1. Parse.
    let mut value: serde_yaml::Value = serde_yaml::from_str(yaml)
        .map_err(|e| LoadError(format!("YAML parse error: {e}")))?;
    if value.is_null() {
        value = serde_yaml::Value::Mapping(Default::default());
    }
    // 2. Env overrides.
    apply_env_overrides(&mut value, env);
    let raw: RawConfig = serde_yaml::from_value(value)
        .map_err(|e| LoadError(format!("config error: {e}")))?;

    // 3. Defaults.
    let mut warnings = Vec::new();
    let listen = ListenKeys {
        http: raw.proxy.http_listen.clone().unwrap_or_else(|| ":80".into()),
        https: raw.proxy.https_listen.clone(),
        tunnel: raw.proxy.tunnel_listen.clone(),
        dns: raw.dns.as_ref().filter(|d| d.enabled).map(|d| {
            d.listen.clone().unwrap_or_else(|| ":53".into())
        }),
        management: raw.management.as_ref().map(|m| m.listen.clone()),
    };
    let max_request_body_bytes = raw.proxy.max_request_body_bytes.unwrap_or(1 << 20);
    let max_response_body_bytes = raw.proxy.max_response_body_bytes.unwrap_or(0);
    let upstream_response_header_timeout = raw
        .proxy
        .upstream_response_header_timeout
        .as_deref()
        .map(parse_duration)
        .transpose()?
        .unwrap_or(Duration::from_secs(30));
    let log_level = raw
        .log
        .as_ref()
        .and_then(|l| l.level.clone())
        .unwrap_or_else(|| "info".into());

    // 4. Validate.
    // L2 features are schema-checked but not served at this level.
    if listen.https.is_some() {
        warnings.push("https_listen is configured but TLS MITM is L2; not served".into());
    }
    if listen.tunnel.is_some() {
        warnings.push("tunnel_listen is configured but the tunnel listener is L2; not served".into());
    }
    if let Some(dns) = &raw.dns {
        if dns.enabled {
            warnings.push("dns is enabled but the DNS server is L2; not served".into());
            if dns.proxy_ip.is_none() {
                return Err(LoadError("dns.proxy_ip is required when DNS is enabled".into()));
            }
            if let Some(ip) = &dns.proxy_ip {
                if ip.parse::<std::net::Ipv4Addr>().is_err() {
                    return Err(LoadError(format!("dns.proxy_ip must be IPv4: {ip:?}")));
                }
            }
            for r in &dns.records {
                if r.record_type != "A" && r.record_type != "CNAME" {
                    return Err(LoadError(format!(
                        "dns record type {:?} is not A or CNAME (Part 06 §2)",
                        r.record_type
                    )));
                }
            }
        }
    }
    if (listen.https.is_some() || listen.tunnel.is_some()) && raw.tls.is_none() {
        return Err(LoadError(
            "tls.ca_cert and tls.ca_key are required when the HTTPS or tunnel listener is enabled"
                .into(),
        ));
    }
    if let Some(cidrs) = &raw.proxy.upstream_deny_cidrs {
        // Prefix lengths are required; kernel Cidr::parse enforces it.
        Guard::new(cidrs).map_err(LoadError)?;
    }

    // Management: listen set ⇒ api_key_env names a non-empty env var.
    let management_api_key = match &raw.management {
        None => None,
        Some(m) => {
            let var = m
                .api_key_env
                .clone()
                .unwrap_or_else(|| "HEMATITE_MANAGEMENT_API_KEY".into());
            match env(&var) {
                Some(key) if !key.is_empty() => Some(key),
                _ => {
                    return Err(LoadError(format!(
                        "management.listen is set but env var {var:?} is empty or unset"
                    )))
                }
            }
        }
    };

    // Transforms: kernel-side validation (registry, allowlist presence,
    // matcher compilation, ordering lints).
    let transforms = raw
        .transforms
        .iter()
        .map(|t| {
            Ok(TransformSpec { name: t.name.clone(), config: yaml_to_json(&t.config)? })
        })
        .collect::<Result<Vec<_>, LoadError>>()?;
    let built = build_pipeline(&transforms)?;
    warnings.extend(built.warnings);

    Ok(Config {
        listen,
        max_request_body_bytes,
        max_response_body_bytes,
        upstream_response_header_timeout,
        upstream_deny_cidrs: raw.proxy.upstream_deny_cidrs,
        management_api_key,
        log_level,
        transforms,
        warnings,
    })
}

/// Compile a loaded config into a runnable `Runtime`.
pub fn build_runtime(config: &Config) -> Result<Runtime, LoadError> {
    let pipeline = build_pipeline(&config.transforms)?.pipeline;
    let guard = match &config.upstream_deny_cidrs {
        None => Guard::default_set(),
        Some(cidrs) => Guard::new(cidrs).map_err(LoadError)?,
    };
    Ok(Runtime {
        pipeline,
        guard,
        max_request_body_bytes: config.max_request_body_bytes,
        upstream_response_header_timeout: config.upstream_response_header_timeout,
        dial_timeout: Duration::from_secs(30),
    })
}

/// The OS environment, as `load_str`'s `env` argument.
pub fn os_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}
