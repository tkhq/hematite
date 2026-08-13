//! Part 09 — load order, defaults, env overrides, validation.

use std::collections::HashMap;
use std::time::Duration;

use hematite_proxy::config::load_str;

const MINIMAL: &str = r#"
transforms:
  - name: allowlist
    config:
      domains: ["api.example.com"]
"#;

fn no_env(_: &str) -> Option<String> {
    None
}

#[test]
fn defaults_applied() {
    let config = load_str(MINIMAL, &no_env).expect("minimal config loads");
    assert_eq!(config.listen.http, ":80");
    assert_eq!(config.max_request_body_bytes, 1 << 20);
    assert_eq!(config.max_response_body_bytes, 0);
    assert_eq!(
        config.upstream_response_header_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(config.log_level, "info");
    assert!(
        config.upstream_deny_cidrs.is_none(),
        "absent = default deny set"
    );
}

#[test]
fn env_override_applies() {
    let env_map: HashMap<String, String> = [(
        "HEMATITE_PROXY_HTTP_LISTEN".to_string(),
        ":8080".to_string(),
    )]
    .into();
    let env = move |name: &str| env_map.get(name).cloned();
    let config = load_str(MINIMAL, &env).expect("config loads");
    assert_eq!(config.listen.http, ":8080");
}

#[test]
fn unknown_top_level_key_rejected() {
    let yaml = format!("{MINIMAL}\nproxyy: {{}}\n");
    assert!(
        load_str(&yaml, &no_env).is_err(),
        "typos must not silently no-op (threat T9)"
    );
}

#[test]
fn unknown_proxy_key_rejected() {
    let yaml = format!("{MINIMAL}\nproxy:\n  http_lissten: \":80\"\n");
    assert!(load_str(&yaml, &no_env).is_err());
}

#[test]
fn missing_allowlist_rejected() {
    let yaml = r#"
transforms:
  - name: header_allowlist
    config:
      headers: ["Accept"]
"#;
    assert!(
        load_str(yaml, &no_env).is_err(),
        "default-deny is structural (Part 04 §1)"
    );
}

#[test]
fn explicit_empty_deny_cidrs_differs_from_absent() {
    let yaml = format!("{MINIMAL}\nproxy:\n  upstream_deny_cidrs: []\n");
    let config = load_str(&yaml, &no_env).expect("config loads");
    assert_eq!(
        config.upstream_deny_cidrs,
        Some(vec![]),
        "explicit [] disables the guard"
    );
}

#[test]
fn bare_ip_deny_cidr_rejected() {
    let yaml = format!("{MINIMAL}\nproxy:\n  upstream_deny_cidrs: [\"10.0.0.1\"]\n");
    assert!(
        load_str(&yaml, &no_env).is_err(),
        "prefix lengths are required (Part 02 §3)"
    );
}

#[test]
fn management_requires_api_key_env() {
    let yaml = format!("{MINIMAL}\nmanagement:\n  listen: \"127.0.0.1:9092\"\n");
    assert!(
        load_str(&yaml, &no_env).is_err(),
        "listen set => api_key_env non-empty"
    );

    let env_map: HashMap<String, String> =
        [("HEMATITE_MANAGEMENT_API_KEY".to_string(), "tok".to_string())].into();
    let env = move |name: &str| env_map.get(name).cloned();
    let config = load_str(&yaml, &env).expect("config loads with key set");
    assert_eq!(config.management_api_key.as_deref(), Some("tok"));
}

#[test]
fn dns_enabled_requires_proxy_ip() {
    let yaml = format!("{MINIMAL}\ndns:\n  enabled: true\n");
    assert!(load_str(&yaml, &no_env).is_err());

    let yaml = format!("{MINIMAL}\ndns:\n  enabled: true\n  proxy_ip: \"172.20.0.2\"\n");
    let config = load_str(&yaml, &no_env).expect("config loads");
    assert!(config.dns.is_some(), "dns settings resolved");
}

#[test]
fn tls_required_when_https_listener_enabled() {
    let yaml = format!("{MINIMAL}\nproxy:\n  https_listen: \":443\"\n");
    assert!(load_str(&yaml, &no_env).is_err());
}

/// YAML snippet shared by observability tests — has a valid allowlist transform.
const OBS_BASE: &str = "proxy:\n  http_listen: \":80\"\ntransforms:\n  - name: allowlist\n    config:\n      domains: [\"api.example.com\"]\n";

#[test]
fn observability_defaults_when_absent() {
    let c = load_str(OBS_BASE, &|_| None).unwrap();
    assert!(c.observability.metrics.enabled);
    assert_eq!(c.observability.log.format, "json");
    assert!(!c.observability.otlp.enabled);
    assert!((c.observability.otlp.sample_ratio - 1.0).abs() < f64::EPSILON);
    assert_eq!(c.observability.otlp.service_name, "hematite");
}

#[test]
fn otlp_enabled_requires_endpoint() {
    let yaml = format!("{OBS_BASE}observability:\n  otlp:\n    enabled: true\n");
    assert!(load_str(&yaml, &|_| None).is_err());
}

#[test]
fn otlp_sample_ratio_range_validated() {
    let yaml = format!(
        "{OBS_BASE}observability:\n  otlp:\n    enabled: true\n    endpoint: \"http://c:4318\"\n    sample_ratio: 1.5\n"
    );
    assert!(load_str(&yaml, &|_| None).is_err());
}

#[test]
fn log_format_validated() {
    let yaml = format!("{OBS_BASE}observability:\n  log:\n    format: \"xml\"\n");
    assert!(load_str(&yaml, &|_| None).is_err());
}

#[test]
fn three_segment_env_override() {
    let env = |k: &str| {
        (k == "HEMATITE_OBSERVABILITY_OTLP_ENDPOINT").then(|| "http://collector:4318".to_string())
    };
    let yaml = format!("{OBS_BASE}observability:\n  otlp:\n    enabled: true\n");
    let c = load_str(&yaml, &env).unwrap();
    assert_eq!(
        c.observability.otlp.endpoint.as_deref(),
        Some("http://collector:4318")
    );
}

#[test]
fn two_segment_env_override_still_works() {
    let env = |k: &str| (k == "HEMATITE_LOG_LEVEL").then(|| "debug".to_string());
    let c = load_str(OBS_BASE, &env).unwrap();
    assert_eq!(c.log_level, "debug");
}

/// Regression: SAMPLE_RATIO env values "0" and "1" must deserialize as f64, not
/// be mis-typed as u64 integers (which rely on serde_yaml integer→float coercion).
#[test]
fn sample_ratio_env_zero_is_float() {
    let env = |k: &str| match k {
        "HEMATITE_OBSERVABILITY_OTLP_SAMPLE_RATIO" => Some("0".to_string()),
        "HEMATITE_OBSERVABILITY_OTLP_ENDPOINT" => Some("http://c:4318".to_string()),
        "HEMATITE_OBSERVABILITY_OTLP_ENABLED" => Some("true".to_string()),
        _ => None,
    };
    let c = load_str(OBS_BASE, &env).expect("sample_ratio=0 should load");
    assert_eq!(c.observability.otlp.sample_ratio, 0.0_f64);
}

#[test]
fn sample_ratio_env_one_is_float() {
    let env = |k: &str| match k {
        "HEMATITE_OBSERVABILITY_OTLP_SAMPLE_RATIO" => Some("1".to_string()),
        "HEMATITE_OBSERVABILITY_OTLP_ENDPOINT" => Some("http://c:4318".to_string()),
        "HEMATITE_OBSERVABILITY_OTLP_ENABLED" => Some("true".to_string()),
        _ => None,
    };
    let c = load_str(OBS_BASE, &env).expect("sample_ratio=1 should load");
    assert!((c.observability.otlp.sample_ratio - 1.0_f64).abs() < f64::EPSILON);
}

#[test]
fn sample_ratio_env_fractional() {
    let env = |k: &str| match k {
        "HEMATITE_OBSERVABILITY_OTLP_SAMPLE_RATIO" => Some("0.5".to_string()),
        "HEMATITE_OBSERVABILITY_OTLP_ENDPOINT" => Some("http://c:4318".to_string()),
        "HEMATITE_OBSERVABILITY_OTLP_ENABLED" => Some("true".to_string()),
        _ => None,
    };
    let c = load_str(OBS_BASE, &env).expect("sample_ratio=0.5 should load");
    assert!((c.observability.otlp.sample_ratio - 0.5_f64).abs() < f64::EPSILON);
}

#[test]
fn ordering_lint_surfaces_as_warning() {
    let yaml = r#"
transforms:
  - name: header_allowlist
    config:
      headers: ["Accept"]
  - name: allowlist
    config:
      domains: ["api.example.com"]
"#;
    let config = load_str(yaml, &no_env).expect("config loads");
    assert!(config.warnings.iter().any(|w| w.contains("not first")));
}

#[test]
fn passthrough_domains_parse_and_compile() {
    let yaml = r#"
proxy:
  tunnel_passthrough_domains: ["telemetry.example.com", "*.blind.example"]
transforms:
  - name: allowlist
    config: { domains: ["api.example.com", "telemetry.example.com"] }
"#;
    let config = load_str(yaml, &no_env).expect("config loads");
    assert_eq!(config.tunnel_passthrough_domains.len(), 2);
    let runtime = hematite_proxy::config::build_runtime(&config).expect("runtime builds");
    assert!(runtime.passthrough_matches("telemetry.example.com"));
    assert!(runtime.passthrough_matches("deep.blind.example"));
    assert!(!runtime.passthrough_matches("api.example.com"));
}

#[test]
fn passthrough_overlapping_transform_rule_is_a_load_error() {
    // A secrets rule scoped to a passthrough host could never run: the
    // tunnel is spliced, so the transform pipeline never sees the traffic.
    // That must refuse to boot, not warn (Part 05 §4.4).
    let yaml = r#"
proxy:
  tunnel_passthrough_domains: ["api.example.com"]
transforms:
  - name: allowlist
    config: { domains: ["api.example.com"] }
  - name: secrets
    config:
      secrets:
        - source: { type: env, var: KEY }
          proxy_value: "proxy-tok"
          match_headers: ["Authorization"]
          rules:
            - host: "api.example.com"
"#;
    let config = load_str(yaml, &no_env).expect("schema-valid config loads");
    let err = hematite_proxy::config::build_runtime(&config)
        .err()
        .expect("overlap must be a load error");
    assert!(
        err.to_string().contains("passthrough"),
        "error names the conflict: {err}"
    );
}

#[test]
fn passthrough_glob_overlap_is_caught_both_directions() {
    // The transform rule is broader than the passthrough entry: the glob
    // matches the passthrough domain, so the overlap check must fire.
    let yaml = r#"
proxy:
  tunnel_passthrough_domains: ["api.example.com"]
transforms:
  - name: allowlist
    config: { domains: ["*.example.com"] }
  - name: header_allowlist
    config:
      headers: ["Host"]
      rules:
        - host: "*.example.com"
"#;
    let config = load_str(yaml, &no_env).expect("schema-valid config loads");
    assert!(hematite_proxy::config::build_runtime(&config).is_err());
}
