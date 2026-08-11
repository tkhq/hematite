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
