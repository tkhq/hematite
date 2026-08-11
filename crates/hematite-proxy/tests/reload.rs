//! Part 09 §4 — reload: atomic swap, fail-closed 422, listener addresses
//! not reloadable. Exercises the decision function directly.

use std::io::Write;

use hematite_kernel::summary::{Body, Headers, Mode, RequestSummary};
use hematite_proxy::config::{build_runtime, load_str};
use hematite_proxy::management::reload;
use hematite_proxy::state::SharedState;

const V1: &str = r#"
transforms:
  - name: allowlist
    config:
      domains: ["one.example"]
"#;

const V2: &str = r#"
transforms:
  - name: allowlist
    config:
      domains: ["two.example"]
"#;

const BROKEN: &str = r#"
transforms:
  - name: allowlist
    config:
      domains: []
      cidrs: []
"#;

fn no_env(_: &str) -> Option<String> {
    None
}

fn summary(host: &str) -> RequestSummary {
    RequestSummary {
        mode: Mode::Http,
        method: "GET".into(),
        host: host.into(),
        port: 80,
        path: "/".into(),
        query: String::new(),
        headers: Headers::new(vec![]),
        body: Body::new(vec![], false),
        sni: None,
        remote_addr: None,
    }
}

fn allows(state: &SharedState, host: &str) -> bool {
    let mut req = summary(host);
    matches!(
        state.current().pipeline.evaluate_request(&mut req).outcome,
        hematite_kernel::pipeline::Outcome::Continue(_)
    )
}

fn write_config(path: &std::path::Path, yaml: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(yaml.as_bytes()).unwrap();
}

#[test]
fn reload_swaps_rejects_and_survives() {
    let dir = std::env::temp_dir().join(format!("hematite-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.yaml");

    write_config(&path, V1);
    let config = load_str(V1, &no_env).unwrap();
    let state = SharedState::new(build_runtime(&config).unwrap());
    assert!(allows(&state, "one.example"));
    assert!(!allows(&state, "two.example"));

    // Valid new config → 200, swapped.
    write_config(&path, V2);
    let (status, _) = reload(&path, &config.listen, &state, &no_env);
    assert_eq!(status, 200);
    assert!(allows(&state, "two.example"));
    assert!(!allows(&state, "one.example"));

    // Invalid new config → 422; the old (v2) config keeps serving.
    write_config(&path, BROKEN);
    let (status, message) = reload(&path, &config.listen, &state, &no_env);
    assert_eq!(status, 422, "{message}");
    assert!(
        allows(&state, "two.example"),
        "fail-closed: surviving config untouched"
    );

    // Changed listener address → 422.
    write_config(&path, &format!("{V2}\nproxy:\n  http_listen: \":8081\"\n"));
    let (status, message) = reload(&path, &config.listen, &state, &no_env);
    assert_eq!(status, 422, "{message}");
    assert!(message.contains("not reloadable"));

    // Unreadable file → 500.
    let (status, _) = reload(&dir.join("missing.yaml"), &config.listen, &state, &no_env);
    assert_eq!(status, 500);

    std::fs::remove_dir_all(&dir).ok();
}
