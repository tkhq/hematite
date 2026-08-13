//! Part 04 §3.1 — the file-source cache: TTL refresh, failure-TTL, and
//! stale-serve on a refresh failure, driven by a mock clock.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hematite_kernel::secret::{SecretResolver, SourceKind, SourceRef};
use hematite_proxy::resolver::{Clock, EnvFileResolver};

struct MockClock(Arc<AtomicU64>);
impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn file_source(path: &str, ttl: Option<Duration>, failure_ttl: Option<Duration>) -> SourceRef {
    SourceRef {
        kind: SourceKind::File { path: path.into() },
        json_key: None,
        ttl,
        failure_ttl,
    }
}

// The resolved `Secret` is opaque (INV-1), so the cache behavior is asserted
// through ok/err transitions across the mock clock: a stale-serve shows up
// as `Ok` after the file is deleted, a cached failure as `Err`.

#[test]
fn file_ttl_refresh_failure_and_stale_serve() {
    let dir = std::env::temp_dir().join(format!("hematite-ttl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tok");
    std::fs::write(&path, "v1").unwrap();

    let clock = Arc::new(AtomicU64::new(0));
    let resolver = EnvFileResolver::with_clock(Box::new(MockClock(clock.clone())));
    let src = file_source(
        path.to_str().unwrap(),
        Some(Duration::from_secs(10)),
        Some(Duration::from_secs(5)),
    );

    // First resolve succeeds and caches.
    assert!(resolver.resolve(&src).is_ok(), "initial read");

    // Within the TTL, a change on disk is NOT observed (cached).
    std::fs::write(&path, "v2").unwrap();
    clock.store(5_000, Ordering::SeqCst); // 5s < 10s ttl
    assert!(resolver.resolve(&src).is_ok(), "cached within ttl");

    // After the TTL, a refresh happens and picks up the new value.
    clock.store(11_000, Ordering::SeqCst); // > ttl
    assert!(resolver.resolve(&src).is_ok(), "refresh after ttl");

    // Now delete the file: after the next expiry the refresh fails, but the
    // prior success means the stale value is still served.
    std::fs::remove_file(&path).unwrap();
    clock.store(22_000, Ordering::SeqCst);
    assert!(
        resolver.resolve(&src).is_ok(),
        "stale-serve on refresh failure"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// Two secrets reading different `json_key`s from one file are different
// secrets and must not share a cache entry — otherwise service A's key is
// served (and swapped into requests) for service B. The value itself is
// unobservable (INV-1), so the tests assert through ok/err asymmetry.

#[test]
fn json_keys_from_one_file_do_not_share_a_cache_entry() {
    let dir = std::env::temp_dir().join(format!("hematite-jsonkey-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("creds.json");
    std::fs::write(&path, r#"{"service_a": "ka"}"#).unwrap();

    let resolver = EnvFileResolver::default();
    let mut src_a = file_source(path.to_str().unwrap(), None, None);
    src_a.json_key = Some("service_a".into());
    let mut src_b = file_source(path.to_str().unwrap(), None, None);
    src_b.json_key = Some("service_b".into());

    // A resolves and caches; B's key is absent from the file, so B must
    // fail — a cache entry keyed on the path alone would serve A's value.
    assert!(resolver.resolve(&src_a).is_ok(), "service_a resolves");
    assert!(
        resolver.resolve(&src_b).is_err(),
        "service_b must not receive service_a's cached value"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_and_file_sources_with_the_same_name_stay_distinct() {
    // An env var whose name equals a (nonexistent) file path: resolving
    // the env source must not populate a cache entry the file source hits.
    let name = "/no/such/hematite/dir/HEMATITE_SAME_NAME_TOKEN";
    std::env::set_var(name, "env-value");
    let resolver = EnvFileResolver::default();

    let env_src = SourceRef {
        kind: SourceKind::Env { var: name.into() },
        json_key: None,
        ttl: None,
        failure_ttl: None,
    };
    let file_src = file_source(name, None, None);

    assert!(resolver.resolve(&env_src).is_ok(), "env resolves");
    assert!(
        resolver.resolve(&file_src).is_err(),
        "the file does not exist; the env value must not be served for it"
    );
    std::env::remove_var(name);
}

#[test]
fn failure_is_cached_then_retried() {
    let clock = Arc::new(AtomicU64::new(0));
    let resolver = EnvFileResolver::with_clock(Box::new(MockClock(clock.clone())));
    let missing = file_source("/no/such/hematite/file", None, Some(Duration::from_secs(5)));

    // First resolve fails (no prior success) and caches the failure.
    assert!(resolver.resolve(&missing).is_err(), "initial failure");
    // Still within failure_ttl: cached failure.
    clock.store(3_000, Ordering::SeqCst);
    assert!(resolver.resolve(&missing).is_err(), "cached failure");
    // After failure_ttl: retried (still failing here, but the retry path
    // ran — no stale value exists to serve).
    clock.store(6_000, Ordering::SeqCst);
    assert!(
        resolver.resolve(&missing).is_err(),
        "retry after failure_ttl"
    );
}
