//! Part 05 §3 — leaf minting and the single-flight cert cache.

use std::sync::Arc;

use hematite_proxy::tls::{install_crypto_provider, CertCache, SigningCa};

/// A throwaway CA (cert PEM, key PEM) for tests.
fn test_ca() -> (String, String) {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "hematite test CA");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

#[test]
fn mint_leaf_for_hostname_and_ip() {
    install_crypto_provider();
    let (cert_pem, key_pem) = test_ca();
    let ca = SigningCa::from_pem(&cert_pem, &key_pem, 72).unwrap();

    let host_leaf = ca.mint("api.example.com").unwrap();
    assert_eq!(host_leaf.chain.len(), 2, "chain is [leaf, CA]");
    host_leaf
        .server_config()
        .expect("hostname leaf builds a ServerConfig");

    let ip_leaf = ca.mint("10.0.0.5").unwrap();
    assert_eq!(ip_leaf.chain.len(), 2);
    ip_leaf
        .server_config()
        .expect("IP-literal leaf builds a ServerConfig");
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_returns_same_config_and_single_flights() {
    install_crypto_provider();
    let (cert_pem, key_pem) = test_ca();
    let ca = Arc::new(SigningCa::from_pem(&cert_pem, &key_pem, 72).unwrap());
    let cache = Arc::new(CertCache::new(ca, 100));

    // Concurrent misses for one hostname must resolve to one shared config.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            cache.get("api.example.com").await.unwrap()
        }));
    }
    let configs: Vec<_> = futures_join(handles).await;
    let first = &configs[0];
    for c in &configs[1..] {
        assert!(
            Arc::ptr_eq(first, c),
            "single-flight: one Arc for concurrent misses"
        );
    }

    // A different hostname gets a different config.
    let other = cache.get("other.example.com").await.unwrap();
    assert!(!Arc::ptr_eq(first, &other));

    // A repeat hit returns the cached Arc.
    let repeat = cache.get("api.example.com").await.unwrap();
    assert!(
        Arc::ptr_eq(first, &repeat),
        "cache hit returns the same Arc"
    );
}

/// Minimal join without pulling in the `futures` crate.
async fn futures_join<T>(handles: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}
