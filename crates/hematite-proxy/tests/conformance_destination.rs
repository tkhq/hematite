//! Canonical destination vectors shared by HTTP, CONNECT, and SOCKS paths.

use hematite_proxy::destination::{CanonicalDestination, Scheme};

#[test]
fn canonical_destination_vectors_and_reject_mutations() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/canonical-destinations.json");
    let vectors: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let scheme = match case["scheme"].as_str().unwrap() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            "connect" => Scheme::Connect,
            _ => unreachable!(),
        };
        let destination =
            CanonicalDestination::parse_authority(case["authority"].as_str().unwrap(), scheme)
                .unwrap();
        assert_eq!(destination.host(), case["host"].as_str().unwrap());
        assert_eq!(destination.port(), case["port"].as_u64().unwrap() as u16);
        assert_eq!(
            destination,
            CanonicalDestination::from_host_port(destination.host(), destination.port(), scheme)
                .unwrap(),
            "all listener entry points converge"
        );
    }
    for authority in vectors["reject"].as_array().unwrap() {
        assert!(CanonicalDestination::parse_authority(
            authority.as_str().unwrap(),
            Scheme::Connect
        )
        .is_err());
    }
}
