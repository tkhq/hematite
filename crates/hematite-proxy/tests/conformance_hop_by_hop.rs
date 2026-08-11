//! Appendix C §3 (spec/vectors/hop-by-hop.json) — L1.

use std::path::PathBuf;

use hematite_proxy::hop::strip_hop_by_hop;

#[test]
fn hop_by_hop_vectors() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/hop-by-hop.json");
    let data = std::fs::read_to_string(&path).expect("vector file readable");
    let vectors: serde_json::Value = serde_json::from_str(&data).expect("vector file is JSON");

    for (i, case) in vectors["cases"].as_array().unwrap().iter().enumerate() {
        let mut headers: Vec<(String, String)> =
            serde_json::from_value(case["input"].clone()).unwrap();
        let expected: Vec<(String, String)> =
            serde_json::from_value(case["forwarded"].clone()).unwrap();
        let websocket = case["valid_websocket_handshake"].as_bool().unwrap_or(false);

        strip_hop_by_hop(&mut headers, websocket);
        assert_eq!(headers, expected, "case {i}: {}", case["input"]);
    }
}
