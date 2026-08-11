//! Part 07 §3 — header hygiene: hop-by-hop stripping (RFC 7230 §6.1).
//! Vectors: Appendix C §3 (`spec/vectors/hop-by-hop.json`).

/// The fixed hop-by-hop set (lowercase).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Strip hop-by-hop headers in place.
///
/// - Removes the RFC 7230 §6.1 set plus every header named in any
///   `Connection` value (comma-separated tokens).
/// - Exception: `TE: trailers` is preserved (a `TE` value listing several
///   codings is rewritten to `trailers` only).
/// - Exception: when `valid_websocket_handshake` is true, `Upgrade` and
///   `Connection` survive (Part 05 §5).
pub fn strip_hop_by_hop(headers: &mut Vec<(String, String)>, valid_websocket_handshake: bool) {
    // Tokens named in any Connection value are headers to remove too.
    let mut connection_named: Vec<String> = Vec::new();
    for (name, value) in headers.iter() {
        if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',') {
                let token = token.trim();
                if !token.is_empty() {
                    connection_named.push(token.to_ascii_lowercase());
                }
            }
        }
    }

    let mut kept: Vec<(String, String)> = Vec::new();
    for (name, value) in headers.drain(..) {
        let lower = name.to_ascii_lowercase();

        if lower == "te" {
            // Preserve only the `trailers` coding (gRPC over HTTP/1.1).
            let has_trailers = value
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("trailers"));
            if has_trailers {
                kept.push((name, "trailers".to_string()));
            }
            continue;
        }

        if valid_websocket_handshake && (lower == "upgrade" || lower == "connection") {
            kept.push((name, value));
            continue;
        }

        if HOP_BY_HOP.contains(&lower.as_str()) || connection_named.contains(&lower) {
            continue;
        }
        kept.push((name, value));
    }
    *headers = kept;
}
