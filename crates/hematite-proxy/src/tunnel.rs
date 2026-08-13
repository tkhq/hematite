//! Part 05 §4 — the tunnel listener's wire handshakes: protocol dispatch on
//! the first byte, `CONNECT` parsing, SOCKS5 negotiation, and inner-protocol
//! sniffing. The parsing/encoding here is pure and unit-tested; `listen.rs`
//! drives the sockets.

/// Part 05 §4 — first-byte protocol dispatch.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientProtocol {
    Socks5,
    /// An ASCII uppercase letter: an HTTP method (CONNECT or absolute-form).
    Http,
    /// Anything else → close.
    Unknown,
}

pub fn dispatch(first_byte: u8) -> ClientProtocol {
    match first_byte {
        0x05 => ClientProtocol::Socks5,
        b'A'..=b'Z' => ClientProtocol::Http,
        _ => ClientProtocol::Unknown,
    }
}

/// The CONNECT target (host, port) for the synthetic summary (Part 05 §4.1).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

/// Parse a `CONNECT host:port HTTP/1.1` request line. Default port 443.
/// `raw` is the full request head (through the blank line).
pub fn parse_connect(raw: &str) -> Option<ConnectTarget> {
    let line = raw.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "CONNECT" {
        return None;
    }
    let authority = parts.next()?;
    // The target is host:port; default 443 when the port is absent.
    let (host, port) = split_authority(authority, 443)?;
    Some(ConnectTarget { host, port })
}

fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let end = rest.find(']')?;
        let host = rest[..end].to_ascii_lowercase();
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_ascii_lowercase(), p.parse().ok()?)),
        _ => Some((authority.to_ascii_lowercase(), default_port)),
    }
}

// ---- SOCKS5 (Part 05 §4.2) --------------------------------------------

/// The reply for a SOCKS5 method-selection message. No-auth only.
#[derive(Debug, PartialEq, Eq)]
pub enum Socks5Method {
    /// Accept: reply `05 00`.
    NoAuth,
    /// No acceptable method: reply `05 FF` and close.
    Unacceptable,
}

/// Parse the SOCKS5 greeting (after the leading `0x05` version byte has been
/// consumed by dispatch): `[nmethods][methods...]`. `rest` is the bytes
/// following the version byte.
pub fn parse_socks5_methods(rest: &[u8]) -> Option<Socks5Method> {
    let nmethods = *rest.first()? as usize;
    let methods = rest.get(1..1 + nmethods)?;
    if methods.contains(&0x00) {
        Some(Socks5Method::NoAuth)
    } else {
        Some(Socks5Method::Unacceptable)
    }
}

/// Reason a SOCKS5 request is refused, with its reply byte (Part 05 §4.2).
#[derive(Debug, PartialEq, Eq)]
pub enum Socks5Reject {
    /// Command not CONNECT → `0x07`.
    CommandNotSupported,
    /// Address type not v4/domain/v6 → `0x08`.
    AddressNotSupported,
    /// Malformed request.
    Malformed,
}

impl Socks5Reject {
    pub fn reply_code(&self) -> u8 {
        match self {
            Socks5Reject::CommandNotSupported => 0x07,
            Socks5Reject::AddressNotSupported => 0x08,
            Socks5Reject::Malformed => 0x01, // general failure
        }
    }
}

/// Parse a SOCKS5 request `[ver=5][cmd][rsv=0][atyp][addr][port]` into a
/// CONNECT target. Only CMD=CONNECT (0x01) and ATYP v4/domain/v6 succeed.
pub fn parse_socks5_request(req: &[u8]) -> Result<ConnectTarget, Socks5Reject> {
    if req.len() < 4 || req[0] != 0x05 {
        return Err(Socks5Reject::Malformed);
    }
    if req[1] != 0x01 {
        return Err(Socks5Reject::CommandNotSupported);
    }
    let atyp = req[3];
    let (host, port_offset) = match atyp {
        0x01 => {
            // IPv4.
            let addr = req.get(4..8).ok_or(Socks5Reject::Malformed)?;
            (
                format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
                8,
            )
        }
        0x03 => {
            // Domain: [len][name].
            let len = *req.get(4).ok_or(Socks5Reject::Malformed)? as usize;
            let name = req.get(5..5 + len).ok_or(Socks5Reject::Malformed)?;
            let host = std::str::from_utf8(name)
                .map_err(|_| Socks5Reject::Malformed)?
                .to_ascii_lowercase();
            (host, 5 + len)
        }
        0x04 => {
            // IPv6.
            let addr = req.get(4..20).ok_or(Socks5Reject::Malformed)?;
            let mut segs = [0u16; 8];
            for (i, seg) in segs.iter_mut().enumerate() {
                *seg = u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]);
            }
            (std::net::Ipv6Addr::from(segs).to_string(), 20)
        }
        _ => return Err(Socks5Reject::AddressNotSupported),
    };
    let port_bytes = req
        .get(port_offset..port_offset + 2)
        .ok_or(Socks5Reject::Malformed)?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Ok(ConnectTarget { host, port })
}

/// The SOCKS5 success reply: `05 00 00 01` + 0.0.0.0 + port 0 (Part 05 §4.2).
pub const SOCKS5_SUCCESS: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

/// A SOCKS5 failure reply for the given code: `05 <code> 00 01` + zero addr.
pub fn socks5_failure(code: u8) -> [u8; 10] {
    [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

// ---- Inner-protocol sniffing (Part 05 §4.3) ---------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum InnerProtocol {
    /// `0x16` → TLS ClientHello: terminate with a minted leaf.
    Tls,
    /// ASCII uppercase → plain HTTP.
    Http,
    /// Anything else → close.
    Unknown,
}

pub fn sniff_inner(first_byte: u8) -> InnerProtocol {
    match first_byte {
        0x16 => InnerProtocol::Tls,
        b'A'..=b'Z' => InnerProtocol::Http,
        _ => InnerProtocol::Unknown,
    }
}

/// Result of scanning buffered inner bytes for a TLS ClientHello SNI
/// (Part 05 §4.4 — the passthrough SNI/target check, threat T6).
#[derive(Debug, PartialEq, Eq)]
pub enum SniScan {
    /// Not enough bytes buffered yet to decide.
    Incomplete,
    /// A complete ClientHello with no server_name extension (or one this
    /// scanner cannot see, e.g. a ClientHello spanning TLS records). The
    /// caller treats this as "no name to check", not as a mismatch.
    NoSni,
    /// The server_name the client asked for.
    Sni(String),
    /// The bytes are not a parseable TLS handshake record.
    NotTls,
}

/// Extract the SNI from the first TLS record of a buffered ClientHello.
/// Pure and total: never panics on arbitrary input.
pub fn scan_client_hello_sni(buf: &[u8]) -> SniScan {
    // TLS record header: type(1)=0x16 version(2) length(2).
    if buf.len() < 5 {
        return SniScan::Incomplete;
    }
    if buf[0] != 0x16 {
        return SniScan::NotTls;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record = match buf.get(5..5 + record_len) {
        Some(r) => r,
        None => return SniScan::Incomplete,
    };
    // Handshake header: type(1)=0x01 length(3).
    if record.len() < 4 || record[0] != 0x01 {
        return SniScan::NotTls;
    }
    let hs_len = u32::from_be_bytes([0, record[1], record[2], record[3]]) as usize;
    let body = match record.get(4..) {
        Some(b) if b.len() >= hs_len => &b[..hs_len],
        // ClientHello continues in a later record; give up rather than
        // reassemble (rare in practice, and NoSni fails open to the
        // CONNECT-authority policy already applied).
        Some(_) => return SniScan::NoSni,
        None => return SniScan::NoSni,
    };
    // client_version(2) random(32).
    let mut i = 34usize;
    // session_id.
    let Some(&sid_len) = body.get(i) else {
        return SniScan::NotTls;
    };
    i += 1 + sid_len as usize;
    // cipher_suites.
    let Some(cs) = body.get(i..i + 2) else {
        return SniScan::NotTls;
    };
    i += 2 + u16::from_be_bytes([cs[0], cs[1]]) as usize;
    // compression_methods.
    let Some(&comp_len) = body.get(i) else {
        return SniScan::NotTls;
    };
    i += 1 + comp_len as usize;
    // extensions.
    let Some(ext_total) = body.get(i..i + 2) else {
        return SniScan::NoSni; // no extensions block at all
    };
    let ext_end = i + 2 + u16::from_be_bytes([ext_total[0], ext_total[1]]) as usize;
    i += 2;
    while i + 4 <= ext_end.min(body.len()) {
        let ext_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let ext_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        let Some(ext) = body.get(i..i + ext_len) else {
            return SniScan::NoSni;
        };
        if ext_type == 0 {
            // server_name list: list_len(2) name_type(1)=0 name_len(2) name.
            if ext.len() < 5 || ext[2] != 0 {
                return SniScan::NoSni;
            }
            let name_len = u16::from_be_bytes([ext[3], ext[4]]) as usize;
            let Some(name) = ext.get(5..5 + name_len) else {
                return SniScan::NoSni;
            };
            return match std::str::from_utf8(name) {
                Ok(n) => SniScan::Sni(n.to_ascii_lowercase()),
                Err(_) => SniScan::NoSni,
            };
        }
        i += ext_len;
    }
    SniScan::NoSni
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_first_byte() {
        assert_eq!(dispatch(0x05), ClientProtocol::Socks5);
        assert_eq!(dispatch(b'C'), ClientProtocol::Http);
        assert_eq!(dispatch(b'G'), ClientProtocol::Http);
        assert_eq!(dispatch(0x16), ClientProtocol::Unknown);
    }

    #[test]
    fn connect_parsing() {
        assert_eq!(
            parse_connect("CONNECT api.example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(ConnectTarget {
                host: "api.example.com".into(),
                port: 443
            })
        );
        // Default port 443.
        assert_eq!(
            parse_connect("CONNECT api.example.com HTTP/1.1\r\n\r\n"),
            Some(ConnectTarget {
                host: "api.example.com".into(),
                port: 443
            })
        );
        assert_eq!(
            parse_connect("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n"),
            Some(ConnectTarget {
                host: "2001:db8::1".into(),
                port: 8443
            })
        );
        assert_eq!(parse_connect("GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn socks5_method_selection() {
        // nmethods=1, method 0x00 (no-auth).
        assert_eq!(
            parse_socks5_methods(&[0x01, 0x00]),
            Some(Socks5Method::NoAuth)
        );
        // only method 0x02 (user/pass) → unacceptable.
        assert_eq!(
            parse_socks5_methods(&[0x01, 0x02]),
            Some(Socks5Method::Unacceptable)
        );
    }

    #[test]
    fn socks5_request_ipv4_domain_ipv6() {
        // IPv4 10.0.0.5:443.
        let v4 = [0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5, 0x01, 0xBB];
        assert_eq!(
            parse_socks5_request(&v4),
            Ok(ConnectTarget {
                host: "10.0.0.5".into(),
                port: 443
            })
        );
        // Domain api.example.com:443.
        let host = b"api.example.com";
        let mut dom = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        dom.extend_from_slice(host);
        dom.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            parse_socks5_request(&dom),
            Ok(ConnectTarget {
                host: "api.example.com".into(),
                port: 443
            })
        );
        // Non-CONNECT command.
        let bind = [0x05, 0x02, 0x00, 0x01, 10, 0, 0, 5, 0x01, 0xBB];
        assert_eq!(
            parse_socks5_request(&bind),
            Err(Socks5Reject::CommandNotSupported)
        );
        // Unknown address type.
        let bad_atyp = [0x05, 0x01, 0x00, 0x09, 0, 0];
        assert_eq!(
            parse_socks5_request(&bad_atyp),
            Err(Socks5Reject::AddressNotSupported)
        );
    }

    #[test]
    fn inner_sniff() {
        assert_eq!(sniff_inner(0x16), InnerProtocol::Tls);
        assert_eq!(sniff_inner(b'G'), InnerProtocol::Http);
        assert_eq!(sniff_inner(0x05), InnerProtocol::Unknown);
    }

    /// Build a minimal ClientHello record with an optional SNI.
    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(name) = sni {
            let n = name.as_bytes();
            let mut sni_ext = Vec::new();
            sni_ext.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes()); // list len
            sni_ext.push(0); // name_type host_name
            sni_ext.extend_from_slice(&(n.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(n);
            ext.extend_from_slice(&0u16.to_be_bytes()); // ext type server_name
            ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            ext.extend_from_slice(&sni_ext);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression len
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sni_scan_extracts_name() {
        let hello = client_hello(Some("Upstream.TEST"));
        assert_eq!(
            scan_client_hello_sni(&hello),
            SniScan::Sni("upstream.test".into())
        );
    }

    #[test]
    fn sni_scan_no_extension_is_nosni() {
        assert_eq!(scan_client_hello_sni(&client_hello(None)), SniScan::NoSni);
    }

    #[test]
    fn sni_scan_partial_record_is_incomplete() {
        let hello = client_hello(Some("a.test"));
        assert_eq!(scan_client_hello_sni(&hello[..3]), SniScan::Incomplete);
        assert_eq!(
            scan_client_hello_sni(&hello[..hello.len() - 1]),
            SniScan::Incomplete
        );
    }

    #[test]
    fn sni_scan_non_tls_is_rejected() {
        assert_eq!(
            scan_client_hello_sni(b"GET / HTTP/1.1\r\n"),
            SniScan::NotTls
        );
    }

    #[test]
    fn sni_scan_never_panics_on_truncations() {
        let hello = client_hello(Some("fuzz.test"));
        for cut in 0..hello.len() {
            let _ = scan_client_hello_sni(&hello[..cut]);
        }
    }
}
