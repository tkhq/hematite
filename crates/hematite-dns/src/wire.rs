//! Minimal DNS wire handling (RFC 1035): parse the question, build A /
//! CNAME / empty-NOERROR / SERVFAIL responses. Only the subset Part 06
//! needs — no general resolver, no compression in what we emit beyond the
//! single question-name pointer.

use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

/// RCODEs we emit.
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;

/// The parsed question plus the bytes needed to echo it back.
#[derive(Debug, Clone)]
pub struct Query {
    pub id: u16,
    /// Recursion-desired bit from the request flags.
    pub rd: bool,
    /// Lowercased, no trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// The raw question section (QNAME..QCLASS), echoed verbatim.
    pub question_raw: Vec<u8>,
}

/// Parse a DNS query message. Returns `None` on anything malformed or with
/// no question (the caller answers SERVFAIL / drops).
pub fn parse_query(msg: &[u8]) -> Option<Query> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qr = flags & 0x8000 != 0;
    if qr {
        return None; // a response, not a query
    }
    let rd = flags & 0x0100 != 0;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount < 1 {
        return None;
    }

    // Parse QNAME labels starting at offset 12 (no compression in queries).
    let mut i = 12;
    let mut name = String::new();
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointer in a question: unsupported
        }
        if !name.is_empty() {
            name.push('.');
        }
        let label = msg.get(i + 1..i + 1 + len)?;
        name.push_str(&String::from_utf8_lossy(label));
        i += 1 + len;
    }
    let qtype = u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]);
    let qclass = u16::from_be_bytes([*msg.get(i + 2)?, *msg.get(i + 3)?]);
    let question_raw = msg.get(12..i + 4)?.to_vec();

    Some(Query {
        id,
        rd,
        name: name.to_ascii_lowercase(),
        qtype,
        qclass,
        question_raw,
    })
}

/// Encode a domain name as DNS labels (root terminated).
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// The answer records to place in a response.
pub enum Answer {
    A { ip: Ipv4Addr, ttl: u32 },
    Cname { name: String, ttl: u32 },
}

fn header(id: u16, rd: bool, aa: bool, rcode: u8, ancount: u16) -> [u8; 12] {
    // QR=1, Opcode=0, AA=aa, TC=0, RD=rd, RA=1.
    let mut flags: u16 = 0x8000;
    if aa {
        flags |= 0x0400;
    }
    if rd {
        flags |= 0x0100;
    }
    flags |= 0x0080; // RA
    flags |= u16::from(rcode) & 0x000f;
    let [f0, f1] = flags.to_be_bytes();
    let [id0, id1] = id.to_be_bytes();
    let [a0, a1] = ancount.to_be_bytes();
    [id0, id1, f0, f1, 0, 1, a0, a1, 0, 0, 0, 0]
}

/// Build a response echoing the question and appending `answers`.
/// `aa` marks authoritative (static/intercept answers).
pub fn build_response(query: &Query, answers: &[Answer], aa: bool) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&header(
        query.id,
        query.rd,
        aa,
        RCODE_NOERROR,
        answers.len() as u16,
    ));
    msg.extend_from_slice(&query.question_raw);
    for answer in answers {
        // NAME: pointer to the question name at offset 12.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        match answer {
            Answer::A { ip, ttl } => {
                msg.extend_from_slice(&TYPE_A.to_be_bytes());
                msg.extend_from_slice(&CLASS_IN.to_be_bytes());
                msg.extend_from_slice(&ttl.to_be_bytes());
                msg.extend_from_slice(&4u16.to_be_bytes());
                msg.extend_from_slice(&ip.octets());
            }
            Answer::Cname { name, ttl } => {
                let encoded = encode_name(name);
                msg.extend_from_slice(&TYPE_CNAME.to_be_bytes());
                msg.extend_from_slice(&CLASS_IN.to_be_bytes());
                msg.extend_from_slice(&ttl.to_be_bytes());
                msg.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                msg.extend_from_slice(&encoded);
            }
        }
    }
    msg
}

/// An empty NOERROR response (echoes the question, zero answers).
pub fn build_empty_noerror(query: &Query, aa: bool) -> Vec<u8> {
    build_response(query, &[], aa)
}

/// A SERVFAIL response (upstream failure, Part 06 §3).
pub fn build_servfail(query: &Query) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&header(query.id, query.rd, false, RCODE_SERVFAIL, 0));
    msg.extend_from_slice(&query.question_raw);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal query packet for `name`/`qtype`.
    pub fn query_packet(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut msg = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00, // RD set
            0,
            1, // QDCOUNT
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        msg.extend_from_slice(&encode_name(name));
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg
    }

    #[test]
    fn roundtrip_question() {
        let packet = query_packet(0x1234, "API.Example.com", TYPE_A);
        let q = parse_query(&packet).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "api.example.com");
        assert_eq!(q.qtype, TYPE_A);
        assert!(q.rd);
    }

    #[test]
    fn a_response_shape() {
        let q = parse_query(&query_packet(1, "x.test", TYPE_A)).unwrap();
        let resp = build_response(
            &q,
            &[Answer::A {
                ip: Ipv4Addr::new(10, 0, 0, 5),
                ttl: 60,
            }],
            true,
        );
        // QR + AA + RA set, ANCOUNT=1, and the A rdata is present.
        assert_eq!(resp[2] & 0x80, 0x80, "QR");
        assert_eq!(resp[2] & 0x04, 0x04, "AA");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT");
        assert!(resp.ends_with(&[10, 0, 0, 5]));
    }

    #[test]
    fn servfail_and_empty() {
        let q = parse_query(&query_packet(1, "x.test", TYPE_AAAA)).unwrap();
        assert_eq!(build_servfail(&q)[3] & 0x0f, RCODE_SERVFAIL);
        let empty = build_empty_noerror(&q, true);
        assert_eq!(u16::from_be_bytes([empty[6], empty[7]]), 0, "no answers");
        assert_eq!(empty[3] & 0x0f, RCODE_NOERROR);
    }

    #[test]
    fn rejects_response_and_short() {
        assert!(parse_query(&[0; 4]).is_none());
        let mut resp = query_packet(1, "x", TYPE_A);
        resp[2] |= 0x80; // QR set → not a query
        assert!(parse_query(&resp).is_none());
    }
}
