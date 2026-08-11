//! Part 06 §2 — resolution precedence: static records, then passthrough,
//! then intercept. Pure: `(config, query) → Decision`; the server performs
//! the passthrough I/O.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use hematite_kernel::matcher::DomainGlob;

use crate::wire::{Answer, Query, TYPE_A, TYPE_AAAA, TYPE_CNAME};

/// A configured static record (Part 06 §1). Types A and CNAME only.
#[derive(Debug, Clone)]
pub enum StaticRecord {
    A(Ipv4Addr),
    Cname(String),
}

/// DNS server configuration (Part 06 §1), already validated.
pub struct DnsConfig {
    pub proxy_ip: Ipv4Addr,
    pub passthrough: Vec<DomainGlob>,
    /// name (lowercase, no trailing dot) → record.
    pub records: HashMap<String, StaticRecord>,
    pub ttl: u32,
}

/// What to do with a query.
pub enum Decision {
    /// Answer authoritatively with these records.
    Answer(Vec<Answer>),
    /// Empty NOERROR (AAAA/other for an intercepted name).
    EmptyNoError,
    /// Forward to the upstream resolver and relay (passthrough zone).
    Passthrough,
}

fn normalize(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

/// Apply Part 06 §2 precedence to one query.
pub fn resolve(config: &DnsConfig, query: &Query) -> Decision {
    let name = normalize(&query.name);

    // 1. Static records — exact-name match, highest precedence.
    if let Some(record) = config.records.get(name) {
        return match record {
            StaticRecord::A(ip) => {
                if query.qtype == TYPE_A {
                    Decision::Answer(vec![Answer::A { ip: *ip, ttl: config.ttl }])
                } else {
                    // Name exists but not for this type → empty NOERROR.
                    Decision::EmptyNoError
                }
            }
            StaticRecord::Cname(target) => {
                if query.qtype == TYPE_CNAME || query.qtype == TYPE_A {
                    Decision::Answer(vec![Answer::Cname {
                        name: target.clone(),
                        ttl: config.ttl,
                    }])
                } else {
                    Decision::EmptyNoError
                }
            }
        };
    }

    // 2. Passthrough — forward if the name matches any passthrough glob.
    if config.passthrough.iter().any(|g| g.matches(name)) {
        return Decision::Passthrough;
    }

    // 3. Intercept — A → proxy_ip; AAAA and everything else → empty NOERROR
    //    (so dual-stack clients fall back to the A record, Part 06 §3).
    if query.qtype == TYPE_A {
        Decision::Answer(vec![Answer::A { ip: config.proxy_ip, ttl: config.ttl }])
    } else {
        let _ = TYPE_AAAA;
        Decision::EmptyNoError
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{parse_query, TYPE_A, TYPE_AAAA};

    fn config() -> DnsConfig {
        let mut records = HashMap::new();
        records.insert("db.internal.corp".to_string(), StaticRecord::A(Ipv4Addr::new(10, 0, 0, 9)));
        DnsConfig {
            proxy_ip: Ipv4Addr::new(172, 20, 0, 2),
            passthrough: vec![DomainGlob::parse("*.internal.corp").unwrap()],
            records,
            ttl: 60,
        }
    }

    fn q(name: &str, qtype: u16) -> Query {
        // Reuse the wire test helper via a minimal packet.
        let mut msg = vec![0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        parse_query(&msg).unwrap()
    }

    #[test]
    fn static_beats_passthrough() {
        // db.internal.corp is inside the passthrough zone but has a static
        // record — static wins (acceptance step 6).
        match resolve(&config(), &q("db.internal.corp", TYPE_A)) {
            Decision::Answer(a) => match &a[0] {
                Answer::A { ip, .. } => assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 9)),
                _ => panic!("expected A"),
            },
            _ => panic!("static record must win"),
        }
    }

    #[test]
    fn passthrough_zone_forwards() {
        assert!(matches!(
            resolve(&config(), &q("ns.internal.corp", TYPE_A)),
            Decision::Passthrough
        ));
    }

    #[test]
    fn default_intercepts_to_proxy_ip() {
        match resolve(&config(), &q("anything.example", TYPE_A)) {
            Decision::Answer(a) => match &a[0] {
                Answer::A { ip, .. } => assert_eq!(*ip, Ipv4Addr::new(172, 20, 0, 2)),
                _ => panic!("expected A"),
            },
            _ => panic!("expected intercept"),
        }
    }

    #[test]
    fn aaaa_for_intercepted_is_empty_noerror() {
        assert!(matches!(
            resolve(&config(), &q("anything.example", TYPE_AAAA)),
            Decision::EmptyNoError
        ));
    }
}
