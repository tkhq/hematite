//! Part 02 — the shared matcher: rules, domain globs, CIDRs, path globs,
//! header-name patterns. One matching semantics for every transform and the
//! DNS server. Vectors: Appendix C §1.

use std::fmt;
use std::net::IpAddr;

/// A Part 02 construct that fails to compile at config load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchConfigError(pub String);

impl fmt::Display for MatchConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid matcher: {}", self.0)
    }
}

/// Canonical display form of a header name: `x-request-id` → `X-Request-Id`.
pub fn canonical_name(name: &str) -> String {
    name.split('-')
        .map(|token| {
            let mut chars = token.chars();
            match chars.next() {
                Some(first) => {
                    first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Part 02 §2 — domain glob. `*` is only meaningful as the leading label;
/// `*.example.com` matches `example.com` itself and any subdomain depth.
#[derive(Debug, Clone)]
pub struct DomainGlob {
    /// Lowercase suffix without the `*.` prefix.
    suffix: String,
    wildcard: bool,
}

impl DomainGlob {
    pub fn parse(pattern: &str) -> Result<Self, MatchConfigError> {
        let p = pattern.to_ascii_lowercase();
        if let Some(rest) = p.strip_prefix("*.") {
            if rest.is_empty() || rest.contains('*') {
                return Err(MatchConfigError(format!(
                    "`*` is only valid as the leading label: {pattern:?}"
                )));
            }
            Ok(DomainGlob {
                suffix: rest.to_string(),
                wildcard: true,
            })
        } else if p.contains('*') {
            Err(MatchConfigError(format!(
                "`*` is only valid as the leading label: {pattern:?}"
            )))
        } else if p.is_empty() {
            Err(MatchConfigError("empty domain pattern".into()))
        } else {
            Ok(DomainGlob {
                suffix: p,
                wildcard: false,
            })
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        let h = h.strip_suffix('.').unwrap_or(&h);
        if h == self.suffix {
            return true;
        }
        self.wildcard && h.ends_with(&self.suffix) && {
            let boundary = h.len() - self.suffix.len();
            h.as_bytes()[boundary - 1] == b'.'
        }
    }
}

/// Part 02 §3 — CIDR host clause. Matches only IP *literals*; hostnames
/// never match. A bare IP without a prefix length is a config error.
#[derive(Debug, Clone)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, MatchConfigError> {
        let (addr, len) = s.split_once('/').ok_or_else(|| {
            MatchConfigError(format!(
                "bare IP without prefix length: {s:?} (write /32 or /128 explicitly)"
            ))
        })?;
        let net: IpAddr = addr
            .parse()
            .map_err(|_| MatchConfigError(format!("invalid CIDR address: {s:?}")))?;
        let prefix: u8 = len
            .parse()
            .map_err(|_| MatchConfigError(format!("invalid CIDR prefix: {s:?}")))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(MatchConfigError(format!("CIDR prefix out of range: {s:?}")));
        }
        Ok(Cidr { net, prefix })
    }

    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) routes as IPv4, so
    /// it must match the prefixes its canonical IPv4 form matches — an
    /// AAAA record must not carry a denied address past an IPv4 rule.
    /// The check also runs on the literal form, so an explicit v6 prefix
    /// covering the mapped range still applies.
    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.contains_literal(ip) {
            return true;
        }
        let canonical = ip.to_canonical();
        canonical != ip && self.contains_literal(canonical)
    }

    fn contains_literal(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }

    /// The host clause form: true only when `host` is an IP literal inside
    /// the prefix.
    pub fn matches_host(&self, host: &str) -> bool {
        host.parse::<IpAddr>()
            .map(|ip| self.contains(ip))
            .unwrap_or(false)
    }
}

/// Part 02 §4 — path glob. `*` matches any run of characters including `/`;
/// matching is case-sensitive against the raw path. No `**`, classes, `?`.
#[derive(Debug, Clone)]
pub struct PathGlob {
    pattern: String,
}

impl PathGlob {
    pub fn parse(pattern: &str) -> Result<Self, MatchConfigError> {
        Ok(PathGlob {
            pattern: pattern.to_string(),
        })
    }

    pub fn matches(&self, path: &str) -> bool {
        let parts: Vec<&str> = self.pattern.split('*').collect();
        if parts.len() == 1 {
            return self.pattern == path;
        }
        let mut rest = match path.strip_prefix(parts[0]) {
            Some(r) => r,
            None => return false,
        };
        let last = parts[parts.len() - 1];
        for mid in &parts[1..parts.len() - 1] {
            if mid.is_empty() {
                continue;
            }
            match rest.find(mid) {
                Some(i) => rest = &rest[i + mid.len()..],
                None => return false,
            }
        }
        rest.ends_with(last)
    }
}

/// Part 02 §5 — header-name entry: a case-insensitive literal, or a
/// slash-delimited case-insensitive regex (RE2-class; the `regex` crate is
/// RE2-class by construction) matched against the lowercase name.
#[derive(Debug, Clone)]
pub enum HeaderNameEntry {
    Literal(String),
    Regex(regex::Regex),
}

impl HeaderNameEntry {
    pub fn parse(entry: &str, allow_regex: bool) -> Result<Self, MatchConfigError> {
        if entry.len() >= 2 && entry.starts_with('/') && entry.ends_with('/') {
            if !allow_regex {
                return Err(MatchConfigError(format!(
                    "regex entries are not allowed here: {entry:?}"
                )));
            }
            let inner = &entry[1..entry.len() - 1];
            let re = regex::RegexBuilder::new(inner)
                .case_insensitive(true)
                .build()
                .map_err(|e| MatchConfigError(format!("invalid header regex {entry:?}: {e}")))?;
            Ok(HeaderNameEntry::Regex(re))
        } else if entry.is_empty() {
            Err(MatchConfigError("empty header-name entry".into()))
        } else {
            Ok(HeaderNameEntry::Literal(entry.to_ascii_lowercase()))
        }
    }

    pub fn matches(&self, header_name: &str) -> bool {
        let lower = header_name.to_ascii_lowercase();
        match self {
            HeaderNameEntry::Literal(l) => *l == lower,
            HeaderNameEntry::Regex(re) => re.is_match(&lower),
        }
    }
}

/// Part 02 §1 — the host clause of a rule: a domain glob or a CIDR.
#[derive(Debug, Clone)]
pub enum HostClause {
    Glob(DomainGlob),
    Cidr(Cidr),
}

impl HostClause {
    pub fn parse(s: &str) -> Result<Self, MatchConfigError> {
        if s.contains('/') {
            Ok(HostClause::Cidr(Cidr::parse(s)?))
        } else {
            Ok(HostClause::Glob(DomainGlob::parse(s)?))
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        match self {
            HostClause::Glob(g) => g.matches(host),
            HostClause::Cidr(c) => c.matches_host(host),
        }
    }
}

/// Part 02 §1 — the rule: host AND (methods, if present) AND (paths, if
/// present).
#[derive(Debug, Clone)]
pub struct Rule {
    pub host: HostClause,
    /// Absent = any method. Stored uppercase.
    pub methods: Option<Vec<String>>,
    /// Absent = any path.
    pub paths: Option<Vec<PathGlob>>,
}

impl Rule {
    pub fn matches(&self, host: &str, method: &str, path: &str) -> bool {
        if !self.host.matches(host) {
            return false;
        }
        if let Some(methods) = &self.methods {
            if !methods.iter().any(|m| m == method) {
                return false;
            }
        }
        if let Some(paths) = &self.paths {
            if !paths.iter().any(|p| p.matches(path)) {
                return false;
            }
        }
        true
    }
}

/// A rule list matches when any rule matches (OR).
pub fn any_rule_matches(rules: &[Rule], host: &str, method: &str, path: &str) -> bool {
    rules.iter().any(|r| r.matches(host, method, path))
}
