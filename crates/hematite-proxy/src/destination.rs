//! Canonical logical destinations shared by every workload listener.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
    Connect,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Connect => "connect",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https | Self::Connect => 443,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalDestination {
    scheme: Scheme,
    host: String,
    port: u16,
}

impl CanonicalDestination {
    pub fn parse_authority(authority: &str, scheme: Scheme) -> Result<Self, &'static str> {
        if authority.is_empty()
            || authority.bytes().any(|b| b.is_ascii_control())
            || !authority.is_ascii()
            || authority.contains('@')
        {
            return Err("invalid authority");
        }
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let end = rest.find(']').ok_or("malformed IPv6 brackets")?;
            let inside = &rest[..end];
            let suffix = &rest[end + 1..];
            if inside.contains('%') || inside.is_empty() || suffix.contains(['[', ']']) {
                return Err("invalid IPv6 literal");
            }
            let ip: IpAddr = inside.parse().map_err(|_| "invalid IPv6 literal")?;
            if !ip.is_ipv6() {
                return Err("brackets require IPv6");
            }
            let port = parse_suffix_port(suffix, scheme.default_port())?;
            (ip.to_string(), port)
        } else {
            if authority.contains(['[', ']']) {
                return Err("malformed brackets");
            }
            match authority.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => {
                    (canonical_host(host)?, parse_port(port)?)
                }
                Some(_) => return Err("IPv6 literals must be bracketed"),
                None => (canonical_host(authority)?, scheme.default_port()),
            }
        };
        Ok(Self { scheme, host, port })
    }

    /// Canonicalize a host and concrete port already separated by a binary
    /// protocol such as SOCKS5.
    pub fn from_host_port(host: &str, port: u16, scheme: Scheme) -> Result<Self, &'static str> {
        if port == 0 {
            return Err("port zero is invalid");
        }
        Ok(Self {
            scheme,
            host: canonical_host(host)?,
            port,
        })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn protocol(&self) -> &'static str {
        "tcp"
    }
    pub fn authority(&self) -> String {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn same_authority(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port
    }
}

fn parse_suffix_port(suffix: &str, default: u16) -> Result<u16, &'static str> {
    if suffix.is_empty() {
        Ok(default)
    } else {
        parse_port(suffix.strip_prefix(':').ok_or("invalid authority suffix")?)
    }
}

fn parse_port(port: &str) -> Result<u16, &'static str> {
    let port: u16 = port.parse().map_err(|_| "invalid port")?;
    (port != 0).then_some(port).ok_or("port zero is invalid")
}

fn canonical_host(host: &str) -> Result<String, &'static str> {
    if host.is_empty()
        || !host.is_ascii()
        || host.bytes().any(|b| b.is_ascii_control())
        || host.contains(['@', '[', ']', '%'])
    {
        return Err("invalid host");
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() || host.ends_with('.') || host.len() > 253 {
        return Err("invalid DNS name");
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("invalid DNS name");
        }
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_vectors_and_mutations() {
        let d = CanonicalDestination::parse_authority("EXAMPLE.COM.:443", Scheme::Https).unwrap();
        assert_eq!((d.host(), d.port()), ("example.com", 443));
        let ip =
            CanonicalDestination::parse_authority("[2001:0DB8::1]:8443", Scheme::Connect).unwrap();
        assert_eq!((ip.host(), ip.port()), ("2001:db8::1", 8443));
        for bad in [
            "",
            "user@x.test",
            "x.test:0",
            "x.test:no",
            "[::1",
            "[::1]x",
            "[fe80::1%eth0]",
            "é.test",
            "a..test",
            ".",
            "::1",
        ] {
            assert!(
                CanonicalDestination::parse_authority(bad, Scheme::Http).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn parser_entry_points_are_equivalent() {
        let a = CanonicalDestination::parse_authority("Example.COM.:443", Scheme::Connect).unwrap();
        let b = CanonicalDestination::from_host_port("Example.COM.", 443, Scheme::Connect).unwrap();
        assert_eq!(a, b);
    }
}
