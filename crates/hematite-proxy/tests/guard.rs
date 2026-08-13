//! Part 07 §2 — the deny-CIDR guard at the dialer. DNS controls what
//! address a name resolves to (threat T2), so the guard must hold for
//! every representation of a denied address, including the IPv4-mapped
//! IPv6 form an AAAA record can smuggle in.

use std::net::IpAddr;

use hematite_proxy::state::Guard;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn default_set_denies_ipv4_mapped_forms() {
    let guard = Guard::default_set();
    // The plain IPv4 forms are denied…
    assert!(guard.check(ip("169.254.169.254")).is_err());
    assert!(guard.check(ip("127.0.0.1")).is_err());
    // …and the IPv4-mapped IPv6 forms must be equally denied: the OS
    // routes ::ffff:a.b.c.d as IPv4, so letting them through reaches the
    // very addresses the rules name.
    assert!(guard.check(ip("::ffff:169.254.169.254")).is_err());
    assert!(guard.check(ip("::ffff:127.0.0.1")).is_err());
}

#[test]
fn mapped_forms_of_allowed_addresses_still_pass() {
    let guard = Guard::default_set();
    assert!(guard.check(ip("93.184.216.34")).is_ok());
    assert!(guard.check(ip("::ffff:93.184.216.34")).is_ok());
    assert!(guard.check(ip("2606:2800:220:1::1")).is_ok());
}

#[test]
fn configured_v4_rule_covers_mapped_probe() {
    let guard = Guard::new(&["10.0.0.0/8".into()]).unwrap();
    assert!(guard.check(ip("::ffff:10.1.2.3")).is_err());
    assert!(guard.check(ip("::ffff:11.0.0.1")).is_ok());
}
