//! Appendix C §1 (spec/vectors/matching.json) — L0.

mod common;

use hematite_kernel::matcher::{Cidr, DomainGlob, HeaderNameEntry, PathGlob};

#[test]
fn domain_globs() {
    let vectors = common::load_vector("matching.json");
    for row in vectors["domain_globs"].as_array().unwrap() {
        let pattern = row["pattern"].as_str().unwrap();
        if row["config_error"].as_bool() == Some(true) {
            assert!(
                DomainGlob::parse(pattern).is_err(),
                "pattern {pattern:?} must be rejected at config load"
            );
            continue;
        }
        let glob = DomainGlob::parse(pattern)
            .unwrap_or_else(|e| panic!("pattern {pattern:?} must compile: {e}"));
        let host = row["host"].as_str().unwrap();
        let want = row["match"].as_bool().unwrap();
        assert_eq!(
            glob.matches(host),
            want,
            "pattern {pattern:?} vs host {host:?}"
        );
    }
}

#[test]
fn cidrs() {
    let vectors = common::load_vector("matching.json");
    for row in vectors["cidrs"].as_array().unwrap() {
        let cidr = row["cidr"].as_str().unwrap();
        if row["config_error"].as_bool() == Some(true) {
            assert!(
                Cidr::parse(cidr).is_err(),
                "cidr {cidr:?} must be rejected at config load"
            );
            continue;
        }
        let compiled =
            Cidr::parse(cidr).unwrap_or_else(|e| panic!("cidr {cidr:?} must compile: {e}"));
        let host = row["host"].as_str().unwrap();
        let want = row["match"].as_bool().unwrap();
        assert_eq!(
            compiled.matches_host(host),
            want,
            "cidr {cidr:?} vs host {host:?}"
        );
    }
}

#[test]
fn path_globs() {
    let vectors = common::load_vector("matching.json");
    for row in vectors["path_globs"].as_array().unwrap() {
        let pattern = row["pattern"].as_str().unwrap();
        let glob = PathGlob::parse(pattern)
            .unwrap_or_else(|e| panic!("pattern {pattern:?} must compile: {e}"));
        let path = row["path"].as_str().unwrap();
        let want = row["match"].as_bool().unwrap();
        assert_eq!(
            glob.matches(path),
            want,
            "pattern {pattern:?} vs path {path:?}"
        );
    }
}

#[test]
fn header_names() {
    let vectors = common::load_vector("matching.json");
    for row in vectors["header_names"].as_array().unwrap() {
        let entry = row["entry"].as_str().unwrap();
        let compiled = HeaderNameEntry::parse(entry, true)
            .unwrap_or_else(|e| panic!("entry {entry:?} must compile: {e}"));
        let header = row["header"].as_str().unwrap();
        let want = row["match"].as_bool().unwrap();
        assert_eq!(
            compiled.matches(header),
            want,
            "entry {entry:?} vs header {header:?}"
        );
    }
}
