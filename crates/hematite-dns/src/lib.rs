//! hematite-dns — the L2 DNS interception server (spec Part 06).
//!
//! Points the workload's resolver at hematite so every lookup answers with
//! the proxy's IP and traffic arrives at the listeners without client
//! cooperation. Static records and passthrough zones override intercept.

#![forbid(unsafe_code)]

pub mod resolve;
pub mod server;
pub mod wire;

pub use resolve::{DnsConfig, StaticRecord};
pub use server::{DnsDecisionKind, DnsServer};
