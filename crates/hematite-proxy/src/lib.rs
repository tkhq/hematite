//! hematite-proxy — the L1 forward proxy data plane.
//!
//! Spec: Parts 05 §1–§2 and §6 (common handling, HTTP listener, failure
//! behavior), 07 (upstream dialing and the guard), 08 (audit emission),
//! 09 (configuration, validation, reload).

#![forbid(unsafe_code)]

pub mod audit;
pub mod config;
pub mod dial;
pub mod hop;
pub mod http;
pub mod management;
pub mod state;
