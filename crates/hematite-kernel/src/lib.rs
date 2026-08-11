//! hematite-kernel — the pure L0 policy kernel.
//!
//! Spec: Parts 01 (decision model), 02 (matching), 03 (pipeline),
//! 04 §1–§2 + §4–§6 (transform policy logic), 08 §2 (record schema).
//!
//! INV-4 (kernel purity): this crate has no async runtime, filesystem,
//! network, or clock dependency. `duration_ms` is supplied by the caller.

#![forbid(unsafe_code)]

pub mod audit;
pub mod codec;
pub mod config;
pub mod matcher;
pub mod pipeline;
pub mod secret;
pub mod secrets;
pub mod summary;
pub mod transforms;
pub mod verdict;
