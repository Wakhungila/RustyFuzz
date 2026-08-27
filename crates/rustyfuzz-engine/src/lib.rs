//! Fuzzing domain model and campaign infrastructure for RustyFuzz.
//!
//! This crate owns the fuzzing-side concepts that sit above the EVM backend:
//! the semantic input model ([`input`]), campaign scoring primitives,
//! LibAFL-integrated scheduling, execution budgeting/telemetry, the bounded
//! event sink for cold-path outputs, and concolic hint statistics.
//!
//! Dependency direction: `core <- evm <- engine <- root fuzzer`. The engine
//! must never be depended on by `core` or `evm`.

pub mod campaign;
pub mod concolic_stats;
pub mod events;
pub mod input;
pub mod scheduler;
pub mod scoring;
