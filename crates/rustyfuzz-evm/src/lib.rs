//! REVM-backed EVM execution backend.
//!
//! This crate owns execution semantics only: fork/cached state handling, the
//! coverage inspector, and transaction/result domain types. Fuzzing policy,
//! scheduling, mutators, oracles, and persistence remain in the root fuzzer.

pub mod coverage;
pub mod dataflow;
pub mod execution;
pub mod executor;
pub mod fork_db;
pub mod inspector;
pub mod transaction;

pub use dataflow::DataflowRegistry;
pub use executor::{EvmExecutor, ExecutionMode};
pub use fork_db::{EvmCacheDb, ForkDb};
pub use inspector::MAP_SIZE;
pub use transaction::SingletonTx;

/// Keccak-256, re-exported so downstream crates hash identity material with
/// the exact same primitive the backend uses (no second implementation).
pub use revm::primitives::keccak256;
pub use revm::primitives::U256;
