pub mod common;
pub mod evm;
pub mod hybrid;
pub mod engine;
pub mod chain;
pub mod config;
pub mod oracles;

// SVM is disabled by default due to version conflicts with Solana 2.0.18
// Enable only with: cargo build --features svm --no-default-features
// #[cfg(feature = "svm")]
// pub mod svm;

#[cfg(feature = "evm")]
pub use evm::*;

#[cfg(feature = "evm")]
pub use common::types::*;