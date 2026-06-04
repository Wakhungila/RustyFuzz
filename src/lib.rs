pub mod chain;
pub mod common;
pub mod config;
pub mod engine;
pub mod evm;
pub mod hybrid;
pub mod oracles;
pub mod satori;

#[cfg(feature = "svm")]
compile_error!(
    "RustyFuzz SVM support is experimental and unsupported in this EVM-first build. Disable `svm` until the SVM modules are rebuilt and tested."
);

#[cfg(feature = "sgx")]
compile_error!(
    "RustyFuzz SGX support is experimental and unsupported. Disable `sgx` until the SGX executor is rebuilt against the active revm API and dependencies."
);

// SVM is disabled by default due to version conflicts with Solana 2.0.18
// Enable only with: cargo build --features svm --no-default-features
// #[cfg(feature = "svm")]
// pub mod svm;

#[cfg(feature = "evm")]
pub use evm::*;

#[cfg(feature = "evm")]
pub use common::types::*;
