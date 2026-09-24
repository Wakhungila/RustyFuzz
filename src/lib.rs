#[cfg(feature = "evm")]
pub mod chain;
#[cfg(feature = "evm")]
pub mod common;
#[cfg(feature = "evm")]
pub mod config;
#[cfg(feature = "evm")]
pub mod engine;
#[cfg(feature = "evm")]
pub mod error;
#[cfg(feature = "evm")]
pub mod evm;
#[cfg(feature = "evm")]
pub mod hybrid;
#[cfg(feature = "evm")]
pub mod oracles;
#[cfg(feature = "evm")]
pub mod satori;

#[cfg(not(feature = "evm"))]
compile_error!("RustyFuzz currently requires the `evm` feature; build with --features evm");

#[cfg(feature = "svm")]
compile_error!(
    "The `svm` feature is intentionally unsupported: the Solana/Mollusk executor is quarantined until rebuilt and tested. Use the default EVM engine."
);

#[cfg(feature = "sgx")]
pub mod sgx;

#[cfg(feature = "evm")]
pub use evm::*;

#[cfg(feature = "evm")]
pub use common::types::*;
