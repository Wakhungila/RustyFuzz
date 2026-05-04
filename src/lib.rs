pub mod common;
pub mod evm;
// #[cfg(feature = "svm")]    // ← only compile if feature `svm` is enabled
// pub mod svm;   // disabled for now (or remove entirely);
pub mod hybrid;
pub mod engine;
pub mod chain;
pub mod config;
pub mod oracles;