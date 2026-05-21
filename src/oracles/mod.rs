//! Oracle implementations for detecting vulnerabilities

pub mod economic;

pub use economic::{
    AccessControlOracle, EconomicOracleBundle, FlashLoanOracle, PriceManipulationOracle,
};
