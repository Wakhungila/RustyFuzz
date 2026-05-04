//! Oracle implementations for detecting vulnerabilities

pub mod economic;

pub use economic::{
    FlashLoanOracle, 
    PriceManipulationOracle, 
    AccessControlOracle, 
    EconomicOracleBundle,
};
