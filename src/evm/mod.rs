// Core Fuzzing Logic
pub mod corpus;
pub mod economic;
pub mod economic_views;
pub mod feedback;
#[cfg(feature = "evm")]
pub mod fuzz;
pub mod registry;
pub mod snapshot;

pub mod trace;

#[cfg(feature = "evm")]
pub mod erc20_discovery;
#[cfg(feature = "evm")]
pub mod etherscan_abi_fetcher;
#[cfg(feature = "evm")]
pub mod fork;
#[cfg(feature = "evm")]
pub mod seed_ingester;
