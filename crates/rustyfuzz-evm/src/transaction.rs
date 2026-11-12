//! EVM semantic transaction representation.

use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

/// Represents a single EVM transaction in a fuzzing sequence.
///
/// A `SingletonTx` contains all the necessary information to execute a transaction
/// during fuzzing, including calldata, caller, target address, value, and victim status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SingletonTx {
    /// The transaction calldata (function selector + arguments)
    pub input: Vec<u8>,
    /// The address of the transaction sender
    pub caller: Address,
    /// The target contract address
    pub to: Address,
    /// The ETH value sent with the transaction
    pub value: U256,
    /// Whether this transaction is marked as a victim (for MEV/sandwich attacks)
    pub is_victim: bool,
}
