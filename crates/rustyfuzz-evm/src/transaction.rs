//! EVM semantic transaction representation.

use revm::context::TxEnv;
use revm::primitives::{Address, Bytes, U256};
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

impl SingletonTx {
    pub fn to_revm_tx_env(&self) -> TxEnv {
        TxEnv {
            caller: self.caller,
            kind: revm::primitives::TxKind::Call(self.to),
            gas_limit: 10_000_000,
            gas_price: 0,
            value: self.value,
            data: Bytes::copy_from_slice(&self.input),
            gas_priority_fee: Some(0),
            access_list: Default::default(),
            blob_hashes: Vec::new(),
            max_fee_per_blob_gas: 0,
            ..Default::default()
        }
    }
}
