use revm::primitives::{Address, U256, keccak256};
use revm::database::{CacheDB, EmptyDB};
use crate::common::types::{ChainState, SingletonTx};
use crate::evm::executor::EvmExecutor;
use crate::evm::fuzz::AbiRegistry;
use std::sync::Arc;

/// ERC20Discovery: Utility to dynamically find storage slots for ERC20 balances and total supply.
/// This is crucial for making economic oracles resilient to non-standard token layouts.
pub struct Erc20Discovery {
    executor: Arc<EvmExecutor>,
    abi_registry: Arc<AbiRegistry>,
}

impl Erc20Discovery {
    pub fn new(executor: Arc<EvmExecutor>, abi_registry: Arc<AbiRegistry>) -> Self {
        Self { executor, abi_registry }
    }

    /// Heuristically finds the storage slot for `balances[holder_address]` for a given ERC20 token.
    /// It probes common mapping slots (0-10) and verifies by calling `balanceOf()`.
    pub async fn find_balance_slot(
        &self,
        token_address: Address,
        holder_address: Address,
        initial_db: &CacheDB<EmptyDB>,
    ) -> Option<U256> {
        // 1. Get the actual balance of the holder by calling balanceOf()
        let balance_of_selector = [0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
        let mut call_data = balance_of_selector.to_vec();
        call_data.extend_from_slice(&[0u8; 12]); // Pad
        call_data.extend_from_slice(holder_address.as_slice());

        let mut temp_state = ChainState::Evm(initial_db.clone());
        let mut dummy_coverage = bitvec::bitvec![u8, bitvec::prelude::Lsb0; 0; crate::evm::inspector::MAP_SIZE];
        let mut dummy_dataflow = crate::evm::dataflow::DataflowRegistry::new();
        let mut dummy_waypoints = Vec::new();
        let mut dummy_block_env = revm::context::BlockEnv::default();

        let tx = SingletonTx {
            input: call_data,
            caller: Address::ZERO, // Neutral caller
            to: token_address,
            value: U256::ZERO,
            is_victim: false,
        };

        let actual_balance = if let Ok(_gas) = self.executor.execute(&mut temp_state, &mut dummy_block_env, &tx, dummy_coverage.as_raw_mut_slice(), &mut dummy_dataflow, &mut dummy_waypoints, 0) {
            let ChainState::Evm(db) = &temp_state;
            db.cache.accounts.get(&token_address).map(|acc| acc.info.balance).unwrap_or(U256::ZERO)
        } else { U256::ZERO };

        if actual_balance.is_zero() { return None; } // Cannot verify if balance is zero

        // 2. Probe common storage slots (0-10) for the balances mapping
        for slot_idx in 0..10 {
            let mut slot_key_bytes = [0u8; 64];
            slot_key_bytes[12..32].copy_from_slice(holder_address.as_slice()); // Address
            slot_key_bytes[32..64].copy_from_slice(&U256::from(slot_idx).to_be_bytes::<32>()); // Base slot
            let derived_slot = U256::from_be_bytes(keccak256(&slot_key_bytes).0);

            if let Some(token_acc) = initial_db.cache.accounts.get(&token_address) {
                if let Some(stored_balance) = token_acc.storage.get(&derived_slot) {
                    if *stored_balance == actual_balance {
                        log::info!("Discovered balance slot for Token {} at {}", token_address, derived_slot);
                        return Some(derived_slot);
                    }
                }
            }
        }
        None
    }

    /// Heuristically finds the storage slot for `totalSupply()` for a given ERC20 token.
    pub async fn find_total_supply_slot(&self, token_address: Address, initial_db: &CacheDB<EmptyDB>) -> Option<U256> {
        // This is a simpler heuristic: totalSupply is often at slot 0 or 1.
        // In production, we'd call totalSupply() and compare against probed slots.
        // For now, we assume slot 0 or 1.
        if let Some(token_acc) = initial_db.cache.accounts.get(&token_address) {
            if token_acc.storage.contains_key(&U256::ZERO) { return Some(U256::ZERO); }
            if token_acc.storage.contains_key(&U256::from(1)) { return Some(U256::from(1)); }
        }
        None
    }
}