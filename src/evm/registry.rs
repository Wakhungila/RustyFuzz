use alloy::primitives::Address;
use std::collections::HashSet;
use crate::common::types::ChainState;
use libafl_bolts::rands::Rand;

#[derive(Default, Clone, Debug)]
pub struct GlobalAccountRegistry {
    pub contracts: HashSet<Address>,
}

impl GlobalAccountRegistry {
    /// Scans the EVM state for accounts with code and adds them to the registry.
    pub fn discover_from_state(&mut self, state: &ChainState) {
        if let ChainState::Evm(db) = state {
            for (addr, acc) in &db.accounts {
                // Heuristic: If it has code, it's a potential fuzzing target
                if acc.info.code.as_ref().map_or(false, |c| !c.is_empty()) {
                    let alloy_addr = Address::from_slice(addr.as_slice());
                    self.contracts.insert(alloy_addr);
                }
            }
        }
    }

    pub fn random_contract<R: Rand>(&self, rand: &mut R) -> Option<Address> {
        if self.contracts.is_empty() { return None; }
        let idx = rand.below(self.contracts.len() as u64) as usize;
        self.contracts.iter().nth(idx).cloned()
    }
}