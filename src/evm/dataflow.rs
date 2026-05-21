use revm::primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct DataflowRegistry {
    /// Maps a contract address to a set of storage slots that have been
    /// influenced by user-controlled calldata.
    pub influenced_slots: HashMap<Address, HashSet<B256>>,
}

impl DataflowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_influenced(&mut self, address: Address, slot: B256) {
        self.influenced_slots
            .entry(address)
            .or_default()
            .insert(slot);
    }

    pub fn is_influenced(&self, address: Address, slot: B256) -> bool {
        self.influenced_slots
            .get(&address)
            .is_some_and(|slots| slots.contains(&slot))
    }
}
