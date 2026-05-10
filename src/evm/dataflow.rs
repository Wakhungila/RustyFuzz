use revm::primitives::{Address, B256};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

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
        self.influenced_slots.entry(address).or_default().insert(slot);
    }

    pub fn is_influenced(&self, address: Address, slot: B256) -> bool {
        self.influenced_slots.get(&address).map_or(false, |slots| slots.contains(&slot))
    }
}