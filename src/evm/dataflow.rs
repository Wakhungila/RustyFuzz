use crate::common::types::{SymbolicExpression, TaintSource};
use revm::primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct DataflowRegistry {
    /// Maps a contract address to a set of storage slots that have been
    /// influenced by user-controlled calldata.
    pub influenced_slots: HashMap<Address, HashSet<B256>>,
    pub storage_taints: HashMap<(Address, B256), TaintSource>,
    pub storage_expressions: HashMap<(Address, B256), SymbolicExpression>,
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

    pub fn mark_storage_symbolic(
        &mut self,
        address: Address,
        slot: B256,
        taint: Option<TaintSource>,
        expression: Option<SymbolicExpression>,
    ) {
        if let Some(taint) = taint {
            self.storage_taints.insert((address, slot), taint);
        }
        if let Some(expression) = expression {
            self.storage_expressions.insert((address, slot), expression);
        }
    }

    pub fn storage_taint(&self, address: Address, slot: B256) -> Option<TaintSource> {
        self.storage_taints.get(&(address, slot)).cloned()
    }

    pub fn storage_expression(&self, address: Address, slot: B256) -> Option<SymbolicExpression> {
        self.storage_expressions.get(&(address, slot)).cloned()
    }
}
