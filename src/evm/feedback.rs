//! EVM-specific feedback implementations for LibAFL
//! 
//! This module provides feedback mechanisms that understand EVM execution
//! patterns like coverage, gas usage, and state changes.

use libafl::prelude::*;
use libafl::executors::UsesState;
use revm::primitives::Address;
use std::collections::HashSet;
use crate::evm::fuzz::EvmInput;

/// Feedback that tracks EVM edge coverage using the shared coverage map
pub struct EvmCoverageFeedback {
    /// Set of addresses that were touched in this execution
    touched_addresses: HashSet<Address>,
}

impl EvmCoverageFeedback {
    pub fn new() -> Self {
        Self {
            touched_addresses: HashSet::new(),
        }
    }
}

impl<EM, S, OT> Feedback<EM, EvmInput, OT, S> for EvmCoverageFeedback
where
    S: HasCorpus<EvmInput>,
    EM: UsesState<State = S>,
    OT: ObserversTuple<S>,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &EvmInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error> {
        // For now, always consider inputs interesting
        // In a full implementation, we'd analyze the coverage map
        Ok(true)
    }
}

impl Default for EvmCoverageFeedback {
    fn default() -> Self {
        Self::new()
    }
}
