//! EVM-specific feedback implementations for LibAFL
//! 
//! This module provides feedback mechanisms that understand EVM execution
//! patterns like coverage, gas usage, and state changes.

use libafl::prelude::*;
// TODO: UsesState trait location changed in libafl
// use libafl::executors::hooks::UsesState;
use revm::primitives::Address;
use std::collections::HashSet;
use crate::evm::fuzz::EvmInput;

/// Feedback that tracks EVM edge coverage using the shared coverage map
/// EvmCoverageFeedback: Tracks which contracts have been touched during fuzzing.
pub struct EvmCoverageFeedback {
    pub touched_addresses: HashSet<Address>,
}

impl EvmCoverageFeedback {
    pub fn new() -> Self {
        Self {
            touched_addresses: HashSet::new(),
        }
    }
}

impl Default for EvmCoverageFeedback {
    fn default() -> Self {
        Self {
            touched_addresses: HashSet::new(),
        }
    }
}

impl libafl_bolts::Named for EvmCoverageFeedback {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("EvmCoverageFeedback");
        &NAME
    }
}

impl<S> libafl::feedbacks::StateInitializer<S> for EvmCoverageFeedback {
    fn init_state(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl<EM, S, OT> Feedback<EM, EvmInput, OT, S> for EvmCoverageFeedback
where
    S: HasCorpus<EvmInput>,
    // EM: UsesState<State = S>, // TODO: UsesState trait moved in libafl
    OT: ObserversTuple<S, EvmInput>,
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
