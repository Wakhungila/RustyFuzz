//! EVM-specific feedback implementations for LibAFL
//!
//! This module provides feedback mechanisms that understand EVM execution
//! patterns like coverage, gas usage, and state changes.

use crate::evm::fuzz::EvmInput;
use libafl::observers::StdMapObserver;
use libafl::prelude::*;
use libafl_bolts::{tuples::MatchName, AsSlice};
use revm::primitives::Address;
use std::collections::HashSet;

const DEFAULT_MAP_SIZE: usize = 65_536;

fn bucket_hitcount(hit: u8) -> u8 {
    match hit {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// Feedback that tracks EVM edge coverage using the shared coverage map
/// EvmCoverageFeedback: Tracks which contracts have been touched during fuzzing.
pub struct EvmCoverageFeedback {
    pub touched_addresses: HashSet<Address>,
    virgin: Vec<u8>,
    observer_name: &'static str,
}

impl EvmCoverageFeedback {
    pub fn new() -> Self {
        Self {
            touched_addresses: HashSet::new(),
            virgin: vec![0; DEFAULT_MAP_SIZE],
            observer_name: "edges",
        }
    }

    pub fn with_map_size(map_size: usize) -> Self {
        Self {
            touched_addresses: HashSet::new(),
            virgin: vec![0; map_size],
            observer_name: "edges",
        }
    }

    pub fn observe_coverage(&mut self, coverage: &[u8]) -> bool {
        if self.virgin.len() != coverage.len() {
            self.virgin.resize(coverage.len(), 0);
        }

        let mut interesting = false;
        for (seen, hit) in self.virgin.iter_mut().zip(coverage.iter().copied()) {
            let bucket = bucket_hitcount(hit);
            if bucket > *seen {
                *seen = bucket;
                interesting = true;
            }
        }
        interesting
    }

    pub fn stable_path_hash(coverage: &[u8]) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        for (idx, hit) in coverage.iter().copied().enumerate() {
            let bucket = bucket_hitcount(hit);
            if bucket == 0 {
                continue;
            }
            hash ^= idx as u64;
            hash = hash.wrapping_mul(0x100000001b3);
            hash ^= bucket as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}

impl Default for EvmCoverageFeedback {
    fn default() -> Self {
        Self {
            touched_addresses: HashSet::new(),
            virgin: vec![0; DEFAULT_MAP_SIZE],
            observer_name: "edges",
        }
    }
}

impl libafl_bolts::Named for EvmCoverageFeedback {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> =
            std::borrow::Cow::Borrowed("EvmCoverageFeedback");
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
    OT: ObserversTuple<S, EvmInput> + MatchName,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &EvmInput,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error> {
        #[allow(deprecated)]
        let observer = observers
            .match_name::<StdMapObserver<'_, u8, false>>(self.observer_name)
            .ok_or_else(|| libafl::Error::key_not_found("edges map observer"))?;
        Ok(self.observe_coverage(observer.as_slice()))
    }
}
