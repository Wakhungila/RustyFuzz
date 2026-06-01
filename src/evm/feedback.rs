//! EVM-specific feedback implementations for LibAFL
//!
//! This module provides feedback mechanisms that understand EVM execution
//! patterns like coverage, gas usage, and state changes.

use crate::common::types::{CallPhase, SequenceExecutionResult, StorageDiff};
use crate::evm::fuzz::EvmInput;
use crate::evm::inspector::MAP_SIZE;
use libafl::observers::StdMapObserver;
use libafl::prelude::*;
use libafl_bolts::{tuples::MatchName, AsSlice};
use revm::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateNoveltyReport {
    pub interesting: bool,
    pub new_transition_hashes: Vec<u64>,
    pub new_slot_hashes: Vec<u64>,
    pub new_read_hashes: Vec<u64>,
    pub new_call_edge_hashes: Vec<u64>,
    pub new_contracts: Vec<Address>,
    pub state_hash: u64,
    pub write_set_hash: u64,
    pub read_set_hash: u64,
    pub call_graph_hash: u64,
}

impl StateNoveltyReport {
    pub fn novelty_score(&self) -> u64 {
        (self.new_transition_hashes.len() as u64 * 16)
            + (self.new_slot_hashes.len() as u64 * 8)
            + (self.new_read_hashes.len() as u64 * 3)
            + (self.new_call_edge_hashes.len() as u64 * 4)
            + (self.new_contracts.len() as u64 * 6)
    }
}

/// Tracks durable EVM state novelty from canonical execution artifacts.
/// This is independent from coverage novelty: two executions can share the same
/// path but write a new slot, reach a new state transition, or touch a new
/// protocol edge.
#[derive(Debug, Clone, Default)]
pub struct EvmStateNoveltyFeedback {
    seen_transition_hashes: HashSet<u64>,
    seen_slot_hashes: HashSet<u64>,
    seen_read_hashes: HashSet<u64>,
    seen_call_edge_hashes: HashSet<u64>,
    seen_contracts: HashSet<Address>,
}

impl EvmStateNoveltyFeedback {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_execution(&mut self, execution: &SequenceExecutionResult) -> StateNoveltyReport {
        let mut new_transition_hashes = Vec::new();
        let mut new_slot_hashes = Vec::new();
        let mut new_read_hashes = Vec::new();
        let mut new_call_edge_hashes = Vec::new();
        let mut new_contracts = Vec::new();

        for diff in canonical_storage_diffs(execution) {
            let transition_hash = stable_storage_transition_hash(&diff);
            if self.seen_transition_hashes.insert(transition_hash) {
                new_transition_hashes.push(transition_hash);
            }

            let slot_hash = stable_slot_hash(diff.address, diff.slot);
            if self.seen_slot_hashes.insert(slot_hash) {
                new_slot_hashes.push(slot_hash);
            }
        }

        for read in &execution.storage_reads {
            let read_hash = stable_slot_hash(read.address, read.slot);
            if self.seen_read_hashes.insert(read_hash) {
                new_read_hashes.push(read_hash);
            }
        }

        for call in execution
            .call_trace
            .iter()
            .filter(|call| call.phase == CallPhase::End)
        {
            if self.seen_contracts.insert(call.target) {
                new_contracts.push(call.target);
            }
            let selector = call.input.get(..4).map(|bytes| {
                let mut selector = [0u8; 4];
                selector.copy_from_slice(bytes);
                selector
            });
            let edge_hash = stable_call_edge_hash(call.caller, call.target, selector);
            if self.seen_call_edge_hashes.insert(edge_hash) {
                new_call_edge_hashes.push(edge_hash);
            }
        }

        new_transition_hashes.sort_unstable();
        new_slot_hashes.sort_unstable();
        new_read_hashes.sort_unstable();
        new_call_edge_hashes.sort_unstable();
        new_contracts.sort_unstable();

        let state_hash = stable_execution_state_hash(execution);
        let write_set_hash = stable_write_set_hash(execution);
        let read_set_hash = stable_read_set_hash(execution);
        let call_graph_hash = stable_call_graph_hash(execution);
        let interesting = !(new_transition_hashes.is_empty()
            && new_slot_hashes.is_empty()
            && new_read_hashes.is_empty()
            && new_call_edge_hashes.is_empty()
            && new_contracts.is_empty());

        StateNoveltyReport {
            interesting,
            new_transition_hashes,
            new_slot_hashes,
            new_read_hashes,
            new_call_edge_hashes,
            new_contracts,
            state_hash,
            write_set_hash,
            read_set_hash,
            call_graph_hash,
        }
    }

    pub fn stable_execution_state_hash(execution: &SequenceExecutionResult) -> u64 {
        stable_execution_state_hash(execution)
    }
}

pub fn stable_execution_state_hash(execution: &SequenceExecutionResult) -> u64 {
    let mut hashes: Vec<_> = canonical_storage_diffs(execution)
        .into_iter()
        .map(|diff| stable_storage_transition_hash(&diff))
        .collect();
    hashes.sort_unstable();
    stable_hash_words(&hashes)
}

pub fn stable_write_set_hash(execution: &SequenceExecutionResult) -> u64 {
    let slots: BTreeSet<_> = execution
        .storage_writes
        .iter()
        .map(|write| stable_slot_hash(write.address, write.slot))
        .collect();
    stable_hash_words(slots.iter())
}

pub fn stable_read_set_hash(execution: &SequenceExecutionResult) -> u64 {
    let slots: BTreeSet<_> = execution
        .storage_reads
        .iter()
        .map(|read| stable_slot_hash(read.address, read.slot))
        .collect();
    stable_hash_words(slots.iter())
}

pub fn stable_call_graph_hash(execution: &SequenceExecutionResult) -> u64 {
    let edges: BTreeSet<_> = execution
        .call_trace
        .iter()
        .filter(|call| call.phase == CallPhase::End)
        .map(|call| stable_call_edge_hash(call.caller, call.target, None))
        .collect();
    stable_hash_words(edges.iter())
}

fn canonical_storage_diffs(execution: &SequenceExecutionResult) -> Vec<StorageDiff> {
    let mut diffs = execution.storage_diffs.clone();
    diffs.sort_by_key(|diff| {
        (
            diff.address,
            diff.slot,
            diff.old_value,
            diff.new_value,
            diff.tx_index,
            diff.pc,
        )
    });
    diffs.dedup();
    diffs
}

fn stable_storage_transition_hash(diff: &StorageDiff) -> u64 {
    let mut hash = Fnv64::new();
    hash.write_address(diff.address);
    hash.write_b256(diff.slot);
    hash.write_u256(diff.old_value);
    hash.write_u256(diff.new_value);
    hash.finish()
}

fn stable_slot_hash(address: Address, slot: B256) -> u64 {
    let mut hash = Fnv64::new();
    hash.write_address(address);
    hash.write_b256(slot);
    hash.finish()
}

fn stable_call_edge_hash(caller: Address, target: Address, selector: Option<[u8; 4]>) -> u64 {
    let mut hash = Fnv64::new();
    hash.write_address(caller);
    hash.write_address(target);
    if let Some(selector) = selector {
        hash.write_bytes(&selector);
    }
    hash.finish()
}

fn stable_hash_words<'a>(words: impl IntoIterator<Item = &'a u64>) -> u64 {
    let mut hash = Fnv64::new();
    for word in words {
        hash.write_u64(*word);
    }
    hash.finish()
}

struct Fnv64(u64);

impl Fnv64 {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_be_bytes());
    }

    fn write_u256(&mut self, value: U256) {
        self.write_bytes(&value.to_be_bytes::<32>());
    }

    fn write_b256(&mut self, value: B256) {
        self.write_bytes(value.as_slice());
    }

    fn write_address(&mut self, value: Address) {
        self.write_bytes(value.as_slice());
    }

    fn finish(self) -> u64 {
        self.0
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
            virgin: vec![0; MAP_SIZE],
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
            virgin: vec![0; MAP_SIZE],
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
