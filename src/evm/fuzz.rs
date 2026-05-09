use libafl::{
    prelude::*,
    inputs::Input,
    feedbacks::Feedback,
};
use libafl_bolts::{HasLen, Named, rands::Rand, Error};
use crate::common::types::{SingletonTx, Snapshot, Waypoint};
use revm::primitives::{U256, Address};
use alloy_dyn_abi::{DynSolValue, DynSolType};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, sync::Arc, collections::HashMap};
use crate::evm::registry::GlobalAccountRegistry;
use parking_lot::RwLock;
use crate::engine::concolic::ConcolicSolver;
use hashlink::LruCache;

/// Maximum number of entries allowed in the decode cache before eviction is triggered.
const MAX_DECODE_CACHE_SIZE: usize = 10000;

/// Registry of known function selectors and their input types.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct AbiRegistry {
    pub functions: HashMap<[u8; 4], Vec<DynSolType>>,
}

/// Represents a structured EVM execution step.
/// This is the "Input" that LibAFL evolves.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmInput {
    pub txs: Vec<SingletonTx>, // Change to a sequence for multi-step exploits
    pub base_snapshot_id: u64,
    pub waypoints: Vec<Vec<Waypoint>>, // execution feedback per transaction
}

impl Input for EvmInput {
    fn generate_name(&self, id: usize) -> String {
        format!("seq_{}_{}", self.base_snapshot_id, id)
    }
}

impl HasLen for EvmInput {
    fn len(&self) -> usize {
        self.txs.iter().map(|t| t.input.len()).sum()
    }
}

/// A top-tier mutator doesn't just flip bits; it understands the EVM state.
pub struct EvmMutator {
    pub abi_registry: Arc<AbiRegistry>,
    pub account_registry: Arc<RwLock<GlobalAccountRegistry>>,
    pub type_cache: RwLock<HashMap<[u8; 4], DynSolType>>,
    pub decode_cache: RwLock<LruCache<Vec<u8>, DynSolValue>>,
}

impl<S> Mutator<EvmInput, S> for EvmMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EvmInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, libafl::Error> {
        let rand = state.rand_mut();
        let mutation_type = rand.below(100);

        #[cfg(feature = "z3")]
        if mutation_type < 20 && !input.waypoints.is_empty() {
            // Constraint-Guided Mutation (Concolic Hints): Resolves branch constraints
            // collected during sequence execution to explore alternative state transitions.
            let cfg = z3::Config::new();
            let ctx = z3::Context::new(&cfg);
            let solver = ConcolicSolver::new(&ctx);

            // Enable multi-transaction discovery by attempting to solve constraints 
            // from any point in the transaction sequence.
            let tx_idx = rand.below(input.txs.len() as u64) as usize;
            if let Some(tx_waypoints) = input.waypoints.get(tx_idx) {
                let mut comparisons: Vec<_> = tx_waypoints
                    .iter()
                    .filter(|w| matches!(w, Waypoint::Comparison { calldata_offset: Some(_), .. }))
                    .collect();

                if !comparisons.is_empty() {
                    let waypoint = comparisons[rand.below(comparisons.len() as u64) as usize];
                    if let Some(hint) = solver.solve_hint(waypoint) {
                        if let Waypoint::Comparison { calldata_offset: Some(offset), .. } = waypoint {
                            let tx = &mut input.txs[tx_idx];
                            // Apply the solver-generated hint at the precise calldata offset.
                            // This enables deterministic bypassing of guards like access control.
                            if tx.input.len() >= offset + 32 {
                                tx.input[*offset..*offset + 32].copy_from_slice(&hint);
                                return Ok(MutationResult::Mutated);
                            }
                        }
                    }
                }
            }
        }

        match mutation_type {
            0..=5 => {
                // Structural Mutation: Add a new transaction to the sequence
                let new_tx = SingletonTx {
                    input: vec![0, 0, 0, 0], // Placeholder for a default/random selector
                    caller: Address::random(),
                    to: Address::ZERO,
                    value: U256::ZERO,
                };
                input.txs.push(new_tx);
                return Ok(MutationResult::Mutated);
            }
            0..=15 => {
                // Semantic Mutation: Change the caller to a privileged or malicious actor
                let idx = rand.below(input.txs.len() as u64) as usize;
                input.txs[idx].caller = Address::random();
            }
            16..=25 => {
                // Discovery Mutation: Call a randomly discovered contract from the state
                let idx = rand.below(input.txs.len() as u64) as usize;
                let registry = self.account_registry.read();
                if let Some(target) = registry.random_contract(rand) {
                    input.txs[idx].to = target;
                }
            }
            26..=70 => {
                // ABI-Aware Mutation: Lookup selector and mutate actual types
                let idx = rand.below(input.txs.len() as u64) as usize;
                let tx = &mut input.txs[idx];
                
                if tx.input.len() >= 4 {
                    let mut selector = [0u8; 4];
                    selector.copy_from_slice(&tx.input[0..4]);
                    
                    // 1. Retrieve or build the tuple type from the type cache
                    let tuple_type = {
                        let cache = self.type_cache.read();
                        cache.get(&selector).cloned()
                    }.or_else(|| {
                        self.abi_registry.functions.get(&selector).map(|types| {
                            let t = DynSolType::Tuple(types.clone());
                            self.type_cache.write().insert(selector, t.clone());
                            t
                        })
                    };

                    if let Some(tuple_type) = tuple_type {
                        let calldata = &tx.input[4..];
                        
                        // 2. Attempt to retrieve decoded value from LRU cache
                        // We use a write lock because LruCache::get updates the access order
                        let mut decoded = self.decode_cache.write().get(calldata).cloned();

                        if decoded.is_none() {
                            if let Ok(d) = tuple_type.decode(calldata) {
                                self.decode_cache.write().insert(calldata.to_vec(), d.clone());
                                decoded = Some(d);
                            }
                        }

                        if let Some(mut val) = decoded {
                            self.mutate_sol_value(&mut val, rand);
                            let mut new_input = selector.to_vec();
                            new_input.extend(val.encode());
                            tx.input = new_input;
                        }
                    }
                }
            }
            _ => {
                // Boundary Value Mutation for ETH 'value'
                let choices = [U256::ZERO, U256::MAX, U256::from(10u128.pow(18))];
                let idx = rand.below(input.txs.len() as u64) as usize;
                input.txs[idx].value = choices[rand.below(choices.len() as u64) as usize];
            }
        }
        Ok(MutationResult::Mutated)
    }
}

impl EvmMutator {
    fn mutate_sol_value<R: Rand>(&self, value: &mut DynSolValue, rand: &mut R) {
        match value {
            DynSolValue::Array(ref mut elements, _) => {
                if elements.is_empty() {
                    // Add a new element if array is empty
                    // Requires knowing the element type, which is part of DynSolType::Array
                    // For now, we'll skip adding if empty, or add a default if type is known.
                } else {
                    let choice = rand.below(100);
                    if choice < 70 { // Mutate an existing element
                        let idx = rand.below(elements.len() as u64) as usize;
                        self.mutate_sol_value(&mut elements[idx], rand);
                    } else if choice < 85 && elements.len() > 1 { // Remove an element
                        let idx = rand.below(elements.len() as u64) as usize;
                        elements.remove(idx);
                    } else { // Add a new element (requires a default value for the type)
                        // This is complex without knowing the element's DynSolType
                        // For a real fuzzer, you'd have a `DynSolType::default_value()` method
                    }
                }
            }
            DynSolValue::FixedArray(ref mut elements, _) => {
                if !elements.is_empty() {
                    let idx = rand.below(elements.len() as u64) as usize;
                    self.mutate_sol_value(&mut elements[idx], rand);
                }
            }
            DynSolValue::Tuple(ref mut vals) => {
                if !vals.is_empty() {
                    let idx = rand.below(vals.len() as u64) as usize;
                    self.mutate_sol_value(&mut vals[idx], rand);
                }
            }
            DynSolValue::Uint(ref mut val, _) => {
                // High-fidelity boundary constants for DeFi logic
                let choices = [
                    U256::MAX, 
                    U256::ZERO, 
                    U256::from(1), 
                    U256::from(10u128.pow(18)), // 1e18 (Standard WAD)
                    U256::from(10u128.pow(6)),  // 1e6 (Standard USDC)
                    val.wrapping_add(U256::from(1)),
                    val.wrapping_sub(U256::from(1)),
                ];
                *val = choices[rand.below(choices.len() as u64) as usize];
            }
            DynSolValue::Address(ref mut addr) => {
                *addr = Address::random();
            }
            DynSolValue::Bool(ref mut b) => {
                *b = !*b;
            }
            DynSolValue::Bytes(ref mut b) => {
                if !b.is_empty() {
                    let idx = rand.below(b.len() as u64) as usize;
                    b[idx] = rand.next() as u8;
                }
            }
            DynSolValue::String(ref mut s) => {
                if !s.is_empty() {
                    let idx = rand.below(s.len() as u64) as usize;
                    s.replace_range(idx..idx + 1, &((rand.next() as u8) as char).to_string());
                }
            }
            _ => {} // Extend for arrays, bools, etc.
        }
    }
}

/// Feedback mechanism to detect if a Snapshot found new coverage bits.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmCoverageFeedback;

impl Named for EvmCoverageFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EvmCoverageFeedback");
        &NAME
    }
}

impl<S> Feedback<S> for EvmCoverageFeedback
where
    S: State + HasCorpus,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        // ... implementation truncated for brevity ...
        _exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error> {
        Ok(true)
    }
}