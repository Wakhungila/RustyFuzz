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
use crate::engine::concolic::{ConcolicSolver, ConcolicHint};
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
    pub base_snapshot_id: u64, // The ID of the snapshot this input was derived from
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

            // Enable multi-transaction symbolic path discovery by attempting to solve constraints 
            // from any point in the transaction sequence.
            let tx_idx = rand.below(input.txs.len() as u64) as usize;
            if let Some(tx_waypoints) = input.waypoints.get(tx_idx) {
                // Priority: Solve for 'BranchPath' first to explore new control flow
                let mut candidates: Vec<_> = tx_waypoints
                    .iter()
                    .filter(|w| matches!(w, Waypoint::BranchPath { .. } | Waypoint::Comparison { taint_source: Some(_), .. }))
                    .collect();

                if !candidates.is_empty() {
                    // Higher selection energy for BranchPath waypoints
                    let waypoint = candidates[rand.below(candidates.len() as u64) as usize];
                    if let Some(hint) = solver.solve_hint(waypoint) {
                        if let Some(ts) = match waypoint {
                            Waypoint::Comparison { taint_source: Some(ts), .. } => Some(ts),
                            Waypoint::Arithmetic { taint_source: Some(ts), .. } => Some(ts),
                            _ => None,
                        } {
                            // Apply the hint to the original transaction in the sequence
                            let (target_tx_idx, offset) = match ts {
                                TaintSource::Calldata(o) => (tx_idx, *o),
                                TaintSource::Storage(orig_tx_idx, o) => (*orig_tx_idx, *o),
                            };

                            let tx = &mut input.txs[target_tx_idx];
                            if tx.input.len() >= offset + 32 {
                                tx.input[offset..offset + 32].copy_from_slice(&hint);
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
                    to: Address::random(), // New transactions should target random addresses
                    value: U256::ZERO,
                    is_victim: false,
                };
                input.txs.push(new_tx);
                return Ok(MutationResult::Mutated);
            }
            6..=15 => {
                // Semantic Chaining: Follow the protocol graph to chain logical steps
                if let Some(last_tx) = input.txs.last() {
                    let registry = self.account_registry.read();
                    let downstream = registry.get_downstream_targets(&last_tx.to);
                    if !downstream.is_empty() {
                        let target = downstream[rand.below(downstream.len() as u64) as usize];
                        let mut selector = [0u8; 4];
                        // Pick a selector known for this contract or a global common one
                        if let Some(s) = self.abi_registry.functions.keys().nth(rand.below(self.abi_registry.functions.len() as u64) as usize) {
                            selector = *s;
                        }
                        
                        let new_tx = SingletonTx {
                            input: selector.to_vec(),
                            caller: last_tx.caller,
                            to: target,
                            value: U256::ZERO,
                            is_victim: false,
                        };
                        input.txs.push(new_tx);
                        return Ok(MutationResult::Mutated);
                    }
                }
                Ok(MutationResult::Skipped)
            }
            6..=10 => {
                // Semantic Chaining: Use the protocol graph to find a logical next step.
                // If TX1 is a Deposit into a Vault, TX2 should target the Vault or its Underlying.
                if let Some(last_tx) = input.txs.last() {
                    let registry = self.account_registry.read();
                    let downstream = registry.get_downstream_targets(&last_tx.to);
                    
                    if !downstream.is_empty() {
                        let target = downstream[rand.below(downstream.len() as u64) as usize];
                        let new_tx = SingletonTx {
                            input: vec![0, 0, 0, 0], // Mutator will fill this in next round
                            caller: last_tx.caller,
                            to: target,
                            value: U256::ZERO,
                        };
                        input.txs.push(new_tx);
                        return Ok(MutationResult::Mutated);
                    }
                }
                Ok(MutationResult::Skipped)
            }
            11..=15 => {
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
                    let tuple_type = self.type_cache.read().get(&selector).cloned().or_else(|| {
                        self.abi_registry.functions.get(&selector).map(|types| {
                            let t = DynSolType::Tuple(types.clone());
                            self.type_cache.write().insert(selector, t.clone());
                            t
                        })
                    });

                    if let Some(tuple_type) = tuple_type {
                        let calldata = &tx.input[4..];
                        
                        // 2. Attempt to retrieve decoded value from LRU cache
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
            71..=85 => {
                // native flashloan injection: wrap existing sequence in an EIP-3156 loop
                if !input.txs.is_empty() {
                    let registry = self.account_registry.read();
                    // Heuristic: pick a contract that has been seen responding to flashLoan calls
                    // or just a random discovered contract to probe for lender interfaces.
                    if let Some(lender) = registry.random_contract(rand) {
                        let token = Address::random(); // In production, pick a known liquid token (WETH/USDC)
                        let amount = U256::from(10u128.pow(21)); // 1000 ETH-scale loan
                        
                        // Encode the sequence into the 'data' parameter for the callback
                        let sequence_data = bincode::serialize(&input.txs).unwrap_or_default();
                        
                        // EIP-3156 flashLoan selector: 0x5c19e951
                        let mut call_data = vec![0x5c, 0x19, 0xe9, 0x51];
                        // receiver = fuzzer_address (mocked as zeros here, usually a specific attack contract)
                        call_data.extend_from_slice(&[0u8; 12]);
                        call_data.extend_from_slice(&[0u8; 20]); 
                        // token
                        call_data.extend_from_slice(&[0u8; 12]);
                        call_data.extend_from_slice(token.as_slice());
                        // amount
                        call_data.extend_from_slice(&amount.to_be_bytes::<32>());
                        // data offset and length
                        call_data.extend_from_slice(&U256::from(128).to_be_bytes::<32>());
                        call_data.extend_from_slice(&U256::from(sequence_data.len()).to_be_bytes::<32>());
                        call_data.extend(sequence_data);

                        input.txs = vec![SingletonTx {
                            input: call_data,
                            caller: Address::random(),
                            to: lender,
                            value: U256::ZERO,
                            is_victim: false,
                        }];
                        return Ok(MutationResult::Mutated);
                    }
                }
                Ok(MutationResult::Skipped)
            }
            86..=93 => {
                // Oracle Pressure: Prepend a massive swap to the sequence
                // This pressures oracles by moving spot prices before an invariant check.
                let registry = self.account_registry.read();
                if let Some(dex_pool) = registry.random_contract(rand) {
                    // Uniswap V2 swap selector: 0x022c0d9f
                    let mut swap_data = vec![0x02, 0x2c, 0x0d, 0x9f];
                    // amount0Out, amount1Out, to, data
                    swap_data.extend_from_slice(&U256::from(10u128.pow(24)).to_be_bytes::<32>()); // 1M tokens
                    swap_data.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
                    swap_data.extend_from_slice(&[0u8; 12]);
                    swap_data.extend_from_slice(Address::random().as_slice());
                    swap_data.extend_from_slice(&U256::from(128).to_be_bytes::<32>());
                    swap_data.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());

                    let pressure_tx = SingletonTx {
                        input: swap_data,
                        caller: Address::random(),
                        to: dex_pool,
                        value: U256::ZERO,
                        is_victim: false,
                    };
                    input.txs.insert(0, pressure_tx);
                    return Ok(MutationResult::Mutated);
                }
                Ok(MutationResult::Skipped)
            }
            94..=100 => {
                // MEV Sandwich Simulation: Interleave frontrun/backrun around a victim
                if !input.txs.is_empty() {
                    let idx = rand.below(input.txs.len() as u64) as usize;
                    // Tag current TX as victim (likely a trade from mainnet seeds)
                    input.txs[idx].is_victim = true;
                    
                    let victim_to = input.txs[idx].to;
                    let attacker = Address::random();

                    // 1. Frontrun Swap (move price against victim)
                    let frontrun = SingletonTx {
                        input: vec![0x02, 0x2c, 0x0d, 0x9f, 1, 2, 3], // Simplified swap
                        caller: attacker,
                        to: victim_to,
                        value: U256::ZERO,
                        is_victim: false,
                    };

                    // 2. Backrun Swap (arbitrage the slippage)
                    let backrun = SingletonTx {
                        input: vec![0x02, 0x2c, 0x0d, 0x9f, 3, 2, 1], // Reverse swap
                        caller: attacker,
                        to: victim_to,
                        value: U256::ZERO,
                        is_victim: false,
                    };

                    input.txs.insert(idx, frontrun);
                    input.txs.insert(idx + 2, backrun);
                    return Ok(MutationResult::Mutated);
                }
                Ok(MutationResult::Skipped)
            }
            _ => {
                // Boundary Value Mutation for ETH 'value'
                let choices = [U256::ZERO, U256::MAX, U256::from(10u128.pow(18))];
                let idx = rand.below(input.txs.len() as u64) as usize;
                input.txs[idx].value = choices[rand.below(choices.len() as u64) as usize];
                Ok(MutationResult::Mutated)
            }
        }
    }
}

impl EvmMutator {
    fn mutate_sol_value<R: Rand>(&self, value: &mut DynSolValue, rand: &mut R) {
        match value {
            DynSolValue::Array(ref mut elements, ty) => {
                if elements.is_empty() {
                    // Grow the array by generating a default value for the inner type
                    elements.push(self.generate_default_sol_value(ty, rand));
                } else {
                    let choice = rand.below(100);
                    if choice < 70 { // Mutate an existing element
                        let idx = rand.below(elements.len() as u64) as usize;
                        self.mutate_sol_value(&mut elements[idx], rand);
                    } else if choice < 85 && elements.len() > 1 { // Remove an element
                        let idx = rand.below(elements.len() as u64) as usize;
                        elements.remove(idx);
                    } else { 
                        // Add another element of the same type
                        elements.push(self.generate_default_sol_value(ty, rand));
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

    /// Generates a sensible default value for a given Solidity type to aid in sequence growth.
    fn generate_default_sol_value<R: Rand>(&self, ty: &DynSolType, rand: &mut R) -> DynSolValue {
        match ty {
            DynSolType::Uint(size) => DynSolValue::Uint(U256::ZERO, *size),
            DynSolType::Int(size) => DynSolValue::Int(alloy_dyn_abi::I256::ZERO, *size),
            DynSolType::Address => DynSolValue::Address(Address::ZERO),
            DynSolType::Bool => DynSolValue::Bool(false),
            DynSolType::Bytes => DynSolValue::Bytes(vec![0u8; 32]),
            DynSolType::String => DynSolValue::String(String::from("RustyFuzz")),
            DynSolType::Tuple(inner_types) => {
                let vals = inner_types.iter().map(|t| self.generate_default_sol_value(t, rand)).collect();
                DynSolValue::Tuple(vals)
            }
            _ => DynSolValue::Uint(U256::ZERO, 256),
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