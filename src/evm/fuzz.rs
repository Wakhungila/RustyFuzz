use libafl::{
    corpus::CorpusId,
    inputs::Input,
    mutators::{Mutator, MutationResult},
    state::HasRand,
    Error,
};
use libafl_bolts::{rands::Rand, HasLen, Named};
use std::num::NonZero;
use crate::common::types::{SingletonTx, Waypoint};
use revm::primitives::{Address, U256};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc}; 
use crate::evm::registry::GlobalAccountRegistry;
use parking_lot::RwLock;
#[cfg(feature = "z3")]
use crate::engine::concolic::ConcolicSolver;
use hashlink::LruCache;

/// Maximum number of entries allowed in the decode cache before eviction is triggered.
const MAX_DECODE_CACHE_SIZE: usize = 10000;

/// Registry of known function selectors and their input types.
#[derive(Default, Clone, Debug)]
pub struct AbiRegistry {
    pub functions: HashMap<[u8; 4], Vec<DynSolType>>,
}

/// Represents a structured EVM execution step.
/// This is the "Input" that LibAFL evolves.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct EvmInput {
    pub txs: Vec<SingletonTx>, // Change to a sequence for multi-step exploits
    pub base_snapshot_id: u64, // The ID of the snapshot this input was derived from
    pub waypoints: Vec<Vec<Waypoint>>, // execution feedback per transaction
}

impl Input for EvmInput {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        format!("seq_{}_len_{}", self.base_snapshot_id, self.txs.len())
    }
}

impl HasLen for EvmInput {
    fn len(&self) -> usize {
        self.txs.iter().map(|t| t.input.len()).sum()
    }
}

impl Named for EvmMutator {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("EvmMutator");
        &NAME
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
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        let bucket = rand.below(NonZero::new(100).unwrap());

        let result = match bucket {
            0..=14 => self.concolic_mutation(rand, input),
            15..=24 => self.structural_mutation(rand, input),
            25..=39 => self.semantic_chaining(rand, input),
            40..=49 => self.caller_mutation(rand, input),
            50..=59 => self.discovery_mutation(rand, input),
            60..=84 => self.abi_mutation(rand, input),
            85..=92 => self.wrap_flashloan(rand, input),
            93..=96 => self.oracle_pressure(rand, input),
            97..=98 => self.mev_sandwich(rand, input),
            _ => self.value_boundary(rand, input),
        };

        Ok(result)
    }

    fn post_exec(&mut self, _state: &mut S, _corpus_idx: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl EvmMutator {
    pub fn new(
        abi_registry: Arc<AbiRegistry>,
        account_registry: Arc<RwLock<GlobalAccountRegistry>>,
    ) -> Self {
        Self {
            abi_registry,
            account_registry,
            type_cache: RwLock::new(HashMap::new()),
            decode_cache: RwLock::new(LruCache::new(MAX_DECODE_CACHE_SIZE)),
        }
    }

    #[cfg(feature = "z3")]
    fn concolic_mutation<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        if input.waypoints.is_empty() {
            return MutationResult::Skipped;
        }

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let solver = ConcolicSolver::new(&ctx);

        if let Some(tx_idx) = self.random_index(rand, input.txs.len()) {
            if let Some(tx_waypoints) = input.waypoints.get(tx_idx) {
                let candidates: Vec<_> = tx_waypoints
                    .iter()
                    .filter(|w| matches!(w, Waypoint::BranchPath { .. } | Waypoint::Comparison { taint_source: Some(_), .. }))
                    .collect();

                if let Some(waypoint) = self.pick_random(rand, &candidates) {
                    if let Some(hint) = solver.solve_hint(waypoint) {
                        if let Some(ts) = match waypoint {
                            Waypoint::Comparison { taint_source: Some(ts), .. } => Some(ts),
                            Waypoint::Arithmetic { taint_source: Some(ts), .. } => Some(ts),
                            _ => None,
                        } {
                            let (target_tx_idx, offset) = match ts {
                                TaintSource::Calldata(o) => (tx_idx, *o),
                                TaintSource::Storage(orig_tx_idx, o) => (*orig_tx_idx, *o),
                            };

                            if let Some(tx) = input.txs.get_mut(target_tx_idx) {
                                let end = offset + 32;
                                if tx.input.len() >= end {
                                    tx.input[offset..end].copy_from_slice(&hint);
                                    return MutationResult::Mutated;
                                }
                            }
                        }
                    }
                }
            }
        }

        MutationResult::Skipped
    }

    #[cfg(not(feature = "z3"))]
    fn concolic_mutation<R: Rand>(&self, _rand: &mut R, _input: &mut EvmInput) -> MutationResult {
        MutationResult::Skipped
    }

    fn structural_mutation<R: Rand>(&self, _rand: &mut R, input: &mut EvmInput) -> MutationResult {
        let new_tx = SingletonTx {
            input: vec![0, 0, 0, 0],
            caller: Address::new([0x13; 20]),
            to: Address::new([0x14; 20]),
            value: U256::ZERO,
            is_victim: false,
        };
        input.txs.push(new_tx);
        MutationResult::Mutated
    }

    fn semantic_chaining<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        let (caller, last_to) = match input.txs.last() {
            Some(tx) => (tx.caller, tx.to),
            None => return MutationResult::Skipped,
        };

        let registry = self.account_registry.read();
        let downstream = registry.get_downstream_targets(&last_to);
        if downstream.is_empty() {
            return MutationResult::Skipped;
        }

        let target_idx = rand.below(NonZero::new(downstream.len()).unwrap());
        let target = downstream[target_idx];
        let selector = self.random_selector(rand);

        let new_tx = SingletonTx {
            input: selector.to_vec(),
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        };
        input.txs.push(new_tx);
        MutationResult::Mutated
    }

    fn caller_mutation<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        if let Some(idx) = self.random_index(rand, input.txs.len()) {
            input.txs[idx].caller = Address::new([0x15; 20]);
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        }
    }

    fn discovery_mutation<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        if let Some(idx) = self.random_index(rand, input.txs.len()) {
            let registry = self.account_registry.read();
            if let Some(target) = registry.random_contract(rand) {
                input.txs[idx].to = target;
                MutationResult::Mutated
            } else {
                MutationResult::Skipped
            }
        } else {
            MutationResult::Skipped
        }
    }

    fn abi_mutation<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        let idx = match self.random_index(rand, input.txs.len()) {
            Some(i) => i,
            None => return MutationResult::Skipped,
        };

        let tx = &mut input.txs[idx];
        if tx.input.len() < 4 {
            return MutationResult::Skipped;
        }

        let mut selector = [0u8; 4];
        selector.copy_from_slice(&tx.input[0..4]);

        let tuple_type = self.type_cache.read().get(&selector).cloned().or_else(|| {
            self.abi_registry.functions.get(&selector).map(|types| {
                let t = DynSolType::Tuple(types.clone());
                self.type_cache.write().insert(selector, t.clone());
                t
            })
        });

        let tuple_type = match tuple_type {
            Some(t) => t,
            None => return MutationResult::Skipped,
        };

        let calldata = &tx.input[4..];
        let mut cache = self.decode_cache.write();
        let mut decoded = cache.get(calldata).cloned();
        if decoded.is_none() {
            if let Ok(value) = tuple_type.abi_decode(calldata) {
                cache.insert(calldata.to_vec(), value.clone());
                decoded = Some(value);
            }
        }
        drop(cache);

        if let Some(mut value) = decoded {
            self.mutate_sol_value(&mut value, rand);
            let mut new_input = selector.to_vec();
            let encoded = value.abi_encode();
            new_input.extend_from_slice(&encoded);
            tx.input = new_input;
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        }
    }

    fn wrap_flashloan<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        if input.txs.is_empty() {
            return MutationResult::Skipped;
        }

        let registry = self.account_registry.read();
        let lender = match registry.random_contract(rand) {
            Some(l) => l,
            None => return MutationResult::Skipped,
        };

        let token = Address::new([0x17; 20]);
        let amount = U256::from(10u128.pow(21));
        let sequence_data = bincode::serde::encode_to_vec(&input.txs, bincode::config::standard()).unwrap_or_else(|_| vec![]);

        let mut call_data = vec![0x5c, 0x19, 0xe9, 0x51];
        call_data.extend_from_slice(&[0u8; 12]);
        call_data.extend_from_slice(&[0u8; 20]);
        call_data.extend_from_slice(&[0u8; 12]);
        call_data.extend_from_slice(token.as_slice());
        call_data.extend_from_slice(&amount.to_be_bytes::<32>());
        call_data.extend_from_slice(&U256::from(128).to_be_bytes::<32>());
        call_data.extend_from_slice(&U256::from(sequence_data.len()).to_be_bytes::<32>());
        std::iter::Extend::extend(&mut call_data, sequence_data);

        input.txs = vec![SingletonTx {
            input: call_data,
            caller: Address::new([0x18; 20]),
            to: lender,
            value: U256::ZERO,
            is_victim: false,
        }];
        MutationResult::Mutated
    }

    fn oracle_pressure<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        let registry = self.account_registry.read();
        let dex_pool = match registry.random_contract(rand) {
            Some(p) => p,
            None => return MutationResult::Skipped,
        };

        let mut swap_data = vec![0x02, 0x2c, 0x0d, 0x9f];
        swap_data.extend_from_slice(&U256::from(10u128.pow(24)).to_be_bytes::<32>());
        swap_data.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
        swap_data.extend_from_slice(&[0u8; 12]);
        swap_data.extend_from_slice(Address::new([0x19; 20]).as_slice());
        swap_data.extend_from_slice(&U256::from(128).to_be_bytes::<32>());
        swap_data.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());

        let pressure_tx = SingletonTx {
            input: swap_data,
            caller: Address::new([0x18; 20]),
            to: dex_pool,
            value: U256::ZERO,
            is_victim: false,
        };
        input.txs.insert(0, pressure_tx);
        MutationResult::Mutated
    }

    fn mev_sandwich<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        let idx = match self.random_index(rand, input.txs.len()) {
            Some(i) => i,
            None => return MutationResult::Skipped,
        };

        input.txs[idx].is_victim = true;
        let victim_to = input.txs[idx].to;
        let attacker = Address::new([0x16; 20]);

        let frontrun = SingletonTx {
            input: vec![0x02, 0x2c, 0x0d, 0x9f, 1, 2, 3],
            caller: attacker,
            to: victim_to,
            value: U256::ZERO,
            is_victim: false,
        };

        let backrun = SingletonTx {
            input: vec![0x02, 0x2c, 0x0d, 0x9f, 3, 2, 1],
            caller: attacker,
            to: victim_to,
            value: U256::ZERO,
            is_victim: false,
        };

        input.txs.insert(idx, frontrun);
        input.txs.insert(idx + 2, backrun);
        MutationResult::Mutated
    }

    fn value_boundary<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        let idx = match self.random_index(rand, input.txs.len()) {
            Some(i) => i,
            None => return MutationResult::Skipped,
        };

        let choices = [U256::ZERO, U256::MAX, U256::from(10u128.pow(18))];
        let choice = rand.below(NonZero::new(choices.len()).unwrap());
        input.txs[idx].value = choices[choice];
        MutationResult::Mutated
    }

    fn random_index<R: Rand>(&self, rand: &mut R, len: usize) -> Option<usize> {
        if len == 0 {
            None
        } else {
            Some(rand.below(NonZero::new(len).unwrap()))
        }
    }

    fn pick_random<'a, R: Rand, T>(&self, rand: &mut R, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            Some(&items[rand.below(NonZero::new(items.len()).unwrap())])
        }
    }

    fn random_selector<R: Rand>(&self, rand: &mut R) -> [u8; 4] {
        if self.abi_registry.functions.is_empty() {
            [0u8; 4]
        } else {
            let idx = rand.below(NonZero::new(self.abi_registry.functions.len()).unwrap());
            *self.abi_registry
                .functions
                .keys()
                .nth(idx)
                .unwrap_or(&[0u8; 4])
        }
    }

    fn mutate_sol_value<R: Rand>(&self, value: &mut DynSolValue, rand: &mut R) {
        match value {
            DynSolValue::Array(elements) => {
                if elements.is_empty() {
                    // Without type info, default to zeroed uints
                    elements.push(DynSolValue::Uint(U256::ZERO, 256));
                } else {
                    let choice = rand.below(NonZero::new(100).unwrap());
                    if choice < 70 { // Mutate an existing element
                        let idx = rand.below(NonZero::new(elements.len()).unwrap());
                        self.mutate_sol_value(&mut elements[idx], rand);
                    } else if choice < 85 && elements.len() > 1 { // Remove an element
                        let idx = rand.below(NonZero::new(elements.len()).unwrap());
                        elements.remove(idx);
                    } else { 
                        // Add another element of the same type
                        elements.push(elements.last().cloned().unwrap_or(DynSolValue::Uint(U256::ZERO, 256)));
                    }
                }
            }
            DynSolValue::FixedArray(elements) => {
                if !elements.is_empty() {
                    let idx = rand.below(NonZero::new(elements.len()).unwrap());
                    self.mutate_sol_value(&mut elements[idx], rand);
                }
            }
            DynSolValue::Tuple(vals) => {
                if !vals.is_empty() {
                    let idx = rand.below(NonZero::new(vals.len()).unwrap());
                    self.mutate_sol_value(&mut vals[idx], rand);
                }
            }
            DynSolValue::Uint(val, _) => {
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
                *val = choices[rand.below(NonZero::new(choices.len()).unwrap())];
            }
            DynSolValue::Address(addr) => {
                *addr = Address::new([0x1a; 20]);
            }
            DynSolValue::Bool(b) => {
                *b = !*b;
            }
            DynSolValue::Bytes(b) => {
                if !b.is_empty() {
                    let idx = rand.below(NonZero::new(b.len()).unwrap());
                    b[idx] = rand.next() as u8;
                }
            }
            DynSolValue::String(s) => {
                if !s.is_empty() {
                    let idx = rand.below(NonZero::new(s.len()).unwrap());
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
            DynSolType::Int(size) => DynSolValue::Int(alloy_primitives::I256::ZERO, *size),
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