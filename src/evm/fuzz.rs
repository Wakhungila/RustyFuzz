use crate::common::types::{SingletonTx, Waypoint};
use crate::engine::concolic::ConcolicSolver;
use crate::evm::registry::GlobalAccountRegistry;
use alloy_dyn_abi::{DynSolType, DynSolValue};
use hashlink::LruCache;
use libafl::{
    corpus::CorpusId,
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::{rands::Rand, HasLen, Named};
use parking_lot::RwLock;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use std::{collections::HashMap, sync::Arc};

/// Maximum number of entries allowed in the decode cache before eviction is triggered.
const MAX_DECODE_CACHE_SIZE: usize = 10000;

/// Registry of known function selectors and their input types.
#[derive(Default, Clone, Debug)]
pub struct AbiRegistry {
    pub functions: HashMap<[u8; 4], Vec<DynSolType>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct MutationProvenance {
    pub strategy: String,
    pub tx_index: Option<usize>,
    pub selector: Option<[u8; 4]>,
    pub detail: String,
}

/// Represents a structured EVM execution step.
/// This is the "Input" that LibAFL evolves.
#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct EvmInput {
    pub txs: Vec<SingletonTx>, // Change to a sequence for multi-step exploits
    pub base_snapshot_id: u64, // The ID of the snapshot this input was derived from
    pub waypoints: Vec<Vec<Waypoint>>, // execution feedback per transaction
    #[serde(default)]
    pub mutation_provenance: Vec<MutationProvenance>,
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
    fn mutate(&mut self, state: &mut S, input: &mut EvmInput) -> Result<MutationResult, Error> {
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

    fn concolic_mutation<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        if input.waypoints.is_empty() {
            return MutationResult::Skipped;
        }

        let solver = ConcolicSolver::new();
        let hints = solver.solve_hints(
            input
                .waypoints
                .iter()
                .enumerate()
                .flat_map(|(tx_idx, waypoints)| waypoints.iter().map(move |w| (tx_idx, w))),
        );
        let applicable: Vec<_> = hints
            .iter()
            .filter(|hint| {
                input
                    .txs
                    .get(hint.tx_index)
                    .is_some_and(|tx| tx.input.len() >= hint.calldata_offset.saturating_add(32))
            })
            .collect();

        let Some(hint) = self.pick_random(rand, &applicable) else {
            return MutationResult::Skipped;
        };

        if let Some(tx) = input.txs.get_mut(hint.tx_index) {
            let end = hint.calldata_offset + 32;
            tx.input[hint.calldata_offset..end].copy_from_slice(&hint.word);
            let selector = selector_for_calldata(&tx.input);
            let detail = format!(
                "solved {:?} at pc {} into calldata[{}..{}]",
                hint.strategy, hint.pc, hint.calldata_offset, end
            );
            self.record_mutation(
                input,
                "concolic_comparison",
                Some(hint.tx_index),
                selector,
                &detail,
            );
            return MutationResult::Mutated;
        }

        MutationResult::Skipped
    }

    fn structural_mutation<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        let selector = self.random_selector(rand);
        let types = match self.abi_registry.functions.get(&selector) {
            Some(types) => types,
            None => return MutationResult::Skipped,
        };
        let target = input
            .txs
            .last()
            .map(|tx| tx.to)
            .or_else(|| self.account_registry.read().random_contract(rand))
            .unwrap_or_else(|| Address::new([0x14; 20]));
        let caller = input
            .txs
            .last()
            .map(|tx| tx.caller)
            .unwrap_or_else(|| Address::new([0x13; 20]));
        let insert_at = if input.txs.is_empty() {
            0
        } else {
            rand.below(NonZero::new(input.txs.len() + 1).unwrap())
        };
        let new_tx = SingletonTx {
            input: self.encode_default_call(selector, types),
            caller,
            to: target,
            value: self.default_call_value(types, rand),
            is_victim: false,
        };
        input.txs.insert(insert_at, new_tx);
        self.record_mutation(
            input,
            "abi_sequence_insert",
            Some(insert_at),
            Some(selector),
            "inserted ABI-valid transaction",
        );
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
        let types = match self.abi_registry.functions.get(&selector) {
            Some(types) => types,
            None => return MutationResult::Skipped,
        };

        let new_tx = SingletonTx {
            input: self.encode_default_call(selector, types),
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        };
        input.txs.push(new_tx);
        self.record_mutation(
            input,
            "abi_semantic_chain",
            input.txs.len().checked_sub(1),
            Some(selector),
            "appended ABI-valid call to downstream target",
        );
        MutationResult::Mutated
    }

    fn caller_mutation<R: Rand>(&self, rand: &mut R, input: &mut EvmInput) -> MutationResult {
        if let Some(idx) = self.random_index(rand, input.txs.len()) {
            input.txs[idx].caller = Address::new([0x15; 20]);
            self.record_mutation(input, "caller", Some(idx), None, "changed caller role");
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
                drop(registry);
                self.record_mutation(input, "target_discovery", Some(idx), None, "changed target");
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

        if input.txs[idx].input.len() < 4 {
            return self.retarget_tx_to_known_abi(rand, input, idx);
        }

        let mut selector = [0u8; 4];
        selector.copy_from_slice(&input.txs[idx].input[0..4]);

        if !self.abi_registry.functions.contains_key(&selector)
            && rand.below(NonZero::new(100).unwrap()) < 70
        {
            return self.retarget_tx_to_known_abi(rand, input, idx);
        }

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

        let calldata = &input.txs[idx].input[4..];
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
            input.txs[idx].input = new_input;
            self.record_mutation(
                input,
                "abi_argument",
                Some(idx),
                Some(selector),
                "decoded, mutated, and re-encoded ABI arguments",
            );
            MutationResult::Mutated
        } else {
            self.retarget_tx_to_known_abi(rand, input, idx)
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
        let sequence_data = bincode::serde::encode_to_vec(&input.txs, bincode::config::standard())
            .unwrap_or_else(|_| vec![]);

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
        self.record_mutation(
            input,
            "flashloan_wrap",
            Some(0),
            Some([0x5c, 0x19, 0xe9, 0x51]),
            "wrapped sequence in EIP-3156-style flashloan call",
        );
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
        self.record_mutation(
            input,
            "oracle_pressure",
            Some(0),
            Some([0x02, 0x2c, 0x0d, 0x9f]),
            "prepended swap-like pressure transaction",
        );
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
        self.record_mutation(
            input,
            "mev_sandwich",
            Some(idx),
            Some([0x02, 0x2c, 0x0d, 0x9f]),
            "wrapped victim transaction with attacker frontrun/backrun",
        );
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
        self.record_mutation(input, "value_boundary", Some(idx), None, "changed tx value");
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
            let mut selectors: Vec<_> = self.abi_registry.functions.keys().copied().collect();
            selectors.sort_unstable();
            let idx = rand.below(NonZero::new(selectors.len()).unwrap());
            selectors[idx]
        }
    }

    fn retarget_tx_to_known_abi<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        idx: usize,
    ) -> MutationResult {
        let selector = self.random_selector(rand);
        let types = match self.abi_registry.functions.get(&selector) {
            Some(types) => types,
            None => return MutationResult::Skipped,
        };
        input.txs[idx].input = self.encode_default_call(selector, types);
        input.txs[idx].value = self.default_call_value(types, rand);
        self.record_mutation(
            input,
            "abi_retarget",
            Some(idx),
            Some(selector),
            "replaced calldata with ABI-valid registered function",
        );
        MutationResult::Mutated
    }

    fn encode_default_call(&self, selector: [u8; 4], types: &[DynSolType]) -> Vec<u8> {
        let values: Vec<_> = types
            .iter()
            .map(|ty| self.generate_default_sol_value(ty))
            .collect();
        let mut calldata = selector.to_vec();
        calldata.extend_from_slice(&DynSolValue::Tuple(values).abi_encode());
        calldata
    }

    fn default_call_value<R: Rand>(&self, types: &[DynSolType], rand: &mut R) -> U256 {
        if types.iter().any(|ty| matches!(ty, DynSolType::Uint(_)))
            && rand.below(NonZero::new(10).unwrap()) == 0
        {
            U256::from(10u128.pow(18))
        } else {
            U256::ZERO
        }
    }

    fn record_mutation(
        &self,
        input: &mut EvmInput,
        strategy: &str,
        tx_index: Option<usize>,
        selector: Option<[u8; 4]>,
        detail: &str,
    ) {
        input.mutation_provenance.push(MutationProvenance {
            strategy: strategy.to_string(),
            tx_index,
            selector,
            detail: detail.to_string(),
        });
        if input.mutation_provenance.len() > 64 {
            let excess = input.mutation_provenance.len() - 64;
            input.mutation_provenance.drain(0..excess);
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
                    if choice < 70 {
                        // Mutate an existing element
                        let idx = rand.below(NonZero::new(elements.len()).unwrap());
                        self.mutate_sol_value(&mut elements[idx], rand);
                    } else if choice < 85 && elements.len() > 1 {
                        // Remove an element
                        let idx = rand.below(NonZero::new(elements.len()).unwrap());
                        elements.remove(idx);
                    } else {
                        // Add another element of the same type
                        elements.push(
                            elements
                                .last()
                                .cloned()
                                .unwrap_or(DynSolValue::Uint(U256::ZERO, 256)),
                        );
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
    fn generate_default_sol_value(&self, ty: &DynSolType) -> DynSolValue {
        match ty {
            DynSolType::Uint(size) => DynSolValue::Uint(U256::ZERO, *size),
            DynSolType::Int(size) => DynSolValue::Int(alloy_primitives::I256::ZERO, *size),
            DynSolType::Address => DynSolValue::Address(Address::ZERO),
            DynSolType::Bool => DynSolValue::Bool(false),
            DynSolType::Bytes => DynSolValue::Bytes(vec![0u8; 32]),
            DynSolType::String => DynSolValue::String(String::from("RustyFuzz")),
            DynSolType::Tuple(inner_types) => {
                let vals = inner_types
                    .iter()
                    .map(|t| self.generate_default_sol_value(t))
                    .collect();
                DynSolValue::Tuple(vals)
            }
            _ => DynSolValue::Uint(U256::ZERO, 256),
        }
    }
}

fn selector_for_calldata(calldata: &[u8]) -> Option<[u8; 4]> {
    if calldata.len() < 4 {
        return None;
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    Some(selector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{ComparisonOperand, TaintSource};
    use libafl::mutators::MutationResult;
    use libafl_bolts::rands::RomuDuoJrRand;

    #[test]
    fn structural_mutation_inserts_abi_valid_transaction_with_provenance() {
        let selector = [0xa9, 0x05, 0x9c, 0xbb];
        let mut registry = AbiRegistry::default();
        registry
            .functions
            .insert(selector, vec![DynSolType::Address, DynSolType::Uint(256)]);
        let mut account_registry = GlobalAccountRegistry::default();
        let target = Address::repeat_byte(0x42);
        account_registry.contracts.insert(target);

        let mutator = EvmMutator::new(Arc::new(registry), Arc::new(RwLock::new(account_registry)));
        let mut input = EvmInput {
            txs: Vec::new(),
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let mut rand = RomuDuoJrRand::with_seed(7);

        assert_eq!(
            mutator.structural_mutation(&mut rand, &mut input),
            MutationResult::Mutated
        );
        assert_eq!(input.txs.len(), 1);
        assert_eq!(&input.txs[0].input[..4], selector.as_slice());
        assert_eq!(input.txs[0].input.len(), 68);
        assert_eq!(input.txs[0].to, target);
        assert_eq!(input.mutation_provenance.len(), 1);
        assert_eq!(input.mutation_provenance[0].strategy, "abi_sequence_insert");
    }

    #[test]
    fn abi_mutation_retargets_unknown_calldata_to_registered_function() {
        let selector = [0x70, 0xa0, 0x82, 0x31];
        let mut registry = AbiRegistry::default();
        registry
            .functions
            .insert(selector, vec![DynSolType::Address]);
        let mutator = EvmMutator::new(
            Arc::new(registry),
            Arc::new(RwLock::new(GlobalAccountRegistry::default())),
        );
        let mut input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x11),
                to: Address::repeat_byte(0x22),
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let mut rand = RomuDuoJrRand::with_seed(11);

        assert_eq!(
            mutator.abi_mutation(&mut rand, &mut input),
            MutationResult::Mutated
        );
        assert_eq!(&input.txs[0].input[..4], selector.as_slice());
        assert_eq!(input.txs[0].input.len(), 36);
        assert_eq!(input.mutation_provenance[0].strategy, "abi_retarget");
    }

    #[test]
    fn concolic_mutation_updates_originating_sequence_transaction() {
        let mutator = EvmMutator::new(
            Arc::new(AbiRegistry::default()),
            Arc::new(RwLock::new(GlobalAccountRegistry::default())),
        );
        let mut input = EvmInput {
            txs: vec![
                SingletonTx {
                    input: vec![0u8; 68],
                    caller: Address::repeat_byte(0x11),
                    to: Address::repeat_byte(0x22),
                    value: U256::ZERO,
                    is_victim: false,
                },
                SingletonTx {
                    input: vec![0u8; 68],
                    caller: Address::repeat_byte(0x33),
                    to: Address::repeat_byte(0x44),
                    value: U256::ZERO,
                    is_victim: false,
                },
            ],
            base_snapshot_id: 0,
            waypoints: vec![
                Vec::new(),
                vec![Waypoint::Comparison {
                    op: 0x14,
                    lhs: U256::from(1),
                    rhs: U256::from(0xfeed_u64),
                    pc: 123,
                    calldata_offset: None,
                    condition: false,
                    hit: false,
                    taint_source: Some(TaintSource::Storage(0, 36)),
                    tainted_operand: ComparisonOperand::Lhs,
                }],
            ],
            mutation_provenance: Vec::new(),
        };
        let mut rand = RomuDuoJrRand::with_seed(19);

        assert_eq!(
            mutator.concolic_mutation(&mut rand, &mut input),
            MutationResult::Mutated
        );
        assert_eq!(
            U256::from_be_slice(&input.txs[0].input[36..68]),
            U256::from(0xfeed_u64)
        );
        assert!(input.txs[1].input[36..68].iter().all(|byte| *byte == 0));
        assert_eq!(input.mutation_provenance[0].strategy, "concolic_comparison");
    }
}
