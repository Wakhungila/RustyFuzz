use crate::common::types::{SingletonTx, Waypoint};
use crate::engine::concolic::{
    ConcolicHint, ConcolicHintStats, ConcolicRepairTarget, ConcolicSolver,
};
use crate::engine::flashloan::{FlashLoanTemplate, EIP3156_FLASHLOAN_SELECTOR};
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
use parking_lot::{Mutex, RwLock};
use revm::primitives::{keccak256, Address, U256};
use rustyfuzz_core::InputId;
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use std::{collections::HashMap, sync::Arc};

/// Maximum number of entries allowed in the decode cache before eviction is triggered.
const MAX_DECODE_CACHE_SIZE: usize = 10000;

/// Maximum number of transactions allowed in a sequence to prevent unbounded growth.
const MAX_SEQUENCE_LENGTH: usize = 100;

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

/// Represents a structured EVM execution sequence.
///
/// This is the primary input type that LibAFL evolves during fuzzing. An `EvmInput`
/// contains only execution-defining semantic data. Execution feedback and mutation
/// provenance live in `EvmTestcaseMetadata`.
#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct EvmInput {
    /// Sequence of transactions to execute (multi-step exploits)
    pub txs: Vec<SingletonTx>,
    /// The ID of the snapshot this input was derived from
    pub base_snapshot_id: u64,
}

/// EVM-specific testcase feedback and mutation metadata.
///
/// This is intentionally outside `EvmInput` so feedback changes cannot alter the
/// semantic identity of an executable testcase.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct EvmTestcaseMetadata {
    /// Execution feedback (waypoints) per transaction
    #[serde(default)]
    pub waypoints: Vec<Vec<Waypoint>>,
    /// History of mutations applied to this input
    #[serde(default)]
    pub mutation_provenance: Vec<MutationProvenance>,
}

/// Stage 2B compatibility reader for pre-separation input JSON.
#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct LegacyEvmInputV1 {
    pub txs: Vec<SingletonTx>,
    pub base_snapshot_id: u64,
    #[serde(default)]
    pub waypoints: Vec<Vec<Waypoint>>,
    #[serde(default)]
    pub mutation_provenance: Vec<MutationProvenance>,
}

/// Temporary metadata bridge for the current monolithic LibAFL mutator/harness.
///
/// TODO(stage-4): move this state into LibAFL testcase/state metadata or an
/// explicit mutation context when campaign worker boundaries are split.
#[derive(Clone, Default)]
pub struct EvmTestcaseMetadataStore {
    inner: Arc<Mutex<HashMap<InputId, EvmTestcaseMetadata>>>,
}

impl Input for EvmInput {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        format!("seq_{}_len_{}", self.base_snapshot_id, self.txs.len())
    }
}

impl EvmInput {
    pub const INPUT_ID_SCHEMA_VERSION: &'static str = "rustyfuzz-input-id-v1";

    /// Creates a semantic input from a transaction sequence and snapshot handle.
    pub fn new(txs: Vec<SingletonTx>, base_snapshot_id: u64) -> Self {
        Self {
            txs,
            base_snapshot_id,
        }
    }

    /// Validates that the input respects system limits
    pub fn validate(&self) -> bool {
        self.txs.len() <= MAX_SEQUENCE_LENGTH
    }

    /// Derives the canonical semantic input ID.
    ///
    /// The identity bytes include only the version string, base snapshot id,
    /// and executable transaction sequence (calldata, caller, target, value).
    /// Feedback, provenance, role markers (`is_victim`), coverage, scheduler
    /// scores, oracle output, and execution statistics are excluded: REVM's
    /// `TxEnv` is built from `caller`, `value`, `data`, and `to` only.
    pub fn semantic_input_id(&self) -> InputId {
        let hash = keccak256(self.canonical_identity_bytes());
        InputId::new(format!("0x{}", hex::encode(hash))).expect("keccak input id is non-empty")
    }

    pub fn semantic_input_hash(&self) -> String {
        self.semantic_input_id().into_inner()
    }

    fn canonical_identity_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        append_len_prefixed(&mut out, Self::INPUT_ID_SCHEMA_VERSION.as_bytes());
        out.extend_from_slice(&self.base_snapshot_id.to_be_bytes());
        out.extend_from_slice(&(self.txs.len() as u64).to_be_bytes());
        for tx in &self.txs {
            append_len_prefixed(&mut out, &tx.input);
            out.extend_from_slice(tx.caller.as_slice());
            out.extend_from_slice(tx.to.as_slice());
            out.extend_from_slice(&tx.value.to_be_bytes::<32>());
        }
        out
    }

    /// Converts legacy v0.1/Stage 2A input JSON into semantic input plus metadata.
    pub fn split_legacy_json(bytes: &[u8]) -> serde_json::Result<(Self, EvmTestcaseMetadata)> {
        let legacy: LegacyEvmInputV1 = serde_json::from_slice(bytes)?;
        Ok(legacy.into_parts())
    }
}

impl LegacyEvmInputV1 {
    pub fn into_parts(self) -> (EvmInput, EvmTestcaseMetadata) {
        (
            EvmInput {
                txs: self.txs,
                base_snapshot_id: self.base_snapshot_id,
            },
            EvmTestcaseMetadata {
                waypoints: self.waypoints,
                mutation_provenance: self.mutation_provenance,
            },
        )
    }
}

impl EvmTestcaseMetadata {
    /// Merges `incoming` into `self` without duplicating identical records.
    ///
    /// Deterministic ordering: existing waypoints/provenance keep their
    /// positions; new unique items are appended in incoming order. Bounds are
    /// re-enforced by the caller via `apply_waypoint_backpressure` and by the
    /// same 64-entry provenance cap used for single writes.
    pub fn merge_from(&mut self, incoming: EvmTestcaseMetadata) {
        for (tx_idx, tx_waypoints) in incoming.waypoints.into_iter().enumerate() {
            if self.waypoints.len() <= tx_idx {
                self.waypoints.resize_with(tx_idx + 1, Vec::new);
            }
            let target = &mut self.waypoints[tx_idx];
            for waypoint in tx_waypoints {
                if !target.contains(&waypoint) {
                    target.push(waypoint);
                }
            }
        }

        for record in incoming.mutation_provenance {
            if !self.mutation_provenance.contains(&record) {
                self.mutation_provenance.push(record);
            }
        }
        if self.mutation_provenance.len() > 64 {
            let excess = self.mutation_provenance.len() - 64;
            self.mutation_provenance.drain(0..excess);
        }
    }

    /// Applies backpressure to waypoint accumulation by truncating if over limit
    pub fn apply_waypoint_backpressure(&mut self) {
        // Enforce per-transaction waypoint limit
        for tx_waypoints in &mut self.waypoints {
            if tx_waypoints.len() > crate::common::types::MAX_WAYPOINTS_PER_TX {
                let excess = tx_waypoints.len() - crate::common::types::MAX_WAYPOINTS_PER_TX;
                tx_waypoints.drain(0..excess);
            }
        }

        // Enforce total waypoint limit across all transactions
        let total_waypoints: usize = self.waypoints.iter().map(|w| w.len()).sum();
        if total_waypoints > crate::common::types::MAX_TOTAL_WAYPOINTS {
            // Remove waypoints from earlier transactions (keep recent ones)
            let mut to_remove = total_waypoints - crate::common::types::MAX_TOTAL_WAYPOINTS;
            for tx_waypoints in &mut self.waypoints {
                if to_remove == 0 {
                    break;
                }
                let remove_count = to_remove.min(tx_waypoints.len());
                tx_waypoints.drain(0..remove_count);
                to_remove -= remove_count;
            }
        }
    }

    pub fn record_mutation(
        &mut self,
        strategy: &str,
        tx_index: Option<usize>,
        selector: Option<[u8; 4]>,
        detail: &str,
    ) {
        self.mutation_provenance.push(MutationProvenance {
            strategy: strategy.to_string(),
            tx_index,
            selector,
            detail: detail.to_string(),
        });
        if self.mutation_provenance.len() > 64 {
            let excess = self.mutation_provenance.len() - 64;
            self.mutation_provenance.drain(0..excess);
        }
    }
}

/// Maximum entries retained by `EvmTestcaseMetadataStore` before eviction.
///
/// The store is a Stage 2B sidecar (see TODO(stage-4) on the struct); without a
/// bound it could grow with every mutated semantic input over a long campaign.
const MAX_METADATA_STORE_ENTRIES: usize = 65_536;

impl EvmTestcaseMetadataStore {
    /// Merges metadata into the store for the input's semantic identity.
    ///
    /// Deterministic same-id semantics:
    /// - identical `MutationProvenance` records are not duplicated;
    /// - new provenance records are appended after existing ones;
    /// - identical waypoints are not duplicated; new waypoints are appended
    ///   per transaction index, then waypoint backpressure is re-applied;
    /// - provenance is capped at 64 entries, dropping the oldest first
    ///   (same retention policy as provenance recorded inside one metadata);
    /// - when unrelated inputs evict this entry it is simply replaced.
    pub fn insert(&self, input: &EvmInput, mut metadata: EvmTestcaseMetadata) {
        let id = input.semantic_input_id();
        let mut map = self.inner.lock();
        if let Some(existing) = map.get_mut(&id) {
            existing.merge_from(metadata);
            existing.apply_waypoint_backpressure();
        } else {
            if map.len() >= MAX_METADATA_STORE_ENTRIES {
                // Drop an arbitrary stale entry (HashMap iteration order is fine
                // for eviction: every entry stays independently valid).
                if let Some(stale) = map.keys().next().cloned() {
                    map.remove(&stale);
                }
            }
            metadata.apply_waypoint_backpressure();
            map.insert(id, metadata);
        }
    }

    pub fn get(&self, input: &EvmInput) -> Option<EvmTestcaseMetadata> {
        self.inner.lock().get(&input.semantic_input_id()).cloned()
    }

    pub fn get_or_default(&self, input: &EvmInput) -> EvmTestcaseMetadata {
        self.get(input).unwrap_or_default()
    }

    /// Number of retained semantic entries; used by bounds tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
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

/// EVM-aware mutation engine for LibAFL.
///
/// The `EvmMutator` implements domain-specific mutation strategies that understand
/// EVM semantics, including ABI-aware mutations, concolic solving, economic pressure,
/// and MEV patterns like sandwich attacks.
pub struct EvmMutator {
    /// Registry of known function selectors and their input types
    pub abi_registry: Arc<AbiRegistry>,
    /// Registry of known contracts and their relationships
    pub account_registry: Arc<RwLock<GlobalAccountRegistry>>,
    /// Queue of concolic hints to apply during mutation
    pub concolic_hints: Arc<Mutex<Vec<ConcolicHint>>>,
    /// Statistics about concolic hint generation and application
    pub concolic_hint_stats: Arc<ConcolicHintStats>,
    /// Cache of ABI types for function selectors
    pub type_cache: RwLock<HashMap<[u8; 4], DynSolType>>,
    /// LRU cache for decoded calldata values
    pub decode_cache: RwLock<LruCache<Vec<u8>, DynSolValue>>,
    /// Temporary sidecar store for EVM testcase metadata.
    pub testcase_metadata: EvmTestcaseMetadataStore,
}

impl<S> Mutator<EvmInput, S> for EvmMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut EvmInput) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        let mut metadata = self.testcase_metadata.get_or_default(input);
        let has_concolic_hints = { !self.concolic_hints.lock().is_empty() };
        if has_concolic_hints
            && rand.below(NonZero::new(100).unwrap()) < 15
            && matches!(
                self.apply_queued_concolic_hint(input, &mut metadata),
                MutationResult::Mutated
            )
        {
            self.testcase_metadata.insert(input, metadata);
            return Ok(MutationResult::Mutated);
        }

        let bucket = rand.below(NonZero::new(100).unwrap());

        let result = match bucket {
            0..=6 => self.concolic_mutation(rand, input, &mut metadata),
            7..=14 => self.concolic_sequence_synthesis(rand, input, &mut metadata),
            15..=24 => self.structural_mutation(rand, input, &mut metadata),
            25..=39 => self.semantic_chaining(rand, input, &mut metadata),
            40..=49 => self.caller_mutation(rand, input, &mut metadata),
            50..=59 => self.discovery_mutation(rand, input, &mut metadata),
            60..=79 => self.abi_mutation(rand, input, &mut metadata),
            80..=88 => self.economic_objective_mutation(rand, input, &mut metadata),
            89..=94 => self.wrap_flashloan(rand, input, &mut metadata),
            95..=97 => self.oracle_pressure(rand, input, &mut metadata),
            98 => self.mev_sandwich(rand, input, &mut metadata),
            _ => self.value_boundary(rand, input, &mut metadata),
        };

        if matches!(result, MutationResult::Mutated) {
            self.testcase_metadata.insert(input, metadata);
        }
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
            concolic_hints: Arc::new(Mutex::new(Vec::new())),
            concolic_hint_stats: Arc::new(ConcolicHintStats::default()),
            type_cache: RwLock::new(HashMap::new()),
            decode_cache: RwLock::new(LruCache::new(MAX_DECODE_CACHE_SIZE)),
            testcase_metadata: EvmTestcaseMetadataStore::default(),
        }
    }

    /// Checks if adding `count` transactions would exceed the maximum sequence length
    fn can_add_transactions(&self, input: &EvmInput, count: usize) -> bool {
        input.txs.len() + count <= MAX_SEQUENCE_LENGTH
    }

    pub fn with_concolic_hints(
        abi_registry: Arc<AbiRegistry>,
        account_registry: Arc<RwLock<GlobalAccountRegistry>>,
        concolic_hints: Arc<Mutex<Vec<ConcolicHint>>>,
    ) -> Self {
        Self::with_concolic_hints_and_stats(
            abi_registry,
            account_registry,
            concolic_hints,
            Arc::new(ConcolicHintStats::default()),
            EvmTestcaseMetadataStore::default(),
        )
    }

    pub fn with_concolic_hints_and_stats(
        abi_registry: Arc<AbiRegistry>,
        account_registry: Arc<RwLock<GlobalAccountRegistry>>,
        concolic_hints: Arc<Mutex<Vec<ConcolicHint>>>,
        concolic_hint_stats: Arc<ConcolicHintStats>,
        testcase_metadata: EvmTestcaseMetadataStore,
    ) -> Self {
        Self {
            abi_registry,
            account_registry,
            concolic_hints,
            concolic_hint_stats,
            type_cache: RwLock::new(HashMap::new()),
            decode_cache: RwLock::new(LruCache::new(MAX_DECODE_CACHE_SIZE)),
            testcase_metadata,
        }
    }

    pub fn metadata_store(&self) -> EvmTestcaseMetadataStore {
        self.testcase_metadata.clone()
    }

    fn apply_queued_concolic_hint(
        &self,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        let Some(hint) = self.concolic_hints.lock().pop() else {
            return MutationResult::Skipped;
        };
        let Some(tx) = input.txs.get_mut(hint.tx_index) else {
            return MutationResult::Skipped;
        };
        let parameter_types = selector_for_calldata(&tx.input)
            .and_then(|selector| self.abi_registry.functions.get(&selector))
            .cloned();
        let placement = apply_concolic_hint(tx, &hint, parameter_types.as_deref());
        let selector = selector_for_calldata(&tx.input);
        self.record_mutation(
            metadata,
            "concolic_hint",
            Some(hint.tx_index),
            selector,
            &format!("applied queued hint from pc {} into {}", hint.pc, placement),
        );
        self.concolic_hint_stats.record_applied();
        MutationResult::Mutated
    }

    fn concolic_mutation<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        if metadata.waypoints.is_empty() {
            return MutationResult::Skipped;
        }

        let mut solver = ConcolicSolver::new();
        let hints = solver.solve_hints(
            metadata
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
                    .is_some_and(|_| match hint.repair_target {
                        ConcolicRepairTarget::CalldataWord => hint.calldata_offset <= 4096,
                        ConcolicRepairTarget::Caller | ConcolicRepairTarget::TxValue => true,
                    })
            })
            .collect();

        let Some(hint) = self.pick_random(rand, &applicable) else {
            return MutationResult::Skipped;
        };

        if let Some(tx) = input.txs.get_mut(hint.tx_index) {
            let parameter_types = selector_for_calldata(&tx.input)
                .and_then(|selector| self.abi_registry.functions.get(&selector))
                .cloned();
            let placement = apply_concolic_hint(tx, hint, parameter_types.as_deref());
            let selector = selector_for_calldata(&tx.input);
            let detail = format!(
                "solved {:?} at pc {} into {}",
                hint.strategy, hint.pc, placement
            );
            self.record_mutation(
                metadata,
                "concolic_comparison",
                Some(hint.tx_index),
                selector,
                &detail,
            );
            return MutationResult::Mutated;
        }

        MutationResult::Skipped
    }

    fn concolic_sequence_synthesis<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        if metadata.waypoints.is_empty() || input.txs.is_empty() {
            return MutationResult::Skipped;
        }

        // Enforce maximum sequence length
        if !self.can_add_transactions(input, 1) {
            return MutationResult::Skipped;
        }

        let mut solver = ConcolicSolver::new();
        let hints = solver.solve_hints(
            metadata
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
                    .is_some_and(|_| match hint.repair_target {
                        ConcolicRepairTarget::CalldataWord => hint.calldata_offset <= 4096,
                        ConcolicRepairTarget::Caller | ConcolicRepairTarget::TxValue => true,
                    })
            })
            .collect();
        let Some(hint) = self.pick_random(rand, &applicable) else {
            return MutationResult::Skipped;
        };
        let Some(template) = input.txs.get(hint.tx_index).cloned() else {
            return MutationResult::Skipped;
        };

        let parameter_types = selector_for_calldata(&template.input)
            .and_then(|selector| self.abi_registry.functions.get(&selector))
            .cloned();

        let mut synthesized = template;
        let placement = apply_concolic_hint(&mut synthesized, hint, parameter_types.as_deref());
        let selector = selector_for_calldata(&synthesized.input);
        let insert_at = (hint.tx_index + 1).min(input.txs.len());
        input.txs.insert(insert_at, synthesized);
        self.record_mutation(
            metadata,
            "concolic_sequence_synthesis",
            Some(insert_at),
            selector,
            &format!(
                "inserted solver-backed tx from pc {} with {:?} into {}",
                hint.pc, hint.strategy, placement
            ),
        );
        MutationResult::Mutated
    }

    fn structural_mutation<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        // Enforce maximum sequence length
        if !self.can_add_transactions(input, 1) {
            return MutationResult::Skipped;
        }

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
            metadata,
            "abi_sequence_insert",
            Some(insert_at),
            Some(selector),
            "inserted ABI-valid transaction",
        );
        MutationResult::Mutated
    }

    fn semantic_chaining<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        let (caller, last_to) = match input.txs.last() {
            Some(tx) => (tx.caller, tx.to),
            None => return MutationResult::Skipped,
        };

        // Enforce maximum sequence length
        if !self.can_add_transactions(input, 1) {
            return MutationResult::Skipped;
        }

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
            metadata,
            "abi_semantic_chain",
            input.txs.len().checked_sub(1),
            Some(selector),
            "appended ABI-valid call to downstream target",
        );
        MutationResult::Mutated
    }

    fn caller_mutation<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        if let Some(idx) = self.random_index(rand, input.txs.len()) {
            input.txs[idx].caller = Address::new([0x15; 20]);
            self.record_mutation(metadata, "caller", Some(idx), None, "changed caller role");
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        }
    }

    fn discovery_mutation<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        if let Some(idx) = self.random_index(rand, input.txs.len()) {
            let registry = self.account_registry.read();
            if let Some(target) = registry.random_contract(rand) {
                input.txs[idx].to = target;
                drop(registry);
                self.record_mutation(
                    metadata,
                    "target_discovery",
                    Some(idx),
                    None,
                    "changed target",
                );
                MutationResult::Mutated
            } else {
                MutationResult::Skipped
            }
        } else {
            MutationResult::Skipped
        }
    }

    fn abi_mutation<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        let idx = match self.random_index(rand, input.txs.len()) {
            Some(i) => i,
            None => return MutationResult::Skipped,
        };

        if input.txs[idx].input.len() < 4 {
            return self.retarget_tx_to_known_abi(rand, input, metadata, idx);
        }

        let mut selector = [0u8; 4];
        selector.copy_from_slice(&input.txs[idx].input[0..4]);

        if !self.abi_registry.functions.contains_key(&selector)
            && rand.below(NonZero::new(100).unwrap()) < 70
        {
            return self.retarget_tx_to_known_abi(rand, input, metadata, idx);
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
                metadata,
                "abi_argument",
                Some(idx),
                Some(selector),
                "decoded, mutated, and re-encoded ABI arguments",
            );
            MutationResult::Mutated
        } else {
            self.retarget_tx_to_known_abi(rand, input, metadata, idx)
        }
    }

    fn wrap_flashloan<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        if input.txs.is_empty() {
            return MutationResult::Skipped;
        }

        // Enforce maximum sequence length (flashloan wrap adds transactions)
        // Estimate: flashloan typically adds 2-3 transactions (borrow, execute, repay)
        if !self.can_add_transactions(input, 3) {
            return MutationResult::Skipped;
        }

        let registry = self.account_registry.read();
        let lender = match registry.random_contract(rand) {
            Some(l) => l,
            None => return MutationResult::Skipped,
        };

        let template = FlashLoanTemplate {
            lender,
            receiver: Address::new([0x18; 20]),
            token: Address::new([0x17; 20]),
            amount: U256::from(10u128.pow(21)),
        };
        *input = template.wrap_sequence(input.clone());
        self.record_mutation(
            metadata,
            "flashloan_template",
            Some(0),
            Some(EIP3156_FLASHLOAN_SELECTOR),
            "borrow->manipulate->exploit->repay wrapper with net-profit validation target",
        );

        // Validate the wrapped sequence doesn't exceed limit
        if input.txs.len() > MAX_SEQUENCE_LENGTH {
            return MutationResult::Skipped;
        }

        self.record_mutation(
            metadata,
            "flashloan_wrap",
            Some(0),
            Some(EIP3156_FLASHLOAN_SELECTOR),
            "wrapped sequence in EIP-3156-style flashloan call",
        );
        MutationResult::Mutated
    }

    fn economic_objective_mutation<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        if input.txs.is_empty() {
            return MutationResult::Skipped;
        }
        let idx = rand.below(NonZero::new(input.txs.len()).unwrap());
        let Some(tx) = input.txs.get_mut(idx) else {
            return MutationResult::Skipped;
        };
        let objective = metadata
            .mutation_provenance
            .iter()
            .rev()
            .find(|entry| entry.strategy.starts_with("goal_"))
            .map(|entry| entry.strategy.as_str())
            .unwrap_or("goal_MaximizeAttackerProfit");
        let amount = match objective {
            name if name.contains("IncreaseSharesPerAsset") => U256::from(10u128.pow(18)),
            name if name.contains("ReduceCollateralHealth") => U256::from(10u128.pow(22)),
            name if name.contains("CreateReserveProductAnomaly") => U256::from(10u128.pow(24)),
            name if name.contains("BypassRoleCheck") => {
                tx.caller = Address::new([0x44; 20]);
                U256::ONE
            }
            _ => U256::from(10u128.pow(21)),
        };
        if tx.input.len() < 36 {
            tx.input.resize(36, 0);
        }
        tx.input[4..36].copy_from_slice(&amount.to_be_bytes::<32>());
        self.record_mutation(
            metadata,
            "economic_objective",
            Some(idx),
            selector_for_calldata(&input.txs[idx].input),
            format!("optimized calldata amount/caller for {objective}").as_str(),
        );
        MutationResult::Mutated
    }

    fn oracle_pressure<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        // Enforce maximum sequence length
        if !self.can_add_transactions(input, 1) {
            return MutationResult::Skipped;
        }

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
            metadata,
            "oracle_pressure",
            Some(0),
            Some([0x02, 0x2c, 0x0d, 0x9f]),
            "prepended swap-like pressure transaction",
        );
        MutationResult::Mutated
    }

    fn mev_sandwich<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        // Enforce maximum sequence length (mev_sandwich adds 2 transactions)
        if !self.can_add_transactions(input, 2) {
            return MutationResult::Skipped;
        }

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
            metadata,
            "mev_sandwich",
            Some(idx),
            Some([0x02, 0x2c, 0x0d, 0x9f]),
            "wrapped victim transaction with attacker frontrun/backrun",
        );
        MutationResult::Mutated
    }

    fn value_boundary<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut EvmInput,
        metadata: &mut EvmTestcaseMetadata,
    ) -> MutationResult {
        let idx = match self.random_index(rand, input.txs.len()) {
            Some(i) => i,
            None => return MutationResult::Skipped,
        };

        let choices = [U256::ZERO, U256::MAX, U256::from(10u128.pow(18))];
        let choice = rand.below(NonZero::new(choices.len()).unwrap());
        input.txs[idx].value = choices[choice];
        self.record_mutation(
            metadata,
            "value_boundary",
            Some(idx),
            None,
            "changed tx value",
        );
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
        metadata: &mut EvmTestcaseMetadata,
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
            metadata,
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
        metadata: &mut EvmTestcaseMetadata,
        strategy: &str,
        tx_index: Option<usize>,
        selector: Option<[u8; 4]>,
        detail: &str,
    ) {
        metadata.record_mutation(strategy, tx_index, selector, detail);
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
            DynSolValue::String(s) if !s.is_empty() => {
                let idx = rand.below(NonZero::new(s.len()).unwrap());
                s.replace_range(idx..idx + 1, &((rand.next() as u8) as char).to_string());
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

fn apply_concolic_hint(
    tx: &mut SingletonTx,
    hint: &crate::engine::concolic::ConcolicHint,
    parameter_types: Option<&[DynSolType]>,
) -> String {
    match hint.repair_target {
        ConcolicRepairTarget::Caller => {
            tx.caller = Address::from_slice(&hint.word[12..]);
            return format!("msg.sender={:?}", tx.caller);
        }
        ConcolicRepairTarget::TxValue => {
            tx.value = U256::from_be_bytes(hint.word);
            return format!("msg.value={}", tx.value);
        }
        ConcolicRepairTarget::CalldataWord => {}
    }

    if let Some(types) = parameter_types {
        repair_dynamic_abi_layout(&mut tx.input, types);
    }

    let offset = hint.calldata_offset;
    let placement = abi_hint_offset(&tx.input, offset, parameter_types).unwrap_or(offset);
    let end = placement.saturating_add(32);
    if tx.input.len() < end {
        tx.input.resize(end, 0);
    }
    tx.input[placement..end].copy_from_slice(&hint.word);
    if placement == offset {
        format!("calldata[{placement}..{end}]")
    } else {
        format!("abi_word[{placement}..{end}] from source offset {offset}")
    }
}

fn abi_hint_offset(
    calldata: &[u8],
    offset: usize,
    parameter_types: Option<&[DynSolType]>,
) -> Option<usize> {
    if calldata.len() < 4 || offset < 4 {
        return None;
    }
    let word_offset = 4 + ((offset - 4) / 32) * 32;

    if let Some(types) = parameter_types {
        let arg_index = (word_offset - 4) / 32;
        if types
            .get(arg_index)
            .is_some_and(solidity_type_contains_dynamic_tail)
        {
            let placement = dynamic_tail_data_word(calldata, types, arg_index)
                .unwrap_or_else(|| 4 + types.len() * 32 + 32);
            if placement.saturating_add(32) <= 4096 {
                return Some(placement);
            }
        }
    }

    if word_offset.saturating_add(32) <= 4096 {
        Some(word_offset)
    } else {
        None
    }
}

fn repair_dynamic_abi_layout(calldata: &mut Vec<u8>, parameter_types: &[DynSolType]) {
    if parameter_types
        .iter()
        .all(|ty| !solidity_type_contains_dynamic_tail(ty))
    {
        return;
    }

    let head_size = 4 + parameter_types.len() * 32;
    if calldata.len() < head_size {
        calldata.resize(head_size, 0);
    }

    let mut tail_cursor = head_size;
    for (idx, ty) in parameter_types.iter().enumerate() {
        if !solidity_type_contains_dynamic_tail(ty) {
            continue;
        }

        let head_word = 4 + idx * 32;
        let encoded_offset = U256::from(tail_cursor.saturating_sub(4));
        calldata[head_word..head_word + 32].copy_from_slice(&encoded_offset.to_be_bytes::<32>());

        let minimum_tail_len = dynamic_tail_minimum_len(ty);
        let tail_end = tail_cursor.saturating_add(minimum_tail_len);
        if calldata.len() < tail_end {
            calldata.resize(tail_end, 0);
        }

        if minimum_tail_len >= 32 {
            let default_len = dynamic_tail_default_length(ty);
            calldata[tail_cursor..tail_cursor + 32]
                .copy_from_slice(&U256::from(default_len).to_be_bytes::<32>());
        }
        tail_cursor = align_abi_word(tail_end);
    }
}

fn dynamic_tail_data_word(
    calldata: &[u8],
    parameter_types: &[DynSolType],
    arg_index: usize,
) -> Option<usize> {
    if arg_index >= parameter_types.len() {
        return None;
    }
    let head_word = 4 + arg_index * 32;
    let encoded = calldata.get(head_word..head_word + 32)?;
    let relative = U256::from_be_slice(encoded);
    let relative: usize = relative.try_into().ok()?;
    Some(4 + relative + 32)
}

fn solidity_type_contains_dynamic_tail(ty: &DynSolType) -> bool {
    match ty {
        DynSolType::Bytes | DynSolType::String | DynSolType::Array(_) => true,
        DynSolType::Tuple(fields) => fields.iter().any(solidity_type_contains_dynamic_tail),
        _ => false,
    }
}

fn dynamic_tail_minimum_len(ty: &DynSolType) -> usize {
    match ty {
        DynSolType::Bytes | DynSolType::String => 64,
        DynSolType::Array(_) => 32,
        DynSolType::Tuple(fields) => 32 + fields.len() * 32,
        _ => 32,
    }
}

fn dynamic_tail_default_length(ty: &DynSolType) -> usize {
    match ty {
        DynSolType::Bytes | DynSolType::String => 32,
        DynSolType::Array(_) | DynSolType::Tuple(_) => 0,
        _ => 0,
    }
}

fn align_abi_word(value: usize) -> usize {
    value.next_multiple_of(32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{
        CallKind, CallPhase, ComparisonOperand, SymbolicExpression, TaintSource,
    };
    use crate::engine::concolic::{ConcolicHint, ConcolicStrategy};
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
        let mut input = EvmInput::new(Vec::new(), 0);
        let mut metadata = EvmTestcaseMetadata::default();
        let mut rand = RomuDuoJrRand::with_seed(7);

        assert_eq!(
            mutator.structural_mutation(&mut rand, &mut input, &mut metadata),
            MutationResult::Mutated
        );
        assert_eq!(input.txs.len(), 1);
        assert_eq!(&input.txs[0].input[..4], selector.as_slice());
        assert_eq!(input.txs[0].input.len(), 68);
        assert_eq!(input.txs[0].to, target);
        assert_eq!(metadata.mutation_provenance.len(), 1);
        assert_eq!(
            metadata.mutation_provenance[0].strategy,
            "abi_sequence_insert"
        );
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
        let mut input = EvmInput::new(
            vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x11),
                to: Address::repeat_byte(0x22),
                value: U256::ZERO,
                is_victim: false,
            }],
            0,
        );
        let mut metadata = EvmTestcaseMetadata::default();
        let mut rand = RomuDuoJrRand::with_seed(11);

        assert_eq!(
            mutator.abi_mutation(&mut rand, &mut input, &mut metadata),
            MutationResult::Mutated
        );
        assert_eq!(&input.txs[0].input[..4], selector.as_slice());
        assert_eq!(input.txs[0].input.len(), 36);
        assert_eq!(metadata.mutation_provenance[0].strategy, "abi_retarget");
    }

    #[test]
    fn concolic_mutation_updates_originating_sequence_transaction() {
        let mutator = EvmMutator::new(
            Arc::new(AbiRegistry::default()),
            Arc::new(RwLock::new(GlobalAccountRegistry::default())),
        );
        let mut input = EvmInput::new(
            vec![
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
            0,
        );
        let mut metadata = EvmTestcaseMetadata {
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
                    lhs_expression: Some(SymbolicExpression::Source(TaintSource::Storage(0, 36))),
                    rhs_expression: Some(SymbolicExpression::Constant(U256::from(0xfeed_u64))),
                    branch_distance: Some(U256::from(0xfeed_u64 - 1)),
                }],
            ],
            mutation_provenance: Vec::new(),
        };
        let mut rand = RomuDuoJrRand::with_seed(19);

        assert_eq!(
            mutator.concolic_mutation(&mut rand, &mut input, &mut metadata),
            MutationResult::Mutated
        );
        assert_eq!(
            U256::from_be_slice(&input.txs[0].input[36..68]),
            U256::from(0xfeed_u64)
        );
        assert!(input.txs[1].input[36..68].iter().all(|byte| *byte == 0));
        assert_eq!(
            metadata.mutation_provenance[0].strategy,
            "concolic_comparison"
        );
    }

    #[test]
    fn concolic_mutation_extends_short_originating_calldata() {
        let mutator = EvmMutator::new(
            Arc::new(AbiRegistry::default()),
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
        };
        let mut metadata = EvmTestcaseMetadata {
            waypoints: vec![vec![Waypoint::Comparison {
                op: 0x14,
                lhs: U256::ZERO,
                rhs: U256::from(99),
                pc: 321,
                calldata_offset: None,
                condition: false,
                hit: false,
                taint_source: Some(TaintSource::Calldata(36)),
                tainted_operand: ComparisonOperand::Lhs,
                lhs_expression: Some(SymbolicExpression::Source(TaintSource::Calldata(36))),
                rhs_expression: Some(SymbolicExpression::Constant(U256::from(99))),
                branch_distance: Some(U256::from(99)),
            }]],
            mutation_provenance: Vec::new(),
        };
        let mut rand = RomuDuoJrRand::with_seed(23);

        assert_eq!(
            mutator.concolic_mutation(&mut rand, &mut input, &mut metadata),
            MutationResult::Mutated
        );
        assert_eq!(input.txs[0].input.len(), 68);
        assert_eq!(
            U256::from_be_slice(&input.txs[0].input[36..68]),
            U256::from(99)
        );
    }

    #[test]
    fn concolic_hint_repairs_dynamic_abi_tail_before_writing_hint() {
        let selector = [0x12, 0x34, 0x56, 0x78];
        let mut tx = SingletonTx {
            input: selector.to_vec(),
            caller: Address::repeat_byte(0x11),
            to: Address::repeat_byte(0x22),
            value: U256::ZERO,
            is_victim: false,
        };
        let word = U256::from(0xfeed_u64).to_be_bytes::<32>();
        let hint = ConcolicHint {
            source: TaintSource::Calldata(4),
            tx_index: 0,
            calldata_offset: 4,
            word,
            pc: 1,
            strategy: ConcolicStrategy::FlipComparison {
                opcode: 0x14,
                target_true: true,
            },
            repair_target: ConcolicRepairTarget::CalldataWord,
        };

        let placement = apply_concolic_hint(&mut tx, &hint, Some(&[DynSolType::Bytes]));

        assert_eq!(placement, "abi_word[68..100] from source offset 4");
        assert_eq!(tx.input.len(), 100);
        assert_eq!(U256::from_be_slice(&tx.input[4..36]), U256::from(32));
        assert_eq!(U256::from_be_slice(&tx.input[36..68]), U256::from(32));
        assert_eq!(
            U256::from_be_slice(&tx.input[68..100]),
            U256::from(0xfeed_u64)
        );
    }

    #[test]
    fn concolic_hint_repairs_msg_value() {
        let mut tx = SingletonTx {
            input: vec![0xab, 0xcd, 0xef, 0x01],
            caller: Address::repeat_byte(0x11),
            to: Address::repeat_byte(0x22),
            value: U256::ZERO,
            is_victim: false,
        };
        let hint = ConcolicHint {
            source: TaintSource::CallValue,
            tx_index: 0,
            calldata_offset: 0,
            word: U256::from(1_000_000_u64).to_be_bytes::<32>(),
            pc: 1,
            strategy: ConcolicStrategy::FlipComparison {
                opcode: 0x10,
                target_true: false,
            },
            repair_target: ConcolicRepairTarget::TxValue,
        };

        let placement = apply_concolic_hint(&mut tx, &hint, None);
        assert_eq!(placement, "msg.value=1000000");
        assert_eq!(tx.value, U256::from(1_000_000_u64));
    }

    #[test]
    fn concolic_hint_repairs_msg_sender() {
        let mut tx = SingletonTx {
            input: vec![0xab, 0xcd, 0xef, 0x01],
            caller: Address::repeat_byte(0x11),
            to: Address::repeat_byte(0x22),
            value: U256::ZERO,
            is_victim: false,
        };
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(Address::repeat_byte(0x99).as_slice());
        let hint = ConcolicHint {
            source: TaintSource::Caller,
            tx_index: 0,
            calldata_offset: 0,
            word,
            pc: 1,
            strategy: ConcolicStrategy::FlipComparison {
                opcode: 0x14,
                target_true: true,
            },
            repair_target: ConcolicRepairTarget::Caller,
        };

        let placement = apply_concolic_hint(&mut tx, &hint, None);
        assert!(placement.contains("msg.sender="));
        assert_eq!(tx.caller, Address::repeat_byte(0x99));
    }

    fn golden_input() -> EvmInput {
        EvmInput::new(
            vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x11),
                to: Address::repeat_byte(0x22),
                value: U256::from(1_000u64),
                is_victim: false,
            }],
            42,
        )
    }

    #[test]
    fn waypoints_do_not_change_semantic_input_id() {
        let plain = golden_input();
        let with_waypoints = golden_input();
        let metadata = EvmTestcaseMetadata {
            waypoints: vec![vec![Waypoint::Comparison {
                op: 0x14,
                lhs: U256::ZERO,
                rhs: U256::ONE,
                pc: 10,
                calldata_offset: None,
                condition: false,
                hit: true,
                taint_source: None,
                tainted_operand: ComparisonOperand::Lhs,
                lhs_expression: None,
                rhs_expression: None,
                branch_distance: Some(U256::ONE),
            }]],
            mutation_provenance: Vec::new(),
        };
        assert_ne!(metadata.waypoints, EvmTestcaseMetadata::default().waypoints);
        // Semantic identity is a function of the input alone; feedback lives outside.
        assert_eq!(
            with_waypoints.semantic_input_id(),
            plain.semantic_input_id()
        );
    }

    #[test]
    fn provenance_entries_do_not_change_semantic_input_id() {
        // Same EvmInput, different EvmTestcaseMetadata only: the metadata store
        // may hold arbitrary provenance variants without affecting identity.
        let plain = golden_input();
        let annotated = golden_input();
        let metadata = EvmTestcaseMetadata {
            waypoints: Vec::new(),
            mutation_provenance: vec![
                MutationProvenance {
                    strategy: "caller".to_string(),
                    tx_index: Some(0),
                    selector: None,
                    detail: "changed caller role (provenance record only)".to_string(),
                },
                MutationProvenance {
                    strategy: "goal_max_attacker_profit".to_string(),
                    tx_index: None,
                    selector: None,
                    detail: "objective-driven bounded search".to_string(),
                },
            ],
        };
        assert!(metadata.mutation_provenance != EvmTestcaseMetadata::default().mutation_provenance);
        assert_eq!(plain, annotated);
        assert_eq!(plain.semantic_input_id(), annotated.semantic_input_id());
    }

    #[test]
    fn execution_defining_differences_change_semantic_input_id() {
        let base = golden_input();

        let mut calldata_changed = golden_input();
        calldata_changed.txs[0].input.push(0xff);
        assert_ne!(
            calldata_changed.semantic_input_id(),
            base.semantic_input_id()
        );

        let mut caller_changed = golden_input();
        caller_changed.txs[0].caller = Address::repeat_byte(0x33);
        assert_ne!(caller_changed.semantic_input_id(), base.semantic_input_id());

        let mut value_changed = golden_input();
        value_changed.txs[0].value = U256::ZERO;
        assert_ne!(value_changed.semantic_input_id(), base.semantic_input_id());

        let snapshot_changed = EvmInput::new(base.txs.clone(), 43);
        assert_ne!(
            snapshot_changed.semantic_input_id(),
            base.semantic_input_id()
        );
    }

    #[test]
    fn semantic_input_hash_is_deterministic_and_survives_legacy_round_trip() {
        let first = golden_input().semantic_input_hash();
        let second = golden_input().semantic_input_hash();
        assert_eq!(first, second);

        let serialized = serde_json::to_vec(&golden_input()).unwrap();
        let reparsed: LegacyEvmInputV1 = serde_json::from_slice(&serialized).unwrap();
        let (input, metadata) = reparsed.into_parts();
        assert_eq!(input, golden_input());
        assert_eq!(input.semantic_input_hash(), first);
        assert!(metadata.waypoints.is_empty());
        assert!(metadata.mutation_provenance.is_empty());
    }

    #[test]
    fn legacy_json_split_preserves_waypoints_and_provenance() {
        let clean = golden_input();
        let mut legacy_json = serde_json::to_value(&clean).unwrap();
        legacy_json["waypoints"] = serde_json::json!([[], []]);
        legacy_json["mutation_provenance"] = serde_json::json!([{
            "strategy": "goal_max_attacker_profit",
            "tx_index": null,
            "selector": null,
            "detail": "bounded search"
        }]);
        let bytes = serde_json::to_vec(&legacy_json).unwrap();

        let (input, metadata) = EvmInput::split_legacy_json(&bytes).unwrap();
        assert_eq!(input, clean);
        assert_eq!(metadata.waypoints.len(), 2);
        assert_eq!(metadata.mutation_provenance.len(), 1);
        assert_eq!(
            metadata.mutation_provenance[0].strategy,
            "goal_max_attacker_profit"
        );

        // The legacy file carries no semantic delta; it deduplicates against a
        // clean rewrite of the same execution-defining content.
        let round_trip =
            EvmInput::split_legacy_json(serde_json::to_vec(&input).unwrap().as_slice()).unwrap();
        assert_eq!(round_trip.0.semantic_input_id(), input.semantic_input_id());
    }

    #[test]
    fn semantic_input_hash_matches_pinned_golden_value() {
        assert_eq!(
            golden_input().semantic_input_hash(),
            "0xedbbb6647289e0df39694c6c9a8b810163991ca5cd0ed4c0b387a6c999af74ba"
        );
    }

    #[test]
    fn is_victim_role_marker_does_not_change_semantic_input_id() {
        let plain = golden_input();
        let mut victim_marked = golden_input();
        victim_marked.txs[0].is_victim = true;

        // `is_victim` is an analysis/role marker consumed by MEV/economic-delta
        // oracles and actor assignment. EvmExecutor builds REVM TxEnv from
        // caller/value/data/to only, so the victim flag cannot affect execution.
        assert_ne!(plain.txs, victim_marked.txs);
        assert_eq!(plain.semantic_input_id(), victim_marked.semantic_input_id());
    }

    #[test]
    fn metadata_store_merges_distinct_variants_for_one_semantic_input() {
        let mutator = EvmMutator::new(
            Arc::new(AbiRegistry::default()),
            Arc::new(RwLock::new(GlobalAccountRegistry::default())),
        );
        let input = golden_input();

        let record = |strategy: &str, detail: &str| MutationProvenance {
            strategy: strategy.to_string(),
            tx_index: None,
            selector: None,
            detail: detail.to_string(),
        };

        mutator.testcase_metadata.insert(
            &input,
            EvmTestcaseMetadata {
                waypoints: vec![vec![Waypoint::BranchPath {
                    pc: 7,
                    taken: true,
                    constraint: Box::new(Waypoint::CallTrace {
                        tx_idx: 0,
                        depth: 0,
                        caller: Address::ZERO,
                        target: Address::ZERO,
                        value: U256::ZERO,
                        input: Vec::new(),
                        output: Vec::new(),
                        gas_limit: 0,
                        gas_used: 0,
                        success: true,
                        kind: CallKind::Call,
                        phase: CallPhase::End,
                        result: Some("Success".to_string()),
                    }),
                }]],
                mutation_provenance: vec![record("caller", "first write")],
            },
        );

        // Same semantic InputId, different metadata variant (the exact review
        // scenario: InputId X -> A then InputId X -> B).
        mutator.testcase_metadata.insert(
            &input,
            EvmTestcaseMetadata {
                waypoints: vec![vec![Waypoint::BranchPath {
                    pc: 11,
                    taken: false,
                    constraint: Box::new(Waypoint::CallTrace {
                        tx_idx: 0,
                        depth: 0,
                        caller: Address::ZERO,
                        target: Address::ZERO,
                        value: U256::ZERO,
                        input: Vec::new(),
                        output: Vec::new(),
                        gas_limit: 0,
                        gas_used: 0,
                        success: true,
                        kind: CallKind::Call,
                        phase: CallPhase::End,
                        result: Some("Success".to_string()),
                    }),
                }]],
                mutation_provenance: vec![
                    record("caller", "first write"),
                    record("value_boundary", "second write"),
                ],
            },
        );

        let merged = mutator.testcase_metadata.get_or_default(&input);
        assert!(merged
            .waypoints
            .iter()
            .flatten()
            .any(|waypoint| matches!(waypoint, Waypoint::BranchPath { pc: 7, .. })));
        assert!(merged
            .waypoints
            .iter()
            .flatten()
            .any(|waypoint| matches!(waypoint, Waypoint::BranchPath { pc: 11, .. })));
        assert_eq!(
            merged.mutation_provenance,
            vec![
                record("caller", "first write"),
                record("value_boundary", "second write")
            ]
        );
    }

    #[test]
    fn metadata_store_respects_entry_bound_and_replace_eviction() {
        let store = EvmTestcaseMetadataStore::default();
        let inputs: Vec<EvmInput> = (0..MAX_METADATA_STORE_ENTRIES + 8)
            .map(|idx| EvmInput::new(golden_input().txs.clone(), idx as u64))
            .collect();
        for input in &inputs {
            store.insert(input, EvmTestcaseMetadata::default());
        }
        assert!(store.len() <= MAX_METADATA_STORE_ENTRIES);
        // Evicted entries return defaults; retained entries keep their metadata.
        assert_eq!(
            store.get_or_default(&inputs[0]),
            EvmTestcaseMetadata::default()
        );
        assert_eq!(
            store.get_or_default(inputs.last().unwrap()),
            EvmTestcaseMetadata::default()
        );
    }

    #[test]
    fn economic_objective_mutation_preserves_goal_guidance_from_metadata_store() {
        let mutator = EvmMutator::new(
            Arc::new(AbiRegistry::default()),
            Arc::new(RwLock::new(GlobalAccountRegistry::default())),
        );
        // Simulate a bounded-search seed whose goal tags live in the metadata store.
        let seeded = golden_input();
        mutator.testcase_metadata.insert(
            &seeded,
            EvmTestcaseMetadata {
                waypoints: Vec::new(),
                mutation_provenance: vec![MutationProvenance {
                    strategy: "goal_IncreaseSharesPerAsset".to_string(),
                    tx_index: None,
                    selector: None,
                    detail: "objective-driven bounded search".to_string(),
                }],
            },
        );

        // The mutator restores guidance through the store for this semantic input
        // and the objective mutation still reads it.
        let mut metadata = mutator.testcase_metadata.get_or_default(&seeded);
        assert_eq!(
            metadata.mutation_provenance[0].strategy,
            "goal_IncreaseSharesPerAsset"
        );

        let mut input = seeded;
        let mut rand = RomuDuoJrRand::with_seed(3);
        assert_eq!(
            mutator.economic_objective_mutation(&mut rand, &mut input, &mut metadata),
            MutationResult::Mutated
        );
        assert_eq!(
            U256::from_be_slice(&input.txs[0].input[4..36]),
            U256::from(10u128.pow(18))
        );
        assert_eq!(
            metadata.mutation_provenance.last().unwrap().strategy,
            "economic_objective"
        );
    }

    #[test]
    fn economic_objective_mutation_without_guidance_uses_default_objective() {
        let mutator = EvmMutator::new(
            Arc::new(AbiRegistry::default()),
            Arc::new(RwLock::new(GlobalAccountRegistry::default())),
        );
        let mut input = golden_input();
        let mut metadata = EvmTestcaseMetadata::default();
        let mut rand = RomuDuoJrRand::with_seed(9);
        assert_eq!(
            mutator.economic_objective_mutation(&mut rand, &mut input, &mut metadata),
            MutationResult::Mutated
        );
        assert_eq!(
            U256::from_be_slice(&input.txs[0].input[4..36]),
            U256::from(10u128.pow(21))
        );
    }
}
