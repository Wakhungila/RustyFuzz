//! Semantic executable input model and testcase metadata.
//!
//! Moved verbatim from the monolith's `evm::fuzz` in Stage 3 so scheduling and
//! future campaign infrastructure can depend on the model without depending on
//! the root fuzzer. Identity contract `rustyfuzz-input-id-v1` lives here.

use libafl::corpus::CorpusId;
use libafl::inputs::Input;
use libafl_bolts::HasLen;
use parking_lot::Mutex;
use rustyfuzz_core::InputId;
use rustyfuzz_evm::execution::{Waypoint, MAX_TOTAL_WAYPOINTS, MAX_WAYPOINTS_PER_TX};
use rustyfuzz_evm::{keccak256, SingletonTx};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Maximum number of transactions allowed in a sequence to prevent unbounded growth.
pub const MAX_SEQUENCE_LENGTH: usize = 100;

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
            if tx_waypoints.len() > MAX_WAYPOINTS_PER_TX {
                let excess = tx_waypoints.len() - MAX_WAYPOINTS_PER_TX;
                tx_waypoints.drain(0..excess);
            }
        }

        // Enforce total waypoint limit across all transactions
        let total_waypoints: usize = self.waypoints.iter().map(|w| w.len()).sum();
        if total_waypoints > MAX_TOTAL_WAYPOINTS {
            // Remove waypoints from earlier transactions (keep recent ones)
            let mut to_remove = total_waypoints - MAX_TOTAL_WAYPOINTS;
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustyfuzz_evm::U256;

    fn revm_u256_one() -> U256 {
        U256::from(1u64)
    }

    fn bound_input() -> EvmInput {
        EvmInput::new(
            vec![SingletonTx {
                input: vec![0xde],
                caller: [0x11u8; 20].into(),
                to: [0x22u8; 20].into(),
                value: revm_u256_one(),
                is_victim: false,
            }],
            0,
        )
    }

    #[test]
    fn metadata_store_respects_entry_bound_and_replace_eviction() {
        let store = EvmTestcaseMetadataStore::default();
        let inputs: Vec<EvmInput> = (0..MAX_METADATA_STORE_ENTRIES + 8)
            .map(|idx| EvmInput::new(bound_input().txs.clone(), idx as u64))
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
}
