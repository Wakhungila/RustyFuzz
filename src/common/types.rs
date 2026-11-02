use bitvec::prelude::{BitVec, Lsb0};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use crate::evm::fuzz::EvmInput;
// TODO(stage-2b): replace legacy numeric/string identifiers in corpus and
// artifacts with these strong core IDs as semantic input metadata is split out.
pub use rustyfuzz_core::{CampaignId, InputId, OracleId, SnapshotId};
// TODO(stage-2e): keep this compatibility path until EVM execution result
// types move behind the rustyfuzz-evm boundary.
pub use rustyfuzz_core::ExecutionStatus;

// TODO(stage-2e): EVM execution domain types now live in `rustyfuzz-evm`;
// these compatibility re-exports keep existing import paths compiling until
// callers migrate (Stage 2F/4 removal).
pub use rustyfuzz_evm::execution::{
    CallKind, CallObservation, CallPhase, ChainState, ComparisonOperand, OracleObservation,
    SequenceExecutionResult, StorageAccess, StorageDiff, SymbolicExpression, TaintSource,
    TxExecutionResult, Waypoint,
};
pub use rustyfuzz_evm::execution::{MAX_TOTAL_WAYPOINTS, MAX_WAYPOINTS_PER_TX};
pub use rustyfuzz_evm::transaction::SingletonTx;

/// One resolved term of a predicate, carried into a finding's evidence.
///
/// Mirrors `rustyfuzz_predicate::TermEvidence` but lives here so the proof and report
/// types do not depend on the predicate crate's internals. Values are decimal strings
/// because the evidence is read by humans before it is parsed by machines.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PredicateTerm {
    pub symbol: String,
    pub address: String,
    pub slot: String,
    pub offset_bits: u16,
    pub width_bits: u16,
    pub value: String,
    /// `write`, `observed_read`, `pre_value` or `re_read`, so a reviewer can tell a
    /// trace observation from a re-read.
    pub provenance: String,
    pub tx_index: usize,
}

#[derive(Clone)]
pub struct Snapshot {
    pub id: u64,
    pub state: Arc<RwLock<ChainState>>,
    pub coverage: BitVec<u8, Lsb0>,
    pub producing_input: Option<EvmInput>,
    pub waypoints: Vec<Waypoint>,
    pub depth: u32,
    pub gas_used: u64,
}

impl Snapshot {
    /// Applies backpressure to waypoint accumulation by truncating if over limit
    pub fn apply_waypoint_backpressure(&mut self) {
        if self.waypoints.len() > MAX_WAYPOINTS_PER_TX {
            // Keep the most recent waypoints (they're more relevant for concolic solving)
            let excess = self.waypoints.len() - MAX_WAYPOINTS_PER_TX;
            self.waypoints.drain(0..excess);
        }
    }
}
