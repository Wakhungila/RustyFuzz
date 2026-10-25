//! Per-transaction invariant checking, wired into the campaign loop.
//!
//! This is the producer that the predicate layer was built for and that the proof path
//! now has a slot for. Until this existed, a candidate could carry a
//! `ViolationPredicate` only if an oracle happened to emit a `DeniedMint` shape, which
//! almost nothing does.
//!
//! # Why per transaction, not per sequence
//!
//! An accounting bug is usually visible at an intermediate step and invisible at the end:
//! a repair path writes the global accumulator down, a later transaction restores the
//! totals, and the sequence as a whole balances. Checking only the final state would miss
//! it — the same reason Basin's `invariant_*` functions run after every handler call
//! rather than once at teardown.
//!
//! # What it deliberately does not do
//!
//! It does not decide that a finding is real. It produces an outcome plus evidence; the
//! confirmation gate, replay and PoC decide the rest. `Unknown` and a div0-degraded pass
//! are both no-signal (§5.1 of the design) and produce nothing.

use crate::common::types::{PredicateTerm, SequenceExecutionResult, StorageDiff};
use rustyfuzz_predicate::{
    Evidence, InvariantRegistry, Outcome, ReReadBudget, ReadRecord, SequenceView,
    StateReader, WriteRecord,
};

/// Resolves a slot from committed state, for the on-demand re-read.
///
/// The campaign already holds the post-transaction `CacheDB`, which answers a slot lookup
/// from memory. This adapter keeps the predicate crate free of `revm` types.
pub struct ChainStateReader<'a> {
    state: &'a crate::common::types::ChainState,
}

impl<'a> ChainStateReader<'a> {
    pub fn new(state: &'a crate::common::types::ChainState) -> Self {
        Self { state }
    }
}

impl StateReader for ChainStateReader<'_> {
    fn read_slot(&mut self, address: [u8; 20], slot: [u8; 32]) -> Option<[u8; 32]> {
        use revm::DatabaseRef;
        let crate::common::types::ChainState::Evm(db) = self.state;
        let address = revm::primitives::Address::from(address);
        let slot_key = revm::primitives::U256::from_be_bytes(slot);
        // `DatabaseRef` on CacheDB answers from the in-memory cache on a hit, which is the
        // common case because the sequence just touched the slot.
        db.storage_ref(address, slot_key)
            .ok()
            .map(|value| value.to_be_bytes())
    }
}

/// Adapts the campaign's storage diffs into the predicate layer's record shape.
fn writes_from(diffs: &[StorageDiff]) -> Vec<WriteRecord> {
    diffs
        .iter()
        .map(|diff| WriteRecord {
            tx_index: diff.tx_index,
            address: diff.address.into_array(),
            slot: diff.slot.0,
            old_value: diff.old_value.to_be_bytes(),
            new_value: diff.new_value.to_be_bytes(),
        })
        .collect()
}

/// Adapts observed reads into the predicate layer's record shape.
fn reads_from(execution: &SequenceExecutionResult) -> Vec<ReadRecord> {
    execution
        .storage_reads
        .iter()
        .filter_map(|read| {
            read.value.map(|value| ReadRecord {
                tx_index: read.tx_index,
                address: read.address.into_array(),
                slot: read.slot.0,
                value: value.to_be_bytes(),
            })
        })
        .collect()
}

/// One violation discovered mid-sequence.
#[derive(Debug, Clone)]
pub struct SequenceViolation {
    /// Predicate text, carried verbatim into the finding.
    pub predicate: String,
    /// Transaction after which it failed.
    pub tx_index: usize,
    /// Resolved operands, so the verdict can be recomputed.
    pub terms: Vec<PredicateTerm>,
    /// Full evidence, including counters and provenance.
    pub evidence: Evidence,
}

/// Checks every registered invariant after each transaction of a sequence.
///
/// Returns the first violation in transaction order. Returning early is deliberate: a
/// sequence that breaks an invariant at step 2 and again at step 5 has one root cause, and
/// reporting the earlier one gives the shortest counterexample.
pub fn check_sequence(
    registry: &InvariantRegistry,
    execution: &SequenceExecutionResult,
    state: &crate::common::types::ChainState,
    block: rustyfuzz_predicate::BlockContext,
    budget_per_check: usize,
) -> Option<SequenceViolation> {
    let writes = writes_from(&execution.storage_diffs);
    let reads = reads_from(execution);

    for tx_index in 0..execution.tx_results.len() {
        let view = SequenceView {
            writes: &writes,
            reads: &reads,
            block,
        };
        let mut reader = ChainStateReader::new(state);
        let results = registry.check_all(
            &view,
            tx_index,
            &mut reader,
            ReReadBudget::new(budget_per_check),
        );
        for (outcome, evidence) in results {
            // Only a violation produces a finding. `Unknown` and a div0-degraded pass are
            // no-signal by §5.1, and treating either as a finding is exactly the
            // false-positive behaviour the layer exists to prevent.
            if !outcome.is_violation() {
                continue;
            }
            if !matches!(outcome, Outcome::False) {
                continue;
            }
            let terms = evidence
                .terms
                .iter()
                .map(|term| PredicateTerm {
                    symbol: term.symbol.clone(),
                    address: term.address.clone(),
                    slot: term.slot.clone(),
                    offset_bits: term.offset_bits,
                    width_bits: term.width_bits,
                    value: term.value.clone(),
                    provenance: format!("{:?}", term.provenance).to_ascii_lowercase(),
                    tx_index: term.tx_index,
                })
                .collect();
            return Some(SequenceViolation {
                predicate: evidence.predicate.clone(),
                tx_index,
                terms,
                evidence,
            });
        }
    }
    None
}

/// Builds a registry from `(name, predicate, manifest)` triples.
///
/// Construction is where a bad manifest or a malformed predicate fails, so an
/// unusable configuration is rejected before a campaign starts rather than after minutes
/// of fuzzing.
pub fn build_registry(
    specs: &[(String, String, String)],
) -> Result<InvariantRegistry, Vec<String>> {
    let mut registry = InvariantRegistry::new();
    let mut errors = Vec::new();
    for (name, predicate, manifest) in specs {
        match rustyfuzz_predicate::PredicateOracle::new(
            rustyfuzz_predicate::InvariantSpec {
                name: name.clone(),
                predicate: predicate.clone(),
            },
            manifest,
        ) {
            Ok(oracle) => registry.register(Box::new(oracle)),
            Err(error) => errors.push(format!("{name}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(registry)
    } else {
        Err(errors)
    }
}

/// Names of the registered invariants, for logging a campaign's configuration.
pub fn oracle_names(registry: &InvariantRegistry) -> Vec<String> {
    registry.names().into_iter().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{ChainState, ExecutionStatus, TxExecutionResult};
    use revm::database::CacheDB;
    use revm::primitives::{Address, B256, U256};

    fn address(last: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = last;
        Address::from(bytes)
    }

    fn word(value: u64) -> U256 {
        U256::from(value)
    }

    fn slot(value: u8) -> B256 {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        B256::from(bytes)
    }

    const MANIFEST: &str = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "balanced": { "kind": "slot", "slot": "0x1", "offset_bits": 0, "width_bits": 256 },
            "expected": { "kind": "slot", "slot": "0x2", "offset_bits": 0, "width_bits": 256 }
        }
    }"#;

    fn execution_with(diffs: Vec<StorageDiff>, txs: usize) -> SequenceExecutionResult {
        SequenceExecutionResult {
            tx_results: (0..txs)
                .map(|index| TxExecutionResult {
                    tx_index: index,
                    status: ExecutionStatus::Success,
                    gas_used: 21_000,
                    output: Vec::new(),
                    coverage_hash: 0,
                    coverage_edges: 0,
                    storage_reads: Vec::new(),
                    storage_writes: Vec::new(),
                    storage_diffs: Vec::new(),
                    call_trace: Vec::new(),
                    waypoints: Vec::new(),
                })
                .collect(),
            total_gas_used: 21_000 * txs as u64,
            final_coverage_hash: 0,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: diffs,
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        }
    }

    fn diff(tx_index: usize, slot_value: u8, old: u64, new: u64) -> StorageDiff {
        StorageDiff {
            tx_index,
            address: address(0xaa),
            slot: slot(slot_value),
            old_value: word(old),
            new_value: word(new),
            pc: 0,
        }
    }

    fn registry() -> InvariantRegistry {
        build_registry(&[(
            "balanced".to_string(),
            "balanced == expected".to_string(),
            MANIFEST.to_string(),
        )])
        .expect("registry builds")
    }

    fn state() -> ChainState {
        ChainState::Evm(CacheDB::new(rustyfuzz_evm::ForkDb::empty()))
    }

    #[test]
    fn a_balanced_sequence_produces_no_violation() {
        let execution = execution_with(vec![diff(0, 1, 0, 100), diff(0, 2, 0, 100)], 1);
        let violation = check_sequence(
            &registry(),
            &execution,
            &state(),
            rustyfuzz_predicate::BlockContext::default(),
            8,
        );
        assert!(violation.is_none(), "balanced books must not report");
    }

    #[test]
    fn an_unbalanced_sequence_produces_a_violation_with_terms() {
        let execution = execution_with(vec![diff(0, 1, 0, 100), diff(0, 2, 0, 40)], 1);
        let violation = check_sequence(
            &registry(),
            &execution,
            &state(),
            rustyfuzz_predicate::BlockContext::default(),
            8,
        )
        .expect("the difference must be reported");
        assert_eq!(violation.predicate, "balanced == expected");
        assert_eq!(violation.terms.len(), 2);
        let values: Vec<&str> = violation.terms.iter().map(|t| t.value.as_str()).collect();
        assert!(values.contains(&"100"));
        assert!(values.contains(&"40"));
    }

    #[test]
    fn an_intermediate_violation_is_reported_even_when_the_end_state_balances() {
        // This is the whole reason for per-transaction checking: tx 0 breaks the books,
        // tx 1 restores them, and a final-state check would see nothing wrong.
        let execution = execution_with(
            vec![
                diff(0, 1, 0, 100),
                diff(0, 2, 0, 40),
                // tx 1 restores the balance.
                diff(1, 2, 40, 100),
            ],
            2,
        );
        let violation = check_sequence(
            &registry(),
            &execution,
            &state(),
            rustyfuzz_predicate::BlockContext::default(),
            8,
        )
        .expect("the intermediate break must be reported");
        assert_eq!(
            violation.tx_index, 0,
            "the earliest offending transaction is the counterexample"
        );
    }

    #[test]
    fn an_unevaluable_sequence_produces_nothing_rather_than_a_false_positive() {
        // No writes at all: every term is Unknown, which is no-signal, not a violation.
        let execution = execution_with(Vec::new(), 1);
        let violation = check_sequence(
            &registry(),
            &execution,
            &state(),
            rustyfuzz_predicate::BlockContext::default(),
            8,
        );
        assert!(
            violation.is_none(),
            "an absence of evidence must never become a finding"
        );
    }

    #[test]
    fn a_bad_manifest_fails_at_registry_build_time() {
        // The manifest omits the mandatory bit range; this must be rejected before a
        // campaign starts, not after minutes of fuzzing.
        let bad = r#"{
            "target": "0x00000000000000000000000000000000000000aa",
            "symbols": { "x": { "kind": "slot", "slot": "0x1" } }
        }"#;
        let errors =
            build_registry(&[("broken".to_string(), "x == 1".to_string(), bad.to_string())])
                .unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("broken"));
        assert!(errors[0].contains("offset_bits"));
    }

    #[test]
    fn a_malformed_predicate_fails_at_registry_build_time() {
        let errors = build_registry(&[(
            "syntax".to_string(),
            "x ==".to_string(),
            MANIFEST.to_string(),
        )])
        .unwrap_err();
        assert!(errors[0].contains("syntax"));
    }

    #[test]
    fn multiple_broken_specs_are_all_reported() {
        // Reporting only the first would make fixing a configuration a sequence of runs.
        let errors = build_registry(&[
            ("a".to_string(), "x ==".to_string(), MANIFEST.to_string()),
            ("b".to_string(), "y == 1".to_string(), MANIFEST.to_string()),
        ])
        .unwrap_err();
        assert_eq!(errors.len(), 2, "both must be reported: {errors:?}");
    }
}
