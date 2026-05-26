use crate::common::oracle::ProtocolFinding;
use crate::common::types::{SequenceExecutionResult, SingletonTx, StorageDiff};
use crate::engine::actors::ActorType;
use crate::engine::economic_delta::{EconomicDeltaEngine, EconomicDeltaReport};
use crate::engine::exploit_path::{
    CounterexampleProofStatus, ExploitPathCandidate, MinimizedSequenceStatus, ReplayabilityStatus,
};
use revm::primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplayVerificationStatus {
    NotAttempted,
    Verified,
    Mismatch { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProofConfidenceTier {
    Heuristic,
    Replayed,
    ReplayedMinimized,
    ProofCarrying,
    PocGenerated,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofCarryingFinding {
    pub target: Option<Address>,
    pub vulnerability_class: Option<String>,
    pub invariant_id: Option<String>,
    pub actor_roles: BTreeMap<usize, ActorType>,
    pub tx_sequence: Vec<SingletonTx>,
    pub pre_state_evidence: Vec<String>,
    pub post_state_evidence: Vec<String>,
    pub storage_diffs: Vec<StorageDiff>,
    pub economic_delta: EconomicDeltaReport,
    pub violated_condition: String,
    pub replay_result: ReplayVerificationStatus,
    pub minimization_result: MinimizedSequenceStatus,
    pub confidence: u64,
    pub caveats: Vec<String>,
    pub foundry_poc_path: Option<PathBuf>,
    pub proof_status: CounterexampleProofStatus,
    pub confidence_tier: ProofConfidenceTier,
}

impl ProofCarryingFinding {
    pub fn from_candidate(
        candidate: &ExploitPathCandidate,
        execution: &SequenceExecutionResult,
        findings: &[ProtocolFinding],
    ) -> Self {
        let economic_delta = EconomicDeltaEngine::from_execution(
            &crate::evm::fuzz::EvmInput {
                txs: candidate.sequence.clone(),
                base_snapshot_id: 0,
                waypoints: Vec::new(),
                mutation_provenance: Vec::new(),
            },
            execution,
        );
        let violated_condition = candidate
            .violated_invariant
            .clone()
            .or_else(|| {
                findings
                    .iter()
                    .max_by_key(|finding| finding.severity.clone())
                    .map(|finding| finding.vuln.to_string())
            })
            .unwrap_or_else(|| "unknown-violated-condition".to_string());
        let replay_result = if candidate.replayability_status == ReplayabilityStatus::Replayable
            && execution.tx_results.iter().all(|result| {
                matches!(
                    result.status,
                    crate::common::types::ExecutionStatus::Success
                )
            }) {
            ReplayVerificationStatus::Verified
        } else if candidate.replayability_status == ReplayabilityStatus::Replayable {
            ReplayVerificationStatus::Mismatch {
                reason: "candidate did not replay cleanly on the concrete execution".to_string(),
            }
        } else {
            ReplayVerificationStatus::NotAttempted
        };

        let mut proof = Self {
            target: candidate.target,
            vulnerability_class: findings
                .iter()
                .max_by_key(|finding| finding.severity.clone())
                .map(|finding| finding.vuln.to_string()),
            invariant_id: candidate.violated_invariant.clone(),
            actor_roles: candidate.actor_roles.clone(),
            tx_sequence: candidate.sequence.clone(),
            pre_state_evidence: candidate.required_preconditions.clone(),
            post_state_evidence: build_post_state_evidence(execution, findings),
            storage_diffs: execution.storage_diffs.clone(),
            economic_delta,
            violated_condition,
            replay_result,
            minimization_result: candidate.minimized_sequence_status.clone(),
            confidence: candidate.confidence,
            caveats: build_caveats(candidate, findings),
            foundry_poc_path: None,
            proof_status: candidate.proof_status.clone(),
            confidence_tier: ProofConfidenceTier::Heuristic,
        };
        proof.confidence_tier = proof.compute_confidence_tier();
        proof
    }

    pub fn with_replay_result(mut self, replay_result: ReplayVerificationStatus) -> Self {
        self.replay_result = replay_result;
        self.confidence_tier = self.compute_confidence_tier();
        self
    }

    pub fn with_foundry_poc_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.foundry_poc_path = Some(path.into());
        self.confidence_tier = self.compute_confidence_tier();
        self
    }

    pub fn with_economic_delta(mut self, economic_delta: EconomicDeltaReport) -> Self {
        self.economic_delta = economic_delta;
        self.confidence_tier = self.compute_confidence_tier();
        self
    }

    pub fn verify_against(
        &self,
        execution: &SequenceExecutionResult,
        findings: &[ProtocolFinding],
    ) -> ReplayVerificationStatus {
        if self.tx_sequence.len() != execution.tx_results.len() {
            return ReplayVerificationStatus::Mismatch {
                reason: format!(
                    "tx_count mismatch: proof={} replay={}",
                    self.tx_sequence.len(),
                    execution.tx_results.len()
                ),
            };
        }
        if self.storage_diffs != execution.storage_diffs {
            return ReplayVerificationStatus::Mismatch {
                reason: format!(
                    "storage diff mismatch: proof={} replay={}",
                    self.storage_diffs.len(),
                    execution.storage_diffs.len()
                ),
            };
        }
        let expected_evidence = [
            format!("txs={}", execution.tx_results.len()),
            format!("storage_diffs={}", execution.storage_diffs.len()),
            format!("call_trace={}", execution.call_trace.len()),
        ];
        if expected_evidence.iter().any(|expected| {
            !self
                .post_state_evidence
                .iter()
                .any(|actual| actual == expected)
        }) {
            return ReplayVerificationStatus::Mismatch {
                reason: format!(
                    "evidence mismatch: proof={:?} replay={:?}",
                    self.post_state_evidence, expected_evidence
                ),
            };
        }
        if self.vulnerability_class.is_none() && findings.is_empty() {
            return ReplayVerificationStatus::Mismatch {
                reason: "no vulnerability class or protocol findings recorded".to_string(),
            };
        }
        ReplayVerificationStatus::Verified
    }

    pub fn compute_confidence_tier(&self) -> ProofConfidenceTier {
        match &self.replay_result {
            ReplayVerificationStatus::NotAttempted | ReplayVerificationStatus::Mismatch { .. } => {
                ProofConfidenceTier::Heuristic
            }
            ReplayVerificationStatus::Verified => {
                if self.foundry_poc_path.is_some() {
                    ProofConfidenceTier::PocGenerated
                } else if self.proof_status == CounterexampleProofStatus::ConcretelyReplayed {
                    match self.minimization_result {
                        MinimizedSequenceStatus::Minimized => ProofConfidenceTier::ProofCarrying,
                        MinimizedSequenceStatus::NeedsMinimization
                        | MinimizedSequenceStatus::NotAttempted => {
                            ProofConfidenceTier::ReplayedMinimized
                        }
                    }
                } else if self.minimization_result == MinimizedSequenceStatus::Minimized {
                    ProofConfidenceTier::ReplayedMinimized
                } else {
                    ProofConfidenceTier::Replayed
                }
            }
        }
    }

    pub fn confidence_is_confirmed(&self) -> bool {
        matches!(
            self.confidence_tier,
            ProofConfidenceTier::Replayed
                | ProofConfidenceTier::ReplayedMinimized
                | ProofConfidenceTier::ProofCarrying
                | ProofConfidenceTier::PocGenerated
                | ProofConfidenceTier::Confirmed
        )
    }

    pub fn confidence_is_strictly_confirmed(&self) -> bool {
        matches!(self.confidence_tier, ProofConfidenceTier::Confirmed)
    }
}

fn build_post_state_evidence(
    execution: &SequenceExecutionResult,
    findings: &[ProtocolFinding],
) -> Vec<String> {
    let mut out = vec![
        format!("txs={}", execution.tx_results.len()),
        format!("storage_diffs={}", execution.storage_diffs.len()),
        format!("call_trace={}", execution.call_trace.len()),
    ];
    out.extend(findings.iter().map(|finding| {
        format!(
            "finding {:?}:{:?} tx_index={:?} target={:?}",
            finding.pack, finding.vuln, finding.tx_index, finding.target
        )
    }));
    out
}

fn build_caveats(candidate: &ExploitPathCandidate, findings: &[ProtocolFinding]) -> Vec<String> {
    let mut caveats = candidate.required_preconditions.clone();
    if findings.is_empty() {
        caveats.push("no protocol oracle evidence was observed".to_string());
    }
    if candidate.replayability_status != ReplayabilityStatus::Replayable {
        caveats.push("candidate is not replayable without additional fork state".to_string());
    }
    caveats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::oracle::{ProtocolOraclePackKind, ProtocolSeverity, VulnType};
    use crate::common::types::{
        CallKind, CallPhase, ExecutionStatus, SequenceExecutionResult, SingletonTx,
        TxExecutionResult,
    };
    use crate::engine::exploit_path::{
        CounterexampleProofStatus, MinimizedSequenceStatus, ReplayabilityStatus,
    };
    use std::collections::BTreeMap;

    fn candidate() -> ExploitPathCandidate {
        ExploitPathCandidate {
            sequence: vec![SingletonTx {
                input: vec![0xb6, 0xb5, 0x5f, 0x25],
                caller: Address::repeat_byte(0xaa),
                to: Address::repeat_byte(0x11),
                value: revm::primitives::U256::ZERO,
                is_victim: false,
            }],
            target: Some(Address::repeat_byte(0x11)),
            attacker: Some(Address::repeat_byte(0xaa)),
            victims: vec![Address::repeat_byte(0xbb)],
            actor_roles: BTreeMap::new(),
            profit_delta: Some(revm::primitives::U256::from(1)),
            violated_invariant: Some("share inflation".to_string()),
            confidence: 90,
            required_preconditions: vec!["fund attacker".to_string()],
            replayability_status: ReplayabilityStatus::Replayable,
            minimized_sequence_status: MinimizedSequenceStatus::Minimized,
            proof_status: CounterexampleProofStatus::ConcretelyReplayed,
            proof: None,
            extension_hints: Vec::new(),
            persistence_reason: Some("test".to_string()),
        }
    }

    fn execution() -> SequenceExecutionResult {
        SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 1,
                output: Vec::new(),
                coverage_hash: 1,
                coverage_edges: 1,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: vec![],
                call_trace: vec![crate::common::types::CallObservation {
                    tx_index: 0,
                    depth: 0,
                    caller: Address::repeat_byte(0xaa),
                    target: Address::repeat_byte(0x11),
                    value: revm::primitives::U256::ZERO,
                    input: vec![0xb6, 0xb5, 0x5f, 0x25],
                    output: Vec::new(),
                    gas_limit: 1,
                    gas_used: 1,
                    success: true,
                    kind: CallKind::Transaction,
                    phase: CallPhase::End,
                    created_address: None,
                    result: Some("Success".to_string()),
                }],
                waypoints: Vec::new(),
            }],
            total_gas_used: 1,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        }
    }

    #[test]
    fn proof_serializes_and_marks_replayed_minimized_when_verified() {
        let proof = ProofCarryingFinding::from_candidate(
            &candidate(),
            &execution(),
            &[ProtocolFinding {
                pack: ProtocolOraclePackKind::Erc4626,
                vuln: VulnType::VaultInflation,
                severity: ProtocolSeverity::High,
                tx_index: Some(0),
                target: Some(Address::repeat_byte(0x11)),
                evidence: "share inflation".to_string(),
            }],
        )
        .with_replay_result(ReplayVerificationStatus::Verified);

        assert!(proof.confidence_is_confirmed());
        assert!(matches!(
            proof.confidence_tier,
            ProofConfidenceTier::ProofCarrying
                | ProofConfidenceTier::ReplayedMinimized
                | ProofConfidenceTier::Replayed
        ));
        let json = serde_json::to_string(&proof).expect("serializes");
        assert!(json.contains("share inflation"));
    }

    #[test]
    fn proof_mismatch_downgrades_to_heuristic() {
        let proof = ProofCarryingFinding::from_candidate(
            &candidate(),
            &execution(),
            &[ProtocolFinding {
                pack: ProtocolOraclePackKind::Erc4626,
                vuln: VulnType::VaultInflation,
                severity: ProtocolSeverity::High,
                tx_index: Some(0),
                target: Some(Address::repeat_byte(0x11)),
                evidence: "share inflation".to_string(),
            }],
        )
        .with_replay_result(ReplayVerificationStatus::Mismatch {
            reason: "different storage diffs".to_string(),
        });

        assert!(!proof.confidence_is_confirmed());
        assert!(matches!(
            proof.confidence_tier,
            ProofConfidenceTier::Heuristic
        ));
    }
}
