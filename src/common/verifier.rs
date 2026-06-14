use crate::common::oracle::{
    EvidenceGrade, FindingStatus, RejectionReason, VulnType, VulnerabilityOracle,
};
use crate::common::types::{ChainState, OracleObservation, SequenceExecutionResult, Snapshot};
use crate::evm::corpus::PersistentCorpus;
use crate::evm::dataflow::DataflowRegistry;
use crate::evm::economic_views::{snapshot_economic_views, EconomicViewProbePlan};
use crate::evm::executor::EvmExecutor;
use crate::evm::feedback::EvmCoverageFeedback;
use crate::evm::fork_db::EvmCacheDb;
use crate::evm::fork_db::ForkDb;
use crate::evm::fuzz::EvmInput;
use anyhow::Result;
use async_trait::async_trait;
use hex;
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::database_interface::DatabaseRef;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

pub struct ReplayVerifier {
    executor: EvmExecutor,
    map_size: usize,
}

pub struct RealismVerifier {
    executor: EvmExecutor,
    map_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifferentialReplayReport {
    pub equivalent: bool,
    pub gas_delta: i128,
    pub cached_coverage_hash: u64,
    pub live_coverage_hash: u64,
    pub cached_tx_count: usize,
    pub live_tx_count: usize,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayEconomicResult {
    pub execution: SequenceExecutionResult,
    pub before: crate::engine::economic_delta::EconomicViewSnapshot,
    pub after: crate::engine::economic_delta::EconomicViewSnapshot,
    pub delta: crate::engine::economic_delta::EconomicDeltaReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealismProofReport {
    pub success: bool,
    pub status: FindingStatus,
    pub evidence_grade: EvidenceGrade,
    pub rejection_reasons: Vec<RejectionReason>,
    pub execution: Option<SequenceExecutionResult>,
}

impl ReplayVerifier {
    pub fn new(map_size: usize) -> Self {
        Self {
            executor: EvmExecutor::new(),
            map_size,
        }
    }

    pub fn replay(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> Result<SequenceExecutionResult> {
        let mut state = base_state.clone();
        let mut env = block_env.clone();
        let mut coverage = vec![0u8; self.map_size];
        let mut dataflow = DataflowRegistry::new();
        let mut tx_results = Vec::with_capacity(input.txs.len());

        for (tx_idx, tx) in input.txs.iter().enumerate() {
            let mut waypoints = Vec::new();
            let result = self.executor.execute_with_result(
                &mut state,
                &mut env,
                tx,
                &mut coverage,
                &mut dataflow,
                &mut waypoints,
                tx_idx,
            )?;
            tx_results.push(result);
        }

        Ok(SequenceExecutionResult {
            total_gas_used: tx_results.iter().map(|result| result.gas_used).sum(),
            final_coverage_hash: EvmCoverageFeedback::stable_path_hash(&coverage),
            storage_reads: tx_results
                .iter()
                .flat_map(|result| result.storage_reads.clone())
                .collect(),
            storage_writes: tx_results
                .iter()
                .flat_map(|result| result.storage_writes.clone())
                .collect(),
            storage_diffs: tx_results
                .iter()
                .flat_map(|result| result.storage_diffs.clone())
                .collect(),
            call_trace: tx_results
                .iter()
                .flat_map(|result| result.call_trace.clone())
                .collect(),
            oracle_observations: Vec::new(),
            tx_results,
        })
    }

    pub fn replay_with_economic_views(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
        target: Option<Address>,
    ) -> Result<ReplayEconomicResult> {
        let plan = EconomicViewProbePlan::from_sequence(input, target);
        let before = snapshot_economic_views(base_state, block_env, &plan, 0);
        let execution = self.replay(base_state, block_env, input)?;

        let mut state = base_state.clone();
        let mut env = block_env.clone();
        let mut coverage = vec![0u8; self.map_size];
        let mut dataflow = DataflowRegistry::new();
        for (tx_idx, tx) in input.txs.iter().enumerate() {
            let mut waypoints = Vec::new();
            self.executor.execute_with_result(
                &mut state,
                &mut env,
                tx,
                &mut coverage,
                &mut dataflow,
                &mut waypoints,
                tx_idx,
            )?;
        }

        let after = snapshot_economic_views(&state, &env, &plan, input.txs.len());
        let delta = crate::engine::economic_delta::economic_view_delta(&before, &after);
        Ok(ReplayEconomicResult {
            execution,
            before,
            after,
            delta,
        })
    }

    pub fn verify_deterministic(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> Result<SequenceExecutionResult> {
        let first = self.replay(base_state, block_env, input)?;
        let second = self.replay(base_state, block_env, input)?;
        anyhow::ensure!(
            first == second,
            "deterministic replay mismatch: first={first:?}, second={second:?}"
        );
        Ok(first)
    }

    pub fn verify_persisted_input(
        &self,
        corpus: &PersistentCorpus,
        input_id: &str,
        fork_cache_id: &str,
        block_env: &BlockEnv,
    ) -> Result<SequenceExecutionResult> {
        let input = corpus.load_input(input_id)?;
        let fork_db = corpus.load_offline_fork_db(fork_cache_id)?;
        let base_db: EvmCacheDb = CacheDB::new(fork_db);
        self.verify_deterministic(&ChainState::Evm(base_db), block_env, &input)
    }

    pub fn verify_cached_vs_live(
        &self,
        cached_fork_db: ForkDb,
        live_fork_db: ForkDb,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> Result<SequenceExecutionResult> {
        let (cached, report) =
            self.compare_cached_vs_live(cached_fork_db, live_fork_db, block_env, input)?;
        anyhow::ensure!(
            report.equivalent,
            "cached-vs-live replay mismatch: {report:?}"
        );
        Ok(cached)
    }

    pub fn compare_cached_vs_live(
        &self,
        cached_fork_db: ForkDb,
        live_fork_db: ForkDb,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> Result<(SequenceExecutionResult, DifferentialReplayReport)> {
        let cached = self.verify_deterministic(
            &ChainState::Evm(CacheDB::new(cached_fork_db)),
            block_env,
            input,
        )?;
        let live = self.verify_deterministic(
            &ChainState::Evm(CacheDB::new(live_fork_db)),
            block_env,
            input,
        )?;
        let report = differential_report(&cached, &live);
        Ok((cached, report))
    }

    pub fn evaluate_oracle(
        &self,
        execution: &mut SequenceExecutionResult,
        oracle_name: impl Into<String>,
        oracle: &dyn VulnerabilityOracle,
        before: &Snapshot,
        after: &Snapshot,
    ) -> Option<VulnType> {
        let finding = oracle.check(before, after)?;
        execution.oracle_observations.push(OracleObservation {
            oracle: oracle_name.into(),
            finding: finding.to_string(),
            tx_index: execution.tx_results.last().map(|result| result.tx_index),
            evidence: format!(
                "storage_diffs={}, calls={}, coverage_hash={}",
                execution.storage_diffs.len(),
                execution.call_trace.len(),
                execution.final_coverage_hash
            ),
        });
        Some(finding)
    }
}

impl RealismVerifier {
    pub fn new(map_size: usize) -> Self {
        Self {
            executor: EvmExecutor::proof(),
            map_size,
        }
    }

    pub fn prove(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> RealismProofReport {
        let mut rejection_reasons = preflight_realism_rejections(base_state, input);
        if !rejection_reasons.is_empty() {
            rejection_reasons.sort();
            rejection_reasons.dedup();
            return RealismProofReport {
                success: false,
                status: FindingStatus::Rejected,
                evidence_grade: EvidenceGrade::Heuristic,
                rejection_reasons,
                execution: None,
            };
        }

        let first = self.replay_once(base_state, block_env, input);
        let second = self.replay_once(base_state, block_env, input);
        match (first, second) {
            (Ok(first), Ok(second)) if first == second => RealismProofReport {
                success: true,
                status: FindingStatus::Proved,
                evidence_grade: EvidenceGrade::RealisticForkProof,
                rejection_reasons: Vec::new(),
                execution: Some(first),
            },
            (Ok(_), Ok(_)) => RealismProofReport {
                success: false,
                status: FindingStatus::Rejected,
                evidence_grade: EvidenceGrade::DeterministicReplay,
                rejection_reasons: vec![RejectionReason::NonDeterministic],
                execution: None,
            },
            (Err(_), _) | (_, Err(_)) => RealismProofReport {
                success: false,
                status: FindingStatus::Rejected,
                evidence_grade: EvidenceGrade::Heuristic,
                rejection_reasons: vec![RejectionReason::ReplayFailed],
                execution: None,
            },
        }
    }

    fn replay_once(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> Result<SequenceExecutionResult> {
        let mut state = base_state.clone();
        let mut env = block_env.clone();
        let mut coverage = vec![0u8; self.map_size];
        let mut dataflow = DataflowRegistry::new();
        let mut tx_results = Vec::with_capacity(input.txs.len());

        for (tx_idx, tx) in input.txs.iter().enumerate() {
            let mut waypoints = Vec::new();
            let result = self.executor.execute_with_result(
                &mut state,
                &mut env,
                tx,
                &mut coverage,
                &mut dataflow,
                &mut waypoints,
                tx_idx,
            )?;
            tx_results.push(result);
        }

        Ok(SequenceExecutionResult {
            total_gas_used: tx_results.iter().map(|result| result.gas_used).sum(),
            final_coverage_hash: EvmCoverageFeedback::stable_path_hash(&coverage),
            storage_reads: tx_results
                .iter()
                .flat_map(|result| result.storage_reads.clone())
                .collect(),
            storage_writes: tx_results
                .iter()
                .flat_map(|result| result.storage_writes.clone())
                .collect(),
            storage_diffs: tx_results
                .iter()
                .flat_map(|result| result.storage_diffs.clone())
                .collect(),
            call_trace: tx_results
                .iter()
                .flat_map(|result| result.call_trace.clone())
                .collect(),
            oracle_observations: Vec::new(),
            tx_results,
        })
    }
}

fn preflight_realism_rejections(base_state: &ChainState, input: &EvmInput) -> Vec<RejectionReason> {
    let mut balances = std::collections::HashMap::<Address, U256>::new();
    let ChainState::Evm(db) = base_state;
    for tx in &input.txs {
        let balance = *balances.entry(tx.caller).or_insert_with(|| {
            db.basic_ref(tx.caller)
                .ok()
                .flatten()
                .map(|account| account.balance)
                .unwrap_or_default()
        });
        if balance < tx.value {
            return vec![RejectionReason::MissingBalance];
        }
        balances.insert(tx.caller, balance.saturating_sub(tx.value));
    }
    Vec::new()
}

fn differential_report(
    cached: &SequenceExecutionResult,
    live: &SequenceExecutionResult,
) -> DifferentialReplayReport {
    let mut mismatches = Vec::new();
    if cached.tx_results.len() != live.tx_results.len() {
        mismatches.push(format!(
            "tx_count cached={} live={}",
            cached.tx_results.len(),
            live.tx_results.len()
        ));
    }
    if cached.final_coverage_hash != live.final_coverage_hash {
        mismatches.push(format!(
            "coverage_hash cached={} live={}",
            cached.final_coverage_hash, live.final_coverage_hash
        ));
    }
    if cached.storage_diffs != live.storage_diffs {
        mismatches.push(format!(
            "storage_diffs cached={} live={}",
            cached.storage_diffs.len(),
            live.storage_diffs.len()
        ));
    }
    if cached.call_trace != live.call_trace {
        mismatches.push(format!(
            "call_trace cached={} live={}",
            cached.call_trace.len(),
            live.call_trace.len()
        ));
    }
    for (idx, (cached_tx, live_tx)) in cached
        .tx_results
        .iter()
        .zip(live.tx_results.iter())
        .enumerate()
    {
        if cached_tx.status != live_tx.status {
            mismatches.push(format!(
                "tx {idx} status cached={:?} live={:?}",
                cached_tx.status, live_tx.status
            ));
        }
        if cached_tx.output != live_tx.output {
            mismatches.push(format!(
                "tx {idx} output cached_len={} live_len={}",
                cached_tx.output.len(),
                live_tx.output.len()
            ));
        }
    }
    DifferentialReplayReport {
        equivalent: mismatches.is_empty(),
        gas_delta: cached.total_gas_used as i128 - live.total_gas_used as i128,
        cached_coverage_hash: cached.final_coverage_hash,
        live_coverage_hash: live.final_coverage_hash,
        cached_tx_count: cached.tx_results.len(),
        live_tx_count: live.tx_results.len(),
        mismatches,
    }
}

/// Abstract interface for a symbolic execution verifier.
/// This allows RustyFuzz to integrate with various formal verification tools.
#[async_trait]
pub trait SymbolicVerifier: Send + Sync {
    /// Verifies if a given input sequence truly triggers a vulnerability.
    /// Returns true if the vulnerability is formally proven, false otherwise.
    async fn verify(&self, input: &EvmInput, vuln_desc: &str) -> Result<bool>;
}

/// HalmosVerifier: Integrates with the Halmos symbolic execution engine.
/// Halmos is a Foundry-native symbolic executor, ideal for EVM contract verification.
pub struct HalmosVerifier {
    pub halmos_path: String,
    pub contract_path: String,
}

impl HalmosVerifier {
    pub fn new(halmos_path: String, contract_path: String) -> Self {
        Self {
            halmos_path,
            contract_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::oracle::{EvidenceGrade, RejectionReason};
    use crate::common::types::SingletonTx;
    use revm::state::AccountInfo;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    #[test]
    fn realism_verifier_rejects_synthetic_funding_dependency() {
        let caller = addr(0x41);
        let target = addr(0x42);
        let input = EvmInput {
            txs: vec![SingletonTx {
                caller,
                to: target,
                value: U256::from(1),
                input: Vec::new(),
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let base = ChainState::Evm(CacheDB::new(ForkDb::empty()));
        let report = RealismVerifier::new(1024).prove(&base, &BlockEnv::default(), &input);

        assert!(!report.success);
        assert_eq!(report.status, FindingStatus::Rejected);
        assert_eq!(report.evidence_grade, EvidenceGrade::Heuristic);
        assert_eq!(
            report.rejection_reasons,
            vec![RejectionReason::MissingBalance]
        );
    }

    #[test]
    fn realism_verifier_proves_exact_sequence_with_real_balance() {
        let caller = addr(0x51);
        let target = addr(0x52);
        let mut db = CacheDB::new(ForkDb::empty());
        db.insert_account_info(
            caller,
            AccountInfo {
                balance: U256::from(10u128.pow(30)),
                ..AccountInfo::default()
            },
        );
        let input = EvmInput {
            txs: vec![SingletonTx {
                caller,
                to: target,
                value: U256::from(1),
                input: Vec::new(),
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let base = ChainState::Evm(db);
        let report = RealismVerifier::new(1024).prove(&base, &BlockEnv::default(), &input);

        assert!(report.success, "{report:?}");
        assert_eq!(report.status, FindingStatus::Proved);
        assert_eq!(report.evidence_grade, EvidenceGrade::RealisticForkProof);
        assert!(report.rejection_reasons.is_empty());
        assert!(report.execution.is_some());
    }
}

#[async_trait]
impl SymbolicVerifier for HalmosVerifier {
    async fn verify(&self, input: &EvmInput, vuln_desc: &str) -> Result<bool> {
        log::info!("Invoking Halmos for formal verification of: {}", vuln_desc);

        // Generate a concrete harness from the EvmInput
        let harness = self.generate_harness(input, vuln_desc)?;

        // Write harness to a temporary file
        let harness_path = format!("{}_halmos.t.sol", input.txs.len());
        std::fs::write(&harness_path, harness)?;

        // Run Halmos
        let output = tokio::process::Command::new(&self.halmos_path)
            .arg("--contract")
            .arg("HalmosHarness")
            .arg("--function")
            .arg("check_vulnerability")
            .arg("--target")
            .arg(&self.contract_path)
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        log::debug!("Halmos stdout: {}", stdout);
        log::debug!("Halmos stderr: {}", stderr);

        // Clean up temporary file
        let _ = std::fs::remove_file(&harness_path);

        // Parse output to determine if vulnerability was verified
        let verified =
            stdout.contains("Counterexample found") || stdout.contains("Violation found");

        if output.status.success() {
            Ok(verified)
        } else {
            anyhow::bail!(
                "Halmos execution failed: status={}, stdout={}, stderr={}",
                output.status,
                stdout,
                stderr
            )
        }
    }
}

impl HalmosVerifier {
    /// Generates a Foundry/Halmos harness from an EvmInput sequence
    fn generate_harness(&self, input: &EvmInput, vuln_desc: &str) -> Result<String> {
        let mut cheatcodes = String::new();

        for (idx, tx) in input.txs.iter().enumerate() {
            cheatcodes.push_str(&format!("        // Transaction {}\n", idx));
            cheatcodes.push_str(&format!("        vm.prank({:?});\n", tx.caller));
            cheatcodes.push_str(&format!(
                "        target.call{:?}({:?});\n",
                tx.to,
                hex::encode(&tx.input)
            ));
        }

        Ok(format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "../{}";

contract HalmosHarness is Test {{
    Vm vm = Vm(address(0x7109709ECfa91a80626FF3989D68f67F5b1DD12D));
    Target target;

    function setUp() public {{
        target = new Target();
    }}

    function check_vulnerability() public {{
        // Vulnerability description: {}
{}
        // Add assertions based on the specific vulnerability being tested
        assertTrue(true, "Harness generated - add specific assertions");
    }}
}}
"#,
            self.contract_path, vuln_desc, cheatcodes
        ))
    }
}
