use crate::common::oracle::{
    EvidenceGrade, FindingStatus, RejectionReason, VulnType, VulnerabilityOracle,
};
use crate::common::types::{ChainState, OracleObservation, SequenceExecutionResult, Snapshot};
use crate::evm::corpus::PersistentCorpus;
use crate::evm::economic_views::{snapshot_economic_views, EconomicViewProbePlan};
use crate::evm::feedback::EvmCoverageFeedback;
use crate::evm::fuzz::EvmInput;
use crate::satori::fsutil::{
    redact_external_output, run_bounded_external_command_with_output_limit,
    MAX_EXTERNAL_COMMAND_TIMEOUT, MAX_EXTERNAL_OUTPUT_BYTES,
};
use anyhow::Result;
use async_trait::async_trait;
use hex;
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::database_interface::DatabaseRef;
use revm::primitives::{Address, U256};
use rustyfuzz_evm::dataflow::DataflowRegistry;
use rustyfuzz_evm::executor::EvmExecutor;
use rustyfuzz_evm::fork_db::EvmCacheDb;
use rustyfuzz_evm::fork_db::ForkDb;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

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
const MAX_HALMOS_CALLDATA_BYTES: usize = 16 * 1024;
const MAX_HALMOS_TOTAL_CALLDATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_HALMOS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HalmosInvariant {
    pub id: String,
    pub expression: String,
}

impl HalmosInvariant {
    fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            format!("{}\0{}", self.id, self.expression).as_bytes(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct HalmosCounterexample {
    invariant_id: String,
    invariant_digest: String,
    calldata: Vec<String>,
    pre_state: std::collections::BTreeMap<String, String>,
    post_state: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HalmosExecutionResult {
    HeuristicOnly,
}

pub struct HalmosVerifier {
    pub halmos_path: String,
    pub contract_path: String,
    invariant: Option<HalmosInvariant>,
}

impl HalmosVerifier {
    pub fn new(halmos_path: String, contract_path: String) -> Self {
        Self {
            halmos_path,
            contract_path,
            invariant: None,
        }
    }

    pub fn with_invariant(mut self, invariant: HalmosInvariant) -> Self {
        self.invariant = Some(invariant);
        self
    }
}

#[async_trait]
impl SymbolicVerifier for HalmosVerifier {
    async fn verify(&self, input: &EvmInput, vuln_desc: &str) -> Result<bool> {
        let harness = self.generate_harness(input, vuln_desc)?;
        let project_root = self.foundry_project_root()?;
        let harness_dir = project_root.join(format!(
            ".rustyfuzz-halmos-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&harness_dir)?;
        let halmos_path = self.halmos_path.clone();
        let invariant = self.invariant.clone();
        let cleanup_dir = harness_dir.clone();
        let result = tokio::task::spawn_blocking(move || {
            run_halmos_in_project_dir(
                &halmos_path,
                &project_root,
                &harness_dir,
                &harness,
                invariant.as_ref(),
            )
        })
        .await;
        let cleanup_result = std::fs::remove_dir_all(&cleanup_dir);
        let result = match result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => return Err(error),
            Err(error) => return Err(anyhow::anyhow!("Halmos worker failed: {error}")),
        };
        cleanup_result?;
        let _ = result;
        Ok(false)
    }
}

impl HalmosVerifier {
    fn foundry_project_root(&self) -> Result<std::path::PathBuf> {
        let contract_path = self.safe_contract_path()?;
        let fallback = contract_path.parent().map(Path::to_path_buf);
        let mut current = fallback.clone();
        while let Some(candidate) = current {
            if candidate.join("foundry.toml").is_file() {
                return Ok(candidate);
            }
            current = candidate.parent().map(Path::to_path_buf);
        }
        fallback.ok_or_else(|| anyhow::anyhow!("Halmos contract path has no project parent"))
    }

    fn safe_contract_path(&self) -> Result<std::path::PathBuf> {
        let path = std::path::Path::new(&self.contract_path);
        let mut current = Some(path.to_path_buf());
        while let Some(candidate) = current {
            let metadata = std::fs::symlink_metadata(&candidate)?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "Halmos contract path must not contain symlink components"
            );
            current = candidate
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(Path::to_path_buf);
        }
        let canonical = path.canonicalize()?;
        let metadata = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Halmos contract path must be a regular non-symlink Solidity file"
        );
        anyhow::ensure!(
            canonical
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("sol"),
            "Halmos contract path must identify a Solidity source file"
        );
        Ok(canonical)
    }

    fn generate_harness(&self, input: &EvmInput, vuln_desc: &str) -> Result<String> {
        let project_root = self.foundry_project_root()?;
        let contract_path = self.safe_contract_path()?;
        let contract_path = contract_path
            .strip_prefix(&project_root)
            .map_err(|_| {
                anyhow::anyhow!("Halmos contract path is outside the Foundry project root")
            })?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Halmos contract path is not valid UTF-8"))?;
        let contract_path = solidity_string_literal(contract_path)?;
        anyhow::ensure!(
            vuln_desc.len() <= 4096,
            "Halmos vulnerability description exceeds the fixed data limit"
        );
        let description = solidity_string_literal(vuln_desc)?;
        anyhow::ensure!(
            input.txs.len() <= 256,
            "Halmos transaction sequence exceeds the fixed harness limit"
        );
        anyhow::ensure!(
            input
                .txs
                .iter()
                .all(|tx| tx.input.len() <= MAX_HALMOS_CALLDATA_BYTES),
            "Halmos transaction calldata exceeds the fixed harness limit"
        );
        anyhow::ensure!(
            input.txs.iter().map(|tx| tx.input.len()).sum::<usize>()
                <= MAX_HALMOS_TOTAL_CALLDATA_BYTES,
            "Halmos transaction calldata exceeds the aggregate harness limit"
        );
        let mut calls = String::new();
        for tx in &input.txs {
            calls.push_str(&format!(
                "        address targetAddress = address(0x{});\n        vm.prank(address(0x{}));\n        targetAddress.call{{value: {}}}(hex\"{}\");\n",
                hex::encode(tx.to.as_slice()),
                hex::encode(tx.caller.as_slice()),
                tx.value,
                hex::encode(&tx.input)
            ));
        }
        let invariant_id = self
            .invariant
            .as_ref()
            .map(|invariant| invariant.id.as_str())
            .unwrap_or_default();
        let invariant_digest = self
            .invariant
            .as_ref()
            .map(HalmosInvariant::digest)
            .unwrap_or_default();
        let invariant_id = solidity_string_literal(invariant_id)?;
        let invariant_digest = solidity_string_literal(&invariant_digest)?;
        Ok(format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import {contract_path};

contract HalmosHarness is Test {{
    Vm internal vm = Vm(address(0x7109709ECfa91a80626FF3989D68f67F5b1DD12D));
    string internal vulnerabilityDescription;
    string internal invariantId;
    string internal invariantDigest;

    function setUp() public {{
        vulnerabilityDescription = {description};
        invariantId = {invariant_id};
        invariantDigest = {invariant_digest};
    }}

    function check_vulnerability() public {{
{calls}    }}
}}
"#,
        ))
    }
}

fn run_halmos_in_project_dir(
    halmos_path: &str,
    project_root: &Path,
    harness_dir: &Path,
    harness: &str,
    invariant: Option<&HalmosInvariant>,
) -> Result<HalmosExecutionResult> {
    let harness_path = harness_dir.join("HalmosHarness.t.sol");
    rustyfuzz_artifacts::fsutil::write_atomic(&harness_path, harness.as_bytes())?;
    let target = harness_path
        .strip_prefix(project_root)
        .map_err(|_| anyhow::anyhow!("Halmos harness path escaped the Foundry project root"))?;
    let mut command = Command::new(halmos_path);
    command
        .arg("--contract")
        .arg("HalmosHarness")
        .arg("--function")
        .arg("check_vulnerability")
        .arg("--target")
        .arg(target)
        .current_dir(project_root);
    let output = run_bounded_external_command_with_output_limit(
        &mut command,
        MAX_EXTERNAL_COMMAND_TIMEOUT,
        MAX_HALMOS_OUTPUT_BYTES,
    )?;
    let stdout = redact_external_output(&output.stdout, MAX_EXTERNAL_OUTPUT_BYTES);
    let stderr = redact_external_output(&output.stderr, MAX_EXTERNAL_OUTPUT_BYTES);
    if output.status.success() && !output.timed_out {
        Ok(classify_halmos_output(&output.stdout, invariant))
    } else if output.timed_out {
        anyhow::bail!(
            "Halmos execution timed out after {} seconds: stdout={stdout}, stderr={stderr}",
            MAX_EXTERNAL_COMMAND_TIMEOUT.as_secs()
        )
    } else {
        anyhow::bail!(
            "Halmos execution failed: status={}, stdout={stdout}, stderr={stderr}",
            output.status
        )
    }
}

fn classify_halmos_output(
    output: &[u8],
    invariant: Option<&HalmosInvariant>,
) -> HalmosExecutionResult {
    let _parsed_counterexample =
        invariant.and_then(|invariant| parse_halmos_counterexample(output, invariant));
    HalmosExecutionResult::HeuristicOnly
}

fn parse_halmos_counterexample(
    output: &[u8],
    invariant: &HalmosInvariant,
) -> Option<HalmosCounterexample> {
    output
        .split(|byte| *byte == b'\n')
        .filter_map(|line| std::str::from_utf8(line).ok())
        .filter_map(|line| {
            let start = line.find('{')?;
            let end = line.rfind('}')?;
            serde_json::from_str::<HalmosCounterexample>(line[start..=end].trim()).ok()
        })
        .find(|counterexample| {
            counterexample.invariant_id == invariant.id
                && counterexample.invariant_digest == invariant.digest()
                && !counterexample.calldata.is_empty()
                && counterexample.calldata.iter().all(|calldata| {
                    calldata.starts_with("0x")
                        && calldata.len() > 2
                        && calldata[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                && !counterexample.pre_state.is_empty()
                && !counterexample.post_state.is_empty()
        })
}

fn solidity_string_literal(value: &str) -> Result<String> {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_ascii_graphic() || character == ' ' => {
                escaped.push(character)
            }
            _ => anyhow::bail!("Halmos harness data contains unsupported characters"),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::oracle::{EvidenceGrade, RejectionReason};
    use crate::common::types::SingletonTx;
    use revm::state::AccountInfo;
    use std::collections::BTreeMap;

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
        };
        let base = ChainState::Evm(db);
        let report = RealismVerifier::new(1024).prove(&base, &BlockEnv::default(), &input);

        assert!(report.success, "{report:?}");
        assert_eq!(report.status, FindingStatus::Proved);
        assert_eq!(report.evidence_grade, EvidenceGrade::RealisticForkProof);
        assert!(report.rejection_reasons.is_empty());
        assert!(report.execution.is_some());
    }

    #[test]
    fn is_victim_role_marker_does_not_change_evm_execution() {
        // `is_victim` is a fuzzer role marker; EvmExecutor constructs TxEnv from
        // caller/value/data/to only, so both executions must produce identical
        // state effects (gas, storage, call trace, coverage).
        let caller = addr(0x53);
        let target = addr(0x54);
        let make_input = |is_victim: bool| EvmInput {
            txs: vec![SingletonTx {
                caller,
                to: target,
                value: U256::from(1),
                input: Vec::new(),
                is_victim,
            }],
            base_snapshot_id: 0,
        };
        let base_db = || {
            let mut db = CacheDB::new(ForkDb::empty());
            db.insert_account_info(
                caller,
                AccountInfo {
                    balance: U256::from(10u128.pow(30)),
                    ..AccountInfo::default()
                },
            );
            ChainState::Evm(db)
        };

        let verifier = ReplayVerifier::new(1024);
        let plain = verifier
            .replay(&base_db(), &BlockEnv::default(), &make_input(false))
            .expect("plain replay");
        let victim = verifier
            .replay(&base_db(), &BlockEnv::default(), &make_input(true))
            .expect("victim-marked replay");

        assert_eq!(plain.total_gas_used, victim.total_gas_used);
        assert_eq!(plain.final_coverage_hash, victim.final_coverage_hash);
        assert_eq!(plain.storage_diffs, victim.storage_diffs);
        assert_eq!(plain.call_trace, victim.call_trace);
    }

    #[test]
    fn halmos_generic_output_cannot_confirm_a_vulnerability() {
        let invariant = HalmosInvariant {
            id: "shares-sum".to_string(),
            expression: "totalAssets >= totalShares".to_string(),
        };
        assert!(
            parse_halmos_counterexample(b"Counterexample found\nViolation found", &invariant)
                .is_none()
        );
        assert_eq!(
            classify_halmos_output(b"Counterexample found\nViolation found", Some(&invariant)),
            HalmosExecutionResult::HeuristicOnly
        );
    }

    #[test]
    fn halmos_structured_parser_match_remains_heuristic_without_replay_adapter() {
        let invariant = HalmosInvariant {
            id: "shares-sum".to_string(),
            expression: "totalAssets >= totalShares".to_string(),
        };
        let marker = serde_json::to_vec(&HalmosCounterexample {
            invariant_id: invariant.id.clone(),
            invariant_digest: invariant.digest(),
            calldata: vec!["0xdeadbeef".to_string()],
            pre_state: BTreeMap::from([("totalAssets".to_string(), "0".to_string())]),
            post_state: BTreeMap::from([("totalAssets".to_string(), "1".to_string())]),
        })
        .expect("encode counterexample");
        let mut output = vec![b'x'; MAX_EXTERNAL_OUTPUT_BYTES + 1];
        output.push(b'\n');
        output.extend_from_slice(&marker);
        assert!(parse_halmos_counterexample(&output, &invariant).is_some());
        assert_eq!(
            classify_halmos_output(&output, Some(&invariant)),
            HalmosExecutionResult::HeuristicOnly
        );
    }

    #[tokio::test]
    async fn halmos_temp_directory_is_removed_when_execution_errors() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rustyfuzz-halmos-cleanup-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root)?;
        let contract = root.join("Contract.sol");
        std::fs::write(&contract, b"contract Contract {}")?;
        let verifier = HalmosVerifier::new(
            root.join("missing-halmos").to_string_lossy().into_owned(),
            contract.to_string_lossy().into_owned(),
        );
        let input = EvmInput {
            txs: Vec::new(),
            base_snapshot_id: 0,
        };
        assert!(verifier.verify(&input, "test").await.is_err());
        let leftovers = std::fs::read_dir(&root)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".rustyfuzz-halmos-")
            })
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn halmos_harness_uses_transaction_destinations_and_escaped_data() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rustyfuzz-halmos-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root)?;
        let contract = root.join("Contract.sol");
        std::fs::write(&contract, b"contract Contract {}")?;
        let verifier = HalmosVerifier::new("halmos".to_string(), contract.to_string_lossy().into());
        let input = EvmInput {
            txs: vec![
                SingletonTx {
                    caller: addr(1),
                    to: addr(0x22),
                    value: U256::ZERO,
                    input: vec![1, 2, 3],
                    is_victim: false,
                },
                SingletonTx {
                    caller: addr(3),
                    to: addr(0x33),
                    value: U256::from(1),
                    input: vec![4, 5, 6],
                    is_victim: false,
                },
            ],
            base_snapshot_id: 0,
        };
        let harness = verifier.generate_harness(
            &input,
            "\"; } contract Injected { function pwn() public payable {} } //",
        )?;
        assert!(harness.contains("vulnerabilityDescription = \"\\\"; } contract Injected"));
        assert!(!harness
            .lines()
            .any(|line| line.trim_start().starts_with("contract Injected")));
        assert!(harness.contains("import \"Contract.sol\""));
        assert!(harness.contains("address(0x2222222222222222222222222222222222222222)"));
        assert!(harness.contains("address(0x3333333333333333333333333333333333333333)"));
        assert!(!harness.contains("Target internal"));
        assert!(!harness.contains("new Target"));
        assert!(!harness.contains(root.to_string_lossy().as_ref()));
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
