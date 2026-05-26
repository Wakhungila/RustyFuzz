use crate::common::oracle::{VulnType, VulnerabilityOracle};
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
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::primitives::Address;
use serde::{Deserialize, Serialize};

pub struct ReplayVerifier {
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

#[async_trait]
impl SymbolicVerifier for HalmosVerifier {
    async fn verify(&self, _input: &EvmInput, vuln_desc: &str) -> Result<bool> {
        log::info!("Invoking Halmos for formal verification of: {}", vuln_desc);

        // --- Logic for 2026 Formal Verification Handoff ---
        // 1. Convert EvmInput into a Solidity "Cheatcode" sequence.
        // 2. Wrap the sequence in a Foundry invariant test or property.
        // 3. Run Halmos: `halmos --contract MyContract --function check_vulnerability`

        /*
        let output = Command::new(&self.halmos_path)
            .arg("--target")
            .arg(&self.contract_path)
            .output()?;

        let verified = String::from_utf8_lossy(&output.stdout).contains("Counterexample found");
        */

        anyhow::bail!(
            "Halmos verifier is not wired to a concrete harness yet: {}",
            vuln_desc
        )
    }
}
