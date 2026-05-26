use crate::common::oracle::{
    ProtocolFinding, ProtocolOraclePack, ProtocolOraclePackKind, ProtocolSeverity, VulnType,
    VulnerabilityOracle,
};
use crate::common::types::{ChainState, SequenceExecutionResult, SingletonTx, Snapshot};
use crate::engine::exploit_synthesizer::synthesize_foundry_poc_with_findings;
use crate::evm::corpus::{CorpusEntryMetadata, CrashRecord, PersistentCorpus};
use crate::evm::dataflow::DataflowRegistry;
use crate::evm::executor::EvmExecutor;
use crate::evm::feedback::EvmStateNoveltyFeedback;
use crate::evm::fork_db::EvmCacheDb;
use crate::evm::fuzz::EvmInput;
use crate::evm::snapshot::new_evm_snapshot;
use bitvec::prelude::*;
use parking_lot::RwLock;
use revm::context::BlockEnv;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Minimizer<'a> {
    pub executor: &'a EvmExecutor,
    pub oracle: &'a dyn VulnerabilityOracle,
    pub initial_db: EvmCacheDb,
    pub initial_block_env: BlockEnv,
}

impl<'a> Minimizer<'a> {
    pub fn new(
        executor: &'a EvmExecutor,
        oracle: &'a dyn VulnerabilityOracle,
        initial_db: EvmCacheDb,
        initial_block_env: BlockEnv,
    ) -> Self {
        Self {
            executor,
            oracle,
            initial_db,
            initial_block_env,
        }
    }

    pub fn minimize_crash<F>(&self, original: &EvmInput, preserves_crash: F) -> Option<EvmInput>
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        if !self
            .replay_input(original)
            .ok()
            .as_ref()
            .is_some_and(&preserves_crash)
        {
            return None;
        }

        let mut minimized = original.clone();
        self.minimize_sequence(&mut minimized, &preserves_crash);
        self.minimize_values(&mut minimized, &preserves_crash);
        self.minimize_calldata(&mut minimized, &preserves_crash);
        Some(minimized)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn minimize_crash_to_foundry_poc<F>(
        &self,
        original: &EvmInput,
        corpus: &PersistentCorpus,
        report_dir: &Path,
        vuln: &VulnType,
        rpc_url: &str,
        fork_block: u64,
        reason: &str,
        preserves_crash: F,
    ) -> anyhow::Result<MinimizedCrashArtifact>
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        let minimized = self
            .minimize_crash(original, &preserves_crash)
            .ok_or_else(|| anyhow::anyhow!("original input does not reproduce crash predicate"))?;
        let execution = self.replay_input(&minimized)?;
        anyhow::ensure!(
            preserves_crash(&execution),
            "minimized input failed crash predicate after replay"
        );

        let mut state_feedback = EvmStateNoveltyFeedback::new();
        let novelty = state_feedback.observe_execution(&execution);
        let coverage = execution_coverage_material(&execution);
        let metadata = corpus.persist_execution_input(
            &minimized,
            &execution,
            &coverage,
            novelty.novelty_score(),
        )?;
        let crash = corpus.persist_crash(&metadata, reason)?;
        let reproduction_report =
            corpus.write_reproduction_report(&minimized, &execution, Some(&crash))?;
        let protocol_findings = ProtocolOraclePack::default().evaluate(&execution);
        let poc_findings = if protocol_findings.is_empty() {
            vec![ProtocolFinding {
                pack: ProtocolOraclePackKind::Erc20,
                vuln: vuln.clone(),
                severity: ProtocolSeverity::Medium,
                tx_index: execution.tx_results.last().map(|result| result.tx_index),
                target: minimized.txs.last().map(|tx| tx.to),
                evidence: format!(
                    "minimized replay preserved crash predicate `{reason}`; txs={}; storage_diffs={}",
                    minimized.txs.len(),
                    execution.storage_diffs.len()
                ),
            }]
        } else {
            protocol_findings.clone()
        };
        let foundry_poc = PathBuf::from(synthesize_foundry_poc_with_findings(
            &minimized,
            vuln,
            Some(&execution),
            &poc_findings,
            report_dir,
            rpc_url,
            fork_block,
        )?);

        Ok(MinimizedCrashArtifact {
            original_tx_count: original.txs.len(),
            minimized_tx_count: minimized.txs.len(),
            minimized_input: minimized,
            execution,
            metadata,
            crash,
            protocol_findings,
            reproduction_report,
            foundry_poc,
        })
    }

    pub fn replay_input(&self, input: &EvmInput) -> anyhow::Result<SequenceExecutionResult> {
        let mut current_db = self.initial_db.clone();
        let mut block_env = self.initial_block_env.clone();
        let mut dataflow = DataflowRegistry::new();
        let mut coverage = vec![0u8; 65_536];
        let mut tx_results = Vec::with_capacity(input.txs.len());

        for (idx, tx) in input.txs.iter().enumerate() {
            let mut chain_state = ChainState::Evm(current_db.clone());
            let mut waypoints = Vec::new();
            let result = self.executor.execute_with_result(
                &mut chain_state,
                &mut block_env,
                tx,
                &mut coverage,
                &mut dataflow,
                &mut waypoints,
                idx,
            )?;
            let ChainState::Evm(new_db) = chain_state;
            current_db = new_db;
            tx_results.push(result);
        }

        Ok(sequence_result_from_tx_results(tx_results))
    }

    fn minimize_sequence<F>(&self, input: &mut EvmInput, preserves_crash: &F)
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        let mut idx = 0;
        while idx < input.txs.len() {
            if input.txs.len() == 1 {
                break;
            }
            let mut candidate = input.clone();
            candidate.txs.remove(idx);
            if self.input_preserves(&candidate, preserves_crash) {
                *input = candidate;
            } else {
                idx += 1;
            }
        }
    }

    fn minimize_values<F>(&self, input: &mut EvmInput, preserves_crash: &F)
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        for idx in 0..input.txs.len() {
            if input.txs[idx].value.is_zero() {
                continue;
            }
            let mut candidate = input.clone();
            candidate.txs[idx].value = revm::primitives::U256::ZERO;
            if self.input_preserves(&candidate, preserves_crash) {
                *input = candidate;
            }
        }
    }

    fn minimize_calldata<F>(&self, input: &mut EvmInput, preserves_crash: &F)
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        for tx_idx in 0..input.txs.len() {
            self.truncate_calldata(input, tx_idx, preserves_crash);
            self.zero_abi_words(input, tx_idx, preserves_crash);
            self.remove_abi_words(input, tx_idx, preserves_crash);
        }
    }

    fn truncate_calldata<F>(&self, input: &mut EvmInput, tx_idx: usize, preserves_crash: &F)
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        let min_len = if input.txs[tx_idx].input.len() >= 4 {
            4
        } else {
            0
        };
        let mut target_len = input.txs[tx_idx].input.len();
        while target_len > min_len {
            target_len = min_len + ((target_len - min_len) / 2);
            let mut candidate = input.clone();
            candidate.txs[tx_idx].input.truncate(target_len);
            if self.input_preserves(&candidate, preserves_crash) {
                *input = candidate;
            } else if target_len == min_len {
                break;
            }
        }
    }

    fn zero_abi_words<F>(&self, input: &mut EvmInput, tx_idx: usize, preserves_crash: &F)
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        let len = input.txs[tx_idx].input.len();
        if len <= 4 {
            return;
        }
        let mut offset = 4;
        while offset < len {
            let end = (offset + 32).min(len);
            let mut candidate = input.clone();
            candidate.txs[tx_idx].input[offset..end].fill(0);
            if self.input_preserves(&candidate, preserves_crash) {
                *input = candidate;
            }
            offset += 32;
        }
    }

    fn remove_abi_words<F>(&self, input: &mut EvmInput, tx_idx: usize, preserves_crash: &F)
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        let mut offset = 4;
        while offset < input.txs[tx_idx].input.len() {
            let end = (offset + 32).min(input.txs[tx_idx].input.len());
            let mut candidate = input.clone();
            candidate.txs[tx_idx].input.drain(offset..end);
            if self.input_preserves(&candidate, preserves_crash) {
                *input = candidate;
            } else {
                offset += 32;
            }
        }
    }

    fn input_preserves<F>(&self, input: &EvmInput, preserves_crash: &F) -> bool
    where
        F: Fn(&SequenceExecutionResult) -> bool,
    {
        self.replay_input(input)
            .ok()
            .as_ref()
            .is_some_and(preserves_crash)
    }

    /// Reduces a sequence of transactions to the smallest possible subset
    /// that still triggers the same vulnerability.
    pub fn minimize(&self, original_txs: Vec<SingletonTx>) -> Vec<SingletonTx> {
        let mut minimized = original_txs.clone();
        let mut i = 0;

        log::info!(
            "Starting delta-debugging minimization ({} txs)...",
            minimized.len()
        );

        while i < minimized.len() {
            let mut candidate = minimized.clone();
            candidate.remove(i);

            if self.verify_vuln(&candidate) {
                minimized = candidate;
                log::debug!(
                    "Unnecessary transaction removed. Remaining: {}",
                    minimized.len()
                );
            } else {
                i += 1;
            }
        }

        minimized
    }

    /// Replays a sequence of transactions to check if the oracle still triggers.
    fn verify_vuln(&self, txs: &[SingletonTx]) -> bool {
        let mut current_db = self.initial_db.clone();
        let mut block_env = self.initial_block_env.clone();

        // v38: Executors now require dataflow and waypoint tracking even during minimization
        let mut dataflow = DataflowRegistry::new();
        let mut coverage_vec = vec![0u8; 65536];

        let mut prev_snapshot = new_evm_snapshot(0, current_db.clone());

        for (idx, tx) in txs.iter().enumerate() {
            let mut chain_state = ChainState::Evm(current_db.clone());
            let mut waypoints = Vec::new();

            // Match the updated EvmExecutor::execute signature
            let exec_result = self.executor.execute(
                &mut chain_state,
                &mut block_env,
                tx,
                &mut coverage_vec,
                &mut dataflow,
                &mut waypoints,
                idx,
            );

            if exec_result.is_err() {
                return false;
            }

            let ChainState::Evm(new_db) = chain_state;
            let current_snapshot = Snapshot {
                id: (idx + 1) as u64,
                state: Arc::new(RwLock::new(ChainState::Evm(new_db.clone()))),
                coverage: BitVec::from_slice(&coverage_vec),
                producing_input: None, // Minimization doesn't need to track origin
                waypoints,
                depth: (idx + 1) as u32,
                gas_used: exec_result.unwrap_or(0),
            };

            // Check if the oracle triggers on this specific state transition
            if self
                .oracle
                .check(&prev_snapshot, &current_snapshot)
                .is_some()
            {
                return true;
            }

            current_db = new_db;
            prev_snapshot = current_snapshot;
        }

        false
    }
}

#[derive(Debug)]
pub struct MinimizedCrashArtifact {
    pub original_tx_count: usize,
    pub minimized_tx_count: usize,
    pub minimized_input: EvmInput,
    pub execution: SequenceExecutionResult,
    pub metadata: CorpusEntryMetadata,
    pub crash: CrashRecord,
    pub protocol_findings: Vec<ProtocolFinding>,
    pub reproduction_report: PathBuf,
    pub foundry_poc: PathBuf,
}

fn sequence_result_from_tx_results(
    tx_results: Vec<crate::common::types::TxExecutionResult>,
) -> SequenceExecutionResult {
    let total_gas_used = tx_results.iter().map(|result| result.gas_used).sum();
    let final_coverage_hash = tx_results
        .last()
        .map(|result| result.coverage_hash)
        .unwrap_or_default();
    SequenceExecutionResult {
        total_gas_used,
        final_coverage_hash,
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
    }
}

fn execution_coverage_material(execution: &SequenceExecutionResult) -> Vec<u8> {
    let mut material = Vec::with_capacity(execution.tx_results.len() * 8);
    for result in &execution.tx_results {
        material.extend_from_slice(&result.coverage_hash.to_be_bytes());
    }
    if material.is_empty() {
        material.extend_from_slice(&execution.final_coverage_hash.to_be_bytes());
    }
    material
}
