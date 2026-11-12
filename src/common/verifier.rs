use crate::common::oracle::{
    EvidenceGrade, FindingStatus, RejectionReason, VulnType, VulnerabilityOracle,
};
use crate::common::types::{ChainState, OracleObservation, SequenceExecutionResult, Snapshot};
use crate::evm::corpus::PersistentCorpus;
use crate::evm::economic_views::{snapshot_economic_views, EconomicViewProbePlan};
use crate::evm::feedback::EvmCoverageFeedback;
use crate::evm::fuzz::EvmInput;
use anyhow::Result;
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::database_interface::DatabaseRef;
use revm::primitives::{Address, U256};
use rustyfuzz_evm::dataflow::DataflowRegistry;
use rustyfuzz_evm::executor::EvmExecutor;
use rustyfuzz_evm::fork_db::EvmCacheDb;
use rustyfuzz_evm::fork_db::ForkDb;
use serde::{Deserialize, Serialize};

pub struct ReplayVerifier {
    executor: EvmExecutor,
    map_size: usize,
    /// Must match the campaign's policy, or a time-dependent finding will not
    /// reproduce: the replayed transactions would observe different blocks than
    /// the ones that produced the finding.
    time_warp: rustyfuzz_evm::time_warp::TimeWarp,
}

pub struct RealismVerifier {
    executor: EvmExecutor,
    map_size: usize,
    /// Proof replay must advance blocks exactly as the campaign did, otherwise a
    /// time-dependent finding is not reproducible from pinned state.
    time_warp: rustyfuzz_evm::time_warp::TimeWarp,
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
    /// Why the replay failed, when it did.
    ///
    /// Without it a rejected replay is indistinguishable from a rejected
    /// predicate: both end up as a bare `ReplayFailed` reason, and the
    /// operator cannot tell a missing fork state from a transaction the
    /// executor refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_detail: Option<String>,
}

impl ReplayVerifier {
    pub fn new(map_size: usize) -> Self {
        Self {
            executor: EvmExecutor::new(),
            map_size,
            // Defaults to the campaign default so a verifier built without
            // explicit configuration still reproduces default campaigns.
            time_warp: rustyfuzz_evm::time_warp::TimeWarp::DEFAULT,
        }
    }

    /// Builds a verifier that replays under an explicit time-warp policy.
    pub fn with_time_warp(map_size: usize, time_warp: rustyfuzz_evm::time_warp::TimeWarp) -> Self {
        Self {
            executor: EvmExecutor::new(),
            map_size,
            time_warp,
        }
    }

    pub fn replay(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> Result<SequenceExecutionResult> {
        self.replay_with_coverage(base_state, block_env, input)
            .map(|(execution, _)| execution)
    }

    pub fn replay_with_coverage(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> Result<(SequenceExecutionResult, Vec<u8>)> {
        let mut state = base_state.clone();
        let mut coverage = vec![0u8; self.map_size];
        let mut dataflow = DataflowRegistry::new();
        let mut tx_results = Vec::with_capacity(input.txs.len());

        for (tx_idx, tx) in input.txs.iter().enumerate() {
            // Rebuild the block context for this index so replay observes the
            // same blocks the campaign did.
            let mut env = block_env.clone();
            self.time_warp.apply(&mut env, tx_idx);
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

        let execution = SequenceExecutionResult {
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
        };
        Ok((execution, coverage))
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

/// A security condition bound to the original rule, contract and actors.
/// Unsupported heuristic findings deliberately have no proof predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ViolationPredicate {
    DeniedMint {
        target: Address,
        caller: Address,
        recipient: Address,
        mint_calldata: Vec<u8>,
        policy_calldata: Vec<u8>,
    },
    /// A predicate from the invariant layer evaluated to `False`.
    ///
    /// The predicate and bindings are evaluated again on replay. Recorded terms
    /// are human-readable evidence of the discovery, never proof of the replay.
    ///
    /// Its absence is why the baseline's five cases could not be confirmed. Every case
    /// reached `ExpectedFinding` and `InvariantViolation`, but the only predicate variant
    /// was `DeniedMint`, so `confidence_is_confirmed()` was false, so no PoC was
    /// generated, so `FoundryPocGenerated` failed — a circle with no entry point. This
    /// variant is the entry point.
    InvariantViolated {
        /// The predicate exactly as authored.
        predicate: String,
        /// Original binding manifest. Older findings without it cannot prove a violation.
        #[serde(default)]
        binding_manifest: String,
        /// Transaction index at which it evaluated to false.
        tx_index: usize,
        /// Resolved terms, sufficient to recompute the verdict by hand.
        terms: Vec<crate::common::types::PredicateTerm>,
    },
}

impl ViolationPredicate {
    /// Builds the predicate for an invariant that the predicate layer found violated.
    ///
    /// `terms` are the resolved operands; a violation with no resolved terms is not
    /// evidence and is rejected, which keeps the "no proof without observations" rule.
    pub fn from_invariant_violation(
        predicate: impl Into<String>,
        binding_manifest: impl Into<String>,
        tx_index: usize,
        terms: Vec<crate::common::types::PredicateTerm>,
    ) -> Option<Self> {
        let predicate = predicate.into();
        if predicate.trim().is_empty() || terms.is_empty() {
            return None;
        }
        Some(Self::InvariantViolated {
            predicate,
            binding_manifest: binding_manifest.into(),
            tx_index,
            terms,
        })
    }

    pub fn from_finding(
        finding: &crate::common::oracle::ProtocolFinding,
        execution: &SequenceExecutionResult,
    ) -> Option<Self> {
        use crate::common::types::{CallKind, CallPhase};
        if finding.pack != crate::common::oracle::ProtocolOraclePackKind::Erc20
            || finding.vuln != VulnType::Other("mint authorization policy violation".into())
        {
            return None;
        }
        let target = finding.target?;
        let mint = execution.call_trace.iter().find(|call| {
            call.target == target
                && Some(call.tx_index) == finding.tx_index
                && call.kind == CallKind::Transaction
                && call.phase == CallPhase::End
                && call.success
                && call.input.len() == 68
                && call.input[..4] == [0x40, 0xc1, 0x0f, 0x19]
                && call.input[4..16] == [0; 12]
        })?;
        let policy = execution.call_trace.iter().find(|call| {
            call.tx_index.checked_add(1) == Some(mint.tx_index)
                && call.target == target
                && call.caller == mint.caller
                && call.kind == CallKind::Transaction
                && call.phase == CallPhase::End
                && call.input.len() == 36
                && (revm::primitives::keccak256("canMint(address)").as_slice()[..4]
                    == call.input[..4]
                    || revm::primitives::keccak256("isMinter(address)").as_slice()[..4]
                        == call.input[..4])
                && call.input[4..16] == [0; 12]
                && call.input[16..36] == mint.caller.as_slice()[..]
        })?;
        let predicate = Self::DeniedMint {
            target,
            caller: mint.caller,
            recipient: Address::from_slice(&mint.input[16..36]),
            mint_calldata: mint.input.clone(),
            policy_calldata: policy.input.clone(),
        };
        predicate.holds(execution).then_some(predicate)
    }

    pub fn holds(&self, execution: &SequenceExecutionResult) -> bool {
        self.holds_with_block(execution, None)
    }

    fn holds_with_block(
        &self,
        execution: &SequenceExecutionResult,
        block: Option<rustyfuzz_predicate::BlockContext>,
    ) -> bool {
        match self {
            Self::DeniedMint { .. } => self.observation_indices(execution).is_some(),
            Self::InvariantViolated {
                predicate,
                binding_manifest,
                tx_index,
                ..
            } => {
                use rustyfuzz_predicate::{
                    InvariantOracle, InvariantSpec, NoReRead, Outcome, PredicateOracle,
                    ReReadBudget, SequenceView,
                };
                if !execution
                    .tx_results
                    .iter()
                    .any(|tx| tx.tx_index == *tx_index)
                {
                    return false;
                }
                // Sequence results do not carry block headers. Without an explicit
                // replay environment, a block-dependent predicate cannot be proved.
                if block.is_none()
                    && predicate
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .any(|word| word == "block")
                {
                    return false;
                }
                let Ok(oracle) = PredicateOracle::new(
                    InvariantSpec {
                        name: "replay".into(),
                        predicate: predicate.clone(),
                    },
                    binding_manifest,
                ) else {
                    return false;
                };
                let writes =
                    crate::engine::invariant_runtime::writes_from(&execution.storage_diffs);
                let reads = crate::engine::invariant_runtime::reads_from(&execution.storage_reads);
                // Call outputs are re-derived from this replay's own trace, mirroring
                // storage: recorded discovery evidence is never consulted.
                let call_outputs = crate::engine::invariant_runtime::call_outputs_from(
                    &execution.call_trace,
                    *tx_index,
                );
                let view = SequenceView {
                    writes: &writes,
                    reads: &reads,
                    call_outputs: &call_outputs,
                    block: block.unwrap_or_default(),
                };
                // Only observations from this replay may resolve operands. Missing
                // slots stay Unknown; recorded discovery terms are never consulted.
                matches!(
                    oracle
                        .check(&view, *tx_index, &mut NoReRead, ReReadBudget::new(0))
                        .0,
                    Outcome::False
                )
            }
        }
    }

    /// This deliberately narrow predicate requires four adjacent committed calls:
    /// balance, explicit denied policy, mint, balance. It does not infer token
    /// semantics from arbitrary storage changes or permit another policy/actor.
    pub fn observation_indices(
        &self,
        execution: &SequenceExecutionResult,
    ) -> Option<(usize, usize, usize, usize)> {
        use crate::common::types::{CallKind, CallPhase, ExecutionStatus};
        // Only the DeniedMint shape has an observable call pattern; an invariant
        // violation carries its evidence directly and has no indices to return.
        let Self::DeniedMint {
            target,
            caller,
            recipient,
            mint_calldata,
            policy_calldata,
        } = self
        else {
            return None;
        };
        if mint_calldata.len() != 68
            || mint_calldata[..4] != [0x40, 0xc1, 0x0f, 0x19]
            || mint_calldata[4..16] != [0; 12]
            || mint_calldata[16..36] != recipient.as_slice()[..]
            || U256::from_be_slice(&mint_calldata[36..]).is_zero()
            || policy_calldata.len() != 36
            || policy_calldata[4..16] != [0; 12]
            || policy_calldata[16..36] != caller.as_slice()[..]
            || ![
                revm::primitives::keccak256("canMint(address)"),
                revm::primitives::keccak256("isMinter(address)"),
            ]
            .iter()
            .any(|selector| selector[..4] == policy_calldata[..4])
        {
            return None;
        }
        let calls: Vec<_> = execution
            .call_trace
            .iter()
            .filter(|call| {
                call.kind == CallKind::Transaction
                    && call.phase == CallPhase::End
                    && call.success
                    && call.target == *target
                    && call.caller == *caller
                    && execution.tx_results.iter().any(|tx| {
                        tx.tx_index == call.tx_index && tx.status == ExecutionStatus::Success
                    })
            })
            .collect();
        let balance = |call: &&crate::common::types::CallObservation| {
            call.input.len() == 36
                && call.input[..4] == [0x70, 0xa0, 0x82, 0x31]
                && call.input[4..16] == [0; 12]
                && call.input[16..36] == recipient.as_slice()[..]
                && call.output.len() == 32
        };
        for mint in calls.iter().filter(|call| call.input == *mint_calldata) {
            let Some(policy_index) = mint.tx_index.checked_sub(1) else {
                continue;
            };
            let Some(before_index) = mint.tx_index.checked_sub(2) else {
                continue;
            };
            let Some(policy) = calls.iter().find(|call| {
                call.tx_index == policy_index
                    && call.input == *policy_calldata
                    && call.output.len() == 32
                    && U256::from_be_slice(&call.output).is_zero()
            }) else {
                continue;
            };
            let Some(before) = calls
                .iter()
                .find(|call| call.tx_index == before_index && balance(call))
            else {
                continue;
            };
            let Some(after) = calls
                .iter()
                .find(|call| Some(call.tx_index) == mint.tx_index.checked_add(1) && balance(call))
            else {
                continue;
            };
            let probes_mutate = execution.storage_diffs.iter().any(|diff| {
                [before.tx_index, policy.tx_index, after.tx_index].contains(&diff.tx_index)
                    && diff.old_value != diff.new_value
            });
            if !probes_mutate
                && U256::from_be_slice(&after.output) > U256::from_be_slice(&before.output)
            {
                return Some((
                    before.tx_index,
                    policy.tx_index,
                    mint.tx_index,
                    after.tx_index,
                ));
            }
        }
        None
    }
}

impl RealismVerifier {
    pub fn new(map_size: usize) -> Self {
        Self {
            executor: EvmExecutor::proof(),
            map_size,
            // A proof replay must reproduce the finding on the state that was
            // actually verified, so every transaction runs at the pinned
            // block. Advancing the block here would not just change the
            // observation: the proof executor resolves the environment with
            // the exactly-pinned policy and refuses anything else, so the
            // replay could never succeed. It would also disagree with the
            // generated Foundry PoC, which forks at the pinned block and
            // replays the sequence there.
            time_warp: rustyfuzz_evm::time_warp::TimeWarp::NONE,
        }
    }

    /// Builds a proof verifier that replays under an explicit time-warp policy.
    ///
    /// Only usable where the execution environment accepts a block number
    /// other than the pinned one; the proof executor does not.
    pub fn with_time_warp(map_size: usize, time_warp: rustyfuzz_evm::time_warp::TimeWarp) -> Self {
        Self {
            executor: EvmExecutor::proof(),
            map_size,
            time_warp,
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
                failure_detail: None,
            };
        }

        let first = self.replay_once(base_state, block_env, input);
        let second = self.replay_once(base_state, block_env, input);
        match (first, second) {
            (Ok(first), Ok(second)) if first == second => RealismProofReport {
                success: true,
                status: FindingStatus::Replayed,
                evidence_grade: EvidenceGrade::DeterministicReplay,
                rejection_reasons: Vec::new(),
                execution: Some(first),
                failure_detail: None,
            },
            (Ok(_), Ok(_)) => RealismProofReport {
                success: false,
                status: FindingStatus::Rejected,
                evidence_grade: EvidenceGrade::DeterministicReplay,
                rejection_reasons: vec![RejectionReason::NonDeterministic],
                execution: None,
                failure_detail: Some(
                    "two replays of the same sequence produced different results".to_string(),
                ),
            },
            (Err(first), _) | (_, Err(first)) => RealismProofReport {
                success: false,
                status: FindingStatus::Rejected,
                evidence_grade: EvidenceGrade::Heuristic,
                rejection_reasons: vec![RejectionReason::ReplayFailed],
                execution: None,
                failure_detail: Some(format!("{first:#}")),
            },
        }
    }

    /// Repeatability is necessary but only this method checks a security condition.
    pub fn prove_violation(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
        predicate: &ViolationPredicate,
    ) -> RealismProofReport {
        let mut report = self.prove(base_state, block_env, input);
        if report.success {
            if report.execution.as_ref().is_some_and(|execution| {
                let tx_index = match predicate {
                    ViolationPredicate::InvariantViolated { tx_index, .. } => *tx_index,
                    _ => 0,
                };
                let mut env = block_env.clone();
                self.time_warp.apply(&mut env, tx_index);
                predicate.holds_with_block(
                    execution,
                    Some(rustyfuzz_predicate::BlockContext {
                        number: rustyfuzz_predicate::Int256(env.number.to_be_bytes()),
                        timestamp: rustyfuzz_predicate::Int256(env.timestamp.to_be_bytes()),
                    }),
                )
            }) {
                report.status = FindingStatus::Proved;
                report.evidence_grade = EvidenceGrade::RealisticForkProof;
            } else {
                report.success = false;
                report.status = FindingStatus::Rejected;
                report
                    .rejection_reasons
                    .push(RejectionReason::OracleWeakness);
            }
        }
        report
    }

    fn replay_once(
        &self,
        base_state: &ChainState,
        block_env: &BlockEnv,
        input: &EvmInput,
    ) -> Result<SequenceExecutionResult> {
        let mut state = base_state.clone();
        let mut coverage = vec![0u8; self.map_size];
        let mut dataflow = DataflowRegistry::new();
        let mut tx_results = Vec::with_capacity(input.txs.len());

        for (tx_idx, tx) in input.txs.iter().enumerate() {
            // Rebuild the block context for this index so replay observes the
            // same blocks the campaign did.
            let mut env = block_env.clone();
            self.time_warp.apply(&mut env, tx_idx);
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
    if input.base_snapshot_id != 0 || !input.validate() {
        return vec![RejectionReason::ReplayFailed];
    }
    let ChainState::Evm(db) = base_state;
    if let Some(tx) = input.txs.first() {
        // Only the first transaction can be checked against the initial
        // balance. Later callers may receive funds during earlier
        // transactions. REVM checks their actual sequential balances,
        // including gas, during proof replay.
        match db.basic_ref(tx.caller) {
            Ok(Some(account)) => {
                if account.balance < tx.value {
                    return vec![RejectionReason::MissingBalance];
                }
            }
            Ok(None) => {
                // Absent account: zero balance, cannot cover any value.
                if !tx.value.is_zero() {
                    return vec![RejectionReason::MissingBalance];
                }
            }
            Err(error) => {
                // Preflight could not read state (RPC outage, cache gap).
                // Fabricating `MissingBalance` here would turn a transient
                // infrastructure failure into a permanent-looking proof
                // rejection, so skip the preflight and let the realism
                // proof surface the real error instead.
                log::warn!(
                    "realism preflight could not read caller balance; skipping balance check: {error}"
                );
            }
        }
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
        assert_eq!(report.status, FindingStatus::Replayed);
        assert_eq!(report.evidence_grade, EvidenceGrade::DeterministicReplay);
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
}

#[cfg(test)]
mod invariant_predicate_tests {
    use super::*;
    use crate::common::types::PredicateTerm;

    fn term(symbol: &str, value: &str) -> PredicateTerm {
        PredicateTerm {
            symbol: symbol.to_string(),
            address: "0x00000000000000000000000000000000000000aa".to_string(),
            slot: "0000000000000000000000000000000000000000000000000000000000000003".to_string(),
            offset_bits: 0,
            width_bits: 256,
            value: value.to_string(),
            provenance: "write".to_string(),
            tx_index: 1,
        }
    }

    const MANIFEST: &str = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": { "x": { "kind": "slot", "slot": "0x1", "offset_bits": 0, "width_bits": 256 } }
    }"#;

    fn predicate(text: &str, tx_index: usize) -> ViolationPredicate {
        ViolationPredicate::from_invariant_violation(
            text,
            MANIFEST,
            tx_index,
            vec![term("x", "99")],
        )
        .expect("recorded violation")
    }

    fn fixture(values: &[u64]) -> (ChainState, EvmInput) {
        use crate::common::types::SingletonTx;
        use revm::{bytecode::Bytecode, primitives::Bytes, state::AccountInfo};
        let caller = Address::repeat_byte(0x55);
        let target = Address::with_last_byte(0xaa);
        let mut db = CacheDB::new(ForkDb::empty());
        db.insert_account_info(
            caller,
            AccountInfo {
                balance: U256::from(10u128.pow(30)),
                ..Default::default()
            },
        );
        // Store calldata word 0 into slot 1.
        let code = Bytecode::new_raw(Bytes::from(hex::decode("60003560015500").unwrap()));
        db.insert_account_info(
            target,
            AccountInfo {
                code_hash: code.hash_slow(),
                code: Some(code),
                ..Default::default()
            },
        );
        let txs = values
            .iter()
            .map(|value| SingletonTx {
                caller,
                to: target,
                value: U256::ZERO,
                input: U256::from(*value).to_be_bytes::<32>().to_vec(),
                is_victim: false,
            })
            .collect();
        (ChainState::Evm(db), EvmInput::new(txs, 0))
    }

    #[test]
    fn stale_recorded_terms_do_not_prove_a_satisfied_replay() {
        let (base, input) = fixture(&[7]);
        let predicate = predicate("x == 7", 0);
        let verifier = RealismVerifier::new(1024);
        let replay = verifier.prove(&base, &BlockEnv::default(), &input);
        assert!(replay.success, "{replay:?}");
        assert!(!predicate.holds(replay.execution.as_ref().unwrap()));
        let report = verifier.prove_violation(&base, &BlockEnv::default(), &input, &predicate);
        assert!(!report.success);
        assert_eq!(report.status, FindingStatus::Rejected);
        assert_eq!(report.evidence_grade, EvidenceGrade::DeterministicReplay);
        assert_eq!(
            report.rejection_reasons,
            vec![RejectionReason::OracleWeakness]
        );
    }

    #[test]
    fn replay_proves_a_real_violation_at_the_recorded_transaction() {
        let (base, input) = fixture(&[7, 8]);
        let predicate = predicate("x == 8", 0);
        let report = RealismVerifier::new(1024).prove_violation(
            &base,
            &BlockEnv::default(),
            &input,
            &predicate,
        );
        assert!(report.success, "{report:?}");
        assert_eq!(report.status, FindingStatus::Proved);
        assert_eq!(report.evidence_grade, EvidenceGrade::RealisticForkProof);
        let execution = report.execution.unwrap();
        assert!(predicate.holds(&execution));
        assert!(!self::predicate("x == 8", 1).holds(&execution));
        assert!(!self::predicate("x == 8", 2).holds(&execution));
        let json = serde_json::to_string(&predicate).unwrap();
        assert!(serde_json::from_str::<ViolationPredicate>(&json)
            .unwrap()
            .holds(&execution));
    }

    #[test]
    fn unknown_div0_and_invalid_configuration_cannot_prove_a_violation() {
        let (base, input) = fixture(&[7]);
        let execution = ReplayVerifier::new(1024)
            .replay(&base, &BlockEnv::default(), &input)
            .unwrap();
        for text in ["old(x) == 0", "x / 0 == 0", "x ==", "block.number == 10"] {
            assert!(!predicate(text, 0).holds(&execution), "{text}");
        }
        let mut missing = execution.clone();
        missing.storage_diffs.clear();
        missing.storage_reads.clear();
        assert!(!predicate("x == 8", 0).holds(&missing));
        let invalid =
            ViolationPredicate::from_invariant_violation("x == 8", "{}", 0, vec![term("x", "99")])
                .unwrap();
        assert!(!invalid.holds(&execution));
        let mut legacy = serde_json::to_value(predicate("x == 8", 0)).unwrap();
        legacy["InvariantViolated"]
            .as_object_mut()
            .unwrap()
            .remove("binding_manifest");
        assert!(!serde_json::from_value::<ViolationPredicate>(legacy)
            .unwrap()
            .holds(&execution));
    }

    #[test]
    fn proof_evaluates_block_fields_with_the_replayed_time_warp() {
        let (base, input) = fixture(&[7, 8]);
        let env = BlockEnv {
            number: U256::from(100),
            timestamp: U256::from(1000),
            ..Default::default()
        };
        let verifier = RealismVerifier::with_time_warp(
            1024,
            rustyfuzz_evm::time_warp::TimeWarp::from_seconds(60, 2),
        );
        let satisfied = predicate(
            "x == 8 && block.number == 102 && block.timestamp == 1060",
            1,
        );
        let report = verifier.prove_violation(&base, &env, &input, &satisfied);
        assert_eq!(report.status, FindingStatus::Rejected);
        assert_eq!(
            report.rejection_reasons,
            vec![RejectionReason::OracleWeakness]
        );
        let violated = predicate("x == 8 && block.number == 100", 1);
        let report = verifier.prove_violation(&base, &env, &input, &violated);
        assert!(report.success, "{report:?}");
        assert_eq!(report.status, FindingStatus::Proved);
    }

    #[test]
    fn a_violation_without_terms_is_not_a_predicate() {
        // The rule that makes this variant trustworthy: no observations, no proof.
        assert!(
            ViolationPredicate::from_invariant_violation("x == y", MANIFEST, 0, Vec::new())
                .is_none()
        );
        assert!(ViolationPredicate::from_invariant_violation(
            "   ",
            MANIFEST,
            0,
            vec![term("a", "1")]
        )
        .is_none());
    }

    #[test]
    fn an_invariant_predicate_is_the_entry_point_the_old_enum_lacked() {
        // Before this variant the only predicate was DeniedMint, so no other finding
        // could ever satisfy `confidence_is_confirmed` and no PoC was generated. This
        // test pins that a plain invariant violation now satisfies the is_some() half.
        let predicate = ViolationPredicate::from_invariant_violation(
            "approx_eq(lpSupply, functionCalc, 100, 6) && lpSupply <= functionCalc",
            MANIFEST,
            3,
            vec![term("lpSupply", "1000001"), term("functionCalc", "1000000")],
        )
        .expect("accepted");
        // `Some(..)` is what `confidence_is_confirmed` tests first; the tier check is
        // separate and exercised by the confirmation gate's own tests.
        assert!(matches!(
            predicate,
            ViolationPredicate::InvariantViolated { .. }
        ));
    }
}
