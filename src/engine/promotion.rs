use crate::common::oracle::{
    oracle_rejection_reasons_for_finding, EvidenceGrade, FindingStatus, ProtocolFinding,
    ProtocolOraclePack, ProtocolSeverity, RejectionReason, VulnType,
};
use crate::common::types::{
    CallObservation, ChainState, ExecutionStatus, SequenceExecutionResult, Snapshot, StorageDiff,
};
use crate::common::verifier::{RealismVerifier, ReplayVerifier};
use crate::engine::economic_delta::TokenBalanceView;
use crate::engine::exploit_synthesizer::synthesize_foundry_poc_with_findings;
use crate::engine::minimizer::Minimizer;
use crate::evm::corpus::{CampaignArtifactRecord, PersistentCorpus};
use crate::evm::fuzz::EvmInput;
use crate::satori::fsutil::{
    redact_external_output, run_bounded_command, BoundedCommandOutput,
    MAX_EXTERNAL_COMMAND_TIMEOUT, MAX_EXTERNAL_OUTPUT_BYTES,
};
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::primitives::Address;
use rustyfuzz_artifacts::fsutil::{write_atomic, write_json_atomic};
use rustyfuzz_evm::executor::EvmExecutor;
use rustyfuzz_evm::fork_db::{EvmCacheDb, ForkCacheProvenance, ForkDb};
use rustyfuzz_evm::inspector::MAP_SIZE;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingLifecycleStage {
    Candidate,
    Replayed,
    Minimized,
    PocGenerated,
    Confirmed,
    Rejected,
}

impl FindingLifecycleStage {
    /// Maps the promotion-pipeline stage onto the canonical Stage 2D lifecycle.
    ///
    /// Note: `PocGenerated` maps to `Minimized` — PoC generation is evidence
    /// gathering and must not advance proof by itself (ADR: AI/forge output
    /// never proves; invariant #4/#5).
    ///
    /// TODO(stage-4): retire this compatibility mapping once the pipeline
    /// consumes `rustyfuzz_core::FindingLifecycle` directly.
    pub fn canonical(&self) -> rustyfuzz_core::FindingLifecycle {
        match self {
            FindingLifecycleStage::Candidate => rustyfuzz_core::FindingLifecycle::Candidate,
            FindingLifecycleStage::Replayed => rustyfuzz_core::FindingLifecycle::Replayed,
            FindingLifecycleStage::Minimized => rustyfuzz_core::FindingLifecycle::Minimized,
            FindingLifecycleStage::PocGenerated => rustyfuzz_core::FindingLifecycle::Minimized,
            FindingLifecycleStage::Confirmed => rustyfuzz_core::FindingLifecycle::Proved,
            FindingLifecycleStage::Rejected => rustyfuzz_core::FindingLifecycle::Rejected,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionConfig {
    pub enabled: bool,
    pub require_replay_for_report: bool,
    pub require_poc_for_confirmed: bool,
    #[serde(default)]
    pub strict_proof: bool,
    #[serde(default)]
    pub no_synthetic_proof: bool,
    #[serde(default)]
    pub no_promotion: bool,
    #[serde(default)]
    pub external_foundry_opt_in: bool,
    #[serde(default)]
    pub require_foundry_poc: bool,
    #[serde(default)]
    pub require_minimized: bool,
    #[serde(default)]
    pub reject_heuristics: bool,
    #[serde(default)]
    pub max_finding_noise: Option<u64>,
    #[serde(default)]
    pub poc_out: Option<String>,
    pub promotion_limit: Option<u64>,
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_replay_for_report: true,
            require_poc_for_confirmed: true,
            strict_proof: false,
            no_synthetic_proof: false,
            no_promotion: false,
            external_foundry_opt_in: false,
            require_foundry_poc: false,
            require_minimized: false,
            reject_heuristics: false,
            max_finding_noise: None,
            poc_out: None,
            promotion_limit: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionEvidenceHashes {
    pub original_replay: String,
    pub minimized_input: String,
    pub minimized_replay: String,
    pub generated_poc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingPromotionRecord {
    pub finding_id: String,
    pub campaign_id: String,
    pub input_id: String,
    pub fork_cache_id: String,
    pub target: Option<Address>,
    pub fork_block: u64,
    pub vuln_type: String,
    pub severity: ProtocolSeverity,
    pub confidence: u64,
    #[serde(default)]
    pub status: FindingStatus,
    #[serde(default)]
    pub evidence_grade: EvidenceGrade,
    #[serde(default)]
    pub rejection_reasons: Vec<RejectionReason>,
    pub lifecycle_stage: FindingLifecycleStage,
    pub replay_status: String,
    pub minimize_status: String,
    pub poc_status: String,
    #[serde(default)]
    pub evidence_hash: Option<String>,
    #[serde(default)]
    pub evidence_hashes: Option<PromotionEvidenceHashes>,
    pub synthetic_mode: bool,
    pub caveats: Vec<String>,
    pub artifact_paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayPromotionReport {
    pub success: bool,
    pub tx_count: usize,
    pub expected_tx_count: usize,
    pub final_coverage_hash: u64,
    pub tx_statuses: Vec<ExecutionStatus>,
    pub oracle_findings: Vec<ProtocolFinding>,
    pub storage_diff_count: usize,
    pub storage_diffs: Vec<StorageDiff>,
    pub call_trace_shape: Vec<String>,
    pub call_trace: Vec<CallObservation>,
    pub final_balances: Vec<TokenBalanceView>,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MinimizationPromotionReport {
    pub status: String,
    pub original_tx_count: usize,
    pub minimized_tx_count: usize,
    pub reason: String,
}

const MAX_PROMOTION_POC_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PocValidationReport {
    pub success: bool,
    pub static_assertions_present: bool,
    pub transaction_replay_assertions_present: bool,
    pub invariant_hook_present: bool,
    pub forge_status: String,
    pub forge_command: Option<String>,
    pub stdout_snippet: String,
    pub stderr_snippet: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionCampaignSummary {
    pub campaign_id: String,
    pub total_executions: u64,
    #[serde(default)]
    pub mutated_inputs: u64,
    #[serde(default)]
    pub seed_replays: u64,
    pub total_artifacts: u64,
    #[serde(default)]
    pub coverage_edges: u64,
    #[serde(default)]
    pub interesting_candidates: u64,
    #[serde(default)]
    pub candidate_findings: u64,
    #[serde(default)]
    pub unproven_candidates: u64,
    #[serde(default)]
    pub missing_poc_for_promoted: u64,
    pub promoted_findings: u64,
    pub confirmed_findings: u64,
    pub rejected_candidates: u64,
    pub synthetic_non_production_findings: u64,
    pub highest_confidence: u64,
    pub poc_count: u64,
    pub replay_failure_count: u64,
    pub minimization_attempts: u64,
    pub minimization_reduced: u64,
    pub minimization_not_reducible: u64,
    #[serde(default)]
    pub promotion_failures: u64,
    #[serde(default)]
    pub promotion_pending: u64,
    #[serde(default)]
    pub promotion_capped: u64,
}

#[derive(Debug, Default)]
pub struct PromotionCampaignStats {
    promoted_ids: Mutex<BTreeSet<String>>,
    capped_ids: Mutex<BTreeSet<String>>,
    promoted_findings: AtomicU64,
    confirmed_findings: AtomicU64,
    rejected_candidates: AtomicU64,
    synthetic_non_production_findings: AtomicU64,
    highest_confidence: AtomicU64,
    poc_count: AtomicU64,
    replay_failure_count: AtomicU64,
    minimization_attempts: AtomicU64,
    minimization_reduced: AtomicU64,
    minimization_not_reducible: AtomicU64,
    promotion_failures: AtomicU64,
    promotion_pending: AtomicU64,
    promotion_capped: AtomicU64,
}

impl PromotionCampaignStats {
    pub fn promoted_count(&self) -> u64 {
        self.promoted_findings.load(Ordering::Relaxed)
    }

    pub fn promotion_failure_count(&self) -> u64 {
        self.promotion_failures.load(Ordering::Relaxed)
    }

    pub fn promotion_pending_count(&self) -> u64 {
        self.promotion_pending.load(Ordering::Relaxed)
    }

    pub fn promotion_capped_count(&self) -> u64 {
        self.promotion_capped.load(Ordering::Relaxed)
    }

    pub fn reserve_promotion(&self, finding_id: &str) -> bool {
        self.promoted_ids
            .lock()
            .expect("promotion id lock poisoned")
            .insert(finding_id.to_string())
    }

    pub fn release_promotion(&self, finding_id: &str) {
        self.promoted_ids
            .lock()
            .expect("promotion id lock poisoned")
            .remove(finding_id);
    }

    pub fn record_pending(&self) {
        self.promotion_pending.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_capped(&self, finding_id: &str) {
        let mut capped_ids = match self.capped_ids.lock() {
            Ok(capped_ids) => capped_ids,
            Err(poisoned) => {
                log::warn!("capped promotion id lock was poisoned; recovering bookkeeping state");
                poisoned.into_inner()
            }
        };
        if capped_ids.insert(finding_id.to_string()) {
            self.promotion_capped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_failure(&self, pending: bool) {
        self.promotion_failures.fetch_add(1, Ordering::Relaxed);
        if pending {
            self.promotion_pending.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record(&self, record: &FindingPromotionRecord) {
        self.promoted_findings.fetch_add(1, Ordering::Relaxed);
        self.highest_confidence
            .fetch_max(record.confidence, Ordering::Relaxed);
        if record.synthetic_mode {
            self.synthetic_non_production_findings
                .fetch_add(1, Ordering::Relaxed);
        }
        if record.lifecycle_stage == FindingLifecycleStage::Confirmed {
            self.confirmed_findings.fetch_add(1, Ordering::Relaxed);
        }
        if record.lifecycle_stage == FindingLifecycleStage::Rejected {
            self.rejected_candidates.fetch_add(1, Ordering::Relaxed);
        }
        if record.replay_status != "success" {
            self.replay_failure_count.fetch_add(1, Ordering::Relaxed);
        }
        if record.poc_status == "validated" {
            self.poc_count.fetch_add(1, Ordering::Relaxed);
        }
        match record.minimize_status.as_str() {
            "reduced" => {
                self.minimization_attempts.fetch_add(1, Ordering::Relaxed);
                self.minimization_reduced.fetch_add(1, Ordering::Relaxed);
            }
            "not_reducible" => {
                self.minimization_attempts.fetch_add(1, Ordering::Relaxed);
                self.minimization_not_reducible
                    .fetch_add(1, Ordering::Relaxed);
            }
            "failed" => {
                self.minimization_attempts.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn summary(
        &self,
        campaign_id: impl Into<String>,
        total_executions: u64,
        mutated_inputs: u64,
        seed_replays: u64,
        total_artifacts: u64,
        coverage_edges: u64,
    ) -> PromotionCampaignSummary {
        let promoted_findings = self.promoted_findings.load(Ordering::Relaxed);
        let confirmed_findings = self.confirmed_findings.load(Ordering::Relaxed);
        let rejected_candidates = self.rejected_candidates.load(Ordering::Relaxed);
        let poc_count = self.poc_count.load(Ordering::Relaxed);
        let candidate_findings =
            promoted_findings.saturating_sub(confirmed_findings + rejected_candidates);
        let unproven_candidates = total_artifacts.saturating_sub(confirmed_findings);
        PromotionCampaignSummary {
            campaign_id: campaign_id.into(),
            total_executions,
            mutated_inputs,
            seed_replays,
            total_artifacts,
            coverage_edges,
            interesting_candidates: unproven_candidates,
            candidate_findings,
            unproven_candidates,
            missing_poc_for_promoted: promoted_findings.saturating_sub(poc_count),
            promoted_findings,
            confirmed_findings,
            rejected_candidates,
            synthetic_non_production_findings: self
                .synthetic_non_production_findings
                .load(Ordering::Relaxed),
            highest_confidence: self.highest_confidence.load(Ordering::Relaxed),
            poc_count,
            replay_failure_count: self.replay_failure_count.load(Ordering::Relaxed),
            minimization_attempts: self.minimization_attempts.load(Ordering::Relaxed),
            minimization_reduced: self.minimization_reduced.load(Ordering::Relaxed),
            minimization_not_reducible: self.minimization_not_reducible.load(Ordering::Relaxed),
            promotion_failures: self.promotion_failures.load(Ordering::Relaxed),
            promotion_pending: self.promotion_pending.load(Ordering::Relaxed),
            promotion_capped: self.promotion_capped.load(Ordering::Relaxed),
        }
    }
}

fn validate_promotion_provenance(
    provenance: &ForkCacheProvenance,
    expected_block: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !provenance.provider_sanitized.is_empty()
            && provenance.chain_id.is_some()
            && provenance.block_number == Some(expected_block)
            && provenance.block_hash.is_some()
            && provenance.cache_id.is_some(),
        "promotion requires valid live-RPC fork provenance"
    );
    Ok(())
}

pub struct PromotionRequest<'a> {
    pub corpus: &'a PersistentCorpus,
    pub artifact: &'a CampaignArtifactRecord,
    pub block_env: &'a BlockEnv,
    pub report_dir: &'a Path,
    pub campaign_id: &'a str,
    pub fork_block: u64,
    pub rpc_url: &'a str,
    pub synthetic_mode: bool,
    pub config: &'a PromotionConfig,
}

pub fn promote_finding_artifact(
    request: PromotionRequest<'_>,
) -> anyhow::Result<FindingPromotionRecord> {
    anyhow::ensure!(
        !request.config.no_promotion,
        "refusing promotion while no-promotion mode is active"
    );
    rustyfuzz_evm::rpc_url::validate_production_rpc_url(request.rpc_url)
        .map_err(|error| anyhow::anyhow!("invalid promotion RPC URL: {error}"))?;
    anyhow::ensure!(
        !request.synthetic_mode,
        "refusing to promote synthetic fallback evidence"
    );
    anyhow::ensure!(
        !request.artifact.findings.is_empty(),
        "refusing to promote score-only artifact input_id={} without oracle/protocol finding evidence",
        request.artifact.input_id
    );
    let finding = request.artifact.findings.first().cloned();
    let cached_fork = request
        .corpus
        .load_fork_cache(&request.artifact.fork_cache_id)?;
    validate_promotion_provenance(&cached_fork.provenance, request.fork_block)?;
    let finding_id = finding_id(request.campaign_id, &request.artifact.input_id);
    let finding_dir = request.report_dir.join("findings").join(&finding_id);
    fs::create_dir_all(&finding_dir)?;

    let mut caveats = Vec::new();
    if request.synthetic_mode {
        caveats.push("synthetic fallback evidence; non-production and cannot be confirmed".into());
    }
    let input = request.corpus.load_input(&request.artifact.input_id)?;
    let fork_db = if request.synthetic_mode {
        request
            .corpus
            .load_offline_fork_db(&request.artifact.fork_cache_id)?
    } else {
        let live_fork = ForkDb::new(request.rpc_url, request.fork_block);
        let observed = live_fork.refresh_remote_provenance()?;
        let chain_id = observed
            .chain_id
            .ok_or_else(|| anyhow::anyhow!("live fork provenance is missing chain id"))?;
        let block_hash = observed
            .block_hash
            .ok_or_else(|| anyhow::anyhow!("live fork provenance is missing block hash"))?;
        request.corpus.load_online_fork_db(
            &request.artifact.fork_cache_id,
            request.fork_block,
            &observed.provider_sanitized,
            chain_id,
            &block_hash,
        )?
    };
    let base_db: EvmCacheDb = CacheDB::new(fork_db.clone());
    let verifier = ReplayVerifier::new(MAP_SIZE);
    let replay_result = verifier.verify_deterministic(
        &ChainState::Evm(CacheDB::new(fork_db)),
        request.block_env,
        &input,
    );

    let mut artifact_paths = BTreeMap::new();
    let mut lifecycle_stage: FindingLifecycleStage;
    let replay_status: String;
    let mut minimize_status = "not_run".to_string();
    let mut poc_status = "not_run".to_string();
    let mut evidence_hash = None;
    let mut evidence_hashes = None;
    let mut minimized_input = input.clone();
    let mut minimized_replay_execution = None;
    let mut minimized_replay_hash = None;
    let mut generated_poc_hash = None;
    let mut realism_proof = None;
    let mut policy_rejections = Vec::new();

    match replay_result {
        Ok(execution) => {
            let final_balances = verifier
                .replay_with_economic_views(
                    &ChainState::Evm(base_db.clone()),
                    request.block_env,
                    &input,
                    request.artifact.target,
                )
                .ok()
                .map(|result| result.after.token_balances)
                .unwrap_or_default();
            let replay_findings = ProtocolOraclePack::default().evaluate(&execution);
            let replay_report_value =
                replay_report(&input, &execution, &replay_findings, final_balances);
            let replay_path = finding_dir.join("replay.json");
            write_json(&replay_path, &replay_report_value)?;
            evidence_hash = Some(hash_file(&replay_path)?);
            artifact_paths.insert("replay".to_string(), replay_path.display().to_string());
            replay_status = "success".to_string();
            lifecycle_stage = FindingLifecycleStage::Replayed;

            let executor = EvmExecutor::new();
            let minimizer = Minimizer::new(
                &executor,
                &NullOracle,
                base_db.clone(),
                request.block_env.clone(),
            );
            let original_len = input.txs.len();
            let target_vuln = finding.as_ref().map(|finding| finding.vuln.clone());
            let minimized = minimizer.minimize_crash(&input, |candidate_execution| {
                promotion_predicate(candidate_execution, target_vuln.as_ref())
            });
            match minimized {
                Some(candidate) => {
                    minimized_input = candidate;
                    let minimized_len = minimized_input.txs.len();
                    minimize_status = if minimized_len < original_len {
                        "reduced".to_string()
                    } else {
                        "not_reducible".to_string()
                    };
                    lifecycle_stage = FindingLifecycleStage::Minimized;
                    let minimization_report = MinimizationPromotionReport {
                        status: minimize_status.clone(),
                        original_tx_count: original_len,
                        minimized_tx_count: minimized_len,
                        reason: if minimized_len < original_len {
                            "removed unnecessary transactions or calldata while preserving oracle evidence"
                                .to_string()
                        } else {
                            "original sequence already minimal for the current oracle predicate"
                                .to_string()
                        },
                    };
                    let min_report_path = finding_dir.join("minimization.json");
                    write_json(&min_report_path, &minimization_report)?;
                    artifact_paths.insert(
                        "minimization".to_string(),
                        min_report_path.display().to_string(),
                    );
                    let min_input_path = finding_dir.join("minimized_input.json");
                    write_json(&min_input_path, &minimized_input)?;
                    artifact_paths.insert(
                        "minimized_input".to_string(),
                        min_input_path.display().to_string(),
                    );
                }
                None => {
                    minimize_status = "failed".to_string();
                    caveats.push("minimization failed to preserve replayed oracle evidence".into());
                }
            }

            if minimize_status == "reduced" || minimize_status == "not_reducible" {
                let minimized_replay = verifier.verify_deterministic(
                    &ChainState::Evm(base_db.clone()),
                    request.block_env,
                    &minimized_input,
                );
                match minimized_replay {
                    Ok(execution) => {
                        let minimized_findings = ProtocolOraclePack::default().evaluate(&execution);
                        let minimized_report = replay_report(
                            &minimized_input,
                            &execution,
                            &minimized_findings,
                            Vec::new(),
                        );
                        let minimized_replay_path = finding_dir.join("minimized_replay.json");
                        write_json(&minimized_replay_path, &minimized_report)?;
                        minimized_replay_hash = Some(hash_file(&minimized_replay_path)?);
                        artifact_paths.insert(
                            "minimized_replay".to_string(),
                            minimized_replay_path.display().to_string(),
                        );
                        minimized_replay_execution = Some(execution);
                    }
                    Err(error) => {
                        let minimized_replay_path = finding_dir.join("minimized_replay.json");
                        write_json(
                            &minimized_replay_path,
                            &serde_json::json!({
                                "success": false,
                                "error": error.to_string(),
                            }),
                        )?;
                        artifact_paths.insert(
                            "minimized_replay".to_string(),
                            minimized_replay_path.display().to_string(),
                        );
                        caveats.push(format!("minimized sequence replay failed: {error:#}"));
                    }
                }
            }

            if (minimize_status == "reduced" || minimize_status == "not_reducible")
                && minimized_replay_execution.is_some()
            {
                if let Some(finding) = finding.as_ref() {
                    let poc_dir = request
                        .config
                        .poc_out
                        .as_deref()
                        .map(Path::new)
                        .unwrap_or(&finding_dir);
                    fs::create_dir_all(poc_dir)?;
                    match synthesize_foundry_poc_with_findings(
                        &minimized_input,
                        &finding.vuln,
                        minimized_replay_execution.as_ref(),
                        &request.artifact.findings,
                        poc_dir,
                        request.rpc_url,
                        request.fork_block,
                    ) {
                        Ok(path) => {
                            generated_poc_hash = Some(hash_file(Path::new(&path))?);
                            let validation = if request.config.external_foundry_opt_in {
                                validate_foundry_poc(
                                    Path::new(&path),
                                    &request.artifact.findings,
                                    request.report_dir,
                                )
                            } else {
                                PocValidationReport {
                                    success: false,
                                    static_assertions_present: true,
                                    transaction_replay_assertions_present: true,
                                    invariant_hook_present: true,
                                    forge_status: "skipped".to_string(),
                                    forge_command: None,
                                    stdout_snippet: String::new(),
                                    stderr_snippet: String::new(),
                                    reason: "Foundry runtime validation was skipped because external Foundry opt-in is disabled"
                                        .to_string(),
                                }
                            };
                            let validation_path = finding_dir.join("poc_validation.json");
                            write_json(&validation_path, &validation)?;
                            artifact_paths.insert(
                                "poc_validation".to_string(),
                                validation_path.display().to_string(),
                            );
                            if validation.success {
                                poc_status = "validated".to_string();
                                lifecycle_stage = FindingLifecycleStage::PocGenerated;
                            } else {
                                poc_status = "generated_unvalidated".to_string();
                                caveats.push(format!(
                                    "Foundry PoC scaffold generated but not accepted as proof: {}",
                                    validation.reason
                                ));
                            }
                            artifact_paths.insert("poc".to_string(), path);
                        }
                        Err(err) => {
                            poc_status = "failed".to_string();
                            caveats.push(format!(
                                "Foundry PoC generation failed; manual assertion required: {err:#}"
                            ));
                        }
                    }
                } else {
                    poc_status = "skipped".to_string();
                    caveats.push(
                        "manual assertion required; no replayed oracle finding available".into(),
                    );
                }
            }

            if let (Some(original_replay), Some(minimized_replay), Some(generated_poc)) = (
                evidence_hash.clone(),
                minimized_replay_hash,
                generated_poc_hash,
            ) {
                let minimized_input_path = artifact_paths
                    .get("minimized_input")
                    .ok_or_else(|| anyhow::anyhow!("minimized input evidence path is missing"))?;
                evidence_hashes = Some(PromotionEvidenceHashes {
                    original_replay,
                    minimized_input: hash_file(Path::new(minimized_input_path))?,
                    minimized_replay,
                    generated_poc,
                });
            }

            let realism = RealismVerifier::new(MAP_SIZE).prove(
                &ChainState::Evm(base_db.clone()),
                request.block_env,
                &minimized_input,
            );
            let realism_path = finding_dir.join("realism_proof.json");
            write_json(&realism_path, &realism)?;
            artifact_paths.insert(
                "realism_proof".to_string(),
                realism_path.display().to_string(),
            );
            if !realism.success {
                caveats.push(format!(
                    "realistic proof rejected candidate: {:?}",
                    realism.rejection_reasons
                ));
            }
            realism_proof = Some(realism);
        }
        Err(err) => {
            replay_status = "failed".to_string();
            lifecycle_stage = FindingLifecycleStage::Rejected;
            caveats.push(format!("deterministic replay failed: {err:#}"));
            let replay_path = finding_dir.join("replay.json");
            write_json(
                &replay_path,
                &serde_json::json!({
                    "success": false,
                    "error": err.to_string(),
                }),
            )?;
            artifact_paths.insert("replay".to_string(), replay_path.display().to_string());
        }
    }

    if lifecycle_stage == FindingLifecycleStage::PocGenerated
        && !request.synthetic_mode
        && (!request.config.require_poc_for_confirmed || poc_status == "validated")
        && replay_status == "success"
        && realism_proof.as_ref().is_some_and(|proof| proof.success)
    {
        lifecycle_stage = FindingLifecycleStage::Confirmed;
    }

    if request.synthetic_mode && lifecycle_stage == FindingLifecycleStage::Confirmed {
        lifecycle_stage = FindingLifecycleStage::PocGenerated;
    }

    let strict_proof = request.config.strict_proof;
    let no_synthetic_proof = request.config.no_synthetic_proof || strict_proof;
    let require_minimized = request.config.require_minimized || strict_proof;
    let require_foundry_poc = request.config.require_foundry_poc || strict_proof;
    let reject_heuristics = request.config.reject_heuristics || strict_proof;
    let minimized = minimize_status == "reduced" || minimize_status == "not_reducible";
    let realism_success = realism_proof.as_ref().is_some_and(|proof| proof.success);
    for finding in &request.artifact.findings {
        let oracle_rejections = oracle_rejection_reasons_for_finding(finding);
        if !oracle_rejections.is_empty() && (strict_proof || reject_heuristics) {
            policy_rejections.extend(oracle_rejections);
            caveats.push(format!(
                "oracle evidence failed strict precondition checks for {:?}",
                finding.vuln
            ));
        }
    }

    if no_synthetic_proof && request.synthetic_mode {
        policy_rejections.push(RejectionReason::SyntheticFundingRequired);
        caveats.push("strict proof rejected synthetic fallback evidence".to_string());
    }
    if require_minimized && !minimized {
        policy_rejections.push(RejectionReason::MinimizedAway);
        caveats.push("strict proof requires a minimized sequence".to_string());
    }
    if require_foundry_poc && poc_status != "validated" {
        policy_rejections.push(RejectionReason::OracleWeakness);
        caveats.push("strict proof requires a validated Foundry PoC artifact".to_string());
    }
    if reject_heuristics && (replay_status != "success" || !realism_success) {
        policy_rejections.push(if replay_status == "success" {
            RejectionReason::ReplayFailed
        } else {
            RejectionReason::OracleWeakness
        });
        caveats.push("strict proof rejects heuristic-only evidence".to_string());
    }
    if request.config.max_finding_noise == Some(0)
        && lifecycle_stage != FindingLifecycleStage::Confirmed
    {
        policy_rejections.push(RejectionReason::OracleWeakness);
        caveats.push("max finding noise is zero; non-proved finding rejected".to_string());
    }
    if !policy_rejections.is_empty() {
        lifecycle_stage = FindingLifecycleStage::Rejected;
    }

    let confidence = confidence_for(
        &lifecycle_stage,
        request.synthetic_mode,
        replay_status == "success",
        minimized,
        poc_status == "validated",
    );
    let status = status_for_lifecycle(
        &lifecycle_stage,
        replay_status == "success",
        minimized,
        poc_status == "validated" && realism_success,
    );
    let evidence_grade = realism_proof
        .as_ref()
        .map(|proof| proof.evidence_grade.clone())
        .unwrap_or_else(|| {
            if replay_status == "success" {
                EvidenceGrade::DeterministicReplay
            } else {
                EvidenceGrade::Heuristic
            }
        });
    let mut rejection_reasons = realism_proof
        .as_ref()
        .map(|proof| proof.rejection_reasons.clone())
        .unwrap_or_default();
    rejection_reasons.extend(policy_rejections);
    rejection_reasons.sort();
    rejection_reasons.dedup();

    require_replay_for_report(request.config, &replay_status)?;

    let record = FindingPromotionRecord {
        finding_id: finding_id.clone(),
        campaign_id: request.campaign_id.to_string(),
        input_id: request.artifact.input_id.clone(),
        fork_cache_id: request.artifact.fork_cache_id.clone(),
        target: request.artifact.target,
        fork_block: request.fork_block,
        vuln_type: finding
            .as_ref()
            .map(|finding| finding.vuln.to_string())
            .unwrap_or_else(|| "score-only".to_string()),
        severity: finding
            .as_ref()
            .map(|finding| finding.severity.clone())
            .unwrap_or(ProtocolSeverity::Info),
        confidence,
        status,
        evidence_grade,
        rejection_reasons,
        lifecycle_stage,
        replay_status,
        minimize_status,
        poc_status,
        evidence_hash,
        evidence_hashes,
        synthetic_mode: request.synthetic_mode,
        caveats,
        artifact_paths,
    };

    let finding_json = finding_dir.join("finding.json");
    write_json(&finding_json, &record)?;
    let finding_md = finding_dir.join("finding.md");
    write_atomic(
        &finding_md,
        finding_markdown(&record, finding.as_ref(), &minimized_input).as_bytes(),
    )?;
    log::info!(
        "Promoted finding: id={}, stage={:?}, confidence={}, report={}",
        record.finding_id,
        record.lifecycle_stage,
        record.confidence,
        finding_json.display()
    );
    Ok(record)
}

fn forge_version_is_unavailable(version: &std::io::Result<BoundedCommandOutput>) -> bool {
    match version {
        Ok(output) => output.timed_out,
        Err(_) => true,
    }
}

fn validate_foundry_poc(
    poc_path: &Path,
    findings: &[ProtocolFinding],
    project_root: &Path,
) -> PocValidationReport {
    let contents = match read_bounded_poc(poc_path) {
        Ok(contents) => contents,
        Err(error) => {
            return PocValidationReport {
                success: false,
                static_assertions_present: false,
                transaction_replay_assertions_present: false,
                invariant_hook_present: false,
                forge_status: "not_run".to_string(),
                forge_command: None,
                stdout_snippet: String::new(),
                stderr_snippet: redact_external_output(
                    error.to_string().as_bytes(),
                    MAX_EXTERNAL_OUTPUT_BYTES,
                ),
                reason: "generated PoC could not be read within the promotion file limit"
                    .to_string(),
            };
        }
    };

    let static_assertions_present =
        findings.is_empty() || contents.contains("assertRustyFuzzProtocolEvidence()");
    let transaction_replay_assertions_present = findings.iter().all(|finding| {
        finding
            .tx_index
            .map(|idx| contents.contains(&format!("assertTrue(ok{idx}")))
            .unwrap_or(true)
    });
    let invariant_hook_present = contents.contains("assertRustyFuzzInvariant()");
    let static_success = static_assertions_present
        && transaction_replay_assertions_present
        && invariant_hook_present;
    if !static_success {
        return PocValidationReport {
            success: false,
            static_assertions_present,
            transaction_replay_assertions_present,
            invariant_hook_present,
            forge_status: "not_run".to_string(),
            forge_command: None,
            stdout_snippet: String::new(),
            stderr_snippet: String::new(),
            reason: "generated PoC is missing replay, protocol, or invariant assertions"
                .to_string(),
        };
    }

    let mut version_command = Command::new("forge");
    version_command.arg("--version");
    let version = run_bounded_command(&mut version_command, MAX_EXTERNAL_COMMAND_TIMEOUT);
    if forge_version_is_unavailable(&version) {
        let stderr_snippet = match &version {
            Ok(output) => {
                let mut snippet = redact_external_output(&output.stderr, MAX_EXTERNAL_OUTPUT_BYTES);
                if output.timed_out {
                    if !snippet.is_empty() {
                        snippet.push('\n');
                    }
                    snippet.push_str("[Forge version timed out]");
                }
                snippet
            }
            Err(error) => {
                redact_external_output(error.to_string().as_bytes(), MAX_EXTERNAL_OUTPUT_BYTES)
            }
        };
        return PocValidationReport {
            success: false,
            static_assertions_present,
            transaction_replay_assertions_present,
            invariant_hook_present,
            forge_status: "unavailable".to_string(),
            forge_command: None,
            stdout_snippet: String::new(),
            stderr_snippet,
            reason: "static PoC validation passed; forge runtime validation was unavailable"
                .to_string(),
        };
    }

    let command_display = format!("forge test --match-path {}", poc_path.display());
    let mut command = Command::new("forge");
    command
        .arg("test")
        .arg("--match-path")
        .arg(poc_path)
        .current_dir(project_root);
    match run_bounded_command(&mut command, MAX_EXTERNAL_COMMAND_TIMEOUT) {
        Ok(output) => PocValidationReport {
            success: output.status.success() && !output.timed_out,
            static_assertions_present,
            transaction_replay_assertions_present,
            invariant_hook_present,
            forge_status: if output.status.success() && !output.timed_out {
                "passed".to_string()
            } else if output.timed_out {
                "timed_out".to_string()
            } else {
                "failed".to_string()
            },
            forge_command: Some(command_display),
            stdout_snippet: redact_external_output(&output.stdout, MAX_EXTERNAL_OUTPUT_BYTES),
            stderr_snippet: {
                let mut snippet = redact_external_output(&output.stderr, MAX_EXTERNAL_OUTPUT_BYTES);
                if output.timed_out {
                    if !snippet.is_empty() {
                        snippet.push('\n');
                    }
                    snippet.push_str("[Forge timed out]");
                }
                snippet
            },
            reason: if output.status.success() {
                "static and forge runtime validation passed".to_string()
            } else {
                "static validation passed, but forge runtime validation failed".to_string()
            },
        },
        Err(error) => PocValidationReport {
            success: false,
            static_assertions_present,
            transaction_replay_assertions_present,
            invariant_hook_present,
            forge_status: "failed_to_start".to_string(),
            forge_command: Some(command_display),
            stdout_snippet: String::new(),
            stderr_snippet: redact_external_output(
                error.to_string().as_bytes(),
                MAX_EXTERNAL_OUTPUT_BYTES,
            ),
            reason: "could not start forge runtime validation".to_string(),
        },
    }
}

fn read_bounded_poc(path: &Path) -> anyhow::Result<String> {
    let metadata = fs::metadata(path)?;
    anyhow::ensure!(
        metadata.len() <= MAX_PROMOTION_POC_BYTES as u64,
        "generated PoC exceeds the {MAX_PROMOTION_POC_BYTES} byte limit"
    );
    let file = fs::File::open(path)?;
    let mut limited = file.take(MAX_PROMOTION_POC_BYTES as u64 + 1);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::read_to_end(&mut limited, &mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_PROMOTION_POC_BYTES,
        "generated PoC exceeds the {MAX_PROMOTION_POC_BYTES} byte limit"
    );
    Ok(String::from_utf8(bytes)?)
}

pub fn write_campaign_summary(
    report_dir: &Path,
    summary: &PromotionCampaignSummary,
) -> anyhow::Result<()> {
    fs::create_dir_all(report_dir)?;
    let json_path = report_dir.join("campaign_summary.json");
    let md_path = report_dir.join("campaign_summary.md");
    write_json_atomic(&json_path, summary).map_err(anyhow::Error::from)?;
    write_atomic(&md_path, campaign_summary_markdown(summary).as_bytes())
        .map_err(anyhow::Error::from)?;
    fs::File::open(report_dir)?.sync_all()?;
    log::info!(
        "Campaign promotion summary written: {}, {}",
        json_path.display(),
        md_path.display()
    );
    Ok(())
}

pub fn write_campaign_status(report_dir: &Path, status: &impl Serialize) -> anyhow::Result<()> {
    fs::create_dir_all(report_dir)?;
    let status_path = report_dir.join("campaign_status.json");
    write_json_atomic(&status_path, status).map_err(anyhow::Error::from)?;
    fs::File::open(report_dir)?.sync_all()?;
    Ok(())
}

fn require_replay_for_report(config: &PromotionConfig, replay_status: &str) -> anyhow::Result<()> {
    if config.require_replay_for_report {
        anyhow::ensure!(
            replay_status == "success",
            "replay is required before writing a finding report"
        );
    }
    Ok(())
}

pub fn confidence_for(
    stage: &FindingLifecycleStage,
    synthetic_mode: bool,
    replayed: bool,
    minimized: bool,
    poc_generated: bool,
) -> u64 {
    let cap = if !replayed || *stage == FindingLifecycleStage::Candidate {
        40
    } else if poc_generated {
        90
    } else if minimized {
        80
    } else {
        65
    };
    if synthetic_mode || *stage == FindingLifecycleStage::Rejected {
        cap.min(40)
    } else {
        cap
    }
}

fn status_for_lifecycle(
    stage: &FindingLifecycleStage,
    replayed: bool,
    minimized: bool,
    poc_validated: bool,
) -> FindingStatus {
    match stage {
        FindingLifecycleStage::Rejected => FindingStatus::Rejected,
        FindingLifecycleStage::Confirmed if replayed && minimized && poc_validated => {
            FindingStatus::Proved
        }
        FindingLifecycleStage::PocGenerated | FindingLifecycleStage::Minimized => {
            FindingStatus::Minimized
        }
        FindingLifecycleStage::Replayed => FindingStatus::Replayed,
        FindingLifecycleStage::Candidate | FindingLifecycleStage::Confirmed => FindingStatus::Lead,
    }
}

fn promotion_predicate(
    execution: &SequenceExecutionResult,
    target_vuln: Option<&VulnType>,
) -> bool {
    let findings = ProtocolOraclePack::default().evaluate(execution);
    if let Some(target_vuln) = target_vuln {
        findings.iter().any(|finding| &finding.vuln == target_vuln)
    } else {
        !findings.is_empty()
    }
}

fn replay_report(
    input: &EvmInput,
    execution: &SequenceExecutionResult,
    findings: &[ProtocolFinding],
    final_balances: Vec<TokenBalanceView>,
) -> ReplayPromotionReport {
    let mut mismatches = Vec::new();
    if input.txs.len() != execution.tx_results.len() {
        mismatches.push(format!(
            "tx count mismatch: input={} replay={}",
            input.txs.len(),
            execution.tx_results.len()
        ));
    }
    ReplayPromotionReport {
        success: mismatches.is_empty(),
        tx_count: execution.tx_results.len(),
        expected_tx_count: input.txs.len(),
        final_coverage_hash: execution.final_coverage_hash,
        tx_statuses: execution
            .tx_results
            .iter()
            .map(|result| result.status.clone())
            .collect(),
        oracle_findings: findings.to_vec(),
        storage_diff_count: execution.storage_diffs.len(),
        storage_diffs: execution.storage_diffs.iter().take(128).cloned().collect(),
        call_trace_shape: execution
            .call_trace
            .iter()
            .take(64)
            .map(|call| {
                format!(
                    "{:?}:{}->{}:depth{}",
                    call.kind, call.caller, call.target, call.depth
                )
            })
            .collect(),
        call_trace: execution.call_trace.iter().take(128).cloned().collect(),
        final_balances,
        mismatches,
    }
}

fn finding_id(campaign_id: &str, input_id: &str) -> String {
    format!(
        "{}-{}",
        sanitize_component(campaign_id),
        sanitize_component(input_id)
    )
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    write_json_atomic(path, value)?;
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn hash_file(path: &Path) -> anyhow::Result<String> {
    Ok(hash_bytes(&fs::read(path)?))
}

fn finding_markdown(
    record: &FindingPromotionRecord,
    finding: Option<&ProtocolFinding>,
    input: &EvmInput,
) -> String {
    let txs = input
        .txs
        .iter()
        .enumerate()
        .map(|(idx, tx)| {
            format!(
                "{}. caller={} target={} value={} calldata=0x{}",
                idx + 1,
                tx.caller,
                tx.to,
                tx.value,
                hex::encode(&tx.input)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let evidence = finding
        .map(|finding| finding.evidence.clone())
        .unwrap_or_else(|| "score-only artifact; no oracle finding".to_string());
    let caveats = if record.caveats.is_empty() {
        "- none".to_string()
    } else {
        record
            .caveats
            .iter()
            .map(|caveat| format!("- {caveat}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let affected = affected_functions_markdown(input, finding);
    let root_cause = finding
        .map(|finding| root_cause_for(&finding.vuln))
        .unwrap_or("No protocol oracle finding survived into this promotion record.");
    let impact = finding
        .map(|finding| impact_for(&finding.vuln))
        .unwrap_or("No exploit impact is established.");
    let recommended_fix = finding
        .map(|finding| recommended_fix_for(&finding.vuln))
        .unwrap_or(
            "Add a detector-specific assertion before treating this artifact as a vulnerability.",
        );
    let false_positive_checks = false_positive_checks_markdown(record);
    let limitations = limitations_markdown(record);
    let severity_label = if record.status == FindingStatus::Proved {
        "Severity"
    } else {
        "Severity hint"
    };
    format!(
        "# RustyFuzz Finding {}\n\n## Summary\n{}\n\n## Status\n{:?}\n\n## {}\n{:?}\n\n## Confidence\n{}\n\n## Lifecycle stage\n{:?}\n\n## Target\n{:?}\n\n## Fork block\n{}\n\n## Affected contracts and functions\n{}\n\n## Root cause hypothesis\n{}\n\n## Impact\n{}\n\n## Transaction sequence\n{}\n\n## Oracle evidence\n{}\n\n## Storage and call evidence\n- replay: `{}`\n- minimized_input: `{}`\n- evidence_hash: `{}`\n\n## Replay result\n{}\n\n## Minimization result\n{}\n\n## Foundry PoC path\n{}\n\n## Reproduction commands\n`cargo run -- replay --input {}`\n\n## False-positive checks performed\n{}\n\n## Limitations\n{}\n\n## Recommended fix\n{}\n\n## Caveats\n{}\n",
        record.finding_id,
        record.vuln_type,
        record.status,
        severity_label,
        record.severity,
        record.confidence,
        record.lifecycle_stage,
        record.target,
        record.fork_block,
        affected,
        root_cause,
        impact,
        txs,
        evidence,
        record
            .artifact_paths
            .get("replay")
            .cloned()
            .unwrap_or_else(|| "not generated".to_string()),
        record
            .artifact_paths
            .get("minimized_input")
            .cloned()
            .unwrap_or_else(|| "not generated".to_string()),
        record
            .evidence_hash
            .clone()
            .unwrap_or_else(|| "not available".to_string()),
        record.replay_status,
        record.minimize_status,
        record
            .artifact_paths
            .get("poc")
            .cloned()
            .unwrap_or_else(|| "not generated".to_string()),
        record.input_id,
        false_positive_checks,
        limitations,
        recommended_fix,
        caveats
    )
}

fn affected_functions_markdown(input: &EvmInput, finding: Option<&ProtocolFinding>) -> String {
    let mut rows = Vec::new();
    for (idx, tx) in input.txs.iter().enumerate() {
        if finding
            .and_then(|finding| finding.tx_index)
            .is_some_and(|finding_idx| finding_idx != idx)
        {
            continue;
        }
        let selector = if tx.input.len() >= 4 {
            format!("0x{}", hex::encode(&tx.input[..4]))
        } else {
            "<fallback-or-empty-calldata>".to_string()
        };
        rows.push(format!(
            "- tx{} target={} selector={} caller={}",
            idx + 1,
            tx.to,
            selector,
            tx.caller
        ));
    }
    if rows.is_empty() {
        "- no selector-specific transaction evidence".to_string()
    } else {
        rows.join("\n")
    }
}

fn root_cause_for(vuln: &VulnType) -> &'static str {
    match vuln {
        VulnType::Reentrancy | VulnType::ReadOnlyReentrancy | VulnType::TokenCallbackReentrancy => {
            "External control is yielded before protocol accounting or invariant restoration is complete."
        }
        VulnType::VaultDonationAttack | VulnType::VaultInflation => {
            "Vault share/accounting math appears sensitive to donation or rounding-driven exchange-rate movement."
        }
        VulnType::PriceManipulation | VulnType::PriceOracleManipulation => {
            "A protocol decision appears dependent on a manipulable or insufficiently bounded price source."
        }
        VulnType::PrecisionLossExploit | VulnType::RoundingLeakage => {
            "Rounding, scaling, or interest-index precision appears to move value in the attacker-favorable direction."
        }
        VulnType::AccountingDesync | VulnType::CrossContractDesync => {
            "Internal accounting appears to diverge from observed token/value movement."
        }
        VulnType::PrivilegeEscalation
        | VulnType::ProxyUpgradeabilityViolation
        | VulnType::MissingSignerCheck => {
            "A non-privileged caller appears able to reach privileged state-changing behavior."
        }
        VulnType::GovernanceTakeover | VulnType::GovernanceParameterManipulation => {
            "Governance state appears mutable without the expected proposal, quorum, vote, queue, or timelock preconditions."
        }
        VulnType::BridgeInvariantViolation => {
            "Bridge/message state appears replayable, finalized on the wrong domain, or finalized without valid prerequisite evidence."
        }
        VulnType::FlashLoanProfit | VulnType::FlashLoanAttack => {
            "Temporary liquidity appears to create an extractive state transition that survives repayment."
        }
        VulnType::InvariantViolation(_) => {
            "A configured target invariant was violated by the replayed transaction sequence."
        }
        VulnType::UnintendedPanic(_) => {
            "Execution reached a panic/assertion path that may represent a broken protocol invariant."
        }
        _ => "The oracle emitted protocol evidence that needs detector-specific review.",
    }
}

fn impact_for(vuln: &VulnType) -> &'static str {
    match vuln {
        VulnType::PrivilegeEscalation
        | VulnType::ProxyUpgradeabilityViolation
        | VulnType::MissingSignerCheck => {
            "Unauthorized administrative mutation, upgrade, pause, role grant, or parameter control."
        }
        VulnType::VaultDonationAttack
        | VulnType::VaultInflation
        | VulnType::PrecisionLossExploit
        | VulnType::RoundingLeakage
        | VulnType::AccountingDesync => {
            "Potential value extraction or protocol accounting loss."
        }
        VulnType::PriceManipulation | VulnType::PriceOracleManipulation => {
            "Potential mispricing, bad debt, unfair liquidation, or value extraction through dependent protocol actions."
        }
        VulnType::GovernanceTakeover | VulnType::GovernanceParameterManipulation => {
            "Potential protocol parameter takeover or unauthorized governance execution."
        }
        VulnType::BridgeInvariantViolation => {
            "Potential double mint/release, wrong-domain finalization, or message replay."
        }
        VulnType::FlashLoanProfit | VulnType::FlashLoanAttack => {
            "Potential atomic profit or solvency damage enabled by temporary liquidity."
        }
        VulnType::Reentrancy | VulnType::ReadOnlyReentrancy | VulnType::TokenCallbackReentrancy => {
            "Potential stale-accounting exploitation, repeated withdrawal, or manipulated downstream reads."
        }
        _ => "Impact requires manual review of replay evidence and generated PoC assertions.",
    }
}

fn recommended_fix_for(vuln: &VulnType) -> &'static str {
    match vuln {
        VulnType::Reentrancy | VulnType::ReadOnlyReentrancy | VulnType::TokenCallbackReentrancy => {
            "Apply checks-effects-interactions, reentrancy guards where appropriate, and restore accounting before external calls."
        }
        VulnType::VaultDonationAttack | VulnType::VaultInflation => {
            "Use ERC-4626 inflation-resistant share math, minimum share checks, virtual offsets, and donation-aware accounting."
        }
        VulnType::PriceManipulation | VulnType::PriceOracleManipulation => {
            "Use manipulation-resistant oracles, TWAP/median bounds, staleness checks, and action-level price movement limits."
        }
        VulnType::PrecisionLossExploit | VulnType::RoundingLeakage => {
            "Audit scale factors and rounding direction; bound index growth and round against attacker-favorable flows."
        }
        VulnType::AccountingDesync | VulnType::CrossContractDesync => {
            "Credit only actual received amounts, reconcile internal accounting with token balances, and handle fee-on-transfer behavior."
        }
        VulnType::PrivilegeEscalation
        | VulnType::ProxyUpgradeabilityViolation
        | VulnType::MissingSignerCheck => {
            "Gate privileged selectors with explicit role checks and protect initializer/upgrade paths on proxy and implementation contracts."
        }
        VulnType::GovernanceTakeover | VulnType::GovernanceParameterManipulation => {
            "Enforce proposal lifecycle, quorum, snapshot vote weight, queue delay, timelock, and one-time execution."
        }
        VulnType::BridgeInvariantViolation => {
            "Bind proofs to domain, nonce, message hash, and consumed-state; reject duplicate or wrong-domain finalization."
        }
        _ => "Derive the fix from the replayed invariant violation and add regression tests around the minimized sequence.",
    }
}

fn false_positive_checks_markdown(record: &FindingPromotionRecord) -> String {
    let checks = [
        (
            "deterministic replay",
            record.replay_status == "success",
            &record.replay_status,
        ),
        (
            "minimization preserved evidence",
            matches!(record.minimize_status.as_str(), "reduced" | "not_reducible"),
            &record.minimize_status,
        ),
        (
            "Foundry PoC validated",
            record.poc_status == "validated",
            &record.poc_status,
        ),
    ];
    checks
        .iter()
        .map(|(name, passed, status)| {
            format!(
                "- {}: {} ({})",
                name,
                if *passed { "passed" } else { "not passed" },
                status
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn limitations_markdown(record: &FindingPromotionRecord) -> String {
    let mut limitations = Vec::new();
    if record.status != FindingStatus::Proved {
        limitations.push("finding is not confirmed; severity is only a hint");
    }
    if record.synthetic_mode {
        limitations.push("synthetic fallback evidence is non-production");
    }
    if record.evidence_hash.is_none() {
        limitations.push("replay evidence hash is unavailable");
    }
    if record.poc_status != "validated" {
        limitations.push("generated PoC did not pass forge validation");
    }
    if limitations.is_empty() {
        "- none for the current proof pipeline".to_string()
    } else {
        limitations
            .into_iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn campaign_summary_markdown(summary: &PromotionCampaignSummary) -> String {
    format!(
        "# RustyFuzz Campaign Summary\n\n- campaign_id: `{}`\n- total_executions: `{}`\n- mutated_inputs: `{}`\n- seed_replays: `{}`\n- total_artifacts: `{}`\n- coverage_edges: `{}`\n- confirmed_vulnerabilities: `{}`\n- interesting_candidates: `{}`\n- candidate_findings: `{}`\n- promoted_findings: `{}`\n- confirmed_findings: `{}`\n- rejected_candidates: `{}`\n- unproven_candidates: `{}`\n- poc_count: `{}`\n- missing_poc_for_promoted: `{}`\n- replay_failure_count: `{}`\n- synthetic_non_production_findings: `{}`\n- highest_confidence: `{}`\n- minimization_attempts: `{}`\n- minimization_reduced: `{}`\n- minimization_not_reducible: `{}`\n- promotion_capped: `{}`\n\nSuccess definition: no replay-confirmed finding means no confirmed vulnerability; no passing PoC means the issue is not bounty-grade confirmed.\n",
        summary.campaign_id,
        summary.total_executions,
        summary.mutated_inputs,
        summary.seed_replays,
        summary.total_artifacts,
        summary.coverage_edges,
        summary.confirmed_findings,
        summary.interesting_candidates,
        summary.candidate_findings,
        summary.promoted_findings,
        summary.confirmed_findings,
        summary.rejected_candidates,
        summary.unproven_candidates,
        summary.poc_count,
        summary.missing_poc_for_promoted,
        summary.replay_failure_count,
        summary.synthetic_non_production_findings,
        summary.highest_confidence,
        summary.minimization_attempts,
        summary.minimization_reduced,
        summary.minimization_not_reducible,
        summary.promotion_capped
    )
}

struct NullOracle;

impl crate::common::oracle::VulnerabilityOracle for NullOracle {
    fn check(&self, _before: &Snapshot, _after: &Snapshot) -> Option<VulnType> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forge_version_timeout_is_unavailable() {
        let status = Command::new("sh")
            .args(["-c", "exit 0"])
            .status()
            .expect("create a local process status");
        let timed_out = crate::satori::fsutil::BoundedCommandOutput {
            status,
            timed_out: true,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        };
        assert!(forge_version_is_unavailable(&Ok(timed_out)));
        assert!(forge_version_is_unavailable(&Err(std::io::Error::other(
            "forge is unavailable"
        ))));
    }

    #[test]
    fn promotion_forge_output_is_bounded_and_redacted() {
        let output = redact_external_output(
            b"Authorization: Bearer super-secret\nhttps://rpc.example/v1?apikey=url-secret",
            MAX_EXTERNAL_OUTPUT_BYTES,
        );
        assert!(!output.contains("super-secret"));
        assert!(!output.contains("url-secret"));
        assert!(output.contains("<redacted>"));
    }

    #[test]
    fn promotion_poc_reader_rejects_oversized_files() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!(
            "rustyfuzz-promotion-poc-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&path, vec![b'x'; MAX_PROMOTION_POC_BYTES + 1])?;
        assert!(read_bounded_poc(&path).is_err());
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn replay_report_gate_rejects_failed_replay_when_enabled() {
        let config = PromotionConfig {
            require_replay_for_report: true,
            ..PromotionConfig::default()
        };
        assert!(require_replay_for_report(&config, "failed").is_err());
        assert!(require_replay_for_report(&config, "success").is_ok());
        let mut optional = config;
        optional.require_replay_for_report = false;
        assert!(require_replay_for_report(&optional, "failed").is_ok());
    }

    #[test]
    fn confidence_caps_follow_lifecycle() {
        assert_eq!(
            confidence_for(
                &FindingLifecycleStage::Candidate,
                false,
                false,
                false,
                false
            ),
            40
        );
        assert_eq!(
            confidence_for(&FindingLifecycleStage::Replayed, false, true, false, false),
            65
        );
        assert_eq!(
            confidence_for(&FindingLifecycleStage::Minimized, false, true, true, false),
            80
        );
        assert_eq!(
            confidence_for(
                &FindingLifecycleStage::PocGenerated,
                false,
                true,
                true,
                true
            ),
            90
        );
        assert_eq!(
            confidence_for(&FindingLifecycleStage::PocGenerated, true, true, true, true),
            40
        );
    }

    #[test]
    fn synthetic_record_cannot_be_confirmed_by_confidence() {
        assert!(confidence_for(&FindingLifecycleStage::Confirmed, true, true, true, true) <= 40);
    }

    #[test]
    fn status_requires_full_validation_for_confirmed() {
        assert_eq!(
            status_for_lifecycle(&FindingLifecycleStage::Candidate, false, false, false),
            FindingStatus::Lead
        );
        assert_eq!(
            status_for_lifecycle(&FindingLifecycleStage::PocGenerated, true, true, true),
            FindingStatus::Minimized
        );
        assert_eq!(
            status_for_lifecycle(&FindingLifecycleStage::Confirmed, true, true, true),
            FindingStatus::Proved
        );
        assert_eq!(
            status_for_lifecycle(&FindingLifecycleStage::Confirmed, true, true, false),
            FindingStatus::Lead
        );
        assert_eq!(
            status_for_lifecycle(&FindingLifecycleStage::Rejected, false, false, false),
            FindingStatus::Rejected
        );
    }

    #[test]
    fn campaign_summary_counts_candidates_confirmed_and_rejected_separately() {
        let stats = PromotionCampaignStats::default();
        let confirmed = FindingPromotionRecord {
            finding_id: "confirmed".to_string(),
            campaign_id: "campaign".to_string(),
            input_id: "input-1".to_string(),
            fork_cache_id: "fork-1".to_string(),
            target: None,
            fork_block: 1,
            vuln_type: "reentrancy".to_string(),
            severity: ProtocolSeverity::High,
            confidence: 90,
            status: FindingStatus::Proved,
            evidence_grade: EvidenceGrade::RealisticForkProof,
            rejection_reasons: Vec::new(),
            lifecycle_stage: FindingLifecycleStage::Confirmed,
            replay_status: "success".to_string(),
            minimize_status: "reduced".to_string(),
            poc_status: "validated".to_string(),
            evidence_hash: Some("sha256:test".to_string()),
            evidence_hashes: None,
            synthetic_mode: false,
            caveats: Vec::new(),
            artifact_paths: BTreeMap::new(),
        };
        let mut rejected = confirmed.clone();
        rejected.finding_id = "rejected".to_string();
        rejected.status = FindingStatus::Rejected;
        rejected.lifecycle_stage = FindingLifecycleStage::Rejected;
        rejected.replay_status = "failed".to_string();
        rejected.poc_status = "not_run".to_string();
        let mut candidate = confirmed.clone();
        candidate.finding_id = "candidate".to_string();
        candidate.status = FindingStatus::Minimized;
        candidate.lifecycle_stage = FindingLifecycleStage::Minimized;
        candidate.poc_status = "generated_unvalidated".to_string();

        stats.record(&confirmed);
        stats.record(&rejected);
        stats.record(&candidate);

        let summary = stats.summary("campaign", 10, 7, 3, 5, 12);
        assert_eq!(summary.total_executions, 10);
        assert_eq!(summary.mutated_inputs, 7);
        assert_eq!(summary.seed_replays, 3);
        assert_eq!(summary.promoted_findings, 3);
        assert_eq!(summary.confirmed_findings, 1);
        assert_eq!(summary.rejected_candidates, 1);
        assert_eq!(summary.candidate_findings, 1);
        assert_eq!(summary.unproven_candidates, 4);
        assert_eq!(summary.poc_count, 1);
    }

    #[test]
    fn capped_id_count_survives_poisoned_mutex() {
        let stats = PromotionCampaignStats::default();
        let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = stats.capped_ids.lock().expect("poison capped id mutex");
            panic!("poison capped id mutex");
        }));
        assert!(poison_result.is_err());

        stats.record_capped("finding-1");
        stats.record_capped("finding-1");
        stats.record_capped("finding-2");

        assert_eq!(stats.promotion_capped_count(), 2);
    }

    #[test]
    fn finding_markdown_labels_unconfirmed_severity_and_evidence_hash() {
        let record = FindingPromotionRecord {
            finding_id: "candidate".to_string(),
            campaign_id: "campaign".to_string(),
            input_id: "input-1".to_string(),
            fork_cache_id: "fork-1".to_string(),
            target: Some(Address::repeat_byte(0x22)),
            fork_block: 1,
            vuln_type: "VaultInflation".to_string(),
            severity: ProtocolSeverity::High,
            confidence: 80,
            status: FindingStatus::Minimized,
            evidence_grade: EvidenceGrade::DeterministicReplay,
            rejection_reasons: Vec::new(),
            lifecycle_stage: FindingLifecycleStage::Minimized,
            replay_status: "success".to_string(),
            minimize_status: "not_reducible".to_string(),
            poc_status: "generated_unvalidated".to_string(),
            evidence_hash: Some("sha256:abc".to_string()),
            evidence_hashes: None,
            synthetic_mode: false,
            caveats: Vec::new(),
            artifact_paths: BTreeMap::new(),
        };
        let input = EvmInput {
            txs: Vec::new(),
            base_snapshot_id: 0,
        };

        let markdown = finding_markdown(&record, None, &input);
        assert!(markdown.contains("## Severity hint"));
        assert!(markdown.contains("sha256:abc"));
        assert!(markdown.contains("## Root cause hypothesis"));
        assert!(markdown.contains("## Recommended fix"));
    }

    #[test]
    fn stage_2d_promotion_pipeline_transitions_are_canonical_legal() {
        use rustyfuzz_core::FindingLifecycle;

        // The exact transition sequence used by the promotion pipeline maps
        // onto legal canonical transitions. PoC generation does not advance
        // proof; Confirmed is policy-gated Proved.
        let steps = [
            FindingLifecycleStage::Candidate,
            FindingLifecycleStage::Replayed,
            FindingLifecycleStage::Minimized,
            FindingLifecycleStage::PocGenerated,
            FindingLifecycleStage::Confirmed,
        ];
        for pair in steps.windows(2) {
            let from = pair[0].canonical();
            let to = pair[1].canonical();
            assert!(
                from.can_transition(to),
                "illegal promotion transition {:?} -> {:?}",
                pair[0],
                pair[1]
            );
        }
        // Rejection path stays available from any intermediate stage.
        for stage in &steps[..steps.len() - 1] {
            assert!(stage.canonical().can_transition(FindingLifecycle::Rejected));
        }
    }

    #[test]
    fn stage_2d_oracle_signal_maps_to_signal_not_proved() {
        use rustyfuzz_core::FindingLifecycle;

        // Freshly detected findings hold status Lead, canonically Signal; the
        // trust model forbids jumping to Proved without deterministic stages.
        let lead = FindingStatus::default();
        assert_eq!(lead.canonical(), FindingLifecycle::Signal);
        assert!(lead
            .canonical()
            .transition(FindingLifecycle::Proved)
            .is_err());
    }
}
