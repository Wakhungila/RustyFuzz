use crate::common::oracle::{ProtocolFinding, ProtocolOraclePack, ProtocolSeverity, VulnType};
use crate::common::types::{
    CallObservation, ChainState, ExecutionStatus, SequenceExecutionResult, Snapshot, StorageDiff,
};
use crate::common::verifier::ReplayVerifier;
use crate::engine::exploit_synthesizer::synthesize_foundry_poc_with_findings;
use crate::engine::minimizer::Minimizer;
use crate::evm::corpus::{CampaignArtifactRecord, PersistentCorpus};
use crate::evm::executor::EvmExecutor;
use crate::evm::fork_db::EvmCacheDb;
use crate::evm::fuzz::EvmInput;
use crate::evm::inspector::MAP_SIZE;
use crate::engine::economic_delta::TokenBalanceView;
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionConfig {
    pub enabled: bool,
    pub require_replay_for_report: bool,
    pub require_poc_for_confirmed: bool,
    pub promotion_limit: Option<u64>,
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_replay_for_report: true,
            require_poc_for_confirmed: true,
            promotion_limit: None,
        }
    }
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
    pub lifecycle_stage: FindingLifecycleStage,
    pub replay_status: String,
    pub minimize_status: String,
    pub poc_status: String,
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
    pub total_artifacts: u64,
    #[serde(default)]
    pub coverage_edges: u64,
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
}

#[derive(Debug, Default)]
pub struct PromotionCampaignStats {
    promoted_ids: Mutex<BTreeSet<String>>,
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
}

impl PromotionCampaignStats {
    pub fn promoted_count(&self) -> u64 {
        self.promoted_findings.load(Ordering::Relaxed)
    }

    pub fn reserve_promotion(&self, finding_id: &str) -> bool {
        self.promoted_ids
            .lock()
            .expect("promotion id lock poisoned")
            .insert(finding_id.to_string())
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
        total_artifacts: u64,
        coverage_edges: u64,
    ) -> PromotionCampaignSummary {
        PromotionCampaignSummary {
            campaign_id: campaign_id.into(),
            total_executions,
            total_artifacts,
            coverage_edges,
            promoted_findings: self.promoted_findings.load(Ordering::Relaxed),
            confirmed_findings: self.confirmed_findings.load(Ordering::Relaxed),
            rejected_candidates: self.rejected_candidates.load(Ordering::Relaxed),
            synthetic_non_production_findings: self
                .synthetic_non_production_findings
                .load(Ordering::Relaxed),
            highest_confidence: self.highest_confidence.load(Ordering::Relaxed),
            poc_count: self.poc_count.load(Ordering::Relaxed),
            replay_failure_count: self.replay_failure_count.load(Ordering::Relaxed),
            minimization_attempts: self.minimization_attempts.load(Ordering::Relaxed),
            minimization_reduced: self.minimization_reduced.load(Ordering::Relaxed),
            minimization_not_reducible: self.minimization_not_reducible.load(Ordering::Relaxed),
        }
    }
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
        !request.artifact.findings.is_empty(),
        "refusing to promote score-only artifact input_id={} without oracle/protocol finding evidence",
        request.artifact.input_id
    );
    let finding = request.artifact.findings.first().cloned();
    let finding_id = finding_id(request.campaign_id, &request.artifact.input_id);
    let finding_dir = request.report_dir.join("findings").join(&finding_id);
    fs::create_dir_all(&finding_dir)?;

    let mut caveats = Vec::new();
    if request.synthetic_mode {
        caveats.push("synthetic fallback evidence; non-production and cannot be confirmed".into());
    }
    let input = request.corpus.load_input(&request.artifact.input_id)?;
    let fork_db = request
        .corpus
        .load_offline_fork_db(&request.artifact.fork_cache_id)?;
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
    let mut minimized_input = input.clone();

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
            let replay_report = replay_report(&input, &execution, &replay_findings, final_balances);
            let replay_path = finding_dir.join("replay.json");
            write_json(&replay_path, &replay_report)?;
            artifact_paths.insert("replay".to_string(), replay_path.display().to_string());
            replay_status = "success".to_string();
            lifecycle_stage = FindingLifecycleStage::Replayed;

            let executor = EvmExecutor::new();
            let minimizer =
                Minimizer::new(&executor, &NullOracle, base_db, request.block_env.clone());
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
                if let Some(finding) = finding.as_ref() {
                    match synthesize_foundry_poc_with_findings(
                        &minimized_input,
                        &finding.vuln,
                        Some(&execution),
                        &request.artifact.findings,
                        &finding_dir,
                        request.rpc_url,
                        request.fork_block,
                    ) {
                        Ok(path) => {
                            let validation = validate_foundry_poc(
                                Path::new(&path),
                                &request.artifact.findings,
                                request.report_dir,
                            );
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
    {
        lifecycle_stage = FindingLifecycleStage::Confirmed;
    }

    if request.synthetic_mode && lifecycle_stage == FindingLifecycleStage::Confirmed {
        lifecycle_stage = FindingLifecycleStage::PocGenerated;
    }

    let confidence = confidence_for(
        &lifecycle_stage,
        request.synthetic_mode,
        replay_status == "success",
        minimize_status == "reduced" || minimize_status == "not_reducible",
        poc_status == "validated",
    );

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
        lifecycle_stage,
        replay_status,
        minimize_status,
        poc_status,
        synthetic_mode: request.synthetic_mode,
        caveats,
        artifact_paths,
    };

    let finding_json = finding_dir.join("finding.json");
    write_json(&finding_json, &record)?;
    let finding_md = finding_dir.join("finding.md");
    fs::write(
        &finding_md,
        finding_markdown(&record, finding.as_ref(), &minimized_input),
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

fn validate_foundry_poc(
    poc_path: &Path,
    findings: &[ProtocolFinding],
    project_root: &Path,
) -> PocValidationReport {
    let contents = match fs::read_to_string(poc_path) {
        Ok(contents) => contents,
        Err(err) => {
            return PocValidationReport {
                success: false,
                static_assertions_present: false,
                transaction_replay_assertions_present: false,
                invariant_hook_present: false,
                forge_status: "not_run".to_string(),
                forge_command: None,
                stdout_snippet: String::new(),
                stderr_snippet: String::new(),
                reason: format!("could not read generated PoC: {err:#}"),
            };
        }
    };

    let static_assertions_present =
        findings.is_empty() || contents.contains("assertRustyFuzzProtocolEvidence()");
    let transaction_replay_assertions_present =
        findings.iter().all(|finding| {
            finding
                .tx_index
                .map(|idx| contents.contains(&format!("assertTrue(ok{idx}")))
                .unwrap_or(true)
        });
    let invariant_hook_present = contents.contains("assertRustyFuzzInvariant()");
    let static_success =
        static_assertions_present && transaction_replay_assertions_present && invariant_hook_present;
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
            reason: "generated PoC is missing replay, protocol, or invariant assertions".to_string(),
        };
    }

    if Command::new("forge").arg("--version").output().is_err() {
        return PocValidationReport {
            success: false,
            static_assertions_present,
            transaction_replay_assertions_present,
            invariant_hook_present,
            forge_status: "unavailable".to_string(),
            forge_command: None,
            stdout_snippet: String::new(),
            stderr_snippet: "forge is not installed or not on PATH".to_string(),
            reason: "static PoC validation passed; forge runtime validation was unavailable"
                .to_string(),
        };
    }

    if std::env::var("ETH_RPC_URL").unwrap_or_default().is_empty() {
        return PocValidationReport {
            success: false,
            static_assertions_present,
            transaction_replay_assertions_present,
            invariant_hook_present,
            forge_status: "skipped_missing_eth_rpc_url".to_string(),
            forge_command: None,
            stdout_snippet: String::new(),
            stderr_snippet: "ETH_RPC_URL is required by generated fork-replay PoCs".to_string(),
            reason: "static PoC validation passed; forge runtime validation needs ETH_RPC_URL"
                .to_string(),
        };
    }

    let command = format!("forge test --match-path {}", poc_path.display());
    match Command::new("forge")
        .arg("test")
        .arg("--match-path")
        .arg(poc_path)
        .current_dir(project_root)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            PocValidationReport {
                success: output.status.success(),
                static_assertions_present,
                transaction_replay_assertions_present,
                invariant_hook_present,
                forge_status: if output.status.success() {
                    "passed".to_string()
                } else {
                    "failed".to_string()
                },
                forge_command: Some(command),
                stdout_snippet: snippet(&stdout),
                stderr_snippet: snippet(&stderr),
                reason: if output.status.success() {
                    "static and forge runtime validation passed".to_string()
                } else {
                    "static validation passed, but forge runtime validation failed".to_string()
                },
            }
        }
        Err(err) => PocValidationReport {
            success: false,
            static_assertions_present,
            transaction_replay_assertions_present,
            invariant_hook_present,
            forge_status: "failed_to_start".to_string(),
            forge_command: Some(command),
            stdout_snippet: String::new(),
            stderr_snippet: err.to_string(),
            reason: "could not start forge runtime validation".to_string(),
        },
    }
}

fn snippet(value: &str) -> String {
    const LIMIT: usize = 800;
    if value.len() <= LIMIT {
        value.to_string()
    } else {
        value.chars().take(LIMIT).collect()
    }
}

pub fn write_campaign_summary(
    report_dir: &Path,
    summary: &PromotionCampaignSummary,
) -> anyhow::Result<()> {
    fs::create_dir_all(report_dir)?;
    let json_path = report_dir.join("campaign_summary.json");
    write_json(&json_path, summary)?;
    let md_path = report_dir.join("campaign_summary.md");
    fs::write(&md_path, campaign_summary_markdown(summary))?;
    log::info!(
        "Campaign promotion summary written: {}, {}",
        json_path.display(),
        md_path.display()
    );
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
    if synthetic_mode {
        cap.min(40)
    } else if *stage == FindingLifecycleStage::Rejected {
        cap.min(40)
    } else {
        cap
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
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
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
    format!(
        "# RustyFuzz Finding {}\n\n## Summary\n{}\n\n## Severity\n{:?}\n\n## Confidence\n{}\n\n## Lifecycle stage\n{:?}\n\n## Target\n{:?}\n\n## Fork block\n{}\n\n## Transaction sequence\n{}\n\n## Oracle evidence\n{}\n\n## Storage diffs\nSee replay.json and minimized_input.json.\n\n## Call trace highlights\nSee replay.json.\n\n## Replay result\n{}\n\n## Minimization result\n{}\n\n## Foundry PoC path\n{}\n\n## Reproduction commands\n`cargo run -- replay --input {}`\n\n## Caveats\n{}\n",
        record.finding_id,
        record.vuln_type,
        record.severity,
        record.confidence,
        record.lifecycle_stage,
        record.target,
        record.fork_block,
        txs,
        evidence,
        record.replay_status,
        record.minimize_status,
        record
            .artifact_paths
            .get("poc")
            .cloned()
            .unwrap_or_else(|| "not generated".to_string()),
        record.input_id,
        caveats
    )
}

fn campaign_summary_markdown(summary: &PromotionCampaignSummary) -> String {
    format!(
        "# RustyFuzz Campaign Summary\n\n- campaign_id: `{}`\n- total_executions: `{}`\n- total_artifacts: `{}`\n- coverage_edges: `{}`\n- promoted_findings: `{}`\n- confirmed_findings: `{}`\n- rejected_candidates: `{}`\n- synthetic_non_production_findings: `{}`\n- highest_confidence: `{}`\n- poc_count: `{}`\n- replay_failure_count: `{}`\n- minimization_attempts: `{}`\n- minimization_reduced: `{}`\n- minimization_not_reducible: `{}`\n",
        summary.campaign_id,
        summary.total_executions,
        summary.total_artifacts,
        summary.coverage_edges,
        summary.promoted_findings,
        summary.confirmed_findings,
        summary.rejected_candidates,
        summary.synthetic_non_production_findings,
        summary.highest_confidence,
        summary.poc_count,
        summary.replay_failure_count,
        summary.minimization_attempts,
        summary.minimization_reduced,
        summary.minimization_not_reducible
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
}
