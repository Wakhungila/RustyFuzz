use crate::common::fs_security::validate_job_bounds;
use crate::common::types::SingletonTx;
use crate::config::HardenedDefiConfig;
use crate::engine::fuzz_engine;
use crate::engine::promotion::{
    FindingLifecycleStage, FindingPromotionRecord, PromotionCampaignSummary, PromotionConfig,
};
use crate::evm::corpus::PersistentCorpus;
use crate::evm::fuzz::{EvmInput, MAX_SEQUENCE_LENGTH};
use crate::evm::seed_ingester::{MainnetSeed, MainnetSeedBundle, SeedMetadata};
use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{
    canonical_run_dir_path, read_dir_under, read_json_in_run, validate_identifier,
};
use crate::satori::types::{ProofStatus, RustyFuzzJobSpec, ValidationStatus, ValidationVerdict};
use revm::primitives::{Address, U256};
use rustyfuzz_evm::fork_db::ForkDbCacheSnapshot;
use rustyfuzz_evm::rpc_url::validate_production_rpc_url;
use std::path::Path;
use std::str::FromStr;

pub fn has_direct_rustyfuzz_context(job: &RustyFuzzJobSpec) -> bool {
    job.target_contract.is_some() && job.fork_rpc_url.is_some() && job.fork_block.is_some()
}

const MAX_HYPOTHESIS_FIELD_BYTES: usize = 1_024;
const MAX_HYPOTHESIS_CALLDATA_BYTES: usize = 8_192;
const REQUIRED_SEED_PROVENANCE: &str = "rustyfuzz:required-seed";

#[derive(Debug, Clone, PartialEq, Eq)]
enum SequenceResolutionError {
    Missing(String),
    Invalid(String),
}

impl SequenceResolutionError {
    fn status(&self) -> ValidationStatus {
        match self {
            Self::Missing(_) => ValidationStatus::NeedsMoreContext,
            Self::Invalid(_) => ValidationStatus::ValidationFailed,
        }
    }

    fn reason(&self) -> String {
        match self {
            Self::Missing(detail) => format!("hypothesis sequence needs more context: {detail}"),
            Self::Invalid(detail) => format!("hypothesis sequence validation failed: {detail}"),
        }
    }
}

fn resolve_hypothesis_sequence(
    job: &RustyFuzzJobSpec,
    target: Address,
) -> Result<EvmInput, SequenceResolutionError> {
    if job.sequence_template.is_empty() {
        return Err(SequenceResolutionError::Missing(
            "attack sequence is empty".to_string(),
        ));
    }
    if job.sequence_template.len() > MAX_SEQUENCE_LENGTH
        || job.sequence_template.len() > job.max_depth
    {
        return Err(SequenceResolutionError::Invalid(format!(
            "attack sequence length {} exceeds max_depth {} or engine limit {}",
            job.sequence_template.len(),
            job.max_depth,
            MAX_SEQUENCE_LENGTH
        )));
    }

    let mut txs = Vec::with_capacity(job.sequence_template.len());
    for (index, step) in job.sequence_template.iter().enumerate() {
        let actor = required_field(&step.actor, "actor", index)?;
        let caller = parse_address(&actor, "actor", index)?;
        let action = required_field(&step.action, "action", index)?;
        if action.is_empty() {
            return Err(SequenceResolutionError::Invalid(format!(
                "step {index} has an empty action"
            )));
        }
        let target = match step.target.as_deref() {
            Some(value) => parse_address(value, "target", index)?,
            None => target,
        };
        if target == Address::ZERO {
            return Err(SequenceResolutionError::Invalid(format!(
                "step {index} resolves to the zero target"
            )));
        }
        let calldata = match step.calldata_hint.as_deref() {
            Some(value) => parse_calldata(value, index)?,
            None => {
                return Err(SequenceResolutionError::Missing(format!(
                    "step {index} has no explicit hex calldata"
                )))
            }
        };
        let value = match step.value_hint.as_deref() {
            Some(value) => parse_value(value, index)?,
            None => U256::ZERO,
        };
        txs.push(SingletonTx {
            input: calldata,
            caller,
            to: target,
            value,
            is_victim: false,
        });
    }

    let input = EvmInput::new(txs, 0);
    if !input.validate() {
        return Err(SequenceResolutionError::Invalid(
            "resolved EvmInput exceeded engine bounds".to_string(),
        ));
    }
    Ok(input)
}

fn required_field(
    value: &str,
    field: &str,
    index: usize,
) -> Result<String, SequenceResolutionError> {
    if value.len() > MAX_HYPOTHESIS_FIELD_BYTES {
        return Err(SequenceResolutionError::Invalid(format!(
            "step {index} {field} exceeds {MAX_HYPOTHESIS_FIELD_BYTES} bytes"
        )));
    }
    let value = value.trim();
    if value.is_empty() {
        return Err(SequenceResolutionError::Missing(format!(
            "step {index} has no {field}"
        )));
    }
    Ok(value.to_string())
}

fn parse_address(
    value: &str,
    field: &str,
    index: usize,
) -> Result<Address, SequenceResolutionError> {
    let value = required_field(value, field, index)?;
    Address::from_str(&value).map_err(|_| {
        SequenceResolutionError::Invalid(format!(
            "step {index} {field} must be a 20-byte 0x address"
        ))
    })
}

fn parse_calldata(value: &str, index: usize) -> Result<Vec<u8>, SequenceResolutionError> {
    let value = required_field(value, "calldata", index)?;
    let value = value.strip_prefix("0x").ok_or_else(|| {
        SequenceResolutionError::Invalid(format!("step {index} calldata must start with 0x"))
    })?;
    if value.len() % 2 != 0 || value.len() / 2 > MAX_HYPOTHESIS_CALLDATA_BYTES {
        return Err(SequenceResolutionError::Invalid(format!(
            "step {index} calldata is not even-length hex within {MAX_HYPOTHESIS_CALLDATA_BYTES} bytes"
        )));
    }
    hex::decode(value).map_err(|_| {
        SequenceResolutionError::Invalid(format!("step {index} calldata is not valid hex"))
    })
}

fn parse_value(value: &str, index: usize) -> Result<U256, SequenceResolutionError> {
    let value = required_field(value, "value", index)?;
    let parsed = if let Some(hex_value) = value.strip_prefix("0x") {
        U256::from_str_radix(hex_value, 16)
    } else {
        U256::from_str_radix(&value, 10)
    };
    parsed.map_err(|_| {
        SequenceResolutionError::Invalid(format!("step {index} value is not a bounded uint256"))
    })
}

fn persist_required_seed_bundle(
    corpus_dir: &Path,
    bundle_id: &str,
    fork_block: u64,
    target: Address,
    input: &EvmInput,
) -> SatoriResult<()> {
    let sequence_hash = input.semantic_input_hash();
    let mut fork_cache = ForkDbCacheSnapshot {
        block_tag: fork_block.to_string(),
        accounts: Vec::new(),
        code_by_hash: Vec::new(),
        storage: Vec::new(),
        block_hashes: Vec::new(),
        provenance: Default::default(),
        content_digest: String::new(),
    };
    fork_cache.content_digest = fork_cache
        .calculate_content_digest()
        .map_err(|error| anyhow::anyhow!("could not digest required seed fork cache: {error}"))?;
    let bundle = MainnetSeedBundle {
        fork_block,
        target,
        seeds: vec![MainnetSeed {
            id: format!("sequence-{sequence_hash}"),
            input: input.clone(),
            metadata: SeedMetadata {
                source_block: fork_block,
                block_offset: 0,
                transaction_ordinal: 0,
                caller: input
                    .txs
                    .first()
                    .map(|tx| tx.caller)
                    .unwrap_or(Address::ZERO),
                target,
                value: input.txs.first().map(|tx| tx.value).unwrap_or(U256::ZERO),
                selector: input
                    .txs
                    .first()
                    .and_then(|tx| tx.input.get(0..4))
                    .and_then(|bytes| bytes.try_into().ok()),
                calldata_len: input.txs.iter().map(|tx| tx.input.len()).sum(),
                discovered_address_hints: Vec::new(),
                matched_target: Some(target),
                match_kind: Some("satori-required-sequence".to_string()),
                confidence: Some(100),
                provenance: Some(format!("{REQUIRED_SEED_PROVENANCE}:{sequence_hash}")),
                decoded: None,
                tx_hash: None,
                top_level_caller: input.txs.first().map(|tx| tx.caller),
                internal_caller: None,
                trace_path: None,
                trace_source: None,
            },
        }],
        discovered_accounts: Vec::new(),
        fork_cache,
        scan: None,
    };
    PersistentCorpus::new(corpus_dir)?.persist_mainnet_seed_bundle(bundle_id, &bundle)?;
    Ok(())
}

fn required_seed_replay_verified(run_dir: &Path, marker_path: &Path, sequence_hash: &str) -> bool {
    let Ok(relative) = marker_path.strip_prefix(run_dir) else {
        return false;
    };
    let Ok(marker) = read_json_in_run::<serde_json::Value>(run_dir, relative) else {
        return false;
    };
    marker.get("completed").and_then(serde_json::Value::as_bool) == Some(true)
        && marker
            .get("sequence_hash")
            .and_then(serde_json::Value::as_str)
            == Some(sequence_hash)
}

pub async fn execute_bounded_job(
    job: &RustyFuzzJobSpec,
    run_dir: &Path,
) -> SatoriResult<ValidationVerdict> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    validate_job_limits(job)?;
    let target = match job
        .target_contract
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("job target contract is missing"))
        .and_then(|value| Address::from_str(value).map_err(Into::into))
    {
        Ok(target) => target,
        Err(error) => {
            return Ok(ValidationVerdict {
                hypothesis_id: job.hypothesis_id.clone(),
                job_id: Some(job.job_id.clone()),
                status: ValidationStatus::NeedsMoreContext,
                proof_status: ProofStatus::HeuristicOnly,
                reason: format!(
                    "hypothesis sequence target is not a concrete address: {error}; generic fuzzing was not started"
                ),
                artifacts: Vec::new(),
                economic_impact: None,
                confidence_after_validation: 0.0,
            });
        }
    };
    let required_sequence = match resolve_hypothesis_sequence(job, target) {
        Ok(input) => input,
        Err(error) => {
            return Ok(ValidationVerdict {
                hypothesis_id: job.hypothesis_id.clone(),
                job_id: Some(job.job_id.clone()),
                status: error.status(),
                proof_status: ProofStatus::HeuristicOnly,
                reason: format!("{}; generic fuzzing was not started", error.reason()),
                artifacts: Vec::new(),
                economic_impact: None,
                confidence_after_validation: 0.0,
            });
        }
    };
    let sequence_hash = required_sequence.semantic_input_hash();
    let rpc_url = job
        .fork_rpc_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("job fork RPC is missing"))?;
    let fork_block = job
        .fork_block
        .ok_or_else(|| anyhow::anyhow!("job fork block is missing"))?;
    let job_id = job.job_id.clone();
    validate_identifier(&job_id)?;
    let run_id = format!(
        "{job_id}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| anyhow::anyhow!("validation run clock failed: {error}"))?
            .as_nanos()
    );
    let job_root = run_dir
        .join("jobs")
        .join(&job_id)
        .join("runs")
        .join(&run_id);
    let report_dir = job_root.join("reports");
    let corpus_dir = job_root.join("corpus");
    persist_required_seed_bundle(
        &corpus_dir,
        "satori-sequence",
        fork_block,
        target,
        &required_sequence,
    )?;
    let hardened = HardenedDefiConfig {
        enabled: true,
        single_process: true,
        deterministic: true,
        rng_seed: Some(0),
        enable_bounded_search: true,
        ..HardenedDefiConfig::default()
    };
    let campaign_id = format!("satori-{job_id}-{}-{}", run_id, hypothesis_fingerprint(job));
    let config = fuzz_engine::Config {
        rpc_url: rpc_url.to_string(),
        fork_block,
        target_contract: Some(target),
        corpus_dir: corpus_dir.to_string_lossy().into_owned(),
        report_dir: report_dir.to_string_lossy().into_owned(),
        foundry_harness: None,
        mainnet_seed_bundle: Some("satori-sequence".to_string()),
        in_memory_bytecode: None,
        cores: None,
        require_seed_bundle: true,
        require_rpc_fork: true,
        allow_synthetic_fallback: false,
        hardened_defi: hardened,
        target_invariant_manifest: None,
        abi_path: None,
        max_execs: Some(job.max_execs),
        duration_secs: Some(job.duration_secs),
        artifact_limit: Some(128),
        campaign_id: Some(campaign_id.clone()),
        paths_are_isolated: true,
        min_finding_confidence: 0,

        promotion: PromotionConfig {
            enabled: true,
            no_promotion: false,
            require_replay_for_report: true,
            require_poc_for_confirmed: true,
            strict_proof: true,
            no_synthetic_proof: true,
            require_foundry_poc: true,
            require_minimized: true,
            reject_heuristics: true,
            max_finding_noise: Some(0),
            poc_out: None,
            promotion_limit: Some(8),
        },
    };

    let execution_result =
        tokio::task::spawn_blocking(move || fuzz_engine::run_fuzz_campaign_blocking(config))
            .await
            .map_err(|error| anyhow::anyhow!("bounded campaign worker failed: {error}"))?;
    if let Err(error) = execution_result {
        return Ok(ValidationVerdict {
            hypothesis_id: job.hypothesis_id.clone(),
            job_id: Some(job.job_id.clone()),
            status: ValidationStatus::ValidationFailed,
            proof_status: ProofStatus::NotReproducible,
            reason: format!("bounded RustyFuzz execution failed: {error}"),
            artifacts: vec![job_root],
            economic_impact: None,
            confidence_after_validation: 0.0,
        });
    }
    let replay_marker_path = report_dir.join("required_seed_replay.json");
    if !required_seed_replay_verified(&run_dir, &replay_marker_path, &sequence_hash) {
        return Ok(ValidationVerdict {
            hypothesis_id: job.hypothesis_id.clone(),
            job_id: Some(job.job_id.clone()),
            status: ValidationStatus::ValidationFailed,
            proof_status: ProofStatus::NotReproducible,
            reason: "bounded engine did not prove execution of the resolved hypothesis sequence before generic fuzzing".to_string(),
            artifacts: vec![replay_marker_path],
            economic_impact: None,
            confidence_after_validation: 0.0,
        });
    }

    let persisted_sequence_id =
        PersistentCorpus::new(&corpus_dir)?.resolve_input_id(&required_sequence)?;
    let summary_path = report_dir.join("campaign_summary.json");
    let summary: PromotionCampaignSummary = match read_json_in_run(
        &run_dir,
        summary_path.strip_prefix(&run_dir).map_err(|_| {
            anyhow::anyhow!("campaign summary path is outside the Satori run directory")
        })?,
    ) {
        Ok(summary) => summary,
        Err(error) => {
            return Ok(ValidationVerdict {
                hypothesis_id: job.hypothesis_id.clone(),
                job_id: Some(job.job_id.clone()),
                status: ValidationStatus::ValidationFailed,
                proof_status: ProofStatus::NotReproducible,
                reason: error.to_string(),
                artifacts: vec![summary_path],
                economic_impact: None,
                confidence_after_validation: 0.0,
            });
        }
    };

    let findings_dir = report_dir.join("findings");
    let records = tokio::task::spawn_blocking(move || load_finding_records(&findings_dir))
        .await
        .map_err(|error| anyhow::anyhow!("finding artifact reader failed: {error}"))??;
    let matching_records = records
        .iter()
        .filter(|record| {
            finding_matches_job(job, record, target, &campaign_id, &persisted_sequence_id)
        })
        .collect::<Vec<_>>();
    let confirmed_matches = matching_records
        .iter()
        .filter(|record| record.lifecycle_stage == FindingLifecycleStage::Confirmed)
        .count();
    let candidate_matches = matching_records
        .iter()
        .filter(|record| record.lifecycle_stage == FindingLifecycleStage::Candidate)
        .count();

    let (status, proof_status, reason, confidence) = bounded_verdict_classification(
        &matching_records,
        confirmed_matches,
        candidate_matches,
        &summary,
    );

    Ok(ValidationVerdict {
        hypothesis_id: job.hypothesis_id.clone(),
        job_id: Some(job.job_id.clone()),
        status,
        proof_status,
        reason,
        artifacts: vec![replay_marker_path, summary_path],
        economic_impact: None,
        confidence_after_validation: confidence,
    })
}

fn bounded_verdict_classification(
    matching_records: &[&FindingPromotionRecord],
    confirmed_matches: usize,
    candidate_matches: usize,
    summary: &PromotionCampaignSummary,
) -> (ValidationStatus, ProofStatus, String, f64) {
    if confirmed_matches > 0 {
        return (
            ValidationStatus::ValidatedMinimized,
            ProofStatus::Minimized,
            format!(
                "bounded execution produced {confirmed_matches} matching independently replayed, minimized, PoC-validated findings"
            ),
            0.90,
        );
    }
    if matching_records.is_empty() {
        return (
            ValidationStatus::PlausibleUnvalidated,
            ProofStatus::HeuristicOnly,
            "bounded execution completed without a matching finding or persisted required-sequence artifact; unrelated campaign signals do not invalidate the hypothesis"
                .to_string(),
            0.0,
        );
    }
    if summary.rejected_candidates > 0 || summary.replay_failure_count > 0 {
        return (
            ValidationStatus::ValidationFailed,
            ProofStatus::NotReproducible,
            "bounded execution produced rejected candidates or replay failures; no matching independent confirmation"
                .to_string(),
            0.0,
        );
    }
    if candidate_matches > 0 {
        return (
            ValidationStatus::RustyFuzzSignal,
            ProofStatus::RustyFuzzSignal,
            format!("bounded execution produced {candidate_matches} matching unconfirmed findings; independent promotion did not confirm them"),
            0.49,
        );
    }
    (
        ValidationStatus::PlausibleUnvalidated,
        ProofStatus::HeuristicOnly,
        "bounded execution completed without a matching confirmed signal; score-only artifacts are not findings"
            .to_string(),
        0.0,
    )
}

fn confirmed_record_has_complete_evidence(record: &FindingPromotionRecord) -> bool {
    record.lifecycle_stage != FindingLifecycleStage::Confirmed
        || (!record.synthetic_mode
            && record.replay_status == "success"
            && record.poc_status == "validated"
            && matches!(record.minimize_status.as_str(), "reduced" | "not_reducible")
            && record.evidence_hash.is_some()
            && record.evidence_hashes.is_some())
}

fn verify_record_evidence(
    record: &FindingPromotionRecord,
    findings_root: &Path,
) -> SatoriResult<()> {
    let hashes = record
        .evidence_hashes
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("confirmed finding is missing content evidence digests"))?;
    let verify = |name: &str, path: Option<&String>, expected: &str| -> SatoriResult<()> {
        let path = path
            .ok_or_else(|| anyhow::anyhow!("confirmed finding is missing {name} artifact path"))?;
        let actual = format!(
            "sha256:{}",
            crate::satori::fsutil::sha256_hex(&crate::satori::fsutil::read_evidence_file(
                findings_root,
                Path::new(path)
            )?)
        );
        anyhow::ensure!(
            actual == expected,
            "confirmed finding {name} digest mismatch: expected {expected}, got {actual}"
        );
        Ok(())
    };
    anyhow::ensure!(
        record.evidence_hash.as_deref() == Some(hashes.original_replay.as_str()),
        "confirmed finding legacy evidence hash is not bound to the original replay digest"
    );
    verify(
        "original replay",
        record.artifact_paths.get("replay"),
        &hashes.original_replay,
    )?;
    verify(
        "minimized input",
        record.artifact_paths.get("minimized_input"),
        &hashes.minimized_input,
    )?;
    verify(
        "minimized replay",
        record.artifact_paths.get("minimized_replay"),
        &hashes.minimized_replay,
    )?;
    verify(
        "generated PoC",
        record.artifact_paths.get("poc"),
        &hashes.generated_poc,
    )?;
    Ok(())
}

fn load_finding_records(findings_dir: &Path) -> SatoriResult<Vec<FindingPromotionRecord>> {
    let mut records = Vec::new();
    if !findings_dir.exists() {
        return Ok(records);
    }
    let entries = read_dir_under(findings_dir, findings_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path().join("finding.json");
        let record: FindingPromotionRecord =
            crate::satori::fsutil::read_json_under(findings_dir, &path)?;
        if !confirmed_record_has_complete_evidence(&record) {
            return Err(anyhow::anyhow!(
                "confirmed finding record lacks complete replay, minimization, PoC, and evidence provenance"
            ));
        }
        if record.lifecycle_stage == FindingLifecycleStage::Confirmed {
            verify_record_evidence(&record, findings_dir)?;
        }
        records.push(record);
    }
    Ok(records)
}

fn validate_job_limits(job: &RustyFuzzJobSpec) -> SatoriResult<()> {
    validate_job_bounds(Some(job.max_execs), Some(job.duration_secs))
        .map_err(anyhow::Error::msg)?;
    validate_identifier(&job.job_id)?;
    if let Some(rpc_url) = job.fork_rpc_url.as_deref() {
        validate_production_rpc_url(rpc_url).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn hypothesis_fingerprint(job: &RustyFuzzJobSpec) -> String {
    let payload = serde_json::to_vec(job).unwrap_or_default();
    crate::satori::fsutil::sha256_hex(&payload)
}

fn finding_matches_job(
    job: &RustyFuzzJobSpec,
    record: &FindingPromotionRecord,
    target: Address,
    campaign_id: &str,
    persisted_sequence_id: &str,
) -> bool {
    record.campaign_id == campaign_id
        && record.input_id == persisted_sequence_id
        && record.target == Some(target)
        && bug_classes_match(&job.bug_class, &record.vuln_type)
}

fn bug_classes_match(job_class: &str, finding_type: &str) -> bool {
    let job_class = crate::satori::memory::bug_class::normalize_bug_class(job_class);
    let finding_type = crate::satori::memory::bug_class::normalize_bug_class(finding_type);
    let matches = |expected: &[&str]| expected.iter().any(|value| finding_type.contains(value));
    match job_class.as_str() {
        "access_control" => matches(&["privilege_escalation"]),
        "erc4626_share_inflation" | "share_inflation" | "vault_inflation" => {
            matches(&["vault_inflation", "share_inflation"])
        }
        "erc20_mint_inflation"
        | "mint_policy_violation"
        | "mint_authorization_policy_violation"
        | "erc20_mint_policy_violation" => matches(&[
            "mint_authorization_policy_violation",
            "mint_policy_violation",
            "mint_inflation",
        ]),
        "lending" | "lending_bad_debt" | "bad_debt" => {
            matches(&["lending", "bad_debt", "debt_accounting"])
        }
        "amm" | "amm_reserve_desync" | "liquidity_asymmetry" => {
            matches(&["uniswap", "liquidity", "amm"])
        }
        "bridge" | "bridge_message_replay" => matches(&["bridge", "replay"]),
        "timelock_delay_bypass" | "governance_reinitialization_takeover" => {
            matches(&["governance", "timelock"])
        }
        _ => job_class == finding_type,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::{
        AttackStep, CandidateInvariant, ValidationStep, VulnerabilityHypothesis,
    };
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn no_matching_required_sequence_is_unvalidated_even_with_unrelated_rejections() {
        let summary = PromotionCampaignSummary {
            rejected_candidates: 1,
            replay_failure_count: 1,
            ..Default::default()
        };
        let (status, proof_status, _, confidence) =
            bounded_verdict_classification(&[], 0, 0, &summary);
        assert_eq!(status, ValidationStatus::PlausibleUnvalidated);
        assert_eq!(proof_status, ProofStatus::HeuristicOnly);
        assert_eq!(confidence, 0.0);
    }

    #[test]
    fn finding_class_matching_rejects_unrelated_confirmed_finding() {
        assert!(bug_classes_match("access_control", "privilege_escalation"));
        assert!(bug_classes_match("share_inflation", "vault_inflation"));
        assert!(bug_classes_match(
            "mint_policy_violation",
            "mint_authorization_policy_violation"
        ));
        assert!(bug_classes_match(
            "erc20_mint_inflation",
            "mint_policy_violation"
        ));
        assert!(!bug_classes_match("access_control", "vault_inflation"));
    }

    #[test]
    fn hypothesis_fingerprint_changes_with_sequence() {
        let hypothesis = VulnerabilityHypothesis {
            id: "h1".to_string(),
            title: "x".to_string(),
            bug_class: "access_control".to_string(),
            root_cause: "x".to_string(),
            affected_contracts: vec!["0x0000000000000000000000000000000000000001".to_string()],
            affected_functions: vec!["withdraw()".to_string()],
            evidence_from_context: vec![],
            required_conditions: vec![],
            attack_sequence: vec![AttackStep {
                actor: "attacker".to_string(),
                action: "withdraw".to_string(),
                target: None,
                calldata_hint: None,
                value_hint: None,
            }],
            false_positive_checks: vec![],
            validation_plan: vec![],
            suggested_invariants: vec![],
            rustyfuzz_objective: "x".to_string(),
            confidence_before_validation: 0.4,
        };
        let job = crate::satori::jobs::job_from_hypothesis(&hypothesis);
        let mut changed = job.clone();
        changed.sequence_template[0].action = "deposit".to_string();
        assert_ne!(
            hypothesis_fingerprint(&job),
            hypothesis_fingerprint(&changed)
        );
    }

    #[test]
    fn sequence_resolution_requires_explicit_executable_fields() {
        let hypothesis = VulnerabilityHypothesis {
            id: "h1".to_string(),
            title: "x".to_string(),
            bug_class: "access_control".to_string(),
            root_cause: "x".to_string(),
            affected_contracts: vec!["0x0000000000000000000000000000000000000001".to_string()],
            affected_functions: vec!["withdraw()".to_string()],
            evidence_from_context: vec![],
            required_conditions: vec![],
            attack_sequence: vec![AttackStep {
                actor: "0x0000000000000000000000000000000000000011".to_string(),
                action: "withdraw".to_string(),
                target: None,
                calldata_hint: None,
                value_hint: None,
            }],
            false_positive_checks: vec![],
            validation_plan: vec![],
            suggested_invariants: vec![],
            rustyfuzz_objective: "x".to_string(),
            confidence_before_validation: 0.4,
        };
        let job = crate::satori::jobs::job_from_hypothesis(&hypothesis);
        let error = resolve_hypothesis_sequence(
            &job,
            Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.status(), ValidationStatus::NeedsMoreContext);
    }

    #[test]
    fn finding_matching_is_bound_to_the_resolved_sequence_hash() {
        let hypothesis = VulnerabilityHypothesis {
            id: "h1".to_string(),
            title: "x".to_string(),
            bug_class: "access_control".to_string(),
            root_cause: "x".to_string(),
            affected_contracts: vec!["0x0000000000000000000000000000000000000001".to_string()],
            affected_functions: vec!["withdraw()".to_string()],
            evidence_from_context: vec![],
            required_conditions: vec![],
            attack_sequence: vec![AttackStep {
                actor: "0x0000000000000000000000000000000000000011".to_string(),
                action: "withdraw".to_string(),
                target: Some("0x0000000000000000000000000000000000000001".to_string()),
                calldata_hint: Some("0x1234".to_string()),
                value_hint: Some("2".to_string()),
            }],
            false_positive_checks: vec![],
            validation_plan: vec![],
            suggested_invariants: vec![],
            rustyfuzz_objective: "x".to_string(),
            confidence_before_validation: 0.4,
        };
        let job = crate::satori::jobs::job_from_hypothesis(&hypothesis);
        let target = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let input = resolve_hypothesis_sequence(&job, target).unwrap();
        let corpus_dir = std::env::temp_dir().join(format!(
            "satori-persisted-sequence-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let corpus = PersistentCorpus::new(&corpus_dir).unwrap();
        let metadata = corpus.persist_input(&input, &[], 0).unwrap();
        assert_ne!(metadata.id, input.semantic_input_hash());
        assert_eq!(corpus.resolve_input_id(&input).unwrap(), metadata.id);
        assert_eq!(corpus.load_input(&metadata.id).unwrap(), input);
        let mut record = FindingPromotionRecord {
            finding_id: "f1".to_string(),
            campaign_id: "campaign".to_string(),
            input_id: metadata.id.clone(),
            fork_cache_id: "cache".to_string(),
            target: Some(target),
            fork_block: 1,
            vuln_type: "privilege_escalation".to_string(),
            severity: crate::common::oracle::ProtocolSeverity::High,
            confidence: 1,
            status: Default::default(),
            evidence_grade: Default::default(),
            rejection_reasons: vec![],
            lifecycle_stage: FindingLifecycleStage::Candidate,
            replay_status: "success".to_string(),
            minimize_status: "not_run".to_string(),
            poc_status: "not_run".to_string(),
            evidence_hash: Some("hash".to_string()),
            evidence_hashes: Some(crate::engine::promotion::PromotionEvidenceHashes {
                original_replay: "hash".to_string(),
                minimized_input: "hash".to_string(),
                minimized_replay: "hash".to_string(),
                generated_poc: "hash".to_string(),
            }),
            synthetic_mode: false,
            caveats: vec![],
            artifact_paths: Default::default(),
        };
        assert!(finding_matches_job(
            &job,
            &record,
            target,
            "campaign",
            &metadata.id
        ));
        let mut confirmed = record.clone();
        confirmed.lifecycle_stage = FindingLifecycleStage::Confirmed;
        confirmed.replay_status = "success".to_string();
        confirmed.minimize_status = "not_reducible".to_string();
        confirmed.poc_status = "validated".to_string();
        assert!(confirmed_record_has_complete_evidence(&confirmed));
        confirmed.minimize_status = "reduced".to_string();
        assert!(confirmed_record_has_complete_evidence(&confirmed));
        confirmed.minimize_status = "failed".to_string();
        assert!(!confirmed_record_has_complete_evidence(&confirmed));
        record.input_id = "0xdead".to_string();
        assert!(!finding_matches_job(
            &job,
            &record,
            target,
            "campaign",
            &metadata.id
        ));
        std::fs::remove_dir_all(corpus_dir).unwrap();
    }

    #[test]
    fn confirmed_evidence_verification_binds_every_artifact_digest() {
        let root = std::env::temp_dir().join(format!(
            "satori-evidence-digests-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let files = [
            ("replay", b"replay-content".as_slice()),
            ("minimized_input", b"input-content".as_slice()),
            ("minimized_replay", b"minimized-replay-content".as_slice()),
            ("poc", b"poc-content".as_slice()),
        ];
        let mut artifact_paths = BTreeMap::new();
        let mut evidence_hashes = crate::engine::promotion::PromotionEvidenceHashes {
            original_replay: String::new(),
            minimized_input: String::new(),
            minimized_replay: String::new(),
            generated_poc: String::new(),
        };
        for (name, content) in files {
            let path = root.join(name);
            std::fs::write(&path, content).unwrap();
            let digest = format!("sha256:{}", crate::satori::fsutil::sha256_hex(content));
            artifact_paths.insert(name.to_string(), path.display().to_string());
            match name {
                "replay" => evidence_hashes.original_replay = digest,
                "minimized_input" => evidence_hashes.minimized_input = digest,
                "minimized_replay" => evidence_hashes.minimized_replay = digest,
                "poc" => evidence_hashes.generated_poc = digest,
                _ => unreachable!(),
            }
        }
        let record = FindingPromotionRecord {
            finding_id: "finding".to_string(),
            campaign_id: "campaign".to_string(),
            input_id: "input".to_string(),
            fork_cache_id: "cache".to_string(),
            target: None,
            fork_block: 1,
            vuln_type: "reentrancy".to_string(),
            severity: crate::common::oracle::ProtocolSeverity::High,
            confidence: 90,
            status: crate::common::oracle::FindingStatus::Proved,
            evidence_grade: Default::default(),
            rejection_reasons: vec![],
            lifecycle_stage: FindingLifecycleStage::Confirmed,
            replay_status: "success".to_string(),
            minimize_status: "reduced".to_string(),
            poc_status: "validated".to_string(),
            evidence_hash: Some(evidence_hashes.original_replay.clone()),
            evidence_hashes: Some(evidence_hashes),
            synthetic_mode: false,
            caveats: vec![],
            artifact_paths,
        };
        verify_record_evidence(&record, &root).unwrap();
        std::fs::write(root.join("poc"), b"tampered").unwrap();
        assert!(verify_record_evidence(&record, &root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn direct_context_requires_target_rpc_and_block() {
        let hypothesis = VulnerabilityHypothesis {
            id: "h1".to_string(),
            title: "x".to_string(),
            bug_class: "access_control".to_string(),
            root_cause: "x".to_string(),
            affected_contracts: vec!["0x0000000000000000000000000000000000000001".to_string()],
            affected_functions: vec!["withdraw()".to_string()],
            evidence_from_context: vec!["public withdraw".to_string()],
            required_conditions: Vec::new(),
            attack_sequence: vec![AttackStep {
                actor: "attacker".to_string(),
                action: "withdraw".to_string(),
                target: None,
                calldata_hint: None,
                value_hint: None,
            }],
            false_positive_checks: Vec::new(),
            validation_plan: vec![ValidationStep {
                tool: "foundry".to_string(),
                action: "compile".to_string(),
                success_condition: "x".to_string(),
            }],
            suggested_invariants: vec![CandidateInvariant {
                id: "i1".to_string(),
                description: "x".to_string(),
                check: "x".to_string(),
                expected_signal: "x".to_string(),
            }],
            rustyfuzz_objective: "x".to_string(),
            confidence_before_validation: 0.4,
        };
        let mut job = crate::satori::jobs::job_from_hypothesis(&hypothesis);
        assert!(!has_direct_rustyfuzz_context(&job));
        job.target_contract = Some("0x0000000000000000000000000000000000000001".to_string());
        job.fork_rpc_url = Some("http://127.0.0.1:8545".to_string());
        job.fork_block = Some(1);
        assert!(has_direct_rustyfuzz_context(&job));
    }
}
