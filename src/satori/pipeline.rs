use crate::common::fs_security::ensure_path_contained;
use crate::satori::analysis::analyze_project;
use crate::satori::budget::BudgetTracker;
use crate::satori::cache::ResponseCache;
use crate::satori::error::SatoriResult;
use crate::satori::fsutil::redact_source_text;
use crate::satori::fsutil::{
    canonical_run_dir, canonical_run_dir_path, canonical_run_root, ensure_dir, new_run_id_checked,
    read_dir_under, read_json_in_run, safe_identifier_path, validate_identifier,
    verify_source_file_binding, write_json_in_run,
};
use crate::satori::graph::build_graph;
use crate::satori::ingest::ingest_project;
use crate::satori::jobs::job_from_hypothesis;
use crate::satori::memory::false_positive::has_minimum_evidence;
use crate::satori::memory::MemoryStore;
use crate::satori::packets::{build_function_packets, build_repo_packet};
use crate::satori::reasoning::parser::parse_strict_json;
use crate::satori::reasoning::prompts::load_prompt;
use crate::satori::reasoning::zen_client::ZenClient;
use crate::satori::report::write_reports;
use crate::satori::types::{
    FunctionAuditResult, FunctionPacket, ProjectModel, ProtocolModel, RustyFuzzJobSpec,
    SatoriConfig, SatoriReport, SatoriRun, StaticAnalysisBundle, VulnerabilityHypothesis,
};
use crate::satori::validation::validate_jobs_async;
use chrono::Utc;
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::path::Path;

pub struct PipelineArtifacts {
    pub run: SatoriRun,
    pub project: ProjectModel,
    pub analysis: StaticAnalysisBundle,
}

pub fn create_run(path: &Path, config: SatoriConfig) -> SatoriResult<SatoriRun> {
    let runs_root = canonical_run_root()?;
    let mut run = None;
    for _ in 0..16 {
        let run_id = new_run_id_checked("satori")?;
        let run_dir = safe_identifier_path(&runs_root, &run_id)?;
        match std::fs::create_dir(&run_dir) {
            Ok(()) => {
                run = Some((run_id, run_dir));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (run_id, run_dir) =
        run.ok_or_else(|| anyhow::anyhow!("failed to reserve a unique Satori run directory"))?;
    ensure_dir(&config.cache_dir)?;
    if let Some(parent) = config.memory_path.parent() {
        ensure_dir(parent)?;
    }
    crate::satori::fsutil::reject_symlink_components(path)?;
    let root = path.canonicalize()?;
    anyhow::ensure!(root.is_dir(), "Satori project root is not a directory");
    Ok(SatoriRun {
        run_id,
        root,
        run_dir,
        started_at: Utc::now(),
        config,
    })
}

pub fn ingest_graph_packets(
    path: &Path,
    config: SatoriConfig,
    packet_limit: usize,
) -> SatoriResult<PipelineArtifacts> {
    let run = create_run(path, config.clone())?;
    write_json_in_run(&run.run_dir, Path::new("run.json"), &run)?;
    let project = ingest_project(path, &run.run_dir)?;
    ensure_project_bound_to_run(&run, &project)?;
    let analysis = analyze_project(
        &project,
        &run.run_dir,
        config.external_foundry_opt_in(),
        config.external_slither_opt_in(),
    )?;
    let graph = build_graph(&project, &analysis, &run.run_dir)?;
    let memory = MemoryStore::new(&config.memory_path);
    build_repo_packet(&project, &analysis, &graph, &run.run_dir)?;
    build_function_packets(&project, &analysis, &run.run_dir, packet_limit, &memory)?;
    Ok(PipelineArtifacts {
        run,
        project,
        analysis,
    })
}

pub fn load_run_project_analysis(
    run_id: &str,
) -> SatoriResult<(SatoriRun, ProjectModel, StaticAnalysisBundle)> {
    let run_dir = canonical_run_dir(run_id)?;
    let run: SatoriRun = read_json_in_run(&run_dir, Path::new("run.json"))?;
    ensure_loaded_run_dir(&run, run_id)?;
    let project: ProjectModel = read_json_in_run(&run_dir, Path::new("project.json"))?;
    let analysis: StaticAnalysisBundle =
        read_json_in_run(&run_dir, Path::new("static_analysis.json"))?;
    ensure_project_bound_to_run(&run, &project)?;
    Ok((run, project, analysis))
}

fn ensure_loaded_run_dir(run: &SatoriRun, expected_run_id: &str) -> SatoriResult<()> {
    anyhow::ensure!(
        run.run_id == expected_run_id,
        "Satori run artifact identity does not match the requested run"
    );
    let runs_root = canonical_run_root()?;
    let expected = canonical_run_dir(&run.run_id)?;
    ensure_path_contained(&runs_root, &run.run_dir).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        canonical_run_dir_path(&run.run_dir)? == expected,
        "Satori run directory does not match its canonical run root"
    );
    Ok(())
}

fn ensure_project_bound_to_run(run: &SatoriRun, project: &ProjectModel) -> SatoriResult<()> {
    crate::satori::fsutil::reject_symlink_components(&run.root)?;
    crate::satori::fsutil::reject_symlink_components(&project.root)?;
    let run_root = run.root.canonicalize()?;
    let project_root = project.root.canonicalize()?;
    anyhow::ensure!(
        run_root == project_root,
        "Satori project root is not bound to the original run root"
    );
    for source in project.source_files.iter().chain(project.docs.iter()) {
        verify_source_file_binding(
            &project_root,
            &source.path,
            &source.relative_path,
            &source.content_hash,
        )?;
    }
    Ok(())
}

pub async fn run_model_audit(path: &Path, config: SatoriConfig) -> SatoriResult<SatoriReport> {
    let artifacts = ingest_graph_packets(path, config.clone(), config.max_critical_functions)?;
    let function_packets = load_function_packets(&artifacts.run.run_dir)?;
    let cache = ResponseCache::new(&config.cache_dir);
    let client = ZenClient::new(&config.model, cache)?;
    let mut budget = BudgetTracker::default();
    let mut hypotheses = Vec::new();
    let mut rejected = Vec::new();
    let mut model_hypotheses = 0usize;
    for packet in &function_packets {
        let prompt = function_audit_prompt(packet, config.max_hypotheses_per_function);
        let (response, cached) = client.complete_json(&prompt).await?;
        budget.record_call(&prompt, &response, cached);
        let audit: FunctionAuditResult = parse_strict_json(&response)?;
        ensure_hypothesis_count(
            audit.hypotheses.len(),
            config.max_hypotheses_per_function,
            "per-function",
        )?;
        for hypothesis in audit.hypotheses {
            model_hypotheses = model_hypotheses
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Satori hypothesis count overflow"))?;
            ensure_hypothesis_count(model_hypotheses, config.max_hypotheses_total, "global")?;
            match reject_hypothesis(&hypothesis, &config) {
                None => hypotheses.push(hypothesis),
                Some(reason) => rejected.push(format!("{}: {reason}", hypothesis.id)),
            }
        }
    }
    ensure_unique_hypotheses(&hypotheses)?;
    write_json_in_run(
        &artifacts.run.run_dir,
        Path::new("hypotheses.json"),
        &hypotheses,
    )?;
    let jobs = if config.generate_jobs {
        hypotheses
            .iter()
            .map(job_from_hypothesis)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    ensure_unique_job_ids(&jobs)?;
    ensure_job_count(jobs.len(), config.max_jobs)?;
    let jobs_dir = artifacts.run.run_dir.join("jobs");
    ensure_dir(&jobs_dir)?;
    for job in &jobs {
        validate_identifier(&job.job_id)?;
        write_json_in_run(
            &artifacts.run.run_dir,
            Path::new("jobs")
                .join(format!("{}.rustyfuzz.json", job.job_id))
                .as_path(),
            job,
        )?;
    }
    write_json_in_run(&artifacts.run.run_dir, Path::new("jobs.json"), &jobs)?;
    let (verdicts, pocs) = if config.validate {
        validate_jobs_async(
            &artifacts.project,
            &artifacts.run.run_dir,
            &hypotheses,
            &jobs,
            config.external_foundry_opt_in(),
        )
        .await?
    } else {
        write_json_in_run(
            &artifacts.run.run_dir,
            Path::new("validation_verdicts.json"),
            &Vec::<crate::satori::types::ValidationVerdict>::new(),
        )?;
        write_json_in_run(
            &artifacts.run.run_dir,
            Path::new("foundry_pocs.json"),
            &Vec::<crate::satori::types::FoundryPocSpec>::new(),
        )?;
        (Vec::new(), Vec::new())
    };
    let protocol_model = ProtocolModel {
        protocol_types: artifacts.project.detected_protocols.clone(),
        confidence: 0.4,
        explanation: "Deterministic source and detector inference; Zen function audit consumed compact packets.".to_string(),
        ..ProtocolModel::default()
    };
    let report = SatoriReport {
        run_id: artifacts.run.run_id.clone(),
        project_summary: format!(
            "{} source files, {} tests, {} docs",
            artifacts.project.source_files.len(),
            artifacts.project.test_files.len(),
            artifacts.project.docs.len()
        ),
        tool_status: artifacts.analysis.tool_runs.clone(),
        protocol_model,
        critical_functions: artifacts.analysis.functions.clone(),
        hypotheses,
        rejected_hypotheses: rejected,
        jobs,
        foundry_pocs: pocs,
        validation_verdicts: verdicts,
        budget: budget.report(),
        next_steps: vec![
            "Bind generated jobs to concrete target address, ABI, fork RPC, and fork block where missing.".to_string(),
            "Run local replay/minimization before treating any hypothesis as a finding.".to_string(),
        ],
    };
    write_reports(&artifacts.run.run_dir, &report)?;
    Ok(report)
}

pub async fn revalidate_existing_run(run_id: &str) -> SatoriResult<SatoriReport> {
    let revalidation_rpc_url = std::env::var("RUSTYFUZZ_SATORI_REVALIDATION_RPC_URL").ok();
    revalidate_existing_run_with_rpc(run_id, revalidation_rpc_url.as_deref()).await
}

pub async fn revalidate_existing_run_with_rpc(
    run_id: &str,
    revalidation_rpc_url: Option<&str>,
) -> SatoriResult<SatoriReport> {
    let (run, project, analysis) = load_run_project_analysis(run_id)?;
    ensure_loaded_run_dir(&run, run_id)?;
    ensure_project_bound_to_run(&run, &project)?;
    let hypotheses: Vec<VulnerabilityHypothesis> =
        read_json_in_run(&run.run_dir, Path::new("hypotheses.json"))?;
    let mut jobs: Vec<RustyFuzzJobSpec> = read_json_in_run(&run.run_dir, Path::new("jobs.json"))?;
    ensure_revalidation_caps(&run.config, hypotheses.len(), jobs.len())?;
    apply_revalidation_rpc_context(&mut jobs, revalidation_rpc_url);
    ensure_unique_hypotheses(&hypotheses)?;
    ensure_unique_job_ids(&jobs)?;
    let (validation_verdicts, foundry_pocs) = validate_jobs_async(
        &project,
        &run.run_dir,
        &hypotheses,
        &jobs,
        run.config.external_foundry_opt_in(),
    )
    .await?;
    let report = SatoriReport {
        run_id: run.run_id.clone(),
        project_summary: format!(
            "{} source files, {} tests, {} docs",
            project.source_files.len(),
            project.test_files.len(),
            project.docs.len()
        ),
        tool_status: analysis.tool_runs.clone(),
        protocol_model: ProtocolModel {
            protocol_types: project.detected_protocols.clone(),
            confidence: 0.4,
            explanation: "Deterministic Satori artifacts with bounded RustyFuzz revalidation."
                .to_string(),
            ..ProtocolModel::default()
        },
        critical_functions: analysis.functions.clone(),
        hypotheses,
        rejected_hypotheses: Vec::new(),
        jobs,
        foundry_pocs,
        validation_verdicts,
        budget: Default::default(),
        next_steps: vec![
            "Treat only independently replayed and minimized findings as validated.".to_string(),
            "Do not treat generated hypotheses or compiled scaffolds as exploit proof.".to_string(),
        ],
    };
    write_reports(&run.run_dir, &report)?;
    Ok(report)
}

fn apply_revalidation_rpc_context(jobs: &mut [RustyFuzzJobSpec], rpc_url: Option<&str>) {
    for job in jobs.iter_mut() {
        job.fork_rpc_url = rpc_url
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string);
    }
}

pub fn build_report_for_existing_run(run_id: &str) -> SatoriResult<SatoriReport> {
    let (run, project, analysis) = load_run_project_analysis(run_id)?;
    ensure_loaded_run_dir(&run, run_id)?;
    ensure_project_bound_to_run(&run, &project)?;
    let hypotheses: Vec<VulnerabilityHypothesis> =
        read_json_in_run(&run.run_dir, Path::new("hypotheses.json")).map_err(|error| {
            anyhow::anyhow!("Satori hypotheses artifact is missing or malformed: {error:#}")
        })?;
    let jobs: Vec<RustyFuzzJobSpec> = read_json_in_run(&run.run_dir, Path::new("jobs.json"))
        .map_err(|error| {
            anyhow::anyhow!("Satori jobs artifact is missing or malformed: {error:#}")
        })?;

    ensure_unique_hypotheses(&hypotheses)?;
    ensure_unique_job_ids(&jobs)?;
    let (verdicts, pocs) = load_validation_artifacts(&run)?;

    let report = SatoriReport {
        run_id: run.run_id.clone(),
        project_summary: format!(
            "{} source files, {} tests, {} docs",
            project.source_files.len(),
            project.test_files.len(),
            project.docs.len()
        ),
        tool_status: analysis.tool_runs.clone(),
        protocol_model: ProtocolModel {
            protocol_types: project.detected_protocols.clone(),
            confidence: 0.4,
            explanation: "Loaded deterministic Satori run artifacts.".to_string(),
            ..ProtocolModel::default()
        },
        critical_functions: analysis.functions.clone(),
        hypotheses,
        rejected_hypotheses: Vec::new(),
        jobs,
        foundry_pocs: pocs,
        validation_verdicts: verdicts,
        budget: Default::default(),
        next_steps: vec![
            "Inspect unvalidated hypotheses and provide concrete replay context.".to_string(),
        ],
    };
    write_reports(&run.run_dir, &report)?;
    Ok(report)
}

fn load_validation_artifacts(
    run: &crate::satori::types::SatoriRun,
) -> SatoriResult<(
    Vec<crate::satori::types::ValidationVerdict>,
    Vec<crate::satori::types::FoundryPocSpec>,
)> {
    if run.config.validate {
        let verdicts: Vec<crate::satori::types::ValidationVerdict> =
            read_json_in_run(&run.run_dir, Path::new("validation_verdicts.json")).map_err(
                |error| {
                    anyhow::anyhow!(
                        "Satori validation verdicts artifact is missing or malformed: {error:#}"
                    )
                },
            )?;
        let pocs: Vec<crate::satori::types::FoundryPocSpec> =
            read_json_in_run(&run.run_dir, Path::new("foundry_pocs.json")).map_err(|error| {
                anyhow::anyhow!("Satori Foundry PoC artifact is missing or malformed: {error:#}")
            })?;
        return Ok((verdicts, pocs));
    }
    let verdicts = read_optional_json_in_run(&run.run_dir, Path::new("validation_verdicts.json"))
        .map_err(|error| {
            anyhow::anyhow!("Satori validation verdicts artifact is malformed: {error:#}")
        })?
        .unwrap_or_default();
    let pocs = read_optional_json_in_run(&run.run_dir, Path::new("foundry_pocs.json"))
        .map_err(|error| anyhow::anyhow!("Satori Foundry PoC artifact is malformed: {error:#}"))?
        .unwrap_or_default();
    Ok((verdicts, pocs))
}

fn read_optional_json_in_run<T: DeserializeOwned>(
    run_dir: &Path,
    relative_path: &Path,
) -> SatoriResult<Option<T>> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    let path = run_dir.join(relative_path);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => read_json_in_run(&run_dir, relative_path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn load_function_packets(run_dir: &Path) -> SatoriResult<Vec<FunctionPacket>> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    let runs_root = canonical_run_root()?;
    let packet_dir = run_dir.join("packets");
    let mut packets = Vec::new();
    for entry in read_dir_under(&runs_root, &packet_dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.starts_with("function_") && name.ends_with(".json"))
            .unwrap_or(false)
        {
            packets.push(read_json_in_run(
                &run_dir,
                path.strip_prefix(&run_dir).map_err(|_| {
                    anyhow::anyhow!("Satori packet path is outside its run directory")
                })?,
            )?);
        }
    }
    Ok(packets)
}

fn function_audit_prompt(packet: &FunctionPacket, max_hypotheses: usize) -> String {
    let packet_json = serde_json::to_string_pretty(packet).unwrap_or_default();
    format!(
        "{}\n\n{}\n\nReturn at most {} hypotheses as FunctionAuditResult JSON.\n\nPACKET:\n{}",
        load_prompt("system"),
        load_prompt("function_audit"),
        max_hypotheses,
        redact_source_text(&packet_json)
    )
}

fn ensure_hypothesis_count(count: usize, cap: usize, scope: &str) -> SatoriResult<()> {
    anyhow::ensure!(
        count <= cap,
        "Satori model returned {count} hypotheses, exceeding the {scope} cap of {cap}"
    );
    Ok(())
}

fn ensure_revalidation_caps(
    config: &SatoriConfig,
    hypothesis_count: usize,
    job_count: usize,
) -> SatoriResult<()> {
    ensure_hypothesis_count(hypothesis_count, config.max_hypotheses_total, "global")?;
    ensure_job_count(job_count, config.max_jobs)?;
    Ok(())
}

fn ensure_job_count(count: usize, cap: usize) -> SatoriResult<()> {
    anyhow::ensure!(
        count <= cap,
        "Satori generated {count} jobs, exceeding the job cap of {cap}"
    );
    Ok(())
}

fn ensure_unique_hypotheses(hypotheses: &[VulnerabilityHypothesis]) -> SatoriResult<()> {
    let mut seen = BTreeSet::new();
    for hypothesis in hypotheses {
        anyhow::ensure!(
            seen.insert(hypothesis.id.as_str()),
            "duplicate model hypothesis id `{}`",
            hypothesis.id
        );
    }
    Ok(())
}

fn ensure_unique_job_ids(jobs: &[RustyFuzzJobSpec]) -> SatoriResult<()> {
    let mut seen = BTreeSet::new();
    for job in jobs {
        anyhow::ensure!(
            seen.insert(job.job_id.as_str()),
            "duplicate Satori job id `{}`",
            job.job_id
        );
    }
    Ok(())
}

fn reject_hypothesis(
    hypothesis: &VulnerabilityHypothesis,
    config: &SatoriConfig,
) -> Option<String> {
    if !has_minimum_evidence(hypothesis) {
        return Some("missing concrete evidence, attack sequence, or validation plan".to_string());
    }
    if hypothesis.confidence_before_validation > 0.95 {
        return Some("pre-validation confidence is overclaimed".to_string());
    }
    if hypothesis.confidence_before_validation < config.min_confidence {
        return Some("below configured minimum confidence".to_string());
    }
    if hypothesis
        .attack_sequence
        .iter()
        .any(|step| step.action.to_ascii_lowercase().contains("broadcast"))
    {
        return Some("live transaction broadcasting is unsupported".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::FunctionSummary;

    #[test]
    fn function_audit_prompt_redacts_source_secrets() {
        let packet = FunctionPacket {
            target_function: FunctionSummary {
                id: "Vault::deposit()".to_string(),
                contract: "Vault".to_string(),
                name: "deposit".to_string(),
                signature: "deposit()".to_string(),
                selector: None,
                file: std::path::PathBuf::from("Vault.sol"),
                visibility: "external".to_string(),
                mutability: "nonpayable".to_string(),
                modifiers: Vec::new(),
                source_snippet: "string private_key = \"prompt-secret\";".to_string(),
                reads: Vec::new(),
                writes: Vec::new(),
                internal_calls: Vec::new(),
                external_calls: Vec::new(),
                detector_signals: Vec::new(),
                criticality_score: 0.8,
            },
            related_functions: Vec::new(),
            protocol_context: ProtocolModel::default(),
            relevant_memories: Vec::new(),
            known_bug_classes: Vec::new(),
            detector_evidence: Vec::new(),
            output_constraints: Vec::new(),
        };
        let prompt = function_audit_prompt(&packet, 2);
        assert!(!prompt.contains("prompt-secret"));
        assert!(prompt.contains("<redacted>"));
    }

    #[test]
    fn revalidation_rpc_context_is_explicit_and_never_reuses_artifact_secrets() {
        let mut jobs = vec![RustyFuzzJobSpec {
            job_id: "job-h1".to_string(),
            hypothesis_id: "h1".to_string(),
            job_type: "sequence_fuzz".to_string(),
            target_contract: Some("0x0000000000000000000000000000000000000001".to_string()),
            bug_class: "access_control".to_string(),
            actors: Vec::new(),
            preconditions: Vec::new(),
            sequence_template: Vec::new(),
            mutation_focus: Vec::new(),
            invariants: Vec::new(),
            objective: "objective".to_string(),
            success_condition: "success".to_string(),
            max_depth: 1,
            max_execs: 1,
            duration_secs: 1,
            fork_rpc_url: Some("https://artifact.example/v1/old-secret".to_string()),
            fork_block: Some(1),
            abi_hints: Vec::new(),
        }];
        apply_revalidation_rpc_context(&mut jobs, None);
        assert_eq!(jobs[0].fork_rpc_url, None);
        apply_revalidation_rpc_context(&mut jobs, Some("https://rpc.example/v1"));
        assert_eq!(
            jobs[0].fork_rpc_url.as_deref(),
            Some("https://rpc.example/v1")
        );
        let serialized = serde_json::to_string(&jobs).expect("serialize job");
        assert!(!serialized.contains("fork_rpc_url"));
    }

    #[test]
    fn hypothesis_and_job_caps_are_enforced_before_artifacts_are_written() {
        assert!(ensure_hypothesis_count(2, 1, "per-function").is_err());
        assert!(ensure_hypothesis_count(3, 2, "global").is_err());
        assert!(ensure_hypothesis_count(2, 2, "global").is_ok());
        assert!(ensure_job_count(3, 2).is_err());
        assert!(ensure_job_count(2, 2).is_ok());
    }

    #[test]
    fn revalidation_enforces_hypothesis_and_job_caps() {
        let config = SatoriConfig {
            max_hypotheses_total: 1,
            max_jobs: 1,
            ..SatoriConfig::default()
        };

        assert!(ensure_revalidation_caps(&config, 2, 1).is_err());
        assert!(ensure_revalidation_caps(&config, 1, 2).is_err());
        assert!(ensure_revalidation_caps(&config, 1, 1).is_ok());
    }

    #[test]
    fn duplicate_model_hypothesis_ids_are_rejected() {
        let raw = serde_json::json!({
            "id": "h1",
            "title": "title",
            "bug_class": "access_control",
            "root_cause": "root",
            "affected_contracts": [],
            "affected_functions": [],
            "evidence_from_context": [],
            "required_conditions": [],
            "attack_sequence": [],
            "false_positive_checks": [],
            "validation_plan": [],
            "suggested_invariants": [],
            "rustyfuzz_objective": "objective",
            "confidence_before_validation": 0.5
        });
        let hypothesis: VulnerabilityHypothesis = serde_json::from_value(raw.clone()).unwrap();
        let duplicate: VulnerabilityHypothesis = serde_json::from_value(raw).unwrap();
        let error = ensure_unique_hypotheses(&[hypothesis.clone(), duplicate])
            .expect_err("duplicate hypothesis ids must fail");
        assert!(error
            .to_string()
            .contains("duplicate model hypothesis id `h1`"));
    }

    #[test]
    fn duplicate_job_ids_are_rejected() {
        let raw = serde_json::json!({
            "job_id": "job-h1",
            "hypothesis_id": "h1",
            "job_type": "sequence_fuzz",
            "target_contract": null,
            "bug_class": "access_control",
            "actors": [],
            "preconditions": [],
            "sequence_template": [],
            "mutation_focus": [],
            "invariants": [],
            "objective": "objective",
            "success_condition": "success",
            "max_depth": 1,
            "max_execs": 1,
            "duration_secs": 1,
            "fork_rpc_url": null,
            "fork_block": null,
            "abi_hints": []
        });
        let job: RustyFuzzJobSpec = serde_json::from_value(raw.clone()).unwrap();
        let duplicate: RustyFuzzJobSpec = serde_json::from_value(raw).unwrap();
        let error = ensure_unique_job_ids(&[job.clone(), duplicate])
            .expect_err("duplicate Satori job ids must fail");
        assert!(error
            .to_string()
            .contains("duplicate Satori job id `job-h1`"));
    }

    #[test]
    fn missing_validation_artifacts_are_incomplete_unless_validation_is_disabled(
    ) -> SatoriResult<()> {
        let run_dir = canonical_run_root()?.join(format!(
            "validation-artifact-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&run_dir)?;
        let config = SatoriConfig {
            validate: true,
            ..SatoriConfig::default()
        };
        let run = crate::satori::types::SatoriRun {
            run_id: "run-test".to_string(),
            root: std::env::current_dir()?,
            run_dir: run_dir.clone(),
            started_at: Utc::now(),
            config: config.clone(),
        };
        assert!(load_validation_artifacts(&run).is_err());
        let disabled_config = SatoriConfig {
            validate: false,
            ..config
        };
        let disabled = crate::satori::types::SatoriRun {
            config: disabled_config,
            ..run
        };
        assert!(load_validation_artifacts(&disabled).is_ok());
        let _ = std::fs::remove_dir_all(run_dir);
        Ok(())
    }
}
