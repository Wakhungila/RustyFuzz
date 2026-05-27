use crate::satori::analysis::analyze_project;
use crate::satori::budget::BudgetTracker;
use crate::satori::cache::ResponseCache;
use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{ensure_dir, new_run_id, read_json, write_json};
use crate::satori::graph::build_graph;
use crate::satori::ingest::ingest_project;
use crate::satori::jobs::job_from_hypothesis;
use crate::satori::memory::false_positive::has_minimum_evidence;
use crate::satori::memory::MemoryStore;
use crate::satori::packets::{build_function_packets, build_repo_packet};
use crate::satori::reasoning::o3_client::O3Client;
use crate::satori::reasoning::parser::parse_strict_json;
use crate::satori::reasoning::prompts::load_prompt;
use crate::satori::report::write_reports;
use crate::satori::types::{
    FunctionAuditResult, FunctionPacket, ProjectModel, ProtocolModel, SatoriConfig, SatoriReport,
    SatoriRun, StaticAnalysisBundle, VulnerabilityHypothesis,
};
use crate::satori::validation::validate_jobs;
use chrono::Utc;
use std::path::{Path, PathBuf};

pub struct PipelineArtifacts {
    pub run: SatoriRun,
    pub project: ProjectModel,
    pub analysis: StaticAnalysisBundle,
}

pub fn create_run(path: &Path, config: SatoriConfig) -> SatoriResult<SatoriRun> {
    let run_id = new_run_id("satori");
    let run_dir = PathBuf::from("satori/runs").join(&run_id);
    ensure_dir(&run_dir)?;
    ensure_dir(&config.cache_dir)?;
    if let Some(parent) = config.memory_path.parent() {
        ensure_dir(parent)?;
    }
    Ok(SatoriRun {
        run_id,
        root: path.to_path_buf(),
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
    write_json(run.run_dir.join("run.json"), &run)?;
    let project = ingest_project(path, &run.run_dir)?;
    let analysis = analyze_project(&project, &run.run_dir)?;
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
    let run_dir = PathBuf::from("satori/runs").join(run_id);
    let run = read_json(run_dir.join("run.json"))?;
    let project = read_json(run_dir.join("project.json"))?;
    let analysis = read_json(run_dir.join("static_analysis.json"))?;
    Ok((run, project, analysis))
}

pub async fn run_model_audit(path: &Path, config: SatoriConfig) -> SatoriResult<SatoriReport> {
    let artifacts = ingest_graph_packets(path, config.clone(), config.max_critical_functions)?;
    let function_packets = load_function_packets(&artifacts.run.run_dir)?;
    let cache = ResponseCache::new(&config.cache_dir);
    let client = O3Client::new(&config.model, cache);
    let mut budget = BudgetTracker::default();
    let mut hypotheses = Vec::new();
    let mut rejected = Vec::new();
    for packet in &function_packets {
        let prompt = function_audit_prompt(packet, config.max_hypotheses_per_function);
        let (response, cached) = client.complete_json(&prompt).await?;
        budget.record_call(&prompt, &response, cached);
        let audit: FunctionAuditResult = parse_strict_json(&response)?;
        for hypothesis in audit.hypotheses {
            if reject_hypothesis(&hypothesis, &config).is_none() {
                hypotheses.push(hypothesis);
            } else {
                rejected.push(format!(
                    "{}: {}",
                    hypothesis.id,
                    reject_hypothesis(&hypothesis, &config).unwrap()
                ));
            }
        }
    }
    write_json(artifacts.run.run_dir.join("hypotheses.json"), &hypotheses)?;
    let jobs = if config.generate_jobs {
        hypotheses
            .iter()
            .map(job_from_hypothesis)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    ensure_dir(artifacts.run.run_dir.join("jobs"))?;
    for job in &jobs {
        write_json(
            artifacts
                .run
                .run_dir
                .join("jobs")
                .join(format!("{}.rustyfuzz.json", job.job_id)),
            job,
        )?;
    }
    write_json(artifacts.run.run_dir.join("jobs.json"), &jobs)?;
    let (verdicts, pocs) = if config.validate {
        validate_jobs(
            &artifacts.project,
            &artifacts.run.run_dir,
            &hypotheses,
            &jobs,
        )?
    } else {
        (Vec::new(), Vec::new())
    };
    let protocol_model = ProtocolModel {
        protocol_types: artifacts.project.detected_protocols.clone(),
        confidence: 0.4,
        explanation: "Deterministic source and detector inference; o3 function audit consumed compact packets.".to_string(),
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

pub fn build_report_for_existing_run(run_id: &str) -> SatoriResult<SatoriReport> {
    let (run, project, analysis) = load_run_project_analysis(run_id)?;
    let hypotheses = read_json(run.run_dir.join("hypotheses.json")).unwrap_or_default();
    let jobs = read_json(run.run_dir.join("jobs.json")).unwrap_or_default();
    let verdicts = read_json(run.run_dir.join("validation_verdicts.json")).unwrap_or_default();
    let pocs = read_json(run.run_dir.join("foundry_pocs.json")).unwrap_or_default();
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

fn load_function_packets(run_dir: &Path) -> SatoriResult<Vec<FunctionPacket>> {
    let packet_dir = run_dir.join("packets");
    let mut packets = Vec::new();
    for entry in std::fs::read_dir(packet_dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.starts_with("function_") && name.ends_with(".json"))
            .unwrap_or(false)
        {
            packets.push(read_json(path)?);
        }
    }
    Ok(packets)
}

fn function_audit_prompt(packet: &FunctionPacket, max_hypotheses: usize) -> String {
    format!(
        "{}\n\n{}\n\nReturn at most {} hypotheses as FunctionAuditResult JSON.\n\nPACKET:\n{}",
        load_prompt("system"),
        load_prompt("function_audit"),
        max_hypotheses,
        serde_json::to_string_pretty(packet).unwrap_or_default()
    )
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
