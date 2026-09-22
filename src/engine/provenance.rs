use crate::common::oracle::ProtocolFinding;
use crate::common::types::{EvmInput, SequenceExecutionResult};
use crate::engine::scoring::CampaignScore;
use rustyfuzz_artifacts::fsutil::write_json_atomic;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const EXECUTION_PROVENANCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProvenanceRecord {
    pub schema_version: u32,
    pub execution_index: u64,
    pub budget_consumed: u64,
    pub input: EvmInput,
    pub input_id: String,
    pub execution: SequenceExecutionResult,
    pub coverage_edges: usize,
    pub state_novelty_score: u64,
    pub campaign_score: CampaignScore,
    pub findings: Vec<ProtocolFinding>,
    pub mutation_strategies: Vec<String>,
}

pub struct PersistRequest<'a> {
    pub execution_index: u64,
    pub budget_consumed: u64,
    pub input: &'a EvmInput,
    pub execution: &'a SequenceExecutionResult,
    pub coverage_edges: usize,
    pub state_novelty_score: u64,
    pub campaign_score: &'a CampaignScore,
    pub findings: &'a [ProtocolFinding],
    pub mutation_strategies: &'a [String],
}

pub fn persist(root: &Path, request: PersistRequest<'_>) -> anyhow::Result<()> {
    let directory = root.join("execution_provenance");
    std::fs::create_dir_all(&directory)?;
    let record = ExecutionProvenanceRecord {
        schema_version: EXECUTION_PROVENANCE_SCHEMA_VERSION,
        execution_index: request.execution_index,
        budget_consumed: request.budget_consumed,
        input: request.input.clone(),
        input_id: request.input.semantic_input_hash(),
        execution: request.execution.clone(),
        coverage_edges: request.coverage_edges,
        state_novelty_score: request.state_novelty_score,
        campaign_score: request.campaign_score.clone(),
        findings: request.findings.to_vec(),
        mutation_strategies: request.mutation_strategies.to_vec(),
    };
    write_json_atomic(
        &directory.join(format!("{:020}.json", request.execution_index)),
        &record,
    )?;
    Ok(())
}
