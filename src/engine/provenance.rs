use crate::common::oracle::ProtocolFinding;
use crate::common::types::{EvmInput, SequenceExecutionResult};
use crate::engine::scoring::CampaignScore;
use rustyfuzz_artifacts::fsutil::write_json_atomic;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// v1: baseline execution provenance.
/// v2: adds live-RPC / fork-cache provenance (Gate 4 + Gate 10).
pub const EXECUTION_PROVENANCE_SCHEMA_VERSION: u32 = 2;

/// Live-RPC and fork-cache provenance attached to every execution record.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcProvenance {
    /// Sanitized provider (`scheme://host[:port]`), never credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_sanitized: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_block: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_block_hash: Option<String>,
    /// Unix seconds the fork state / cache was fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_cache_id: Option<String>,
    /// `live_rpc`, `cache_replay`, or `synthetic_fallback`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

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
    /// Gate 4/10: RPC and cache provenance for this execution.
    #[serde(default)]
    pub rpc_provenance: RpcProvenance,
    /// Bytecode hash of the primary target when known (Gate 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytecode_hash: Option<String>,
    /// Configuration fingerprint of the campaign (Gate 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    /// Tool revision / version string (Gate 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_revision: Option<String>,
    /// RNG seed when determinism was requested (Gate 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rng_seed: Option<u64>,
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
    pub rpc_provenance: RpcProvenance,
    pub bytecode_hash: Option<String>,
    pub config_hash: Option<String>,
    pub tool_revision: Option<String>,
    pub rng_seed: Option<u64>,
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
        rpc_provenance: request.rpc_provenance,
        bytecode_hash: request.bytecode_hash,
        config_hash: request.config_hash,
        tool_revision: request.tool_revision,
        rng_seed: request.rng_seed,
    };
    write_json_atomic(
        &directory.join(format!("{:020}.json", request.execution_index)),
        &record,
    )?;
    Ok(())
}
