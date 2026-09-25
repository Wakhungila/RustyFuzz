use crate::common::fs_security::validate_filesystem_identifier;
use crate::common::oracle::ProtocolFinding;
use crate::common::types::{EvmInput, SequenceExecutionResult};
use crate::engine::scoring::CampaignScore;
use rustyfuzz_artifacts::fsutil::write_json_atomic;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// v1: baseline execution provenance.
/// v2: adds live-RPC / fork-cache provenance (Gate 4 + Gate 10).
/// v3: adds source identity and collision-safe multi-worker execution identity.
pub const EXECUTION_PROVENANCE_SCHEMA_VERSION: u32 = 3;

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
    /// Run nonce and worker identity form a globally unique execution identity
    /// in multi-worker campaigns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Source revision, dirty state, diff digest, and binary digest. Missing
    /// inputs are represented explicitly as `unknown`.
    #[serde(default)]
    pub source_identity: rustyfuzz_artifacts::SourceIdentity,
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
    pub run_nonce: Option<String>,
    pub worker_id: Option<String>,
    pub source_identity: rustyfuzz_artifacts::SourceIdentity,
    pub tool_revision: Option<String>,
    pub rng_seed: Option<u64>,
}

pub fn persist(root: &Path, request: PersistRequest<'_>) -> anyhow::Result<()> {
    let directory = root.join("execution_provenance");
    std::fs::create_dir_all(&directory)?;
    let path = execution_provenance_path(
        &directory,
        request.execution_index,
        request.run_nonce.as_deref(),
        request.worker_id.as_deref(),
    )?;
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
        run_nonce: request.run_nonce,
        worker_id: request.worker_id,
        source_identity: request.source_identity,
        tool_revision: request.tool_revision,
        rng_seed: request.rng_seed,
    };
    write_json_atomic(&path, &record)?;
    Ok(())
}

fn execution_provenance_path(
    directory: &Path,
    execution_index: u64,
    run_nonce: Option<&str>,
    worker_id: Option<&str>,
) -> anyhow::Result<std::path::PathBuf> {
    if let Some(run_nonce) = run_nonce {
        validate_filesystem_identifier(run_nonce).map_err(anyhow::Error::msg)?;
    }
    if let Some(worker_id) = worker_id {
        validate_filesystem_identifier(worker_id).map_err(anyhow::Error::msg)?;
    }
    Ok(match (run_nonce, worker_id) {
        (Some(run_nonce), Some(worker_id)) => directory.join(format!(
            "{run_nonce}-worker-{worker_id}-{:020}.json",
            execution_index
        )),
        _ => directory.join(format!("{execution_index:020}.json")),
    })
}

#[cfg(test)]
mod tests {
    use super::{execution_provenance_path, EXECUTION_PROVENANCE_SCHEMA_VERSION};
    use std::path::Path;

    #[test]
    fn two_worker_provenance_filenames_cannot_collide() {
        let directory = Path::new("execution_provenance");
        let first = execution_provenance_path(directory, 7, Some("run-123"), Some("0")).unwrap();
        let second = execution_provenance_path(directory, 7, Some("run-123"), Some("1")).unwrap();

        assert_ne!(first, second);
        assert!(first
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("run-123-worker-0-"));
        assert!(second
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("run-123-worker-1-"));
    }

    #[test]
    fn single_worker_provenance_filename_preserves_ordered_index() {
        let path =
            execution_provenance_path(Path::new("execution_provenance"), 7, None, None).unwrap();
        assert_eq!(
            path,
            Path::new("execution_provenance/00000000000000000007.json")
        );
        assert!(execution_provenance_path(
            Path::new("execution_provenance"),
            7,
            Some("../escape"),
            Some("worker"),
        )
        .is_err());
        assert_eq!(EXECUTION_PROVENANCE_SCHEMA_VERSION, 3);
    }
}
