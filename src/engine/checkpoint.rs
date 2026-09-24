//! Coordinated single-process campaign checkpoints, published at stage boundaries.
use super::concolic::ConcolicHint;
use super::foundry_ingest::FoundryHarnessManifest;
use super::fuzz_engine::Config;
use super::promotion::PromotionConfig;
use crate::common::types::{ChainState, Snapshot, Waypoint};
use crate::evm::corpus::{SnapshotCorpus, SnapshotMetadata};
use crate::evm::feedback::{EvmCoverageFeedback, EvmStateNoveltyFeedback};
use crate::evm::fuzz::{EvmInput, EvmTestcaseMetadata};
use crate::evm::registry::GlobalAccountRegistry;
use anyhow::{ensure, Context};
use parking_lot::RwLock;
use revm::database::{Cache, CacheDB};
use revm::primitives::{keccak256, Address, B256};
use rustyfuzz_artifacts::fsutil::write_json_atomic;
use rustyfuzz_core::InputId;
use rustyfuzz_engine::campaign::{budget::BudgetCheckpoint, telemetry::TelemetryCheckpoint};
use rustyfuzz_evm::{
    dataflow::DataflowRegistry,
    fork_db::{ForkDb, ForkDbCacheSnapshot},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    path::PathBuf,
    sync::Arc,
};

#[derive(Debug, Clone, Deserialize)]
pub struct CheckpointConfig {
    pub directory: PathBuf,
    #[serde(default)]
    pub resume: bool,
    #[serde(default = "default_interval")]
    pub every_execs: u64,
}
fn default_interval() -> u64 {
    1000
}

pub const CHECKPOINT_SCHEMA_VERSION: u32 = 2;
pub const CHECKPOINT_CONFIG_IDENTITY_SCHEMA_VERSION: u32 = 2;
const LEGACY_CHECKPOINT_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct CheckpointIdentity {
    schema_version: u32,
    rpc_url: String,
    fork_block: u64,
    target_contract: Option<Address>,
    corpus_dir: String,
    report_dir: String,
    foundry_harness: Option<FoundryHarnessManifest>,
    mainnet_seed_bundle: Option<String>,
    in_memory_bytecode: Option<String>,
    cores: Option<String>,
    require_seed_bundle: bool,
    require_rpc_fork: bool,
    allow_synthetic_fallback: bool,
    hardened_defi: HardenedDefiIdentity,
    target_invariant_manifest: Option<String>,
    abi_path: Option<String>,
    max_execs: Option<u64>,
    duration_secs: Option<u64>,
    artifact_limit: Option<u64>,
    campaign_id: Option<String>,
    min_finding_confidence: u64,
    promotion: PromotionConfig,
}

#[derive(Serialize)]
struct HardenedDefiIdentity {
    enabled: bool,
    single_process: bool,
    deterministic: bool,
    rng_seed: Option<u64>,
    enable_bounded_search: bool,
    historical_seed_file: Option<String>,
    max_template_sequences: usize,
    max_actor_roles: usize,
    max_tx_depth: usize,
    enable_actor_model: bool,
    enable_economic_delta: bool,
    enable_protocol_invariants: bool,
    enable_exploit_templates: bool,
    min_persist_confidence: f64,
    require_confirmation_for_poc: bool,
}

fn checkpoint_rpc_identity(rpc_url: &str) -> String {
    format!("sha256:{:x}", keccak256(rpc_url.as_bytes()))
}

fn checkpoint_identity_digest(config: &Config) -> anyhow::Result<String> {
    let identity = CheckpointIdentity {
        schema_version: CHECKPOINT_CONFIG_IDENTITY_SCHEMA_VERSION,
        rpc_url: checkpoint_rpc_identity(&config.rpc_url),
        fork_block: config.fork_block,
        target_contract: config.target_contract,
        corpus_dir: config.corpus_dir.clone(),
        report_dir: config.report_dir.clone(),
        foundry_harness: config.foundry_harness.clone(),
        mainnet_seed_bundle: config.mainnet_seed_bundle.clone(),
        in_memory_bytecode: config.in_memory_bytecode.as_ref().map(hex::encode),
        cores: config.cores.as_ref().map(|cores| cores.cmdline.clone()),
        require_seed_bundle: config.require_seed_bundle,
        require_rpc_fork: config.require_rpc_fork,
        allow_synthetic_fallback: config.allow_synthetic_fallback,
        hardened_defi: HardenedDefiIdentity {
            enabled: config.hardened_defi.enabled,
            single_process: config.hardened_defi.single_process,
            deterministic: config.hardened_defi.deterministic,
            rng_seed: config.hardened_defi.rng_seed,
            enable_bounded_search: config.hardened_defi.enable_bounded_search,
            historical_seed_file: config.hardened_defi.historical_seed_file.clone(),
            max_template_sequences: config.hardened_defi.max_template_sequences,
            max_actor_roles: config.hardened_defi.max_actor_roles,
            max_tx_depth: config.hardened_defi.max_tx_depth,
            enable_actor_model: config.hardened_defi.enable_actor_model,
            enable_economic_delta: config.hardened_defi.enable_economic_delta,
            enable_protocol_invariants: config.hardened_defi.enable_protocol_invariants,
            enable_exploit_templates: config.hardened_defi.enable_exploit_templates,
            min_persist_confidence: config.hardened_defi.min_persist_confidence,
            require_confirmation_for_poc: config.hardened_defi.require_confirmation_for_poc,
        },
        target_invariant_manifest: config.target_invariant_manifest.clone(),
        abi_path: config.abi_path.clone(),
        max_execs: config.max_execs,
        duration_secs: config.duration_secs,
        artifact_limit: config.artifact_limit,
        campaign_id: config.campaign_id.clone(),
        min_finding_confidence: config.min_finding_confidence,
        promotion: config.promotion.clone(),
    };
    let mut identity = serde_json::to_vec(&identity).context("serialize checkpoint identity")?;
    for path in [
        &config.abi_path,
        &config.target_invariant_manifest,
        &config.hardened_defi.historical_seed_file,
    ]
    .into_iter()
    .flatten()
    {
        let bytes = fs::read(path).with_context(|| format!("checkpoint identity input {path}"))?;
        identity.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        identity.extend_from_slice(&bytes);
    }
    Ok(format!("{:x}", keccak256(identity)))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SavedSnapshot {
    id: u64,
    cache: Cache,
    fork: ForkDbCacheSnapshot,
    coverage: Vec<bool>,
    producing_input: Option<EvmInput>,
    waypoints: Vec<Waypoint>,
    depth: u32,
    gas_used: u64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SavedSnapshots {
    snapshots: Vec<SavedSnapshot>,
    parents: HashMap<u64, u64>,
    children: HashMap<u64, Vec<u64>>,
    metadata: HashMap<u64, SnapshotMetadata>,
    hotspots: Vec<((Address, B256), usize)>,
    priority: Vec<bool>,
}
fn validate_fork_lineage(snapshots: &[SavedSnapshot]) -> anyhow::Result<()> {
    let root = snapshots
        .iter()
        .find(|snapshot| snapshot.id == 0)
        .context("checkpoint lacks root EVM snapshot")?;
    if root.fork.provenance.provider_sanitized.is_empty() {
        return Ok(());
    }
    root.fork
        .ensure_consistent(None, None, None, None, true)
        .map_err(|error| anyhow::anyhow!("root checkpoint fork cache is inconsistent: {error}"))?;
    for snapshot in snapshots {
        ensure!(
            snapshot.fork.provenance.provider_sanitized == root.fork.provenance.provider_sanitized,
            "checkpoint fork provider mismatch"
        );
        ensure!(
            snapshot.fork.provenance.chain_id == root.fork.provenance.chain_id,
            "checkpoint fork chain id mismatch"
        );
        snapshot
            .fork
            .ensure_consistent(
                root.fork.provenance.block_number,
                root.fork.provenance.block_hash.as_deref(),
                None,
                None,
                true,
            )
            .map_err(|error| {
                anyhow::anyhow!("checkpoint fork snapshot is inconsistent: {error}")
            })?;
    }
    Ok(())
}

impl SavedSnapshots {
    pub fn capture(corpus: &SnapshotCorpus) -> Self {
        let mut ids: Vec<_> = corpus.snapshots.keys().copied().collect();
        ids.sort_unstable();
        Self {
            snapshots: ids
                .into_iter()
                .map(|id| {
                    let snapshot = corpus.snapshots[&id].read();
                    let state = snapshot.state.read();
                    let ChainState::Evm(db) = &*state;
                    SavedSnapshot {
                        id,
                        cache: db.cache.clone(),
                        fork: db.db.cache_snapshot(),
                        coverage: snapshot.coverage.iter().map(|b| *b).collect(),
                        producing_input: snapshot.producing_input.clone(),
                        waypoints: snapshot.waypoints.clone(),
                        depth: snapshot.depth,
                        gas_used: snapshot.gas_used,
                    }
                })
                .collect(),
            parents: corpus.parent_map.clone(),
            children: corpus.children_map.clone(),
            metadata: corpus.metadata.clone(),
            hotspots: corpus
                .global_read_hotspots
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            priority: corpus.priority_gap_map.iter().map(|b| *b).collect(),
        }
    }
    pub fn initial_db(&self) -> anyhow::Result<CacheDB<ForkDb>> {
        validate_fork_lineage(&self.snapshots)?;
        let root = self
            .snapshots
            .iter()
            .find(|s| s.id == 0)
            .context("checkpoint lacks root EVM snapshot")?;
        Ok(CacheDB {
            cache: root.cache.clone(),
            db: ForkDb::from_cache_snapshot(root.fork.clone()),
        })
    }
    pub fn restore(self) -> anyhow::Result<SnapshotCorpus> {
        validate_fork_lineage(&self.snapshots)?;
        Ok(SnapshotCorpus {
            snapshots: self
                .snapshots
                .into_iter()
                .map(|s| {
                    (
                        s.id,
                        Arc::new(RwLock::new(Snapshot {
                            id: s.id,
                            state: Arc::new(RwLock::new(ChainState::Evm(CacheDB {
                                cache: s.cache,
                                db: ForkDb::from_cache_snapshot(s.fork),
                            }))),
                            coverage: s.coverage.into_iter().collect(),
                            producing_input: s.producing_input,
                            waypoints: s.waypoints,
                            depth: s.depth,
                            gas_used: s.gas_used,
                        })),
                    )
                })
                .collect(),
            parent_map: self.parents,
            children_map: self.children,
            metadata: self.metadata,
            global_read_hotspots: self.hotspots.into_iter().collect(),
            priority_gap_map: self.priority.into_iter().collect(),
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Checkpoint {
    pub state: Vec<u8>,
    pub feedback: EvmCoverageFeedback,
    pub raw_coverage: Vec<u8>,
    pub snapshots: SavedSnapshots,
    pub novelty: EvmStateNoveltyFeedback,
    pub dataflow: DataflowRegistry,
    pub accounts: GlobalAccountRegistry,
    pub metadata: HashMap<InputId, EvmTestcaseMetadata>,
    pub hints: Vec<ConcolicHint>,
    pub scheduler: (u64, u64),
    pub pending_score: Option<rustyfuzz_engine::scoring::CampaignScore>,
    pub strategies:
        std::collections::BTreeMap<String, rustyfuzz_engine::campaign::telemetry::StrategyCounts>,
    pub budget: BudgetCheckpoint,
    pub telemetry: TelemetryCheckpoint,
    pub block_env: revm::context::BlockEnv,
}

/// Single atomic publication; all referenced runtime state is embedded, not in
/// independently updated files. Payload is postcard, hex-encoded for JSON transport.
#[derive(Serialize, Deserialize)]
pub struct CheckpointEnvelope {
    pub schema_version: u32,
    #[serde(default)]
    pub config_schema_version: u32,
    pub producer_version: String,
    pub config_digest: String,
    pub budget_consumed: u64,
    pub completed_execs: u64,
    pub corpus_ids: Vec<String>,
    pub coverage: Vec<u8>,
    pub payload_digest: String,
    pub payload_hex: String,
}

pub(crate) struct CheckpointSession {
    config: CheckpointConfig,
    digest: String,
    _lock: File,
    pub saved: Option<Checkpoint>,
    pub last_published: u64,
}
impl CheckpointSession {
    pub fn open(config: &Config) -> anyhow::Result<Option<Self>> {
        let Some(options) = &config.hardened_defi.checkpoint else {
            return Ok(None);
        };
        ensure!(config.hardened_defi.single_process, "checkpointing currently requires single_process=true; broker restart accounting is not implemented");
        ensure!(!config.promotion.enabled, "checkpointing with promotion is unsupported: promotion side effects are not transactional");
        ensure!(
            options.every_execs > 0,
            "checkpoint every_execs must be positive"
        );
        // Hash, never persist, endpoint credentials. Resume requires the same
        // execution configuration; checkpoint controls themselves may change.
        let digest = checkpoint_identity_digest(config)?;
        fs::create_dir_all(&options.directory)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(options.directory.join("checkpoint.lock"))?;
        lock.try_lock()
            .context("checkpoint directory is owned by another campaign")?;
        let path = options.directory.join("checkpoint.json");
        let saved = if options.resume {
            let envelope: CheckpointEnvelope = serde_json::from_slice(
                &fs::read(&path).with_context(|| format!("read checkpoint {}", path.display()))?,
            )?;
            if envelope.schema_version == LEGACY_CHECKPOINT_SCHEMA_VERSION {
                anyhow::bail!(
                    "legacy checkpoint schema {} is not resumable; start a new campaign with a new checkpoint directory",
                    LEGACY_CHECKPOINT_SCHEMA_VERSION
                );
            }
            ensure!(
                envelope.schema_version == CHECKPOINT_SCHEMA_VERSION,
                "unsupported checkpoint schema {}; expected {}",
                envelope.schema_version,
                CHECKPOINT_SCHEMA_VERSION
            );
            ensure!(
                envelope.config_schema_version == CHECKPOINT_CONFIG_IDENTITY_SCHEMA_VERSION,
                "checkpoint config identity schema mismatch: expected {}, got {}",
                CHECKPOINT_CONFIG_IDENTITY_SCHEMA_VERSION,
                envelope.config_schema_version
            );
            ensure!(
                envelope.producer_version == env!("CARGO_PKG_VERSION"),
                "checkpoint producer version mismatch: expected {}, got {}",
                env!("CARGO_PKG_VERSION"),
                envelope.producer_version
            );
            ensure!(
                envelope.config_digest == digest,
                "checkpoint execution configuration mismatch"
            );
            let bytes = hex::decode(&envelope.payload_hex)?;
            ensure!(
                format!("{:x}", keccak256(&bytes)) == envelope.payload_digest,
                "checkpoint checksum mismatch"
            );
            let saved: Checkpoint =
                postcard::from_bytes(&bytes).context("decode checkpoint runtime state")?;
            ensure!(
                saved.budget.consumed == envelope.budget_consumed
                    && saved.telemetry.executions == envelope.completed_execs,
                "checkpoint counter mismatch"
            );
            ensure!(
                saved.raw_coverage.len() == rustyfuzz_evm::inspector::MAP_SIZE,
                "checkpoint coverage map size mismatch"
            );
            ensure!(
                envelope.coverage == saved.feedback.checkpoint_coverage(),
                "checkpoint coverage summary mismatch"
            );
            Some(saved)
        } else {
            ensure!(
                !path.exists(),
                "checkpoint exists: enable resume or choose a new directory"
            );
            None
        };
        let last_published = saved.as_ref().map_or(0, |s| s.budget.consumed);
        Ok(Some(Self {
            config: options.clone(),
            digest,
            _lock: lock,
            saved,
            last_published,
        }))
    }
    pub fn due(&self, consumed: u64) -> bool {
        consumed.saturating_sub(self.last_published) >= self.config.every_execs
    }
    pub fn publish(
        &mut self,
        saved: &Checkpoint,
        corpus_ids: Vec<String>,
        coverage: Vec<u8>,
        _resumed: bool,
    ) -> anyhow::Result<()> {
        let bytes = postcard::to_stdvec(saved).context("serialize checkpoint")?;
        let envelope = CheckpointEnvelope {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            config_schema_version: CHECKPOINT_CONFIG_IDENTITY_SCHEMA_VERSION,
            producer_version: env!("CARGO_PKG_VERSION").into(),
            config_digest: self.digest.clone(),
            budget_consumed: saved.budget.consumed,
            completed_execs: saved.telemetry.executions,
            corpus_ids,
            coverage,
            payload_digest: format!("{:x}", keccak256(&bytes)),
            payload_hex: hex::encode(bytes),
        };
        write_json_atomic(&self.config.directory.join("checkpoint.json"), &envelope)?;
        File::open(&self.config.directory)?.sync_all()?;
        self.last_published = saved.budget.consumed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::checkpoint_rpc_identity;

    #[test]
    fn checkpoint_rpc_identity_distinguishes_paths_and_query_credentials() {
        let first = checkpoint_rpc_identity("https://rpc.example/v1?api_key=secret-one");
        let second = checkpoint_rpc_identity("https://rpc.example/v2?api_key=secret-one");
        let third = checkpoint_rpc_identity("https://rpc.example/v1?api_key=secret-two");
        assert_ne!(first, second);
        assert_ne!(first, third);
        assert!(!first.contains("secret-one"));
        assert!(!first.contains("rpc.example"));
    }
}
