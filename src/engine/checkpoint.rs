//! Coordinated single-process campaign checkpoints, published at stage boundaries.
use super::concolic::ConcolicHint;
use super::fuzz_engine::Config;
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
    pub fn restore(self) -> SnapshotCorpus {
        SnapshotCorpus {
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
        }
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
        let mut identity_config = config.clone();
        identity_config.hardened_defi.checkpoint = None;
        let mut identity = format!("{identity_config:?}").into_bytes();
        for path in [
            &config.abi_path,
            &config.target_invariant_manifest,
            &config.hardened_defi.historical_seed_file,
        ]
        .into_iter()
        .flatten()
        {
            let bytes =
                fs::read(path).with_context(|| format!("checkpoint identity input {path}"))?;
            identity.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            identity.extend_from_slice(&bytes);
        }
        let digest = format!("{:x}", keccak256(identity));
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
            ensure!(
                envelope.schema_version == 1,
                "unsupported checkpoint schema"
            );
            ensure!(
                envelope.producer_version == env!("CARGO_PKG_VERSION"),
                "checkpoint producer version mismatch"
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
        resumed: bool,
    ) -> anyhow::Result<()> {
        let bytes = postcard::to_stdvec(saved).context("serialize checkpoint")?;
        let envelope = CheckpointEnvelope {
            schema_version: 1,
            producer_version: env!("CARGO_PKG_VERSION").into(),
            config_digest: self.digest.clone(),
            budget_consumed: saved.budget.consumed,
            completed_execs: saved.telemetry.executions,
            corpus_ids,
            coverage,
            payload_digest: format!("{:x}", keccak256(&bytes)),
            payload_hex: hex::encode(bytes),
        };
        let name = if resumed {
            "resume.json"
        } else {
            "checkpoint.json"
        };
        write_json_atomic(&self.config.directory.join(name), &envelope)?;
        // Checkpoint publication requires directory sync, unlike best-effort
        // report output. A failed sync is an error, never a successful commit.
        File::open(&self.config.directory)?.sync_all()?;
        self.last_published = saved.budget.consumed;
        Ok(())
    }
}
