use crate::common::fs_security::{contained_path, validate_filesystem_identifier};
use crate::common::oracle::{FindingStatus, ProtocolFinding, ProtocolSeverity};
use crate::common::types::{
    ChainState, ExecutionStatus, SequenceExecutionResult, Snapshot, Waypoint,
};
use crate::engine::confirmation::{FindingConfirmation, FindingConfirmationGate};
use crate::engine::exploit_path::ExploitPathCandidate;
use crate::engine::proof::{ProofCarryingFinding, ProofConfidenceTier};
use crate::engine::scoring::CampaignScore;
use crate::evm::feedback::EvmCoverageFeedback;
use crate::evm::fuzz::{EvmInput, EvmTestcaseMetadata};
use crate::evm::seed_ingester::MainnetSeedBundle;
use anyhow::Context;
use libafl_bolts::rands::Rand;
use parking_lot::RwLock;
use revm::primitives::{Address, B256, U256};
use rustyfuzz_artifacts::fsutil::write_atomic;
use rustyfuzz_core::SnapshotId;
use rustyfuzz_evm::fork_db::{validate_block_hash, EvmCacheDb, ForkDb, ForkDbCacheSnapshot};
use rustyfuzz_evm::inspector::MAP_SIZE;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
use std::num::{NonZero, NonZeroU128};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
// use bitvec::bitvec; // Unused
use bitvec::prelude::{BitVec, Lsb0};
use serde::{Deserialize, Serialize};

/// Owns only locks successfully created by this process. Release on both
/// success and error so a failed disk write does not poison later attempts.
struct ArtifactLock {
    file: Option<fs::File>,
    path: PathBuf,
}

impl Drop for ArtifactLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    IdMismatch { expected: u64, actual: u64 },
    DuplicateSnapshot { id: u64 },
    MissingParent { id: u64, parent_id: u64 },
    CyclicLineage { id: u64, parent_id: u64 },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::IdMismatch { expected, actual } => write!(
                f,
                "snapshot id mismatch: requested id {expected}, snapshot payload id {actual}"
            ),
            SnapshotError::DuplicateSnapshot { id } => {
                write!(f, "snapshot id {id} already exists")
            }
            SnapshotError::MissingParent { id, parent_id } => write!(
                f,
                "snapshot {id} references missing parent snapshot {parent_id}"
            ),
            SnapshotError::CyclicLineage { id, parent_id } => write!(
                f,
                "snapshot {id} under parent {parent_id} would create cyclic lineage"
            ),
        }
    }
}

impl std::error::Error for SnapshotError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorpusEntryMetadata {
    pub id: String,
    pub input_hash: String,
    pub path_hash: u64,
    #[serde(default)]
    pub state_hash: u64,
    #[serde(default)]
    pub state_novelty_score: u64,
    pub coverage_edges: usize,
    pub gas_used: u64,
    pub crash_fingerprint: Option<String>,
    #[serde(default)]
    pub frontier: CorpusFrontierMetadata,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorpusFrontierMetadata {
    pub branch_distances: Vec<String>,
    pub expression_backed_comparisons: usize,
    pub mapping_derivations: usize,
    pub oracle_observations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashRecord {
    pub fingerprint: String,
    pub input_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// Persisted schema version; 1 for the original (pre-versioned) layout.
    #[serde(default = "default_snapshot_manifest_schema_version")]
    pub schema_version: u32,
    pub id: u64,
    pub state_hash: String,
    pub coverage_hash: u64,
    pub coverage_edges: usize,
    pub producing_input_id: Option<String>,
    pub depth: u32,
    pub gas_used: u64,
}

fn default_snapshot_manifest_schema_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampaignArtifactRecord {
    pub input_id: String,
    pub fork_cache_id: String,
    #[serde(default)]
    pub artifact_key: String,
    pub block_number: u64,
    pub target: Option<Address>,
    pub reason: String,
    pub score: CampaignScore,
    pub findings: Vec<ProtocolFinding>,
    #[serde(default)]
    pub proof: Option<ProofCarryingFinding>,
    pub metadata: CorpusEntryMetadata,
    #[serde(default)]
    pub triage: CampaignArtifactTriageSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampaignArtifactOutcome {
    pub record: CampaignArtifactRecord,
    pub created_new: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampaignArtifactTriageSummary {
    #[serde(default)]
    pub status: FindingStatus,
    pub persisted_reason: String,
    pub confidence: u64,
    #[serde(default)]
    pub proof_tier: Option<ProofConfidenceTier>,
    #[serde(default)]
    pub confirmation: Option<FindingConfirmation>,
    #[serde(default)]
    pub high_value_artifact: bool,
    #[serde(default)]
    pub replayable: bool,
    pub false_positive_risks: Vec<String>,
    pub suggested_next_command: String,
    pub dedup_key: String,
    pub finding_kinds: Vec<String>,
}

pub struct CampaignArtifactRequest<'a> {
    pub input: &'a EvmInput,
    pub execution: &'a SequenceExecutionResult,
    pub coverage: &'a [u8],
    pub state_novelty_score: u64,
    pub base_fork_state: &'a EvmCacheDb,
    pub score: &'a CampaignScore,
    pub findings: &'a [ProtocolFinding],
    pub exploit_candidate: Option<&'a ExploitPathCandidate>,
    pub block_number: u64,
    pub target: Option<Address>,
    pub reason: &'a str,
}

pub struct PersistentCorpus {
    root: PathBuf,
    global_root: Option<PathBuf>,
}

fn safe_corpus_path(
    root: &Path,
    area: &str,
    identifier: &str,
    suffix: &str,
) -> anyhow::Result<PathBuf> {
    validate_filesystem_identifier(identifier).map_err(anyhow::Error::msg)?;
    let path = root.join(area).join(format!("{identifier}{suffix}"));
    contained_path(root, &path).map_err(anyhow::Error::msg)
}

fn ensure_corpus_directory(root: &Path, path: &Path) -> anyhow::Result<()> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    if safe_path.exists() {
        anyhow::ensure!(
            safe_path.is_dir(),
            "corpus path is not a directory: {}",
            safe_path.display()
        );
    } else {
        fs::create_dir_all(&safe_path)?;
    }
    let canonical_root = fs::canonicalize(root)?;
    let canonical_path = fs::canonicalize(&safe_path)?;
    anyhow::ensure!(
        canonical_path.starts_with(&canonical_root),
        "corpus directory escapes its canonical root"
    );
    Ok(())
}

fn reject_symlink_components(path: &Path) -> anyhow::Result<()> {
    let mut current = Some(path.to_path_buf());
    while let Some(candidate) = current {
        if let Ok(metadata) = fs::symlink_metadata(&candidate) {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "corpus path contains a symlink: {}",
                candidate.display()
            );
        }
        current = candidate.parent().map(Path::to_path_buf);
    }
    Ok(())
}

fn canonical_corpus_root(path: &Path, label: &str) -> anyhow::Result<PathBuf> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(metadata.is_dir(), "{label} is not a directory");
    let canonical = fs::canonicalize(path)?;
    anyhow::ensure!(
        fs::symlink_metadata(&canonical)?.is_dir(),
        "{label} is not a directory after canonicalization"
    );
    Ok(canonical)
}

const MAX_PERSISTED_CORPUS_JSON_BYTES: u64 = 64 * 1024 * 1024;

fn read_regular_file_under(root: &Path, path: &Path, description: &str) -> anyhow::Result<Vec<u8>> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&safe_path)?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{description} is not a regular non-symlink file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_PERSISTED_CORPUS_JSON_BYTES,
        "{description} exceeds the {MAX_PERSISTED_CORPUS_JSON_BYTES} byte limit"
    );
    let file = fs::File::open(&safe_path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let read = file
        .take(MAX_PERSISTED_CORPUS_JSON_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_PERSISTED_CORPUS_JSON_BYTES
            && read as u64 <= MAX_PERSISTED_CORPUS_JSON_BYTES + 1,
        "{description} exceeds the {MAX_PERSISTED_CORPUS_JSON_BYTES} byte limit"
    );
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SeedBundleStatus {
    Loaded {
        bundle_id: String,
        path: PathBuf,
        seed_count: usize,
        account_count: usize,
    },
    Missing {
        bundle_id: String,
        path: PathBuf,
    },
    Empty {
        bundle_id: String,
        path: PathBuf,
        account_count: usize,
    },
    TargetMismatch {
        bundle_id: String,
        path: PathBuf,
        bundle_target: Address,
        campaign_target: Address,
        seed_count: usize,
    },
    Invalid {
        bundle_id: String,
        path: PathBuf,
        error: String,
    },
    Disabled,
}

impl PersistentCorpus {
    pub fn new(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::new_with_global_root(root, None::<&Path>)
    }

    pub fn new_with_global_root(
        root: impl AsRef<Path>,
        global_root: Option<impl AsRef<Path>>,
    ) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        reject_symlink_components(&root)?;
        fs::create_dir_all(&root)?;
        reject_symlink_components(&root)?;
        let root = canonical_corpus_root(&root, "corpus root")?;
        ensure_corpus_directory(&root, &root.join("inputs"))?;
        ensure_corpus_directory(&root, &root.join("crashes"))?;
        ensure_corpus_directory(&root, &root.join("fork_cache"))?;
        ensure_corpus_directory(&root, &root.join("mainnet_seeds"))?;
        ensure_corpus_directory(&root, &root.join("campaign_artifacts"))?;
        ensure_corpus_directory(&root, &root.join("campaign_artifacts").join("index"))?;
        ensure_corpus_directory(&root, &root.join("campaign_artifacts").join("summaries"))?;
        Self::validate_published_artifacts(&root)?;
        let global_root = global_root
            .map(|root| canonical_corpus_root(root.as_ref(), "global corpus root"))
            .transpose()?;
        Ok(Self { root, global_root })
    }

    fn validate_published_artifacts(root: &Path) -> anyhow::Result<()> {
        let index_dir = root.join("campaign_artifacts").join("index");
        reject_symlink_components(&index_dir)?;
        anyhow::ensure!(
            fs::symlink_metadata(&index_dir)?.is_dir(),
            "campaign artifact index directory is not a regular directory"
        );
        for entry in fs::read_dir(&index_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let bytes = read_regular_file_under(
                root,
                &path,
                &format!("campaign artifact index {}", path.display()),
            )?;
            let record: CampaignArtifactRecord = serde_json::from_slice(&bytes)
                .with_context(|| format!("validate campaign artifact index {}", path.display()))?;
            let input_id = &record.input_id;
            let members = [
                (
                    safe_corpus_path(root, "inputs", input_id, ".json")?,
                    "input",
                ),
                (
                    safe_corpus_path(root, "inputs", input_id, ".meta.json")?,
                    "input metadata",
                ),
                (
                    safe_corpus_path(root, "fork_cache", &record.fork_cache_id, ".json")?,
                    "fork cache",
                ),
                (
                    safe_corpus_path(root, "campaign_artifacts", input_id, ".json")?,
                    "artifact record",
                ),
                (
                    safe_corpus_path(root, "campaign_artifacts/summaries", input_id, ".md")?,
                    "artifact summary",
                ),
            ];
            for (member, label) in members {
                let member_bytes = read_regular_file_under(
                    root,
                    &member,
                    &format!(
                        "recover campaign artifact {input_id}: {label} {}",
                        member.display()
                    ),
                )?;
                if label != "artifact summary" {
                    match label {
                        "input" => {
                            EvmInput::split_legacy_json(&member_bytes).with_context(|| {
                                format!("recover campaign artifact {input_id}: validate {label}")
                            })?;
                        }
                        "input metadata" => {
                            serde_json::from_slice::<CorpusEntryMetadata>(&member_bytes)
                                .with_context(|| {
                                    format!(
                                        "recover campaign artifact {input_id}: validate {label}"
                                    )
                                })?;
                        }
                        "fork cache" => {
                            serde_json::from_slice::<ForkDbCacheSnapshot>(&member_bytes)
                                .with_context(|| {
                                    format!(
                                        "recover campaign artifact {input_id}: validate {label}"
                                    )
                                })?;
                        }
                        "artifact record" => {
                            serde_json::from_slice::<CampaignArtifactRecord>(&member_bytes)
                                .with_context(|| {
                                    format!(
                                        "recover campaign artifact {input_id}: validate {label}"
                                    )
                                })?;
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        Ok(())
    }

    pub fn persist_input(
        &self,
        input: &EvmInput,
        coverage: &[u8],
        gas_used: u64,
    ) -> anyhow::Result<CorpusEntryMetadata> {
        // Stage 2B: identity is derived from canonical semantic content only
        // (schema version || base snapshot || transactions), never from serialized
        // feedback fields.
        let input_hash = input.semantic_input_hash();
        let metadata = CorpusEntryMetadata {
            id: String::new(),
            input_hash,
            path_hash: EvmCoverageFeedback::stable_path_hash(coverage),
            state_hash: 0,
            state_novelty_score: 0,
            coverage_edges: coverage.iter().filter(|&&hit| hit != 0).count(),
            gas_used,
            crash_fingerprint: None,
            frontier: CorpusFrontierMetadata::default(),
        };

        self.write_entry_file(input, metadata)
    }

    pub fn persist_execution_input(
        &self,
        input: &EvmInput,
        execution: &SequenceExecutionResult,
        coverage: &[u8],
        state_novelty_score: u64,
    ) -> anyhow::Result<CorpusEntryMetadata> {
        // Stage 2B: canonical semantic identity; execution feedback stays out.
        let input_hash = input.semantic_input_hash();
        let metadata = CorpusEntryMetadata {
            id: String::new(),
            input_hash,
            path_hash: EvmCoverageFeedback::stable_path_hash(coverage),
            state_hash: crate::evm::feedback::stable_execution_state_hash(execution),
            state_novelty_score,
            coverage_edges: coverage.iter().filter(|&&hit| hit != 0).count(),
            gas_used: execution.total_gas_used,
            crash_fingerprint: None,
            frontier: frontier_metadata(execution),
        };

        self.write_entry_file(input, metadata)
    }

    /// Writes one input entry using the legacy 16-hex-char filename derived
    /// from the full semantic hash.
    ///
    /// Stage 2B.1 collision guard: the truncated prefix is only an index hint.
    /// When the target files already exist we compare the recorded full input
    /// hash against the entry being written:
    /// - equal -> same semantic input; rewriting is idempotent;
    /// - different -> a real 64-bit-prefix collision (or legacy foreign file);
    ///   the new entry keeps both inputs distinct under a deterministic
    ///   extended name `<prefix>-<fullhash>.json`.
    ///
    /// Historical corpora never rewritten; loading resolves full hashes via
    /// `load_input_with_metadata` against `input_hash` when needed.
    fn write_entry_file(
        &self,
        input: &EvmInput,
        mut metadata: CorpusEntryMetadata,
    ) -> anyhow::Result<CorpusEntryMetadata> {
        let full_hash = metadata.input_hash.trim_start_matches("0x").to_string();
        let prefix = &full_hash[..16];
        let prefix_input_path = safe_corpus_path(&self.root, "inputs", prefix, ".json")?;
        let prefix_meta_path = safe_corpus_path(&self.root, "inputs", prefix, ".meta.json")?;

        let id = if prefix_input_path.exists() {
            let existing_full = read_regular_file_under(
                &self.root,
                &prefix_meta_path,
                "existing persisted input metadata",
            )
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CorpusEntryMetadata>(&bytes).ok())
            .map(|existing| existing.input_hash)
            .unwrap_or_default();
            if existing_full.trim_start_matches("0x") == full_hash {
                prefix.to_string()
            } else {
                format!("{prefix}-{full_hash}")
            }
        } else {
            prefix.to_string()
        };

        metadata.id = id.clone();
        let input_path = safe_corpus_path(&self.root, "inputs", &id, ".json")?;
        let meta_path = safe_corpus_path(&self.root, "inputs", &id, ".meta.json")?;
        write_atomic(input_path, serde_json::to_vec_pretty(input)?)?;
        write_atomic(meta_path, serde_json::to_vec_pretty(&metadata)?)?;
        Ok(metadata)
    }

    /// Loads a persisted input together with any legacy feedback/provenance.
    ///
    /// Pre-Stage-2B corpus files embed `waypoints` and `mutation_provenance`
    /// directly in the input JSON. This loader splits them explicitly so no
    /// historical data is silently discarded. Semantic inputs written after
    /// Stage 2B deserialize with empty metadata.
    pub fn load_input_with_metadata(
        &self,
        id: &str,
    ) -> anyhow::Result<(EvmInput, EvmTestcaseMetadata)> {
        let path = safe_corpus_path(&self.root, "inputs", id, ".json")?;
        let bytes = read_regular_file_under(&self.root, &path, &format!("persisted input {id}"))?;
        EvmInput::split_legacy_json(&bytes)
            .map_err(|err| anyhow::Error::new(err).context("deserialize persisted EvmInput"))
    }

    /// Legacy-compatible loader returning only the semantic executable input.
    ///
    /// TODO(stage-4): retire once all loaders consume `load_input_with_metadata`
    /// or metadata moves fully into LibAFL testcase state.
    pub fn load_input(&self, id: &str) -> anyhow::Result<EvmInput> {
        Ok(self.load_input_with_metadata(id)?.0)
    }

    pub fn resolve_input_id(&self, input: &EvmInput) -> anyhow::Result<String> {
        let input_hash = input.semantic_input_hash();
        let input_dir = self.root.join("inputs");
        for entry in fs::read_dir(input_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json")
                || path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".meta.json"))
            {
                continue;
            }
            let metadata_path = path.with_extension("meta.json");
            let Ok(bytes) =
                read_regular_file_under(&self.root, &metadata_path, "persisted input metadata")
            else {
                continue;
            };
            let metadata: CorpusEntryMetadata = serde_json::from_slice(&bytes)?;
            if metadata.input_hash == input_hash {
                return Ok(metadata.id);
            }
        }
        anyhow::bail!("persisted corpus entry for semantic input hash is missing")
    }

    pub fn len(&self) -> anyhow::Result<usize> {
        let input_dir = self.root.join("inputs");
        let mut count = 0usize;
        for entry in fs::read_dir(input_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json")
                && !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".meta.json"))
            {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn is_empty(&self) -> anyhow::Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn persist_fork_cache(
        &self,
        id: &str,
        fork_db: &ForkDb,
    ) -> anyhow::Result<ForkDbCacheSnapshot> {
        let snapshot = fork_db.cache_snapshot();
        let path = safe_corpus_path(&self.root, "fork_cache", id, ".json")?;
        write_atomic(&path, serde_json::to_vec_pretty(&snapshot)?)
            .with_context(|| format!("persist fork cache id={id:?} path={}", path.display()))?;
        Ok(snapshot)
    }

    pub fn persist_cache_db_fork_state(
        &self,
        id: &str,
        cache_db: &EvmCacheDb,
    ) -> anyhow::Result<ForkDbCacheSnapshot> {
        let snapshot_db = ForkDb::from_cache_snapshot(cache_db.db.cache_snapshot());

        for (address, account) in &cache_db.cache.accounts {
            if let Some(info) = account.info() {
                snapshot_db.cache_account(*address, info);
            }
            for (slot, value) in &account.storage {
                snapshot_db.cache_storage(*address, *slot, *value);
            }
        }

        for (code_hash, code) in &cache_db.cache.contracts {
            snapshot_db.cache_code(*code_hash, code.clone());
        }

        for (number, hash) in &cache_db.cache.block_hashes {
            if let Ok(number) = (*number).try_into() {
                snapshot_db.cache_block_hash(number, *hash);
            }
        }

        self.persist_fork_cache(id, &snapshot_db)
    }

    pub fn persist_campaign_artifact(
        &self,
        request: CampaignArtifactRequest<'_>,
    ) -> anyhow::Result<CampaignArtifactOutcome> {
        let artifact_key = artifact_equivalence_key(&request)?;
        validate_filesystem_identifier(&artifact_key).map_err(anyhow::Error::msg)?;
        let index_path = safe_corpus_path(
            &self.root,
            "campaign_artifacts/index",
            &artifact_key,
            ".json",
        )?;
        let lock_path = contained_path(
            &self.root,
            &self
                .root
                .join("campaign_artifacts")
                .join("index")
                .join(format!("{artifact_key}.lock")),
        )
        .map_err(anyhow::Error::msg)?;
        if let Ok(bytes) =
            read_regular_file_under(&self.root, &index_path, "campaign artifact index")
        {
            if let Ok(existing) = serde_json::from_slice::<CampaignArtifactRecord>(&bytes) {
                if existing.score.total >= request.score.total {
                    return Ok(CampaignArtifactOutcome {
                        record: existing,
                        created_new: false,
                    });
                }
            }
        }

        let lock_file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(_) => {
                let mut waited = 0u64;
                loop {
                    if let Ok(bytes) =
                        read_regular_file_under(&self.root, &index_path, "campaign artifact index")
                    {
                        if let Ok(existing) =
                            serde_json::from_slice::<CampaignArtifactRecord>(&bytes)
                        {
                            return Ok(CampaignArtifactOutcome {
                                record: existing,
                                created_new: false,
                            });
                        }
                    }

                    if waited >= 1_000 {
                        break;
                    }
                    waited += 1;
                    thread::sleep(Duration::from_millis(10));
                }

                if let Ok(bytes) =
                    read_regular_file_under(&self.root, &index_path, "campaign artifact index")
                {
                    if let Ok(existing) = serde_json::from_slice::<CampaignArtifactRecord>(&bytes) {
                        return Ok(CampaignArtifactOutcome {
                            record: existing,
                            created_new: false,
                        });
                    }
                }

                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&lock_path)
                    .with_context(|| format!("acquire artifact lock {}", lock_path.display()))?
            }
        };
        let _lock = ArtifactLock {
            file: Some(lock_file),
            path: lock_path,
        };

        if let Ok(bytes) =
            read_regular_file_under(&self.root, &index_path, "campaign artifact index")
        {
            if let Ok(existing) = serde_json::from_slice::<CampaignArtifactRecord>(&bytes) {
                if existing.score.total >= request.score.total {
                    return Ok(CampaignArtifactOutcome {
                        record: existing,
                        created_new: false,
                    });
                }
            }
        }

        let metadata = self.persist_execution_input(
            request.input,
            request.execution,
            request.coverage,
            request.state_novelty_score,
        )?;
        validate_filesystem_identifier(&metadata.id).map_err(anyhow::Error::msg)?;
        let record_path =
            safe_corpus_path(&self.root, "campaign_artifacts", &metadata.id, ".json")?;
        if let Ok(bytes) =
            read_regular_file_under(&self.root, &record_path, "campaign artifact record")
        {
            if let Ok(existing) = serde_json::from_slice::<CampaignArtifactRecord>(&bytes) {
                if existing.score.total >= request.score.total {
                    return Ok(CampaignArtifactOutcome {
                        record: existing,
                        created_new: false,
                    });
                }
            }
        }
        let fork_cache_id = metadata.id.clone();
        self.persist_cache_db_fork_state(&fork_cache_id, request.base_fork_state)?;
        let proof = request.exploit_candidate.map(|candidate| {
            ProofCarryingFinding::from_candidate(candidate, request.execution, request.findings)
        });
        let confirmation = FindingConfirmationGate::default().evaluate(
            proof.as_ref(),
            request.findings,
            request.score,
        );

        let record = CampaignArtifactRecord {
            input_id: metadata.id.clone(),
            fork_cache_id,
            artifact_key: artifact_key.clone(),
            block_number: request.block_number,
            target: request.target,
            reason: request.reason.to_string(),
            score: request.score.clone(),
            findings: request.findings.to_vec(),
            proof: proof.clone(),
            metadata,
            triage: triage_summary(TriageSummaryInput {
                artifact_key: &artifact_key,
                reason: request.reason,
                score: request.score,
                findings: request.findings,
                target: request.target,
                proof_tier: Some(confirmation.tier.clone()),
                replayable: confirmation.replay_success,
                confirmation: Some(confirmation),
            }),
        };
        let record_bytes = serde_json::to_vec_pretty(&record)?;
        write_atomic(&record_path, &record_bytes)?;
        write_atomic(
            safe_corpus_path(
                &self.root,
                "campaign_artifacts/summaries",
                &record.input_id,
                ".md",
            )?,
            triage_markdown(&record),
        )?;
        // Publish the discovery index only after every dependent artifact.
        write_atomic(&index_path, &record_bytes)?;
        Ok(CampaignArtifactOutcome {
            record,
            created_new: true,
        })
    }

    pub fn list_campaign_artifacts(&self) -> anyhow::Result<Vec<CampaignArtifactRecord>> {
        let index_dir = self.root.join("campaign_artifacts").join("index");
        reject_symlink_components(&index_dir)?;
        anyhow::ensure!(
            fs::symlink_metadata(&index_dir)?.is_dir(),
            "campaign artifact index directory is not a regular directory"
        );
        let mut records = fs::read_dir(index_dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .map(|path| {
                read_regular_file_under(
                    &self.root,
                    &path,
                    &format!("campaign artifact index {}", path.display()),
                )
                .and_then(|bytes| {
                    serde_json::from_slice::<CampaignArtifactRecord>(&bytes)
                        .with_context(|| format!("decode campaign artifact {}", path.display()))
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        records.sort_by(|left, right| left.input_id.cmp(&right.input_id));
        records.dedup_by(|left, right| left.input_id == right.input_id);
        Ok(records)
    }

    pub fn load_fork_cache(&self, id: &str) -> anyhow::Result<ForkDbCacheSnapshot> {
        let path = safe_corpus_path(&self.root, "fork_cache", id, ".json")?;
        let bytes = read_regular_file_under(&self.root, &path, &format!("fork cache {id}"))?;
        let snapshot: ForkDbCacheSnapshot = serde_json::from_slice(&bytes)?;
        snapshot
            .verify_content_digest()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(snapshot)
    }

    pub fn load_offline_fork_db(&self, id: &str) -> anyhow::Result<ForkDb> {
        Ok(ForkDb::from_cache_snapshot(self.load_fork_cache(id)?))
    }

    pub fn load_online_fork_db(
        &self,
        id: &str,
        expected_block: u64,
        expected_provider: &str,
        expected_chain_id: u64,
        observed_block_hash: &str,
    ) -> anyhow::Result<ForkDb> {
        let snapshot = self.load_fork_cache(id)?;
        anyhow::ensure!(
            !snapshot.provenance.provider_sanitized.is_empty(),
            "online fork cache is missing provider provenance"
        );
        anyhow::ensure!(
            snapshot.provenance.provider_sanitized == expected_provider,
            "online fork cache provider does not match the live provider"
        );
        anyhow::ensure!(
            snapshot.provenance.chain_id == Some(expected_chain_id),
            "online fork cache chain id is missing or does not match the live chain"
        );
        anyhow::ensure!(
            snapshot.provenance.block_number == Some(expected_block),
            "online fork cache is missing the expected block number"
        );
        let block_hash = snapshot
            .provenance
            .block_hash
            .as_deref()
            .context("online fork cache is missing a pinned block hash")?;
        validate_block_hash(block_hash)
            .map_err(|error| anyhow::anyhow!("online fork cache block hash is invalid: {error}"))?;
        validate_block_hash(observed_block_hash)
            .map_err(|error| anyhow::anyhow!("live block hash is invalid: {error}"))?;
        anyhow::ensure!(
            snapshot.provenance.fetched_at_unix.is_some(),
            "online fork cache is missing a fetch timestamp"
        );
        anyhow::ensure!(
            snapshot
                .provenance
                .cache_id
                .as_deref()
                .is_some_and(|cache_id| !cache_id.is_empty()),
            "online fork cache is missing a cache id"
        );
        snapshot
            .ensure_consistent(
                Some(expected_block),
                Some(observed_block_hash),
                None,
                None,
                true,
            )
            .map_err(|error| anyhow::anyhow!("fork cache is not replay-consistent: {error}"))?;
        Ok(ForkDb::from_cache_snapshot(snapshot))
    }

    pub fn validate_seed_bundle_id(id: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            Self::valid_seed_bundle_id(id),
            "seed bundle id contains unsupported path characters"
        );
        Ok(())
    }

    fn valid_seed_bundle_id(id: &str) -> bool {
        validate_filesystem_identifier(id).is_ok()
    }

    pub fn persist_mainnet_seed_bundle(
        &self,
        id: &str,
        bundle: &MainnetSeedBundle,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            Self::valid_seed_bundle_id(id),
            "seed bundle id contains unsupported path characters"
        );
        let bundle_path = self.root.join("mainnet_seeds").join(id);
        ensure_corpus_directory(&self.root, &bundle_path.join("inputs"))?;

        write_atomic(
            contained_path(&self.root, &bundle_path.join("manifest.json"))
                .map_err(anyhow::Error::msg)?,
            serde_json::to_vec_pretty(bundle)?,
        )?;
        write_atomic(
            contained_path(&self.root, &bundle_path.join("fork_cache.json"))
                .map_err(anyhow::Error::msg)?,
            serde_json::to_vec_pretty(&bundle.fork_cache)?,
        )?;

        for seed in &bundle.seeds {
            validate_filesystem_identifier(&seed.id).map_err(anyhow::Error::msg)?;
            let seed_path = contained_path(
                &self.root,
                &bundle_path.join("inputs").join(format!("{}.json", seed.id)),
            )
            .map_err(anyhow::Error::msg)?;
            write_atomic(seed_path, serde_json::to_vec_pretty(&seed.input)?)?;
        }

        Ok(())
    }

    pub fn load_mainnet_seed_bundle(&self, id: &str) -> anyhow::Result<MainnetSeedBundle> {
        anyhow::ensure!(
            Self::valid_seed_bundle_id(id),
            "seed bundle id contains unsupported path characters"
        );
        let path = self
            .resolve_mainnet_seed_bundle_manifest_path(id)
            .unwrap_or(self.safe_mainnet_seed_bundle_manifest_path(id)?);
        let bytes = read_regular_file_under(
            path.parent().unwrap_or(&self.root),
            &path,
            &format!("mainnet seed bundle {id} manifest"),
        )?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn safe_mainnet_seed_bundle_manifest_path(&self, id: &str) -> anyhow::Result<PathBuf> {
        Self::validate_seed_bundle_id(id)?;
        let path = self
            .root
            .join("mainnet_seeds")
            .join(id)
            .join("manifest.json");
        contained_path(&self.root, &path).map_err(anyhow::Error::msg)
    }

    fn resolve_mainnet_seed_bundle_manifest_path(&self, id: &str) -> Option<PathBuf> {
        let local = self.safe_mainnet_seed_bundle_manifest_path(id).ok()?;
        if local.exists() {
            return Some(local);
        }
        let global_root = self.global_root.as_deref()?;
        let global = global_root
            .join("mainnet_seeds")
            .join(id)
            .join("manifest.json");
        let global = contained_path(global_root, &global).ok()?;
        (global != local && global.exists()).then_some(global)
    }

    pub fn inspect_mainnet_seed_bundle(
        &self,
        id: Option<&str>,
        campaign_target: Address,
    ) -> SeedBundleStatus {
        let Some(id) = id else {
            return SeedBundleStatus::Disabled;
        };
        if !Self::valid_seed_bundle_id(id) {
            return SeedBundleStatus::Invalid {
                bundle_id: id.to_string(),
                path: self.root.join("mainnet_seeds").join("<invalid>"),
                error: "seed bundle id contains unsupported path characters".to_string(),
            };
        }
        let local_path = match self.safe_mainnet_seed_bundle_manifest_path(id) {
            Ok(path) => path,
            Err(error) => {
                return SeedBundleStatus::Invalid {
                    bundle_id: id.to_string(),
                    path: self.root.join("mainnet_seeds").join("<invalid>"),
                    error: error.to_string(),
                }
            }
        };
        let Some(path) = self.resolve_mainnet_seed_bundle_manifest_path(id) else {
            return SeedBundleStatus::Missing {
                bundle_id: id.to_string(),
                path: local_path,
            };
        };
        match self.load_mainnet_seed_bundle(id) {
            Ok(bundle) if bundle.target != campaign_target => SeedBundleStatus::TargetMismatch {
                bundle_id: id.to_string(),
                path,
                bundle_target: bundle.target,
                campaign_target,
                seed_count: bundle.seeds.len(),
            },
            Ok(bundle) if bundle.seeds.is_empty() => SeedBundleStatus::Empty {
                bundle_id: id.to_string(),
                path,
                account_count: bundle.discovered_accounts.len(),
            },
            Ok(bundle) => SeedBundleStatus::Loaded {
                bundle_id: id.to_string(),
                path,
                seed_count: bundle.seeds.len(),
                account_count: bundle.discovered_accounts.len(),
            },
            Err(err) => SeedBundleStatus::Invalid {
                bundle_id: id.to_string(),
                path,
                error: err.to_string(),
            },
        }
    }

    pub fn persist_crash(
        &self,
        metadata: &CorpusEntryMetadata,
        reason: &str,
    ) -> anyhow::Result<CrashRecord> {
        validate_filesystem_identifier(&metadata.id).map_err(anyhow::Error::msg)?;
        let material = format!("{}:{reason}", metadata.path_hash);
        let fingerprint = format!("0x{}", hex::encode(revm::primitives::keccak256(material)));
        let record = CrashRecord {
            fingerprint: fingerprint.clone(),
            input_id: metadata.id.clone(),
            reason: reason.to_string(),
        };
        write_atomic(
            safe_corpus_path(&self.root, "crashes", &fingerprint[2..18], ".json")?,
            serde_json::to_vec_pretty(&record)?,
        )?;
        Ok(record)
    }

    pub fn persist_snapshot_manifest(
        &self,
        snapshot: &Snapshot,
        producing_input_id: Option<String>,
    ) -> anyhow::Result<SnapshotManifest> {
        ensure_corpus_directory(&self.root, &self.root.join("snapshots"))?;
        let manifest = SnapshotManifest {
            schema_version: 1,
            id: snapshot.id,
            state_hash: hash_snapshot_state(snapshot),
            coverage_hash: EvmCoverageFeedback::stable_path_hash(
                &snapshot
                    .coverage
                    .iter()
                    .map(|bit| u8::from(*bit))
                    .collect::<Vec<_>>(),
            ),
            coverage_edges: snapshot.coverage.count_ones(),
            producing_input_id,
            depth: snapshot.depth,
            gas_used: snapshot.gas_used,
        };
        write_atomic(
            contained_path(
                &self.root,
                &self
                    .root
                    .join("snapshots")
                    .join(format!("{}.manifest.json", snapshot.id)),
            )
            .map_err(anyhow::Error::msg)?,
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        Ok(manifest)
    }

    pub fn write_reproduction_report(
        &self,
        input: &EvmInput,
        execution: &SequenceExecutionResult,
        crash: Option<&CrashRecord>,
    ) -> anyhow::Result<PathBuf> {
        let input_hash = input
            .semantic_input_hash()
            .trim_start_matches("0x")
            .to_string();
        let report_id = &input_hash[..16];
        let path = contained_path(&self.root, &self.root.join(format!("repro_{report_id}.md")))
            .map_err(anyhow::Error::msg)?;

        let mut report = String::new();
        report.push_str("# RustyFuzz Reproduction\n\n");
        report.push_str(&format!("- Input hash: `0x{input_hash}`\n"));
        report.push_str(&format!("- Transactions: `{}`\n", input.txs.len()));
        report.push_str(&format!(
            "- Total gas used: `{}`\n",
            execution.total_gas_used
        ));
        report.push_str(&format!(
            "- Final coverage hash: `{}`\n",
            execution.final_coverage_hash
        ));
        if let Some(crash) = crash {
            report.push_str(&format!("- Crash fingerprint: `{}`\n", crash.fingerprint));
            report.push_str(&format!("- Crash reason: `{}`\n", crash.reason));
        }

        report.push_str("\n## Transaction Sequence\n\n");
        report.push_str("| Index | Caller | Target | Value | Status | Gas | Calldata |\n");
        report.push_str("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for (idx, tx) in input.txs.iter().enumerate() {
            let result = execution.tx_results.get(idx);
            let status = result
                .map(|result| format!("{:?}", result.status))
                .unwrap_or_else(|| "NotExecuted".to_string());
            let gas = result
                .map(|result| result.gas_used.to_string())
                .unwrap_or_else(|| "0".to_string());
            report.push_str(&format!(
                "| {} | `{}` | `{}` | `{}` | `{}` | `{}` | `0x{}` |\n",
                idx,
                tx.caller,
                tx.to,
                tx.value,
                status,
                gas,
                hex::encode(&tx.input)
            ));
        }

        report.push_str("\n## Execution Evidence\n\n");
        for result in &execution.tx_results {
            report.push_str(&format!(
                "- tx {}: status `{:?}`, gas `{}`, edges `{}`, coverage hash `{}`\n",
                result.tx_index,
                result.status,
                result.gas_used,
                result.coverage_edges,
                result.coverage_hash
            ));
            for waypoint in result.waypoints.iter().take(16) {
                report.push_str(&format!("  - `{:?}`\n", waypoint));
            }
        }

        write_atomic(&path, report)?;
        Ok(path)
    }
}

fn frontier_metadata(execution: &SequenceExecutionResult) -> CorpusFrontierMetadata {
    let mut branch_distances = Vec::new();
    let mut expression_backed_comparisons = 0usize;
    let mut mapping_derivations = 0usize;

    for waypoint in execution
        .tx_results
        .iter()
        .flat_map(|result| result.waypoints.iter())
    {
        match waypoint {
            Waypoint::Comparison {
                branch_distance,
                lhs_expression,
                rhs_expression,
                ..
            } => {
                if let Some(distance) = branch_distance {
                    branch_distances
                        .push(format!("0x{}", hex::encode(distance.to_be_bytes::<32>())));
                }
                if lhs_expression.is_some() || rhs_expression.is_some() {
                    expression_backed_comparisons += 1;
                }
            }
            Waypoint::MappingDerivation { .. } => {
                mapping_derivations += 1;
            }
            _ => {}
        }
    }

    branch_distances.sort();
    branch_distances.dedup();
    CorpusFrontierMetadata {
        branch_distances,
        expression_backed_comparisons,
        mapping_derivations,
        oracle_observations: execution.oracle_observations.len(),
    }
}

fn hash_snapshot_state(snapshot: &Snapshot) -> String {
    let state = snapshot.state.read();
    let ChainState::Evm(db) = &*state;
    let mut material = Vec::new();
    let mut accounts: Vec<_> = db.cache.accounts.iter().collect();
    accounts.sort_by_key(|(address, _)| **address);
    for (address, account) in accounts {
        material.extend_from_slice(address.as_slice());
        material.extend_from_slice(&account.info.balance.to_be_bytes::<32>());
        material.extend_from_slice(&account.info.nonce.to_be_bytes());
        material.extend_from_slice(account.info.code_hash.as_slice());

        let mut storage: Vec<_> = account.storage.iter().collect();
        storage.sort_by_key(|(slot, _)| **slot);
        for (slot, value) in storage {
            material.extend_from_slice(&slot.to_be_bytes::<32>());
            material.extend_from_slice(&value.to_be_bytes::<32>());
        }
    }
    format!("0x{}", hex::encode(revm::primitives::keccak256(material)))
}

#[derive(Debug, Serialize)]
struct ArtifactEquivalenceComponents {
    sequence_hash: String,
    final_coverage_hash: u64,
    finding_types: Vec<String>,
    target: Option<Address>,
    touched_slots: Vec<(Address, B256)>,
    reason: String,
}

fn artifact_equivalence_key(request: &CampaignArtifactRequest<'_>) -> anyhow::Result<String> {
    let components = artifact_equivalence_components(
        request.input,
        request.execution,
        request.findings,
        request.target,
        request.reason,
    )?;
    let encoded = serde_json::to_vec(&components)?;
    Ok(hex::encode(revm::primitives::keccak256(encoded)))
}

fn artifact_equivalence_components(
    input: &EvmInput,
    execution: &SequenceExecutionResult,
    findings: &[ProtocolFinding],
    target: Option<Address>,
    reason: &str,
) -> anyhow::Result<ArtifactEquivalenceComponents> {
    let sequence_hash = input.semantic_input_hash();
    let mut finding_types: Vec<_> = findings
        .iter()
        .map(|finding| format!("{:?}:{:?}", finding.pack, finding.vuln))
        .collect();
    finding_types.sort();
    finding_types.dedup();

    let mut touched_slots: Vec<_> = execution
        .storage_diffs
        .iter()
        .map(|diff| (diff.address, diff.slot))
        .collect();
    touched_slots.sort();
    touched_slots.dedup();
    touched_slots.truncate(64);

    Ok(ArtifactEquivalenceComponents {
        sequence_hash,
        final_coverage_hash: execution.final_coverage_hash,
        finding_types,
        target,
        touched_slots,
        reason: reason.to_string(),
    })
}

struct TriageSummaryInput<'a> {
    artifact_key: &'a str,
    reason: &'a str,
    score: &'a CampaignScore,
    findings: &'a [ProtocolFinding],
    target: Option<Address>,
    proof_tier: Option<ProofConfidenceTier>,
    replayable: bool,
    confirmation: Option<FindingConfirmation>,
}

fn triage_summary(input: TriageSummaryInput<'_>) -> CampaignArtifactTriageSummary {
    let finding_kinds: Vec<_> = input
        .findings
        .iter()
        .map(|finding| format!("{:?}:{:?}", finding.pack, finding.vuln))
        .collect();
    let max_severity = input
        .findings
        .iter()
        .map(|finding| severity_confidence(&finding.severity))
        .max()
        .unwrap_or(0);
    let mut confidence = max_severity
        .saturating_add((input.score.total / 100).min(25))
        .min(100);
    let mut false_positive_risks = if input.findings.is_empty() {
        vec![
            "score-only artifact; replay before treating as vulnerability evidence".to_string(),
            "state novelty or economic pressure may be benign protocol behavior".to_string(),
        ]
    } else {
        input
            .findings
            .iter()
            .flat_map(|finding| {
                [
                    format!(
                        "{} evidence is heuristic unless replay/minimization preserves it",
                        finding.vuln
                    ),
                    "fork-specific balances, roles, or oracle state may affect reproducibility"
                        .to_string(),
                ]
            })
            .collect()
    };
    if input.reason.starts_with("synthetic-non-production") {
        confidence = confidence.min(35);
        false_positive_risks.push(
            "synthetic fallback artifact; non-production evidence until replayed on a real fork"
                .to_string(),
        );
    }
    let suggested_next_command = match input.target {
        Some(address) => {
            format!("cargo run --release -- fuzz --chain evm --contract {address}")
        }
        None => "cargo run --release -- fuzz --chain evm".to_string(),
    };

    CampaignArtifactTriageSummary {
        status: triage_status(input.findings, input.confirmation.as_ref()),
        persisted_reason: input.reason.to_string(),
        confidence,
        proof_tier: input.proof_tier,
        high_value_artifact: input
            .confirmation
            .as_ref()
            .is_some_and(|confirmation| confirmation.high_value_artifact),
        confirmation: input.confirmation,
        replayable: input.replayable,
        false_positive_risks,
        suggested_next_command,
        dedup_key: input.artifact_key.to_string(),
        finding_kinds,
    }
}

fn triage_status(
    findings: &[ProtocolFinding],
    confirmation: Option<&FindingConfirmation>,
) -> FindingStatus {
    if confirmation.is_some_and(|confirmation| confirmation.confirmed) {
        FindingStatus::Proved
    } else if confirmation.is_some_and(|confirmation| confirmation.minimized_path) {
        FindingStatus::Minimized
    } else if confirmation.is_some_and(|confirmation| confirmation.replay_success) {
        FindingStatus::Replayed
    } else {
        let _ = findings;
        FindingStatus::Lead
    }
}

fn severity_confidence(severity: &ProtocolSeverity) -> u64 {
    match severity {
        ProtocolSeverity::Info => 20,
        ProtocolSeverity::Low => 35,
        ProtocolSeverity::Medium => 55,
        ProtocolSeverity::High => 75,
        ProtocolSeverity::Critical => 90,
    }
}

fn triage_markdown(record: &CampaignArtifactRecord) -> String {
    format!(
        "# RustyFuzz Campaign Artifact\n\n- input_id: `{}`\n- status: `{:?}`\n- reason: `{}`\n- confidence: `{}`\n- proof_tier: `{:?}`\n- high_value_artifact: `{}`\n- replayable: `{}`\n- score: `{}`\n- target: `{:?}`\n- dedup_key: `{}`\n- findings: `{}`\n- confirmation_blockers: `{}`\n\n## False-positive risks\n{}\n\n## Next command\n`{}`\n",
        record.input_id,
        record.triage.status,
        record.reason,
        record.triage.confidence,
        record.triage.proof_tier,
        record.triage.high_value_artifact,
        record.triage.replayable,
        record.score.total,
        record.target,
        record.artifact_key,
        record.triage.finding_kinds.join(", "),
        record
            .triage
            .confirmation
            .as_ref()
            .map(|confirmation| confirmation.reasons.join(", "))
            .unwrap_or_else(|| "not evaluated".to_string()),
        record
            .triage
            .false_positive_risks
            .iter()
            .map(|risk| format!("- {risk}"))
            .collect::<Vec<_>>()
            .join("\n"),
        record.triage.suggested_next_command
    )
}

#[cfg(test)]
mod artifact_tests {
    use super::*;
    use crate::common::types::{
        CallKind, CallObservation, CallPhase, ComparisonOperand, ExecutionStatus,
        OracleObservation, SingletonTx, StorageAccess, StorageDiff, TxExecutionResult, Waypoint,
    };
    use crate::evm::seed_ingester::{MainnetSeed, SeedMetadata};
    use libafl_bolts::rands::{Rand, RomuDuoJrRand};
    use revm::database::CacheDB;
    use revm::primitives::U256;
    use std::num::NonZeroUsize;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug)]
    struct ScriptedRand {
        draws: Vec<usize>,
        cursor: usize,
    }

    impl ScriptedRand {
        fn new(draws: impl Into<Vec<usize>>) -> Self {
            Self {
                draws: draws.into(),
                cursor: 0,
            }
        }
    }

    impl Rand for ScriptedRand {
        fn set_seed(&mut self, _seed: u64) {
            self.cursor = 0;
        }

        fn next(&mut self) -> u64 {
            0
        }

        fn below(&mut self, upper_bound_excl: NonZeroUsize) -> usize {
            let value = self.draws.get(self.cursor).copied().unwrap_or(0);
            self.cursor += 1;
            assert!(
                value < upper_bound_excl.get(),
                "scripted draw {value} is outside 0..{}",
                upper_bound_excl.get()
            );
            value
        }
    }

    fn temp_corpus_root(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("rustyfuzz-{name}-{}-{suffix}", std::process::id()))
    }

    fn seed_bundle(target: Address, seeds: Vec<MainnetSeed>) -> MainnetSeedBundle {
        MainnetSeedBundle {
            fork_block: 100,
            target,
            seeds,
            discovered_accounts: Vec::new(),
            fork_cache: ForkDb::empty().cache_snapshot(),
            scan: None,
        }
    }

    fn seed(target: Address) -> MainnetSeed {
        MainnetSeed {
            id: "seed-1".to_string(),
            input: EvmInput {
                txs: vec![SingletonTx {
                    input: vec![0xde, 0xad, 0xbe, 0xef],
                    caller: Address::repeat_byte(0x13),
                    to: target,
                    value: U256::ZERO,
                    is_victim: false,
                }],
                base_snapshot_id: 0,
            },
            metadata: SeedMetadata {
                source_block: 100,
                block_offset: 0,
                transaction_ordinal: 0,
                caller: Address::repeat_byte(0x13),
                target,
                value: U256::ZERO,
                selector: Some([0xde, 0xad, 0xbe, 0xef]),
                calldata_len: 4,
                discovered_address_hints: Vec::new(),
                matched_target: Some(target),
                match_kind: Some("direct".to_string()),
                confidence: Some(95),
                provenance: Some("test".to_string()),
                decoded: None,
                tx_hash: None,
                top_level_caller: Some(Address::repeat_byte(0x13)),
                internal_caller: None,
                trace_path: None,
                trace_source: None,
            },
        }
    }

    fn snapshot_with_coverage(id: u64, coverage_edges: usize, depth: u32) -> Snapshot {
        let mut coverage = bitvec::bitvec![u8, Lsb0; 0; 16];
        for idx in 0..coverage_edges.min(coverage.len()) {
            coverage.set(idx, true);
        }
        Snapshot {
            id,
            state: Arc::new(RwLock::new(ChainState::Evm(CacheDB::new(ForkDb::empty())))),
            coverage,
            producing_input: None,
            waypoints: Vec::new(),
            depth,
            gas_used: 0,
        }
    }

    fn insert_snapshot(
        corpus: &mut SnapshotCorpus,
        id: u64,
        parent_id: u64,
        coverage_edges: usize,
        depth: u32,
    ) {
        corpus
            .add_snapshot(
                id,
                parent_id,
                snapshot_with_coverage(id, coverage_edges, depth),
            )
            .expect("insert test snapshot");
    }

    fn scored_execution(
        target: Address,
        selector: [u8; 4],
        branch_distance: Option<U256>,
        oracle: bool,
        depth: usize,
        slot: B256,
        delta: U256,
    ) -> SequenceExecutionResult {
        let waypoint = branch_distance.map(|distance| Waypoint::Comparison {
            op: 0x14,
            lhs: U256::from(1),
            rhs: U256::from(2),
            pc: 7,
            calldata_offset: Some(4),
            condition: false,
            hit: false,
            taint_source: None,
            tainted_operand: ComparisonOperand::Lhs,
            lhs_expression: None,
            rhs_expression: None,
            branch_distance: Some(distance),
        });
        let diff = StorageDiff {
            tx_index: 0,
            address: target,
            slot,
            old_value: U256::ZERO,
            new_value: delta,
            pc: 1,
        };
        let call = CallObservation {
            tx_index: 0,
            depth,
            caller: Address::repeat_byte(0x11),
            target,
            value: U256::ZERO,
            input: selector.to_vec(),
            output: Vec::new(),
            gas_limit: 100_000,
            gas_used: 20_000,
            success: true,
            kind: CallKind::Call,
            phase: CallPhase::End,
            created_address: None,
            result: None,
        };
        let observation = OracleObservation {
            oracle: "event:Transfer".to_string(),
            finding: "near invariant".to_string(),
            tx_index: Some(0),
            evidence: "oracle proximity".to_string(),
        };
        SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 21_000,
                output: Vec::new(),
                coverage_hash: 1,
                coverage_edges: if oracle { 8 } else { 1 },
                storage_reads: Vec::new(),
                storage_writes: vec![StorageAccess {
                    tx_index: 0,
                    address: target,
                    slot,
                    value: Some(delta),
                    pc: 1,
                }],
                storage_diffs: vec![diff.clone()],
                call_trace: vec![call.clone()],
                waypoints: waypoint.into_iter().collect(),
            }],
            total_gas_used: 21_000,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: vec![StorageAccess {
                tx_index: 0,
                address: target,
                slot,
                value: Some(delta),
                pc: 1,
            }],
            storage_diffs: vec![diff],
            call_trace: vec![call],
            oracle_observations: oracle.then_some(observation).into_iter().collect(),
        }
    }

    #[test]
    fn snapshot_corpus_grows_from_meaningful_post_transaction_state() {
        let caller = Address::repeat_byte(0x44);
        let target = Address::repeat_byte(0x45);
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller,
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
        };
        let mut corpus = SnapshotCorpus::new();
        corpus
            .add_snapshot(
                0,
                0,
                Snapshot {
                    id: 0,
                    state: Arc::new(RwLock::new(ChainState::Evm(CacheDB::new(ForkDb::empty())))),
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: None,
                    waypoints: Vec::new(),
                    depth: 0,
                    gas_used: 0,
                },
            )
            .expect("insert root snapshot");
        let execution = SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 21_000,
                output: Vec::new(),
                coverage_hash: 1,
                coverage_edges: 1,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: vec![StorageDiff {
                    tx_index: 0,
                    address: target,
                    slot: B256::ZERO,
                    old_value: U256::ZERO,
                    new_value: U256::from(1),
                    pc: 1,
                }],
                call_trace: Vec::new(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 21_000,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: vec![StorageDiff {
                tx_index: 0,
                address: target,
                slot: B256::ZERO,
                old_value: U256::ZERO,
                new_value: U256::from(1),
                pc: 1,
            }],
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };
        let mut coverage = vec![0u8; 8];
        coverage[3] = 1;

        let id = corpus.maybe_add_post_execution_snapshot(
            0,
            &input,
            ChainState::Evm(CacheDB::new(ForkDb::empty())),
            &coverage,
            &execution,
            8,
        );

        assert_eq!(id, Some(1));
        assert_eq!(corpus.snapshots.len(), 2);
        let snapshot = corpus.get_snapshot(1).expect("snapshot inserted");
        let snapshot = snapshot.read();
        assert_eq!(snapshot.depth, 1);
        assert_eq!(snapshot.producing_input.as_ref(), Some(&input));
        assert!(snapshot.coverage[3]);
    }

    #[test]
    fn snapshot_scoring_is_deterministic_and_componentized() {
        let target = Address::repeat_byte(0x51);
        let execution = scored_execution(
            target,
            [0xde, 0xad, 0xbe, 0xef],
            Some(U256::from(1)),
            true,
            3,
            B256::from(U256::from(9).to_be_bytes::<32>()),
            U256::from(10u128.pow(18)),
        );
        let known_slots = HashSet::new();
        let known_selectors = HashSet::new();
        let left = SnapshotScore::from_execution(&execution, &known_slots, &known_selectors);
        let right = SnapshotScore::from_execution(&execution, &known_slots, &known_selectors);

        assert_eq!(left, right);
        assert_eq!(left.branch_distance, 1);
        assert_eq!(left.comparison_distance, 1);
        assert_eq!(left.oracle_proximity, 1);
        assert_eq!(left.event_novelty, 1);
        assert!(left.total(&SnapshotScoreWeights::default()) > 0);
    }

    #[test]
    fn high_value_snapshot_score_outranks_low_value_snapshot() {
        let target = Address::repeat_byte(0x52);
        let high = scored_execution(
            target,
            [0xaa, 0xbb, 0xcc, 0xdd],
            Some(U256::from(1)),
            true,
            4,
            B256::from(U256::from(1).to_be_bytes::<32>()),
            U256::from(10u128.pow(18)),
        );
        let low = scored_execution(
            target,
            [0xaa, 0xbb, 0xcc, 0xdd],
            None,
            false,
            0,
            B256::from(U256::from(1).to_be_bytes::<32>()),
            U256::from(1),
        );
        let weights = SnapshotScoreWeights::default();
        assert!(
            SnapshotScore::from_execution(&high, &HashSet::new(), &HashSet::new()).total(&weights)
                > SnapshotScore::from_execution(&low, &HashSet::new(), &HashSet::new())
                    .total(&weights)
        );
    }

    #[test]
    fn known_bug_class_weights_emphasize_relevant_snapshot_signals() {
        let default = SnapshotScoreWeights::default();
        let share = SnapshotScoreWeights::for_known_bug_class("erc4626 share inflation");
        let access = SnapshotScoreWeights::for_known_bug_class("proxy access-control bypass");
        let bridge = SnapshotScoreWeights::for_known_bug_class("bridge replay finalization bug");

        assert!(share.asset_delta_proximity > default.asset_delta_proximity);
        assert!(share.state_transition_rarity > default.state_transition_rarity);
        assert!(access.branch_distance > default.branch_distance);
        assert!(access.selector_novelty > default.selector_novelty);
        assert!(bridge.call_depth_novelty > default.call_depth_novelty);
        assert!(bridge.selector_novelty > default.selector_novelty);
    }

    #[test]
    fn class_weighted_snapshot_energy_prioritizes_known_bug_shape() {
        let target = Address::repeat_byte(0x54);
        let mut corpus = SnapshotCorpus::new();
        corpus
            .add_snapshot(
                0,
                0,
                Snapshot {
                    id: 0,
                    state: Arc::new(RwLock::new(ChainState::Evm(CacheDB::new(ForkDb::empty())))),
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: None,
                    waypoints: Vec::new(),
                    depth: 0,
                    gas_used: 0,
                },
            )
            .expect("insert root snapshot");
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0x6e, 0x55, 0x3f, 0x65],
                caller: Address::repeat_byte(0x13),
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
        };
        let accounting_like = scored_execution(
            target,
            [0x6e, 0x55, 0x3f, 0x65],
            None,
            true,
            1,
            B256::from(U256::from(3).to_be_bytes::<32>()),
            U256::from(10u128.pow(18)),
        );
        let shallow_coverage = scored_execution(
            target,
            [0x01, 0x02, 0x03, 0x04],
            Some(U256::from(4)),
            false,
            0,
            B256::from(U256::from(3).to_be_bytes::<32>()),
            U256::from(1),
        );
        let coverage = vec![1u8; 8];
        let accounting_id = corpus
            .maybe_add_post_execution_snapshot(
                0,
                &input,
                ChainState::Evm(CacheDB::new(ForkDb::empty())),
                &coverage,
                &accounting_like,
                8,
            )
            .expect("accounting-like snapshot");
        let shallow_id = corpus
            .maybe_add_post_execution_snapshot(
                0,
                &input,
                ChainState::Evm(CacheDB::new(ForkDb::empty())),
                &coverage,
                &shallow_coverage,
                8,
            )
            .expect("shallow snapshot");

        let weights = SnapshotScoreWeights::for_known_bug_class("erc4626 share inflation");
        let accounting_energy = corpus
            .snapshot_energy_with_weights(accounting_id, &weights)
            .expect("accounting energy");
        let shallow_energy = corpus
            .snapshot_energy_with_weights(shallow_id, &weights)
            .expect("shallow energy");

        assert!(accounting_energy > shallow_energy);
    }

    #[test]
    fn stage_2c_restored_snapshot_state_executes_equivalently() {
        use crate::common::verifier::ReplayVerifier;
        use revm::context::BlockEnv;

        // Build a snapshot holding funded state, the way the corpus stores it.
        let caller = Address::repeat_byte(0x61);
        let mut db = CacheDB::new(ForkDb::empty());
        db.insert_account_info(
            caller,
            revm::state::AccountInfo {
                balance: U256::from(10u128.pow(30)),
                ..revm::state::AccountInfo::default()
            },
        );
        let snapshot = Snapshot {
            id: 0,
            state: Arc::new(RwLock::new(ChainState::Evm(db))),
            coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
            producing_input: None,
            waypoints: Vec::new(),
            depth: 0,
            gas_used: 0,
        };

        // Harness-style restore: clone the cached chain state out of the
        // snapshot, execute an identical semantic input under identical env.
        let restore = || {
            let state = snapshot.state.read().clone();
            (state, BlockEnv::default())
        };
        let input = EvmInput::new(
            vec![SingletonTx {
                input: Vec::new(),
                caller,
                to: Address::repeat_byte(0x62),
                value: U256::from(1),
                is_victim: false,
            }],
            0,
        );

        let verifier = ReplayVerifier::new(1024);
        let (state_a, env_a) = restore();
        let first = verifier
            .replay(&state_a, &env_a, &input)
            .expect("first restore execution");
        let (state_b, env_b) = restore();
        let second = verifier
            .replay(&state_b, &env_b, &input)
            .expect("second restore execution");

        // Equivalent restored state + identical environment -> equivalent
        // execution. Determinism is only claimed for identical provenance.
        assert_eq!(first.total_gas_used, second.total_gas_used);
        assert_eq!(first.final_coverage_hash, second.final_coverage_hash);
        assert_eq!(first.storage_diffs, second.storage_diffs);
    }

    #[test]
    fn stage_2c_ancestry_reconstruction_is_deterministic() {
        let mut corpus = SnapshotCorpus::new();
        let empty_state = || Arc::new(RwLock::new(ChainState::Evm(CacheDB::new(ForkDb::empty()))));
        corpus
            .add_snapshot(
                0,
                0,
                Snapshot {
                    id: 0,
                    state: empty_state(),
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: None,
                    waypoints: Vec::new(),
                    depth: 0,
                    gas_used: 0,
                },
            )
            .expect("insert root snapshot");
        let input_a = EvmInput::new(
            vec![SingletonTx {
                input: vec![0xa1],
                caller: Address::repeat_byte(0x11),
                to: Address::repeat_byte(0x22),
                value: U256::ZERO,
                is_victim: false,
            }],
            0,
        );
        let input_b = EvmInput::new(input_a.txs.clone(), 1);
        corpus
            .add_snapshot(
                1,
                0,
                Snapshot {
                    id: 1,
                    state: empty_state(),
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: Some(input_a.clone()),
                    waypoints: Vec::new(),
                    depth: 1,
                    gas_used: 21_000,
                },
            )
            .expect("insert child snapshot");
        corpus
            .add_snapshot(
                2,
                1,
                Snapshot {
                    id: 2,
                    state: empty_state(),
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: Some(input_b.clone()),
                    waypoints: Vec::new(),
                    depth: 2,
                    gas_used: 42_000,
                },
            )
            .expect("insert grandchild snapshot");

        // Root has no parent and reconstructs an empty input sequence.
        assert_eq!(corpus.parent_map.get(&0), Some(&0));
        assert_eq!(corpus.lineage_inputs(0).unwrap(), Vec::<EvmInput>::new());

        // Lineage reconstruction is root-first and deterministic.
        let lineage = corpus.lineage_inputs(2).unwrap();
        assert_eq!(lineage, vec![input_a, input_b]);
        assert_eq!(corpus.lineage_inputs(2).unwrap(), lineage);

        // depth = parent depth + 1 is enforced by construction.
        assert_eq!(corpus.metadata[&1].depth, 1);
        assert_eq!(corpus.metadata[&2].depth, 2);
    }

    #[test]
    fn stage_2c_assigned_ids_and_state_fingerprints_are_distinct_concepts() {
        let make_snapshot = |id: u64| Snapshot {
            id,
            state: Arc::new(RwLock::new(ChainState::Evm(CacheDB::new(ForkDb::empty())))),
            coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
            producing_input: None,
            waypoints: Vec::new(),
            depth: 0,
            gas_used: 0,
        };
        let mut corpus = SnapshotCorpus::new();
        corpus
            .add_snapshot(0, 0, make_snapshot(0))
            .expect("insert root snapshot");
        corpus
            .add_snapshot(1, 0, make_snapshot(1))
            .expect("insert child snapshot");

        // Same cached-state content, different assigned ids: fingerprints match
        // even though ids differ. Ids remain the logical reference.
        assert_eq!(corpus.snapshots.len(), 2);
        assert_ne!(corpus.metadata[&0].state_fingerprint.len(), 0);
        assert_ne!(0, corpus.parent_map.keys().max().copied().unwrap());
        assert_eq!(
            corpus.metadata[&0].state_fingerprint,
            corpus.metadata[&1].state_fingerprint
        );
        assert!(!corpus.metadata[&0].state_fingerprint.is_empty());
    }

    #[test]
    fn stage_2c_cyclic_lineage_insertion_is_refused() {
        // Simulate a restored/merged corpus that already contains a dangling
        // cycle candidate: snapshot 9 claims parent 5 while 5 also references
        // a chain leading back to 9 via manual map surgery.
        let mut corpus = SnapshotCorpus::new();
        let empty_state = Arc::new(RwLock::new(ChainState::Evm(CacheDB::new(ForkDb::empty()))));
        corpus
            .add_snapshot(
                0,
                0,
                Snapshot {
                    id: 0,
                    state: empty_state.clone(),
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: None,
                    waypoints: Vec::new(),
                    depth: 0,
                    gas_used: 0,
                },
            )
            .expect("insert root snapshot");
        corpus
            .add_snapshot(
                5,
                0,
                Snapshot {
                    id: 5,
                    state: empty_state.clone(),
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: None,
                    waypoints: Vec::new(),
                    depth: 1,
                    gas_used: 0,
                },
            )
            .expect("insert snapshot before corruption");
        corpus.parent_map.insert(5, 9);

        let err = corpus
            .add_snapshot(
                9,
                5,
                Snapshot {
                    id: 9,
                    state: empty_state,
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: None,
                    waypoints: Vec::new(),
                    depth: 2,
                    gas_used: 0,
                },
            )
            .expect_err("cyclic insertion must fail");

        // The cycle-forming link was refused: snapshot 9 was not registered.
        assert_eq!(
            err,
            SnapshotError::CyclicLineage {
                id: 9,
                parent_id: 5
            }
        );
        assert!(!corpus.snapshots.contains_key(&9));
    }

    #[test]
    fn snapshot_insertion_rejects_missing_parent_duplicate_and_id_mismatch() {
        let mut corpus = SnapshotCorpus::new();

        assert_eq!(
            corpus
                .add_snapshot(1, 0, snapshot_with_coverage(1, 0, 1))
                .expect_err("missing parent must fail"),
            SnapshotError::MissingParent {
                id: 1,
                parent_id: 0
            }
        );

        insert_snapshot(&mut corpus, 0, 0, 0, 0);
        assert_eq!(
            corpus
                .add_snapshot(0, 0, snapshot_with_coverage(0, 0, 0))
                .expect_err("duplicate id must fail"),
            SnapshotError::DuplicateSnapshot { id: 0 }
        );
        assert_eq!(
            corpus
                .add_snapshot(1, 0, snapshot_with_coverage(99, 0, 1))
                .expect_err("payload id mismatch must fail"),
            SnapshotError::IdMismatch {
                expected: 1,
                actual: 99
            }
        );
    }

    #[test]
    fn pruning_uses_no_novelty_streak_and_protects_roots() {
        let mut corpus = SnapshotCorpus::new();
        insert_snapshot(&mut corpus, 0, 0, 0, 0);
        insert_snapshot(&mut corpus, 1, 0, 1, 1);
        insert_snapshot(&mut corpus, 2, 0, 1, 1);

        corpus.update_metadata(0, 0);
        corpus.update_metadata(0, 0);
        assert_eq!(corpus.metadata[&0].executions_since_novelty, 2);

        corpus.update_metadata(1, 1);
        assert_eq!(corpus.metadata[&1].executions_since_novelty, 1);
        corpus.prune_dead_ends(2);
        assert!(corpus.snapshots.contains_key(&1));

        corpus.update_metadata(1, 1);
        assert_eq!(corpus.metadata[&1].executions_since_novelty, 2);
        corpus.update_metadata(2, 2);
        assert_eq!(corpus.metadata[&2].executions_since_novelty, 0);
        corpus.prune_dead_ends(2);

        assert!(corpus.snapshots.contains_key(&0));
        assert!(!corpus.snapshots.contains_key(&1));
        assert!(corpus.snapshots.contains_key(&2));
    }

    #[test]
    fn retain_keeps_requested_descendant_ancestry_closure() {
        let mut corpus = SnapshotCorpus::new();
        insert_snapshot(&mut corpus, 0, 0, 0, 0);
        insert_snapshot(&mut corpus, 1, 0, 1, 1);
        insert_snapshot(&mut corpus, 2, 1, 1, 2);
        insert_snapshot(&mut corpus, 3, 2, 1, 3);
        insert_snapshot(&mut corpus, 4, 1, 1, 2);

        corpus.retain(&HashSet::from([3]));

        assert_eq!(
            corpus.sorted_snapshot_ids(),
            vec![0, 1, 2, 3],
            "requested descendant and all ancestors should remain"
        );
        assert_eq!(corpus.parent_map.get(&3), Some(&2));
        assert_eq!(corpus.children_map.get(&1), Some(&vec![2]));
        assert_eq!(corpus.children_map.get(&2), Some(&vec![3]));
        assert!(!corpus
            .children_map
            .values()
            .any(|children| children.contains(&4)));
    }

    #[test]
    fn retain_empty_set_still_protects_required_roots() {
        let mut corpus = SnapshotCorpus::new();
        insert_snapshot(&mut corpus, 0, 0, 0, 0);
        insert_snapshot(&mut corpus, 1, 0, 1, 1);

        corpus.retain(&HashSet::new());

        assert_eq!(corpus.sorted_snapshot_ids(), vec![0]);
        assert_eq!(corpus.parent_map.get(&0), Some(&0));
        assert!(corpus.children_map.is_empty());
    }

    #[test]
    fn seeded_snapshot_selection_is_deterministic_across_insertion_order() {
        let mut ascending = SnapshotCorpus::new();
        insert_snapshot(&mut ascending, 0, 0, 0, 0);
        insert_snapshot(&mut ascending, 1, 0, 1, 1);
        insert_snapshot(&mut ascending, 2, 0, 1, 1);
        insert_snapshot(&mut ascending, 3, 0, 1, 1);

        let mut shuffled = SnapshotCorpus::new();
        insert_snapshot(&mut shuffled, 0, 0, 0, 0);
        insert_snapshot(&mut shuffled, 3, 0, 1, 1);
        insert_snapshot(&mut shuffled, 1, 0, 1, 1);
        insert_snapshot(&mut shuffled, 2, 0, 1, 1);

        let mut left_rand = RomuDuoJrRand::with_seed(0x5eed);
        let mut right_rand = RomuDuoJrRand::with_seed(0x5eed);
        let left = (0..32)
            .map(|_| ascending.select_snapshot(&mut left_rand).unwrap())
            .collect::<Vec<_>>();
        let right = (0..32)
            .map(|_| shuffled.select_snapshot(&mut right_rand).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(left, right);
    }

    #[test]
    fn weighted_selection_handles_energy_larger_than_usize_without_overflow() {
        let mut corpus = SnapshotCorpus::new();
        insert_snapshot(&mut corpus, 0, 0, 0, 0);
        insert_snapshot(&mut corpus, 1, 0, 1, 1);
        corpus.metadata.get_mut(&1).unwrap().coverage_score = usize::MAX;
        corpus.metadata.get_mut(&1).unwrap().score = SnapshotScore {
            new_coverage: u64::MAX,
            branch_distance: u64::MAX,
            comparison_distance: u64::MAX,
            oracle_proximity: u64::MAX,
            asset_delta_proximity: u64::MAX,
            storage_slot_sensitivity: u64::MAX,
            call_depth_novelty: u64::MAX,
            selector_novelty: u64::MAX,
            revert_reason_novelty: u64::MAX,
            event_novelty: u64::MAX,
            state_transition_rarity: u64::MAX,
        };
        let weights = SnapshotScoreWeights {
            new_coverage: u64::MAX,
            branch_distance: u64::MAX,
            comparison_distance: u64::MAX,
            oracle_proximity: u64::MAX,
            asset_delta_proximity: u64::MAX,
            storage_slot_sensitivity: u64::MAX,
            call_depth_novelty: u64::MAX,
            selector_novelty: u64::MAX,
            revert_reason_novelty: u64::MAX,
            event_novelty: u64::MAX,
            state_transition_rarity: u64::MAX,
        };

        let energy = corpus.snapshot_energy_with_weights(1, &weights).unwrap();
        assert!(energy > usize::MAX as u128);
        assert_eq!(
            corpus.select_snapshot_with_weights(&mut ScriptedRand::new([]), &weights),
            Some(1)
        );
    }

    #[test]
    fn stage_2c_snapshot_manifest_schema_version_survives_round_trip() {
        // Versioned persistence contract (global invariant #7).
        let legacy_json = r#"{
            "id": 4,
            "state_hash": "0xabc",
            "coverage_hash": 7,
            "coverage_edges": 3,
            "producing_input_id": null,
            "depth": 2,
            "gas_used": 42
        }"#;
        let manifest: SnapshotManifest = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(manifest.schema_version, 1);

        let fresh = SnapshotManifest {
            schema_version: 1,
            id: 4,
            state_hash: "0xabc".to_string(),
            coverage_hash: 7,
            coverage_edges: 3,
            producing_input_id: None,
            depth: 2,
            gas_used: 42,
        };
        let encoded = serde_json::to_string(&fresh).unwrap();
        assert!(encoded.contains("\"schema_version\":1"));
        let decoded: SnapshotManifest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, fresh);
    }

    #[test]
    fn snapshot_pruning_retains_promising_state() {
        let target = Address::repeat_byte(0x53);
        let mut corpus = SnapshotCorpus::new();
        corpus
            .add_snapshot(
                0,
                0,
                Snapshot {
                    id: 0,
                    state: Arc::new(RwLock::new(ChainState::Evm(CacheDB::new(ForkDb::empty())))),
                    coverage: bitvec::bitvec![u8, Lsb0; 0; 8],
                    producing_input: None,
                    waypoints: Vec::new(),
                    depth: 0,
                    gas_used: 0,
                },
            )
            .expect("insert root snapshot");
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xaa, 0xbb, 0xcc, 0xdd],
                caller: Address::repeat_byte(0x13),
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
        };
        let low = scored_execution(
            target,
            [0x10, 0x00, 0x00, 0x00],
            None,
            false,
            0,
            B256::from(U256::from(1).to_be_bytes::<32>()),
            U256::from(1),
        );
        let high = scored_execution(
            target,
            [0x20, 0x00, 0x00, 0x00],
            Some(U256::from(1)),
            true,
            5,
            B256::from(U256::from(2).to_be_bytes::<32>()),
            U256::from(10u128.pow(18)),
        );
        let coverage = vec![1u8; 8];
        let low_id = corpus
            .maybe_add_post_execution_snapshot(
                0,
                &input,
                ChainState::Evm(CacheDB::new(ForkDb::empty())),
                &coverage,
                &low,
                8,
            )
            .expect("low snapshot");
        let high_id = corpus
            .maybe_add_post_execution_snapshot(
                0,
                &input,
                ChainState::Evm(CacheDB::new(ForkDb::empty())),
                &coverage,
                &high,
                2,
            )
            .expect("high snapshot");

        assert!(corpus.snapshots.contains_key(&high_id));
        assert!(!corpus.snapshots.contains_key(&low_id));
        assert_eq!(corpus.snapshots.len(), 2);
    }

    #[test]
    fn artifact_equivalence_deduplicates_same_sequence_coverage_finding_and_slots() {
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x13),
                to: Address::repeat_byte(0xaa),
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
        };
        let execution = SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 0,
                output: Vec::new(),
                coverage_hash: 7,
                coverage_edges: 1,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: Vec::new(),
                call_trace: Vec::new(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 0,
            final_coverage_hash: 7,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: vec![StorageDiff {
                tx_index: 0,
                address: Address::repeat_byte(0xaa),
                slot: B256::from([0x11; 32]),
                old_value: U256::ZERO,
                new_value: U256::from(1),
                pc: 0,
            }],
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };

        let left = artifact_equivalence_components(
            &input,
            &execution,
            &[],
            Some(Address::repeat_byte(0xaa)),
            "state-novelty",
        )
        .expect("components");
        let right = artifact_equivalence_components(
            &input,
            &execution,
            &[],
            Some(Address::repeat_byte(0xaa)),
            "state-novelty",
        )
        .expect("components");

        assert_eq!(
            serde_json::to_vec(&left).unwrap(),
            serde_json::to_vec(&right).unwrap()
        );
    }

    #[test]
    fn persist_campaign_artifact_deduplicates_same_input_id() {
        let root = temp_corpus_root("artifact-input-dedupe");
        let corpus = PersistentCorpus::new(&root).expect("corpus");
        let target = Address::repeat_byte(0xaa);
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x13),
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
        };
        let execution = SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Revert,
                gas_used: 21_000,
                output: Vec::new(),
                coverage_hash: 7,
                coverage_edges: 1,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: Vec::new(),
                call_trace: Vec::new(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 21_000,
            final_coverage_hash: 7,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };
        let score = CampaignScore {
            total: 100,
            economic_pressure: 0,
            invariant_pressure: 0,
            counterexample_pressure: 0,
            oracle_pressure: 0,
            state_pressure: 0,
            exploration_pressure: 0,
            explanation: vec!["test".to_string()],
        };
        let base = EvmCacheDb::new(ForkDb::empty());
        let coverage = vec![1u8; 8];

        // Inject a persistence failure after lock acquisition. Retrying after
        // repairing the filesystem must not be blocked by our abandoned lock.
        let fork_cache = root.join("fork_cache");
        fs::remove_dir(&fork_cache).unwrap();
        fs::write(&fork_cache, b"blocked").unwrap();
        assert!(corpus
            .persist_campaign_artifact(CampaignArtifactRequest {
                input: &input,
                execution: &execution,
                coverage: &coverage,
                state_novelty_score: 1,
                base_fork_state: &base,
                score: &score,
                findings: &[],
                exploit_candidate: None,
                block_number: 1,
                target: Some(target),
                reason: "high-score-non-success-status",
            })
            .is_err());
        assert!(fs::read_dir(root.join("campaign_artifacts/index"))
            .unwrap()
            .all(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_none_or(|ext| ext != "lock")));
        fs::remove_file(&fork_cache).unwrap();
        fs::create_dir(&fork_cache).unwrap();

        let first = corpus
            .persist_campaign_artifact(CampaignArtifactRequest {
                input: &input,
                execution: &execution,
                coverage: &coverage,
                state_novelty_score: 1,
                base_fork_state: &base,
                score: &score,
                findings: &[],
                exploit_candidate: None,
                block_number: 1,
                target: Some(target),
                reason: "high-score-non-success-status",
            })
            .expect("first artifact");
        let second = corpus
            .persist_campaign_artifact(CampaignArtifactRequest {
                input: &input,
                execution: &execution,
                coverage: &coverage,
                state_novelty_score: 1,
                base_fork_state: &base,
                score: &score,
                findings: &[],
                exploit_candidate: None,
                block_number: 1,
                target: Some(target),
                reason: "economic-or-invariant-pressure",
            })
            .expect("second artifact");

        assert!(first.created_new);
        assert!(!second.created_new);
        assert_eq!(first.record.input_id, second.record.input_id);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn truncated_published_artifact_fails_next_corpus_start() {
        let root = temp_corpus_root("artifact-recovery");
        let corpus = PersistentCorpus::new(&root).expect("corpus");
        let target = Address::repeat_byte(0xaa);
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xde, 0xad],
                caller: Address::repeat_byte(0x13),
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
        };
        let execution = SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 1,
                output: Vec::new(),
                coverage_hash: 1,
                coverage_edges: 1,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: Vec::new(),
                call_trace: Vec::new(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 1,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };
        let score = CampaignScore {
            total: 1,
            economic_pressure: 0,
            invariant_pressure: 0,
            counterexample_pressure: 0,
            oracle_pressure: 0,
            state_pressure: 0,
            exploration_pressure: 0,
            explanation: vec!["recovery".to_string()],
        };
        let base = EvmCacheDb::new(ForkDb::empty());
        let record = corpus
            .persist_campaign_artifact(CampaignArtifactRequest {
                input: &input,
                execution: &execution,
                coverage: &[1],
                state_novelty_score: 1,
                base_fork_state: &base,
                score: &score,
                findings: &[],
                exploit_candidate: None,
                block_number: 1,
                target: Some(target),
                reason: "recovery-test",
            })
            .expect("artifact");
        fs::write(
            root.join("fork_cache")
                .join(format!("{}.json", record.record.fork_cache_id)),
            b"{\"truncated\":",
        )
        .unwrap();

        let error = match PersistentCorpus::new(&root) {
            Ok(_) => panic!("corruption was silently accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("fork cache"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stage_2b_legacy_input_json_preserves_feedback_and_keeps_semantic_identity() {
        let root = temp_corpus_root("stage2b-legacy-load");
        let corpus = PersistentCorpus::new(&root).expect("corpus");
        let target = Address::repeat_byte(0xab);
        let clean = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x13),
                to: target,
                value: U256::from(1_000u64),
                is_victim: false,
            }],
            base_snapshot_id: 42,
        };

        // Write a pre-Stage-2B style input file with embedded feedback.
        let mut legacy_json = serde_json::to_value(&clean).unwrap();
        legacy_json["waypoints"] = serde_json::json!([[]]);
        legacy_json["mutation_provenance"] = serde_json::json!([{
            "strategy": "goal_max_attacker_profit",
            "tx_index": null,
            "selector": null,
            "detail": "bounded search"
        }]);
        let id = corpus_root_input_id(&clean);
        let path = root.join("inputs").join(format!("{id}.json"));
        std::fs::write(path, serde_json::to_vec_pretty(&legacy_json).unwrap()).unwrap();

        let (input, metadata) = corpus.load_input_with_metadata(&id).expect("legacy load");
        assert_eq!(input, clean);
        assert_eq!(metadata.waypoints.len(), 1);
        assert_eq!(metadata.mutation_provenance.len(), 1);
        assert_eq!(
            metadata.mutation_provenance[0].strategy,
            "goal_max_attacker_profit"
        );

        // The semantic identity of the legacy record matches a clean rewrite:
        // provenance differences cannot split one executable testcase into two.
        assert_eq!(
            input.semantic_input_hash(),
            EvmInput::split_legacy_json(serde_json::to_vec_pretty(&input).unwrap().as_slice())
                .unwrap()
                .0
                .semantic_input_hash()
        );
        assert_eq!(input.semantic_input_id(), clean.semantic_input_id());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stage_2b_semantic_dedupe_ignores_feedback_variants() {
        let target = Address::repeat_byte(0xcd);
        let txs = vec![SingletonTx {
            input: vec![0xde, 0xad, 0xbe, 0xef],
            caller: Address::repeat_byte(0x13),
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }];

        let plain = EvmInput::new(txs.clone(), 3);
        let feedback_variant_json = serde_json::json!({
            "txs": serde_json::to_value(&txs).unwrap(),
            "base_snapshot_id": 3,
            "waypoints": [[], [], []],
            "mutation_provenance": [
                {"strategy": "caller", "tx_index": 0, "selector": null, "detail": "changed caller role"},
                {"strategy": "value_boundary", "tx_index": 0, "selector": null, "detail": "changed tx value"}
            ]
        });
        let (feedback_variant, metadata) =
            EvmInput::split_legacy_json(feedback_variant_json.to_string().as_bytes()).unwrap();

        assert_ne!(metadata.waypoints, EvmTestcaseMetadata::default().waypoints);
        // Identical execution-defining content, different feedback: same identity.
        assert_eq!(
            plain.semantic_input_id(),
            feedback_variant.semantic_input_id()
        );

        // Different execution-defining content must not deduplicate.
        let mut different_value = plain.clone();
        different_value.txs[0].value = U256::from(7u64);
        assert_ne!(
            plain.semantic_input_id(),
            different_value.semantic_input_id()
        );
    }

    #[test]
    fn stage_2b1_prefix_collision_preserves_both_entries() {
        let root = temp_corpus_root("stage2b1-prefix-collision");
        let corpus = PersistentCorpus::new(&root).expect("corpus");
        let target = Address::repeat_byte(0xef);
        let victim_input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x13),
                to: target,
                value: U256::from(5_000u64),
                is_victim: true,
            }],
            base_snapshot_id: 7,
        };
        let attacker_input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef],
                caller: Address::repeat_byte(0x13),
                to: target,
                value: U256::from(5_000u64),
                is_victim: false,
            }],
            base_snapshot_id: 7,
        };
        // The two inputs differ only in the analysis-only role marker, so they
        // share one semantic InputId. To exercise the prefix-collision path we
        // plant a foreign legacy entry under the same truncated prefix whose
        // recorded full hash points elsewhere.
        let metadata = corpus
            .persist_input(&victim_input, &[1, 2, 3], 21_000)
            .expect("persist first");
        let full_hash = metadata.input_hash.trim_start_matches("0x").to_string();
        assert_eq!(metadata.id, full_hash[..16]);

        // Inject a foreign record occupying the same 16-hex prefix with a
        // different full semantic hash.
        let foreign = CorpusEntryMetadata {
            id: metadata.id.clone(),
            input_hash: format!("0x{}{}", "9".repeat(16), "a".repeat(48)),
            ..serde_json::from_str::<CorpusEntryMetadata>(
                &std::fs::read_to_string(
                    root.join("inputs")
                        .join(format!("{}.meta.json", metadata.id)),
                )
                .unwrap_or_else(|_| serde_json::to_string(&metadata).unwrap()),
            )
            .unwrap_or(metadata.clone())
        };
        std::fs::write(
            root.join("inputs")
                .join(format!("{}.meta.json", metadata.id)),
            serde_json::to_vec_pretty(&foreign).unwrap(),
        )
        .unwrap();

        let second = corpus
            .persist_execution_input(
                &attacker_input,
                &scored_minimal_execution(target),
                &[4, 5, 6],
                3,
            )
            .expect("persist colliding");
        assert_ne!(second.id, metadata.id);
        assert!(second.id.starts_with(&format!("{}-", &full_hash[..16])));
        assert_eq!(second.input_hash, attacker_input.semantic_input_hash());
        // Both entries remain loadable and distinct.
        let loaded_first = corpus
            .load_input_with_metadata(&metadata.id)
            .expect("first");
        let loaded_second = corpus.load_input_with_metadata(&second.id).expect("second");
        assert_eq!(loaded_first.0.semantic_input_hash(), metadata.input_hash);
        assert_eq!(
            loaded_second.0.semantic_input_hash(),
            attacker_input.semantic_input_hash()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn scored_minimal_execution(_target: Address) -> SequenceExecutionResult {
        SequenceExecutionResult {
            tx_results: Vec::new(),
            total_gas_used: 21_000,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        }
    }
    fn corpus_root_input_id(input: &EvmInput) -> String {
        input.semantic_input_hash().trim_start_matches("0x")[..16].to_string()
    }

    #[test]
    fn online_fork_loader_requires_provenance_and_expected_block() {
        let root = temp_corpus_root("online-fork-loader");
        let corpus = PersistentCorpus::new(&root).expect("create corpus");

        let offline = ForkDb::new_offline("0x10");
        corpus
            .persist_fork_cache("offline", &offline)
            .expect("persist offline cache");
        let provider = "https://rpc.example";
        let chain_id = 1;
        let block_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(corpus
            .load_online_fork_db("offline", 16, provider, chain_id, block_hash)
            .is_err());

        let online = ForkDb::new(provider, 17);
        online.set_provenance_chain(chain_id, Some(block_hash.to_string()), 1);
        corpus
            .persist_fork_cache("wrong-block", &online)
            .expect("persist online cache");
        assert!(corpus
            .load_online_fork_db(
                "wrong-block",
                16,
                &online.provenance().provider_sanitized,
                chain_id,
                block_hash,
            )
            .is_err());

        fs::remove_dir_all(root).expect("remove corpus");
    }

    #[test]
    fn online_fork_loader_rejects_each_partial_provenance_field() {
        use rustyfuzz_evm::fork_db::{ForkCacheProvenance, ForkDbCacheSnapshot};

        let root = temp_corpus_root("online-fork-partial-provenance");
        let corpus = PersistentCorpus::new(&root).expect("create corpus");
        let provider = "https://rpc.example";
        let chain_id = 1;
        let block_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let complete = ForkCacheProvenance {
            provider_sanitized: provider.to_string(),
            chain_id: Some(chain_id),
            block_number: Some(16),
            block_hash: Some(block_hash.to_string()),
            fetched_at_unix: Some(1),
            cache_id: Some("fc_test".to_string()),
        };
        let mut snapshot = ForkDbCacheSnapshot {
            block_tag: "0x10".to_string(),
            accounts: vec![],
            code_by_hash: vec![],
            storage: vec![],
            block_hashes: vec![],
            provenance: complete.clone(),
            content_digest: String::new(),
        };
        snapshot.content_digest = snapshot.calculate_content_digest().expect("digest");
        let persist = |id: &str, provenance: ForkCacheProvenance| {
            let mut snapshot = snapshot.clone();
            snapshot.provenance = provenance;
            snapshot.content_digest = snapshot.calculate_content_digest().expect("digest");
            write_atomic(
                root.join("fork_cache").join(format!("{id}.json")),
                serde_json::to_vec(&snapshot).expect("encode snapshot"),
            )
            .expect("persist snapshot");
        };
        persist("complete", complete.clone());
        assert!(corpus
            .load_online_fork_db("complete", 16, provider, chain_id, block_hash)
            .is_ok());

        let partial = [
            (
                "no-provider",
                ForkCacheProvenance {
                    provider_sanitized: String::new(),
                    ..complete.clone()
                },
            ),
            (
                "no-chain",
                ForkCacheProvenance {
                    chain_id: None,
                    ..complete.clone()
                },
            ),
            (
                "no-block",
                ForkCacheProvenance {
                    block_number: None,
                    ..complete.clone()
                },
            ),
            (
                "no-hash",
                ForkCacheProvenance {
                    block_hash: None,
                    ..complete.clone()
                },
            ),
            (
                "no-timestamp",
                ForkCacheProvenance {
                    fetched_at_unix: None,
                    ..complete.clone()
                },
            ),
            (
                "no-cache-id",
                ForkCacheProvenance {
                    cache_id: None,
                    ..complete.clone()
                },
            ),
        ];
        for (id, provenance) in partial {
            persist(id, provenance);
            assert!(
                corpus
                    .load_online_fork_db(id, 16, provider, chain_id, block_hash)
                    .is_err(),
                "{id}"
            );
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fork_cache_loader_rejects_tampered_complete_snapshot() {
        let root = temp_corpus_root("fork-cache-digest");
        let corpus = PersistentCorpus::new(&root).expect("create corpus");
        corpus
            .persist_fork_cache("cache", &ForkDb::new_offline("0x10"))
            .expect("persist cache");
        let path = root.join("fork_cache").join("cache.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read cache")).expect("decode cache");
        value["block_tag"] = serde_json::Value::String("0x11".to_string());
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode tampered cache"),
        )
        .expect("tamper cache");
        assert!(corpus.load_fork_cache("cache").is_err());
        fs::remove_dir_all(root).expect("remove corpus");
    }

    #[test]
    fn seed_bundle_rejects_path_traversal_ids() {
        let root = temp_corpus_root("seed-bundle-path-validation");
        let corpus = PersistentCorpus::new(&root).expect("corpus");
        assert!(corpus
            .persist_mainnet_seed_bundle(
                "../escape",
                &seed_bundle(Address::repeat_byte(0xaa), vec![])
            )
            .is_err());
        assert!(matches!(
            corpus.inspect_mainnet_seed_bundle(Some("../escape"), Address::repeat_byte(0xaa)),
            SeedBundleStatus::Invalid { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corpus_rejects_input_fork_and_artifact_path_ids() {
        let root = temp_corpus_root("corpus-path-validation");
        let corpus = PersistentCorpus::new(&root).expect("corpus");
        assert!(corpus.load_input_with_metadata("../escape").is_err());
        assert!(corpus.load_fork_cache("../escape").is_err());
        let snapshot = ForkDb::new_offline("0x1");
        assert!(corpus.persist_fork_cache("../escape", &snapshot).is_err());
        let mut metadata = CorpusEntryMetadata {
            id: "../escape".to_string(),
            input_hash: "0x01".to_string(),
            path_hash: 1,
            state_hash: 0,
            state_novelty_score: 0,
            coverage_edges: 0,
            gas_used: 0,
            crash_fingerprint: None,
            frontier: CorpusFrontierMetadata::default(),
        };
        assert!(corpus.persist_crash(&metadata, "test").is_err());
        metadata.id = "input-1".to_string();
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn corpus_rejects_preexisting_symlinked_storage_directory() {
        use std::os::unix::fs::symlink;

        let root = temp_corpus_root("preexisting-symlink");
        let outside = root.with_extension("outside");
        fs::create_dir_all(&root).expect("root directory");
        fs::create_dir_all(&outside).expect("outside directory");
        symlink(&outside, root.join("inputs")).expect("inputs symlink");
        assert!(PersistentCorpus::new(&root).is_err());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[cfg(unix)]
    #[test]
    fn corpus_rejects_preexisting_symlinked_index_directory() {
        use std::os::unix::fs::symlink;

        let root = temp_corpus_root("preexisting-index-symlink");
        let outside = root.with_extension("outside");
        fs::create_dir_all(&root).expect("root directory");
        fs::create_dir_all(&outside).expect("outside directory");
        let index = root.join("campaign_artifacts").join("index");
        fs::create_dir_all(&index).expect("index directory");
        fs::remove_dir(&index).expect("remove index directory");
        symlink(&outside, &index).expect("index symlink");
        assert!(PersistentCorpus::new(&root).is_err());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn nested_campaign_corpus_loads_global_seed_bundle() {
        let root = temp_corpus_root("seed-bundle-global-lookup");
        let target = Address::repeat_byte(0xaa);
        let global = PersistentCorpus::new(&root).expect("global corpus");
        global
            .persist_mainnet_seed_bundle("shared", &seed_bundle(target, vec![seed(target)]))
            .expect("persist bundle");
        let nested = PersistentCorpus::new_with_global_root(root.join("campaign-a"), Some(&root))
            .expect("nested corpus");
        assert_eq!(
            nested
                .load_mainnet_seed_bundle("shared")
                .expect("load bundle")
                .target,
            target
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn seed_bundle_status_distinguishes_missing_empty_loaded_and_mismatch() {
        let root = temp_corpus_root("seed-bundle-status");
        let corpus = PersistentCorpus::new(&root).expect("corpus");
        let target = Address::repeat_byte(0xaa);

        assert!(matches!(
            corpus.inspect_mainnet_seed_bundle(Some("missing"), target),
            SeedBundleStatus::Missing { .. }
        ));

        corpus
            .persist_mainnet_seed_bundle("empty", &seed_bundle(target, Vec::new()))
            .expect("persist empty");
        assert!(matches!(
            corpus.inspect_mainnet_seed_bundle(Some("empty"), target),
            SeedBundleStatus::Empty { .. }
        ));

        corpus
            .persist_mainnet_seed_bundle("loaded", &seed_bundle(target, vec![seed(target)]))
            .expect("persist loaded");
        assert!(matches!(
            corpus.inspect_mainnet_seed_bundle(Some("loaded"), target),
            SeedBundleStatus::Loaded { seed_count: 1, .. }
        ));

        let other = Address::repeat_byte(0xbb);
        corpus
            .persist_mainnet_seed_bundle("mismatch", &seed_bundle(other, vec![seed(other)]))
            .expect("persist mismatch");
        assert!(matches!(
            corpus.inspect_mainnet_seed_bundle(Some("mismatch"), target),
            SeedBundleStatus::TargetMismatch { .. }
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn seed_bundle_does_not_infer_a_global_root_from_the_local_parent() {
        let root = temp_corpus_root("seed-bundle-no-implicit-global");
        let target = Address::repeat_byte(0xaa);
        let global = PersistentCorpus::new(&root).expect("global corpus");
        global
            .persist_mainnet_seed_bundle("bundle", &seed_bundle(target, vec![seed(target)]))
            .expect("persist global bundle");
        let nested = PersistentCorpus::new(root.join("campaign-a")).expect("nested corpus");
        assert!(nested.load_mainnet_seed_bundle("bundle").is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn explicit_global_root_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = temp_corpus_root("seed-bundle-global-symlink");
        let outside = root.with_extension("outside");
        fs::create_dir_all(&outside).expect("outside directory");
        let linked = root.with_extension("linked");
        symlink(&outside, &linked).expect("global symlink");
        assert!(
            PersistentCorpus::new_with_global_root(root.join("campaign-a"), Some(&linked),)
                .is_err()
        );
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(linked);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn campaign_corpus_falls_back_to_global_seed_bundle() {
        let root = temp_corpus_root("seed-bundle-global-fallback");
        let global = PersistentCorpus::new(&root).expect("global corpus");
        let target = Address::repeat_byte(0xaa);
        global
            .persist_mainnet_seed_bundle("bundle", &seed_bundle(target, vec![seed(target)]))
            .expect("persist global bundle");

        let campaign = PersistentCorpus::new_with_global_root(root.join("campaign-a"), Some(&root))
            .expect("campaign corpus");
        let status = campaign.inspect_mainnet_seed_bundle(Some("bundle"), target);
        assert!(matches!(
            status,
            SeedBundleStatus::Loaded { seed_count: 1, .. }
        ));
        let bundle = campaign
            .load_mainnet_seed_bundle("bundle")
            .expect("load global bundle through campaign corpus");
        assert_eq!(bundle.seeds.len(), 1);

        let _ = std::fs::remove_dir_all(root);
    }
}

/// A specialized corpus for managing EVM state snapshots.
/// Industry-grade fuzzers like ItyFuzz use a tree-based approach to explore deep states.
pub struct SnapshotCorpus {
    pub snapshots: HashMap<u64, Arc<RwLock<Snapshot>>>,
    pub parent_map: HashMap<u64, u64>,
    pub children_map: HashMap<u64, Vec<u64>>,
    pub metadata: HashMap<u64, SnapshotMetadata>,
    pub global_read_hotspots: HashMap<(Address, B256), usize>,
    pub priority_gap_map: BitVec<u8, Lsb0>, // Edges identified as "uncovered" by Forge
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub visits: usize,
    /// Number of consecutive executions from this snapshot that did not
    /// improve the snapshot's coverage score.
    pub executions_since_novelty: usize,
    pub depth: u32,
    pub coverage_score: usize,
    /// Deterministic digest of this snapshot's cached EVM state content.
    ///
    /// Stage 2C: distinct from the assigned snapshot id. Equal fingerprints
    /// mean equivalent cached-state material; ids only order corpus entries.
    pub state_fingerprint: String,
    pub read_set: HashSet<(Address, B256)>,
    pub write_set: HashSet<(Address, B256)>,
    pub score: SnapshotScore,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SnapshotScore {
    pub new_coverage: u64,
    pub branch_distance: u64,
    pub comparison_distance: u64,
    pub oracle_proximity: u64,
    pub asset_delta_proximity: u64,
    pub storage_slot_sensitivity: u64,
    pub call_depth_novelty: u64,
    pub selector_novelty: u64,
    pub revert_reason_novelty: u64,
    pub event_novelty: u64,
    pub state_transition_rarity: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotScoreWeights {
    pub new_coverage: u64,
    pub branch_distance: u64,
    pub comparison_distance: u64,
    pub oracle_proximity: u64,
    pub asset_delta_proximity: u64,
    pub storage_slot_sensitivity: u64,
    pub call_depth_novelty: u64,
    pub selector_novelty: u64,
    pub revert_reason_novelty: u64,
    pub event_novelty: u64,
    pub state_transition_rarity: u64,
}

impl Default for SnapshotScoreWeights {
    fn default() -> Self {
        Self {
            new_coverage: 10,
            branch_distance: 8,
            comparison_distance: 6,
            oracle_proximity: 14,
            asset_delta_proximity: 10,
            storage_slot_sensitivity: 8,
            call_depth_novelty: 5,
            selector_novelty: 5,
            revert_reason_novelty: 4,
            event_novelty: 3,
            state_transition_rarity: 9,
        }
    }
}

impl SnapshotScoreWeights {
    pub fn for_known_bug_class(class_hint: &str) -> Self {
        let mut weights = Self::default();
        let normalized = class_hint.to_ascii_lowercase();

        if normalized.contains("access")
            || normalized.contains("privilege")
            || normalized.contains("proxy")
            || normalized.contains("upgrade")
        {
            weights.branch_distance = 14;
            weights.comparison_distance = 10;
            weights.selector_novelty = 12;
            weights.storage_slot_sensitivity = 12;
            weights.call_depth_novelty = 8;
        }

        if normalized.contains("erc4626")
            || normalized.contains("share")
            || normalized.contains("donation")
            || normalized.contains("inflation")
            || normalized.contains("accounting")
        {
            weights.asset_delta_proximity = 18;
            weights.oracle_proximity = 16;
            weights.storage_slot_sensitivity = 14;
            weights.state_transition_rarity = 14;
        }

        if normalized.contains("oracle") || normalized.contains("price") {
            weights.oracle_proximity = 24;
            weights.event_novelty = 8;
            weights.call_depth_novelty = 10;
            weights.comparison_distance = 10;
        }

        if normalized.contains("bridge")
            || normalized.contains("replay")
            || normalized.contains("cross-chain")
            || normalized.contains("finalization")
        {
            weights.selector_novelty = 14;
            weights.call_depth_novelty = 12;
            weights.state_transition_rarity = 16;
            weights.event_novelty = 8;
        }

        if normalized.contains("reentrancy") {
            weights.call_depth_novelty = 18;
            weights.storage_slot_sensitivity = 14;
            weights.state_transition_rarity = 14;
        }

        if normalized.contains("rounding") || normalized.contains("precision") {
            weights.branch_distance = 12;
            weights.comparison_distance = 14;
            weights.asset_delta_proximity = 12;
        }

        if normalized.contains("allowance")
            || normalized.contains("approval")
            || normalized.contains("permission")
        {
            weights.selector_novelty = 12;
            weights.storage_slot_sensitivity = 16;
            weights.branch_distance = 12;
            weights.oracle_proximity = 12;
        }

        weights
    }
}

impl SnapshotScore {
    pub fn total(&self, weights: &SnapshotScoreWeights) -> u64 {
        self.new_coverage
            .saturating_mul(weights.new_coverage)
            .saturating_add(self.branch_distance.saturating_mul(weights.branch_distance))
            .saturating_add(
                self.comparison_distance
                    .saturating_mul(weights.comparison_distance),
            )
            .saturating_add(
                self.oracle_proximity
                    .saturating_mul(weights.oracle_proximity),
            )
            .saturating_add(
                self.asset_delta_proximity
                    .saturating_mul(weights.asset_delta_proximity),
            )
            .saturating_add(
                self.storage_slot_sensitivity
                    .saturating_mul(weights.storage_slot_sensitivity),
            )
            .saturating_add(
                self.call_depth_novelty
                    .saturating_mul(weights.call_depth_novelty),
            )
            .saturating_add(
                self.selector_novelty
                    .saturating_mul(weights.selector_novelty),
            )
            .saturating_add(
                self.revert_reason_novelty
                    .saturating_mul(weights.revert_reason_novelty),
            )
            .saturating_add(self.event_novelty.saturating_mul(weights.event_novelty))
            .saturating_add(
                self.state_transition_rarity
                    .saturating_mul(weights.state_transition_rarity),
            )
    }

    pub fn from_execution(
        execution: &SequenceExecutionResult,
        known_storage_slots: &HashSet<(Address, B256)>,
        known_selectors: &HashSet<[u8; 4]>,
    ) -> Self {
        let waypoints = execution
            .tx_results
            .iter()
            .flat_map(|result| result.waypoints.iter());
        let mut near_branch = 0u64;
        let mut near_comparison = 0u64;
        for waypoint in waypoints {
            if let Waypoint::Comparison {
                branch_distance: Some(distance),
                ..
            } = waypoint
            {
                if *distance <= U256::from(256) {
                    near_branch += 1;
                }
                if *distance <= U256::from(4096) {
                    near_comparison += 1;
                }
            }
        }
        let selectors: HashSet<[u8; 4]> = execution
            .call_trace
            .iter()
            .filter_map(|call| call.input.get(0..4)?.try_into().ok())
            .collect();
        let touched_slots: HashSet<(Address, B256)> = execution
            .storage_diffs
            .iter()
            .map(|diff| (diff.address, diff.slot))
            .collect();
        let asset_delta_proximity = execution
            .storage_diffs
            .iter()
            .filter(|diff| {
                let delta = if diff.new_value > diff.old_value {
                    diff.new_value - diff.old_value
                } else {
                    diff.old_value - diff.new_value
                };
                delta >= U256::from(10u128.pow(12))
            })
            .count() as u64;
        let revert_reason_novelty = execution
            .tx_results
            .iter()
            .filter(|result| {
                matches!(
                    result.status,
                    ExecutionStatus::Revert | ExecutionStatus::Halt(_)
                )
            })
            .filter(|result| !result.output.is_empty())
            .count() as u64;
        Self {
            new_coverage: execution
                .tx_results
                .iter()
                .map(|result| result.coverage_edges as u64)
                .sum(),
            branch_distance: near_branch,
            comparison_distance: near_comparison,
            oracle_proximity: execution.oracle_observations.len() as u64,
            asset_delta_proximity,
            storage_slot_sensitivity: touched_slots.difference(known_storage_slots).count() as u64,
            call_depth_novelty: execution
                .call_trace
                .iter()
                .map(|call| call.depth as u64)
                .max()
                .unwrap_or_default(),
            selector_novelty: selectors.difference(known_selectors).count() as u64,
            revert_reason_novelty,
            event_novelty: execution
                .oracle_observations
                .iter()
                .filter(|observation| observation.oracle.to_ascii_lowercase().contains("event"))
                .count() as u64,
            state_transition_rarity: touched_slots
                .iter()
                .filter(|slot| !known_storage_slots.contains(slot))
                .count() as u64,
        }
    }
}

impl SnapshotCorpus {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            parent_map: HashMap::new(),
            children_map: HashMap::new(),
            metadata: HashMap::new(),
            global_read_hotspots: HashMap::new(),
            priority_gap_map: bitvec::bitvec![u8, Lsb0; 0; MAP_SIZE],
        }
    }

    pub fn add_snapshot(
        &mut self,
        id: u64,
        parent_id: u64,
        snapshot: Snapshot,
    ) -> Result<SnapshotId, SnapshotError> {
        // Stage 2C defensive lineage guard. Snapshot ids are assigned
        // monotonically (max + 1), so cycles are structurally impossible in a
        // fresh corpus, but restored/merged corpora must not be able to create
        // one silently. Walk the parent chain; refuse to link the snapshot if
        // doing so would close a cycle.
        if snapshot.id != id {
            return Err(SnapshotError::IdMismatch {
                expected: id,
                actual: snapshot.id,
            });
        }
        if self.snapshots.contains_key(&id) {
            return Err(SnapshotError::DuplicateSnapshot { id });
        }
        if id != parent_id && !self.snapshots.contains_key(&parent_id) {
            return Err(SnapshotError::MissingParent { id, parent_id });
        }
        if id != parent_id && self.would_create_cycle(id, parent_id) {
            return Err(SnapshotError::CyclicLineage { id, parent_id });
        }
        let depth = snapshot.depth;
        let coverage_score = snapshot.coverage.count_ones();
        let state_fingerprint = hash_snapshot_state(&snapshot);
        self.snapshots.insert(id, Arc::new(RwLock::new(snapshot)));
        self.parent_map.insert(id, parent_id);
        if id != parent_id {
            self.children_map.entry(parent_id).or_default().push(id);
        }
        self.metadata.insert(
            id,
            SnapshotMetadata {
                visits: 0,
                executions_since_novelty: 0,
                depth,
                coverage_score,
                state_fingerprint,
                read_set: HashSet::new(), // Populated after execution
                write_set: HashSet::new(),
                score: SnapshotScore {
                    new_coverage: coverage_score as u64,
                    ..SnapshotScore::default()
                },
            },
        );
        Ok(SnapshotId::new(id))
    }

    /// Returns true if inserting `id` with `parent_id` would create a cycle.
    fn would_create_cycle(&self, id: u64, mut ancestor: u64) -> bool {
        let mut hops = 0usize;
        while let Some(&next) = self.parent_map.get(&ancestor) {
            if next == id {
                return true;
            }
            if next == ancestor {
                break;
            }
            ancestor = next;
            hops += 1;
            if hops > self.snapshots.len() {
                return true;
            }
        }
        false
    }

    /// Reconstructs the deterministic input sequence that reaches `id` from
    /// its root: root-first producing inputs along the parent chain.
    ///
    /// Returns `None` when the lineage is missing or cyclic.
    pub fn lineage_inputs(&self, id: u64) -> Option<Vec<EvmInput>> {
        let mut chain = Vec::new();
        let mut current = id;
        loop {
            if chain.contains(&current) {
                return None;
            }
            chain.push(current);
            match self.parent_map.get(&current) {
                Some(parent) if *parent != current => current = *parent,
                _ => break,
            }
        }
        chain.reverse();
        Some(
            chain
                .iter()
                .filter_map(|snapshot_id| {
                    self.snapshots
                        .get(snapshot_id)?
                        .read()
                        .producing_input
                        .clone()
                })
                .collect(),
        )
    }

    pub fn maybe_add_post_execution_snapshot(
        &mut self,
        parent_id: u64,
        input: &EvmInput,
        state: ChainState,
        coverage: &[u8],
        execution: &SequenceExecutionResult,
        max_snapshots: usize,
    ) -> Option<u64> {
        if !meaningful_snapshot_execution(execution) {
            return None;
        }

        let id = self
            .snapshots
            .keys()
            .copied()
            .max()
            .unwrap_or_default()
            .saturating_add(1);
        let parent_depth = self
            .metadata
            .get(&parent_id)
            .map(|metadata| metadata.depth)
            .unwrap_or_default();
        let mut snapshot = Snapshot {
            id,
            state: Arc::new(RwLock::new(state)),
            coverage: coverage_bitvec(coverage),
            producing_input: Some(input.clone()),
            waypoints: execution
                .tx_results
                .iter()
                .flat_map(|result| result.waypoints.clone())
                .collect(),
            depth: parent_depth.saturating_add(1),
            gas_used: execution.total_gas_used,
        };
        snapshot.apply_waypoint_backpressure();
        let inserted_id = match self.add_snapshot(id, parent_id, snapshot) {
            Ok(inserted_id) => inserted_id,
            Err(err) => {
                log::error!("failed to insert post-execution snapshot: {err}");
                return None;
            }
        };
        self.update_snapshot_metadata_from_execution(id, execution);
        self.prune_to_limit(max_snapshots.max(1));
        Some(inserted_id.get())
    }

    fn update_snapshot_metadata_from_execution(
        &mut self,
        id: u64,
        execution: &SequenceExecutionResult,
    ) {
        let known_storage_slots = self
            .metadata
            .values()
            .flat_map(|metadata| metadata.write_set.iter().copied())
            .collect::<HashSet<_>>();
        let known_selectors = self
            .snapshots
            .values()
            .filter_map(|snapshot| snapshot.read().producing_input.clone())
            .flat_map(|input| input.txs.into_iter())
            .filter_map(|tx| tx.input.get(0..4)?.try_into().ok())
            .collect::<HashSet<_>>();
        let score =
            SnapshotScore::from_execution(execution, &known_storage_slots, &known_selectors);
        if let Some(metadata) = self.metadata.get_mut(&id) {
            metadata.read_set = execution
                .storage_reads
                .iter()
                .map(|read| (read.address, read.slot))
                .collect();
            metadata.write_set = execution
                .storage_writes
                .iter()
                .map(|write| (write.address, write.slot))
                .collect();
            metadata.coverage_score = metadata
                .coverage_score
                .saturating_add(execution.storage_diffs.len())
                .saturating_add(execution.call_trace.len())
                .saturating_add(execution.oracle_observations.len() * 10);
            metadata.score = score;
        }
        for read in &execution.storage_reads {
            *self
                .global_read_hotspots
                .entry((read.address, read.slot))
                .or_default() += 1;
        }
    }

    fn prune_to_limit(&mut self, max_snapshots: usize) {
        while self.snapshots.len() > max_snapshots {
            let Some((&id, _)) = self
                .metadata
                .iter()
                .filter(|(id, _)| !self.is_root(**id))
                .min_by_key(|(id, metadata)| {
                    (
                        metadata.score.total(&SnapshotScoreWeights::default()),
                        metadata.coverage_score,
                        metadata.write_set.len(),
                        std::cmp::Reverse(metadata.visits),
                        **id,
                    )
                })
            else {
                break;
            };
            self.prune_recursive(id);
        }
    }

    /// Directed Power Schedule: Prioritizes snapshots that are likely to fill
    /// gaps identified in existing Forge coverage runs.
    pub fn select_snapshot<R: Rand>(&mut self, rand: &mut R) -> Option<u64> {
        self.select_snapshot_with_weights(rand, &SnapshotScoreWeights::default())
    }

    pub fn select_snapshot_with_weights<R: Rand>(
        &mut self,
        rand: &mut R,
        weights: &SnapshotScoreWeights,
    ) -> Option<u64> {
        if self.snapshots.is_empty() {
            return None;
        }

        let mut weighted_ids = Vec::new();
        for id in self.metadata.keys() {
            if let Some(energy) = self.snapshot_energy_with_weights(*id, weights) {
                weighted_ids.push((*id, energy));
            }
        }
        weighted_ids.sort_unstable_by_key(|(id, _)| *id);

        let total_energy = weighted_ids
            .iter()
            .fold(0u128, |acc, (_, energy)| acc.saturating_add(*energy));
        if total_energy == 0 {
            // Fallback to random if no coverage yet
            let keys = self.sorted_snapshot_ids();
            return Some(keys[rand.below(NonZero::new(keys.len()).unwrap())]);
        }

        let mut p = random_weight(rand, total_energy);
        for (id, energy) in weighted_ids {
            if p < energy {
                return Some(id);
            }
            p = p.saturating_sub(energy);
        }

        self.sorted_snapshot_ids().into_iter().next()
    }

    pub fn snapshot_energy_with_weights(
        &self,
        id: u64,
        weights: &SnapshotScoreWeights,
    ) -> Option<u128> {
        let meta = self.metadata.get(&id)?;
        let snap = self.snapshots.get(&id)?.read();
        let gap_intersection = (snap.coverage.clone() & self.priority_gap_map.clone()).count_ones();
        Some(
            (meta.coverage_score as u128)
                .saturating_add((gap_intersection as u128).saturating_mul(10))
                .saturating_add(meta.score.total(weights) as u128),
        )
    }

    pub fn update_metadata(&mut self, id: u64, new_coverage: usize) {
        if let Some(meta) = self.metadata.get_mut(&id) {
            meta.visits = meta.visits.saturating_add(1);
            if new_coverage > meta.coverage_score {
                meta.executions_since_novelty = 0;
                meta.coverage_score = new_coverage;
            } else {
                meta.executions_since_novelty = meta.executions_since_novelty.saturating_add(1);
            }
        }
    }

    /// Pruning logic: If a state branch hasn't yielded new coverage in N visits,
    /// we prune it to keep the search space efficient.
    pub fn prune_dead_ends(&mut self, threshold: usize) {
        if threshold == 0 {
            return;
        }
        let to_remove: Vec<u64> = self
            .metadata
            .iter()
            .filter(|(id, meta)| !self.is_root(**id) && meta.executions_since_novelty >= threshold)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();

        let mut to_remove = to_remove;
        to_remove.sort_unstable();
        for id in to_remove {
            self.prune_recursive(id);
        }
    }

    pub fn retain(&mut self, ids: &HashSet<u64>) {
        let keep = self.ancestry_closure(ids);
        self.snapshots.retain(|id, _| keep.contains(id));
        self.parent_map
            .retain(|id, parent| keep.contains(id) && keep.contains(parent));
        self.metadata.retain(|id, _| keep.contains(id));
        self.rebuild_children_map();
    }

    /// Recursively removes a snapshot and all its descendants from the corpus.
    pub fn prune_recursive(&mut self, id: u64) {
        if self.is_root(id) {
            return;
        }
        if let Some(children) = self.children_map.remove(&id) {
            for child_id in children {
                self.prune_recursive(child_id);
            }
        }
        if let Some(parent_id) = self.parent_map.get(&id).copied() {
            if let Some(siblings) = self.children_map.get_mut(&parent_id) {
                siblings.retain(|child_id| *child_id != id);
            }
        }
        self.snapshots.remove(&id);
        self.parent_map.remove(&id);
        self.metadata.remove(&id);
    }

    fn sorted_snapshot_ids(&self) -> Vec<u64> {
        let mut keys: Vec<u64> = self.snapshots.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    fn is_root(&self, id: u64) -> bool {
        matches!(self.parent_map.get(&id), Some(parent_id) if *parent_id == id)
    }

    fn ancestry_closure(&self, ids: &HashSet<u64>) -> HashSet<u64> {
        let mut keep = HashSet::new();
        for &requested_id in ids {
            let mut current = requested_id;
            let mut seen = HashSet::new();
            loop {
                if !self.snapshots.contains_key(&current) || !seen.insert(current) {
                    break;
                }
                keep.insert(current);
                match self.parent_map.get(&current) {
                    Some(parent_id) if *parent_id != current => current = *parent_id,
                    _ => break,
                }
            }
        }
        for (&id, &parent_id) in &self.parent_map {
            if id == parent_id {
                keep.insert(id);
            }
        }
        keep
    }

    fn rebuild_children_map(&mut self) {
        let mut children_map: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut edges: Vec<(u64, u64)> = self
            .parent_map
            .iter()
            .map(|(id, parent_id)| (*id, *parent_id))
            .collect();
        edges.sort_unstable();
        for (id, parent_id) in edges {
            if id != parent_id {
                children_map.entry(parent_id).or_default().push(id);
            }
        }
        self.children_map = children_map;
    }

    pub fn get_snapshot(&self, id: u64) -> Option<Arc<RwLock<Snapshot>>> {
        self.snapshots.get(&id).cloned()
    }
}

fn random_weight<R: Rand>(rand: &mut R, total_energy: u128) -> u128 {
    debug_assert!(total_energy > 0);
    if let Ok(total_energy) = usize::try_from(total_energy) {
        if let Some(bound) = NonZero::new(total_energy) {
            return rand.below(bound) as u128;
        }
    }

    let bound = NonZeroU128::new(total_energy).expect("positive total energy");
    let sample = ((rand.next() as u128) << 64) | rand.next() as u128;
    sample % bound.get()
}

fn meaningful_snapshot_execution(execution: &SequenceExecutionResult) -> bool {
    execution
        .tx_results
        .iter()
        .any(|result| matches!(result.status, ExecutionStatus::Success))
        && (!execution.storage_diffs.is_empty()
            || !execution.storage_writes.is_empty()
            || !execution.oracle_observations.is_empty()
            || execution.call_trace.len() > execution.tx_results.len()
            || execution.tx_results.iter().any(|result| {
                result.coverage_edges > 0
                    || result
                        .waypoints
                        .iter()
                        .any(|waypoint| matches!(waypoint, Waypoint::Comparison { .. }))
            }))
}

fn coverage_bitvec(coverage: &[u8]) -> BitVec<u8, Lsb0> {
    let mut out = bitvec::bitvec![u8, Lsb0; 0; coverage.len()];
    for (idx, hit) in coverage.iter().enumerate() {
        if *hit != 0 {
            out.set(idx, true);
        }
    }
    out
}

impl Default for SnapshotCorpus {
    fn default() -> Self {
        Self::new()
    }
}
