use crate::common::oracle::{FindingStatus, ProtocolFinding, ProtocolSeverity};
use crate::common::types::{
    ChainState, ExecutionStatus, SequenceExecutionResult, Snapshot, Waypoint,
};
use crate::engine::confirmation::{FindingConfirmation, FindingConfirmationGate};
use crate::engine::exploit_path::ExploitPathCandidate;
use crate::engine::proof::{ProofCarryingFinding, ProofConfidenceTier};
use crate::engine::scoring::CampaignScore;
use crate::evm::feedback::EvmCoverageFeedback;
use crate::evm::fork_db::{EvmCacheDb, ForkDb, ForkDbCacheSnapshot};
use crate::evm::fuzz::EvmInput;
use crate::evm::inspector::MAP_SIZE;
use crate::evm::seed_ingester::MainnetSeedBundle;
use anyhow::Context;
use libafl_bolts::rands::Rand;
use parking_lot::RwLock;
use revm::primitives::{Address, B256, U256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
// use bitvec::bitvec; // Unused
use bitvec::prelude::{BitVec, Lsb0};
use serde::{Deserialize, Serialize};

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
    pub id: u64,
    pub state_hash: String,
    pub coverage_hash: u64,
    pub coverage_edges: usize,
    pub producing_input_id: Option<String>,
    pub depth: u32,
    pub gas_used: u64,
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
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("inputs"))?;
        fs::create_dir_all(root.join("crashes"))?;
        fs::create_dir_all(root.join("fork_cache"))?;
        fs::create_dir_all(root.join("mainnet_seeds"))?;
        fs::create_dir_all(root.join("campaign_artifacts"))?;
        fs::create_dir_all(root.join("campaign_artifacts").join("index"))?;
        fs::create_dir_all(root.join("campaign_artifacts").join("summaries"))?;
        Ok(Self { root })
    }

    pub fn persist_input(
        &self,
        input: &EvmInput,
        coverage: &[u8],
        gas_used: u64,
    ) -> anyhow::Result<CorpusEntryMetadata> {
        let encoded = serde_json::to_vec(input)?;
        let input_hash = format!("0x{}", hex::encode(revm::primitives::keccak256(&encoded)));
        let id = input_hash.trim_start_matches("0x")[..16].to_string();
        let metadata = CorpusEntryMetadata {
            id: id.clone(),
            input_hash,
            path_hash: EvmCoverageFeedback::stable_path_hash(coverage),
            state_hash: 0,
            state_novelty_score: 0,
            coverage_edges: coverage.iter().filter(|&&hit| hit != 0).count(),
            gas_used,
            crash_fingerprint: None,
            frontier: CorpusFrontierMetadata::default(),
        };

        let input_path = self.root.join("inputs").join(format!("{id}.json"));
        let meta_path = self.root.join("inputs").join(format!("{id}.meta.json"));
        fs::write(input_path, serde_json::to_vec_pretty(input)?)?;
        fs::write(meta_path, serde_json::to_vec_pretty(&metadata)?)?;
        Ok(metadata)
    }

    pub fn persist_execution_input(
        &self,
        input: &EvmInput,
        execution: &SequenceExecutionResult,
        coverage: &[u8],
        state_novelty_score: u64,
    ) -> anyhow::Result<CorpusEntryMetadata> {
        let encoded = serde_json::to_vec(input)?;
        let input_hash = format!("0x{}", hex::encode(revm::primitives::keccak256(&encoded)));
        let id = input_hash.trim_start_matches("0x")[..16].to_string();
        let metadata = CorpusEntryMetadata {
            id: id.clone(),
            input_hash,
            path_hash: EvmCoverageFeedback::stable_path_hash(coverage),
            state_hash: crate::evm::feedback::stable_execution_state_hash(execution),
            state_novelty_score,
            coverage_edges: coverage.iter().filter(|&&hit| hit != 0).count(),
            gas_used: execution.total_gas_used,
            crash_fingerprint: None,
            frontier: frontier_metadata(execution),
        };

        let input_path = self.root.join("inputs").join(format!("{id}.json"));
        let meta_path = self.root.join("inputs").join(format!("{id}.meta.json"));
        fs::write(input_path, serde_json::to_vec_pretty(input)?)?;
        fs::write(meta_path, serde_json::to_vec_pretty(&metadata)?)?;
        Ok(metadata)
    }

    pub fn load_input(&self, id: &str) -> anyhow::Result<EvmInput> {
        let bytes = fs::read(self.root.join("inputs").join(format!("{id}.json")))?;
        Ok(serde_json::from_slice(&bytes)?)
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
        let path = self.root.join("fork_cache").join(format!("{id}.json"));
        fs::write(path, serde_json::to_vec_pretty(&snapshot)?)?;
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
        let index_path = self
            .root
            .join("campaign_artifacts")
            .join("index")
            .join(format!("{artifact_key}.json"));
        let lock_path = index_path.with_extension("lock");
        if let Ok(bytes) = fs::read(&index_path) {
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
                    if let Ok(bytes) = fs::read(&index_path) {
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

                if let Ok(bytes) = fs::read(&index_path) {
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
        let _lock_file = lock_file;

        if let Ok(bytes) = fs::read(&index_path) {
            if let Ok(existing) = serde_json::from_slice::<CampaignArtifactRecord>(&bytes) {
                if existing.score.total >= request.score.total {
                    let _ = fs::remove_file(&lock_path);
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
        let record_path = self
            .root
            .join("campaign_artifacts")
            .join(format!("{}.json", metadata.id));
        if let Ok(bytes) = fs::read(&record_path) {
            if let Ok(existing) = serde_json::from_slice::<CampaignArtifactRecord>(&bytes) {
                if existing.score.total >= request.score.total {
                    let _ = fs::remove_file(&lock_path);
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
        let tmp_index_path = index_path.with_extension("json.tmp");
        fs::write(&record_path, &record_bytes)?;
        fs::write(&tmp_index_path, &record_bytes)?;
        fs::rename(&tmp_index_path, &index_path)?;
        fs::write(
            self.root
                .join("campaign_artifacts")
                .join("summaries")
                .join(format!("{}.md", record.input_id)),
            triage_markdown(&record),
        )?;
        let _ = fs::remove_file(&lock_path);
        Ok(CampaignArtifactOutcome {
            record,
            created_new: true,
        })
    }

    pub fn load_fork_cache(&self, id: &str) -> anyhow::Result<ForkDbCacheSnapshot> {
        let bytes = fs::read(self.root.join("fork_cache").join(format!("{id}.json")))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn load_offline_fork_db(&self, id: &str) -> anyhow::Result<ForkDb> {
        Ok(ForkDb::from_cache_snapshot(self.load_fork_cache(id)?))
    }

    pub fn persist_mainnet_seed_bundle(
        &self,
        id: &str,
        bundle: &MainnetSeedBundle,
    ) -> anyhow::Result<()> {
        let bundle_dir = self.root.join("mainnet_seeds").join(id);
        fs::create_dir_all(bundle_dir.join("inputs"))?;

        fs::write(
            bundle_dir.join("manifest.json"),
            serde_json::to_vec_pretty(bundle)?,
        )?;
        fs::write(
            bundle_dir.join("fork_cache.json"),
            serde_json::to_vec_pretty(&bundle.fork_cache)?,
        )?;

        for seed in &bundle.seeds {
            fs::write(
                bundle_dir.join("inputs").join(format!("{}.json", seed.id)),
                serde_json::to_vec_pretty(&seed.input)?,
            )?;
        }

        Ok(())
    }

    pub fn load_mainnet_seed_bundle(&self, id: &str) -> anyhow::Result<MainnetSeedBundle> {
        let path = self
            .resolve_mainnet_seed_bundle_manifest_path(id)
            .unwrap_or_else(|| self.mainnet_seed_bundle_manifest_path(id));
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn mainnet_seed_bundle_manifest_path(&self, id: &str) -> PathBuf {
        self.root
            .join("mainnet_seeds")
            .join(id)
            .join("manifest.json")
    }

    fn resolve_mainnet_seed_bundle_manifest_path(&self, id: &str) -> Option<PathBuf> {
        let local = self.mainnet_seed_bundle_manifest_path(id);
        if local.exists() {
            return Some(local);
        }

        let global = self
            .root
            .parent()
            .map(|parent| parent.join("mainnet_seeds").join(id).join("manifest.json"))?;
        if global != local && global.exists() {
            Some(global)
        } else {
            None
        }
    }

    pub fn inspect_mainnet_seed_bundle(
        &self,
        id: Option<&str>,
        campaign_target: Address,
    ) -> SeedBundleStatus {
        let Some(id) = id else {
            return SeedBundleStatus::Disabled;
        };
        let local_path = self.mainnet_seed_bundle_manifest_path(id);
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
        let material = format!("{}:{reason}", metadata.path_hash);
        let fingerprint = format!("0x{}", hex::encode(revm::primitives::keccak256(material)));
        let record = CrashRecord {
            fingerprint: fingerprint.clone(),
            input_id: metadata.id.clone(),
            reason: reason.to_string(),
        };
        fs::write(
            self.root
                .join("crashes")
                .join(format!("{}.json", &fingerprint[2..18])),
            serde_json::to_vec_pretty(&record)?,
        )?;
        Ok(record)
    }

    pub fn persist_snapshot_manifest(
        &self,
        snapshot: &Snapshot,
        producing_input_id: Option<String>,
    ) -> anyhow::Result<SnapshotManifest> {
        fs::create_dir_all(self.root.join("snapshots"))?;
        let manifest = SnapshotManifest {
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
        fs::write(
            self.root
                .join("snapshots")
                .join(format!("{}.manifest.json", snapshot.id)),
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
        let encoded = serde_json::to_vec(input)?;
        let input_hash = hex::encode(revm::primitives::keccak256(&encoded));
        let report_id = &input_hash[..16];
        let path = self.root.join(format!("repro_{report_id}.md"));

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

        fs::write(&path, report)?;
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
    let encoded = serde_json::to_vec(input)?;
    let sequence_hash = format!("0x{}", hex::encode(revm::primitives::keccak256(encoded)));
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
    use revm::database::CacheDB;
    use revm::primitives::U256;
    use std::time::{SystemTime, UNIX_EPOCH};

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
                waypoints: Vec::new(),
                mutation_provenance: Vec::new(),
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
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let mut corpus = SnapshotCorpus::new();
        corpus.add_snapshot(
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
        );
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
    fn snapshot_pruning_retains_promising_state() {
        let target = Address::repeat_byte(0x53);
        let mut corpus = SnapshotCorpus::new();
        corpus.add_snapshot(
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
        );
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0xaa, 0xbb, 0xcc, 0xdd],
                caller: Address::repeat_byte(0x13),
                to: target,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
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
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
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
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
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
    fn campaign_corpus_falls_back_to_global_seed_bundle() {
        let root = temp_corpus_root("seed-bundle-global-fallback");
        let global = PersistentCorpus::new(&root).expect("global corpus");
        let target = Address::repeat_byte(0xaa);
        global
            .persist_mainnet_seed_bundle("bundle", &seed_bundle(target, vec![seed(target)]))
            .expect("persist global bundle");

        let campaign = PersistentCorpus::new(root.join("campaign-a")).expect("campaign corpus");
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

pub struct SnapshotMetadata {
    pub visits: usize,
    pub last_coverage_gain: usize,
    pub depth: u32,
    pub coverage_score: usize,
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

    pub fn add_snapshot(&mut self, id: u64, parent_id: u64, snapshot: Snapshot) {
        let depth = snapshot.depth;
        let coverage_score = snapshot.coverage.count_ones();
        self.snapshots.insert(id, Arc::new(RwLock::new(snapshot)));
        self.parent_map.insert(id, parent_id);
        if id != parent_id {
            self.children_map.entry(parent_id).or_default().push(id);
        }
        self.metadata.insert(
            id,
            SnapshotMetadata {
                visits: 0,
                last_coverage_gain: 0,
                depth,
                coverage_score,
                read_set: HashSet::new(), // Populated after execution
                write_set: HashSet::new(),
                score: SnapshotScore {
                    new_coverage: coverage_score as u64,
                    ..SnapshotScore::default()
                },
            },
        );
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
        self.add_snapshot(id, parent_id, snapshot);
        self.update_snapshot_metadata_from_execution(id, execution);
        self.prune_to_limit(max_snapshots.max(1));
        Some(id)
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
            let Some((&id, _)) =
                self.metadata
                    .iter()
                    .filter(|(id, _)| **id != 0)
                    .min_by_key(|(_, metadata)| {
                        (
                            metadata.score.total(&SnapshotScoreWeights::default()),
                            metadata.coverage_score,
                            metadata.write_set.len(),
                            std::cmp::Reverse(metadata.visits),
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
        if self.snapshots.is_empty() {
            return None;
        }

        // Calculate energy per snapshot: base coverage + "Gap Potential"
        let mut weighted_ids = Vec::new();
        for (id, meta) in &self.metadata {
            let snap = self.snapshots.get(id).unwrap().read();

            // Heuristic: Intersect current snapshot coverage with the gap map.
            // If this branch is "near" a gap, give it a 10x multiplier.
            let gap_intersection =
                (snap.coverage.clone() & self.priority_gap_map.clone()).count_ones();
            let energy = meta
                .coverage_score
                .saturating_add(gap_intersection * 10)
                .saturating_add(meta.score.total(&SnapshotScoreWeights::default()) as usize);

            weighted_ids.push((*id, energy));
        }

        let total_energy: usize = weighted_ids.iter().map(|(_, e)| *e).sum();
        if total_energy == 0 {
            // Fallback to random if no coverage yet
            let keys: Vec<u64> = self.snapshots.keys().cloned().collect();
            return Some(keys[rand.below(NonZero::new(keys.len()).unwrap())]);
        }

        let mut p = rand.below(NonZero::new(total_energy).unwrap());
        for (id, energy) in weighted_ids {
            if p < energy {
                return Some(id);
            }
            p -= energy;
        }

        self.snapshots.keys().next().cloned()
    }

    pub fn update_metadata(&mut self, id: u64, new_coverage: usize) {
        if let Some(meta) = self.metadata.get_mut(&id) {
            meta.visits += 1;
            if new_coverage > meta.coverage_score {
                meta.last_coverage_gain = 0;
                meta.coverage_score = new_coverage;
            } else {
                meta.last_coverage_gain += 1;
            }
        }
    }

    /// Pruning logic: If a state branch hasn't yielded new coverage in N visits,
    /// we prune it to keep the search space efficient.
    pub fn prune_dead_ends(&mut self, threshold: usize) {
        let to_remove: Vec<u64> = self
            .metadata
            .iter()
            .filter(|(_, meta)| meta.visits > threshold && meta.last_coverage_gain == 0)
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            self.prune_recursive(id);
        }
    }

    pub fn retain(&mut self, ids: &HashSet<u64>) {
        // To ensure no orphaned states remain, if we remove a snapshot,
        // we must also remove all its descendants.
        let all_ids: Vec<u64> = self.snapshots.keys().cloned().collect();
        for id in all_ids {
            if !ids.contains(&id) && self.snapshots.contains_key(&id) {
                self.prune_recursive(id);
            }
        }

        self.snapshots.retain(|id, _| ids.contains(id));
        self.parent_map.retain(|id, _| ids.contains(id));
        self.metadata.retain(|id, _| ids.contains(id));
        self.children_map.retain(|id, _| ids.contains(id));
    }

    /// Recursively removes a snapshot and all its descendants from the corpus.
    pub fn prune_recursive(&mut self, id: u64) {
        if let Some(children) = self.children_map.remove(&id) {
            for child_id in children {
                self.prune_recursive(child_id);
            }
        }
        self.snapshots.remove(&id);
        self.parent_map.remove(&id);
        self.metadata.remove(&id);
    }
    pub fn get_snapshot(&self, id: u64) -> Option<Arc<RwLock<Snapshot>>> {
        self.snapshots.get(&id).cloned()
    }
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
