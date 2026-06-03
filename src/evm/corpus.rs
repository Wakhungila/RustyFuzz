use crate::common::oracle::ProtocolFinding;
use crate::common::oracle::ProtocolSeverity;
use crate::common::types::{ChainState, SequenceExecutionResult, Snapshot, Waypoint};
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
use revm::primitives::{Address, B256};
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
        "# RustyFuzz Campaign Artifact\n\n- input_id: `{}`\n- reason: `{}`\n- confidence: `{}`\n- proof_tier: `{:?}`\n- high_value_artifact: `{}`\n- replayable: `{}`\n- score: `{}`\n- target: `{:?}`\n- dedup_key: `{}`\n- findings: `{}`\n- confirmation_blockers: `{}`\n\n## False-positive risks\n{}\n\n## Next command\n`{}`\n",
        record.input_id,
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
    use crate::common::types::{ExecutionStatus, SingletonTx, StorageDiff, TxExecutionResult};
    use crate::evm::seed_ingester::{MainnetSeed, SeedMetadata};
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
            },
        }
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
            },
        );
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
            let energy = meta.coverage_score + (gap_intersection * 10);

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

impl Default for SnapshotCorpus {
    fn default() -> Self {
        Self::new()
    }
}
