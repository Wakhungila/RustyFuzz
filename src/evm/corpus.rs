use crate::common::types::{ChainState, SequenceExecutionResult, Snapshot};
use crate::evm::feedback::EvmCoverageFeedback;
use crate::evm::fuzz::EvmInput;
use libafl_bolts::rands::Rand;
use parking_lot::RwLock;
use revm::primitives::{Address, B256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::Arc;
// use bitvec::bitvec; // Unused
use bitvec::prelude::{BitVec, Lsb0};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorpusEntryMetadata {
    pub id: String,
    pub input_hash: String,
    pub path_hash: u64,
    pub coverage_edges: usize,
    pub gas_used: u64,
    pub crash_fingerprint: Option<String>,
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

pub struct PersistentCorpus {
    root: PathBuf,
}

impl PersistentCorpus {
    pub fn new(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("inputs"))?;
        fs::create_dir_all(root.join("crashes"))?;
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
            coverage_edges: coverage.iter().filter(|&&hit| hit != 0).count(),
            gas_used,
            crash_fingerprint: None,
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
            priority_gap_map: bitvec::bitvec![u8, Lsb0; 0; 65536],
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
