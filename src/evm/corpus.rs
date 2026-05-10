use crate::common::types::Snapshot;
use revm::primitives::{Address, B256};
use libafl_bolts::rands::Rand;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;
use bitvec::bitvec;
use bitvec::prelude::{BitVec, Lsb0};

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
        self.snapshots.insert(id, Arc::new(RwLock::new(snapshot)));
        self.parent_map.insert(id, parent_id);
        if id != parent_id {
            self.children_map.entry(parent_id).or_default().push(id);
        }
        self.metadata.insert(id, SnapshotMetadata {
            visits: 0,
            last_coverage_gain: 0,
            depth,
            coverage_score: snapshot.coverage.count_ones(),
            read_set: HashSet::new(), // Populated after execution
            write_set: HashSet::new(),
        });
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
            let gap_intersection = (snap.coverage.clone() & self.priority_gap_map.clone()).count_ones();
            let energy = meta.coverage_score + (gap_intersection * 10);
            
            weighted_ids.push((*id, energy));
        }

        let total_energy: usize = weighted_ids.iter().map(|(_, e)| *e).sum();
        if total_energy == 0 {
            // Fallback to random if no coverage yet
            let keys: Vec<u64> = self.snapshots.keys().cloned().collect();
            return Some(keys[rand.below(keys.len() as u64) as usize]);
        }

        let mut p = rand.below(total_energy as u64) as usize;
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
        let to_remove: Vec<u64> = self.metadata
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