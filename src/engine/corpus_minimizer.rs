use crate::evm::corpus::SnapshotCorpus;
use bitvec::prelude::*;
use std::collections::HashSet;

pub struct CorpusMinimizer;

impl CorpusMinimizer {
    /// Reduces the SnapshotCorpus to only those snapshots that contribute unique coverage bits.
    /// Returns the set of snapshot IDs that must be retained.
    pub fn minimize(corpus: &SnapshotCorpus) -> HashSet<u64> {
        let mut global_coverage = bitvec![u8, Lsb0; 0; 65536];
        let mut kept_ids = HashSet::new();

        // Sort snapshots by ID to process the tree in a logical order
        let mut ids: Vec<u64> = corpus.snapshots.keys().cloned().collect();
        ids.sort();

        for id in ids {
            let snap_arc = corpus.snapshots.get(&id).unwrap();
            let snap = snap_arc.read();
            
            let mut contributes_new_coverage = false;
            for i in 0..snap.coverage.len() {
                if snap.coverage[i] && !global_coverage[i] {
                    contributes_new_coverage = true;
                    global_coverage.set(i, true);
                }
            }

            if contributes_new_coverage {
                // This snapshot is unique; retain it and the path back to the root
                let mut current_id = id;
                while !kept_ids.contains(&current_id) {
                    kept_ids.insert(current_id);
                    if let Some(&parent) = corpus.parent_map.get(&current_id) {
                        if current_id == parent { break; } // Root reached
                        current_id = parent;
                    } else {
                        break;
                    }
                }
            }
        }

        log::info!("Corpus minimized: kept {}/{} snapshots", kept_ids.len(), corpus.snapshots.len());
        kept_ids
    }
}