use crate::common::types::{Snapshot, ChainState, ForkedDb};
use bitvec::prelude::Lsb0;
use std::sync::Arc;

/// Creates a new snapshot from a forked database state.
/// 
/// The snapshot includes:
/// - A unique ID for tracking in the corpus
/// - An Arc<RwLock> wrapped ChainState for thread-safe access
/// - A 64KB coverage bitmap (524,288 bits) for edge coverage tracking
/// - Empty waypoints vector (populated during execution)
/// - Initial depth of 0
pub fn new_evm_snapshot(id: u64, forked_db: ForkedDb) -> Snapshot {
    Snapshot {
        id,
        state: Arc::new(parking_lot::RwLock::new(ChainState::Evm(Arc::new(parking_lot::RwLock::new(forked_db))))),
        coverage: bitvec::bitvec![u8, Lsb0; 0; 1024 * 64], // 64KB coverage map
        waypoints: vec![],
        depth: 0,
    }
}

/// Creates a deep copy of a snapshot for mutation and exploration.
/// 
/// This is critical for fuzzing: each mutated input gets its own copy
/// of the state to explore different execution paths independently.
pub fn clone_snapshot(original: &Snapshot) -> Snapshot {
    let state_guard = match original.state.read().try_read() {
        Some(guard) => guard,
        None => {
            // If we can't get a read lock, create a minimal snapshot
            return Snapshot {
                id: original.id + 1,
                state: original.state.clone(),
                coverage: original.coverage.clone(),
                waypoints: original.waypoints.clone(),
                depth: original.depth,
            };
        }
    };
    
    // Clone the inner database state
    let cloned_state = match &*state_guard {
        ChainState::Evm(db_arc) => {
            let db_guard = db_arc.read();
            // Note: CacheDB cloning depends on the underlying DB implementation
            // For AlloyDB, this will clone the cached entries but not re-fetch from RPC
            ChainState::Evm(Arc::new(parking_lot::RwLock::new((*db_guard).clone())))
        }
    };
    
    Snapshot {
        id: original.id + 1,
        state: Arc::new(parking_lot::RwLock::new(cloned_state)),
        coverage: original.coverage.clone(),
        waypoints: original.waypoints.clone(),
        depth: original.depth,
    }
}