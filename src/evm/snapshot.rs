use crate::common::types::{Snapshot, ChainState};
use revm::database::{CacheDB, EmptyDB};

pub fn new_evm_snapshot(id: u64, initial_state: CacheDB<EmptyDB>) -> Snapshot {
    Snapshot {
        id,
        state: std::sync::Arc::new(parking_lot::RwLock::new(ChainState::Evm(initial_state))),
        coverage: bitvec::bitvec![u8, Lsb0; 0; 1024 * 64],
        waypoints: vec![],
        depth: 0,
    }
}