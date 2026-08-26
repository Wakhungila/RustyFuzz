use crate::common::types::{ChainState, Snapshot};
use bitvec::prelude::Lsb0;
use rustyfuzz_evm::fork_db::EvmCacheDb;

pub fn new_evm_snapshot(id: u64, initial_state: EvmCacheDb) -> Snapshot {
    Snapshot {
        id,
        state: std::sync::Arc::new(parking_lot::RwLock::new(ChainState::Evm(initial_state))),
        coverage: bitvec::bitvec![u8, Lsb0; 0; 1024 * 64],
        producing_input: None,
        waypoints: vec![],
        depth: 0,
        gas_used: 0,
    }
}
