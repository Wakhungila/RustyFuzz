use crate::common::types::{Snapshot, ChainState, SvmState};
use std::sync::Arc;
use parking_lot::RwLock;
use bitvec::prelude::*;

pub fn new_svm_snapshot(id: u64, initial_state: SvmState) -> Snapshot {
    Snapshot {
        id,
        state: Arc::new(RwLock::new(ChainState::Svm(initial_state))),
        coverage: bitvec![0; 1024 * 64], // example bitmap
        waypoints: vec![],
        depth: 0,
    }
}