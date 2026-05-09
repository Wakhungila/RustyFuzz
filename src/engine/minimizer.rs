use crate::common::types::{SingletonTx, ChainState, Snapshot};
use crate::evm::executor::EvmExecutor;
use crate::common::oracle::VulnerabilityOracle;
use crate::evm::snapshot::new_evm_snapshot;
use bitvec::prelude::*;
use revm::db::{CacheDB, EmptyDB};

pub struct Minimizer<'a> {
    pub executor: &'a EvmExecutor,
    pub oracle: &'a dyn VulnerabilityOracle,
    pub initial_db: CacheDB<EmptyDB>,
}

impl<'a> Minimizer<'a> {
    pub fn new(executor: &'a EvmExecutor, oracle: &'a dyn VulnerabilityOracle, initial_db: CacheDB<EmptyDB>) -> Self {
        Self { executor, oracle, initial_db }
    }

    /// Reduces a sequence of transactions to the smallest possible subset 
    /// that still triggers the same vulnerability.
    pub fn minimize(&self, original_txs: Vec<SingletonTx>) -> Vec<SingletonTx> {
        let mut minimized = original_txs.clone();
        let mut i = 0;

        log::info!("Starting minimization of {} transactions...", minimized.len());

        while i < minimized.len() {
            // Try removing the transaction at index i
            let mut candidate = minimized.clone();
            candidate.remove(i);

            if self.verify_vuln(&candidate) {
                // If it still fails, the transaction at index i was unnecessary.
                minimized = candidate;
                log::debug!("Reduced sequence to {} transactions", minimized.len());
                // Don't increment i; check the same index again as it now contains a new tx.
            } else {
                i += 1;
            }
        }

        minimized
    }

    /// Replays a sequence of transactions to check if the oracle still triggers.
    fn verify_vuln(&self, txs: &[SingletonTx]) -> bool {
        let mut current_db = self.initial_db.clone();
        let mut current_coverage = bitvec![u8, Lsb0; 0; 65536];
        
        let mut prev_snapshot = new_evm_snapshot(0, current_db.clone());

        for (idx, tx) in txs.iter().enumerate() {
            let mut chain_state = ChainState::Evm(current_db.clone());
            
            if self.executor.execute(&mut chain_state, tx, current_coverage.as_mut_bitslice()).is_err() {
                return false;
            }

            let ChainState::Evm(new_db) = chain_state;
            let current_snapshot = Snapshot {
                id: (idx + 1) as u64,
                state: std::sync::Arc::new(parking_lot::RwLock::new(ChainState::Evm(new_db.clone()))),
                coverage: current_coverage.clone(),
                waypoints: vec![],
                depth: (idx + 1) as u32,
            };

            // Check if this step triggered the oracle
            if self.oracle.check(&prev_snapshot, &current_snapshot).is_some() {
                return true;
            }

            current_db = new_db;
            prev_snapshot = current_snapshot;
        }

        false
    }
}