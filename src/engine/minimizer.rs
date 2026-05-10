use crate::common::types::{SingletonTx, ChainState, Snapshot};
use crate::evm::executor::EvmExecutor;
use crate::common::oracle::VulnerabilityOracle;
use crate::evm::snapshot::new_evm_snapshot;
use crate::evm::dataflow::DataflowRegistry;
use bitvec::prelude::*;
// v38: Database types moved to revm::database
use revm::database::{CacheDB, EmptyDB};
use revm::context::BlockEnv;
use std::sync::Arc;
use parking_lot::RwLock;

pub struct Minimizer<'a> {
    pub executor: &'a EvmExecutor,
    pub oracle: &'a dyn VulnerabilityOracle,
    pub initial_db: CacheDB<EmptyDB>,
    pub initial_block_env: BlockEnv,
}

impl<'a> Minimizer<'a> {
    pub fn new(
        executor: &'a EvmExecutor, 
        oracle: &'a dyn VulnerabilityOracle, 
        initial_db: CacheDB<EmptyDB>,
        initial_block_env: BlockEnv,
    ) -> Self {
        Self { executor, oracle, initial_db, initial_block_env }
    }

    /// Reduces a sequence of transactions to the smallest possible subset 
    /// that still triggers the same vulnerability.
    pub fn minimize(&self, original_txs: Vec<SingletonTx>) -> Vec<SingletonTx> {
        let mut minimized = original_txs.clone();
        let mut i = 0;

        log::info!("Starting delta-debugging minimization ({} txs)...", minimized.len());

        while i < minimized.len() {
            let mut candidate = minimized.clone();
            candidate.remove(i);

            if self.verify_vuln(&candidate) {
                minimized = candidate;
                log::debug!("Unnecessary transaction removed. Remaining: {}", minimized.len());
            } else {
                i += 1;
            }
        }

        minimized
    }

    /// Replays a sequence of transactions to check if the oracle still triggers.
    fn verify_vuln(&self, txs: &[SingletonTx]) -> bool {
        let mut current_db = self.initial_db.clone();
        let mut block_env = self.initial_block_env.clone();
        
        // v38: Executors now require dataflow and waypoint tracking even during minimization
        let mut dataflow = DataflowRegistry::new();
        let mut coverage_vec = vec![0u8; 65536];
        
        let mut prev_snapshot = new_evm_snapshot(0, current_db.clone());

        for (idx, tx) in txs.iter().enumerate() {
            let mut chain_state = ChainState::Evm(current_db.clone());
            let mut waypoints = Vec::new();
            
            // Match the updated EvmExecutor::execute signature
            let exec_result = self.executor.execute(
                &mut chain_state, 
                &mut block_env,
                tx, 
                &mut coverage_vec,
                &mut dataflow,
                &mut waypoints,
                idx
            );

            if exec_result.is_err() {
                return false;
            }

            let ChainState::Evm(new_db) = chain_state;
            let current_snapshot = Snapshot {
                id: (idx + 1) as u64,
                state: Arc::new(RwLock::new(ChainState::Evm(new_db.clone()))),
                coverage: BitVec::from_slice(&coverage_vec),
                producing_input: None, // Minimization doesn't need to track origin
                waypoints,
                depth: (idx + 1) as u32,
                gas_used: exec_result.unwrap_or(0),
            };

            // Check if the oracle triggers on this specific state transition
            if self.oracle.check(&prev_snapshot, &current_snapshot).is_some() {
                return true;
            }

            current_db = new_db;
            prev_snapshot = current_snapshot;
        }

        false
    }
}