use bitvec::bitvec;
use bitvec::prelude::{BitSlice, Lsb0};
use libafl::{prelude::*, stages::Stage, state::HasCorpus};
use parking_lot::RwLock;
use revm::context::BlockEnv;
use std::collections::HashSet;
use std::sync::Arc;

use crate::common::types::ChainState;
use crate::evm::corpus::SnapshotCorpus;
use crate::evm::dataflow::DataflowRegistry;
use crate::evm::executor::EvmExecutor;
use crate::evm::fork_db::EvmCacheDb;
use crate::evm::fuzz::EvmInput;
use crate::evm::inspector::MAP_SIZE;

pub struct CorpusMinimizationStage<S> {
    pub corpus: Arc<RwLock<SnapshotCorpus>>,
    pub executor: Arc<EvmExecutor>,
    pub initial_db: EvmCacheDb,
    pub initial_env: BlockEnv,
    pub interval: usize,
    pub exec_count: usize,
    _phantom: std::marker::PhantomData<S>,
}

impl<S> CorpusMinimizationStage<S>
where
    S: HasCorpus<EvmInput>,
{
    pub fn new(
        corpus: Arc<RwLock<SnapshotCorpus>>,
        executor: Arc<EvmExecutor>,
        initial_db: EvmCacheDb,
        initial_env: BlockEnv,
        interval: usize,
    ) -> Self {
        Self {
            corpus,
            executor,
            initial_db,
            initial_env,
            interval,
            exec_count: 0,
            _phantom: std::marker::PhantomData,
        }
    }

    fn verify_coverage(&self, input: &EvmInput, target: &BitSlice<u8, Lsb0>) -> bool {
        let mut current_db = self.initial_db.clone();
        let mut current_env = self.initial_env.clone();
        let mut total_coverage = bitvec![u8, Lsb0; 0; MAP_SIZE];
        let mut dataflow = DataflowRegistry::new();

        for (idx, tx) in input.txs.iter().enumerate() {
            let mut chain_state = ChainState::Evm(current_db.clone());
            let mut waypoints = Vec::new();

            // Note: Update execute() to take revm::Context in your implementation
            if self
                .executor
                .execute(
                    &mut chain_state,
                    &mut current_env,
                    tx,
                    total_coverage.as_raw_mut_slice(),
                    &mut dataflow,
                    &mut waypoints,
                    idx,
                )
                .is_err()
            {
                return false;
            }

            let ChainState::Evm(new_db) = chain_state;
            current_db = new_db;
        }
        target.iter_ones().all(|i| total_coverage[i])
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for CorpusMinimizationStage<S>
where
    S: HasCorpus<EvmInput>,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut S,
        _manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        self.exec_count += 1;
        if !self.exec_count.is_multiple_of(self.interval) {
            return Ok(());
        }

        log::info!("Starting continuous corpus distillation...");

        // Use the new LibAFL state.corpus() accessor
        let mut corpus_lock = self.corpus.write();
        let kept_ids = CorpusMinimizer::minimize(&corpus_lock);
        corpus_lock.retain(&kept_ids);

        for id in kept_ids {
            if id == 0 {
                continue;
            }
            let snap_arc = corpus_lock.get_snapshot(id).unwrap();
            let (mut evm_input, target_coverage) = {
                let snap = snap_arc.read();
                (snap.producing_input.clone(), snap.coverage.clone())
            };

            if let Some(ref mut input) = evm_input {
                // Delta Debugging Loop
                let mut i = 0;
                while i < input.txs.len() {
                    let mut candidate = input.clone();
                    candidate.txs.remove(i);
                    if self.verify_coverage(&candidate, &target_coverage) {
                        *input = candidate;
                        // Synchronize back to snapshot
                        snap_arc.write().producing_input = Some(input.clone());
                        continue;
                    }
                    i += 1;
                }
            }
        }
        Ok(())
    }
}

pub struct CorpusMinimizer;

impl CorpusMinimizer {
    pub fn minimize(corpus: &SnapshotCorpus) -> HashSet<u64> {
        let mut global_coverage = bitvec![u8, Lsb0; 0; MAP_SIZE];
        let mut kept_ids = HashSet::new();

        let mut ids: Vec<u64> = corpus.snapshots.keys().cloned().collect();
        ids.sort_unstable();

        for id in ids {
            let snap_arc = corpus.snapshots.get(&id).unwrap();
            let snap = snap_arc.read();

            let mut contributes_new_coverage = false;
            for (idx, bit) in snap.coverage.iter().by_vals().enumerate() {
                if bit && !global_coverage[idx] {
                    contributes_new_coverage = true;
                    global_coverage.set(idx, true);
                }
            }

            if contributes_new_coverage {
                let mut current_id = id;
                while !kept_ids.contains(&current_id) {
                    kept_ids.insert(current_id);
                    if let Some(&parent) = corpus.parent_map.get(&current_id) {
                        if current_id == parent {
                            break;
                        }
                        current_id = parent;
                    } else {
                        break;
                    }
                }
            }
        }

        log::info!(
            "Corpus minimized: kept {}/{} snapshots",
            kept_ids.len(),
            corpus.snapshots.len()
        );
        kept_ids
    }
}
