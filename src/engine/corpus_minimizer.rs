use crate::evm::corpus::SnapshotCorpus;
use crate::evm::executor::EvmExecutor;
use crate::common::types::{ChainState, Snapshot, SingletonTx};
use crate::evm::fuzz::EvmInput;
use crate::evm::dataflow::DataflowRegistry;
use bitvec::prelude::*;
use std::collections::{HashSet, HashMap};
use std::sync::Arc;
use parking_lot::RwLock;
use libafl::prelude::*;
use libafl_bolts::prelude::*;
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::BlockEnv;
use log;

pub struct CorpusMinimizer;

/// A LibAFL stage that periodically distills the SnapshotCorpus and
/// performs delta debugging on transaction sequences to maximize throughput.
pub struct CorpusMinimizationStage<S> {
    pub corpus: Arc<RwLock<SnapshotCorpus>>,
    pub executor: Arc<EvmExecutor>,
    pub initial_db: CacheDB<EmptyDB>,
    pub initial_env: BlockEnv,
    pub interval: usize,
    pub exec_count: usize,
    _phantom: std::marker::PhantomData<S>,
}

impl<S> CorpusMinimizationStage<S> {
    pub fn new(
        corpus: Arc<RwLock<SnapshotCorpus>>,
        executor: Arc<EvmExecutor>,
        initial_db: CacheDB<EmptyDB>,
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

    fn verify_coverage(&self, input: &EvmInput, target: &BitVec<u8, Lsb0>) -> bool {
        let mut current_db = self.initial_db.clone();
        let mut current_env = self.initial_env.clone();
        let mut total_coverage = bitvec![u8, Lsb0; 0; 65536];
        let mut dataflow = DataflowRegistry::new();

        for (idx, tx) in input.txs.iter().enumerate() {
            let mut chain_state = ChainState::Evm(current_db.clone());
            let mut waypoints = Vec::new();
            if self.executor.execute(&mut chain_state, &mut current_env, tx, total_coverage.as_mut_bitslice(), &mut dataflow, &mut waypoints, idx).is_err() {
                return false;
            }
            if let ChainState::Evm(new_db) = chain_state { current_db = new_db; }
        }
        target.iter_ones().all(|i| total_coverage[i])
    }
}

impl<S, EM, Z> Stage<S, EM, Z> for CorpusMinimizationStage<S>
where
    S: State + HasCorpus,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut EM,
        _state: &mut S,
        _manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<(), libafl::Error> {
        self.exec_count += 1;
        if self.exec_count % self.interval != 0 { return Ok(()); }

        log::info!("Starting continuous corpus distillation and delta debugging...");
        let mut corpus = self.corpus.write();
        let kept_ids = CorpusMinimizer::minimize(&corpus);
        corpus.retain(&kept_ids);

        for id in kept_ids {
            if id == 0 { continue; }
            let snap_arc = corpus.get_snapshot(id).unwrap();
            let (mut evm_input, target_coverage) = {
                let snap = snap_arc.read();
                (snap.producing_input.clone(), snap.coverage.clone())
            };

            if let Some(ref mut input) = evm_input {
                let mut i = 0;
                while i < input.txs.len() {
                    let mut candidate = input.clone();
                    candidate.txs.remove(i);
                    if self.verify_coverage(&candidate, &target_coverage) {
                        *input = candidate;
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