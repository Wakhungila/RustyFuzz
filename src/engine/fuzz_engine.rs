use crate::common::types::EvmInput;
use crate::engine::corpus_minimizer::CorpusMinimizationStage;
use crate::evm::executor::EvmExecutor;
use crate::evm::corpus::SnapshotCorpus;
use crate::evm::fuzz::{EvmMutator, AbiRegistry};
use crate::evm::registry::GlobalAccountRegistry;
use crate::evm::dataflow::DataflowRegistry;

use std::{sync::Arc, collections::HashMap, time::Instant};
use parking_lot::RwLock;

// LibAFL 0.15.4 Imports
use libafl::prelude::{
    SimpleMonitor, EventConfig, Launcher, StdState, InMemoryCorpus, 
    StdFuzzer, StdScheduler, InProcessExecutor, StdMapObserver, 
    StdMutationalStage, ExitKind, Feedback, HasCorpus, Fuzzer,
};
use libafl_bolts::prelude::*;
use libafl_bolts::shmem::{StdShMemProvider, ShMemProvider};
use libafl_bolts::tuples::{tuple_list, Handled};

const MAP_SIZE: usize = 65536;

pub struct Config {
    pub rpc_url: String,
    pub fork_block: u64,
}

pub fn run_fuzz_campaign(config: Config) -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let start_time = Instant::now();

    // 1. Monitor Setup
    let monitor = SimpleMonitor::new(|s| {
        log::info!("Stats: {} | Duration: {:?}", s, start_time.elapsed());
    });

    // 2. Shared Memory Provider
    let shmem_provider = StdShMemProvider::new()?;

    log::info!("Initializing RustyFuzz v0.15.4 Campaign...");

    // 3. Launcher with LibAFL 0.15 syntax
    Launcher::builder()
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .configuration(EventConfig::AlwaysUnique)
        .run_client(|state: Option<_>, mut manager, core_id| {
            
            // --- Resources (Arc for thread safety across stages) ---
            let snapshot_corpus = Arc::new(RwLock::new(SnapshotCorpus::new()));
            let dataflow_registry = Arc::new(RwLock::new(DataflowRegistry::new()));
            let evm_executor = Arc::new(EvmExecutor::new());
            let account_registry = Arc::new(RwLock::new(GlobalAccountRegistry::default()));
            let abi_registry = Arc::new(AbiRegistry::default());

            // Initialize Forking via tokio handle
            let (initial_db, initial_env) = tokio::runtime::Handle::current().block_on(async {
                let db = crate::evm::fork::create_fork_db(&config.rpc_url, config.fork_block).await.unwrap();
                let env = crate::evm::fork::create_fork_block_env(&config.rpc_url, config.fork_block).await.unwrap();
                (db, env)
            });

            // --- Feedback & State ---
            let mut feedback = crate::evm::feedback::EvmCoverageFeedback::new();
            let mut objective = (); 

            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    StdRand::with_seed(core_id.0 as u64),
                    InMemoryCorpus::<EvmInput>::new(),
                    InMemoryCorpus::<EvmInput>::new(),
                    &mut feedback,
                    &mut objective,
                ).expect("Failed to initialize State")
            });

            // --- Mutator & Stages ---
            let mutator = EvmMutator::new(abi_registry, account_registry.clone());
            
            let mut stages = tuple_list!(
                StdMutationalStage::new(mutator),
                CorpusMinimizationStage::new(
                    snapshot_corpus.clone(),
                    evm_executor.clone(),
                    initial_db.clone(),
                    initial_env.clone(),
                    1000
                ),
            );

            let mut fuzzer = StdFuzzer::new(StdScheduler::new(), feedback, objective);

            // --- Observer Setup ---
            static mut COVERAGE_MAP: [u8; MAP_SIZE] = [0u8; MAP_SIZE];
            let observer = unsafe { 
                StdMapObserver::from_mut_ptr("edges", COVERAGE_MAP.as_mut_ptr(), MAP_SIZE) 
            };
            
            // --- InProcessExecutor (0.15.4 API) ---
            // Observers are passed as part of the tuple_list in the new() constructor
            let mut executor = InProcessExecutor::new(
                &mut observer,
                |input: &EvmInput, _state, _manager| {
                    let snap_id = input.base_snapshot_id;
                    let base_snap_arc = snapshot_corpus.read().get_snapshot(snap_id).unwrap();
                    
                    let mut current_state = base_snap_arc.read().state.read().clone();
                    let mut current_env = initial_env.clone();
                    
                    for (tx_idx, tx) in input.txs.iter().enumerate() {
                        let mut waypoints = Vec::new();
                        let mut df = dataflow_registry.write();
                        
                        // Execute using the revm v38 refactored logic
                        let _ = evm_executor.execute(
                            &mut current_state,
                            &mut current_env,
                            tx,
                            unsafe { &mut COVERAGE_MAP },
                            &mut df,
                            &mut waypoints,
                            tx_idx
                        );
                    }
                    ExitKind::Ok
                },
                &mut state,
                &mut manager,
            )?;

            // --- Fuzz Loop ---
            // In 0.15, Fuzzer::fuzz_loop is a trait method
            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager)?;
            
            Ok(())
        })
        .cores(CoreId::all()?) // CoreId::all() returns Vec in 0.15
        .build()
        .launch()?;

    Ok(())
}