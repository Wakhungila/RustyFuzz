use crate::common::types::{Snapshot, ChainState, SingletonTx, Waypoint};
use crate::config::Config;
use crate::evm::fork::{create_fork_db, create_fork_block_env};
use crate::evm::executor::EvmExecutor;
use crate::common::oracle::{VulnerabilityOracle, ReentrancyOracle, ProfitOracle, SolvencyOracle, PropertyOracle, CustomInvariant, UniswapV3InvariantOracle};
use crate::engine::exploit_synthesizer::synthesize_poc;
use crate::evm::fuzz::{EvmInput, EvmMutator, AbiRegistry};
use crate::evm::sgx_executor::SgxExecutor;
use crate::evm::seed_ingester::SeedIngester;
use crate::evm::corpus::SnapshotCorpus;
use crate::evm::registry::GlobalAccountRegistry;
use crate::evm::dataflow::DataflowRegistry;
use crate::engine::corpus_minimizer::CorpusMinimizer;
use crate::engine::scoring::{ScoringEngine, SeverityScore};
use crate::engine::corpus_minimizer::CorpusMinimizationStage;
use crate::evm::erc20_discovery::Erc20Discovery;
use crate::common::report::generate_report;
use crate::common::verifier::{SymbolicVerifier, HalmosVerifier};
use crate::evm::economic::EconomicState;
use revm::primitives::B256;
use std::{sync::Arc, collections::{HashSet, HashMap}, path::Path};
use parking_lot::RwLock;
use bitvec::prelude::*;
use libafl::prelude::*;
use libafl::prelude::MAP_SIZE; // Import MAP_SIZE from inspector
use libafl_bolts::prelude::*;
use libafl_bolts::rands::{StdRand, SeedableRng, Rand};
use libafl_bolts::shmem::StdShMemProvider;
use alloy::providers::Provider;
use revm::primitives::Address;
use std::path::Path;
use std::time::Instant;

pub async fn run_fuzz_campaign(config: &Config) -> anyhow::Result<()> {
    // 1. Load sensitive configuration from .env
    dotenvy::dotenv().ok();

    let start_time = Instant::now();

    // 2. Define the Monitor (UI/Logging) for the campaign
    let monitor = SimpleMonitor::new(move |s| {
        let elapsed = start_time.elapsed().as_secs().max(1);
        let eps = s.executions() / elapsed;
        log::info!("Stats: {} | Throughput: {} exec/sec | Duration: {}s", s, eps, elapsed);
    });

    // 3. Setup Shared Memory Provider for LLMP
    let shmem_provider = StdShMemProvider::new()?;

    log::info!("Initializing RustyFuzz Distributed Campaign (LLMP)...");

    // 4. Multi-Process Launcher
    // This uses LLMP to scale across all available CPU cores.
    Launcher::builder()
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .configuration(EventConfig::AlwaysUnique)
        .run_client(|state: Option<_>, mut manager, core_id| {
            // This closure is executed on each core
            log::info!("Starting worker process on core {:?}", core_id);
            
            // --- Local Process Setup ---
            // Each process has its own revm instance and local snapshot corpus
            let snapshot_corpus = Arc::new(RwLock::new(SnapshotCorpus::new()));
            let mut dataflow_registry = DataflowRegistry::new();
            let evm_executor = Arc::new(EvmExecutor::new());
            let account_registry = Arc::new(RwLock::new(GlobalAccountRegistry::default()));
            let abi_registry = Arc::new(AbiRegistry::default());

            // Initialize forking (AlloyDB handles remote caching per process)
            let initial_cache_db = tokio::runtime::Handle::current().block_on(async {
                create_fork_db(&config.rpc_url, config.fork_block).await.unwrap()
            });
            let initial_block_env = tokio::runtime::Handle::current().block_on(async {
                create_fork_block_env(&config.rpc_url, config.fork_block).await.unwrap()
            });

            // Bootstrap with root snapshot
            snapshot_corpus.write().add_snapshot(0, 0, crate::evm::snapshot::new_evm_snapshot(0, initial_cache_db.clone()));

            // Setup LibAFL components
            let mut feedback = EvmCoverageFeedback;
            let mut objective = (); 

            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    StdRand::with_seed(core_id.0 as u64),
                    InMemoryCorpus::<EvmInput>::new(),
                    InMemoryCorpus::<EvmInput>::new(),
                    &mut feedback,
                    &mut objective,
                ).unwrap()
            });

            let mut mutator = EvmMutator {
                abi_registry,
                account_registry: account_registry.clone(),
                type_cache: RwLock::new(HashMap::new()),
                decode_cache: RwLock::new(hashlink::LruCache::new(1000)),
            };

            let mut stages = tuple_list!(
                StdMutationalStage::new(mutator),
                CorpusMinimizationStage::new(
                    snapshot_corpus.clone(),
                    evm_executor.clone(),
                    initial_cache_db.clone(),
                    initial_block_env.clone(),
                    1000 // Run distillation every 1000 iterations
                )
            );
            let mut fuzzer = StdFuzzer::new(StdScheduler::new(), feedback, objective);

            // 5. LLMP-Integrated Executor
            let mut coverage_map = [0u8; MAP_SIZE];
            let observer = unsafe { StdMapObserver::from_mut_ptr("edges", coverage_map.as_mut_ptr(), MAP_SIZE) };
            
            let mut executor = InProcessExecutor::with_observers(
                |input: &EvmInput, _state, _manager| {
                    let base_snap_arc = snapshot_corpus.read().get_snapshot(input.base_snapshot_id).unwrap();
                    let current_snapshot = base_snap_arc.read();
                    let mut cloned_state = current_snapshot.state.read().clone();
                    let mut current_block_env = initial_block_env.clone();
                    
                    // Link coverage memory to the inspector for this iteration
                    let mut tx_coverage = bitvec::view::BitSlice::from_slice_mut(&mut coverage_map);

                    for (tx_idx, tx) in input.txs.iter().enumerate() {
                        let mut tx_waypoints = Vec::new();
                        if let Ok(_gas) = evm_executor.execute(&mut cloned_state, &mut current_block_env, tx, tx_coverage, &mut dataflow_registry.write(), &mut tx_waypoints, tx_idx) {
                            // Waypoint and Oracle logic...
                        } else {
                            return ExitKind::Ok; // Reverts are part of discovery
                        }
                    }
                    ExitKind::Ok
                },
                tuple_list!(observer),
                &mut state,
                &mut manager,
            ).unwrap();

            // Run the campaign loop
            loop {
                fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager).unwrap();
                
                // Infrastructure Level: Periodic Corpus Persistence
                // This allows the campaign to be resumed after an infrastructure restart.
                if let Ok(serialized) = postcard::to_allocvec(&state) {
                    let _ = std::fs::write("corpus_checkpoint.bin", serialized);
                    log::info!("Campaign checkpoint saved to disk.");
                }
            }
            Ok(())
        })
        .cores(CoreId::all().unwrap())
        .build()
        .launch()?;

    Ok(())
}