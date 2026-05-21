use crate::common::types::{ChainState, EvmInput, SingletonTx};
use crate::evm::corpus::SnapshotCorpus;
use crate::evm::dataflow::DataflowRegistry;
use crate::evm::executor::EvmExecutor;
use crate::evm::fuzz::{AbiRegistry, EvmMutator};
use crate::evm::registry::GlobalAccountRegistry;
use crate::evm::snapshot::new_evm_snapshot;

use libafl::corpus::{Corpus, Testcase};
use libafl::state::HasCorpus;
use parking_lot::RwLock;
use revm::primitives::{Address, U256};
use revm::state::AccountInfo;
use std::cell::UnsafeCell;
use std::{sync::Arc, time::Instant};

// Sync wrapper for UnsafeCell to allow thread-safe static usage
struct SyncUnsafeCell<T>(UnsafeCell<T>);
unsafe impl<T: Send> Sync for SyncUnsafeCell<T> {}

// LibAFL 0.15.4 Imports
use libafl::events::ClientDescription;
use libafl::prelude::{
    EventConfig, ExitKind, Fuzzer, InMemoryCorpus, InProcessExecutor, Launcher, SimpleMonitor,
    StdFuzzer, StdMapObserver, StdMutationalStage, StdScheduler, StdState,
};
use libafl_bolts::prelude::*;
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
use libafl_bolts::tuples::tuple_list;

const MAP_SIZE: usize = 65536;

pub struct Config {
    pub rpc_url: String,
    pub fork_block: u64,
    pub target_contract: Option<Address>,
    pub corpus_dir: String,
    pub report_dir: String,
}

pub async fn run_fuzz_campaign(config: Config) -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let start_time = Instant::now();

    let monitor = SimpleMonitor::new(|s| {
        log::info!("Stats: {} | Duration: {:?}", s, start_time.elapsed());
    });

    let shmem_provider = StdShMemProvider::new()?;

    log::info!("Initializing RustyFuzz v0.15.4 Campaign...");

    let (mut initial_db, initial_env) = {
        let db = crate::evm::fork::create_fork_db(
            &config.rpc_url,
            config.fork_block,
            config.target_contract,
        )
        .await?;
        let env =
            crate::evm::fork::create_fork_block_env(&config.rpc_url, config.fork_block).await?;
        (db, env)
    };

    let fuzzer_address = Address::repeat_byte(0x13);
    initial_db.insert_account_info(
        fuzzer_address,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );

    Launcher::builder()
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .configuration(EventConfig::AlwaysUnique)
        .run_client(
            |state: Option<StdState<_, _, _, _>>, mut manager, description: ClientDescription| {
                let mut initial_registry = GlobalAccountRegistry::default();
                initial_registry.discover_from_state(&ChainState::Evm(initial_db.clone()));
                let target_contract = choose_target_contract(
                    config.target_contract,
                    &initial_registry,
                )
                .ok_or_else(|| {
                    libafl::Error::unknown("cannot start EVM campaign without a target contract")
                })?;

                let mut initial_snapshot_corpus = SnapshotCorpus::new();
                initial_snapshot_corpus.add_snapshot(0, 0, new_evm_snapshot(0, initial_db.clone()));
                let snapshot_corpus = Arc::new(RwLock::new(initial_snapshot_corpus));
                let dataflow_registry = Arc::new(RwLock::new(DataflowRegistry::new()));
                let evm_executor = Arc::new(EvmExecutor::new());
                let account_registry = Arc::new(RwLock::new(initial_registry));
                let mut initial_abi = AbiRegistry::default();
                account_registry.read().auto_populate_abi(&mut initial_abi);
                let abi_registry = Arc::new(initial_abi);

                let core_id = description.core_id();

                let mut feedback = crate::evm::feedback::EvmCoverageFeedback::new();
                let mut objective = ();

                let mut state = state.unwrap_or_else(|| {
                    StdState::new(
                        StdRand::with_seed(core_id.0 as u64),
                        InMemoryCorpus::<EvmInput>::new(),
                        InMemoryCorpus::<EvmInput>::new(),
                        &mut feedback,
                        &mut objective,
                    )
                    .expect("Failed to initialize State")
                });

                if state.corpus().count() == 0 {
                    state
                        .corpus_mut()
                        .add(Testcase::new(seed_input(target_contract, fuzzer_address)))?;
                }

                let mutator = EvmMutator::new(abi_registry, account_registry.clone());

                let mut stages = tuple_list!(StdMutationalStage::new(mutator),);

                let mut fuzzer = StdFuzzer::new(StdScheduler::new(), feedback, objective);

                static COVERAGE_MAP: SyncUnsafeCell<[u8; MAP_SIZE]> =
                    SyncUnsafeCell(UnsafeCell::new([0u8; MAP_SIZE]));
                let observer = unsafe {
                    StdMapObserver::from_mut_ptr(
                        "edges",
                        (COVERAGE_MAP.0).get() as *mut u8,
                        MAP_SIZE,
                    )
                };

                let mut harness = |input: &EvmInput| {
                    let snap_id = input.base_snapshot_id;
                    let snapshot_corpus_guard = snapshot_corpus.read();
                    let Some(base_snap_arc) = snapshot_corpus_guard.get_snapshot(snap_id) else {
                        log::error!("Input references missing snapshot id {}", snap_id);
                        return ExitKind::Crash;
                    };

                    let mut current_state = base_snap_arc.read().state.read().clone();
                    let mut current_env = initial_env.clone();

                    for (tx_idx, tx) in input.txs.iter().enumerate() {
                        let mut waypoints = Vec::new();
                        let mut df = dataflow_registry.write();
                        let exec_result = unsafe {
                            let map_ptr = (COVERAGE_MAP.0).get() as *mut u8;
                            let map_slice = std::slice::from_raw_parts_mut(map_ptr, MAP_SIZE);
                            evm_executor.execute(
                                &mut current_state,
                                &mut current_env,
                                tx,
                                map_slice,
                                &mut df,
                                &mut waypoints,
                                tx_idx,
                            )
                        };
                        if let Err(err) = exec_result {
                            log::error!("EVM execution failed for tx {}: {err:#}", tx_idx);
                            return ExitKind::Crash;
                        }
                    }
                    ExitKind::Ok
                };

                let mut executor = InProcessExecutor::new(
                    &mut harness,
                    tuple_list!(observer),
                    &mut fuzzer,
                    &mut state,
                    &mut manager,
                )?;

                fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager)?;

                Ok(())
            },
        )
        .cores(&Cores::from_cmdline("all")?)
        .build()
        .launch()?;

    Ok(())
}

fn choose_target_contract(
    configured: Option<Address>,
    registry: &GlobalAccountRegistry,
) -> Option<Address> {
    configured.or_else(|| {
        let mut contracts: Vec<_> = registry.contracts.iter().copied().collect();
        contracts.sort_by_key(|address| *address);
        contracts.into_iter().next()
    })
}

fn seed_input(target_contract: Address, fuzzer_address: Address) -> EvmInput {
    EvmInput {
        txs: vec![SingletonTx {
            input: Vec::new(),
            caller: fuzzer_address,
            to: target_contract,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
    }
}
