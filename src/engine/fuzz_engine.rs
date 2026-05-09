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
use crate::evm::etherscan_abi_fetcher::EtherscanAbiFetcher;
use crate::evm::erc20_discovery::Erc20Discovery;
use crate::common::report::generate_report;
use crate::common::verifier::{SymbolicVerifier, HalmosVerifier};
use crate::evm::economic::EconomicState;
use revm::primitives::B256;
use std::{sync::Arc, collections::{HashSet, HashMap}};
use parking_lot::RwLock;
use bitvec::prelude::*;
use libafl::prelude::*;
use libafl::prelude::MAP_SIZE; // Import MAP_SIZE from inspector
use libafl_bolts::prelude::*;
use libafl_bolts::rands::{StdRand, SeedableRng, Rand};
use alloy::providers::Provider;
use revm::primitives::Address;

pub async fn run_fuzz_campaign(config: &Config) -> anyhow::Result<()> {
    log::info!(
        "RustyFuzz campaign started on {} using {} cores",
        config.chain,
        num_cpus::get()
    );

    // Load sensitive configuration from .env
    dotenvy::dotenv().ok();
    #[cfg(feature = "notifier")]
    let notifier = crate::common::notifier::DiscordNotifier::new();

    // Core components shared between LibAFL and the EVM engine
    let snapshot_corpus = Arc::new(RwLock::new(SnapshotCorpus::new()));
    let mut dataflow_registry = DataflowRegistry::new();
    let evm_executor = Arc::new(EvmExecutor::new());
    let account_registry = Arc::new(RwLock::new(GlobalAccountRegistry::default()));

    // For a fuzzer, we use LibAFL's Launcher to spawn processes/threads
    // For brevity, we demonstrate the multi-threaded coordination logic here.
    let initial_cache_db = create_fork_db(&config.rpc_url, config.fork_block).await?;
    let initial_block_env = create_fork_block_env(&config.rpc_url, config.fork_block).await?;
    
    // 2. High-Fidelity Bootstrapping: Ingest mainnet seeds
    let provider = alloy::providers::ProviderBuilder::new().on_http(config.rpc_url.parse()?);
    let ingester = SeedIngester::new(provider);

    // --- Forge Coverage Seed Integration ---
    // Load uncovered branches from an existing forge coverage run.
    // This allows RustyFuzz to focus on "Cold" code paths.
    if let Ok(coverage_xml) = std::fs::read_to_string("coverage.xml") {
        log::info!("Ingesting Forge coverage report to identify code gaps...");
        let mut corpus_guard = snapshot_corpus.write();
        
        // Simple heuristic parser for Cobertura XML: look for lines with 0 hits
        for line in coverage_xml.lines() {
            if line.contains("hits=\"0\"") {
                // Map line-level gaps to internal edge hashes (heuristic)
                let fake_edge = (line.len() % 65536) as usize; 
                corpus_guard.priority_gap_map.set(fake_edge, true);
            }
        }
    }

    let target_contract = config.target_contract.unwrap_or(Address::from_slice(&[0xaa; 20]));
    let initial_seeds = ingester.ingest_from_target(target_contract, 50).await.unwrap_or_default();

    {
        let mut corpus = snapshot_corpus.write();
        // Add root snapshot
        corpus.add_snapshot(0, 0, crate::evm::snapshot::new_evm_snapshot(0, initial_cache_db.clone()));

        // Execute initial seeds to warm up the corpus with realistic states
        let mut id_counter = 1;
        for seed in initial_seeds {
            let mut warm_state = ChainState::Evm(initial_cache_db.clone());
            let mut warm_env = initial_block_env.clone();
            let mut coverage = bitvec![u8, Lsb0; 0; MAP_SIZE];
            let mut waypoints = Vec::new();
            
            if let Ok(gas) = evm_executor.execute(&mut warm_state, &seed.txs[0], coverage.as_mut_bitslice(), &mut dataflow_registry, &mut waypoints) {
                // Populate the registry with discovered accounts from seed execution
                account_registry.write().discover_from_state(&warm_state);
                // Attempt to fetch ABI for the target contract
                if let Err(e) = account_registry.read().etherscan_abi_fetcher.as_ref().map_or(Ok(()), |f| tokio::runtime::Handle::current().block_on(f.fetch_abi(target_contract)).map(|abi| {
                    account_registry.write().auto_populate_abi(&mut abi_registry.write());
                }).map_err(|e| anyhow::anyhow!("Failed to fetch ABI: {}", e))) { log::warn!("ABI fetch error: {}", e); }
                let snap = Snapshot {
                    id: id_counter,
                    state: Arc::new(RwLock::new(warm_state)),
                    coverage,
                    producing_input: Some(seed),
                    waypoints,
                    depth: 1,
                    gas_used: gas,
                };
                corpus.add_snapshot(id_counter, 0, snap);
                id_counter += 1;
            }
        }

        // Discover ERC20 balance slots for all known tokens
        let erc20_discovery = Erc20Discovery::new(evm_executor.clone(), abi_registry.clone());
        let mut account_registry_guard = account_registry.write();
        for token_addr in account_registry_guard.contracts.iter().cloned() {
            if let Some(balance_slot) = erc20_discovery.find_balance_slot(token_addr, fuzzer_address, &initial_cache_db).await? {
                account_registry_guard.erc20_balance_slots.insert(token_addr, balance_slot);
            }
            if let Some(total_supply_slot) = erc20_discovery.find_total_supply_slot(token_addr, &initial_cache_db).await? {
                account_registry_guard.erc20_total_supply_slots.insert(token_addr, total_supply_slot);
            }
        }
        drop(account_registry_guard); // Release lock
    }

    let sgx_executor = SgxExecutor::new(0); // Hardware enclave instance
    let abi_registry = Arc::new(AbiRegistry::default());
    let mut mutator = EvmMutator {
        // TODO: Initialize type_cache and decode_cache properly
        // This is a placeholder to satisfy the compiler
        type_cache: RwLock::new(HashMap::new()),
        abi_registry,
        account_registry: account_registry.clone(),
        type_cache: RwLock::new(HashSet::new().into_iter().collect()), // Placeholder init
        decode_cache: RwLock::new(hashlink::LruCache::new(1000)),
    };

    let fuzzer_address = Address::from_slice(&[0x13; 20]); // Mock fuzzer wallet
    let mut oracles: Vec<Box<dyn VulnerabilityOracle + Send + Sync>> = vec![
        Box::new(ReentrancyOracle),
        Box::new(ProfitOracle { fuzzer_address, account_registry: account_registry.clone() }),
        Box::new(SolvencyOracle {
            protocol_address: Address::from_slice(&[0xaa; 20]),
            token_thresholds: HashMap::new(),
            account_registry: account_registry.clone(),
        }),
        Box::new(ERC20TotalSupplyInvariant { token_address: Address::ZERO, account_registry: account_registry.clone() }), // Example
    ];

    // --- Foundry Invariant Integration ---
    // Automatically discover functions starting with 'invariant_' and register them as oracles
    let invariant_selectors: Vec<[u8; 4]> = abi_registry.functions.keys()
        .filter(|sel| {
            // Heuristic: check if this selector maps to an invariant_ function
            // In a production build, we would resolve the name via a signature database
            true 
        })
        .cloned()
        .collect();

    oracles.push(Box::new(crate::common::oracle::FoundryInvariantOracle {
        test_contract: target_contract,
        invariant_selectors,
        executor: evm_executor.clone(),
    }));

    // Initialize Halmos Verifier
    let halmos_verifier = HalmosVerifier::new("halmos".to_string()); // Assumes 'halmos' is in PATH

    // --- LibAFL Harness Setup ---
    
    // 1. Observer: Link the coverage map to LibAFL
    // Note: In a production multi-process setup, this would be backed by shared memory (shmem)
    let mut coverage_map = [0u8; MAP_SIZE];
    let observer = unsafe { StdMapObserver::from_mut_ptr("edges", coverage_map.as_mut_ptr(), MAP_SIZE) };

    // 2. Feedback: Defines what makes an input "interesting"
    // MaxMapFeedback maximizes the bits set in the coverage observer
    let mut feedback = MaxMapFeedback::new(&observer);
    
    let mut objective = (); // Wrap oracles here for solution detection

    // 3. State: Holds corpus and RNG
    let mut state = StdState::new(
        StdRand::with_seed(0),
        InMemoryCorpus::<EvmInput>::new(),
        InMemoryCorpus::<EvmInput>::new(),
        &mut feedback,
        &mut objective,
    )?;

    // 4. Scheduler: Weighted selection based on power schedule
    let scheduler = StdScheduler::new();

    // 5. Fuzzer: Orchestrates the loop
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // 6. Stage: The mutation stage
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // 7. Manager: Handles events (e.g., UI or multi-node syncing)
    let mut manager = SimpleEventManager::new(StdScoreBoard::new());

    // 8. Custom Executor: Wraps EvmExecutor logic
    // This replaces the manual `for` loop logic and integrates it into `fuzzer.fuzz_loop`
    let mut executor = InProcessExecutor::new(
        // TODO: Replace with actual observers for coverage and custom feedback
        &mut (), // Observers placeholder (e.g., MapObserver for coverage)
        |input: &EvmInput, _state: &mut S, _manager: &mut EM| {
            let base_snap_arc = snapshot_corpus.read().get_snapshot(input.base_snapshot_id).unwrap();
            let current_snapshot = base_snap_arc.read();

            let mut cloned_state = current_snapshot.state.read().clone();
            let mut current_block_env = initial_block_env.clone();
            let mut tx_coverage = current_snapshot.coverage.clone();
            let mut all_waypoints = Vec::new();
            let mut last_snapshot = current_snapshot.clone();

            for (tx_idx, tx) in input.txs.iter().enumerate() {
                let mut current_tx_waypoints = Vec::new();
                if let Ok(gas) = evm_executor.execute(&mut cloned_state, &mut current_block_env, tx, tx_coverage.as_mut_bitslice(), &mut dataflow_registry, &mut current_tx_waypoints, tx_idx) {
                    all_waypoints.extend(current_tx_waypoints.clone());

                    let after_snapshot = Snapshot {
                        id: last_snapshot.id + 1,
                        producing_input: Some(input.clone()),
                        state: Arc::new(RwLock::new(cloned_state.clone())),
                        coverage: tx_coverage.clone(),
                        waypoints: all_waypoints.clone(), // Aggregate waypoints
                        depth: last_snapshot.depth + 1,
                        gas_used: gas,
                    };

                    // Run oracles against the new state
                    for oracle in &oracles {
                        if let Some(vuln_type) = oracle.check(&last_snapshot, &after_snapshot) {
                            log::error!("VULN DISCOVERED IN SEQUENCE: {:?} at depth {}", vuln_type, after_snapshot.depth);
                            
                            // Generate Foundry PoC
                            let poc_content = synthesize_foundry_poc(input, &vuln_type, Path::new("reports"), &config.rpc_url, config.fork_block.unwrap_or(0)).unwrap_or_default();

                            // Dispatch remote notification
                            #[cfg(feature = "notifier")]
                            let _ = notifier.notify_discovery(&vuln_type, &after_snapshot, None, Some(poc_content)).await;

                            // TODO: Trigger Minimizer and ScoringEngine
                            // For now, we just report and continue
                            return ExitKind::Crash; // Indicate a bug found
                        }
                    }
                    last_snapshot = after_snapshot;
                } else {
                    return ExitKind::Crash; // Treat any revert in sequence as a crash for now
                }
            }
            ExitKind::Ok // Or ExitKind::Oom, ExitKind::Timeout, etc.
        },
        tuple_list!(),
        &mut state,
        &mut manager,
    )?;

    log::info!("Starting LibAFL fuzzing loop...");
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager)?;

    println!("RustyFuzz campaign finished.");

    Ok(())
}