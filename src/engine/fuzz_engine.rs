use crate::common::types::{Snapshot, ChainState, SingletonTx, Waypoint};
use crate::config::Config;
use crate::evm::fork::{create_fork_db, create_fork_block_env};
use crate::evm::executor::EvmExecutor;
use crate::common::oracle::{VulnerabilityOracle, ReentrancyOracle, ProfitOracle, SolvencyOracle};
use crate::engine::exploit_synthesizer::synthesize_poc;
use crate::evm::fuzz::{EvmInput, EvmMutator, AbiRegistry};
use crate::evm::sgx_executor::SgxExecutor;
use crate::evm::corpus::SnapshotCorpus;
use crate::evm::registry::GlobalAccountRegistry;
use crate::evm::dataflow::DataflowRegistry;
use crate::engine::corpus_minimizer::CorpusMinimizer;
use std::sync::Arc;
use parking_lot::RwLock;
use bitvec::prelude::*;
use libafl::mutators::Mutator;
use libafl_bolts::rands::{StdRand, SeedableRng};
use libafl_bolts::rands::Rand;

pub async fn run_fuzz_campaign(config: &Config) -> anyhow::Result<()> {
    log::info!("RustyFuzz campaign started on {} using {} cores", config.chain, num_cpus::get());

    // Load sensitive configuration from .env
    dotenvy::dotenv().ok();
    #[cfg(feature = "notifier")]
    let notifier = crate::common::notifier::DiscordNotifier::new();

    // For a fuzzer, we use LibAFL's Launcher to spawn processes/threads
    // For brevity, we demonstrate the multi-threaded coordination logic here.
    let mut snapshot_corpus = Arc::new(RwLock::new(SnapshotCorpus::new()));
    let mut rand = StdRand::with_seed(0);

    // 1. Create initial state from fork
    let initial_cache_db = create_fork_db(&config.rpc_url, config.fork_block).await?;
    let initial_chain_state = ChainState::Evm(initial_cache_db.clone()); 
    let initial_block_env = create_fork_block_env(&config.rpc_url, config.fork_block).await?;
    {
        let mut corpus = snapshot_corpus.write();
        corpus.add_snapshot(0, 0, crate::evm::snapshot::new_evm_snapshot(0, initial_cache_db, None));
    }

    let evm_executor = EvmExecutor::new();
    let sgx_executor = SgxExecutor::new(0); // Hardware enclave instance
    let abi_registry = Arc::new(AbiRegistry::default());
    let account_registry = Arc::new(RwLock::new(GlobalAccountRegistry::default()));
    let mut mutator = EvmMutator { abi_registry, account_registry: account_registry.clone() };
    
    let fuzzer_address = Address::from_slice(&[0x13; 20]); // Mock fuzzer wallet
    let mut dataflow_registry = DataflowRegistry::new();
    let oracles: Vec<Box<dyn VulnerabilityOracle + Send + Sync>> = vec![
        Box::new(ReentrancyOracle),
        Box::new(ProfitOracle { fuzzer_address }),
        Box::new(SolvencyOracle { protocol_address: Address::from_slice(&[0xaa; 20]), critical_asset_threshold: U256::from(100) }), // Example protocol address and threshold
    ];

    for i in 0..1000 {
        // Selection via Power Schedule
        let base_id = {
            let mut corpus = snapshot_corpus.write();
            corpus.select_snapshot(&mut rand).unwrap_or(0)
        };

        let base_snap_arc = snapshot_corpus.read().get_snapshot(base_id).unwrap();
        let current_snapshot = base_snap_arc.read();

        let mut state_guard = current_snapshot.state.write();
        let mut cloned_state = state_guard.clone();
        drop(state_guard);
        let mut current_block_env = initial_block_env.clone();

        // Structured input generation
        let mut input = EvmInput {
            txs: vec![SingletonTx {
                input: vec![0x00, 0x00, 0x00, 0x00], // Start with a dummy selector
                caller: Default::default(),
                to: Address::random(), // Target a random address for initial exploration
                value: Default::default(),
            }],
            base_snapshot_id: base_id,
        };
        
        let mut dummy_state = libafl::state::StdState::new(rand.clone(), libafl::corpus::InMemoryCorpus::new(), libafl::corpus::InMemoryCorpus::new(), &mut (), &mut ()).unwrap();
        mutator.mutate(&mut dummy_state, &mut input, 0).unwrap();

        // Execute the sequence
        let mut last_snapshot = current_snapshot.clone();
        for tx in &input.txs {
            let mut tx_coverage = last_snapshot.coverage.clone();
            let mut tx_waypoints = Vec::new();
            match evm_executor.execute(&mut cloned_state, &mut current_block_env, tx, tx_coverage.as_mut_bitslice(), &mut dataflow_registry, &mut tx_waypoints) {
                Ok(_) => {
                    let after_snapshot = Snapshot {
                        id: last_snapshot.id + 1,
                        producing_input: Some(input.clone()), // Store the input that led to this state
                        state: Arc::new(RwLock::new(cloned_state.clone())),
                        coverage: tx_coverage,
                        waypoints: tx_waypoints,
                        depth: last_snapshot.depth + 1,
                    };

                    // Discover new contracts from the resulting state
                    account_registry.write().discover_from_state(&cloned_state);

                    for oracle in &oracles {
                        if let Some(vuln_type) = oracle.check(&last_snapshot, &after_snapshot) {
                            log::error!("VULN DISCOVERED IN SEQUENCE: {:?} at depth {}", vuln_type, after_snapshot.depth);
                            
                            // Generate hardware-backed proof of discovery
                            let mut mrenclave = None;
                            if let Ok(report) = sgx_executor.generate_attestation_report(format!("{:?}", vuln_type).as_bytes()) {
                                log::info!("SGX Attestation generated for exploit. MRENCLAVE: {:?}", report.enclave_identity);
                                mrenclave = Some(report.enclave_identity);
                            }

                            // Generate a signed Proof-of-Concept for the finding
                            let poc = after_snapshot.producing_input.as_ref().map(|input| {
                                synthesize_poc(input, &vuln_type)
                            });

                            // Dispatch remote notification
                            #[cfg(feature = "notifier")]
                            let _ = notifier.notify_discovery(&vuln_type, &after_snapshot, mrenclave.as_deref(), poc).await;

                            // Industry grade: Trigger the Minimizer to refine the sequence
                        }
                    }
                    last_snapshot = after_snapshot;
                }
                Err(_) => break, // If a step reverts, the sequence is broken
            }
        }

        // Update corpus metadata with final results of the sequence
        {
            let final_cov = last_snapshot.coverage.count_ones();
            // In a real multi-step execution, we'd aggregate read/write sets across the sequence
            snapshot_corpus.write().update_metadata(
                base_id, 
                final_cov, 
                HashSet::new(), // Placeholder: pass aggregated sets
                HashSet::new()
            );
        }

        // Periodically minimize the corpus to keep the snapshot tree clean
        if i > 0 && i % 500 == 0 {
            let kept_ids = CorpusMinimizer::minimize(&snapshot_corpus.read());
            snapshot_corpus.write().retain(&kept_ids);
        }
    }

    println!("RustyFuzz campaign finished.");

    Ok(())
}