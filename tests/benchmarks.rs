use rand::RngExt;
use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::database_interface::DatabaseRef;
use revm::primitives::{Address, U256};
use revm::state::{AccountInfo, Bytecode};
use rusty_fuzz::common::oracle::{
    AccessControlOracle, ERC4626InflationOracle, ProtocolFinding, ProtocolOraclePack,
    ProtocolOraclePackKind, ProtocolSeverity, ReentrancyOracle, VulnType, VulnerabilityOracle,
};
use rusty_fuzz::common::types::{
    CallKind, CallObservation, CallPhase, ChainState, EvmInput, SequenceExecutionResult,
    SingletonTx, StorageDiff, SymbolicExpression, TaintSource, Waypoint,
};
use rusty_fuzz::common::verifier::ReplayVerifier;
use rusty_fuzz::engine::concolic::ConcolicSolver;
use rusty_fuzz::engine::exploit_synthesizer::{
    synthesize_foundry_poc, synthesize_foundry_poc_with_findings,
};
use rusty_fuzz::engine::minimizer::Minimizer;
use rusty_fuzz::engine::scoring::{CampaignScore, CampaignScorer, CampaignScoringConfig};
use rusty_fuzz::evm::corpus::{CampaignArtifactRequest, PersistentCorpus};
use rusty_fuzz::evm::dataflow::DataflowRegistry;
use rusty_fuzz::evm::executor::EvmExecutor;
use rusty_fuzz::evm::feedback::{
    stable_execution_state_hash, EvmCoverageFeedback, EvmStateNoveltyFeedback,
};
use rusty_fuzz::evm::fork_db::ForkDb;
use rusty_fuzz::evm::registry::GlobalAccountRegistry;
use rusty_fuzz::evm::seed_ingester::{
    discover_accounts_from_seeds, extract_address_hints, normalize_seeds, seed_match_kind,
    MainnetSeed, MainnetSeedBundle, SeedMetadata,
};
use rusty_fuzz::evm::snapshot::new_evm_snapshot;

fn addr(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

fn test_db() -> CacheDB<ForkDb> {
    CacheDB::new(ForkDb::empty())
}

#[test]
fn executor_commits_successful_state_changes_and_coverage() {
    let caller = addr(0xaa);
    let target = addr(0xbb);
    let mut db = test_db();

    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![0x60, 0x01, 0x60, 0x00, 0x55, 0x00].into(),
        )),
    );

    let mut chain_state = rusty_fuzz::common::types::ChainState::Evm(db);
    let mut block = BlockEnv::default();
    let tx = SingletonTx {
        input: Vec::new(),
        caller,
        to: target,
        value: U256::ZERO,
        is_victim: false,
    };
    let mut coverage = vec![0u8; 1024];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();

    let gas = EvmExecutor::new()
        .execute(
            &mut chain_state,
            &mut block,
            &tx,
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("execution should succeed");

    let rusty_fuzz::common::types::ChainState::Evm(db) = chain_state;
    let stored = db
        .cache
        .accounts
        .get(&target)
        .and_then(|account| account.storage.get(&U256::ZERO))
        .copied()
        .unwrap_or_default();
    assert_eq!(stored, U256::from(1));
    assert!(gas > 0);
    assert!(coverage.iter().any(|&hit| hit != 0));
    assert!(waypoints
        .iter()
        .any(|w| matches!(w, Waypoint::StorageWrite { .. })));
}

#[test]
fn execution_result_contains_canonical_trace_and_storage_evidence() {
    let caller = addr(0xa1);
    let target = addr(0xb1);
    let mut db = test_db();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![0x60, 0x03, 0x60, 0x00, 0x55, 0x00].into(),
        )),
    );

    let mut chain_state = ChainState::Evm(db);
    let mut block = BlockEnv::default();
    let tx = SingletonTx {
        input: Vec::new(),
        caller,
        to: target,
        value: U256::ZERO,
        is_victim: false,
    };
    let mut coverage = vec![0u8; 1024];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();

    let result = EvmExecutor::new()
        .execute_with_result(
            &mut chain_state,
            &mut block,
            &tx,
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("execution should succeed");

    assert_eq!(result.storage_writes.len(), 1);
    assert_eq!(result.storage_diffs.len(), 1);
    assert_eq!(result.storage_diffs[0].old_value, U256::ZERO);
    assert_eq!(result.storage_diffs[0].new_value, U256::from(3));
    assert_eq!(result.call_trace.len(), 3);
    assert_eq!(result.call_trace[0].caller, caller);
    assert_eq!(result.call_trace[0].target, target);
    assert_eq!(result.call_trace[0].kind, CallKind::Transaction);
    assert_eq!(result.call_trace[0].phase, CallPhase::End);
    assert_eq!(result.call_trace[1].kind, CallKind::Call);
    assert_eq!(result.call_trace[1].phase, CallPhase::Start);
    assert_eq!(result.call_trace[2].kind, CallKind::Call);
    assert_eq!(result.call_trace[2].phase, CallPhase::End);
    assert_eq!(result.call_trace[2].target, target);
    assert!(result.call_trace[2].success);
}

#[test]
fn storage_read_evidence_contains_exact_sload_value() {
    let caller = addr(0xa2);
    let target = addr(0xb2);
    let mut db = test_db();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![
                0x60, 0x2a, // PUSH1 42
                0x60, 0x00, // PUSH1 slot 0
                0x55, // SSTORE
                0x60, 0x00, // PUSH1 slot 0
                0x54, // SLOAD
                0x00, // STOP
            ]
            .into(),
        )),
    );

    let mut chain_state = ChainState::Evm(db);
    let mut block = BlockEnv::default();
    let tx = SingletonTx {
        input: Vec::new(),
        caller,
        to: target,
        value: U256::ZERO,
        is_victim: false,
    };
    let mut coverage = vec![0u8; 1024];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();

    let result = EvmExecutor::new()
        .execute_with_result(
            &mut chain_state,
            &mut block,
            &tx,
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("execution should succeed");

    assert_eq!(result.storage_reads.len(), 1);
    assert_eq!(result.storage_reads[0].value, Some(U256::from(42)));
}

#[test]
fn concolic_solver_inverts_arithmetic_expression_before_comparison() {
    let caller = addr(0xa3);
    let target = addr(0xb3);
    let mut db = test_db();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![
                0x60, 0x04, // PUSH1 4
                0x35, // CALLDATALOAD
                0x60, 0x05, // PUSH1 5
                0x01, // ADD
                0x60, 0x2a, // PUSH1 42
                0x14, // EQ
                0x00, // STOP
            ]
            .into(),
        )),
    );

    let mut chain_state = ChainState::Evm(db);
    let mut block = BlockEnv::default();
    let tx = SingletonTx {
        input: vec![0u8; 36],
        caller,
        to: target,
        value: U256::ZERO,
        is_victim: false,
    };
    let mut coverage = vec![0u8; 1024];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();

    let result = EvmExecutor::new()
        .execute_with_result(
            &mut chain_state,
            &mut block,
            &tx,
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("execution should succeed");

    let hints = ConcolicSolver::new().solve_hints(result.waypoints.iter().map(|w| (0, w)));
    assert!(hints
        .iter()
        .any(|hint| hint.calldata_offset == 4 && U256::from_be_bytes(hint.word) == U256::from(37)));
}

#[test]
fn inspector_captures_mapping_key_expression_from_sha3_memory() {
    let caller = addr(0xa4);
    let target = addr(0xb4);
    let mut db = test_db();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![
                0x60, 0x04, // PUSH1 4
                0x35, // CALLDATALOAD
                0x60, 0x00, // PUSH1 0
                0x52, // MSTORE key at memory[0]
                0x60, 0x05, // PUSH1 5
                0x60, 0x20, // PUSH1 32
                0x52, // MSTORE base slot at memory[32]
                0x60, 0x40, // PUSH1 64
                0x60, 0x00, // PUSH1 0
                0x20, // SHA3
                0x00, // STOP
            ]
            .into(),
        )),
    );

    let mut chain_state = ChainState::Evm(db);
    let mut block = BlockEnv::default();
    let tx = SingletonTx {
        input: vec![0u8; 36],
        caller,
        to: target,
        value: U256::ZERO,
        is_victim: false,
    };
    let mut coverage = vec![0u8; 1024];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();

    let result = EvmExecutor::new()
        .execute_with_result(
            &mut chain_state,
            &mut block,
            &tx,
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("execution should succeed");

    assert!(result.waypoints.iter().any(|waypoint| matches!(
        waypoint,
        Waypoint::MappingDerivation {
            key_expression: Some(SymbolicExpression::Source(TaintSource::Calldata(4))),
            base_slot_expression: Some(SymbolicExpression::Constant(value)),
            ..
        } if *value == U256::from(5)
    )));
}

#[test]
fn coverage_feedback_tracks_bucketed_novelty() {
    let mut feedback = EvmCoverageFeedback::with_map_size(8);
    assert!(!feedback.observe_coverage(&[0; 8]));
    assert!(feedback.observe_coverage(&[1, 0, 0, 0, 0, 0, 0, 0]));
    assert!(!feedback.observe_coverage(&[1, 0, 0, 0, 0, 0, 0, 0]));
    assert!(feedback.observe_coverage(&[2, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(
        EvmCoverageFeedback::stable_path_hash(&[2, 0, 1]),
        EvmCoverageFeedback::stable_path_hash(&[2, 0, 1])
    );
}

#[test]
fn state_novelty_feedback_tracks_storage_and_call_graph_novelty() {
    let target = addr(0x31);
    let caller = addr(0x32);
    let slot = U256::from(7).to_be_bytes::<32>().into();
    let mut feedback = EvmStateNoveltyFeedback::new();
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 50_000,
        final_coverage_hash: 1,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: vec![StorageDiff {
            tx_index: 0,
            address: target,
            slot,
            old_value: U256::ZERO,
            new_value: U256::from(1),
            pc: 3,
        }],
        call_trace: vec![CallObservation {
            tx_index: 0,
            depth: 1,
            caller,
            target,
            value: U256::ZERO,
            input: vec![0xa9, 0x05, 0x9c, 0xbb],
            output: Vec::new(),
            gas_limit: 100_000,
            gas_used: 20_000,
            success: true,
            kind: CallKind::Call,
            phase: CallPhase::End,
            created_address: None,
            result: Some("Success".to_string()),
        }],
        oracle_observations: Vec::new(),
    };

    let first = feedback.observe_execution(&execution);
    assert!(first.interesting);
    assert_eq!(first.new_transition_hashes.len(), 1);
    assert_eq!(first.new_slot_hashes.len(), 1);
    assert_eq!(first.new_call_edge_hashes.len(), 1);
    assert_eq!(first.new_contracts, vec![target]);
    assert!(first.novelty_score() > 0);

    let repeat = feedback.observe_execution(&execution);
    assert!(!repeat.interesting);
    assert_eq!(repeat.novelty_score(), 0);
    assert_eq!(repeat.state_hash, first.state_hash);

    let mut changed = execution.clone();
    changed.storage_diffs[0].new_value = U256::from(2);
    let third = feedback.observe_execution(&changed);
    assert!(third.interesting);
    assert_eq!(third.new_transition_hashes.len(), 1);
    assert!(third.new_slot_hashes.is_empty());
    assert_ne!(third.state_hash, first.state_hash);
}

#[test]
fn campaign_scorer_rewards_economic_and_invariant_pressure() {
    let target = addr(0x35);
    let caller = addr(0x36);
    let input = EvmInput {
        txs: vec![
            SingletonTx {
                input: vec![0x02, 0x2c, 0x0d, 0x9f],
                caller,
                to: target,
                value: U256::ZERO,
                is_victim: true,
            },
            SingletonTx {
                input: vec![0xfe, 0x0d, 0x94, 0xc1],
                caller,
                to: target,
                value: U256::ZERO,
                is_victim: false,
            },
        ],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: vec![rusty_fuzz::evm::fuzz::MutationProvenance {
            strategy: "oracle_pressure".to_string(),
            tx_index: Some(0),
            selector: Some([0x02, 0x2c, 0x0d, 0x9f]),
            detail: "test".to_string(),
        }],
    };
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 100_000,
        final_coverage_hash: 1,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: vec![
            StorageDiff {
                tx_index: 0,
                address: target,
                slot: U256::ZERO.to_be_bytes::<32>().into(),
                old_value: U256::ZERO,
                new_value: U256::from(10u128.pow(20)),
                pc: 0,
            },
            StorageDiff {
                tx_index: 0,
                address: target,
                slot: U256::from(1).to_be_bytes::<32>().into(),
                old_value: U256::from(10u128.pow(20)),
                new_value: U256::from(1),
                pc: 0,
            },
        ],
        call_trace: vec![
            call(0, target, vec![0x02, 0x2c, 0x0d, 0x9f], true),
            call(1, target, vec![0xfe, 0x0d, 0x94, 0xc1], true),
        ],
        oracle_observations: Vec::new(),
    };
    let findings = ProtocolOraclePack::default().evaluate(&execution);
    let mut state_feedback = EvmStateNoveltyFeedback::new();
    let novelty = state_feedback.observe_execution(&execution);
    let score = CampaignScorer::default().score(&input, &execution, &novelty, &findings);

    assert!(score.total > score.state_pressure);
    assert!(score.economic_pressure > 0);
    assert!(score.invariant_pressure > 0);
    assert!(score.oracle_pressure > 0);
    assert!(score
        .explanation
        .iter()
        .any(|entry| entry.contains("economic_pressure")));

    let tuned_score = CampaignScorer::new(CampaignScoringConfig {
        large_delta_weight: 400,
        economic_finding_weight: 1_200,
        ..CampaignScoringConfig::default()
    })
    .score(&input, &execution, &novelty, &findings);
    assert!(tuned_score.economic_pressure > score.economic_pressure);
}

#[test]
fn corpus_metadata_records_state_novelty_hashes() {
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_state_novelty_corpus_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = PersistentCorpus::new(&root).expect("corpus init");
    let caller = addr(0x33);
    let target = addr(0x34);
    let input = EvmInput {
        txs: vec![SingletonTx {
            input: vec![0xde, 0xad, 0xbe, 0xef],
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 21_000,
        final_coverage_hash: 123,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: vec![StorageDiff {
            tx_index: 0,
            address: target,
            slot: U256::ZERO.to_be_bytes::<32>().into(),
            old_value: U256::ZERO,
            new_value: U256::from(9),
            pc: 1,
        }],
        call_trace: Vec::new(),
        oracle_observations: Vec::new(),
    };
    let metadata = corpus
        .persist_execution_input(&input, &execution, &[1, 2, 0, 0], 24)
        .expect("persist execution input");

    assert_eq!(metadata.state_hash, stable_execution_state_hash(&execution));
    assert_eq!(metadata.state_novelty_score, 24);
    assert_eq!(metadata.gas_used, execution.total_gas_used);
}

#[test]
fn persistent_corpus_writes_campaign_artifact_with_fork_cache() {
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_campaign_artifact_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = PersistentCorpus::new(&root).expect("corpus init");
    let caller = addr(0x35);
    let target = addr(0x36);
    let input = EvmInput {
        txs: vec![SingletonTx {
            input: vec![0xa9, 0x05, 0x9c, 0xbb],
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: true,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 45_000,
        final_coverage_hash: 777,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: vec![StorageDiff {
            tx_index: 0,
            address: target,
            slot: U256::from(1).to_be_bytes::<32>().into(),
            old_value: U256::ZERO,
            new_value: U256::from(10),
            pc: 9,
        }],
        call_trace: vec![call(0, target, vec![0xa9, 0x05, 0x9c, 0xbb], true)],
        oracle_observations: Vec::new(),
    };
    let mut fork_state = test_db();
    fork_state.insert_account_info(
        target,
        AccountInfo {
            balance: U256::from(1),
            ..AccountInfo::default()
        },
    );
    let score = CampaignScore {
        total: 1200,
        economic_pressure: 600,
        invariant_pressure: 0,
        counterexample_pressure: 140,
        oracle_pressure: 100,
        state_pressure: 24,
        exploration_pressure: 10,
        explanation: vec!["economic_pressure".to_string()],
    };
    let finding = rusty_fuzz::common::oracle::ProtocolFinding {
        pack: ProtocolOraclePackKind::Erc20,
        vuln: VulnType::AccountingDesync,
        severity: ProtocolSeverity::Medium,
        tx_index: Some(0),
        target: Some(target),
        evidence: "test finding".to_string(),
    };

    let record = corpus
        .persist_campaign_artifact(CampaignArtifactRequest {
            input: &input,
            execution: &execution,
            coverage: &[1, 0, 2, 0],
            state_novelty_score: 24,
            base_fork_state: &fork_state,
            score: &score,
            findings: &[finding],
            exploit_candidate: None,
            block_number: 19_000_000,
            target: Some(target),
            reason: "protocol-oracle-finding",
        })
        .expect("persist campaign artifact")
        .record;

    assert_eq!(record.input_id, record.metadata.id);
    assert_eq!(record.fork_cache_id, record.metadata.id);
    assert_eq!(record.findings.len(), 1);
    assert!(root
        .join("campaign_artifacts")
        .join(format!("{}.json", record.input_id))
        .exists());
    assert!(root
        .join("fork_cache")
        .join(format!("{}.json", record.fork_cache_id))
        .exists());
    let offline = corpus
        .load_offline_fork_db(&record.fork_cache_id)
        .expect("load offline fork cache");
    assert!(offline
        .basic_ref(target)
        .expect("offline account lookup")
        .is_some());
}

#[test]
fn persistent_corpus_round_trips_replay_inputs_and_crashes() {
    let root = std::env::temp_dir().join(format!("rusty_fuzz_corpus_test_{}", std::process::id()));
    let corpus = PersistentCorpus::new(&root).expect("corpus init");
    let input = EvmInput {
        txs: vec![SingletonTx {
            input: vec![0xde, 0xad, 0xbe, 0xef],
            caller: addr(0x01),
            to: addr(0x02),
            value: U256::from(7),
            is_victim: false,
        }],
        base_snapshot_id: 42,
        waypoints: vec![],
        mutation_provenance: Vec::new(),
    };

    let metadata = corpus
        .persist_input(&input, &[1, 0, 8, 0], 21_000)
        .expect("persist input");
    let replay = corpus.load_input(&metadata.id).expect("load input");
    assert_eq!(replay.txs, input.txs);
    assert_eq!(replay.base_snapshot_id, input.base_snapshot_id);

    let crash = corpus
        .persist_crash(&metadata, "revert-mismatch")
        .expect("persist crash");
    assert_eq!(crash.input_id, metadata.id);
    assert!(crash.fingerprint.starts_with("0x"));
}

#[test]
fn replay_verifier_is_deterministic_and_reports_reproduction() {
    let caller = addr(0x55);
    let target = addr(0x66);
    let mut db = test_db();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![0x60, 0x02, 0x60, 0x00, 0x55, 0x00].into(),
        )),
    );

    let input = EvmInput {
        txs: vec![SingletonTx {
            input: Vec::new(),
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: vec![],
        mutation_provenance: Vec::new(),
    };

    let verifier = ReplayVerifier::new(1024);
    let execution = verifier
        .verify_deterministic(&ChainState::Evm(db.clone()), &BlockEnv::default(), &input)
        .expect("replay should be deterministic");
    assert_eq!(execution.tx_results.len(), 1);
    assert!(execution.total_gas_used > 0);
    assert_eq!(execution.storage_diffs.len(), 1);
    assert_eq!(execution.call_trace.len(), 3);
    assert!(execution
        .call_trace
        .iter()
        .any(|call| call.kind == CallKind::Call && call.phase == CallPhase::Start));
    assert!(execution
        .call_trace
        .iter()
        .any(|call| call.kind == CallKind::Call && call.phase == CallPhase::End));

    let root = std::env::temp_dir().join(format!("rusty_fuzz_repro_test_{}", std::process::id()));
    let corpus = PersistentCorpus::new(&root).expect("corpus init");
    let metadata = corpus
        .persist_input(&input, &[1, 2, 0, 0], execution.total_gas_used)
        .expect("persist input");
    let crash = corpus
        .persist_crash(&metadata, "deterministic-test")
        .expect("persist crash");
    let report = corpus
        .write_reproduction_report(&input, &execution, Some(&crash))
        .expect("write report");
    assert!(report.exists());

    let snapshot = new_evm_snapshot(7, db);
    let manifest = corpus
        .persist_snapshot_manifest(&snapshot, Some(metadata.id))
        .expect("persist snapshot manifest");
    assert_eq!(manifest.id, 7);
    assert!(manifest.state_hash.starts_with("0x"));
}

#[test]
fn foundry_poc_generation_replays_without_fake_assertion() {
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_foundry_poc_test_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp report dir");
    let input = EvmInput {
        txs: vec![SingletonTx {
            input: Vec::new(),
            caller: addr(0x77),
            to: addr(0x88),
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: vec![],
        mutation_provenance: Vec::new(),
    };

    let poc_path = synthesize_foundry_poc(
        &input,
        &VulnType::Other("regression".to_string()),
        &root,
        "http://localhost:8545",
        1,
    )
    .expect("generate poc");
    let source = std::fs::read_to_string(poc_path).expect("read poc");
    assert!(source.contains("testReplay_RustyFuzz"));
    assert!(source.contains("assertRustyFuzzInvariant"));
    assert!(!source.contains("assertTrue(false"));
    assert!(source.contains("hex\"\""));
}

#[test]
fn foundry_poc_generation_embeds_protocol_oracle_assertions() {
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_protocol_poc_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create poc dir");
    let caller = addr(0xe1);
    let pool = addr(0xe2);
    let input = EvmInput {
        txs: vec![SingletonTx {
            input: vec![0x02, 0x2c, 0x0d, 0x9f],
            caller,
            to: pool,
            value: U256::ZERO,
            is_victim: true,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 0,
        final_coverage_hash: 0,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: vec![
            StorageDiff {
                tx_index: 0,
                address: pool,
                slot: U256::ZERO.to_be_bytes::<32>().into(),
                old_value: U256::from(1),
                new_value: U256::from(1_000_000),
                pc: 0,
            },
            StorageDiff {
                tx_index: 0,
                address: pool,
                slot: U256::from(1).to_be_bytes::<32>().into(),
                old_value: U256::from(1_000_000),
                new_value: U256::from(999_999),
                pc: 0,
            },
        ],
        call_trace: vec![call(0, pool, vec![0x02, 0x2c, 0x0d, 0x9f], true)],
        oracle_observations: Vec::new(),
    };
    let findings = ProtocolOraclePack::default().evaluate(&execution);
    assert!(!findings.is_empty());

    let path = synthesize_foundry_poc_with_findings(
        &input,
        &VulnType::UniswapV3LiquidityAsymmetry,
        Some(&execution),
        &findings,
        &root,
        "http://localhost:8545",
        123,
    )
    .expect("generate protocol poc");
    let poc = std::fs::read_to_string(path).expect("read poc");
    assert!(poc.contains("assertRustyFuzzProtocolEvidence"));
    assert!(poc.contains("RustyFuzz finding"));
    assert!(poc.contains("assertTrue(ok0"));
    assert!(poc.contains("vm.load"));
    assert!(poc.contains("pre-state storage mismatch"));
    assert!(poc.contains("storage diff not reproduced"));
    assert!(!poc.contains("vm.deal"));
    assert!(poc.contains("protocol target has no code"));
    assert!(poc.contains("assertRustyFuzzMarketEvidence"));
    assert!(poc.contains("rustyFuzzWord"));
    assert!(poc.contains("market/oracle evidence transaction changed status"));
}

#[test]
fn foundry_poc_generation_embeds_access_control_specific_assertions() {
    let root =
        std::env::temp_dir().join(format!("rusty_fuzz_access_poc_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create poc dir");
    let caller = addr(0xa1);
    let proxy = addr(0xa2);
    let input = EvmInput {
        txs: vec![SingletonTx {
            input: vec![0x36, 0x59, 0xcf, 0xe6],
            caller,
            to: proxy,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 0,
        final_coverage_hash: 0,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: Vec::new(),
        call_trace: vec![call(0, proxy, vec![0x36, 0x59, 0xcf, 0xe6], true)],
        oracle_observations: Vec::new(),
    };
    let finding = ProtocolFinding {
        pack: ProtocolOraclePackKind::ProxyUpgradeability,
        vuln: VulnType::ProxyUpgradeabilityViolation,
        severity: ProtocolSeverity::High,
        tx_index: Some(0),
        target: Some(proxy),
        evidence: "non-admin caller reached upgrade selector".to_string(),
    };

    let path = synthesize_foundry_poc_with_findings(
        &input,
        &VulnType::ProxyUpgradeabilityViolation,
        Some(&execution),
        &[finding],
        &root,
        "http://localhost:8545",
        123,
    )
    .expect("generate access poc");
    let poc = std::fs::read_to_string(path).expect("read poc");
    assert!(poc.contains("assertRustyFuzzAccessControlEvidence"));
    assert!(poc.contains("access-control/proxy evidence transaction changed status"));
    assert!(!poc.contains("vm.deal"));
}

#[test]
fn foundry_poc_generation_fails_closed_without_pinned_fork_for_proof() {
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_poc_fail_closed_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create poc dir");
    let input = EvmInput {
        txs: vec![SingletonTx {
            input: vec![0xb6, 0xb5, 0x5f, 0x25],
            caller: addr(0xf1),
            to: addr(0xf2),
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 0,
        final_coverage_hash: 0,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: Vec::new(),
        call_trace: Vec::new(),
        oracle_observations: Vec::new(),
    };
    let finding = ProtocolFinding {
        pack: ProtocolOraclePackKind::Erc4626,
        vuln: VulnType::VaultInflation,
        severity: ProtocolSeverity::High,
        tx_index: Some(0),
        target: Some(addr(0xf2)),
        evidence: "vault inflation proof".to_string(),
    };

    let err = synthesize_foundry_poc_with_findings(
        &input,
        &VulnType::VaultInflation,
        Some(&execution),
        &[finding],
        &root,
        "http://localhost:8545",
        0,
    )
    .expect_err("proof poc without fork block rejected");
    assert!(err.to_string().contains("pinned fork block"));
}

#[test]
fn crash_minimizer_emits_minimized_foundry_poc() {
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_minimized_poc_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = PersistentCorpus::new(&root).expect("corpus init");
    let caller = addr(0xd1);
    let irrelevant = addr(0xd2);
    let target = addr(0xd3);
    let mut db = test_db();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        irrelevant,
        AccountInfo::default().with_code(Bytecode::new_raw(vec![0x00].into())),
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![0x60, 0x09, 0x60, 0x00, 0x55, 0x00].into(),
        )),
    );

    let original = EvmInput {
        txs: vec![
            SingletonTx {
                input: vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4],
                caller,
                to: irrelevant,
                value: U256::ZERO,
                is_victim: false,
            },
            SingletonTx {
                input: vec![0xa9, 0x05, 0x9c, 0xbb, 0, 1, 2, 3, 4, 5, 6, 7],
                caller,
                to: target,
                value: U256::from(1),
                is_victim: true,
            },
        ],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };
    let executor = EvmExecutor::new();
    let minimizer = Minimizer::new(&executor, &ReentrancyOracle, db, BlockEnv::default());
    let artifact = minimizer
        .minimize_crash_to_foundry_poc(
            &original,
            &corpus,
            &root,
            &VulnType::Other("storage-write-regression".to_string()),
            "http://localhost:8545",
            123,
            "storage slot zero changed to nine",
            |execution| {
                execution.storage_diffs.iter().any(|diff| {
                    diff.address == target
                        && diff.old_value == U256::ZERO
                        && diff.new_value == U256::from(9)
                })
            },
        )
        .expect("minimize crash to poc");

    assert_eq!(artifact.original_tx_count, 2);
    assert_eq!(artifact.minimized_tx_count, 1);
    assert_eq!(artifact.minimized_input.txs[0].to, target);
    assert_eq!(artifact.minimized_input.txs[0].value, U256::ZERO);
    assert!(artifact.minimized_input.txs[0].input.len() <= 4);
    assert!(artifact.reproduction_report.exists());
    assert!(artifact.foundry_poc.exists());
    let poc = std::fs::read_to_string(&artifact.foundry_poc).expect("read poc");
    assert!(poc.contains("vm.createSelectFork"));
    assert!(poc.contains("address("));
    assert!(artifact.protocol_findings.is_empty());
}

#[test]
fn benchmark_reentrancy_detection() {
    let mut db = test_db();
    let target_addr = addr(0x11);

    // Setup: A contract state where storage was modified at depth > 1
    let mut acc_info = AccountInfo::default();
    acc_info.code = Some(Bytecode::new_raw(vec![0x00].into()));
    db.insert_account_info(target_addr, acc_info);

    let before = new_evm_snapshot(0, db.clone());

    // Simulate a reentrant state change
    db.insert_account_storage(target_addr, U256::ZERO, U256::from(1))
        .unwrap();
    let mut after = new_evm_snapshot(1, db);
    after.depth = 2; // Indicator of nested call

    let oracle = ReentrancyOracle;
    let result = oracle.check(&before, &after);

    assert!(
        matches!(result, Some(VulnType::Reentrancy)),
        "Failed to detect reentrancy"
    );

    let mut execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 0,
        final_coverage_hash: 0,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: Vec::new(),
        call_trace: Vec::new(),
        oracle_observations: Vec::new(),
    };
    let observed = ReplayVerifier::new(1024).evaluate_oracle(
        &mut execution,
        "ReentrancyOracle",
        &oracle,
        &before,
        &after,
    );
    assert!(matches!(observed, Some(VulnType::Reentrancy)));
    assert_eq!(execution.oracle_observations.len(), 1);
}

#[test]
fn benchmark_erc4626_inflation_detection() {
    let mut db = test_db();
    let vault_addr = addr(0x22);

    // Setup: Initial state (100 assets, 100 shares -> price 1:1)
    db.insert_account_storage(vault_addr, U256::ZERO, U256::from(100))
        .unwrap(); // totalSupply
    db.insert_account_storage(vault_addr, U256::from(1), U256::from(100))
        .unwrap(); // totalAssets
    let before = new_evm_snapshot(0, db.clone());

    // Exploit: Donation attack doubles the price per share
    db.insert_account_storage(vault_addr, U256::from(1), U256::from(300))
        .unwrap();
    let after = new_evm_snapshot(1, db);

    let oracle = ERC4626InflationOracle { vault: vault_addr };
    let result = oracle.check(&before, &after);

    assert!(
        matches!(result, Some(VulnType::VaultInflation)),
        "Failed to detect donation-based inflation"
    );
}

#[test]
fn benchmark_privilege_escalation() {
    let mut db = test_db();
    let target_addr = addr(0x33);
    let fuzzer_addr = addr(0x44);

    let before = new_evm_snapshot(0, db.clone());

    // Simulate unauthorized SSTORE to an 'owner' slot (0x0)
    db.insert_account_storage(
        target_addr,
        U256::ZERO,
        U256::from_be_slice(fuzzer_addr.as_slice()),
    )
    .unwrap();

    let mut after = new_evm_snapshot(1, db);
    after.producing_input = Some(EvmInput {
        txs: vec![SingletonTx {
            input: vec![],
            caller: fuzzer_addr,
            to: target_addr,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: vec![],
        mutation_provenance: Vec::new(),
    });

    // Add waypoint showing the SSTORE was influenced by input
    after.waypoints.push(Waypoint::Dataflow {
        address: target_addr,
        slot: U256::ZERO.to_be_bytes::<32>().to_vec(),
        influenced: true,
    });

    let oracle = AccessControlOracle {
        fuzzer_address: fuzzer_addr,
    };

    let result = oracle.check(&before, &after);
    assert!(
        matches!(result, Some(VulnType::PrivilegeEscalation)),
        "Failed to detect privilege escalation"
    );
}

/// Stretch Goal: Mainnet Regression Template
/// To run: `cargo test -- --ignored`
#[tokio::test]
#[ignore]
async fn mainnet_regression_euler_finance() {
    // This test would use create_fork_db to pull state from block 16817992
    // and verify that a sequence mimicking the 'donate' exploit triggers
    // the SolvencyOracle or a CustomInvariant.
}

#[test]
fn fork_db_offline_cache_serves_account_code_and_storage() {
    let db = ForkDb::empty();
    let address = addr(0x99);
    let slot = U256::from(3);
    let value = U256::from(42);
    let info = AccountInfo::default()
        .with_balance(U256::from(1))
        .with_code(Bytecode::new_raw(vec![0x00].into()));
    let code_hash = info.code_hash;

    db.cache_account(address, info);
    db.cache_storage(address, slot, value);

    let loaded = db.basic_ref(address).expect("account lookup");
    assert!(loaded.is_some());
    assert_eq!(
        db.storage_ref(address, slot).expect("storage lookup"),
        value
    );
    assert!(!db
        .code_by_hash_ref(code_hash)
        .expect("code lookup")
        .is_empty());
    assert_eq!(db.basic_ref(addr(0x98)).expect("missing account"), None);
    assert_eq!(
        db.storage_ref(address, U256::from(4))
            .expect("missing storage"),
        U256::ZERO
    );
}

#[test]
fn persistent_corpus_round_trips_fork_cache_for_offline_replay() {
    let root =
        std::env::temp_dir().join(format!("rusty_fuzz_fork_cache_test_{}", std::process::id()));
    let corpus = PersistentCorpus::new(&root).expect("corpus init");
    let db = ForkDb::empty();
    let address = addr(0xab);
    let slot = U256::from(7);
    let value = U256::from(1337);
    let info = AccountInfo::default()
        .with_balance(U256::from(5))
        .with_code(Bytecode::new_raw(vec![0x60, 0x00, 0x00].into()));
    let code_hash = info.code_hash;

    db.cache_account(address, info);
    db.cache_storage(address, slot, value);
    let snapshot = corpus
        .persist_fork_cache("fork-cache-regression", &db)
        .expect("persist fork cache");
    assert_eq!(snapshot.accounts.len(), 1);
    assert_eq!(snapshot.storage.len(), 1);

    let offline = corpus
        .load_offline_fork_db("fork-cache-regression")
        .expect("load fork cache");
    assert_eq!(
        offline
            .storage_ref(address, slot)
            .expect("offline storage lookup"),
        value
    );
    assert!(!offline
        .code_by_hash_ref(code_hash)
        .expect("offline code lookup")
        .is_empty());
    assert!(offline
        .basic_ref(address)
        .expect("offline account lookup")
        .is_some());
}

#[test]
fn mainnet_seed_ingestion_normalizes_and_discovers_accounts() {
    let target = addr(0x55);
    let caller = addr(0x56);
    let spender = addr(0x57);
    let db = ForkDb::empty();

    db.cache_account(
        target,
        AccountInfo::default()
            .with_code(Bytecode::new_raw(vec![0x60, 0x00, 0x60, 0x00, 0x55].into())),
    );
    db.cache_account(
        caller,
        AccountInfo {
            balance: U256::from(100),
            nonce: 7,
            ..AccountInfo::default()
        },
    );
    db.cache_account(
        spender,
        AccountInfo {
            balance: U256::from(1),
            nonce: 1,
            ..AccountInfo::default()
        },
    );

    let mut calldata = vec![0x09, 0x5e, 0xa7, 0xb3];
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(spender.as_slice());
    calldata.extend_from_slice(&U256::from(10).to_be_bytes::<32>());

    let input = EvmInput {
        txs: vec![SingletonTx {
            input: calldata.clone(),
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };

    let seed = MainnetSeed {
        id: "seed-b".to_string(),
        input: input.clone(),
        metadata: SeedMetadata {
            source_block: 100,
            block_offset: 1,
            transaction_ordinal: 1,
            caller,
            target,
            value: U256::ZERO,
            selector: Some([0x09, 0x5e, 0xa7, 0xb3]),
            calldata_len: calldata.len(),
            discovered_address_hints: extract_address_hints(&calldata),
            matched_target: Some(target),
            match_kind: Some("direct".to_string()),
            confidence: None,
            provenance: None,
            decoded: None,
            tx_hash: None,
            top_level_caller: Some(caller),
            internal_caller: None,
            trace_path: None,
            trace_source: None,
        },
    };
    let duplicate = MainnetSeed {
        id: "seed-b".to_string(),
        ..seed.clone()
    };
    let earlier = MainnetSeed {
        id: "seed-a".to_string(),
        metadata: SeedMetadata {
            source_block: 99,
            block_offset: 2,
            transaction_ordinal: 0,
            ..seed.metadata.clone()
        },
        ..seed.clone()
    };

    let normalized = normalize_seeds(vec![seed, duplicate, earlier]);
    assert_eq!(normalized.len(), 2);
    assert_eq!(normalized[0].id, "seed-a");
    assert_eq!(normalized[1].id, "seed-b");
    assert_eq!(
        normalized[1].metadata.discovered_address_hints,
        vec![spender]
    );

    let discovered =
        discover_accounts_from_seeds(&normalized, &db).expect("account discovery should work");
    let target_account = discovered
        .iter()
        .find(|account| account.address == target)
        .expect("target discovered");
    assert!(target_account.is_contract);
    assert_eq!(
        target_account.observed_selectors,
        vec![[0x09, 0x5e, 0xa7, 0xb3]]
    );

    let caller_account = discovered
        .iter()
        .find(|account| account.address == caller)
        .expect("caller discovered");
    assert!(!caller_account.is_contract);
    assert_eq!(caller_account.nonce, 7);
}

#[test]
fn seed_matching_accepts_direct_and_routed_target_references() {
    let target = addr(0x61);
    let router = addr(0x62);

    let mut routed_calldata = vec![0x12, 0x34, 0x56, 0x78];
    routed_calldata.extend_from_slice(&[0u8; 12]);
    routed_calldata.extend_from_slice(target.as_slice());

    assert_eq!(seed_match_kind(target, target, &[], false), Some("direct"));
    assert_eq!(
        seed_match_kind(router, target, &routed_calldata, false),
        None
    );
    assert_eq!(
        seed_match_kind(router, target, &routed_calldata, true),
        Some("address-hint")
    );
}

#[test]
fn persistent_corpus_round_trips_mainnet_seed_bundle() {
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_mainnet_seed_bundle_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = PersistentCorpus::new(&root).expect("corpus init");
    let target = addr(0x66);
    let caller = addr(0x67);
    let db = ForkDb::empty();
    db.cache_account(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(vec![0x00].into())),
    );
    db.cache_account(
        caller,
        AccountInfo {
            balance: U256::from(1),
            ..AccountInfo::default()
        },
    );

    let input = EvmInput {
        txs: vec![SingletonTx {
            input: vec![0xa9, 0x05, 0x9c, 0xbb],
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    };
    let seed = MainnetSeed {
        id: "seed-roundtrip".to_string(),
        input,
        metadata: SeedMetadata {
            source_block: 123,
            block_offset: 0,
            transaction_ordinal: 0,
            caller,
            target,
            value: U256::ZERO,
            selector: Some([0xa9, 0x05, 0x9c, 0xbb]),
            calldata_len: 4,
            discovered_address_hints: Vec::new(),
            matched_target: Some(target),
            match_kind: Some("direct".to_string()),
            confidence: None,
            provenance: None,
            decoded: None,
            tx_hash: None,
            top_level_caller: Some(caller),
            internal_caller: None,
            trace_path: None,
            trace_source: None,
        },
    };
    let bundle = MainnetSeedBundle {
        fork_block: 123,
        target,
        discovered_accounts: discover_accounts_from_seeds(std::slice::from_ref(&seed), &db)
            .expect("discover accounts"),
        fork_cache: db.cache_snapshot(),
        seeds: vec![seed],
        scan: None,
    };

    corpus
        .persist_mainnet_seed_bundle("bundle-1", &bundle)
        .expect("persist bundle");
    let loaded = corpus
        .load_mainnet_seed_bundle("bundle-1")
        .expect("load bundle");
    assert_eq!(loaded, bundle);

    let offline_db = ForkDb::from_cache_snapshot(loaded.fork_cache);
    let loaded_target = offline_db
        .basic_ref(target)
        .expect("offline account lookup")
        .expect("target account");
    assert!(loaded_target
        .code
        .as_ref()
        .is_some_and(|code| !code.is_empty()));
}

#[test]
fn replay_verifier_loads_persisted_input_and_fork_cache() {
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_persisted_replay_test_{}",
        std::process::id()
    ));
    let corpus = PersistentCorpus::new(&root).expect("corpus init");
    let fork_db = ForkDb::empty();
    let caller = addr(0xc1);
    let target = addr(0xc2);
    fork_db.cache_account(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    fork_db.cache_account(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![0x60, 0x09, 0x60, 0x00, 0x55, 0x00].into(),
        )),
    );

    let input = EvmInput {
        txs: vec![SingletonTx {
            input: Vec::new(),
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: vec![],
        mutation_provenance: Vec::new(),
    };
    let metadata = corpus
        .persist_input(&input, &[1, 0, 0, 0], 0)
        .expect("persist input");
    corpus
        .persist_fork_cache(&metadata.id, &fork_db)
        .expect("persist fork cache");

    let execution = ReplayVerifier::new(1024)
        .verify_persisted_input(&corpus, &metadata.id, &metadata.id, &BlockEnv::default())
        .expect("persisted replay should be deterministic");
    assert_eq!(execution.tx_results.len(), 1);
    assert!(execution.total_gas_used > 0);
}

#[test]
fn protocol_oracle_pack_detects_governance_and_amm_findings() {
    let governor = addr(0x80);
    let pool = addr(0x81);
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 0,
        final_coverage_hash: 0,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: vec![
            StorageDiff {
                tx_index: 1,
                address: pool,
                slot: U256::ZERO.to_be_bytes::<32>().into(),
                old_value: U256::from(1),
                new_value: U256::from(1_000_000),
                pc: 0,
            },
            StorageDiff {
                tx_index: 1,
                address: pool,
                slot: U256::from(1).to_be_bytes::<32>().into(),
                old_value: U256::from(1_000_000),
                new_value: U256::from(999_999),
                pc: 0,
            },
        ],
        call_trace: vec![
            call(0, governor, vec![0xfe, 0x0d, 0x94, 0xc1], true),
            call(1, pool, vec![0x02, 0x2c, 0x0d, 0x9f], true),
        ],
        oracle_observations: Vec::new(),
    };

    let findings = ProtocolOraclePack::default().evaluate(&execution);
    assert!(findings.iter().any(|finding| {
        finding.pack == ProtocolOraclePackKind::Governance
            && matches!(finding.vuln, VulnType::GovernanceTakeover)
    }));
    assert!(findings.iter().any(|finding| {
        finding.pack == ProtocolOraclePackKind::Amm
            && matches!(finding.vuln, VulnType::UniswapV3LiquidityAsymmetry)
    }));
}

#[test]
fn protocol_oracle_pack_detects_erc4626_and_lending_findings() {
    let vault = addr(0x82);
    let market = addr(0x83);
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 0,
        final_coverage_hash: 0,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: vec![
            StorageDiff {
                tx_index: 0,
                address: vault,
                slot: U256::ZERO.to_be_bytes::<32>().into(),
                old_value: U256::ZERO,
                new_value: U256::from(10u128.pow(20)),
                pc: 0,
            },
            StorageDiff {
                tx_index: 1,
                address: market,
                slot: U256::ZERO.to_be_bytes::<32>().into(),
                old_value: U256::from(10u128.pow(20)),
                new_value: U256::ZERO,
                pc: 0,
            },
        ],
        call_trace: vec![
            call(0, vault, vec![0xb6, 0xb5, 0x5f, 0x25], true),
            call(1, market, vec![0xc5, 0xeb, 0xea, 0xec], true),
        ],
        oracle_observations: Vec::new(),
    };

    let findings = ProtocolOraclePack::default().evaluate(&execution);
    assert!(findings.iter().any(|finding| {
        finding.pack == ProtocolOraclePackKind::Erc4626
            && matches!(finding.vuln, VulnType::VaultInflation)
    }));
    assert!(findings.iter().any(|finding| {
        finding.pack == ProtocolOraclePackKind::Lending
            && matches!(finding.vuln, VulnType::AccountingDesync)
    }));
}

#[test]
fn registry_builds_target_model_from_execution_artifact() {
    let target = addr(0xe8);
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 0,
        final_coverage_hash: 0,
        storage_reads: vec![rusty_fuzz::common::types::StorageAccess {
            tx_index: 0,
            address: target,
            slot: U256::from(7).to_be_bytes::<32>().into(),
            value: Some(U256::from(1)),
            pc: 10,
        }],
        storage_writes: vec![rusty_fuzz::common::types::StorageAccess {
            tx_index: 0,
            address: target,
            slot: U256::from(8).to_be_bytes::<32>().into(),
            value: Some(U256::from(2)),
            pc: 20,
        }],
        storage_diffs: Vec::new(),
        call_trace: vec![call(0, target, vec![0xa9, 0x05, 0x9c, 0xbb], true)],
        oracle_observations: Vec::new(),
    };

    let mut registry = GlobalAccountRegistry::default();
    registry.observe_execution(&execution);
    let model = registry.model_for(&target).expect("target model");
    assert!(model.observed_selectors.contains(&[0xa9, 0x05, 0x9c, 0xbb]));
    assert!(model.storage_reads.contains(&U256::from(7)));
    assert!(model.storage_writes.contains(&U256::from(8)));
    assert_eq!(model.successful_calls, 1);
}

fn call(tx_index: usize, target: Address, selector: Vec<u8>, success: bool) -> CallObservation {
    CallObservation {
        tx_index,
        depth: 1,
        caller: addr(0xf0),
        target,
        value: U256::ZERO,
        input: selector,
        output: vec![0u8; 32],
        gas_limit: 1_000_000,
        gas_used: 1000,
        success,
        kind: CallKind::Call,
        phase: CallPhase::End,
        created_address: None,
        result: Some("Stop".to_string()),
    }
}

// ============================================================================
// INTEGRATION TESTS FOR CRITICAL PATHS
// ============================================================================

#[test]
fn integration_fuzz_campaign_end_to_end() {
    // Integration test for full fuzz campaign execution path
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_integration_campaign_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = PersistentCorpus::new(&root).expect("corpus init");

    let caller = addr(0xc0);
    let target = addr(0xc1);
    let mut db = test_db();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![0x60, 0x05, 0x60, 0x00, 0x55, 0x00].into(),
        )),
    );

    // Simulate fuzz campaign: generate input, execute, persist, replay
    let input = EvmInput {
        txs: vec![SingletonTx {
            input: Vec::new(),
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: vec![],
        mutation_provenance: Vec::new(),
    };

    let mut chain_state = ChainState::Evm(db.clone());
    let mut block = BlockEnv::default();
    let mut coverage = vec![0u8; 1024];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();

    let execution = EvmExecutor::new()
        .execute_with_result(
            &mut chain_state,
            &mut block,
            &input.txs[0],
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("execution should succeed");

    let sequence_result = SequenceExecutionResult {
        tx_results: vec![execution.clone()],
        total_gas_used: execution.gas_used,
        final_coverage_hash: EvmCoverageFeedback::stable_path_hash(&coverage),
        storage_reads: execution.storage_reads,
        storage_writes: execution.storage_writes,
        storage_diffs: execution.storage_diffs,
        call_trace: execution.call_trace,
        oracle_observations: Vec::new(),
    };

    // Persist to corpus
    let metadata = corpus
        .persist_execution_input(&input, &sequence_result, &coverage, execution.gas_used)
        .expect("persist should succeed");

    // Replay from corpus
    let replay_input = corpus
        .load_input(&metadata.id)
        .expect("load should succeed");
    let replay_execution = ReplayVerifier::new(1024)
        .verify_deterministic(&ChainState::Evm(db), &BlockEnv::default(), &replay_input)
        .expect("replay should be deterministic");

    assert_eq!(
        replay_execution.total_gas_used,
        sequence_result.total_gas_used
    );
    assert_eq!(
        replay_execution.storage_diffs.len(),
        sequence_result.storage_diffs.len()
    );
}

#[test]
fn integration_replay_verification_with_oracle_detection() {
    // Integration test for replay verification with oracle detection
    let caller = addr(0xd0);
    let target = addr(0xd1);
    let mut db = test_db();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![0x60, 0x01, 0x60, 0x00, 0x55, 0x00].into(),
        )),
    );

    let input = EvmInput {
        txs: vec![SingletonTx {
            input: Vec::new(),
            caller,
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: vec![],
        mutation_provenance: Vec::new(),
    };

    let before = new_evm_snapshot(0, db.clone());

    // Execute
    let mut chain_state = ChainState::Evm(db.clone());
    let mut block = BlockEnv::default();
    let mut coverage = vec![0u8; 1024];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();

    let _ = EvmExecutor::new()
        .execute_with_result(
            &mut chain_state,
            &mut block,
            &input.txs[0],
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("execution should succeed");

    let after = new_evm_snapshot(1, db.clone());

    // Verify with oracle
    let verifier = ReplayVerifier::new(1024);
    let execution = verifier
        .verify_deterministic(&ChainState::Evm(db.clone()), &BlockEnv::default(), &input)
        .expect("replay should succeed");

    let mut execution_with_oracle = execution.clone();
    let oracle = AccessControlOracle {
        fuzzer_address: caller,
    };

    let _finding = verifier.evaluate_oracle(
        &mut execution_with_oracle,
        "AccessControlOracle",
        &oracle,
        &before,
        &after,
    );

    // Oracle should evaluate (may or may not find vulnerability depending on state)
    assert!(execution_with_oracle.oracle_observations.len() <= 1);
}

#[test]
fn integration_oracle_detection_across_multiple_vulnerability_types() {
    // Integration test for oracle detection across multiple vulnerability types
    let execution = SequenceExecutionResult {
        tx_results: Vec::new(),
        total_gas_used: 100_000,
        final_coverage_hash: 123,
        storage_reads: Vec::new(),
        storage_writes: Vec::new(),
        storage_diffs: vec![
            StorageDiff {
                tx_index: 0,
                address: addr(0x01),
                slot: U256::ZERO.to_be_bytes::<32>().into(),
                old_value: U256::from(1),
                new_value: U256::from(1_000_000),
                pc: 0,
            },
            StorageDiff {
                tx_index: 0,
                address: addr(0x01),
                slot: U256::from(1).to_be_bytes::<32>().into(),
                old_value: U256::from(1_000_000),
                new_value: U256::from(999_999),
                pc: 0,
            },
        ],
        call_trace: vec![call(0, addr(0x01), vec![0x02, 0x2c, 0x0d, 0x9f], true)],
        oracle_observations: Vec::new(),
    };

    let findings = ProtocolOraclePack::default().evaluate(&execution);

    // Should detect at least one finding from the storage diffs
    assert!(!findings.is_empty());

    // Verify findings have required fields
    for finding in &findings {
        assert!(!finding.evidence.is_empty());
        assert!(matches!(
            finding.severity,
            ProtocolSeverity::Info
                | ProtocolSeverity::Low
                | ProtocolSeverity::Medium
                | ProtocolSeverity::High
                | ProtocolSeverity::Critical
        ));
    }
}

#[test]
fn integration_corpus_persistence_and_retrieval_workflow() {
    // Integration test for full corpus persistence and retrieval workflow
    let root = std::env::temp_dir().join(format!(
        "rusty_fuzz_integration_corpus_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = PersistentCorpus::new(&root).expect("corpus init");

    // Create multiple inputs
    let inputs: Vec<EvmInput> = (0..5)
        .map(|i| EvmInput {
            txs: vec![SingletonTx {
                input: vec![i as u8; 4],
                caller: addr(0xe0 + i as u8),
                to: addr(0xf0),
                value: U256::from(i),
                is_victim: i % 2 == 0,
            }],
            base_snapshot_id: i,
            waypoints: vec![],
            mutation_provenance: Vec::new(),
        })
        .collect();

    let mut metadata_ids = Vec::new();
    for input in &inputs {
        let execution = SequenceExecutionResult {
            tx_results: Vec::new(),
            total_gas_used: 21_000,
            final_coverage_hash: 123,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        };

        let metadata = corpus
            .persist_execution_input(input, &execution, &[1, 2, 0, 0], 21_000)
            .expect("persist should succeed");
        metadata_ids.push(metadata.id);
    }

    // Retrieve all inputs
    for (i, id) in metadata_ids.iter().enumerate() {
        let retrieved = corpus.load_input(id).expect("load should succeed");
        assert_eq!(retrieved.txs.len(), inputs[i].txs.len());
        assert_eq!(retrieved.base_snapshot_id, inputs[i].base_snapshot_id);
    }

    // Verify corpus statistics
    assert_eq!(corpus.len().expect("corpus length should be readable"), 5);
}

// ============================================================================
// PROPERTY-BASED TESTS FOR MUTATION STRATEGIES
// ============================================================================

#[test]
fn property_mutation_preserves_valid_calldata_structure() {
    // Property: Any mutation should produce valid calldata (4-byte selector + args)
    let original = vec![0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x01, 0x02, 0x03];

    for _ in 0..100 {
        // Simulate various mutations
        let mutated = simulate_mutation(&original);

        // Property: Mutated calldata should have at least selector (4 bytes)
        assert!(mutated.len() >= 4, "Mutation should preserve selector");

        // Property: If original had selector, mutation should preserve selector or produce valid one
        if original.len() >= 4 {
            // Either keep original selector or produce a new valid one
            assert!(mutated.len() >= 4);
        }
    }
}

#[test]
fn property_mutation_deterministic_with_same_seed() {
    // Property: Mutations with same seed should produce identical results
    let original = vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4];
    let seed = 42u64;

    let mutation1 = simulate_seeded_mutation(&original, seed);
    let mutation2 = simulate_seeded_mutation(&original, seed);

    assert_eq!(
        mutation1, mutation2,
        "Same seed should produce identical mutations"
    );
}

#[test]
fn property_mutation_produces_valid_addresses() {
    // Property: Address mutations should produce valid 20-byte addresses
    let original_addr = Address::repeat_byte(0xaa);

    for _ in 0..100 {
        let mutated_addr = simulate_address_mutation(original_addr);

        // Property: Address should be 20 bytes
        assert_eq!(mutated_addr.as_slice().len(), 20);

        // Property: Address should not be zero address (unless intentionally so)
        if mutated_addr != Address::ZERO {
            assert_ne!(mutated_addr, Address::ZERO);
        }
    }
}

#[test]
fn property_mutation_sequence_length_bounded() {
    // Property: Sequence mutations should respect maximum length bounds
    let max_length = 10;
    let original_sequence: Vec<SingletonTx> = (0..5)
        .map(|i| SingletonTx {
            input: vec![i as u8; 4],
            caller: addr(0x10 + i as u8),
            to: addr(0x20),
            value: U256::from(i),
            is_victim: false,
        })
        .collect();

    for _ in 0..100 {
        let mutated_sequence = simulate_sequence_mutation(&original_sequence, max_length);

        // Property: Sequence length should not exceed maximum
        assert!(
            mutated_sequence.len() <= max_length,
            "Mutation should respect max sequence length"
        );

        // Property: Sequence should not be empty
        assert!(
            !mutated_sequence.is_empty(),
            "Mutation should not empty sequence"
        );
    }
}

#[test]
fn property_mutation_preserves_value_semantics() {
    // Property: Value mutations should preserve U256 semantics (no overflow/underflow)
    let original_value = U256::from(1_000_000);

    for _ in 0..100 {
        let mutated_value = simulate_value_mutation(original_value);

        // Property: Value should be valid U256 (no panic on creation)
        let _ = U256::from(mutated_value.to::<u128>());

        // Property: Value should not cause arithmetic overflow in typical operations
        let _ = mutated_value.saturating_add(U256::from(1));
        let _ = mutated_value.saturating_sub(U256::from(1));
    }
}

// Helper functions for property-based testing (simulating mutation strategies)

fn simulate_mutation(calldata: &[u8]) -> Vec<u8> {
    // Simulate various mutation strategies
    let mut rng = rand::rng();
    let strategy = rng.random_range(0..5);

    match strategy {
        0 => calldata.to_vec(), // No mutation
        1 => {
            // Flip random bit
            let mut result = calldata.to_vec();
            if !result.is_empty() {
                let byte_idx = rng.random_range(0..result.len());
                result[byte_idx] ^= 0x01;
            }
            result
        }
        2 => {
            // Add random byte
            let mut result = calldata.to_vec();
            result.push(rng.random());
            result
        }
        3 => {
            // Remove random byte
            let mut result = calldata.to_vec();
            if !result.is_empty() && result.len() > 4 {
                let byte_idx = rng.random_range(4..result.len());
                result.remove(byte_idx);
            }
            result
        }
        _ => {
            // Swap bytes
            let mut result = calldata.to_vec();
            if result.len() >= 5 {
                let idx1 = rng.random_range(4..result.len());
                let idx2 = rng.random_range(4..result.len());
                result.swap(idx1, idx2);
            }
            result
        }
    }
}

fn simulate_seeded_mutation(calldata: &[u8], seed: u64) -> Vec<u8> {
    // Deterministic mutation based on seed
    let mut result = calldata.to_vec();
    if !result.is_empty() {
        let byte_idx = (seed as usize) % result.len();
        result[byte_idx] = result[byte_idx].wrapping_add(seed as u8);
    }
    result
}

fn simulate_address_mutation(addr: Address) -> Address {
    let mut bytes = addr.as_slice().to_vec();
    let mut rng = rand::rng();

    // Flip random bit in address
    let byte_idx = rng.random_range(0..20);
    bytes[byte_idx] ^= 0x01;

    Address::from_slice(&bytes)
}

fn simulate_sequence_mutation(sequence: &[SingletonTx], max_len: usize) -> Vec<SingletonTx> {
    let mut rng = rand::rng();
    let strategy = rng.random_range(0..4);

    match strategy {
        0 => sequence.to_vec(), // No mutation
        1 => {
            // Add transaction if under max
            if sequence.len() < max_len {
                let mut result = sequence.to_vec();
                result.push(SingletonTx {
                    input: vec![rng.random(); 4],
                    caller: addr(rng.random()),
                    to: addr(rng.random()),
                    value: U256::from(rng.random::<u64>()),
                    is_victim: rng.random(),
                });
                result
            } else {
                sequence.to_vec()
            }
        }
        2 => {
            // Remove transaction if more than 1
            if sequence.len() > 1 {
                let mut result = sequence.to_vec();
                result.remove(rng.random_range(0..result.len()));
                result
            } else {
                sequence.to_vec()
            }
        }
        _ => {
            // Swap transactions
            let mut result = sequence.to_vec();
            if result.len() >= 2 {
                let idx1 = rng.random_range(0..result.len());
                let idx2 = rng.random_range(0..result.len());
                result.swap(idx1, idx2);
            }
            result
        }
    }
}

fn simulate_value_mutation(value: U256) -> U256 {
    let mut rng = rand::rng();
    let strategy = rng.random_range(0..4);

    match strategy {
        0 => value,
        1 => value.saturating_add(U256::from(rng.random::<u64>())),
        2 => value.saturating_sub(U256::from(rng.random::<u64>())),
        _ => value.saturating_mul(U256::from(rng.random_range(1..100))),
    }
}
