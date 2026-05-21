use revm::context::BlockEnv;
use revm::database::CacheDB;
use revm::database_interface::DatabaseRef;
use revm::primitives::{Address, U256};
use revm::state::{AccountInfo, Bytecode};
use rusty_fuzz::common::oracle::{
    AccessControlOracle, ERC4626InflationOracle, ReentrancyOracle, VulnType, VulnerabilityOracle,
};
use rusty_fuzz::common::types::{ChainState, EvmInput, SingletonTx, Waypoint};
use rusty_fuzz::common::verifier::ReplayVerifier;
use rusty_fuzz::engine::exploit_synthesizer::synthesize_foundry_poc;
use rusty_fuzz::evm::corpus::PersistentCorpus;
use rusty_fuzz::evm::dataflow::DataflowRegistry;
use rusty_fuzz::evm::executor::EvmExecutor;
use rusty_fuzz::evm::feedback::EvmCoverageFeedback;
use rusty_fuzz::evm::fork_db::ForkDb;
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
    };

    let verifier = ReplayVerifier::new(1024);
    let execution = verifier
        .verify_deterministic(&ChainState::Evm(db.clone()), &BlockEnv::default(), &input)
        .expect("replay should be deterministic");
    assert_eq!(execution.tx_results.len(), 1);
    assert!(execution.total_gas_used > 0);

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
