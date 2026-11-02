use parking_lot::RwLock;
use revm::{
    database::CacheDB,
    primitives::{Address, U256},
    state::{AccountInfo, Bytecode},
};
use rusty_fuzz::{
    common::{
        types::{ChainState, EvmInput, SingletonTx, Snapshot},
        verifier::ReplayVerifier,
    },
    config::HardenedDefiConfig,
    engine::{
        fuzz_engine::{run_fuzz_campaign, Config},
        promotion::PromotionConfig,
        provenance::ExecutionProvenanceRecord,
    },
    evm::{corpus::SnapshotCorpus, fork::create_offline_fallback_block_env},
};
use rustyfuzz_evm::{fork_db::ForkDb, inspector::MAP_SIZE};
use std::{collections::HashSet, sync::Arc};

const CODE: &[u8] = &[0x60, 0, 0x54, 0x60, 1, 1, 0x60, 0, 0x55, 0];

fn state() -> ChainState {
    let mut db = CacheDB::new(ForkDb::empty());
    db.insert_account_info(
        Address::repeat_byte(0x11),
        AccountInfo::default().with_code(Bytecode::new_raw(CODE.to_vec().into())),
    );
    ChainState::Evm(db)
}

fn input(base: u64) -> EvmInput {
    EvmInput::new(
        vec![SingletonTx {
            caller: Address::repeat_byte(0x13),
            to: Address::repeat_byte(0x11),
            value: U256::ZERO,
            input: vec![],
            is_victim: false,
        }],
        base,
    )
}

fn snapshot(id: u64, producing_input: Option<EvmInput>) -> Snapshot {
    Snapshot {
        id,
        state: Arc::new(RwLock::new(state())),
        coverage: bitvec::bitvec![u8, bitvec::order::Lsb0; 0; 8],
        producing_input,
        waypoints: vec![],
        depth: id as u32,
        gas_used: 0,
    }
}

#[test]
fn root_lineage_is_strict_and_pinned_ancestry_survives_pruning() {
    let mut corpus = SnapshotCorpus::new();
    corpus.add_snapshot(0, 0, snapshot(0, None)).unwrap();
    corpus
        .add_snapshot(1, 0, snapshot(1, Some(input(0))))
        .unwrap();
    corpus
        .add_snapshot(2, 1, snapshot(2, Some(input(1))))
        .unwrap();
    let replay = corpus.root_replay_input(&input(2)).unwrap();
    assert_eq!(replay.base_snapshot_id, 0);
    assert_eq!(replay.txs.len(), 3);
    assert!(corpus.pin_snapshot(2));
    corpus.prune_recursive(1);
    corpus.retain(&HashSet::new());
    assert!(corpus.root_replay_input(&input(2)).is_some());
    assert!(corpus.root_replay_input(&input(99)).is_none());
    corpus.parent_map.insert(1, 2);
    assert!(corpus.root_replay_input(&input(2)).is_none());
    corpus.parent_map.insert(1, 0);
    corpus.get_snapshot(2).unwrap().write().producing_input = Some(input(0));
    assert!(corpus.root_replay_input(&input(2)).is_none());
    corpus.get_snapshot(2).unwrap().write().producing_input = None;
    assert!(corpus.root_replay_input(&input(2)).is_none());
    let mut long = input(1);
    long.txs = vec![long.txs[0].clone(); 100];
    assert!(corpus.root_replay_input(&long).is_none());
}

#[test]
fn snapshot_campaign_worker() {
    let Some(root) = std::env::var_os("RUSTYFUZZ_SNAPSHOT_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let config = Config {
        rpc_url: "offline-test".into(),
        fork_block: 1,
        target_contract: Some(Address::repeat_byte(0x11)),
        corpus_dir: root.join("corpus").display().to_string(),
        report_dir: root.join("reports").display().to_string(),
        foundry_harness: None,
        mainnet_seed_bundle: None,
        in_memory_bytecode: Some(CODE.to_vec()),
        cores: None,
        require_seed_bundle: false,
        require_rpc_fork: false,
        allow_synthetic_fallback: true,
        hardened_defi: HardenedDefiConfig {
            single_process: true,
            deterministic: true,
            rng_seed: Some(42),
            ..Default::default()
        },
        target_invariant_manifest: None,
        predicate_invariants: None,
        abi_path: None,
        max_execs: Some(128),
        duration_secs: None,
        artifact_limit: Some(0),
        campaign_id: Some("snapshot-regression".into()),
        paths_are_isolated: true,
        min_finding_confidence: 0,
        promotion: PromotionConfig::default(),
    };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_fuzz_campaign(config))
        .unwrap();
}

#[test]
fn real_campaign_uses_non_root_snapshots_with_portable_replay_material() {
    let root = std::env::temp_dir().join(format!("rustyfuzz-snapshot-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let log = std::fs::File::create(root.join("campaign.log")).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .current_dir(&root)
        .args(["--exact", "snapshot_campaign_worker", "--nocapture"])
        .env("RUSTYFUZZ_SNAPSHOT_TEST_ROOT", &root)
        .env("RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS", "0")
        .env("RUSTYFUZZ_GIT_REV", "snapshot-test")
        .env("RUSTYFUZZ_SOURCE_DIRTY", "clean")
        .env("RUSTYFUZZ_SOURCE_DIFF_SHA256", "unknown")
        .env(
            "RUSTYFUZZ_BINARY_SHA256",
            format!("sha256:{}", "ab".repeat(32)),
        )
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "{}",
                std::fs::read_to_string(root.join("campaign.log")).unwrap()
            );
            break;
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("bounded snapshot campaign timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let records: Vec<ExecutionProvenanceRecord> = std::fs::read_dir(
        root.join(".rustyfuzz/runs/snapshot-regression/inputs/execution_provenance"),
    )
    .unwrap()
    .map(|entry| serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap())
    .collect();
    let record = records
        .iter()
        .find(|record| {
            record.input.base_snapshot_id != 0
                && record
                    .execution
                    .storage_diffs
                    .iter()
                    .any(|diff| diff.old_value > U256::ZERO)
        })
        .expect("campaign must continue from a retained state");
    let replay_input = record.root_replay_input.as_ref().unwrap();
    assert_eq!(replay_input.base_snapshot_id, 0);
    assert!(replay_input.txs.len() > record.input.txs.len());
    assert_eq!(
        record.environment_policy.as_ref().unwrap().source,
        "synthetic-osaka"
    );
    let replay = ReplayVerifier::new(MAP_SIZE)
        .verify_deterministic(
            &state(),
            &create_offline_fallback_block_env(1),
            replay_input,
        )
        .unwrap();
    assert_eq!(
        replay.storage_diffs.last().unwrap().new_value,
        record.execution.storage_diffs.last().unwrap().new_value
    );
    std::fs::remove_dir_all(root).unwrap();
}
