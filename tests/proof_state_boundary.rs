use revm::{
    database::CacheDB,
    primitives::{Address, U256},
    state::AccountInfo,
};
use rusty_fuzz::{
    common::types::{ChainState, EvmInput, ExecutionStatus, SequenceExecutionResult, SingletonTx},
    engine::scoring::CampaignScore,
    evm::{
        corpus::{CampaignArtifactRequest, PersistentCorpus},
        fork::create_offline_fallback_block_env,
    },
};
use rustyfuzz_evm::{
    dataflow::DataflowRegistry, executor::EvmExecutor, fork_db::ForkDb, inspector::MAP_SIZE,
};

#[test]
fn artifact_base_cache_preserves_original_caller_and_rejects_exploration_funding() {
    let root =
        std::env::temp_dir().join(format!("rustyfuzz-proof-boundary-{}", uuid::Uuid::new_v4()));
    let caller = Address::repeat_byte(0x13);
    let target = Address::repeat_byte(0x55);
    let base = CacheDB::new(ForkDb::empty());
    // Leave this uncached in CacheDB: execution must fetch the original account.
    base.db.cache_account(
        caller,
        AccountInfo {
            balance: U256::from(17),
            nonce: 7,
            ..Default::default()
        },
    );
    let input = EvmInput {
        base_snapshot_id: 0,
        txs: vec![SingletonTx {
            caller,
            to: target,
            value: U256::from(100),
            input: vec![],
            is_victim: false,
        }],
    };
    let mut explored = ChainState::Evm(base.clone());
    let mut block = create_offline_fallback_block_env(1);
    let mut coverage = vec![0; MAP_SIZE];
    let result = EvmExecutor::exploration()
        .execute_with_result(
            &mut explored,
            &mut block,
            &input.txs[0],
            &mut coverage,
            &mut DataflowRegistry::new(),
            &mut vec![],
            0,
        )
        .unwrap();
    assert_eq!(result.status, ExecutionStatus::Success);
    let execution = SequenceExecutionResult {
        total_gas_used: result.gas_used,
        final_coverage_hash: result.coverage_hash,
        tx_results: vec![result],
        storage_reads: vec![],
        storage_writes: vec![],
        storage_diffs: vec![],
        call_trace: vec![],
        oracle_observations: vec![],
    };
    let corpus = PersistentCorpus::new(&root).unwrap();
    let artifact = corpus
        .persist_campaign_artifact(CampaignArtifactRequest {
            input: &input,
            execution: &execution,
            coverage: &coverage,
            state_novelty_score: 0,
            base_fork_state: &base,
            score: &CampaignScore::default(),
            findings: &[],
            exploit_candidate: None,
            block_number: 1,
            target: Some(target),
            reason: "proof-boundary-regression",
        })
        .unwrap();
    let persisted = corpus
        .load_fork_cache(&artifact.record.fork_cache_id)
        .unwrap();
    let account = persisted
        .accounts
        .iter()
        .find(|entry| entry.address == caller)
        .unwrap()
        .info
        .as_ref()
        .unwrap();
    assert_eq!(account.balance, U256::from(17));
    assert_eq!(account.nonce, 7);
    let mut proof_state = ChainState::Evm(CacheDB::new(ForkDb::from_cache_snapshot(persisted)));
    let proof = EvmExecutor::proof().execute_with_result(
        &mut proof_state,
        &mut block,
        &input.txs[0],
        &mut vec![0; MAP_SIZE],
        &mut DataflowRegistry::new(),
        &mut vec![],
        0,
    );
    let error = proof.expect_err("original account cannot afford exploration's transfer and gas");
    assert!(error.to_string().to_lowercase().contains("fund"), "{error}");
    std::fs::remove_dir_all(root).unwrap();
}
