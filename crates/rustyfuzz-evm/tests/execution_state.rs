//! Execute bytecode through the public backend: assertions compare canonical
//! observations with actual cached state, rather than another trace formatter.
use revm::{
    context::BlockEnv,
    database::CacheDB,
    primitives::{Address, B256, U256},
    state::{AccountInfo, Bytecode},
};
use rustyfuzz_evm::{
    execution::{ChainState, ExecutionStatus, TxExecutionResult, Waypoint, MAX_TOTAL_WAYPOINTS},
    inspector::MAP_SIZE,
    DataflowRegistry, EvmExecutor, ForkDb, SingletonTx,
};

fn target() -> Address {
    Address::repeat_byte(0x22)
}

fn caller() -> Address {
    Address::repeat_byte(0x11)
}

fn fixture(code: &[u8], initial_slot: u64, caller_nonce: u64) -> ChainState {
    let fork = ForkDb::empty();
    fork.cache_account(
        caller(),
        AccountInfo {
            balance: U256::from(10u128.pow(20)),
            nonce: caller_nonce,
            ..Default::default()
        },
    );
    // Keep slot state in the underlying database, absent from CacheDB.
    fork.cache_storage(target(), U256::ZERO, U256::from(initial_slot));
    let mut db = CacheDB::new(fork);
    db.insert_account_info(
        target(),
        AccountInfo::default().with_code(Bytecode::new_raw(code.to_vec().into())),
    );
    ChainState::Evm(db)
}

fn transaction() -> SingletonTx {
    SingletonTx {
        input: Vec::new(),
        caller: caller(),
        to: target(),
        value: U256::ZERO,
        is_victim: false,
    }
}

fn execute(
    executor: &EvmExecutor,
    state: &mut ChainState,
    tx: &SingletonTx,
) -> anyhow::Result<TxExecutionResult> {
    let mut env = BlockEnv::default();
    env.set_blob_excess_gas_and_price(0, 3_338_477);
    executor.execute_with_result(
        state,
        &mut env,
        tx,
        &mut vec![0; MAP_SIZE],
        &mut DataflowRegistry::new(),
        &mut Vec::new(),
        0,
    )
}

fn stored(state: &ChainState) -> U256 {
    let ChainState::Evm(db) = state;
    db.cache.accounts[&target()].storage[&U256::ZERO]
}

#[test]
fn reverted_write_remains_telemetry_but_is_not_a_committed_delta() {
    let mut state = fixture(&[0x60, 9, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xfd], 5, 0);
    let result = execute(&EvmExecutor::exploration(), &mut state, &transaction()).unwrap();
    assert_eq!(result.status, ExecutionStatus::Revert);
    assert_eq!(result.storage_writes.len(), 1);
    assert!(result.storage_diffs.is_empty());
    assert_eq!(stored(&state), U256::from(5));
}

#[test]
fn halted_write_is_not_a_committed_delta() {
    let mut state = fixture(&[0x60, 9, 0x60, 0, 0x55, 0xfe], 5, 0);
    let result = execute(&EvmExecutor::exploration(), &mut state, &transaction()).unwrap();
    assert!(matches!(result.status, ExecutionStatus::Halt(_)));
    assert_eq!(result.storage_writes.len(), 1);
    assert!(result.storage_diffs.is_empty());
    assert_eq!(stored(&state), U256::from(5));
}

#[test]
fn cold_slot_uses_authoritative_original_value() {
    let mut state = fixture(&[0x60, 9, 0x60, 0, 0x55, 0x00], 5, 0);
    let result = execute(&EvmExecutor::exploration(), &mut state, &transaction()).unwrap();
    assert_eq!(result.status, ExecutionStatus::Success);
    assert_eq!(result.storage_diffs.len(), 1);
    let diff = &result.storage_diffs[0];
    assert_eq!(diff.address, target());
    assert_eq!(diff.slot, B256::ZERO);
    assert_eq!(diff.old_value, U256::from(5));
    assert_eq!(diff.new_value, stored(&state));
    assert_eq!(diff.new_value, U256::from(9));
}

#[test]
fn committed_deltas_survive_exhausted_waypoint_telemetry() {
    let mut state = fixture(&[0x60, 9, 0x60, 0, 0x55, 0], 5, 0);
    let mut env = BlockEnv::default();
    env.set_blob_excess_gas_and_price(0, 3_338_477);
    let mut waypoints = vec![
        Waypoint::Dataflow {
            address: target(),
            slot: vec![0; 32],
            influenced: false,
        };
        MAX_TOTAL_WAYPOINTS
    ];
    let result = EvmExecutor::exploration()
        .execute_with_result(
            &mut state,
            &mut env,
            &transaction(),
            &mut vec![0; MAP_SIZE],
            &mut DataflowRegistry::new(),
            &mut waypoints,
            0,
        )
        .unwrap();
    assert!(result.storage_writes.is_empty());
    assert_eq!(result.storage_diffs.len(), 1);
    assert_eq!(result.storage_diffs[0].old_value, U256::from(5));
    assert_eq!(result.storage_diffs[0].new_value, stored(&state));
    assert_eq!(result.storage_diffs[0].pc, 0);
}

#[test]
fn repeated_writes_produce_one_before_after_delta() {
    let mut state = fixture(&[0x60, 7, 0x60, 0, 0x55, 0x60, 9, 0x60, 0, 0x55, 0], 5, 0);
    let result = execute(&EvmExecutor::exploration(), &mut state, &transaction()).unwrap();
    assert_eq!(result.storage_writes.len(), 2);
    assert_eq!(result.storage_diffs.len(), 1);
    assert_eq!(result.storage_diffs[0].old_value, U256::from(5));
    assert_eq!(result.storage_diffs[0].new_value, stored(&state));
    assert_eq!(stored(&state), U256::from(9));
}

#[test]
fn write_back_to_original_has_no_committed_delta() {
    let mut state = fixture(&[0x60, 7, 0x60, 0, 0x55, 0x60, 5, 0x60, 0, 0x55, 0], 5, 0);
    let result = execute(&EvmExecutor::exploration(), &mut state, &transaction()).unwrap();
    assert_eq!(result.storage_writes.len(), 2);
    assert!(result.storage_diffs.is_empty());
    assert_eq!(stored(&state), U256::from(5));
}

#[test]
fn exploration_can_fund_a_previously_nonexistent_caller() {
    let mut db = CacheDB::new(ForkDb::empty());
    db.insert_account_info(
        target(),
        AccountInfo::default().with_code(Bytecode::new_raw(vec![0].into())),
    );
    let mut state = ChainState::Evm(db);
    let result = execute(&EvmExecutor::exploration(), &mut state, &transaction()).unwrap();
    assert_eq!(result.status, ExecutionStatus::Success);
    let ChainState::Evm(db) = state;
    assert_eq!(db.cache.accounts[&caller()].info.nonce, 1);
}

#[test]
fn uncached_existing_caller_nonce_is_preserved_in_both_modes() {
    for executor in [EvmExecutor::proof(), EvmExecutor::exploration()] {
        let mut state = fixture(&[0x00], 5, 7);
        let result = execute(&executor, &mut state, &transaction()).unwrap();
        assert_eq!(result.status, ExecutionStatus::Success);
        let ChainState::Evm(db) = state;
        assert_eq!(db.cache.accounts[&caller()].info.nonce, 8);
    }
}

#[test]
fn exploration_preserves_uncached_caller_code_and_does_not_erase_it_to_bypass_validation() {
    let mut state = fixture(&[0x00], 5, 7);
    let ChainState::Evm(db) = &state;
    db.db.cache_account(
        caller(),
        AccountInfo {
            nonce: 7,
            ..AccountInfo::default().with_code(Bytecode::new_raw(vec![0x00].into()))
        },
    );
    assert!(execute(&EvmExecutor::exploration(), &mut state, &transaction()).is_err());
    let ChainState::Evm(db) = state;
    assert!(db.cache.accounts.contains_key(&target()));
    assert!(!db.cache.accounts.contains_key(&caller()));
}

#[test]
fn validation_error_preserves_original_accounts_and_allows_retry() {
    let mut state = fixture(&[0x60, 9, 0x60, 0, 0x55, 0], 5, 7);
    let ChainState::Evm(db) = &state;
    let original_account = db.cache.accounts[&target()].info.clone();
    let mut too_expensive = transaction();
    too_expensive.value = U256::MAX;
    assert!(execute(&EvmExecutor::proof(), &mut state, &too_expensive).is_err());
    let ChainState::Evm(db) = &state;
    assert_eq!(db.cache.accounts.len(), 1);
    assert_eq!(db.cache.accounts[&target()].info, original_account);
    let result = execute(&EvmExecutor::proof(), &mut state, &transaction()).unwrap();
    assert_eq!(result.status, ExecutionStatus::Success);
    assert_eq!(result.storage_diffs[0].old_value, U256::from(5));
}

#[test]
fn caught_child_revert_does_not_publish_its_storage_change() {
    let child = Address::repeat_byte(0x33);
    // CALL child; discard failure; commit a write in the parent.
    let mut parent_code = vec![0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x73];
    parent_code.extend_from_slice(child.as_slice());
    parent_code.extend_from_slice(&[0x5a, 0xf1, 0x50, 0x60, 9, 0x60, 0, 0x55, 0]);
    let mut state = fixture(&parent_code, 5, 0);
    let ChainState::Evm(db) = &mut state;
    db.insert_account_info(
        child,
        AccountInfo::default().with_code(Bytecode::new_raw(
            vec![0x60, 7, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xfd].into(),
        )),
    );
    let result = execute(&EvmExecutor::exploration(), &mut state, &transaction()).unwrap();
    assert_eq!(result.status, ExecutionStatus::Success);
    assert_eq!(result.storage_writes.len(), 2);
    assert_eq!(result.storage_diffs.len(), 1);
    assert_eq!(result.storage_diffs[0].address, target());
    assert_eq!(result.storage_diffs[0].old_value, U256::from(5));
    assert_eq!(result.storage_diffs[0].new_value, U256::from(9));
}
