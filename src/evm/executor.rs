// use crate::common::types::{
//     CallKind, CallObservation, CallPhase, ChainState, ExecutionStatus, SingletonTx, StorageAccess,
//     StorageDiff, TxExecutionResult, Waypoint,
// };
// use crate::evm::dataflow::DataflowRegistry;
// use crate::evm::feedback::EvmCoverageFeedback;
// use crate::evm::fork_db::ForkDb;
// use crate::evm::inspector::CoverageInspector;

// use anyhow::Result;
// use revm::context::result::ExecutionResult;
// use revm::context::{BlockEnv, TxEnv};
// use revm::database::CacheDB;
// use revm::primitives::{Address, TxKind, B256, U256};
// use revm::{Context, InspectCommitEvm, MainBuilder, MainContext};

// pub struct EvmExecutor {}

// impl EvmExecutor {
//     pub fn new() -> Self {
//         EvmExecutor {}
//     }

//     #[allow(clippy::too_many_arguments)]
//     pub fn execute(
//         &self,
//         chain_state: &mut ChainState,
//         _block_env: &mut BlockEnv,
//         tx: &SingletonTx,
//         _coverage: &mut [u8],
//         _dataflow: &mut DataflowRegistry,
//         _waypoints: &mut Vec<Waypoint>,
//         _tx_idx: usize,
//     ) -> Result<u64> {
//         Ok(self
//             .execute_with_result(
//                 chain_state,
//                 _block_env,
//                 tx,
//                 _coverage,
//                 _dataflow,
//                 _waypoints,
//                 _tx_idx,
//             )?
//             .gas_used)
//     }

//     #[allow(clippy::too_many_arguments)]
//     pub fn execute_with_result(
//         &self,
//         chain_state: &mut ChainState,
//         _block_env: &mut BlockEnv,
//         tx: &SingletonTx,
//         _coverage: &mut [u8],
//         _dataflow: &mut DataflowRegistry,
//         _waypoints: &mut Vec<Waypoint>,
//         _tx_idx: usize,
//     ) -> Result<TxExecutionResult> {
//         let ChainState::Evm(db) = chain_state;
//         let caller_nonce = db
//             .cache
//             .accounts
//             .get(&tx.caller)
//             .map(|account| account.info.nonce)
//             .unwrap_or_default();

//         let tx_env = TxEnv {
//             caller: tx.caller,
//             gas_limit: 10_000_000,
//             gas_price: 1_000_000_000_u128,
//             value: tx.value,
//             data: tx.input.clone().into(),
//             kind: if tx.to == Address::ZERO {
//                 TxKind::Create
//             } else {
//                 TxKind::Call(tx.to)
//             },
//             nonce: caller_nonce,
//             ..Default::default()
//         };

//         let (result, final_db, storage_diffs) = {
//             let execution_db = std::mem::replace(db, CacheDB::new(ForkDb::empty()));
//             let pre_execution_db = execution_db.clone();
//             let ctx = Context::mainnet()
//                 .with_db(execution_db)
//                 .with_block(_block_env.clone());
//             let mut evm = ctx.build_mainnet_with_inspector(CoverageInspector::new(
//                 _coverage, _dataflow, _waypoints, _tx_idx,
//             ));

//             let result = evm.inspect_tx_commit(tx_env)?;
//             let final_db = evm.ctx.journaled_state.database;
//             let storage_diffs =
//                 storage_diffs_from_waypoints(&pre_execution_db, &final_db, _waypoints, _tx_idx);
//             (result, final_db, storage_diffs)
//         };

//         let gas_used = result.tx_gas_used();
//         let status = match &result {
//             ExecutionResult::Success { .. } => ExecutionStatus::Success,
//             ExecutionResult::Revert { .. } => ExecutionStatus::Revert,
//             ExecutionResult::Halt { reason, .. } => ExecutionStatus::Halt(format!("{reason:?}")),
//         };
//         let output = result
//             .output()
//             .map(|bytes| bytes.to_vec())
//             .unwrap_or_default();
//         let coverage_hash = EvmCoverageFeedback::stable_path_hash(_coverage);
//         let coverage_edges = _coverage.iter().filter(|&&hit| hit != 0).count();
//         let waypoints = _waypoints.clone();
//         let storage_reads = storage_reads_from_waypoints(&waypoints);
//         let storage_writes = storage_writes_from_waypoints(&waypoints);
//         let mut call_trace = call_trace_from_waypoints(&waypoints, _tx_idx);
//         call_trace.insert(
//             0,
//             CallObservation {
//                 tx_index: _tx_idx,
//                 depth: 0,
//                 caller: tx.caller,
//                 target: tx.to,
//                 value: tx.value,
//                 input: tx.input.clone(),
//                 output: output.clone(),
//                 gas_limit: 10_000_000,
//                 gas_used,
//                 success: matches!(status, ExecutionStatus::Success),
//                 kind: CallKind::Transaction,
//                 phase: CallPhase::End,
//                 created_address: None,
//                 result: Some(format!("{status:?}")),
//             },
//         );
//         *db = final_db;
//         Ok(TxExecutionResult {
//             tx_index: _tx_idx,
//             status,
//             gas_used,
//             output,
//             coverage_hash,
//             coverage_edges,
//             storage_reads,
//             storage_writes,
//             storage_diffs,
//             call_trace,
//             waypoints,
//         })
//     }
// }

// impl Default for EvmExecutor {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// fn storage_reads_from_waypoints(waypoints: &[Waypoint]) -> Vec<StorageAccess> {
//     waypoints
//         .iter()
//         .filter_map(|waypoint| match waypoint {
//             Waypoint::StorageRead {
//                 address,
//                 slot,
//                 value,
//                 pc,
//                 read_tx_idx,
//                 ..
//             } => Some(StorageAccess {
//                 tx_index: *read_tx_idx,
//                 address: *address,
//                 slot: *slot,
//                 value: Some(*value),
//                 pc: *pc,
//             }),
//             _ => None,
//         })
//         .collect()
// }

// fn storage_writes_from_waypoints(waypoints: &[Waypoint]) -> Vec<StorageAccess> {
//     waypoints
//         .iter()
//         .filter_map(|waypoint| match waypoint {
//             Waypoint::StorageWrite {
//                 address,
//                 slot,
//                 value,
//                 pc,
//                 tx_idx,
//                 ..
//             } => Some(StorageAccess {
//                 tx_index: *tx_idx,
//                 address: *address,
//                 slot: b256_from_slot_bytes(slot),
//                 value: Some(*value),
//                 pc: *pc,
//             }),
//             _ => None,
//         })
//         .collect()
// }

// fn storage_diffs_from_waypoints(
//     before: &CacheDB<ForkDb>,
//     after: &CacheDB<ForkDb>,
//     waypoints: &[Waypoint],
//     tx_index: usize,
// ) -> Vec<StorageDiff> {
//     storage_writes_from_waypoints(waypoints)
//         .into_iter()
//         .map(|write| StorageDiff {
//             old_value: cached_storage_value(before, write.address, write.slot),
//             new_value: write
//                 .value
//                 .unwrap_or_else(|| cached_storage_value(after, write.address, write.slot)),
//             tx_index,
//             address: write.address,
//             slot: write.slot,
//             pc: write.pc,
//         })
//         .filter(|diff| diff.old_value != diff.new_value)
//         .collect()
// }

// fn cached_storage_value(db: &CacheDB<ForkDb>, address: Address, slot: B256) -> U256 {
//     db.cache
//         .accounts
//         .get(&address)
//         .and_then(|account| account.storage.get(&U256::from_be_slice(slot.as_slice())))
//         .copied()
//         .unwrap_or_default()
// }

// fn call_trace_from_waypoints(waypoints: &[Waypoint], _tx_index: usize) -> Vec<CallObservation> {
//     waypoints
//         .iter()
//         .filter_map(|waypoint| match waypoint {
//             Waypoint::CallTrace {
//                 tx_idx,
//                 depth,
//                 caller,
//                 target,
//                 value,
//                 input,
//                 output,
//                 gas_limit,
//                 gas_used,
//                 success,
//                 kind,
//                 phase,
//                 result,
//             } => Some(CallObservation {
//                 tx_index: *tx_idx,
//                 depth: *depth,
//                 caller: *caller,
//                 target: *target,
//                 value: *value,
//                 input: input.clone(),
//                 output: output.clone(),
//                 gas_limit: *gas_limit,
//                 gas_used: *gas_used,
//                 success: *success,
//                 kind: kind.clone(),
//                 phase: phase.clone(),
//                 created_address: None,
//                 result: result.clone(),
//             }),
//             Waypoint::CreateTrace {
//                 tx_idx,
//                 depth,
//                 creator,
//                 created_address,
//                 value,
//                 init_code,
//                 deployed_code,
//                 gas_limit,
//                 gas_used,
//                 success,
//                 kind,
//                 phase,
//                 result,
//             } => Some(CallObservation {
//                 tx_index: *tx_idx,
//                 depth: *depth,
//                 caller: *creator,
//                 target: created_address.unwrap_or_default(),
//                 value: *value,
//                 input: init_code.clone(),
//                 output: deployed_code.clone(),
//                 gas_limit: *gas_limit,
//                 gas_used: *gas_used,
//                 success: *success,
//                 kind: kind.clone(),
//                 phase: phase.clone(),
//                 created_address: *created_address,
//                 result: result.clone(),
//             }),
//             _ => None,
//         })
//         .collect()
// }

// fn b256_from_slot_bytes(slot: &[u8]) -> B256 {
//     if slot.len() == 32 {
//         B256::from_slice(slot)
//     } else {
//         B256::from(U256::from_be_slice(slot))
//     }
// }

use crate::common::types::{
    CallKind, CallObservation, CallPhase, ChainState, ExecutionStatus, SingletonTx, StorageAccess,
    StorageDiff, TxExecutionResult, Waypoint,
};
use crate::evm::dataflow::DataflowRegistry;
use crate::evm::feedback::EvmCoverageFeedback;
use crate::evm::fork_db::ForkDb;
use crate::evm::inspector::CoverageInspector;

use anyhow::Result;
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, TxEnv};
use revm::database::CacheDB;
use revm::primitives::{Address, TxKind, B256, U256};
use revm::state::AccountInfo;
use revm::{Context, InspectCommitEvm, MainBuilder, MainContext};
use std::collections::HashSet;

const TX_GAS_LIMIT: u64 = 10_000_000;
const TX_GAS_PRICE_WEI: u128 = 1_000_000_000;
const FUZZ_CALLER_BALANCE_WEI: u128 = 1_000_000_000_000_000_000_000_000_000_000;
const MAX_FUZZ_CALL_VALUE_WEI: u128 = 100_000_000_000_000_000_000;

pub struct EvmExecutor {}

impl EvmExecutor {
    pub fn new() -> Self {
        EvmExecutor {}
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        chain_state: &mut ChainState,
        block_env: &mut BlockEnv,
        tx: &SingletonTx,
        coverage: &mut [u8],
        dataflow: &mut DataflowRegistry,
        waypoints: &mut Vec<Waypoint>,
        tx_idx: usize,
    ) -> Result<u64> {
        Ok(self
            .execute_with_result(
                chain_state,
                block_env,
                tx,
                coverage,
                dataflow,
                waypoints,
                tx_idx,
            )?
            .gas_used)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_result(
        &self,
        chain_state: &mut ChainState,
        block_env: &mut BlockEnv,
        tx: &SingletonTx,
        coverage: &mut [u8],
        dataflow: &mut DataflowRegistry,
        waypoints: &mut Vec<Waypoint>,
        tx_idx: usize,
    ) -> Result<TxExecutionResult> {
        let ChainState::Evm(db) = chain_state;

        // Fuzz-generated callers are often synthetic EOAs. If they are not funded
        // before revm validation, the transaction is rejected before target execution.
        fund_fuzz_caller(db, tx.caller);

        let caller_nonce = db
            .cache
            .accounts
            .get(&tx.caller)
            .map(|account| account.info.nonce)
            .unwrap_or_default();

        // Prevent mutated transaction values from producing impossible payments or
        // overflow-payment validation failures before useful contract execution.
        let executed_value = bounded_tx_value(tx.value);

        let tx_env = TxEnv {
            caller: tx.caller,
            gas_limit: TX_GAS_LIMIT,
            gas_price: TX_GAS_PRICE_WEI,
            value: executed_value,
            data: tx.input.clone().into(),
            kind: if tx.to == Address::ZERO {
                TxKind::Create
            } else {
                TxKind::Call(tx.to)
            },
            nonce: caller_nonce,
            ..Default::default()
        };

        let (result, final_db, storage_diffs) = {
            let execution_db = std::mem::replace(db, CacheDB::new(ForkDb::empty()));
            let pre_execution_db = execution_db.clone();
            let initialized_slots = initialized_storage_slots(&pre_execution_db);

            let ctx = Context::mainnet()
                .with_db(execution_db)
                .with_block(block_env.clone());

            let mut evm =
                ctx.build_mainnet_with_inspector(CoverageInspector::with_initialized_slots(
                    coverage,
                    dataflow,
                    waypoints,
                    tx_idx,
                    initialized_slots,
                ));

            let result = evm.inspect_tx_commit(tx_env)?;
            let final_db = evm.ctx.journaled_state.database;
            let storage_diffs =
                storage_diffs_from_waypoints(&pre_execution_db, &final_db, waypoints, tx_idx);

            (result, final_db, storage_diffs)
        };

        let gas_used = result.tx_gas_used();

        let status = match &result {
            ExecutionResult::Success { .. } => ExecutionStatus::Success,
            ExecutionResult::Revert { .. } => ExecutionStatus::Revert,
            ExecutionResult::Halt { reason, .. } => ExecutionStatus::Halt(format!("{reason:?}")),
        };

        let output = result
            .output()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();

        let coverage_hash = EvmCoverageFeedback::stable_path_hash(coverage);
        let coverage_edges = coverage.iter().filter(|&&hit| hit != 0).count();
        let waypoints = waypoints.clone();
        let storage_reads = storage_reads_from_waypoints(&waypoints);
        let storage_writes = storage_writes_from_waypoints(&waypoints);
        let mut call_trace = call_trace_from_waypoints(&waypoints, tx_idx);

        call_trace.insert(
            0,
            CallObservation {
                tx_index: tx_idx,
                depth: 0,
                caller: tx.caller,
                target: tx.to,
                value: executed_value,
                input: tx.input.clone(),
                output: output.clone(),
                gas_limit: TX_GAS_LIMIT,
                gas_used,
                success: matches!(status, ExecutionStatus::Success),
                kind: CallKind::Transaction,
                phase: CallPhase::End,
                created_address: None,
                result: Some(format!("{status:?}")),
            },
        );

        *db = final_db;

        Ok(TxExecutionResult {
            tx_index: tx_idx,
            status,
            gas_used,
            output,
            coverage_hash,
            coverage_edges,
            storage_reads,
            storage_writes,
            storage_diffs,
            call_trace,
            waypoints,
        })
    }
}

impl Default for EvmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

fn fund_fuzz_caller(db: &mut CacheDB<ForkDb>, caller: Address) {
    let balance = U256::from(FUZZ_CALLER_BALANCE_WEI);

    if let Some(account) = db.cache.accounts.get_mut(&caller) {
        if account.info.balance < balance {
            account.info.balance = balance;
        }
    } else {
        db.insert_account_info(
            caller,
            AccountInfo {
                balance,
                ..AccountInfo::default()
            },
        );
    }
}

fn bounded_tx_value(value: U256) -> U256 {
    let max_value = U256::from(MAX_FUZZ_CALL_VALUE_WEI);

    if value > max_value {
        max_value
    } else {
        value
    }
}

fn initialized_storage_slots(db: &CacheDB<ForkDb>) -> HashSet<(Address, B256)> {
    let mut slots = HashSet::new();
    for (address, account) in &db.cache.accounts {
        for slot in account.storage.keys() {
            slots.insert((*address, B256::from(*slot)));
        }
    }
    slots
}

fn storage_reads_from_waypoints(waypoints: &[Waypoint]) -> Vec<StorageAccess> {
    waypoints
        .iter()
        .filter_map(|waypoint| match waypoint {
            Waypoint::StorageRead {
                address,
                slot,
                value,
                pc,
                read_tx_idx,
                ..
            } => Some(StorageAccess {
                tx_index: *read_tx_idx,
                address: *address,
                slot: *slot,
                value: Some(*value),
                pc: *pc,
            }),
            _ => None,
        })
        .collect()
}

fn storage_writes_from_waypoints(waypoints: &[Waypoint]) -> Vec<StorageAccess> {
    waypoints
        .iter()
        .filter_map(|waypoint| match waypoint {
            Waypoint::StorageWrite {
                address,
                slot,
                value,
                pc,
                tx_idx,
                ..
            } => Some(StorageAccess {
                tx_index: *tx_idx,
                address: *address,
                slot: b256_from_slot_bytes(slot),
                value: Some(*value),
                pc: *pc,
            }),
            _ => None,
        })
        .collect()
}

fn storage_diffs_from_waypoints(
    before: &CacheDB<ForkDb>,
    after: &CacheDB<ForkDb>,
    waypoints: &[Waypoint],
    tx_index: usize,
) -> Vec<StorageDiff> {
    storage_writes_from_waypoints(waypoints)
        .into_iter()
        .map(|write| StorageDiff {
            old_value: cached_storage_value(before, write.address, write.slot),
            new_value: write
                .value
                .unwrap_or_else(|| cached_storage_value(after, write.address, write.slot)),
            tx_index,
            address: write.address,
            slot: write.slot,
            pc: write.pc,
        })
        .filter(|diff| diff.old_value != diff.new_value)
        .collect()
}

fn cached_storage_value(db: &CacheDB<ForkDb>, address: Address, slot: B256) -> U256 {
    db.cache
        .accounts
        .get(&address)
        .and_then(|account| account.storage.get(&U256::from_be_slice(slot.as_slice())))
        .copied()
        .unwrap_or_default()
}

fn call_trace_from_waypoints(waypoints: &[Waypoint], _tx_index: usize) -> Vec<CallObservation> {
    waypoints
        .iter()
        .filter_map(|waypoint| match waypoint {
            Waypoint::CallTrace {
                tx_idx,
                depth,
                caller,
                target,
                value,
                input,
                output,
                gas_limit,
                gas_used,
                success,
                kind,
                phase,
                result,
            } => Some(CallObservation {
                tx_index: *tx_idx,
                depth: *depth,
                caller: *caller,
                target: *target,
                value: *value,
                input: input.clone(),
                output: output.clone(),
                gas_limit: *gas_limit,
                gas_used: *gas_used,
                success: *success,
                kind: kind.clone(),
                phase: phase.clone(),
                created_address: None,
                result: result.clone(),
            }),
            Waypoint::CreateTrace {
                tx_idx,
                depth,
                creator,
                created_address,
                value,
                init_code,
                deployed_code,
                gas_limit,
                gas_used,
                success,
                kind,
                phase,
                result,
            } => Some(CallObservation {
                tx_index: *tx_idx,
                depth: *depth,
                caller: *creator,
                target: created_address.unwrap_or_default(),
                value: *value,
                input: init_code.clone(),
                output: deployed_code.clone(),
                gas_limit: *gas_limit,
                gas_used: *gas_used,
                success: *success,
                kind: kind.clone(),
                phase: phase.clone(),
                created_address: *created_address,
                result: result.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn b256_from_slot_bytes(slot: &[u8]) -> B256 {
    if slot.len() == 32 {
        B256::from_slice(slot)
    } else {
        B256::from(U256::from_be_slice(slot))
    }
}
