use crate::dataflow::DataflowRegistry;
use crate::environment::EnvironmentPolicy;
use crate::execution::{
    bounded_calldata, bounded_returndata, CallKind, CallObservation, CallPhase, ChainState,
    ExecutionStatus, StorageAccess, StorageDiff, TxExecutionResult, Waypoint,
    MAX_CALL_TRACE_OBSERVATIONS,
};
use crate::fork_db::ForkDb;
use crate::inspector::CoverageInspector;
use crate::transaction::SingletonTx;

use anyhow::Result;
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, TxEnv};
use revm::database::{CacheDB, DbAccount};
use revm::primitives::{Address, TxKind, B256, U256};
use revm::state::EvmState;
use revm::{Context, DatabaseCommit, InspectEvm, MainBuilder, MainContext};
use std::collections::{HashMap, HashSet};

/// The cache account shape, captured before an exploration-only funding step so
/// it can be restored exactly if the transaction fails validation.
type CachedAccount = DbAccount;

const FUZZ_CALLER_BALANCE_WEI: u128 = 1_000_000_000_000_000_000_000_000_000_000;
const MAX_FUZZ_CALL_VALUE_WEI: u128 = 100_000_000_000_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Exploration,
    Proof,
}

pub struct EvmExecutor {
    mode: ExecutionMode,
}

impl EvmExecutor {
    pub fn new() -> Self {
        Self::exploration()
    }

    pub fn exploration() -> Self {
        EvmExecutor {
            mode: ExecutionMode::Exploration,
        }
    }

    pub fn proof() -> Self {
        EvmExecutor {
            mode: ExecutionMode::Proof,
        }
    }

    pub fn mode(&self) -> ExecutionMode {
        self.mode
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
        // Exploration may advance blocks (time warp), so it resolves an
        // at-or-after-pin policy. Proof requires the exact pinned block: a
        // finding is evidence only if it reproduces on verified state.
        let environment = match self.mode {
            ExecutionMode::Exploration => EnvironmentPolicy::resolve_advancing(&db.db, block_env)?,
            ExecutionMode::Proof => EnvironmentPolicy::resolve(&db.db, block_env)?,
        };

        // Start the per-transaction touched-edge log. The coverage hash below is
        // derived from it instead of scanning the whole map, and the map itself
        // is cleared by the caller per input, so this only resets bookkeeping.
        crate::coverage::begin_transaction();

        // Snapshot the caller's cache entry before *any* database access, because
        // `load_account` itself populates the cache for a previously unseen
        // account. Capturing afterwards would record the post-insertion state
        // and leave a phantom entry behind when validation fails.
        let caller_info_before = db.cache.accounts.get(&tx.caller).cloned();

        let caller_nonce = db.load_account(tx.caller)?.info.nonce;

        // Exploration funds synthetic callers so that REVM validation does not
        // reject a fuzz-generated EOA before the target runs. Proof mode keeps
        // the pinned database untouched. The funding is applied to the live
        // cache and reverted below for every non-successful outcome, so a
        // failed transaction still leaves the caller's state exactly as found.
        if self.mode == ExecutionMode::Exploration {
            fund_fuzz_caller(db, tx.caller)?;
        }
        let executed_value = match self.mode {
            ExecutionMode::Exploration => {
                // Prevent mutated transaction values from producing impossible payments or
                // overflow-payment validation failures before useful contract execution.
                bounded_tx_value(tx.value)
            }
            ExecutionMode::Proof => tx.value,
        };

        let tx_env = TxEnv {
            caller: tx.caller,
            gas_limit: environment.tx_gas_limit,
            gas_price: environment.tx_gas_price,
            chain_id: Some(environment.chain_id),
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

        // The database is borrowed rather than deep-cloned. `inspect_tx` only
        // finalizes the journal and hands back the touched state; it does not
        // commit. A previous implementation cloned the entire `CacheDB` per
        // transaction to guarantee that validation errors left caller state
        // intact; that made cost proportional to cache size (measured 86x
        // slowdown at 50k slots) for a property that can be enforced by
        // reverting the one account we mutated.
        // Seed the uninitialized-read heuristic once per sequence, before the
        // database is mutably borrowed by the EVM context. Slots written during
        // execution are recorded by the inspector as it goes.
        let seed_slots = if dataflow.initialized_slots.is_empty() {
            seeded_storage_slots(db)
        } else {
            HashSet::new()
        };

        let outcome = {
            let ctx = Context::mainnet()
                .with_db(&mut *db)
                .with_cfg(environment.cfg()?)
                .with_block(environment.block(block_env));

            let mut evm =
                ctx.build_mainnet_with_inspector(CoverageInspector::with_initialized_slots(
                    coverage, dataflow, waypoints, tx_idx, seed_slots,
                ));

            // Finalized REVM state contains original slot values and excludes
            // writes rolled back by reverted frames. Waypoints remain attempted
            // operation telemetry and must never define committed state.
            evm.inspect_tx(tx_env)
        };

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                // Execution-level failure (validation, database error). Restore
                // the caller account to its pre-transaction shape so nothing
                // leaks into the caller's state, then propagate.
                restore_account(db, tx.caller, caller_info_before);
                return Err(error.into());
            }
        };

        let storage_diffs = committed_storage_diffs(&outcome.state, waypoints, tx_idx);
        db.commit(outcome.state);
        let result = outcome.result;

        let gas_used = result.tx_gas_used();

        let status = match &result {
            ExecutionResult::Success { .. } => ExecutionStatus::Success,
            ExecutionResult::Revert { .. } => ExecutionStatus::Revert,
            ExecutionResult::Halt { reason, .. } => ExecutionStatus::Halt(format!("{reason:?}")),
        };

        let output = result
            .output()
            .map(|bytes| canonical_execution_output(bytes))
            .unwrap_or_default();

        let coverage_hash = crate::coverage::transaction_path_hash(coverage);
        let coverage_edges = crate::coverage::transaction_edge_count();
        let waypoints = waypoints.clone();
        let storage_reads = storage_reads_from_waypoints(&waypoints);
        let storage_writes = storage_writes_from_waypoints(&waypoints);
        let mut call_trace =
            call_trace_from_waypoints(&waypoints, MAX_CALL_TRACE_OBSERVATIONS.saturating_sub(1));

        call_trace.insert(
            0,
            CallObservation {
                tx_index: tx_idx,
                depth: 0,
                caller: tx.caller,
                target: tx.to,
                value: executed_value,
                input: bounded_calldata(&tx.input),
                output: bounded_returndata(&output),
                gas_limit: environment.tx_gas_limit,
                gas_used,
                success: matches!(status, ExecutionStatus::Success),
                kind: CallKind::Transaction,
                phase: CallPhase::End,
                created_address: None,
                result: Some(format!("{status:?}")),
            },
        );

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

fn canonical_execution_output(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

fn fund_fuzz_caller(db: &mut CacheDB<ForkDb>, caller: Address) -> Result<()> {
    let balance = U256::from(FUZZ_CALLER_BALANCE_WEI);
    let mut info = db.load_account(caller)?.info.clone();
    if info.balance < balance {
        info.balance = balance;
        // Inserting also marks a previously absent account as existing; merely
        // changing its balance would leave CacheDB::basic returning None.
        db.insert_account_info(caller, info);
    }
    Ok(())
}

fn bounded_tx_value(value: U256) -> U256 {
    let max_value = U256::from(MAX_FUZZ_CALL_VALUE_WEI);

    if value > max_value {
        max_value
    } else {
        value
    }
}

/// Storage slots that the pinned fork database already holds for accounts in the
/// cache.
///
/// This is the per-sequence seed for the uninitialized-read heuristic. It is
/// computed from the cache's account list once per sequence instead of once per
/// transaction. Slot *presence* is what the heuristic reads, so cached zero
/// values are included exactly as the previous per-transaction scan included
/// them; only the timing of the scan changed.
fn seeded_storage_slots(db: &CacheDB<ForkDb>) -> HashSet<(Address, B256)> {
    let mut slots = HashSet::new();
    for (address, account) in &db.cache.accounts {
        for slot in account.storage.keys() {
            slots.insert((*address, B256::from(*slot)));
        }
    }
    slots
}

/// Undo the exploration-only caller funding after a failed transaction.
///
/// `fund_fuzz_caller` only ever raises the balance of an account that already
/// failed validation, and `inspect_tx` does not commit on error, so the cache
/// entry is restored to its exact previous shape (including absence from the
/// cache) to keep failed transactions observationally invisible.
fn restore_account(db: &mut CacheDB<ForkDb>, caller: Address, previous: Option<CachedAccount>) {
    match previous {
        Some(account) => {
            db.cache.accounts.insert(caller, account);
        }
        None => {
            // The caller was absent from the cache before funding. Removing the
            // entry restores that observation instead of leaving a phantom
            // funded account behind.
            db.cache.accounts.remove(&caller);
        }
    }
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

fn committed_storage_diffs(
    state: &EvmState,
    waypoints: &[Waypoint],
    tx_index: usize,
) -> Vec<StorageDiff> {
    let write_pcs: HashMap<_, _> = storage_writes_from_waypoints(waypoints)
        .into_iter()
        .filter(|write| write.tx_index == tx_index)
        .map(|write| ((write.address, write.slot, write.value), write.pc))
        .collect();
    let mut diffs = Vec::new();
    for (address, account) in state {
        if !account.is_touched() || account.is_selfdestructed() {
            continue;
        }
        for (slot, value) in account.changed_storage_slots() {
            let slot = B256::from(*slot);
            diffs.push(StorageDiff {
                tx_index,
                address: *address,
                slot,
                old_value: value.original_value(),
                new_value: value.present_value(),
                // PC is best-effort telemetry: bounded waypoints can omit it.
                pc: write_pcs
                    .get(&(*address, slot, Some(value.present_value())))
                    .copied()
                    .unwrap_or_default(),
            });
        }
    }
    diffs.sort_by_key(|diff| (diff.address, diff.slot));
    diffs
}

fn call_trace_from_waypoints(waypoints: &[Waypoint], max_entries: usize) -> Vec<CallObservation> {
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
                input: bounded_calldata(input),
                output: bounded_returndata(output),
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
                input: bounded_calldata(init_code),
                output: bounded_returndata(deployed_code),
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
        .take(max_entries)
        .collect()
}

fn b256_from_slot_bytes(slot: &[u8]) -> B256 {
    if slot.len() == 32 {
        B256::from_slice(slot)
    } else {
        B256::from(U256::from_be_slice(slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{
        bounded_calldata, bounded_returndata, MAX_CALLDATA_TELEMETRY_BYTES,
        MAX_RETURN_DATA_TELEMETRY_BYTES,
    };

    fn call_waypoint(input: Vec<u8>, output: Vec<u8>) -> Waypoint {
        Waypoint::CallTrace {
            tx_idx: 0,
            depth: 1,
            caller: Address::ZERO,
            target: Address::ZERO,
            value: U256::ZERO,
            input,
            output,
            gas_limit: 1,
            gas_used: 0,
            success: true,
            kind: CallKind::Call,
            phase: CallPhase::End,
            result: None,
        }
    }

    #[test]
    fn call_trace_conversion_is_bounded_and_preserves_input_order() {
        let waypoints = vec![
            call_waypoint(vec![1], vec![2]),
            call_waypoint(vec![3], vec![4]),
            call_waypoint(vec![5], vec![6]),
        ];

        let observations = call_trace_from_waypoints(&waypoints, 2);

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].input, vec![1]);
        assert_eq!(observations[0].output, vec![2]);
        assert_eq!(observations[1].input, vec![3]);
    }

    #[test]
    fn call_trace_conversion_bounds_calldata_and_returndata() {
        let input = vec![0xAA; MAX_CALLDATA_TELEMETRY_BYTES + 1];
        let output = vec![0xBB; MAX_RETURN_DATA_TELEMETRY_BYTES + 1];
        let waypoints = vec![call_waypoint(input.clone(), output.clone())];

        let observations = call_trace_from_waypoints(&waypoints, 1);

        assert_eq!(observations[0].input, bounded_calldata(&input));
        assert_eq!(observations[0].output, bounded_returndata(&output));
    }

    #[test]
    fn canonical_output_distinguishes_results_differing_after_4096_bytes() {
        let first = vec![0x11; MAX_RETURN_DATA_TELEMETRY_BYTES + 1];
        let mut second = first.clone();
        second[MAX_RETURN_DATA_TELEMETRY_BYTES] = 0x22;

        let first_output = canonical_execution_output(&first);
        let second_output = canonical_execution_output(&second);

        assert_eq!(first_output, first);
        assert_ne!(first_output, second_output);
    }
}
