//! Time-warp reachability: a transaction that is impossible in the forked block
//! must become possible after the sequence advances time.
//!
//! The target encodes the shape of a real vesting / timelock guard:
//!
//!   require(block.timestamp >= unlock_at)   // else revert
//!   sstore(0, 1)                            // "withdrawal succeeded"
//!   stop
//!
//! With a static block environment the guard can never pass, so the write is
//! unreachable no matter how the calldata is mutated. This test pins that the
//! per-transaction advance actually lifts the guard, which is the whole point of
//! the feature.

use revm::{
    context::BlockEnv,
    database::CacheDB,
    primitives::{Address, U256},
    state::{AccountInfo, Bytecode},
};
use rustyfuzz_evm::{
    execution::{ChainState, ExecutionStatus},
    inspector::MAP_SIZE,
    time_warp::TimeWarp,
    DataflowRegistry, EvmExecutor, ForkDb, SingletonTx,
};

/// A real post-Cancun mainnet block, so the pinned environment has basefee,
/// prevrandao and blob pricing active. Forking at block 1 would exercise
/// Frontier semantics where those fields are unactivated.
const FORK_BLOCK: u64 = 21_000_000;
const FORK_TIMESTAMP: u64 = 1_716_000_000;
const UNLOCK_AT: u64 = FORK_TIMESTAMP + 3_600; // one hour after the fork block

fn target() -> Address {
    Address::repeat_byte(0x22)
}

fn caller() -> Address {
    Address::repeat_byte(0x11)
}

/// Runtime bytecode for `require(block.timestamp >= UNLOCK_AT); sstore(0, 1)`.
///
/// Stack order matters for the comparison. EVM `LT` computes `a < b` where `a`
/// is the **top** operand, so the sequence is:
///
///   PUSH8 UNLOCK_AT     // stack: [UNLOCK_AT]
///   TIMESTAMP           // stack: [ts, UNLOCK_AT]  (ts on top)
///   LT                  // ts < UNLOCK_AT
///   PUSH1 revert
///   JUMPI               // revert while still locked
fn timelock_code() -> Vec<u8> {
    let mut code = Vec::new();
    // PUSH8 <UNLOCK_AT>
    code.push(0x67);
    code.extend_from_slice(&UNLOCK_AT.to_be_bytes());
    code.push(0x42); // TIMESTAMP
    code.push(0x10); // LT -> timestamp < unlock_at
    let jumpi_at = code.len();
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 <revert, patched>
    code.push(0x57); // JUMPI
    code.extend_from_slice(&[0x60, 0x01, 0x60, 0x00]); // PUSH1 1, PUSH1 0
    code.push(0x55); // SSTORE
    code.push(0x00); // STOP
    let revert_at = code.len();
    // A valid JUMP destination must be a JUMPDEST (0x5B); jumping anywhere else
    // halts with InvalidJump rather than reverting.
    code.push(0x5b); // JUMPDEST
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00]); // PUSH1 0, PUSH1 0
    code.push(0xfd); // REVERT
    code[jumpi_at + 1] = revert_at as u8;
    code
}

fn fixture() -> (ChainState, BlockEnv) {
    let backend = ForkDb::new_offline(format!("0x{FORK_BLOCK:x}"));
    backend.set_provenance_chain(1, Some(format!("0x{}", "42".repeat(32))), 1);
    let mut db = CacheDB::new(backend);
    db.insert_account_info(
        caller(),
        AccountInfo {
            balance: U256::from(10u128.pow(24)),
            ..Default::default()
        },
    );
    db.insert_account_info(
        target(),
        AccountInfo::default().with_code(Bytecode::new_raw(timelock_code().into())),
    );

    let mut env = BlockEnv {
        number: U256::from(FORK_BLOCK),
        // Forked one hour before the unlock.
        timestamp: U256::from(FORK_TIMESTAMP),
        basefee: 1_000_000_000,
        gas_limit: 30_000_000,
        // Post-Merge headers must carry prevrandao.
        prevrandao: Some(revm::primitives::B256::repeat_byte(0x11)),
        ..Default::default()
    };
    env.set_blob_excess_gas_and_price(0, 3_338_477);

    (ChainState::Evm(db), env)
}

fn transaction() -> SingletonTx {
    SingletonTx {
        caller: caller(),
        to: target(),
        input: Vec::new(),
        value: U256::ZERO,
        is_victim: false,
    }
}

fn withdraw_state(state: &ChainState) -> Option<U256> {
    let ChainState::Evm(db) = state;
    db.cache
        .accounts
        .get(&target())
        .and_then(|account| account.storage.get(&U256::ZERO).copied())
}

/// Runs a three-transaction sequence and returns the status of each.
fn run_sequence(time_warp: TimeWarp) -> Vec<ExecutionStatus> {
    let (base, env) = fixture();
    let executor = EvmExecutor::exploration();
    let mut state = base;
    let mut coverage = vec![0u8; MAP_SIZE];
    let mut dataflow = DataflowRegistry::new();
    let mut statuses = Vec::new();

    for tx_idx in 0..3 {
        let mut tx_env = env.clone();
        time_warp.apply(&mut tx_env, tx_idx);
        let mut waypoints = Vec::new();
        let result = executor
            .execute_with_result(
                &mut state,
                &mut tx_env,
                &transaction(),
                &mut coverage,
                &mut dataflow,
                &mut waypoints,
                tx_idx,
            )
            .expect("execution must not fail at the backend level");
        statuses.push(result.status);
    }

    // The guarantee that matters: after the sequence, the guard has been lifted
    // and the protected write committed.
    if time_warp.is_noop() {
        assert_eq!(
            withdraw_state(&state),
            None,
            "without a time warp the guarded write must stay unreachable"
        );
    } else {
        assert_eq!(
            withdraw_state(&state),
            Some(U256::from(1)),
            "with a time warp the guarded write must commit"
        );
    }
    statuses
}

#[test]
fn static_block_environment_makes_the_timelock_unreachable() {
    let statuses = run_sequence(TimeWarp::NONE);
    // Every transaction reverts on the guard; the bug class is unreachable.
    assert!(statuses
        .iter()
        .all(|status| *status == ExecutionStatus::Revert));
}

#[test]
fn advancing_time_lifts_the_timelock_guard() {
    // 3 transactions x 1800s = 5400s > 3600s needed, so a later transaction
    // succeeds where none could before.
    let statuses = run_sequence(TimeWarp::from_seconds(1_800, 1));
    assert_eq!(statuses[0], ExecutionStatus::Revert);
    assert!(statuses.contains(&ExecutionStatus::Success));
}

#[test]
fn default_policy_reaches_an_hourly_timelock_within_a_short_sequence() {
    // The default must be useful at the sequence lengths campaigns actually use.
    // A 12-second slot time would need 300 transactions to clear an hour, which
    // no fuzzed sequence reaches; one hour per transaction clears it in two.
    let statuses = run_sequence(TimeWarp::DEFAULT);
    assert_eq!(statuses[0], ExecutionStatus::Revert);
    assert!(statuses.contains(&ExecutionStatus::Success));
}
