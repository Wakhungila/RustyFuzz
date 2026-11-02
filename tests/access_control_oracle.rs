//! Access-control oracle reachability.
//!
//! The oracle recognises a compromised contract in two ways: the value written
//! equals the attacker address in the EIP-1967 admin slot, or it equals the
//! attacker address in a slot that was *influenced* (whose value flows from
//! attacker-controlled input) and was then written.
//!
//! The second path depends on the inspector emitting a `Dataflow { influenced:
//! true }` waypoint. Nothing emitted one before, so any ownership slot outside
//! the EIP-1967 layout — `address public owner` at slot 0, `Ownable`-style
//! `_owner`, custom `governor` variables — could never be reported. These tests
//! pin both that the waypoint is produced and that the oracle fires because of
//! it.

use revm::{
    context::BlockEnv,
    database::CacheDB,
    primitives::{Address, B256, U256},
    state::{AccountInfo, Bytecode},
};
use rusty_fuzz::common::oracle::{AccessControlOracle, VulnerabilityOracle};
use rusty_fuzz::common::types::{ChainState, Snapshot, Waypoint};
use rustyfuzz_evm::{inspector::MAP_SIZE, DataflowRegistry, EvmExecutor, ForkDb, SingletonTx};
use std::sync::Arc;

/// A real post-Cancun mainnet block so basefee/prevrandao/blob fields are active.
const FORK_BLOCK: u64 = 21_000_000;
const FORK_TIMESTAMP: u64 = 1_716_000_000;
/// keccak256("pick()")[0..4]
const PICKED_SELECTOR: [u8; 4] = [0x0e, 0x89, 0x9d, 0x8b];

fn target() -> Address {
    Address::repeat_byte(0x22)
}

/// The attacker: an address the fuzzer controls, distinguished from the caller
/// used in the bytecode so the assertion cannot pass by coincidence.
fn attacker() -> Address {
    Address::repeat_byte(0xAA)
}

fn caller() -> Address {
    Address::repeat_byte(0x11)
}

/// `function pick() external { owner = msg.sender; }`
///
/// Equivalent to:
///   CALLER            // value  = msg.sender
///   PUSH1 0           // slot   = 0  (top)
///   SSTORE            // owner  = msg.sender
///   STOP
fn setter_code() -> Vec<u8> {
    vec![0x33, 0x60, 0x00, 0x55, 0x00]
}

fn env() -> BlockEnv {
    let mut env = BlockEnv {
        number: U256::from(FORK_BLOCK),
        timestamp: U256::from(FORK_TIMESTAMP),
        basefee: 1_000_000_000,
        gas_limit: 30_000_000,
        prevrandao: Some(B256::repeat_byte(0x11)),
        ..Default::default()
    };
    env.set_blob_excess_gas_and_price(0, 3_338_477);
    env
}

/// Runs the setter and returns the post-state snapshot plus the waypoints the
/// inspector produced.
fn run_setter() -> (ChainState, Vec<Waypoint>) {
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
        AccountInfo::default().with_code(Bytecode::new_raw(setter_code().into())),
    );

    let mut state = ChainState::Evm(db);
    let mut block = env();
    let mut coverage = vec![0u8; MAP_SIZE];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();
    let mut calldata = PICKED_SELECTOR.to_vec();

    EvmExecutor::exploration()
        .execute_with_result(
            &mut state,
            &mut block,
            &SingletonTx {
                caller: caller(),
                to: target(),
                input: std::mem::take(&mut calldata),
                value: U256::ZERO,
                is_victim: false,
            },
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("setter execution must succeed");

    (state, waypoints)
}

fn snapshot_of(state: ChainState, waypoints: Vec<Waypoint>) -> Snapshot {
    Snapshot {
        id: 1,
        state: Arc::new(parking_lot::RwLock::new(state)),
        coverage: bitvec::bitvec![u8, bitvec::prelude::Lsb0; 0; MAP_SIZE],
        producing_input: None,
        waypoints,
        depth: 0,
        gas_used: 0,
    }
}

#[test]
fn ownership_write_from_msg_sender_is_reported_as_influenced() {
    let (state, waypoints) = run_setter();

    // The write committed: slot 0 now holds the caller.
    let ChainState::Evm(db) = &state;
    let stored = db.cache.accounts[&target()].storage[&U256::ZERO];
    let mut expected = [0u8; 32];
    expected[12..].copy_from_slice(caller().as_slice());
    assert_eq!(stored, U256::from_be_bytes(expected));

    // And it was labelled influenced, which is what the oracle needs.
    let influenced_slot_zero = waypoints.iter().any(|waypoint| {
        matches!(
            waypoint,
            Waypoint::Dataflow {
                address,
                slot,
                influenced: true,
            } if *address == target() && slot == &[0u8; 32].to_vec()
        )
    });
    assert!(
        influenced_slot_zero,
        "the inspector must emit an influenced dataflow waypoint for a slot written \
         from msg.sender; without it access-control findings on non-EIP-1967 \
         ownership slots are unreachable. waypoints: {waypoints:#?}"
    );
}

#[test]
fn oracle_detects_ownership_takeover_the_attacker_performed() {
    // The attacker address is the one the oracle looks for. Run the setter as the
    // attacker so the committed owner equals it.
    let backend = ForkDb::new_offline(format!("0x{FORK_BLOCK:x}"));
    backend.set_provenance_chain(1, Some(format!("0x{}", "42".repeat(32))), 1);
    let mut db = CacheDB::new(backend);
    db.insert_account_info(
        attacker(),
        AccountInfo {
            balance: U256::from(10u128.pow(24)),
            ..Default::default()
        },
    );
    db.insert_account_info(
        target(),
        AccountInfo::default().with_code(Bytecode::new_raw(setter_code().into())),
    );

    let mut state = ChainState::Evm(db);
    let mut block = env();
    let mut coverage = vec![0u8; MAP_SIZE];
    let mut dataflow = DataflowRegistry::new();
    let mut waypoints = Vec::new();
    EvmExecutor::exploration()
        .execute_with_result(
            &mut state,
            &mut block,
            &SingletonTx {
                caller: attacker(),
                to: target(),
                input: PICKED_SELECTOR.to_vec(),
                value: U256::ZERO,
                is_victim: false,
            },
            &mut coverage,
            &mut dataflow,
            &mut waypoints,
            0,
        )
        .expect("setter execution must succeed");

    let before = snapshot_of(ChainState::Evm(CacheDB::new(ForkDb::empty())), Vec::new());
    let after = snapshot_of(state, waypoints);

    let oracle = AccessControlOracle {
        fuzzer_address: attacker(),
    };
    let finding = oracle.check(&before, &after);
    assert_eq!(
        finding,
        Some(rusty_fuzz::common::oracle::VulnType::PrivilegeEscalation),
        "an attacker-written owner at slot 0 must be reported as privilege escalation"
    );
}

#[test]
fn oracle_does_not_fire_when_the_owner_is_not_the_attacker() {
    // Same execution, but the oracle is looking for a different attacker
    // address: no finding. This guards against a vacuous test.
    let (state, waypoints) = run_setter();
    let before = snapshot_of(ChainState::Evm(CacheDB::new(ForkDb::empty())), Vec::new());
    let after = snapshot_of(state, waypoints);

    let oracle = AccessControlOracle {
        fuzzer_address: attacker(),
    };
    assert_eq!(
        oracle.check(&before, &after),
        None,
        "the owner is the benign caller, not the attacker"
    );
}
