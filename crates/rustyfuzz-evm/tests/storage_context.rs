use std::collections::{HashMap, HashSet};

use revm::{
    bytecode::Bytecode,
    context::TxEnv,
    database::CacheDB,
    primitives::{Address, TxKind, B256, U256},
    state::AccountInfo,
    Context, InspectCommitEvm, MainBuilder, MainContext,
};
use rustyfuzz_evm::{
    execution::{SymbolicExpression, TaintSource, Waypoint},
    inspector::CoverageInspector,
    DataflowRegistry, EvmCacheDb, ForkDb,
};

fn address(byte: u8) -> Address {
    Address::from([byte; 20])
}

// Return the CALL/DELEGATECALL success flag, so failures cannot silently pass.
fn forwarding_code(target: Address, opcode: u8) -> Vec<u8> {
    let mut code = vec![0x5f, 0x5f, 0x5f, 0x5f];
    if opcode == 0xf1 {
        code.push(0x5f); // CALL's value argument
    }
    code.push(0x73); // PUSH20
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[0x5a, opcode, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
    code
}

struct Observations {
    db: EvmCacheDb,
    waypoints: Vec<Waypoint>,
    reads: HashSet<(Address, B256)>,
    writes: HashSet<(Address, B256)>,
    expressions: HashMap<(Address, B256), SymbolicExpression>,
    dataflow: DataflowRegistry,
}

fn execute(
    contracts: &[(Address, Vec<u8>)],
    entry: Address,
    mut dataflow: DataflowRegistry,
) -> Observations {
    let caller = address(0xaa);
    let mut db = CacheDB::new(ForkDb::empty());
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..Default::default()
        },
    );
    for (address, code) in contracts {
        db.insert_account_info(
            *address,
            AccountInfo::default().with_code(Bytecode::new_raw(code.clone().into())),
        );
        db.insert_account_storage(*address, U256::ZERO, U256::from(7))
            .unwrap();
    }

    let mut coverage = vec![0; 1024];
    let mut waypoints = Vec::new();
    let inspector = CoverageInspector::new(&mut coverage, &mut dataflow, &mut waypoints, 1);
    let mut evm = Context::mainnet()
        .with_db(db)
        .build_mainnet_with_inspector(inspector);
    let result = evm
        .inspect_tx_commit(TxEnv {
            caller,
            kind: TxKind::Call(entry),
            gas_limit: 1_000_000,
            gas_price: 1_000_000_000,
            ..Default::default()
        })
        .unwrap();
    assert!(result.is_success(), "execution failed: {result:?}");
    assert_eq!(
        U256::from_be_slice(result.output().unwrap()),
        U256::from(1),
        "forwarded call failed"
    );
    assert!(waypoint_calls_succeeded(evm.inspector.waypoints));

    let reads = evm.inspector.read_set.clone();
    let writes = evm.inspector.write_set.clone();
    let expressions = evm.inspector.storage_expression_map.clone();
    let db = evm.ctx.journaled_state.database;
    Observations {
        db,
        waypoints,
        reads,
        writes,
        expressions,
        dataflow,
    }
}

fn waypoint_calls_succeeded(waypoints: &[Waypoint]) -> bool {
    use rustyfuzz_evm::execution::CallPhase;
    waypoints.iter().all(|waypoint| match waypoint {
        Waypoint::CallTrace {
            phase: CallPhase::End,
            success,
            ..
        } => *success,
        _ => true,
    })
}

fn assert_persistent_storage_context(opcode: u8, nested: bool) {
    let proxy = address(0x11);
    let implementation = address(0x22);
    let library = address(0x33);
    // Read slot zero (initially 7), then write 9 to it.
    let storage_code = vec![0x5f, 0x54, 0x50, 0x60, 0x09, 0x5f, 0x55, 0x00];
    let mut contracts = vec![(proxy, forwarding_code(implementation, opcode))];
    if nested {
        contracts.push((implementation, forwarding_code(library, 0xf4)));
        contracts.push((library, storage_code));
    } else {
        contracts.push((implementation, storage_code));
    }
    let observations = execute(&contracts, proxy, DataflowRegistry::new());
    let owner = if opcode == 0xf1 {
        implementation
    } else {
        proxy
    };
    let key = (owner, B256::ZERO);
    assert_eq!(observations.reads, HashSet::from([key]));
    assert_eq!(observations.writes, HashSet::from([key]));
    assert!(matches!(
        observations.expressions.get(&key),
        Some(SymbolicExpression::Constant(value)) if *value == U256::from(9)
    ));
    assert_eq!(observations.dataflow.influenced_slots.len(), 1);
    assert!(observations.dataflow.is_influenced(owner, B256::ZERO));
    assert!(observations.waypoints.iter().any(|waypoint| matches!(
        waypoint,
        Waypoint::StorageRead { address, slot, value, .. }
            if (*address, *slot) == key && *value == U256::from(7)
    )));
    assert!(observations.waypoints.iter().any(|waypoint| matches!(
        waypoint,
        Waypoint::StorageWrite { address, value, .. }
            if *address == owner && *value == U256::from(9)
    )));
    for (address, _) in contracts {
        let expected = if address == owner { 9 } else { 7 };
        assert_eq!(
            observations.db.cache.accounts[&address].storage[&U256::ZERO],
            U256::from(expected),
            "unexpected committed storage at {address}"
        );
    }
}

#[test]
fn delegatecall_attributes_persistent_storage_to_proxy() {
    assert_persistent_storage_context(0xf4, false);
}

#[test]
fn call_attributes_persistent_storage_to_callee() {
    assert_persistent_storage_context(0xf1, false);
}

#[test]
fn nested_delegatecall_preserves_outer_storage_context() {
    assert_persistent_storage_context(0xf4, true);
}

#[test]
fn delegatecall_reads_proxy_taint_from_previous_transaction() {
    let proxy = address(0x11);
    let implementation = address(0x22);
    let mut dataflow = DataflowRegistry::new();
    dataflow.mark_storage_symbolic(
        proxy,
        B256::ZERO,
        Some(TaintSource::Storage(0, 32)),
        Some(SymbolicExpression::Source(TaintSource::Calldata(32))),
    );
    let observations = execute(
        &[
            (proxy, forwarding_code(implementation, 0xf4)),
            (implementation, vec![0x5f, 0x54, 0x50, 0x00]),
        ],
        proxy,
        dataflow,
    );
    assert!(observations.waypoints.iter().any(|waypoint| matches!(
        waypoint,
        Waypoint::StorageRead {
            address,
            value,
            taint_source: Some(TaintSource::Storage(0, 32)),
            expression: Some(SymbolicExpression::Source(TaintSource::Calldata(32))),
            ..
        } if *address == proxy && *value == U256::from(7)
    )));
}

#[test]
fn transient_storage_uses_call_storage_context() {
    let proxy = address(0x11);
    let implementation = address(0x22);
    // Store a tainted caller in transient slot zero, then read it.
    let transient_code = vec![0x33, 0x60, 0x00, 0x5d, 0x60, 0x00, 0x5c, 0x50, 0x00];
    for opcode in [0xf1, 0xf4] {
        let observations = execute(
            &[
                (proxy, forwarding_code(implementation, opcode)),
                (implementation, transient_code.clone()),
            ],
            proxy,
            DataflowRegistry::new(),
        );
        let owner = if opcode == 0xf1 {
            implementation
        } else {
            proxy
        };
        let mut reads = 0;
        let mut writes = 0;
        for waypoint in &observations.waypoints {
            match waypoint {
                Waypoint::TransientStorageRead { address, slot, .. } => {
                    assert_eq!((*address, *slot), (owner, B256::ZERO));
                    reads += 1;
                }
                Waypoint::TransientStorageWrite { address, slot, .. } => {
                    assert_eq!((*address, *slot), (owner, B256::ZERO));
                    writes += 1;
                }
                _ => {}
            }
        }
        assert_eq!((reads, writes), (1, 1));
    }
}
