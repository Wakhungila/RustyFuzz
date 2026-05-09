use rusty_fuzz::common::oracle::{VulnerabilityOracle, ReentrancyOracle, ERC4626InflationOracle, PrivilegeEscalationOracle, VulnType};
use rusty_fuzz::common::types::{Snapshot, ChainState, Waypoint, SingletonTx, EvmInput};
use rusty_fuzz::evm::snapshot::new_evm_snapshot;
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{Address, U256, AccountInfo, Bytecode, B256};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::{HashSet, HashMap};

#[tokio::test]
async fn benchmark_reentrancy_detection() {
    let mut db = CacheDB::new(EmptyDB::default());
    let target_addr = Address::random();
    
    // Setup: A contract state where storage was modified at depth > 1
    let mut acc_info = AccountInfo::default();
    acc_info.code = Some(Bytecode::new_raw(vec![0x00].into()));
    db.insert_account_info(target_addr, acc_info);

    let before = new_evm_snapshot(0, db.clone());
    
    // Simulate a reentrant state change
    db.insert_account_storage(target_addr, U256::ZERO, U256::from(1)).unwrap();
    let mut after = new_evm_snapshot(1, db);
    after.depth = 2; // Indicator of nested call

    let oracle = ReentrancyOracle;
    let result = oracle.check(&before, &after);
    
    assert!(matches!(result, Some(VulnType::Reentrancy)), "Failed to detect reentrancy");
}

#[tokio::test]
async fn benchmark_erc4626_inflation_detection() {
    let mut db = CacheDB::new(EmptyDB::default());
    let vault_addr = Address::random();
    
    // Setup: Initial state (100 assets, 100 shares -> price 1:1)
    db.insert_account_storage(vault_addr, U256::ZERO, U256::from(100)).unwrap(); // totalSupply
    db.insert_account_storage(vault_addr, U256::from(1), U256::from(100)).unwrap(); // totalAssets
    let before = new_evm_snapshot(0, db.clone());

    // Exploit: Donation attack doubles the price per share
    db.insert_account_storage(vault_addr, U256::from(1), U256::from(300)).unwrap(); 
    let after = new_evm_snapshot(1, db);

    let oracle = ERC4626InflationOracle { vault: vault_addr };
    let result = oracle.check(&before, &after);
    
    assert!(matches!(result, Some(VulnType::VaultInflation)), "Failed to detect donation-based inflation");
}

#[tokio::test]
async fn benchmark_privilege_escalation() {
    let mut db = CacheDB::new(EmptyDB::default());
    let target_addr = Address::random();
    let fuzzer_addr = Address::random();
    
    let before = new_evm_snapshot(0, db.clone());
    
    // Simulate unauthorized SSTORE to an 'owner' slot (0x0)
    db.insert_account_storage(target_addr, U256::ZERO, U256::from_be_slice(fuzzer_addr.as_slice())).unwrap();
    
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

    let registry = Arc::new(RwLock::new(rusty_fuzz::evm::registry::GlobalAccountRegistry::default()));
    let oracle = PrivilegeEscalationOracle {
        authorized_callers: HashSet::from([Address::random()]), // Fuzzer is NOT authorized
        account_registry: registry,
    };
    
    let result = oracle.check(&before, &after);
    assert!(matches!(result, Some(VulnType::PrivilegeEscalation)), "Failed to detect privilege escalation");
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