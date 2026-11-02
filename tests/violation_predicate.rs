use revm::{
    database::CacheDB,
    primitives::{keccak256, Address, U256},
    state::{AccountInfo, Bytecode},
};
use rusty_fuzz::{
    common::{
        oracle::{FindingStatus, ProtocolOraclePack},
        types::{ChainState, EvmInput, SingletonTx},
        verifier::{RealismVerifier, ViolationPredicate},
    },
    evm::fork::create_offline_fallback_block_env,
};
use rustyfuzz_evm::fork_db::ForkDb;

fn fixture(safe: bool) -> (ChainState, EvmInput) {
    let caller = Address::repeat_byte(0x11);
    let target = Address::repeat_byte(0x22);
    // Minimal executable token: balanceOf reads slot zero, canMint returns false,
    // mint either increments the balance or rejects the unauthorized caller.
    let mut code = vec![0x5f, 0x35, 0x60, 0xe0, 0x1c, 0x80, 0x63];
    code.extend_from_slice(&keccak256("balanceOf(address)")[..4]);
    code.extend_from_slice(&[0x14, 0x60, 0, 0x57, 0x80, 0x63]);
    let balance_jump = 13;
    code.extend_from_slice(&keccak256("mint(address,uint256)")[..4]);
    code.extend_from_slice(&[0x14, 0x60, 0, 0x57]);
    let mint_jump = 23;
    code.extend_from_slice(&[0x5f, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
    code[balance_jump] = code.len() as u8;
    code.extend_from_slice(&[0x5b, 0x5f, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
    code[mint_jump] = code.len() as u8;
    code.push(0x5b);
    if safe {
        code.extend_from_slice(&[0x5f, 0x5f, 0xfd]);
    } else {
        code.extend_from_slice(&[0x60, 1, 0x5f, 0x55, 0x00]);
    }
    let mut db = CacheDB::new(ForkDb::empty());
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(24)),
            ..Default::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
    );
    let calldata = |sig: &str, mint: bool| {
        let mut data = keccak256(sig)[..4].to_vec();
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(caller.as_slice());
        if mint {
            data.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        }
        data
    };
    let tx = |data| SingletonTx {
        caller,
        to: target,
        value: U256::ZERO,
        input: data,
        is_victim: false,
    };
    (
        ChainState::Evm(db),
        EvmInput {
            base_snapshot_id: 0,
            txs: vec![
                tx(calldata("balanceOf(address)", false)),
                tx(calldata("canMint(address)", false)),
                tx(calldata("mint(address,uint256)", true)),
                tx(calldata("balanceOf(address)", false)),
            ],
        },
    )
}

#[test]
fn denied_mint_predicate_proves_violation_and_rejects_safe_counterpart() {
    let (state, input) = fixture(false);
    let env = create_offline_fallback_block_env(1);
    let verifier = RealismVerifier::new(65536);
    let replay = verifier.prove(&state, &env, &input);
    assert_eq!(replay.status, FindingStatus::Replayed);
    let execution = replay.execution.unwrap();
    let findings = ProtocolOraclePack::default().evaluate(&execution);
    let predicate = findings
        .iter()
        .find_map(|finding| ViolationPredicate::from_finding(finding, &execution))
        .expect("concrete denied policy and balance increase");
    assert_eq!(
        verifier
            .prove_violation(&state, &env, &input, &predicate)
            .status,
        FindingStatus::Proved
    );
    let (safe_state, safe_input) = fixture(true);
    assert!(
        !verifier
            .prove_violation(&safe_state, &env, &safe_input, &predicate)
            .success
    );
    let mut changed = input.clone();
    changed.txs[2].caller = Address::repeat_byte(0x33);
    assert!(
        !verifier
            .prove_violation(&state, &env, &changed, &predicate)
            .success
    );
    let mut removed = input.clone();
    removed.txs.remove(1);
    assert!(
        !verifier
            .prove_violation(&state, &env, &removed, &predicate)
            .success
    );
    let mut nonroot = input.clone();
    nonroot.base_snapshot_id = 1;
    assert_eq!(
        verifier.prove(&state, &env, &nonroot).status,
        FindingStatus::Rejected
    );
    for tx_index in [1, 2, 3] {
        let mut other_target = input.clone();
        other_target.txs[tx_index].to = Address::repeat_byte(0x44);
        let report = verifier.prove_violation(&state, &env, &other_target, &predicate);
        assert!(!report.success);
        assert_eq!(report.status, FindingStatus::Rejected);
    }
    let dir = std::env::temp_dir().join(format!("rustyfuzz-predicate-{}", uuid::Uuid::new_v4()));
    let path = rusty_fuzz::engine::exploit_synthesizer::synthesize_foundry_poc_with_findings(
        &input,
        &findings[0].vuln,
        Some(&execution),
        &findings,
        &dir,
        "",
        1,
    )
    .unwrap();
    let generated = std::fs::read_to_string(path).unwrap();
    assert!(generated.contains("mint policy did not deny actor"));
    assert!(generated.contains("denied mint did not increase recipient balance"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn proof_replay_uses_funds_received_during_earlier_transactions() {
    let first = Address::repeat_byte(0x11);
    let second = Address::repeat_byte(0x12);
    let recipient = Address::repeat_byte(0x13);
    let mut db = CacheDB::new(ForkDb::empty());
    db.insert_account_info(
        first,
        AccountInfo {
            balance: U256::from(10u128.pow(24)),
            ..Default::default()
        },
    );
    let input = EvmInput::new(
        vec![
            SingletonTx {
                caller: first,
                to: second,
                value: U256::from(10u128.pow(20)),
                input: vec![],
                is_victim: false,
            },
            SingletonTx {
                caller: second,
                to: recipient,
                value: U256::from(10u128.pow(18)),
                input: vec![],
                is_victim: false,
            },
        ],
        0,
    );
    let report = RealismVerifier::new(1024).prove(
        &ChainState::Evm(db),
        &create_offline_fallback_block_env(1),
        &input,
    );
    assert!(report.success, "{report:?}");
    assert_eq!(report.status, FindingStatus::Replayed);
}

fn denied_mint_predicate(state: &ChainState, input: &EvmInput) -> ViolationPredicate {
    let execution = RealismVerifier::new(65536)
        .prove(state, &create_offline_fallback_block_env(1), input)
        .execution
        .unwrap();
    ProtocolOraclePack::default()
        .evaluate(&execution)
        .iter()
        .find_map(|finding| ViolationPredicate::from_finding(finding, &execution))
        .unwrap()
}

#[test]
fn predicate_binds_target_actor_policy_and_recipient() {
    let (state, input) = fixture(false);
    let predicate = denied_mint_predicate(&state, &input);
    let verifier = RealismVerifier::new(65536);
    let env = create_offline_fallback_block_env(1);
    let mut variants = Vec::new();
    let mut target = input.clone();
    target.txs[2].to = Address::repeat_byte(0x44);
    variants.push(target);
    let mut actor = input.clone();
    actor.txs[1].input[35] ^= 1;
    variants.push(actor);
    let mut policy = input.clone();
    policy.txs[1].input[..4].copy_from_slice(&keccak256("isMinter(address)")[..4]);
    variants.push(policy);
    let mut recipient = input.clone();
    recipient.txs[2].input[35] ^= 1;
    variants.push(recipient);
    for changed in variants {
        let result = verifier.prove_violation(&state, &env, &changed, &predicate);
        assert!(!result.success);
        assert_eq!(result.status, FindingStatus::Rejected);
    }
}

#[test]
fn proof_rejects_snapshot_suffix_without_root_lineage() {
    let (state, mut input) = fixture(false);
    input.base_snapshot_id = 7;
    let result =
        RealismVerifier::new(65536).prove(&state, &create_offline_fallback_block_env(1), &input);
    assert!(!result.success);
    assert_eq!(result.status, FindingStatus::Rejected);
}

#[test]
fn proof_accepts_later_caller_funded_by_previous_transaction() {
    let (state, _) = fixture(false);
    let first = Address::repeat_byte(0x11);
    let second = Address::repeat_byte(0x66);
    let input = EvmInput::new(
        vec![
            SingletonTx {
                caller: first,
                to: second,
                value: U256::from(10u128.pow(18)),
                input: vec![],
                is_victim: false,
            },
            SingletonTx {
                caller: second,
                to: Address::repeat_byte(0x77),
                value: U256::from(10u128.pow(17)),
                input: vec![],
                is_victim: false,
            },
        ],
        0,
    );
    let result =
        RealismVerifier::new(65536).prove(&state, &create_offline_fallback_block_env(1), &input);
    assert!(result.success, "{:?}", result.rejection_reasons);
    assert_eq!(result.status, FindingStatus::Replayed);
}

#[test]
fn proof_minimizer_preserves_the_original_concrete_predicate() {
    let (state, input) = fixture(false);
    let predicate = denied_mint_predicate(&state, &input);
    let ChainState::Evm(db) = state.clone();
    let executor = rustyfuzz_evm::executor::EvmExecutor::proof();
    let oracle = rusty_fuzz::common::oracle::security::PanicOracle;
    let minimizer = rusty_fuzz::engine::minimizer::Minimizer::new(
        &executor,
        &oracle,
        db,
        create_offline_fallback_block_env(1),
    );
    let mut redundant = input.clone();
    redundant.txs.insert(0, input.txs[0].clone());
    let minimized = minimizer
        .minimize_crash(&redundant, |execution| predicate.holds(execution))
        .unwrap();
    assert_eq!(minimized.txs.len(), 4);
    assert_eq!(minimized.txs, input.txs);
    assert!(
        RealismVerifier::new(65536)
            .prove_violation(
                &state,
                &create_offline_fallback_block_env(1),
                &minimized,
                &predicate,
            )
            .success
    );
}
