//! Execute fork-sensitive bytecode through the same executor used by campaigns.
use revm::primitives::hardfork::SpecId;
use revm::{
    context::BlockEnv,
    database::CacheDB,
    primitives::{Address, U256},
    state::{AccountInfo, Bytecode},
};
use rustyfuzz_evm::{
    environment::{mainnet_blob_fraction, mainnet_spec, EnvironmentPolicy},
    execution::{ChainState, ExecutionStatus, TxExecutionResult},
    inspector::MAP_SIZE,
    DataflowRegistry, EvmExecutor, ForkDb, SingletonTx,
};

fn run(
    code: &[u8],
    number: u64,
    timestamp: u64,
    basefee: u64,
) -> anyhow::Result<TxExecutionResult> {
    let backend = ForkDb::new_offline(format!("0x{number:x}"));
    backend.set_provenance_chain(1, Some(format!("0x{}", "42".repeat(32))), 1);
    let mut db = CacheDB::new(backend);
    let target = Address::repeat_byte(0x22);
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(code.to_vec().into())),
    );
    let mut state = ChainState::Evm(db);
    let mut env = BlockEnv {
        number: U256::from(number),
        timestamp: U256::from(timestamp),
        basefee,
        gas_limit: 1_000_000,
        ..Default::default()
    };
    if timestamp >= 1_710_338_135 {
        env.set_blob_excess_gas_and_price(8_000_000, 3_338_477);
    }
    EvmExecutor::exploration().execute_with_result(
        &mut state,
        &mut env,
        &SingletonTx {
            caller: Address::repeat_byte(0x11),
            to: target,
            input: vec![],
            value: U256::ZERO,
            is_victim: false,
        },
        &mut vec![0; MAP_SIZE],
        &mut DataflowRegistry::new(),
        &mut vec![],
        0,
    )
}

#[test]
fn push0_is_rejected_before_shanghai_and_enabled_at_activation() {
    let code = [0x5f, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3];
    assert!(matches!(
        run(&code, 17_034_869, 1_681_338_454, 0).unwrap().status,
        ExecutionStatus::Halt(_)
    ));
    let after = run(&code, 17_034_870, 1_681_338_455, 0).unwrap();
    assert_eq!(after.status, ExecutionStatus::Success);
    assert_eq!(after.output, vec![0; 32]);
}

#[test]
fn chainid_opcode_reads_the_pinned_chain() {
    let result = run(
        &[0x46, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3],
        20_000_000,
        1_720_000_000,
        0,
    )
    .unwrap();
    assert_eq!(U256::from_be_slice(&result.output), U256::from(1));
}

#[test]
fn high_basefee_executes_and_observed_gasprice_covers_actual_header_fee() {
    let result = run(
        &[0x3a, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3],
        20_000_000,
        1_720_000_000,
        80_000_000_000,
    )
    .unwrap();
    assert_eq!(result.status, ExecutionStatus::Success);
    assert_eq!(
        U256::from_be_slice(&result.output),
        U256::from(80_000_000_000u64)
    );
    assert_eq!(result.call_trace[0].gas_limit, 1_000_000);
}

#[test]
fn blobbasefee_uses_the_real_nonzero_header_excess() {
    let code = [0x4a, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3];
    let before = run(&code, 19_426_586, 1_710_338_134, 0).unwrap();
    assert!(matches!(before.status, ExecutionStatus::Halt(_)));
    let after = run(&code, 19_426_587, 1_710_338_135, 0).unwrap();
    // EIP-4844 fake_exponential(1, 8_000_000, 3_338_477) = 10.
    assert_eq!(after.status, ExecutionStatus::Success);
    assert_eq!(U256::from_be_slice(&after.output), U256::from(10));
}

#[test]
fn blob_header_excess_survives_and_pricing_tracks_blob_schedule() {
    let backend = ForkDb::new_offline("0x1312d00");
    backend.set_provenance_chain(1, Some(format!("0x{}", "42".repeat(32))), 1);
    let mut env = BlockEnv {
        number: U256::from(20_000_000),
        timestamp: U256::from(1_767_747_671u64),
        ..Default::default()
    };
    env.set_blob_excess_gas_and_price(10_000_000, 3_338_477);
    let policy = EnvironmentPolicy::resolve(&backend, &env).unwrap();
    assert_eq!(policy.blob_base_fee_update_fraction, Some(11_684_671));
    let actual = policy.block(&env).blob_excess_gas_and_price.unwrap();
    assert_eq!(actual.excess_blob_gas, 10_000_000);
    assert!(actual.blob_gasprice < env.blob_excess_gas_and_price.unwrap().blob_gasprice);
    assert_eq!(mainnet_blob_fraction(1_765_290_071), Some(8_346_193));
    assert_eq!(mainnet_blob_fraction(1_746_612_311), Some(5_007_716));
}

#[test]
fn missing_pinned_fields_and_unknown_chains_fail_closed() {
    let backend = ForkDb::new_offline("0x1312d00");
    let env = BlockEnv {
        number: U256::from(20_000_000),
        timestamp: U256::from(1_720_000_000u64),
        ..Default::default()
    };
    backend.set_provenance_chain(10, Some(format!("0x{}", "42".repeat(32))), 1);
    assert!(EnvironmentPolicy::resolve(&backend, &env)
        .unwrap_err()
        .to_string()
        .contains("unsupported chain 10"));
    backend.set_provenance_chain(1, Some(format!("0x{}", "42".repeat(32))), 1);
    let mut mismatched = env.clone();
    mismatched.number += U256::from(1);
    assert!(EnvironmentPolicy::resolve(&backend, &mismatched).is_err());
    let mut missing = env;
    missing.blob_excess_gas_and_price = None;
    assert!(EnvironmentPolicy::resolve(&backend, &missing).is_err());
}

#[test]
fn exploration_may_advance_but_proof_must_replay_the_pinned_block() {
    // Time warp makes later blocks reachable during exploration. That must not
    // leak into proof: a finding is evidence only on the state that was pinned,
    // so the exact-pin policy has to keep rejecting a later block.
    let backend = ForkDb::new_offline("0x1312d00");
    backend.set_provenance_chain(1, Some(format!("0x{}", "42".repeat(32))), 1);
    let mut env = BlockEnv {
        number: U256::from(20_000_000),
        timestamp: U256::from(1_720_000_000u64),
        ..Default::default()
    };
    env.set_blob_excess_gas_and_price(8_000_000, 3_338_477);
    env.prevrandao = Some(revm::primitives::B256::repeat_byte(0x11));

    // Pinned block: both policies agree.
    assert!(EnvironmentPolicy::resolve(&backend, &env).is_ok());
    assert!(EnvironmentPolicy::resolve_advancing(&backend, &env).is_ok());

    // A later block: exploration allows it, proof does not.
    let mut advanced = env.clone();
    advanced.number += U256::from(1);
    advanced.timestamp += U256::from(3_600u64);
    assert!(EnvironmentPolicy::resolve_advancing(&backend, &advanced).is_ok());
    let error = EnvironmentPolicy::resolve(&backend, &advanced).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("differs from pinned fork provenance"),
        "unexpected error: {error}"
    );

    // An earlier block is never allowed: the pin never observed that state.
    let mut earlier = env.clone();
    earlier.number -= U256::from(1);
    assert!(EnvironmentPolicy::resolve_advancing(&backend, &earlier).is_err());
    assert!(EnvironmentPolicy::resolve(&backend, &earlier).is_err());

    // Advancing implausibly far past the pin demands headers that do not exist.
    let mut far_future = env;
    far_future.number += U256::from(500_000);
    assert!(EnvironmentPolicy::resolve_advancing(&backend, &far_future).is_err());
}

#[test]
fn activation_boundaries_are_explicit() {
    for (number, before, after) in [
        (1_150_000, SpecId::FRONTIER, SpecId::HOMESTEAD),
        (2_463_000, SpecId::HOMESTEAD, SpecId::TANGERINE),
        (2_675_000, SpecId::TANGERINE, SpecId::SPURIOUS_DRAGON),
        (4_370_000, SpecId::SPURIOUS_DRAGON, SpecId::BYZANTIUM),
        (7_280_000, SpecId::BYZANTIUM, SpecId::PETERSBURG),
        (9_069_000, SpecId::PETERSBURG, SpecId::ISTANBUL),
        (12_244_000, SpecId::ISTANBUL, SpecId::BERLIN),
        (12_965_000, SpecId::BERLIN, SpecId::LONDON),
        (15_537_394, SpecId::LONDON, SpecId::MERGE),
    ] {
        assert_eq!(mainnet_spec(number - 1, 0), before);
        assert_eq!(mainnet_spec(number, 0), after);
    }
    for (time, before, after) in [
        (1_681_338_455, SpecId::MERGE, SpecId::SHANGHAI),
        (1_710_338_135, SpecId::SHANGHAI, SpecId::CANCUN),
        (1_746_612_311, SpecId::CANCUN, SpecId::PRAGUE),
        (1_764_798_551, SpecId::PRAGUE, SpecId::OSAKA),
    ] {
        assert_eq!(mainnet_spec(25_000_000, time - 1), before);
        assert_eq!(mainnet_spec(25_000_000, time), after);
    }
}

#[test]
fn fixture_default_is_named_and_versioned() {
    let policy = EnvironmentPolicy::resolve(&ForkDb::empty(), &BlockEnv::default()).unwrap();
    assert_eq!(policy.source, "synthetic-osaka");
    assert_eq!(policy.spec_id, "Osaka");
    assert_eq!(policy.version, 1);
}

/// External client boundary check, deliberately opt-in because it requires an
/// Anvil executable and a loopback socket. Anvil also uses REVM: this is not an
/// independent EVM implementation comparison. No production RPC policy changes.
#[test]
#[ignore = "requires Anvil; run cargo test -p rustyfuzz-evm --test environment anvil_client -- --ignored --nocapture"]
fn anvil_client_agrees_on_hardfork_and_high_basefee_behavior() {
    use serde_json::{json, Value};
    use std::{
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    struct Node(Child);
    impl Drop for Node {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    for (fork, number, timestamp) in [
        ("paris", 17_034_869, 1_681_338_454),
        ("shanghai", 17_034_870, 1_681_338_455),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let _node = Node(
            Command::new("anvil")
                .args([
                    "--host",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--hardfork",
                    fork,
                    "--chain-id",
                    "1",
                    "--base-fee",
                    "80000000000",
                    "--no-mining",
                    "--silent",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("Anvil must be installed to run this explicitly requested test"),
        );
        let url = format!("http://127.0.0.1:{port}");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if client
                .post(&url)
                .json(&json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}))
                .send()
                .is_ok()
            {
                break;
            }
            assert!(Instant::now() < deadline, "Anvil startup timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
        let rpc = |method: &str, params: Value| -> Value {
            client
                .post(&url)
                .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
                .send()
                .unwrap()
                .json()
                .unwrap()
        };
        let target = format!("{:#x}", Address::repeat_byte(0x22));
        let caller = rpc("eth_accounts", json!([]))["result"][0].clone();
        for code in [
            vec![0x5f, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3],
            vec![0x46, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3],
            vec![0x3a, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3],
        ] {
            assert!(rpc(
                "anvil_setCode",
                json!([target, format!("0x{}", hex::encode(&code))])
            )
            .get("error")
            .is_none());
            let external = rpc(
                "eth_call",
                json!([{"from":caller,"to":target,"gas":"0xf4240","gasPrice":"0x12a05f2000"},"latest"]),
            );
            let local = run(&code, number, timestamp, 80_000_000_000).unwrap();
            if matches!(local.status, ExecutionStatus::Success) {
                assert_eq!(
                    external["result"],
                    json!(format!("0x{}", hex::encode(&local.output))),
                    "{fork}: {external}"
                );
            } else {
                assert!(
                    external.get("error").is_some(),
                    "{fork}: expected opcode rejection: {external}"
                );
            }
        }
    }
}
