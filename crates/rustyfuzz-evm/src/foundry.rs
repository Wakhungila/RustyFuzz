//! Foundry-compatible execution for `setUp()` and `invariant_*` calls.
//!
//! Foundry test contracts talk to the VM through the cheatcode address
//! (`0x7109709ECfa91a80626fF3989D68f67F5b1DD12D`). Executing a project's
//! `setUp()` therefore needs those calls intercepted, otherwise any
//! `vm.deal`, `vm.prank` or `makeAddr` in it reverts and nothing can be
//! bootstrapped. This module implements the subset that deployment scripts and
//! invariant harnesses use in practice, and **fails loudly** on everything else:
//! an unsupported cheatcode reverts with its selector in the message rather
//! than returning success, because silently skipping `vm.etch` or
//! `vm.expectRevert` would produce a state that looks valid and is not.
//!
//! Supported: `deal`, `etch`, `store`, `load`, `addr`, `label`, `assume`,
//! `prank`/`startPrank`/`stopPrank`, `warp`, `roll`, `startBroadcast` family
//! (no-op), and the `assert*` family over 256-bit words.
//!
//! Known limits, deliberately not papered over:
//! - `warp`/`roll` take effect for the *next* transaction (the block
//!   environment is fixed for the duration of one), not mid-transaction.
//! - `record`/`accesses` (used by `stdstore` and the token form of
//!   `deal(token, to, amount)`), `expectRevert`, `expectEmit`, `mockCall`,
//!   forking cheatcodes and file/JSON/env cheatcodes are unsupported.

use crate::environment::EnvironmentPolicy;
use crate::fork_db::ForkDb;
use anyhow::{anyhow, Result};
use k256::ecdsa::SigningKey;
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, TxEnv};
use revm::context_interface::journaled_state::account::JournaledAccountTr;
use revm::context_interface::{ContextTr, JournalTr};
use revm::database::CacheDB;
use revm::interpreter::{CallInputs, CallOutcome, Gas, InstructionResult, InterpreterResult};
use revm::primitives::{address, keccak256, Address, Bytes, TxKind, B256, U256};
use revm::state::Bytecode;
use revm::{Context, DatabaseCommit, InspectEvm, Inspector, MainBuilder, MainContext};
use std::collections::HashMap;

/// The Foundry VM cheatcode address, `address(uint160(uint256(keccak256("hevm cheat code"))))`.
pub const HEVM_ADDRESS: Address = address!("7109709ECfa91a80626fF3989D68f67F5b1DD12D");

/// Foundry's default sender and gas-funded deployer account.
pub const DEFAULT_SENDER: Address = address!("1804c8AB1F12E6bbf3894d4083f33e07309d1f38");

const FUND_WEI: u128 = 1_000_000_000_000_000_000_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cheat {
    Deal,
    Etch,
    Store,
    Load,
    Addr,
    Warp,
    Roll,
    Prank,
    StartPrank,
    StopPrank,
    Noop,
    Assume,
    AssertTrue,
    AssertFalse,
    AssertEq,
    AssertNotEq,
    AssertGt,
    AssertGe,
    AssertLt,
    AssertLe,
}

#[derive(Clone, Copy, Debug)]
struct CheatSpec {
    cheat: Cheat,
    /// Compare the two leading words as `int256` instead of `uint256`.
    signed: bool,
}

fn cheat_table() -> HashMap<[u8; 4], CheatSpec> {
    use Cheat::*;
    let mut table = HashMap::new();
    let mut add = |signature: &str, cheat: Cheat, signed: bool| {
        let hash = keccak256(signature.as_bytes());
        table.insert(
            [hash[0], hash[1], hash[2], hash[3]],
            CheatSpec { cheat, signed },
        );
    };
    add("deal(address,uint256)", Deal, false);
    add("etch(address,bytes)", Etch, false);
    add("store(address,bytes32,bytes32)", Store, false);
    add("load(address,bytes32)", Load, false);
    add("addr(uint256)", Addr, false);
    add("warp(uint256)", Warp, false);
    add("roll(uint256)", Roll, false);
    add("prank(address)", Prank, false);
    add("startPrank(address)", StartPrank, false);
    add("stopPrank()", StopPrank, false);
    add("label(address,string)", Noop, false);
    add("startBroadcast()", Noop, false);
    add("startBroadcast(address)", Noop, false);
    add("stopBroadcast()", Noop, false);
    add("broadcast()", Noop, false);
    add("broadcast(address)", Noop, false);
    add("assume(bool)", Assume, false);
    add("assertTrue(bool)", AssertTrue, false);
    add("assertTrue(bool,string)", AssertTrue, false);
    add("assertFalse(bool)", AssertFalse, false);
    add("assertFalse(bool,string)", AssertFalse, false);
    for (ty, signed) in [
        ("uint256", false),
        ("int256", true),
        ("address", false),
        ("bool", false),
        ("bytes32", false),
    ] {
        for (name, cheat) in [("assertEq", AssertEq), ("assertNotEq", AssertNotEq)] {
            add(&format!("{name}({ty},{ty})"), cheat, signed);
            add(&format!("{name}({ty},{ty},string)"), cheat, signed);
        }
    }
    for (ty, signed) in [("uint256", false), ("int256", true)] {
        for (name, cheat) in [
            ("assertGt", AssertGt),
            ("assertGe", AssertGe),
            ("assertLt", AssertLt),
            ("assertLe", AssertLe),
        ] {
            add(&format!("{name}({ty},{ty})"), cheat, signed);
            add(&format!("{name}({ty},{ty},string)"), cheat, signed);
        }
    }
    table
}

/// Block-environment changes requested by `warp`/`roll` during a transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockOverride {
    pub timestamp: Option<U256>,
    pub number: Option<U256>,
}

impl BlockOverride {
    pub fn apply(&self, block: &mut BlockEnv) {
        if let Some(timestamp) = self.timestamp {
            block.timestamp = timestamp;
        }
        if let Some(number) = self.number {
            block.number = number;
        }
    }
}

/// Intercepts calls to [`HEVM_ADDRESS`].
pub struct CheatcodeInspector {
    table: HashMap<[u8; 4], CheatSpec>,
    /// Address of the test contract; `prank` rewrites calls made *by it*.
    test_contract: Address,
    prank: Option<Address>,
    persistent_prank: bool,
    block_override: BlockOverride,
    /// Calls that reached the cheatcode address but were not handled.
    unsupported: Vec<[u8; 4]>,
}

impl CheatcodeInspector {
    pub fn new(test_contract: Address) -> Self {
        Self {
            table: cheat_table(),
            test_contract,
            prank: None,
            persistent_prank: false,
            block_override: BlockOverride::default(),
            unsupported: Vec::new(),
        }
    }

    pub fn block_override(&self) -> BlockOverride {
        self.block_override
    }

    pub fn unsupported(&self) -> &[[u8; 4]] {
        &self.unsupported
    }
}

fn word(data: &[u8], index: usize) -> Option<[u8; 32]> {
    let start = 4 + index * 32;
    data.get(start..start + 32).map(|slice| {
        let mut out = [0u8; 32];
        out.copy_from_slice(slice);
        out
    })
}

fn address_word(data: &[u8], index: usize) -> Option<Address> {
    word(data, index).map(|w| Address::from_slice(&w[12..]))
}

fn error_string(message: &str) -> Bytes {
    // Error(string): selector, offset, length, padded payload.
    let mut out = vec![0x08, 0xc3, 0x79, 0xa0];
    let mut offset = [0u8; 32];
    offset[31] = 0x20;
    out.extend_from_slice(&offset);
    out.extend_from_slice(&U256::from(message.len()).to_be_bytes::<32>());
    out.extend_from_slice(message.as_bytes());
    out.resize(out.len() + (32 - message.len() % 32) % 32, 0);
    out.into()
}

fn outcome(inputs: &CallInputs, result: InstructionResult, output: Bytes) -> CallOutcome {
    CallOutcome::new(
        InterpreterResult::new(result, output, Gas::new(inputs.gas_limit)),
        inputs.return_memory_offset.clone(),
    )
}

fn revert(inputs: &CallInputs, message: &str) -> CallOutcome {
    outcome(inputs, InstructionResult::Revert, error_string(message))
}

fn signed_less(a: U256, b: U256) -> bool {
    let a_neg = a.bit(255);
    let b_neg = b.bit(255);
    match (a_neg, b_neg) {
        (true, false) => true,
        (false, true) => false,
        // Same sign: two's-complement ordering matches unsigned ordering.
        _ => a < b,
    }
}

fn compare(cheat: Cheat, signed: bool, a: U256, b: U256) -> bool {
    let less = if signed { signed_less(a, b) } else { a < b };
    let greater = if signed { signed_less(b, a) } else { a > b };
    match cheat {
        Cheat::AssertEq => a == b,
        Cheat::AssertNotEq => a != b,
        Cheat::AssertGt => greater,
        Cheat::AssertGe => greater || a == b,
        Cheat::AssertLt => less,
        Cheat::AssertLe => less || a == b,
        _ => false,
    }
}

/// `vm.addr(privateKey)`: the address controlled by a secp256k1 private key.
fn address_of_private_key(key: [u8; 32]) -> Option<Address> {
    let signing = SigningKey::from_bytes((&key).into()).ok()?;
    let point = signing.verifying_key().to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    Some(Address::from_slice(&hash[12..]))
}

impl<CTX: ContextTr> Inspector<CTX> for CheatcodeInspector {
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if inputs.target_address != HEVM_ADDRESS {
            if let Some(pranked) = self.prank {
                if inputs.caller == self.test_contract {
                    inputs.caller = pranked;
                    if !self.persistent_prank {
                        self.prank = None;
                    }
                }
            }
            return None;
        }

        let data = inputs.input.bytes(context);
        if data.len() < 4 {
            return Some(revert(inputs, "cheatcode call without selector"));
        }
        let selector = [data[0], data[1], data[2], data[3]];
        let Some(spec) = self.table.get(&selector).copied() else {
            self.unsupported.push(selector);
            return Some(revert(
                inputs,
                &format!("unsupported cheatcode 0x{}", hex::encode(selector)),
            ));
        };
        let data: &[u8] = &data;
        let ok = |output: Bytes| Some(outcome(inputs, InstructionResult::Return, output));
        let bad_args = || Some(revert(inputs, "malformed cheatcode arguments"));

        match spec.cheat {
            Cheat::Noop => ok(Bytes::new()),
            Cheat::Assume => match word(data, 0) {
                Some(w) if w != [0u8; 32] => ok(Bytes::new()),
                Some(_) => Some(revert(inputs, "vm.assume rejected the input")),
                None => bad_args(),
            },
            Cheat::AssertTrue | Cheat::AssertFalse => match word(data, 0) {
                Some(w) => {
                    let truthy = w != [0u8; 32];
                    if truthy == (spec.cheat == Cheat::AssertTrue) {
                        ok(Bytes::new())
                    } else {
                        Some(revert(inputs, "assertion failed"))
                    }
                }
                None => bad_args(),
            },
            Cheat::AssertEq
            | Cheat::AssertNotEq
            | Cheat::AssertGt
            | Cheat::AssertGe
            | Cheat::AssertLt
            | Cheat::AssertLe => match (word(data, 0), word(data, 1)) {
                (Some(a), Some(b)) => {
                    let (a, b) = (U256::from_be_bytes(a), U256::from_be_bytes(b));
                    if compare(spec.cheat, spec.signed, a, b) {
                        ok(Bytes::new())
                    } else {
                        Some(revert(
                            inputs,
                            &format!("assertion failed: {:?} {a} vs {b}", spec.cheat),
                        ))
                    }
                }
                _ => bad_args(),
            },
            Cheat::Addr => match word(data, 0).and_then(address_of_private_key) {
                Some(account) => {
                    let mut out = [0u8; 32];
                    out[12..].copy_from_slice(account.as_slice());
                    ok(out.to_vec().into())
                }
                None => Some(revert(inputs, "vm.addr: invalid private key")),
            },
            Cheat::Warp => match word(data, 0) {
                Some(w) => {
                    self.block_override.timestamp = Some(U256::from_be_bytes(w));
                    ok(Bytes::new())
                }
                None => bad_args(),
            },
            Cheat::Roll => match word(data, 0) {
                Some(w) => {
                    self.block_override.number = Some(U256::from_be_bytes(w));
                    ok(Bytes::new())
                }
                None => bad_args(),
            },
            Cheat::Prank | Cheat::StartPrank => match address_word(data, 0) {
                Some(who) => {
                    self.prank = Some(who);
                    self.persistent_prank = spec.cheat == Cheat::StartPrank;
                    ok(Bytes::new())
                }
                None => bad_args(),
            },
            Cheat::StopPrank => {
                self.prank = None;
                self.persistent_prank = false;
                ok(Bytes::new())
            }
            Cheat::Deal => match (address_word(data, 0), word(data, 1)) {
                (Some(who), Some(amount)) => {
                    let amount = U256::from_be_bytes(amount);
                    match context.journal_mut().load_account_mut(who) {
                        Ok(mut loaded) => {
                            loaded.data.set_balance(amount);
                            ok(Bytes::new())
                        }
                        Err(_) => Some(revert(inputs, "vm.deal: database error")),
                    }
                }
                _ => bad_args(),
            },
            Cheat::Store => match (address_word(data, 0), word(data, 1), word(data, 2)) {
                (Some(who), Some(slot), Some(value)) => {
                    let journal = context.journal_mut();
                    if journal.load_account(who).is_err() {
                        return Some(revert(inputs, "vm.store: database error"));
                    }
                    match journal.sstore(who, U256::from_be_bytes(slot), U256::from_be_bytes(value))
                    {
                        Ok(_) => ok(Bytes::new()),
                        Err(_) => Some(revert(inputs, "vm.store: database error")),
                    }
                }
                _ => bad_args(),
            },
            Cheat::Load => match (address_word(data, 0), word(data, 1)) {
                (Some(who), Some(slot)) => {
                    let journal = context.journal_mut();
                    if journal.load_account(who).is_err() {
                        return Some(revert(inputs, "vm.load: database error"));
                    }
                    match journal.sload(who, U256::from_be_bytes(slot)) {
                        Ok(loaded) => ok(loaded.data.to_be_bytes::<32>().to_vec().into()),
                        Err(_) => Some(revert(inputs, "vm.load: database error")),
                    }
                }
                _ => bad_args(),
            },
            Cheat::Etch => {
                // etch(address,bytes): word0 = address, word1 = offset of `bytes`.
                let who = address_word(data, 0);
                let offset = word(data, 1).map(|w| U256::from_be_bytes(w));
                let (Some(who), Some(offset)) = (who, offset) else {
                    return bad_args();
                };
                let Ok(offset) = usize::try_from(offset) else {
                    return bad_args();
                };
                let len_at = 4usize.saturating_add(offset);
                let Some(len_word) = data.get(len_at..len_at.saturating_add(32)) else {
                    return bad_args();
                };
                let Ok(len) = usize::try_from(U256::from_be_slice(len_word)) else {
                    return bad_args();
                };
                let code_at = len_at + 32;
                let Some(code) = data.get(code_at..code_at.saturating_add(len)) else {
                    return bad_args();
                };
                let journal = context.journal_mut();
                if journal.load_account(who).is_err() {
                    return Some(revert(inputs, "vm.etch: database error"));
                }
                journal.set_code(who, Bytecode::new_raw(Bytes::copy_from_slice(code)));
                ok(Bytes::new())
            }
        }
    }
}

/// Everything one cheatcode-aware execution produced.
#[derive(Debug)]
pub struct CheatRun {
    pub result: ExecutionResult,
    pub block_override: BlockOverride,
    /// Cheatcode selectors the run hit that this module does not implement.
    pub unsupported: Vec<[u8; 4]>,
}

/// Executes one transaction with cheatcodes enabled.
///
/// With `commit == true` the resulting state is written into `db` (deployment,
/// `setUp`). With `commit == false` nothing is written back, which is how
/// `invariant_*` functions are evaluated after every fuzzed transaction without
/// disturbing the sequence under test. The caller is funded for gas either way;
/// when not committing, the cache entry is restored afterwards.
pub fn execute_with_cheatcodes(
    db: &mut CacheDB<ForkDb>,
    block_env: &BlockEnv,
    caller: Address,
    kind: TxKind,
    input: Bytes,
    value: U256,
    test_contract: Address,
    commit: bool,
) -> Result<CheatRun> {
    let environment = EnvironmentPolicy::resolve_advancing(&db.db, block_env)?;
    let before = db.cache.accounts.get(&caller).cloned();
    let nonce = db.load_account(caller)?.info.nonce;
    let mut info = db.load_account(caller)?.info.clone();
    let funded = U256::from(FUND_WEI);
    if info.balance < funded {
        info.balance = funded;
        db.insert_account_info(caller, info);
    }

    let tx_env = TxEnv {
        caller,
        gas_limit: environment.tx_gas_limit,
        gas_price: environment.tx_gas_price,
        chain_id: Some(environment.chain_id),
        value,
        data: input,
        kind,
        nonce,
        ..Default::default()
    };

    let mut inspector = CheatcodeInspector::new(test_contract);
    let outcome = {
        let ctx = Context::mainnet()
            .with_db(&mut *db)
            .with_cfg(environment.cfg()?)
            .with_block(environment.block(block_env));
        let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
        evm.inspect_tx(tx_env)
    };

    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            restore(db, caller, before);
            return Err(anyhow!("cheatcode execution failed: {error:?}"));
        }
    };

    if commit {
        db.commit(outcome.state);
    } else {
        restore(db, caller, before);
    }

    Ok(CheatRun {
        result: outcome.result,
        block_override: inspector.block_override(),
        unsupported: inspector.unsupported().to_vec(),
    })
}

fn restore(db: &mut CacheDB<ForkDb>, caller: Address, previous: Option<revm::database::DbAccount>) {
    match previous {
        Some(account) => {
            db.cache.accounts.insert(caller, account);
        }
        None => {
            db.cache.accounts.remove(&caller);
        }
    }
}

/// `B256` helper for callers that want the cheatcode `failed` slot name.
pub fn failed_slot_key() -> B256 {
    let mut key = [0u8; 32];
    key[..6].copy_from_slice(b"failed");
    B256::from(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hevm_address_is_the_keccak_of_hevm_cheat_code() {
        let hash = keccak256(b"hevm cheat code");
        assert_eq!(Address::from_slice(&hash[12..]), HEVM_ADDRESS);
    }

    #[test]
    fn selectors_match_known_cheatcode_values() {
        let table = cheat_table();
        // deal(address,uint256) = c88a5e6d, warp(uint256) = e5d6bf02,
        // prank(address) = ca669fa7, startPrank(address) = 06447d56,
        // stopPrank() = 90c5013b, etch(address,bytes) = b4d6c782.
        for (selector, cheat) in [
            ("c88a5e6d", Cheat::Deal),
            ("e5d6bf02", Cheat::Warp),
            ("ca669fa7", Cheat::Prank),
            ("06447d56", Cheat::StartPrank),
            ("90c5013b", Cheat::StopPrank),
            ("b4d6c782", Cheat::Etch),
        ] {
            let bytes: [u8; 4] = hex::decode(selector).unwrap().try_into().unwrap();
            assert_eq!(
                table.get(&bytes).map(|s| s.cheat),
                Some(cheat),
                "{selector}"
            );
        }
    }

    #[test]
    fn vm_addr_of_key_one_is_the_well_known_address() {
        let mut key = [0u8; 32];
        key[31] = 1;
        assert_eq!(
            address_of_private_key(key),
            Some(address!("7E5F4552091A69125d5DfCb7b8C2659029395Bdf"))
        );
        assert_eq!(address_of_private_key([0u8; 32]), None, "zero is not a key");
    }

    #[test]
    fn signed_comparison_orders_negatives_below_positives() {
        let minus_one = U256::MAX;
        assert!(compare(Cheat::AssertLt, true, minus_one, U256::from(1)));
        assert!(!compare(Cheat::AssertLt, false, minus_one, U256::from(1)));
        assert!(compare(Cheat::AssertGe, true, U256::from(5), U256::from(5)));
    }

    #[test]
    fn error_string_is_abi_encoded() {
        let encoded = error_string("no");
        assert_eq!(&encoded[..4], &[0x08, 0xc3, 0x79, 0xa0]);
        assert_eq!(encoded.len(), 4 + 32 + 32 + 32);
    }
}
