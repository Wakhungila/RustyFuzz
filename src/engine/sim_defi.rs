//! Real flash-loan machinery: atomic attacker, virtual balances, AMM models.
//!
//! Replaces the old `wrap_flashloan` placeholder (which serialised the
//! sequence and "called" a random contract as an EIP-3156 lender). Pieces:
//!
//! * [`AtomicAttacker`](../../../contracts/sim/AtomicAttacker.sol): one
//!   transaction snapshots the borrowed tokens, runs an arbitrary call list and
//!   reverts unless every token is returned with the fee *and* at least one
//!   ended strictly ahead. A successful `run` is therefore proof of profit.
//! * Virtual balances ([`credit_erc20`], [`credit_eth`]): the "loan" is a
//!   balance written straight into token storage (the mapping slot is found by
//!   probing and verified through `balanceOf`). No lender contract is needed;
//!   the attacker's end-of-transaction check is the repayment.
//! * AMM models ([`deploy_v2_pair`], [`deploy_v3_pool`]): Uniswap V2 pair and
//!   a single-range V3 pool with the real swap math, for pools that don't
//!   exist in a synthetic/fixture state.
//!
//! The Solidity sources and committed runtime bytecode live in
//! `contracts/sim/` (regenerate with `scripts/build_sim_contracts.py`).

use anyhow::{anyhow, bail, Result};
use revm::context::result::ExecutionResult;
use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::primitives::{keccak256, Address, Bytes, TxKind, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::{Context, Database, ExecuteCommitEvm, MainBuilder, MainContext};
use rustyfuzz_evm::fork_db::ForkDb;

use alloy_dyn_abi::DynSolValue;

/// Fixed address of the atomic attacker contract in every campaign.
pub const ATTACKER_ADDR: Address = Address::new([0xa7; 20]);
/// Account used to send setup transactions (never a fuzz caller).
const SETUP_CALLER: Address = Address::new([0x5e; 20]);

/// Default virtual balance credited per token: 1e24 base units.
pub const DEFAULT_CREDIT: u128 = 1_000_000_000_000_000_000_000_000;

const TOKEN_HEX: &str = include_str!("../../contracts/sim/artifacts/MockToken.hex");
const ATTACKER_HEX: &str = include_str!("../../contracts/sim/artifacts/AtomicAttacker.hex");
const V2_HEX: &str = include_str!("../../contracts/sim/artifacts/MockV2Pair.hex");
const V3_HEX: &str = include_str!("../../contracts/sim/artifacts/MockV3Pool.hex");
pub const SPOT_LENDER_HEX: &str = include_str!("../../contracts/sim/artifacts/SpotOracleLender.hex");
pub const FIXED_LENDER_HEX: &str = include_str!("../../contracts/sim/artifacts/FixedOracleLender.hex");

pub type Db = CacheDB<ForkDb>;

pub fn runtime(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str.trim()).expect("committed artifact is valid hex")
}

pub fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes()).0[..4].try_into().unwrap()
}

pub fn encode_call(signature: &str, args: &[DynSolValue]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    out.extend(DynSolValue::Tuple(args.to_vec()).abi_encode_params());
    out
}

pub fn install(db: &mut Db, address: Address, code: Vec<u8>, balance: U256) {
    db.insert_account_info(
        address,
        AccountInfo { balance, ..AccountInfo::default() }
            .with_code(Bytecode::new_raw(Bytes::from(code))),
    );
}

/// Executes a transaction and commits it (nonce read from the cache first).
pub fn transact(db: &mut Db, caller: Address, to: Address, value: U256, data: Vec<u8>) -> Result<ExecutionResult> {
    let nonce = db.load_account(caller)?.info.nonce;
    let tx = TxEnv {
        caller,
        gas_limit: 16_000_000,
        gas_price: 0,
        chain_id: Some(1),
        value,
        data: data.into(),
        kind: TxKind::Call(to),
        nonce,
        ..Default::default()
    };
    let mut evm = Context::mainnet().with_db(&mut *db).build_mainnet();
    Ok(evm.transact_commit(tx)?)
}

fn expect_success(what: &str, result: ExecutionResult) -> Result<Bytes> {
    match result {
        ExecutionResult::Success { output, .. } => Ok(output.into_data()),
        other => bail!("{what} did not succeed: {other:?}"),
    }
}

fn fund_setup_caller(db: &mut Db) {
    if db.load_account(SETUP_CALLER).map(|a| a.info.balance.is_zero()).unwrap_or(true) {
        db.insert_account_info(
            SETUP_CALLER,
            AccountInfo { balance: U256::from(10u128.pow(30)), ..AccountInfo::default() },
        );
    }
}

// ───────────────────────────── virtual balances ─────────────────────────────

pub fn balance_of(db: &mut Db, token: Address, holder: Address) -> Result<U256> {
    fund_setup_caller(db);
    let out = expect_success(
        "balanceOf",
        transact(db, SETUP_CALLER, token, U256::ZERO, encode_call("balanceOf(address)", &[DynSolValue::Address(holder)]))?,
    )?;
    if out.len() < 32 {
        bail!("balanceOf returned {} bytes", out.len());
    }
    Ok(U256::from_be_slice(&out[..32]))
}

/// Gives `holder` a virtual ETH balance.
pub fn credit_eth(db: &mut Db, holder: Address, amount: U256) -> Result<()> {
    let info = db.load_account(holder)?.info.clone();
    db.insert_account_info(holder, AccountInfo { balance: amount, ..info });
    Ok(())
}

/// Gives `holder` a virtual ERC-20 balance by writing the token's balance
/// mapping directly. The slot is found by probing the common layouts
/// (Solidity `keccak(holder . slot)` and Vyper `keccak(slot . holder)` for slots
/// 0..64) and **verified through `balanceOf`**, so a wrong guess can never
/// silently pass. Returns the mapping slot, or `None` if no layout matched
/// (non-standard storage, e.g. packed or rebasing), in which case nothing is
/// changed.
pub fn credit_erc20(db: &mut Db, token: Address, holder: Address, amount: U256) -> Result<Option<(u64, bool)>> {
    for slot in 0u64..64 {
        for vyper in [false, true] {
            let mut preimage = Vec::with_capacity(64);
            if vyper {
                preimage.extend_from_slice(&U256::from(slot).to_be_bytes::<32>());
                preimage.extend_from_slice(&[0u8; 12]);
                preimage.extend_from_slice(holder.as_slice());
            } else {
                preimage.extend_from_slice(&[0u8; 12]);
                preimage.extend_from_slice(holder.as_slice());
                preimage.extend_from_slice(&U256::from(slot).to_be_bytes::<32>());
            }
            let key = U256::from_be_bytes(keccak256(&preimage).0);
            let previous = db.storage(token, key)?;
            db.insert_account_storage(token, key, amount)?;
            if balance_of(db, token, holder).ok() == Some(amount) {
                return Ok(Some((slot, vyper)));
            }
            db.insert_account_storage(token, key, previous)?;
        }
    }
    Ok(None)
}

/// ERC-20-shaped contracts the attacker can usefully borrow: runtime code that
/// mentions both `balanceOf(address)` and `transfer(address,uint256)` AND
/// actually answers `balanceOf` with a word. The behavioural probe matters: a
/// pair or router embeds those selectors as *external-call* constants without
/// implementing them.
pub fn discover_tokens(db: &mut Db) -> Vec<Address> {
    let balance_of = [&[0x63u8][..], &selector("balanceOf(address)")[..]].concat();
    let transfer = [&[0x63u8][..], &selector("transfer(address,uint256)")[..]].concat();
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    let mut candidates: Vec<Address> = db
        .cache
        .accounts
        .iter()
        .filter_map(|(addr, account)| {
            let code = account.info.code.as_ref()?.original_bytes();
            (contains(&code, &balance_of) && contains(&code, &transfer)).then_some(*addr)
        })
        .collect();
    candidates.sort();
    candidates.retain(|token| balance_of_probe(db, *token));
    candidates
}

fn balance_of_probe(db: &mut Db, token: Address) -> bool {
    fund_setup_caller(db);
    let probe = Address::new([0xde; 20]);
    matches!(
        transact(db, SETUP_CALLER, token, U256::ZERO, encode_call("balanceOf(address)", &[DynSolValue::Address(probe)])),
        Ok(ExecutionResult::Success { output, .. }) if output.data().len() == 32
    )
}

// ──────────────────────────── atomic attacker ────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackCall {
    pub target: Address,
    pub value: U256,
    pub data: Vec<u8>,
    /// A failing optional call is skipped instead of reverting the attack.
    pub optional: bool,
}

pub const EXEC_SIGNATURE: &str = "exec((address,uint256,bytes,bool)[])";

fn encode_calls(calls: &[AttackCall]) -> DynSolValue {
    DynSolValue::Array(
        calls
            .iter()
            .map(|c| {
                DynSolValue::Tuple(vec![
                    DynSolValue::Address(c.target),
                    DynSolValue::Uint(c.value, 256),
                    DynSolValue::Bytes(c.data.clone()),
                    DynSolValue::Bool(c.optional),
                ])
            })
            .collect(),
    )
}

/// ABI-encodes `AtomicAttacker.exec(calls)` (no profit gate).
pub fn encode_exec(calls: &[AttackCall]) -> Vec<u8> {
    encode_call(EXEC_SIGNATURE, &[encode_calls(calls)])
}

pub const RUN_SIGNATURE: &str = "run(address[],uint256,(address,uint256,bytes,bool)[])";

/// ABI-encodes `AtomicAttacker.run(tokens, feeBps, calls)`.
pub fn encode_run(tokens: &[Address], fee_bps: u64, calls: &[AttackCall]) -> Vec<u8> {
    let tokens = DynSolValue::Array(tokens.iter().map(|t| DynSolValue::Address(*t)).collect());
    let calls = encode_calls(calls);
    encode_call(RUN_SIGNATURE, &[tokens, DynSolValue::Uint(U256::from(fee_bps), 256), calls])
}

/// Installs the attacker at [`ATTACKER_ADDR`] with a virtual ETH balance and a
/// virtual balance of every supplied token (tokens whose storage layout can't
/// be probed are skipped and returned in the second element).
pub fn deploy_atomic_attacker(db: &mut Db, tokens: &[Address], credit: U256) -> Result<(Address, Vec<Address>)> {
    install(db, ATTACKER_ADDR, runtime(ATTACKER_HEX), credit);
    let mut skipped = Vec::new();
    for token in tokens {
        if credit_erc20(db, *token, ATTACKER_ADDR, credit)?.is_none() {
            skipped.push(*token);
        }
    }
    Ok((ATTACKER_ADDR, skipped))
}

/// Parses `Profit(address indexed token, uint256 opening, uint256 closing, uint256 fee)`
/// logs emitted by the attacker: `(token, opening, closing, fee)`.
pub fn parse_profit_logs(result: &ExecutionResult) -> Vec<(Address, U256, U256, U256)> {
    let topic0 = keccak256("Profit(address,uint256,uint256,uint256)".as_bytes());
    let ExecutionResult::Success { logs, .. } = result else { return Vec::new() };
    logs.iter()
        .filter(|l| l.address == ATTACKER_ADDR && l.data.topics().first() == Some(&topic0))
        .filter_map(|l| {
            let topics = l.data.topics();
            let data = l.data.data.as_ref();
            (topics.len() == 2 && data.len() >= 96).then(|| {
                (
                    Address::from_slice(&topics[1].0[12..]),
                    U256::from_be_slice(&data[0..32]),
                    U256::from_be_slice(&data[32..64]),
                    U256::from_be_slice(&data[64..96]),
                )
            })
        })
        .collect()
}

// ─────────────────────────────── AMM models ───────────────────────────────

pub fn deploy_mock_token(db: &mut Db, address: Address) {
    install(db, address, runtime(TOKEN_HEX), U256::ZERO);
}

/// Uniswap V2 pair at `pair`, seeded with `(reserve0, reserve1)` of
/// `token0`/`token1` (virtual balances + `sync()`).
pub fn deploy_v2_pair(
    db: &mut Db,
    pair: Address,
    token0: Address,
    token1: Address,
    reserve0: U256,
    reserve1: U256,
) -> Result<()> {
    fund_setup_caller(db);
    install(db, pair, runtime(V2_HEX), U256::ZERO);
    expect_success(
        "pair.initialize",
        transact(db, SETUP_CALLER, pair, U256::ZERO, encode_call(
            "initialize(address,address)",
            &[DynSolValue::Address(token0), DynSolValue::Address(token1)],
        ))?,
    )?;
    for (token, amount) in [(token0, reserve0), (token1, reserve1)] {
        credit_erc20(db, token, pair, amount)?
            .ok_or_else(|| anyhow!("cannot seed pair: token {token} storage layout not recognised"))?;
    }
    expect_success("pair.sync", transact(db, SETUP_CALLER, pair, U256::ZERO, encode_call("sync()", &[]))?)?;
    Ok(())
}

pub const Q96: u128 = 1 << 96;

/// Single-range Uniswap V3 pool at `pool` (see `MockV3Pool.sol` for scope).
#[allow(clippy::too_many_arguments)]
pub fn deploy_v3_pool(
    db: &mut Db,
    pool: Address,
    token0: Address,
    token1: Address,
    fee_pips: u32,
    sqrt_price: U256,
    sqrt_lower: U256,
    sqrt_upper: U256,
    liquidity: u128,
    reserve0: U256,
    reserve1: U256,
) -> Result<()> {
    fund_setup_caller(db);
    install(db, pool, runtime(V3_HEX), U256::ZERO);
    expect_success(
        "pool.initialize",
        transact(db, SETUP_CALLER, pool, U256::ZERO, encode_call(
            "initialize(address,address,uint24,uint160,uint160,uint160,uint128)",
            &[
                DynSolValue::Address(token0),
                DynSolValue::Address(token1),
                DynSolValue::Uint(U256::from(fee_pips), 24),
                DynSolValue::Uint(sqrt_price, 160),
                DynSolValue::Uint(sqrt_lower, 160),
                DynSolValue::Uint(sqrt_upper, 160),
                DynSolValue::Uint(U256::from(liquidity), 128),
            ],
        ))?,
    )?;
    for (token, amount) in [(token0, reserve0), (token1, reserve1)] {
        credit_erc20(db, token, pool, amount)?
            .ok_or_else(|| anyhow!("cannot seed pool: token {token} storage layout not recognised"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Address = Address::new([0x10; 20]);
    const T1: Address = Address::new([0x11; 20]);
    const PAIR: Address = Address::new([0x20; 20]);
    const POOL: Address = Address::new([0x21; 20]);
    const LENDER: Address = Address::new([0x30; 20]);
    const EOA: Address = Address::new([0xee; 20]);
    const E18: u128 = 1_000_000_000_000_000_000;

    fn u(n: u128) -> U256 {
        U256::from(n)
    }
    fn addr(a: Address) -> DynSolValue {
        DynSolValue::Address(a)
    }
    fn uint(v: U256) -> DynSolValue {
        DynSolValue::Uint(v, 256)
    }
    fn call(target: Address, signature: &str, args: &[DynSolValue]) -> AttackCall {
        AttackCall { target, value: U256::ZERO, data: encode_call(signature, args), optional: false }
    }
    fn new_db() -> Db {
        let mut db = CacheDB::new(ForkDb::empty());
        deploy_mock_token(&mut db, T0);
        deploy_mock_token(&mut db, T1);
        db
    }
    /// Uniswap V2 `getAmountOut` in 256-bit arithmetic (u128 would overflow).
    fn v2_out(amount_in: u128, reserve_in: u128, reserve_out: u128) -> u128 {
        let in_fee = u(amount_in) * u(997);
        let out = in_fee * u(reserve_out) / (u(reserve_in) * u(1000) + in_fee);
        out.to::<u128>()
    }
    fn swap_call(out0: u128, out1: u128, to: Address) -> AttackCall {
        call(PAIR, "swap(uint256,uint256,address,bytes)", &[uint(u(out0)), uint(u(out1)), addr(to), DynSolValue::Bytes(vec![])])
    }
    fn reverted_with(r: &ExecutionResult, sig: &str) -> bool {
        matches!(r, ExecutionResult::Revert { output, .. } if output.len() >= 4 && output[..4] == selector(sig))
    }

    #[test]
    fn credit_finds_slot_zero_and_verifies_via_balance_of() {
        let mut db = new_db();
        let holder = Address::new([0x42; 20]);
        assert_eq!(credit_erc20(&mut db, T0, holder, u(777)).unwrap(), Some((0, false)));
        assert_eq!(balance_of(&mut db, T0, holder).unwrap(), u(777));
    }

    #[test]
    fn credit_declines_and_changes_nothing_when_no_layout_matches() {
        let mut db = CacheDB::new(ForkDb::empty());
        // Answers every call with constant 42: no storage layout can ever match 5.
        install(&mut db, T0, vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3], U256::ZERO);
        assert_eq!(credit_erc20(&mut db, T0, Address::new([1; 20]), u(5)).unwrap(), None);
    }

    #[test]
    fn discovers_erc20_shaped_contracts_only() {
        let mut db = new_db();
        install(&mut db, PAIR, runtime(V2_HEX), U256::ZERO);
        let found = discover_tokens(&mut db);
        assert!(found.contains(&T0) && found.contains(&T1), "{found:?}");
        assert!(!found.contains(&PAIR));
    }

    #[test]
    fn v2_pair_output_matches_closed_form_and_one_wei_more_breaks_k() {
        let mut db = new_db();
        deploy_v2_pair(&mut db, PAIR, T0, T1, u(1000 * E18), u(1000 * E18)).unwrap();
        let (a, _) = deploy_atomic_attacker(&mut db, &[T0, T1], u(10_000 * E18)).unwrap();
        let amount_in = 10 * E18;
        let expect = v2_out(amount_in, 1000 * E18, 1000 * E18);
        let pay = call(T0, "transfer(address,uint256)", &[addr(PAIR), uint(u(amount_in))]);

        // One wei too greedy: V2's post-swap invariant must reject it.
        let r = transact(&mut db, EOA, a, U256::ZERO, encode_exec(&[pay.clone(), swap_call(0, expect + 1, a)])).unwrap();
        assert!(reverted_with(&r, "CallFailed(uint256,bytes)"), "{r:?}");

        // The exact closed-form amount is accepted and lands in the attacker.
        let before = balance_of(&mut db, T1, a).unwrap();
        let r = transact(&mut db, EOA, a, U256::ZERO, encode_exec(&[pay, swap_call(0, expect, a)])).unwrap();
        assert!(matches!(r, ExecutionResult::Success { .. }), "{r:?}");
        assert_eq!(balance_of(&mut db, T1, a).unwrap() - before, u(expect));
    }

    fn lender_db(lender_code: &str, with_pair_slot: bool) -> (Db, Address) {
        let mut db = new_db();
        deploy_v2_pair(&mut db, PAIR, T0, T1, u(1000 * E18), u(1000 * E18)).unwrap();
        install(&mut db, LENDER, runtime(lender_code), U256::ZERO);
        let mut slots = vec![(0u64, T0), (1, T1)];
        if with_pair_slot {
            slots.push((2, PAIR));
        }
        for (slot, value) in slots {
            db.insert_account_storage(LENDER, U256::from(slot), U256::from_be_slice(value.as_slice())).unwrap();
        }
        credit_erc20(&mut db, T1, LENDER, u(5000 * E18)).unwrap().unwrap();
        let (a, skipped) = deploy_atomic_attacker(&mut db, &[T1], u(10_000 * E18)).unwrap();
        assert!(skipped.is_empty());
        (db, a)
    }

    /// Buy T0 with a flash-loan-sized T1 swap (pushing spot price up), post a
    /// slice as collateral and borrow T1 at the inflated price, then sell the
    /// rest of the T0 back into the pair.
    fn manipulation_calls(attacker: Address) -> Vec<AttackCall> {
        let borrowed_in = 3000 * E18;
        let t0_out = v2_out(borrowed_in, 1000 * E18, 1000 * E18);
        let (r0, r1) = (1000 * E18 - t0_out, 1000 * E18 + borrowed_in);
        let collateral = 100 * E18;
        let rest = t0_out - collateral;
        let t1_back = v2_out(rest, r0, r1);
        vec![
            call(T1, "transfer(address,uint256)", &[addr(PAIR), uint(u(borrowed_in))]),
            swap_call(t0_out, 0, attacker),
            call(T0, "approve(address,uint256)", &[addr(LENDER), uint(U256::MAX)]),
            call(LENDER, "borrow(uint256)", &[uint(u(collateral))]),
            call(T0, "transfer(address,uint256)", &[addr(PAIR), uint(u(rest))]),
            swap_call(0, t1_back, attacker),
        ]
    }

    #[test]
    fn spot_oracle_lender_is_drained_in_one_atomic_transaction() {
        // `price()` reads the pair's spot reserves; the SAME sequence is the
        // control below against a fixed price.
        let (mut db, a) = lender_db(SPOT_LENDER_HEX, true);
        let r = transact(&mut db, EOA, a, U256::ZERO, encode_run(&[T1], 9, &manipulation_calls(a))).unwrap();
        assert!(matches!(r, ExecutionResult::Success { .. }), "attack must succeed: {r:?}");
        let profits = parse_profit_logs(&r);
        assert_eq!(profits.len(), 1, "{profits:?}");
        let (token, opening, closing, fee) = profits[0];
        assert_eq!(token, T1);
        assert_eq!(opening, u(10_000 * E18));
        assert!(closing > opening + fee, "net profit expected: {opening} -> {closing} (fee {fee})");
        // The event matches chain state.
        assert_eq!(balance_of(&mut db, T1, a).unwrap(), closing);
    }

    #[test]
    fn fixed_oracle_lender_control_is_not_profitable_and_is_fully_atomic() {
        // Immutable `fixedPrice` is baked into constructor code, so this runtime
        // artifact reads 0: the lender pays nothing. Either way the contract must
        // refuse a sequence that doesn't beat repayment + fee.
        let (mut db, a) = lender_db(FIXED_LENDER_HEX, false);
        let r = transact(&mut db, EOA, a, U256::ZERO, encode_run(&[T1], 9, &manipulation_calls(a))).unwrap();
        assert!(reverted_with(&r, "NoProfit(address,uint256,uint256,uint256)"), "{r:?}");
        // Nothing from the reverted attempt persisted.
        assert_eq!(balance_of(&mut db, T1, a).unwrap(), u(10_000 * E18));
        assert_eq!(balance_of(&mut db, T1, PAIR).unwrap(), u(1000 * E18));
    }

    #[test]
    fn fee_is_enforced_on_the_opening_balance() {
        // Break even exactly (no calls move value) with a fee: closing == opening
        // < opening + fee, so it must revert as an unpaid fee, not "no profit".
        let (mut db, a) = lender_db(SPOT_LENDER_HEX, true);
        let r = transact(&mut db, EOA, a, U256::ZERO, encode_run(&[T1], 9, &[])).unwrap();
        assert!(reverted_with(&r, "NoProfit(address,uint256,uint256,uint256)"), "{r:?}");
    }

    #[test]
    fn v3_single_range_swap_matches_closed_form_and_stops_at_the_range_edge() {
        let mut db = new_db();
        let q96 = U256::from(Q96);
        let sqrt_lower = q96 * U256::from(7071u64) / U256::from(10_000u64);
        let sqrt_upper = q96 * U256::from(14142u64) / U256::from(10_000u64);
        let l: u128 = 1000 * E18;
        deploy_v3_pool(&mut db, POOL, T0, T1, 3000, q96, sqrt_lower, sqrt_upper, l, u(10_000 * E18), u(10_000 * E18)).unwrap();
        let (a, _) = deploy_atomic_attacker(&mut db, &[T0, T1], u(1_000 * E18)).unwrap();
        let swap = |zero_for_one: bool, amount: u128, limit: U256| {
            call(POOL, "swap(address,bool,int256,uint160,bytes)", &[
                addr(a),
                DynSolValue::Bool(zero_for_one),
                DynSolValue::Int(alloy_primitives::I256::try_from(amount).unwrap(), 256),
                DynSolValue::Uint(limit, 160),
                DynSolValue::Bytes(vec![]),
            ])
        };
        let sqrt_price = |db: &mut Db| -> U256 {
            let out = expect_success("slot0", transact(db, EOA, POOL, U256::ZERO, encode_call("slot0()", &[])).unwrap()).unwrap();
            U256::from_be_slice(&out[..32])
        };

        // 5 token0 in: P' = L*Q96*P / (L*Q96 + inNet*P); out1 = L*(P-P')/Q96.
        let amount_in = 5 * E18;
        let net = u(amount_in) * u(1_000_000 - 3000) / u(1_000_000);
        let p_new = u(l) * q96 / (u(l) + net); // start price is exactly Q96
        let out1 = u(l) * (q96 - p_new) / q96;
        let before1 = balance_of(&mut db, T1, a).unwrap();
        let r = transact(&mut db, EOA, a, U256::ZERO, encode_exec(&[swap(true, amount_in, sqrt_lower + u(1))])).unwrap();
        assert!(matches!(r, ExecutionResult::Success { .. }), "{r:?}");
        assert_eq!(sqrt_price(&mut db), p_new, "post-swap sqrt price");
        assert_eq!(balance_of(&mut db, T1, a).unwrap() - before1, out1, "token1 out");

        // Selling far more token0 than the range holds fills only up to the lower
        // bound; the pool never prices outside its single range.
        let r = transact(&mut db, EOA, a, U256::ZERO, encode_exec(&[swap(true, 900 * E18, sqrt_lower + u(1))])).unwrap();
        assert!(matches!(r, ExecutionResult::Success { .. }), "{r:?}");
        let p = sqrt_price(&mut db);
        assert!(p >= sqrt_lower + u(1) && p < sqrt_lower + u(2), "clamped at lower bound: {p} vs {sqrt_lower}");

        // Price rises again with token1 in.
        let r = transact(&mut db, EOA, a, U256::ZERO, encode_exec(&[swap(false, 10 * E18, U256::ZERO)])).unwrap();
        assert!(matches!(r, ExecutionResult::Success { .. }), "{r:?}");
        assert!(sqrt_price(&mut db) > p);
    }
}
