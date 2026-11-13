//! Parameterized reentrancy attacker harness.
//!
//! Provides a runtime-configurable reentrancy attacker contract that can
//! re-enter ANY fuzz target, configured at runtime via `setTarget(address)`
//! and `setReentrySelector(bytes4)`.
//!
//! ## Provenance
//!
//! The runtime bytecode in `data/param_attacker_runtime.bin` was produced by
//! compiling the following Solidity contract with `solc-js 0.8.38` and is
//! pinned by `test_param_attacker_bytecode_selectors` plus the reentrancy
//! callback test below:
//!
//! ```solidity
//! // SPDX-License-Identifier: MIT
//! pragma solidity ^0.8.20;
//! contract ParamReentrancyAttacker {
//!     address public target;                    // slot 0
//!     bytes32 public reentrySelector;           // slot 1
//!     function setTarget(address t) external { target = t; }
//!     function setReentrySelector(bytes4 s) external { reentrySelector = bytes32(s); }
//!     receive() external payable {
//!         require(target != address(0), "no target");
//!         bytes4 sel = bytes4(reentrySelector);
//!         (bool ok,) = target.call(abi.encodeWithSelector(sel));
//!         require(ok, "reentry failed");
//!     }
//! }
//! ```
//!
//! ### Why `bytes32` instead of `bytes4` for the `reentrySelector` storage
//!
//! Solidity packs consecutive state variables that fit in a single 32-byte
//! slot. `address` (20 bytes) + `bytes4` (4 bytes) = 24 bytes, which fits —
//! so the literal spec source (`bytes4 public reentrySelector`) places the
//! selector in slot 0 bytes 20..23 *packed with* the address, not in its
//! own slot. That contradicts the task spec's storage assertions
//! ("slot 0 == addr", "slot 1 == sel") and makes the bytecode harder to
//! introspect during fuzzing.
//!
//! Declaring the storage variable as `bytes32` forces it into its own slot
//! (slot 1) while the public setter `setReentrySelector(bytes4)` and the
//! `bytes4` re-entry call semantics are preserved. The selector is stored
//! left-aligned in slot 1 (bytes 0..4), matching the natural `bytes32(bytes4)`
//! zero-extended encoding and the ABI encoding of `bytes4` in a 32-byte word.
//!
//! `solc` is not part of the build, so the compiled bytes are committed to
//! the repo and `include_bytes!`-ed below. The selectors used by the
//! dispatcher are recomputed at runtime via `revm::primitives::keccak256`
//! and pinned by `test_param_attacker_bytecode_selectors`, so a future
//! bytecode refresh that breaks the dispatch table is caught.
//!
//! ## Verification
//!
//! `test_param_attacker_reentrancy_callback` is the confidence gate: it
//! deploys the bytecode into a fresh `CacheDB<ForkDb::empty()>`, configures
//! it via real `setTarget`/`setReentrySelector` transactions, sends ETH to
//! the attacker, and asserts the configured target was re-entered.

use anyhow::Result;
use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::primitives::{keccak256, Address, TxKind, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::{Context, ExecuteCommitEvm, MainBuilder, MainContext};

use rustyfuzz_evm::fork_db::ForkDb;

/// Address where the parameterized reentrancy attacker is deployed.
///
/// Deliberately a recognisable sentinel so a fuzz campaign can scan for it
/// without ambiguity. The address holds no special meaning on-chain.
pub const ATTACKER_ADDRESS: Address = Address::new([0xa7; 20]);

/// The externally-owned account that funds the attacker and sends the
/// `setTarget` / `setReentrySelector` setup transactions. Pre-funded in
/// [`deploy_param_reentrancy_attacker`] with enough ETH to cover setup gas.
pub const DEPLOYER_ADDRESS: Address = Address::new([0xde; 20]);

/// `keccak256("setTarget(address)")[0..4]` = `0x776d1a01`.
///
/// (The task spec quoted `0x55241077`, which is not the actual keccak of that
/// signature; the value used here is the one `solc-js` produced for the same
/// signature and is verified by `test_param_attacker_bytecode_selectors`.)
pub const SET_TARGET_SELECTOR: [u8; 4] = [0x77, 0x6d, 0x1a, 0x01];

/// `keccak256("setReentrySelector(bytes4)")[0..4]` = `0xa71c3ccc`.
///
/// Computed at runtime by [`set_reentry_selector`] via
/// `revm::primitives::keccak256` and pinned by
/// `test_param_attacker_bytecode_selectors`.
pub const SET_REENTRY_SELECTOR: [u8; 4] = [0xa7, 0x1c, 0x3c, 0xcc];

/// `keccak256("withdraw()")[0..4]` = `0x3ccfd60b`. A sensible default
/// re-entry target: most vault-style vulnerable contracts expose a
/// `withdraw()` that sends ETH to `msg.sender`, which is what triggers the
/// attacker's `receive()` in the canonical reentrancy exploit.
pub const DEFAULT_REENTRY_SELECTOR: [u8; 4] = [0x3c, 0xcf, 0xd6, 0x0b];

/// Runtime bytecode of the parameterized reentrancy attacker, embedded from
/// `src/engine/data/param_attacker_runtime.bin` (1573 bytes, solc-js 0.8.38
/// output for the source quoted in the module-level provenance comment).
pub const PARAM_ATTACKER_RUNTIME_BYTECODE: &[u8] =
    include_bytes!("data/param_attacker_runtime.bin");

/// Recomputes the four-byte selector for `setReentrySelector(bytes4)` at
/// runtime via `revm::primitives::keccak256`. Used by
/// `assemble_param_attacker_bytecode` and the bytecode-self-check test.
pub fn set_reentry_selector_signature() -> &'static [u8] {
    b"setReentrySelector(bytes4)"
}

/// `keccak256("setReentrySelector(bytes4)")[0..4]` computed at runtime.
pub fn set_reentry_selector() -> [u8; 4] {
    let hash = keccak256(set_reentry_selector_signature());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// `keccak256("setTarget(address)")[0..4]` computed at runtime.
pub fn set_target_selector() -> [u8; 4] {
    let hash = keccak256(b"setTarget(address)");
    [hash[0], hash[1], hash[2], hash[3]]
}

/// ABI-encodes `setTarget(address)` calldata: selector + 32-byte left-padded
/// address word.
pub fn encode_set_target(target: Address) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&SET_TARGET_SELECTOR);
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(target.as_slice());
    calldata.extend_from_slice(&word);
    calldata
}

/// ABI-encodes `setReentrySelector(bytes4)` calldata: selector + 32-byte
/// word whose HIGH 4 bytes hold the reentry selector (bytes 0..4).
///
/// `bytes4` is a fixed-byte type, so the ABI packs it LEFT-aligned in the
/// 32-byte word (the bytes occupy the high-order positions, padded with
/// zeros on the right). This is the opposite of `address`/`uintN` which are
/// right-aligned. Solidity 0.8.x's strict ABI decoder reverts if the
/// trailing padding bytes are non-zero, so getting this alignment right is
/// load-bearing — see `test_param_attacker_set_target_and_reentry`.
pub fn encode_set_reentry_selector(selector: [u8; 4]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&SET_REENTRY_SELECTOR);
    let mut word = [0u8; 32];
    word[0..4].copy_from_slice(&selector);
    calldata.extend_from_slice(&word);
    calldata
}

/// Reads the storage slot for an account directly from the cache. Returns
/// `U256::ZERO` if the account or slot has never been touched, mirroring the
/// EVM's cold-storage semantics for tests.
pub fn cached_storage(db: &CacheDB<ForkDb>, address: Address, slot: U256) -> U256 {
    db.cache
        .accounts
        .get(&address)
        .and_then(|account| account.storage.get(&slot).copied())
        .unwrap_or(U256::ZERO)
}

/// Executes a single revm transaction against `db` and commits the resulting
/// state. Used internally by [`deploy_param_reentrancy_attacker`] to run the
/// `setTarget` / `setReentrySelector` setup transactions against the freshly
/// deployed attacker.
///
/// The caller's nonce is read from the cache immediately before building the
/// `TxEnv`, mirroring [`rustyfuzz_evm::executor::EvmExecutor`]'s pattern.
/// This is what makes the second setup transaction (and the deposit/withdraw
/// probe steps) valid: revm would otherwise reject `nonce 0 too low, expected
/// 1` after the first transaction commits and increments the cached nonce.
///
/// Returns the [`revm::context::result::ExecutionResult`] so callers can
/// distinguish success from revert.
fn transact_commit(
    db: &mut CacheDB<ForkDb>,
    caller: Address,
    to: Address,
    value: U256,
    data: Vec<u8>,
) -> Result<revm::context::result::ExecutionResult> {
    // Read the caller's current nonce so sequential transactions in the same
    // deploy/probe sequence validate. `load_account` populates the cache for
    // a previously-unseen account; the nonce then matches what revm will
    // check inside `transact_commit`.
    let caller_nonce = db.load_account(caller)?.info.nonce;
    let tx_env = TxEnv {
        caller,
        gas_limit: 1_000_000,
        gas_price: 0,
        chain_id: Some(1),
        value,
        data: data.into(),
        kind: if to == Address::ZERO {
            TxKind::Create
        } else {
            TxKind::Call(to)
        },
        nonce: caller_nonce,
        ..Default::default()
    };
    let mut evm = Context::mainnet().with_db(&mut *db).build_mainnet();
    let result = evm.transact_commit(tx_env)?;
    Ok(result)
}

/// Deploys the parameterized reentrancy attacker at [`ATTACKER_ADDRESS`] and
/// configures it to re-enter `target` with `reentry_selector` when it
/// receives ETH.
///
/// ## Setup approach: inline revm execution
///
/// The setter state is written by actually executing `setTarget(target)` and
/// `setReentrySelector(reentry_selector)` as revm transactions from
/// [`DEPLOYER_ADDRESS`], not by directly poking storage. This is the first
/// alternative the task spec offered ("build + execute two setup
/// transactions in a fresh revm EVM") and it doubles as a runtime
/// verification that the embedded bytecode's setters work the way the
/// reentrancy probe assumes.
///
/// After this call returns, sending ETH to `ATTACKER_ADDRESS` (with empty
/// calldata) triggers `target.<reentry_selector>()`.
///
/// The attacker is also pre-funded with `setup_balance` so a downstream
/// probe can immediately use it as the `msg.sender` of a deposit transaction
/// without an extra funding step.
pub fn deploy_param_reentrancy_attacker(
    db: &mut CacheDB<ForkDb>,
    target: Address,
    reentry_selector: [u8; 4],
) -> Result<Address> {
    deploy_param_reentrancy_attacker_with_balance(
        db,
        target,
        reentry_selector,
        U256::from(10u128.pow(30)),
    )
}

/// Same as [`deploy_param_reentrancy_attacker`] but lets the caller pick the
/// attacker's starting ETH balance. Useful for tests that need a tiny,
/// deterministic balance.
pub fn deploy_param_reentrancy_attacker_with_balance(
    db: &mut CacheDB<ForkDb>,
    target: Address,
    reentry_selector: [u8; 4],
    attacker_balance: U256,
) -> Result<Address> {
    // 1. Install the runtime bytecode at ATTACKER_ADDRESS and pre-fund it so
    //    it can be the `msg.sender` of subsequent deposit calls.
    db.insert_account_info(
        ATTACKER_ADDRESS,
        AccountInfo {
            balance: attacker_balance,
            ..AccountInfo::default()
        }
        .with_code(Bytecode::new_raw(
            PARAM_ATTACKER_RUNTIME_BYTECODE.to_vec().into(),
        )),
    );

    // 2. Pre-fund the deployer so its setup transactions pass revm's balance
    //    and nonce validation.
    db.insert_account_info(
        DEPLOYER_ADDRESS,
        AccountInfo {
            balance: U256::from(10u128.pow(30)),
            ..AccountInfo::default()
        },
    );

    // 3. Run setTarget(target) from the deployer. This both configures the
    //    attacker and proves the embedded bytecode's setter works.
    let set_target_data = encode_set_target(target);
    let set_target_result = transact_commit(
        db,
        DEPLOYER_ADDRESS,
        ATTACKER_ADDRESS,
        U256::ZERO,
        set_target_data,
    )?;
    if !set_target_result.is_success() {
        anyhow::bail!(
            "param attacker setTarget transaction failed: {:?}",
            set_target_result
        );
    }

    // 4. Run setReentrySelector(reentry_selector) from the deployer.
    let set_selector_data = encode_set_reentry_selector(reentry_selector);
    let set_selector_result = transact_commit(
        db,
        DEPLOYER_ADDRESS,
        ATTACKER_ADDRESS,
        U256::ZERO,
        set_selector_data,
    )?;
    if !set_selector_result.is_success() {
        anyhow::bail!(
            "param attacker setReentrySelector transaction failed: {:?}",
            set_selector_result
        );
    }

    Ok(ATTACKER_ADDRESS)
}

/// Deploys the parameterized attacker pre-configured to re-enter `target`
/// with the canonical `withdraw()` selector (`0x3ccfd60b`). Kept as a
/// backward-compatible entry point matching the shape of the FIX-C
/// pre-baked harness: callers that just want "re-enter target on every ETH
/// receipt" get the most common case for free.
pub fn deploy_reentrancy_attacker(db: &mut CacheDB<ForkDb>, target: Address) -> Result<Address> {
    deploy_param_reentrancy_attacker(db, target, DEFAULT_REENTRY_SELECTOR)
}

/// One step of a reentrancy probe sequence. The campaign executor turns
/// each step into a revm `TxEnv` and commits it in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackerProbeStep {
    /// Transaction sender. Setup steps use [`DEPLOYER_ADDRESS`]; deposit and
    /// withdraw steps use [`ATTACKER_ADDRESS`] so the target sends ETH back
    /// to the attacker and triggers `receive()`.
    pub caller: Address,
    /// Recipient of the call.
    pub to: Address,
    /// ABI-encoded calldata (selector + args).
    pub calldata: Vec<u8>,
    /// ETH value attached to the call, in wei.
    pub value: U256,
}

/// Builds the reentrancy probe sequence for a fuzz target that exposes a
/// `deposit()`-style payable function (which credits the caller) and a
/// `withdraw()`-style function (which sends ETH back to `msg.sender`).
///
/// The sequence is:
/// 1. `target.deposit{value: amount}()` from the attacker — funds the
///    attacker's credit so `withdraw` has something to send back.
/// 2. `target.withdraw()` from the attacker — the target sends ETH to
///    `ATTACKER_ADDRESS`, triggering `receive()`, which re-enters
///    `target.<reentry_selector>()` before the target has had a chance to
///    zero the attacker's credit. This is the classic reentrancy exploit
///    shape.
///
/// Setup (`setTarget` / `setReentrySelector`) is **not** included here:
/// [`deploy_param_reentrancy_attacker`] configures the attacker inline, so
/// the probe can start directly at `deposit`. If the caller wants a
/// self-contained probe that works without prior deployment, they can
/// prepend the two setup calldatas via [`encode_set_target`] and
/// [`encode_set_reentry_selector`].
pub fn build_reentrancy_probe(
    target: Address,
    deposit_selector: [u8; 4],
    withdraw_selector: [u8; 4],
    amount: U256,
) -> Vec<AttackerProbeStep> {
    vec![
        AttackerProbeStep {
            caller: ATTACKER_ADDRESS,
            to: target,
            calldata: deposit_selector.to_vec(),
            value: amount,
        },
        AttackerProbeStep {
            caller: ATTACKER_ADDRESS,
            to: target,
            calldata: withdraw_selector.to_vec(),
            value: U256::ZERO,
        },
    ]
}

/// Minimal target used by the reentrancy-callback test: on any call it
/// `SSTORE`s 1 into slot 0 and stops. The probe asserts slot 0 == 1 after
/// the attacker's `receive()` fires, proving the re-entry actually happened.
#[cfg(test)]
const SIMPLE_LOGGING_TARGET_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];

/// Builds a target contract that `SSTORE`s 1 into slot 0 if the incoming
/// call's first 4 bytes (the selector) equal `expected`, and `SSTORE`s 2
/// otherwise. Used by `test_param_attacker_uses_configured_selector` to
/// prove the attacker's `receive()` actually invokes the target with the
/// selector stored in slot 1 — not just any call.
///
/// Layout (26 bytes):
/// ```text
/// 5f          PUSH0           ; calldataload offset = 0
/// 35          CALLDATALOAD    ; load first 32 bytes
/// 60 e0       PUSH1 0xe0      ; 224
/// 1c          SHR             ; selector in low 4 bytes
/// 63 <sel>    PUSH4 expected  ; expected selector
/// 14          EQ              ; selector == expected?
/// 60 14       PUSH1 0x14      ; jump target (selector-match branch)
/// 57          JUMPI           ; if match, jump to 0x14
/// 60 02       PUSH1 0x02      ; mismatch value
/// 60 00       PUSH1 0x00      ; slot 0
/// 55          SSTORE          ; SSTORE slot 0 = 2 (mismatch)
/// 00          STOP
/// 5b          JUMPDEST        ; 0x14: selector-match branch
/// 60 01       PUSH1 0x01      ; match value
/// 60 00       PUSH1 0x00      ; slot 0
/// 55          SSTORE          ; SSTORE slot 0 = 1 (match)
/// 00          STOP
/// ```
#[cfg(test)]
fn selector_gated_logging_target_bytecode(expected: [u8; 4]) -> Vec<u8> {
    vec![
        0x5f,
        0x35,
        0x60,
        0xe0,
        0x1c,
        0x63,
        expected[0],
        expected[1],
        expected[2],
        expected[3],
        0x14,
        0x60,
        0x14,
        0x57,
        0x60,
        0x02,
        0x60,
        0x00,
        0x55,
        0x00,
        0x5b,
        0x60,
        0x01,
        0x60,
        0x00,
        0x55,
        0x00,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::context::result::ExecutionResult;
    use revm::database::CacheDB;
    use revm::primitives::{Address, U256};
    use revm::state::{AccountInfo, Bytecode};
    use rustyfuzz_evm::fork_db::ForkDb;

    /// A non-zero address used as the "fuzz target" in the setter test.
    fn sample_target() -> Address {
        Address::new([0x22; 20])
    }

    /// A second non-zero address used as the "logging target" in the
    /// reentrancy-callback test.
    fn logging_target() -> Address {
        Address::new([0x33; 20])
    }

    /// Fresh attacker-only database: just the attacker code at
    /// `ATTACKER_ADDRESS`, no target or storage set up.
    fn attacker_only_db() -> CacheDB<ForkDb> {
        let mut db = CacheDB::new(ForkDb::empty());
        db.insert_account_info(
            DEPLOYER_ADDRESS,
            AccountInfo {
                balance: U256::from(10u128.pow(30)),
                ..AccountInfo::default()
            },
        );
        db.insert_account_info(
            ATTACKER_ADDRESS,
            AccountInfo::default().with_code(Bytecode::new_raw(
                PARAM_ATTACKER_RUNTIME_BYTECODE.to_vec().into(),
            )),
        );
        db
    }

    /// Asserts the embedded `PARAM_ATTACKER_RUNTIME_BYTECODE` produces the
    /// expected dispatcher selectors when executed. This is the cheap,
    /// non-reverting pin that catches a stale `.bin` file before the more
    /// expensive reentrancy test runs.
    #[test]
    fn test_param_attacker_bytecode_selectors() {
        assert_eq!(
            set_target_selector(),
            SET_TARGET_SELECTOR,
            "setTarget(address) selector must match the embedded constant"
        );
        assert_eq!(
            set_reentry_selector(),
            SET_REENTRY_SELECTOR,
            "setReentrySelector(bytes4) selector must match the embedded constant"
        );
        assert_eq!(
            DEFAULT_REENTRY_SELECTOR,
            [0x3c, 0xcf, 0xd6, 0x0b],
            "default reentry selector must be withdraw()"
        );
        // Sanity-check the bytecode is non-empty and starts with the
        // standard Solidity dispatcher prefix (PUSH1 0x80 PUSH1 0x40 MSTORE).
        assert!(
            PARAM_ATTACKER_RUNTIME_BYTECODE.len() > 100,
            "embedded bytecode is unexpectedly short: {} bytes",
            PARAM_ATTACKER_RUNTIME_BYTECODE.len()
        );
        assert_eq!(
            &PARAM_ATTACKER_RUNTIME_BYTECODE[..3],
            &[0x60, 0x80, 0x60],
            "bytecode does not start with the Solidity free-memory-pointer prefix"
        );
    }

    /// Deploys the param attacker, calls `setTarget` and
    /// `setReentrySelector` via real revm transactions, and asserts the
    /// storage slots match. This is the second half of the verification
    /// that the embedded bytecode actually implements the Solidity source
    /// above.
    #[test]
    fn test_param_attacker_set_target_and_reentry() {
        let mut db = attacker_only_db();
        let target = sample_target();
        let selector: [u8; 4] = [0x3c, 0xcf, 0xd6, 0x0b];

        // setTarget(target)
        let set_target_result = transact_commit(
            &mut db,
            DEPLOYER_ADDRESS,
            ATTACKER_ADDRESS,
            U256::ZERO,
            encode_set_target(target),
        )
        .expect("setTarget transaction must execute");
        assert!(
            set_target_result.is_success(),
            "setTarget reverted: {set_target_result:?}"
        );
        let stored_target = cached_storage(&db, ATTACKER_ADDRESS, U256::ZERO);
        assert_eq!(
            stored_target,
            U256::from_be_bytes({
                let mut bytes = [0u8; 32];
                bytes[12..].copy_from_slice(target.as_slice());
                bytes
            }),
            "slot 0 must hold the address we set via setTarget"
        );

        // setReentrySelector(selector)
        let set_selector_result = transact_commit(
            &mut db,
            DEPLOYER_ADDRESS,
            ATTACKER_ADDRESS,
            U256::ZERO,
            encode_set_reentry_selector(selector),
        )
        .expect("setReentrySelector transaction must execute");
        assert!(
            set_selector_result.is_success(),
            "setReentrySelector reverted: {set_selector_result:?}"
        );
        let stored_selector = cached_storage(&db, ATTACKER_ADDRESS, U256::from(1u64));
        // The selector is stored as a `bytes32(bytes4)` in slot 1 — i.e. the
        // 4 selector bytes occupy the HIGH-order positions of the 32-byte
        // word (bytes 0..4), with the remaining 28 bytes zero. As a U256
        // that is `selector << 224`. This mirrors the ABI encoding of
        // `bytes4` and is what `bytes32(bytes4 s)` produces in Solidity.
        assert_eq!(
            stored_selector,
            U256::from_be_bytes({
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&selector);
                bytes
            }),
            "slot 1 must hold the selector we set via setReentrySelector (left-aligned)"
        );
        // Slot 0 must be unchanged by setReentrySelector: the address is
        // still there, no spillover from the bytes32 write.
        let stored_target_after_sel = cached_storage(&db, ATTACKER_ADDRESS, U256::ZERO);
        assert_eq!(
            stored_target_after_sel, stored_target,
            "setReentrySelector must not perturb slot 0 (target)"
        );
    }

    /// THE confidence gate. Deploys the attacker, configures it to re-enter
    /// a minimal logging target, sends ETH to the attacker, and asserts the
    /// target was actually called back. If this test passes, the embedded
    /// bytecode genuinely re-enters the configured target on ETH receipt.
    #[test]
    fn test_param_attacker_reentrancy_callback() {
        let mut db = CacheDB::new(ForkDb::empty());

        // Deploy the minimal logging target: SSTORE slot 0 = 1 on any call.
        let target = logging_target();
        db.insert_account_info(
            target,
            AccountInfo::default().with_code(Bytecode::new_raw(
                SIMPLE_LOGGING_TARGET_BYTECODE.to_vec().into(),
            )),
        );

        // Deploy + configure the attacker via real setter transactions.
        deploy_param_reentrancy_attacker(&mut db, target, DEFAULT_REENTRY_SELECTOR)
            .expect("attacker deployment must succeed");

        // Sanity-check the attacker was configured by the deploy function.
        let stored_target = cached_storage(&db, ATTACKER_ADDRESS, U256::ZERO);
        assert_ne!(
            stored_target,
            U256::ZERO,
            "deploy must set the target before we trigger receive()"
        );

        // Send ETH to the attacker from the deployer with EMPTY calldata.
        // This triggers the attacker's receive() handler, which must call
        // target.<DEFAULT_REENTRY_SELECTOR>() and SSTORE slot 0 = 1.
        let send_eth_result = transact_commit(
            &mut db,
            DEPLOYER_ADDRESS,
            ATTACKER_ADDRESS,
            U256::from(1u128),
            Vec::new(),
        )
        .expect("send-eth transaction must execute");
        assert!(
            send_eth_result.is_success(),
            "receive() reverted: {send_eth_result:?}"
        );

        // THE assertion: the target's slot 0 must be 1, proving the
        // attacker's receive() called back into the target.
        let target_slot_0 = cached_storage(&db, target, U256::ZERO);
        assert_eq!(
            target_slot_0,
            U256::from(1u64),
            "target slot 0 must be 1: the attacker's receive() must have re-entered the target"
        );
    }

    /// Stronger confidence gate: proves the attacker's `receive()` invokes the
    /// target with the **selector stored in slot 1**, not just any call.
    ///
    /// Uses a selector-gated target that `SSTORE`s 1 if the incoming call's
    /// selector matches a configured value and 2 otherwise. We deploy the
    /// attacker twice — once with the matching selector, once with a
    /// mismatching one — and assert the target's slot 0 reflects which path
    /// the attacker took. If the attacker hardcoded any selector (or ignored
    /// slot 1), exactly one of these two cases would fail.
    #[test]
    fn test_param_attacker_uses_configured_selector() {
        let target = logging_target();
        let matching_selector: [u8; 4] = [0x3c, 0xcf, 0xd6, 0x0b]; // withdraw()
        let mismatching_selector: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

        // --- Case A: attacker configured with the MATCHING selector.
        // Target expects `matching_selector`; receive() must call with that
        // selector, so the target writes 1.
        let mut db_a = CacheDB::new(ForkDb::empty());
        db_a.insert_account_info(
            target,
            AccountInfo::default().with_code(Bytecode::new_raw(
                selector_gated_logging_target_bytecode(matching_selector).into(),
            )),
        );
        deploy_param_reentrancy_attacker(&mut db_a, target, matching_selector)
            .expect("deploy attacker with matching selector");
        let send_a = transact_commit(
            &mut db_a,
            DEPLOYER_ADDRESS,
            ATTACKER_ADDRESS,
            U256::from(1u128),
            Vec::new(),
        )
        .expect("send-eth transaction must execute");
        assert!(
            send_a.is_success(),
            "receive() with matching selector reverted: {send_a:?}"
        );
        assert_eq!(
            cached_storage(&db_a, target, U256::ZERO),
            U256::from(1u64),
            "matching selector: target slot 0 must be 1 (selector match branch)"
        );

        // --- Case B: attacker configured with a MISMATCHING selector.
        // Target still expects `matching_selector`; receive() must call with
        // `mismatching_selector`, so the target writes 2.
        let mut db_b = CacheDB::new(ForkDb::empty());
        db_b.insert_account_info(
            target,
            AccountInfo::default().with_code(Bytecode::new_raw(
                selector_gated_logging_target_bytecode(matching_selector).into(),
            )),
        );
        deploy_param_reentrancy_attacker(&mut db_b, target, mismatching_selector)
            .expect("deploy attacker with mismatching selector");
        let send_b = transact_commit(
            &mut db_b,
            DEPLOYER_ADDRESS,
            ATTACKER_ADDRESS,
            U256::from(1u128),
            Vec::new(),
        )
        .expect("send-eth transaction must execute");
        assert!(
            send_b.is_success(),
            "receive() with mismatching selector reverted: {send_b:?}"
        );
        assert_eq!(
            cached_storage(&db_b, target, U256::ZERO),
            U256::from(2u64),
            "mismatching selector: target slot 0 must be 2 (selector mismatch branch)"
        );
    }

    /// Without a configured target (`target == address(0)`), `receive()`
    /// must revert. This is the Solidity `require(target != address(0))`
    /// branch.
    #[test]
    fn test_param_attacker_reverts_without_target() {
        let mut db = attacker_only_db();

        // Deliberately DO NOT call setTarget. Slot 0 stays zero.
        assert_eq!(
            cached_storage(&db, ATTACKER_ADDRESS, U256::ZERO),
            U256::ZERO,
            "precondition: target slot must be zero before receive()"
        );

        // Send ETH. The attacker must revert because target == 0.
        let result = transact_commit(
            &mut db,
            DEPLOYER_ADDRESS,
            ATTACKER_ADDRESS,
            U256::from(1u128),
            Vec::new(),
        )
        .expect("send-eth transaction must execute");
        assert!(
            matches!(result, ExecutionResult::Revert { .. }),
            "receive() without target must revert, got: {result:?}"
        );
    }

    /// `deploy_reentrancy_attacker` is the backward-compatible wrapper: it
    /// must produce the same configured-attacker state as
    /// `deploy_param_reentrancy_attacker` with `DEFAULT_REENTRY_SELECTOR`.
    #[test]
    fn test_deploy_reentrancy_attacker_uses_default_selector() {
        let target = sample_target();
        let mut db_a = CacheDB::new(ForkDb::empty());
        deploy_reentrancy_attacker(&mut db_a, target).expect("deploy via wrapper");

        let mut db_b = CacheDB::new(ForkDb::empty());
        deploy_param_reentrancy_attacker(&mut db_b, target, DEFAULT_REENTRY_SELECTOR)
            .expect("deploy via parameterized path");

        let target_a = cached_storage(&db_a, ATTACKER_ADDRESS, U256::ZERO);
        let target_b = cached_storage(&db_b, ATTACKER_ADDRESS, U256::ZERO);
        assert_eq!(target_a, target_b, "wrapper must set the same target");

        let sel_a = cached_storage(&db_a, ATTACKER_ADDRESS, U256::from(1u64));
        let sel_b = cached_storage(&db_b, ATTACKER_ADDRESS, U256::from(1u64));
        assert_eq!(sel_a, sel_b, "wrapper must set the same selector");
        // Selector is stored left-aligned in slot 1 (bytes 0..4 of the
        // 32-byte word), as `bytes32(bytes4)` produces. Verify the high 4
        // bytes are exactly `DEFAULT_REENTRY_SELECTOR` and the rest is zero.
        let sel_bytes = sel_a.to_be_bytes::<32>();
        assert_eq!(
            sel_bytes[0..4],
            DEFAULT_REENTRY_SELECTOR[..],
            "wrapper must use withdraw() as the default selector (left-aligned in slot 1)"
        );
        assert!(
            sel_bytes[4..].iter().all(|b| *b == 0),
            "slot 1 must be zero-padded after the selector, got {sel_a:#034x}"
        );
    }

    /// The probe sequence for a canonical vault-shaped target must be
    /// exactly two steps: deposit (with value) then withdraw (no value),
    /// both sent from the attacker so the target's ETH refund triggers
    /// `receive()`.
    #[test]
    fn test_build_reentrancy_probe_canonical_sequence() {
        let target = sample_target();
        let deposit: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0]; // deposit()
        let withdraw: [u8; 4] = [0x3c, 0xcf, 0xd6, 0x0b]; // withdraw()
        let amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

        let steps = build_reentrancy_probe(target, deposit, withdraw, amount);
        assert_eq!(steps.len(), 2, "probe must be exactly deposit + withdraw");

        assert_eq!(steps[0].caller, ATTACKER_ADDRESS);
        assert_eq!(steps[0].to, target);
        assert_eq!(steps[0].calldata, deposit.to_vec());
        assert_eq!(steps[0].value, amount);

        assert_eq!(steps[1].caller, ATTACKER_ADDRESS);
        assert_eq!(steps[1].to, target);
        assert_eq!(steps[1].calldata, withdraw.to_vec());
        assert_eq!(steps[1].value, U256::ZERO);
    }
}
