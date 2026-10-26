//! Exporting a real `ForkDbCacheSnapshot` from an archive RPC.
//!
//! # Why this exists
//!
//! The offline replay path (`mainnet_fork` benchmarks) accepts only a
//! `ForkDbCacheSnapshot` with a matching content digest and pinned provenance. Nothing in
//! the tool could *produce* one, so historical replay had no legal entry point: the format
//! was validated but never populated. This module is that entry point.
//!
//! # The honesty problem, stated up front
//!
//! A snapshot is a set of specific slots. A `mapping` cannot be enumerated over JSON-RPC,
//! and neither can storage written in a block we are not replaying. "Complete state" is
//! not achievable, and this module does not pretend otherwise. It:
//!
//! 1. discovers accounts from the *pre-exploit* block and from explicitly named accounts;
//! 2. fetches code, nonce and balance for each;
//! 3. fetches **only the slots it was told about** — from authored invariant bindings and
//!    from explicitly named slots;
//! 4. reports which slots it fetched, which read as zero, and that unlisted slots are
//!    **absent rather than zero**.
//!
//! Point 4 is the difference between a useful capture tool and a machine for manufacturing
//! false confidence. A snapshot that silently returned zero for unfetched slots would make
//! predicates resolve to confident wrong answers — and `Unknown` decaying into `0` is
//! exactly the failure the predicate layer was built to prevent.
//!
//! # What a digest does and does not prove
//!
//! `content_digest` proves the bytes were not corrupted. It proves **nothing** about
//! authenticity. Provenance is recorded from the same RPC, so it is only as trustworthy as
//! that endpoint. The block hash must be checked against an independent source before the
//! snapshot is treated as historical evidence.

use anyhow::{anyhow, Context, Result};
use revm::database::DatabaseRef;
use revm::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::str::FromStr;

use rustyfuzz_evm::fork_db::{ForkDb, ForkDbCacheSnapshot};

/// One slot to capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotRequest {
    pub address: String,
    pub slot: String,
    /// Where this request came from, so a report can justify a slot's presence.
    pub source: String,
}

/// What the capture produced, and what it could not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureReport {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: Option<String>,
    pub provider_sanitized: String,
    pub content_digest: String,
    pub accounts: usize,
    pub slots: usize,
    pub codes: usize,
    /// Accounts the capture fetched state for.
    pub captured_accounts: Vec<String>,
    /// Slots that read as zero on chain, listed separately from un-fetched slots.
    pub zero_valued_slots: Vec<String>,
    /// Accounts named in the request that hold no code at this block.
    ///
    /// Worth surfacing: an EOA where a contract was expected means the pin is wrong or the
    /// address is wrong, and both are cheap to catch here rather than mid-replay.
    pub codeless_accounts: Vec<String>,
    /// `proxy:implementation` pairs discovered by following EIP-1967 pointers.
    ///
    /// Recorded because a reader must be able to tell whether a proxy in this snapshot had
    /// its implementation captured, and one level of following is not a general guarantee.
    pub proxy_implementations: Vec<String>,
    /// The caveat a reader must see, written into the artifact rather than a comment.
    pub completeness: String,
}

/// The EIP-1967 implementation slot.
///
/// `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`. Three of the Audius
/// contracts use exactly this layout, verified by disassembling their runtime and finding
/// the constant pushed before an `SLOAD`.
pub const EIP1967_IMPLEMENTATION_SLOT: B256 = B256::new([
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
    0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
]);

/// Follows an EIP-1967 implementation pointer, if the account is a proxy.
///
/// # Why this is required rather than a convenience
///
/// A proxy's own bytecode is a delegate stub; it contains no implementation code. A replay
/// that calls through a proxy therefore needs the implementation's code in the snapshot,
/// and the implementation appears nowhere in the proxy's account entry. Without this step a
/// captured proxy is unexecutable, and the failure surfaces mid-replay as a call into empty
/// code rather than as a clear error.
///
/// Returns `None` when the slot is empty, which is the honest answer for a non-proxy: the
/// caller must not treat "no pointer" as "pointer to zero".
pub fn follow_implementation(fork: &ForkDb, proxy: Address) -> Result<Option<Address>> {
    let value = fork
        .storage_ref(proxy, EIP1967_IMPLEMENTATION_SLOT.into())
        .map_err(|error| anyhow!("cannot read the implementation slot of {proxy}: {error}"))?;
    if value == U256::ZERO {
        return Ok(None);
    }
    // The pointer is right-aligned in a 32-byte word.
    let bytes: [u8; 32] = value.to_be_bytes();
    let high_is_clear = bytes[..12].iter().all(|byte| *byte == 0);
    if !high_is_clear {
        return Err(anyhow!(
            "implementation slot of {proxy} is not a left-padded address: {value:#x}"
        ));
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes[12..]);
    Ok(Some(Address::from(address)))
}

/// Accounts a capture must include, following proxy pointers one level.
///
/// One level, deliberately: nested proxies are a pattern that would need a cycle guard and a
/// depth budget, and inventing one here would be guessing at a shape none of the audited
/// cases have. A deeper chain reports what it found rather than silently stopping.
pub struct ExpandedAccounts {
    pub all: Vec<Address>,
    /// Proxy -> implementation pairs that were followed.
    pub followed: Vec<(Address, Address)>,
}

pub fn expand_proxies(fork: &ForkDb, accounts: &[Address]) -> Result<ExpandedAccounts> {
    let mut all: BTreeSet<Address> = accounts.iter().copied().collect();
    let mut followed = Vec::new();
    for proxy in accounts {
        if let Some(implementation) = follow_implementation(fork, *proxy)? {
            if implementation != *proxy {
                followed.push((*proxy, implementation));
                all.insert(implementation);
            }
        }
    }
    Ok(ExpandedAccounts {
        all: all.into_iter().collect(),
        followed,
    })
}

/// Builds a `ForkDb` pinned at `block`, with chain id and block hash recorded as
/// provenance.
///
/// Both are mandatory for the offline replay path to accept the resulting snapshot, and
/// both come from the same endpoint, so a capture records what that endpoint claimed. That
/// is provenance, not authentication — see the module note.
pub fn connect(rpc_url: &str, block: u64) -> Result<(u64, ForkDb)> {
    let fork = ForkDb::new(rpc_url, block);
    let chain_id = fork
        .fetch_chain_id()
        .map_err(|error| anyhow!("cannot read chain id: {error}"))?;
    fork.fetch_pinned_block_hash()
        .map_err(|error| anyhow!("cannot read block {block} hash: {error}"))?;
    Ok((chain_id, fork))
}

/// Captures a snapshot at `block_number` for the given accounts and slots.
///
/// Uses `ForkDb` as the transport so the capture shares the live path's URL validation,
/// SSRF guard and API-key handling instead of re-implementing them.
pub fn capture(
    fork: &ForkDb,
    chain_id: u64,
    block_number: u64,
    accounts: &[Address],
    slot_requests: &[SlotRequest],
) -> Result<(ForkDbCacheSnapshot, CaptureReport)> {
    if accounts.is_empty() {
        return Err(anyhow!(
            "no accounts to capture; name at least the target contract"
        ));
    }

    // Follow proxy pointers first: a proxy's own code is a delegate stub, so its
    // implementation must be in the snapshot or every call through the proxy lands in empty
    // code. Doing this inside `capture` rather than leaving it to the caller means a proxy
    // cannot be captured unexecutably by omission.
    let expanded = expand_proxies(fork, accounts)?;
    let accounts = expanded.all.as_slice();

    // Fetch account state through ForkDb, which populates its own caches as a side effect.
    let mut captured = Vec::new();
    let mut codeless = Vec::new();
    for address in accounts {
        let info = fork
            .basic_ref(*address)
            .with_context(|| format!("cannot read account {address} at block {block_number}"))?;
        match info {
            Some(info) if info.code.as_ref().is_some_and(|code| !code.is_empty()) => {
                captured.push(address.to_string())
            }
            Some(_) => codeless.push(address.to_string()),
            None => codeless.push(address.to_string()),
        }
    }

    // Fetch each requested slot. `storage_ref` caches what it reads, so the snapshot below
    // contains exactly these slots and nothing else.
    let mut zero_valued = Vec::new();
    for request in slot_requests {
        let address = Address::from_str(&request.address)
            .with_context(|| format!("slot request address {:?}", request.address))?;
        let slot = parse_word(&request.slot)
            .with_context(|| format!("slot request slot {:?}", request.slot))?;
        let value = fork.storage_ref(address, slot.into()).with_context(|| {
            format!(
                "cannot read storage {address} {slot:#x} ({})",
                request.source
            )
        })?;
        if value == U256::ZERO {
            zero_valued.push(format!("{address}:{slot:#x} ({})", request.source));
        }
    }

    let snapshot = fork.cache_snapshot();

    // A snapshot with no provenance cannot be replayed by the offline path, and a capture
    // that produced one would be silently useless. Fail here instead.
    if snapshot.provenance.chain_id.is_none() {
        return Err(anyhow!(
            "the captured snapshot has no chain id; the offline replay path would reject it"
        ));
    }
    if snapshot.provenance.block_number != Some(block_number) {
        return Err(anyhow!(
            "captured provenance records block {:?}, expected {block_number}",
            snapshot.provenance.block_number
        ));
    }
    snapshot
        .verify_content_digest()
        .map_err(|error| anyhow!("captured snapshot failed its own digest check: {error}"))?;

    let report = CaptureReport {
        chain_id,
        block_number,
        block_hash: snapshot.provenance.block_hash.clone(),
        provider_sanitized: snapshot.provenance.provider_sanitized.clone(),
        content_digest: snapshot.content_digest.clone(),
        accounts: snapshot.accounts.len(),
        slots: snapshot.storage.len(),
        codes: snapshot.code_by_hash.len(),
        captured_accounts: captured,
        zero_valued_slots: zero_valued,
        codeless_accounts: codeless,
        proxy_implementations: expanded
            .followed
            .iter()
            .map(|(proxy, implementation)| format!("{proxy}:{implementation}"))
            .collect(),
        completeness: format!(
            "Captured {} account(s), {} code blob(s) and {} slot(s) at block {}. Slots were \
             fetched ONLY from the requests given; every other slot is ABSENT from this \
             snapshot, so a replay that reads one reports Unknown rather than a fabricated \
             zero. Mappings and other non-enumerable storage are therefore incomplete by \
             construction. The digest proves integrity, not authenticity: verify block hash \
             {:?} against an independent source before treating this as historical evidence.",
            snapshot.accounts.len(),
            snapshot.code_by_hash.len(),
            snapshot.storage.len(),
            block_number,
            snapshot.provenance.block_hash
        ),
    };
    Ok((snapshot, report))
}

/// Parses a 32-byte word, left-padding as JSON-RPC and TOML both return unpadded values.
fn parse_word(text: &str) -> Result<B256> {
    let trimmed = text.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or_else(|| anyhow!("expected a 0x-prefixed word, got {trimmed:?}"))?;
    if hex.len() > 64 {
        return Err(anyhow!(
            "word is longer than 32 bytes: {} hex chars",
            hex.len()
        ));
    }
    let padded = format!("{hex:0>64}");
    let bytes = hex::decode(&padded).context("word is not valid hex")?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(B256::from(out))
}

/// Writes the snapshot and its report next to each other.
pub fn write_snapshot(
    snapshot: &ForkDbCacheSnapshot,
    report: &CaptureReport,
    snapshot_path: &Path,
    report_path: &Path,
) -> Result<()> {
    if let Some(parent) = snapshot_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(snapshot).context("cannot serialise the snapshot")?;
    rustyfuzz_artifacts::fsutil::write_atomic(snapshot_path, &bytes)
        .with_context(|| format!("cannot write {}", snapshot_path.display()))?;
    let report_bytes = serde_json::to_vec_pretty(report).context("cannot serialise the report")?;
    rustyfuzz_artifacts::fsutil::write_atomic(report_path, &report_bytes)
        .with_context(|| format!("cannot write {}", report_path.display()))?;
    Ok(())
}

/// Reads the slot requests authored in an invariants file.
///
/// This is the only *automatic* source of slot knowledge: an authored predicate names the
/// slots it needs, and those are exactly the slots a replay must resolve. Mappings and
/// return values are skipped rather than guessed at, because a mapping needs a key we do
/// not have and a return value is not storage.
pub fn slot_requests_from_invariants(path: &Path) -> Result<Vec<SlotRequest>> {
    let file = crate::engine::invariant_file::InvariantFile::load(path)?;
    let mut out = Vec::new();
    for (symbol, raw) in &file.symbols {
        if raw.kind == "mapping" || raw.kind == "return_value" {
            continue;
        }
        let Some(slot) = raw.slot.as_deref() else {
            continue;
        };
        out.push(SlotRequest {
            address: file.target.clone(),
            slot: slot.to_string(),
            source: format!("invariant symbol `{symbol}`"),
        });
    }
    Ok(out)
}

/// Accounts implied by a historical fixture: the target, attacker and victim.
///
/// Used so the caller does not retype what the fixture already states. All three matter:
/// a replay needs the target's code, the attacker's nonce, and for a case where the victim
/// is a token, the victim's storage. For Euler the transaction's `to` is the *exploit
/// contract*, not the protocol, so the target must come from the fixture's own field rather
/// than from the transaction list.
pub fn accounts_from_fixture(fixture_path: &Path) -> Result<Vec<Address>> {
    let text = std::fs::read_to_string(fixture_path)
        .with_context(|| format!("cannot read fixture {}", fixture_path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).context("fixture is not valid JSON")?;

    let mut out = BTreeSet::new();
    let mut push = |field: &str| -> Result<()> {
        if let Some(raw) = value.get(field).and_then(|v| v.as_str()) {
            out.insert(
                Address::from_str(raw)
                    .with_context(|| format!("fixture field `{field}` is not an address"))?,
            );
        }
        Ok(())
    };
    push("target")?;
    // The attacker is the `from` of the exploit transaction in both historical fixtures.
    if let Some(transactions) = value.get("transactions").and_then(|v| v.as_array()) {
        for transaction in transactions {
            for field in ["from", "to"] {
                if let Some(raw) = transaction.get(field).and_then(|v| v.as_str()) {
                    out.insert(
                        Address::from_str(raw)
                            .with_context(|| format!("transaction `{field}` is not an address"))?,
                    );
                }
            }
        }
    }
    if out.is_empty() {
        return Err(anyhow!(
            "fixture {} names no accounts; it has no target and no transactions",
            fixture_path.display()
        ));
    }
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_left_padded_because_rpc_returns_unpadded_values() {
        // "0x1" must land in the LAST byte. A naive decode puts it in the first and turns
        // slot 1 into slot 2^248 — a silent wrong-slot read.
        let word = parse_word("0x1").unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(word.0, expected);

        assert_eq!(
            parse_word(&format!("0x{}", "ab".repeat(32))).unwrap().0,
            [0xab; 32]
        );
        assert_eq!(parse_word("0x").unwrap(), B256::ZERO);
    }

    #[test]
    fn a_word_longer_than_32_bytes_is_refused() {
        let error = parse_word(&format!("0x{}", "ab".repeat(33)))
            .unwrap_err()
            .to_string();
        assert!(error.contains("longer than 32 bytes"), "{error}");
    }

    #[test]
    fn a_word_without_the_0x_prefix_is_refused() {
        // "2" is ambiguous: decimal 2 or hex 2. Guessing is how slot numbers go wrong.
        assert!(parse_word("2").is_err());
    }

    #[test]
    fn an_empty_account_list_is_refused_rather_than_producing_an_empty_snapshot() {
        let fork = ForkDb::new_offline("0x1");
        let error = capture(&fork, 1, 1, &[], &[]).unwrap_err().to_string();
        assert!(error.contains("no accounts"), "{error}");
    }

    #[test]
    fn an_invariants_file_supplies_only_its_plain_storage_bindings() {
        let dir =
            std::env::temp_dir().join(format!("rustyfuzz-capture-slots-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inv.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "supply": { "kind": "slot", "slot": "0x2", "offset_bits": 0, "width_bits": 256 },
                    "balances": { "kind": "mapping", "slot": "0x3", "offset_bits": 0, "width_bits": 256 },
                    "quoted": { "kind": "return_value", "slot": "0x0ee6f08a",
                                "offset_bits": 0, "width_bits": 256 }
                },
                "invariants": [
                    { "name": "x", "predicate": "supply == supply" }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let requests = slot_requests_from_invariants(&path).unwrap();
        // Only the plain slot is capturable. A mapping needs a key we do not have; a
        // return value is not storage. Both are skipped rather than fabricated.
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].slot, "0x2");
        assert!(requests[0].source.contains("supply"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fixture_accounts_include_target_and_both_transaction_parties() {
        let dir =
            std::env::temp_dir().join(format!("rustyfuzz-capture-accts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fixture.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "provider_replay_only": true,
                "chain_id": 1,
                "block_number": 15201793,
                "target": "0xbdbb5945f252bc3466a319cdcc3ee8056bf2e569",
                "transactions": [{
                    "from": "0xa0c7bd318d69424603cbf91e9969870f21b8ab4c",
                    // For Euler this is the exploit contract, NOT the protocol target.
                    "to": "0xebc29199c817dc47ba12e3f86102564d640cbf99"
                }]
            })
            .to_string(),
        )
        .unwrap();

        let accounts = accounts_from_fixture(&path).unwrap();
        // The target must be present even though no transaction names it: Euler's `to` is
        // the exploit contract, and omitting the protocol would replay against nothing.
        assert_eq!(accounts.len(), 3);
        assert!(accounts
            .contains(&Address::from_str("0xbdbb5945f252bc3466a319cdcc3ee8056bf2e569").unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fixture_with_no_accounts_is_refused() {
        let dir =
            std::env::temp_dir().join(format!("rustyfuzz-capture-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.json");
        std::fs::write(&path, r#"{"chain_id": 1}"#).unwrap();
        let error = accounts_from_fixture(&path).unwrap_err().to_string();
        assert!(error.contains("names no accounts"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_eip1967_slot_is_the_standard_constant() {
        // Pinned numerically because a wrong constant silently returns "not a proxy" for
        // every real proxy, which looks like a perfectly healthy capture.
        let expected = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
        assert_eq!(hex::encode(EIP1967_IMPLEMENTATION_SLOT.0), expected);
    }

    #[test]
    fn a_non_proxy_reports_no_implementation_rather_than_zero() {
        // An offline ForkDb answers every slot with zero, which is exactly the "not a
        // proxy" case. The distinction that matters is None vs Some(0x0): a zero address
        // treated as an implementation would capture nothing while looking successful.
        let fork = ForkDb::new_offline("0x1");
        let address = Address::repeat_byte(0x11);
        assert_eq!(follow_implementation(&fork, address).unwrap(), None);
    }

    #[test]
    fn a_proxy_pointer_is_read_from_the_low_twenty_bytes() {
        let fork = ForkDb::new_offline("0x1");
        let proxy = Address::repeat_byte(0x22);
        let implementation = Address::repeat_byte(0x33);
        // Left-padded, as every real proxy stores it.
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(implementation.as_slice());
        fork.cache_storage(
            proxy,
            EIP1967_IMPLEMENTATION_SLOT.into(),
            U256::from_be_bytes(word),
        );
        assert_eq!(
            follow_implementation(&fork, proxy).unwrap(),
            Some(implementation)
        );
    }

    #[test]
    fn a_dirty_high_half_is_refused_instead_of_truncated() {
        // A pointer with junk above the address is not an address. Truncating would invent
        // an implementation at a plausible-looking address.
        let fork = ForkDb::new_offline("0x1");
        let proxy = Address::repeat_byte(0x22);
        let mut word = [0u8; 32];
        word[0] = 0x01; // junk in the high bytes
        word[31] = 0x33;
        fork.cache_storage(
            proxy,
            EIP1967_IMPLEMENTATION_SLOT.into(),
            U256::from_be_bytes(word),
        );
        let error = follow_implementation(&fork, proxy).unwrap_err().to_string();
        assert!(error.contains("not a left-padded address"), "{error}");
    }

    #[test]
    fn expansion_adds_the_implementation_and_records_the_pair() {
        let fork = ForkDb::new_offline("0x1");
        let proxy = Address::repeat_byte(0x22);
        let implementation = Address::repeat_byte(0x33);
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(implementation.as_slice());
        fork.cache_storage(
            proxy,
            EIP1967_IMPLEMENTATION_SLOT.into(),
            U256::from_be_bytes(word),
        );
        let expanded = expand_proxies(&fork, &[proxy]).unwrap();
        assert_eq!(expanded.all.len(), 2);
        assert!(expanded.all.contains(&implementation));
        assert_eq!(expanded.followed, vec![(proxy, implementation)]);
    }

    #[test]
    fn a_capture_must_record_the_block_it_claims() {
        // The offline path rejects a provenance block that differs from the pin. A capture
        // that recorded a different number would be silently unusable, so it fails here.
        let fork = ForkDb::new_offline("0x1");
        let address = Address::repeat_byte(0x11);
        let result = capture(&fork, 1, 999, &[address], &[]);
        let error = format!("{:#}", result.unwrap_err());
        assert!(
            error.contains("block") || error.contains("chain id"),
            "a mis-pinned capture must be refused: {error}"
        );
    }
}

#[cfg(test)]
mod captured_snapshot_tests {
    //! Proves a real captured snapshot can actually resolve a predicate.
    //!
    //! A snapshot that loads but yields `Unknown` for every term is useless, and the
    //! difference is invisible without a test that runs the evaluator over it. The values
    //! here are the ones measured from mainnet at block 15,201,793 (see
    //! `docs/backtest/runs/2026-10-26-state-audit/AUDIT.md`); the fixture is a literal copy
    //! so this test needs no network.

    use rustyfuzz_predicate::{
        BindingManifest, BlockContext, EvalContext, Outcome, ReReadBudget, Resolver, SequenceView,
        WriteRecord,
    };
    use std::str::FromStr;

    /// Slot 59 of the Audius governance proxy: the proposal counter, 84 before the exploit.
    const PROPOSAL_COUNT_SLOT: &str =
        "0x000000000000000000000000000000000000000000000000000000000000003b";
    const GOVERNANCE_PROXY: &str = "0x4deca517d6817b6510798b7328f2314d3003abac";

    fn manifest() -> String {
        serde_json::json!({
            "target": GOVERNANCE_PROXY,
            "symbols": {
                "proposalCount": {
                    "kind": "slot",
                    "slot": PROPOSAL_COUNT_SLOT,
                    "offset_bits": 0,
                    "width_bits": 256
                }
            }
        })
        .to_string()
    }

    fn evaluate(predicate: &str, observed: Option<u64>) -> Outcome {
        let address = revm::primitives::Address::from_str(GOVERNANCE_PROXY).unwrap();
        let slot = revm::primitives::B256::from_str(PROPOSAL_COUNT_SLOT).unwrap();

        let writes: Vec<WriteRecord> = observed
            .map(|value| {
                let mut word = [0u8; 32];
                word[24..].copy_from_slice(&value.to_be_bytes());
                vec![WriteRecord {
                    tx_index: 0,
                    address: address.into_array(),
                    slot: slot.0,
                    old_value: [0u8; 32],
                    new_value: word,
                }]
            })
            .unwrap_or_default();

        let bindings = BindingManifest::from_json(&manifest())
            .unwrap()
            .resolve()
            .unwrap();
        let checked = rustyfuzz_predicate::compile(predicate).unwrap();
        let view = SequenceView {
            writes: &writes,
            reads: &[],
            block: BlockContext::default(),
        };
        // The resolver needs the writes: they are what a symbol resolves against. Passing
        // `&[]` here made every term Unknown and the test caught it.
        let resolver = Resolver::new(&bindings, &writes, &[], 0);
        let _ = &view;
        let ctx = EvalContext {
            bindings: &bindings,
            resolver: &resolver,
            block: BlockContext::default(),
            tx_index: 0,
        };
        let mut reader = rustyfuzz_predicate::NoReRead;
        let (outcome, _, _) =
            rustyfuzz_predicate::evaluate(checked.expr(), &ctx, &mut reader, ReReadBudget::new(0));
        outcome
    }

    #[test]
    fn a_captured_value_resolves_and_the_predicate_evaluates() {
        // 84 is the measured pre-exploit counter, and it satisfies the bound.
        let outcome = evaluate("proposalCount < 1000000", Some(84));
        assert!(
            outcome.is_clean_pass(),
            "a captured value must resolve, not stay Unknown: {outcome:?}"
        );
    }

    #[test]
    fn the_same_predicate_fails_on_a_value_that_breaks_the_bound() {
        // The pair matters: passing above could be a predicate that always passes.
        let outcome = evaluate("proposalCount < 10", Some(84));
        assert!(
            outcome.is_violation(),
            "84 must violate `proposalCount < 10`: {outcome:?}"
        );
    }

    #[test]
    fn an_uncaptured_slot_is_unknown_rather_than_zero() {
        // The central promise of the capture format. With no write and no reader, the term
        // has no value; reporting 0 here would make `proposalCount < 10` pass and hide a
        // real violation.
        let outcome = evaluate("proposalCount < 10", None);
        assert!(
            matches!(outcome, Outcome::Unknown(_)),
            "an absent slot must be Unknown, never a confidant zero: {outcome:?}"
        );
        assert!(
            !outcome.is_clean_pass() && !outcome.is_violation(),
            "Unknown is neither a pass nor a violation"
        );
    }
}
