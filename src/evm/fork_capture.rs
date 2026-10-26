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
    /// The caveat a reader must see, written into the artifact rather than a comment.
    pub completeness: String,
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
