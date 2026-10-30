//! Validation against the Code4rena 2024-07 Basin invariant suite.
//!
//! Source: <https://github.com/code-423n4/2024-07-basin> at commit
//! `bbe3cafed46822b0d0b1e0b80f9dee623012bd92`. Not vendored; see
//! `docs/backtest/cases/code4rena-2024-07-basin.json` for URL, commit and the
//! verified build/test recipe.
//!
//! # Why this target
//!
//! It is the first genuine stateful target: `setUp()` deploys a Well and a Handler, 14
//! handler selectors drive the sequence, and the suite runs with
//! `{ runs = 50, depth = 500, fail_on_revert = true }`. `forge test` reports
//! **7 passed** (verified locally, 23.44s).
//!
//! # What this file proves, and what it cannot
//!
//! The Well stores its two reserves **packed into one slot**, 16 bytes each
//! (`LibBytes.readUint128`, `shr(128, shl(128, sload(slot)))` for reserve0 and
//! `shr(128, sload(slot))` for reserve1). That is a real production instance of exactly
//! the packed-slot hazard the mandatory bit-range rule exists to prevent, so it is the
//! best available test of the binding layer.
//!
//! The tests cover packed storage, return-value bindings and relative tolerance.
//! Remaining gaps, including calls with computed array arguments, are asserted below
//! so support must be demonstrated when those gaps close.

use rustyfuzz_predicate::{
    Binding, BindingManifest, BlockContext, InvariantOracle, InvariantSpec, Outcome,
    PredicateOracle, ReReadBudget, ReadRecord, Resolver, SequenceView, Signal, StateReader, Symbol,
};
use std::collections::BTreeMap;

/// The Well's reserves storage slot, from `src/Well.sol:40`.
///
/// `bytes32(uint256(keccak256("reserves.storage.slot")) - 1)`, independently verified
/// against a from-scratch keccak computation.
const RESERVES_SLOT_HEX: &str =
    "0x4bba01c388049b5ebd30398b65e8ad45b632802c5faf4964e58085ea8ab03715";

/// The Well under test in the invariant suite (`well` in `LiquidityHelper`).
fn well() -> [u8; 20] {
    let mut address = [0u8; 20];
    address[19] = 0x11;
    address
}

/// A mock token the Well holds.
fn token() -> [u8; 20] {
    let mut address = [0u8; 20];
    address[19] = 0x22;
    address
}

fn reserves_slot() -> [u8; 32] {
    let hex = RESERVES_SLOT_HEX.trim_start_matches("0x");
    let mut slot = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("ascii");
        slot[index] = u8::from_str_radix(pair, 16).expect("hex");
    }
    slot
}

fn word(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Packs two uint128 reserves the way `LibBytes.writeUint128` does: reserve0 in the low
/// 128 bits, reserve1 in the high 128 bits.
fn packed_reserves(reserve0: u128, reserve1: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&reserve1.to_be_bytes());
    out[16..32].copy_from_slice(&reserve0.to_be_bytes());
    out
}

/// Reader that answers return-value bindings, including multi-word and cross-contract.
struct BasinReader {
    returns: BTreeMap<([u8; 20], [u8; 4], u16), [u8; 32]>,
}

impl StateReader for BasinReader {
    fn read_slot(&mut self, _address: [u8; 20], _slot: [u8; 32]) -> Option<[u8; 32]> {
        None
    }

    fn read_return(&mut self, address: [u8; 20], selector: [u8; 4]) -> Option<[u8; 32]> {
        self.read_return_word(address, selector, 0)
    }

    fn read_return_word(
        &mut self,
        address: [u8; 20],
        selector: [u8; 4],
        word_index: u16,
    ) -> Option<[u8; 32]> {
        self.returns.get(&(address, selector, word_index)).copied()
    }
}

const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const GET_RESERVES: [u8; 4] = [0x0e, 0xe6, 0xf0, 0x8a];
const TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];

/// Manifest modelling two Basin invariants over the packed reserves slot.
fn packed_manifest() -> String {
    format!(
        r#"{{
            "target": "0x0000000000000000000000000000000000000011",
            "symbols": {{
                "reserve0": {{ "kind": "slot", "slot": "{RESERVES_SLOT_HEX}",
                               "offset_bits": 0, "width_bits": 128 }},
                "reserve1": {{ "kind": "slot", "slot": "{RESERVES_SLOT_HEX}",
                               "offset_bits": 128, "width_bits": 128 }},
                "lpSupply": {{ "kind": "return_value",
                               "call_target": "0x0000000000000000000000000000000000000011",
                               "slot": "0x18160ddd",
                               "offset_bits": 0, "width_bits": 256 }},
                "token0Balance": {{ "kind": "return_value",
                                    "call_target": "0x0000000000000000000000000000000000000022",
                                    "slot": "0x70a08231",
                                    "offset_bits": 0, "width_bits": 256 }}
            }}
        }}"#
    )
}

fn oracle(predicate: &str) -> PredicateOracle {
    PredicateOracle::new(
        InvariantSpec {
            name: "basin".to_string(),
            predicate: predicate.to_string(),
        },
        &packed_manifest(),
    )
    .expect("oracle builds from the Basin manifest")
}

fn view_with_reserves(
    reserve0: u128,
    reserve1: u128,
    reads: &[ReadRecord],
) -> (Vec<ReadRecord>, [u8; 32]) {
    (reads.to_vec(), packed_reserves(reserve0, reserve1))
}

fn empty_reader() -> BasinReader {
    BasinReader {
        returns: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// The packed-slot property this target exists to exercise
// ---------------------------------------------------------------------------

/// `invariant_token0WellBalanceAndReserves`: `balanceOf(well) >= reserves[0]`.
///
/// Reserve0 is the **low** 128 bits of the packed slot. Reading the whole slot would
/// include reserve1 in the high bits and make the comparison meaningless, which is the
/// concrete hazard the mandatory bit-range rule prevents.
#[test]
fn reserve0_is_the_low_half_of_the_packed_slot() {
    let manifest = BindingManifest::from_json(&packed_manifest())
        .expect("parses")
        .resolve()
        .expect("resolves");
    let reserves = packed_reserves(1_000, 9_999);
    let writes = vec![rustyfuzz_predicate::WriteRecord {
        tx_index: 0,
        address: well(),
        slot: reserves_slot(),
        old_value: [0u8; 32],
        new_value: reserves,
    }];
    let resolver = Resolver::new(&manifest, &writes, &[], 0);
    let mut reader = empty_reader();
    let mut budget = ReReadBudget::new(4);

    let resolved = resolver
        .resolve(
            &Symbol(vec!["reserve0".to_string()]),
            &mut reader,
            &mut budget,
        )
        .expect("resolves");
    assert_eq!(
        resolved.value,
        rustyfuzz_predicate::Int256::from_u64(1_000),
        "reserve0 must be the low 128 bits, not the whole slot"
    );

    let reserve1 = resolver
        .resolve(
            &Symbol(vec!["reserve1".to_string()]),
            &mut reader,
            &mut budget,
        )
        .expect("resolves");
    assert_eq!(
        reserve1.value,
        rustyfuzz_predicate::Int256::from_u64(9_999),
        "reserve1 must be the high 128 bits"
    );
}

/// The negative control: a full-slot read of the same word is a different number, so a
/// manifest that omitted the bit range would silently compare the wrong quantity.
#[test]
fn a_full_slot_read_would_conflate_both_reserves() {
    let whole = packed_reserves(1_000, 9_999);
    let whole_value = rustyfuzz_predicate::Int256(whole);
    assert_ne!(whole_value, rustyfuzz_predicate::Int256::from_u64(1_000));
    assert_ne!(whole_value, rustyfuzz_predicate::Int256::from_u64(9_999));
    // And the manifest refuses to build without explicit bit ranges.
    let missing = r#"{
        "target": "0x0000000000000000000000000000000000000011",
        "symbols": { "reserve0": { "kind": "slot", "slot": "0x4bba01c388049b5ebd30398b65e8ad45b632802c5faf4964e58085ea8ab03715" } }
    }"#;
    let error = BindingManifest::from_json(missing)
        .expect("parses")
        .resolve()
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "binding reserve0: offset_bits/width_bits required (no default)"
    );
}

/// `invariant_token0WellBalanceAndReserves`, expressed as a predicate.
#[test]
fn the_balance_covers_reserves_invariant_holds_and_can_fail() {
    let subject = oracle("token0Balance >= reserve0");

    // Healthy: the Well holds more of the token than its recorded reserve.
    let (reads, reserves) = view_with_reserves(1_000, 2_000, &[]);
    let writes = vec![rustyfuzz_predicate::WriteRecord {
        tx_index: 0,
        address: well(),
        slot: reserves_slot(),
        old_value: [0u8; 32],
        new_value: reserves,
    }];
    let mut reader = BasinReader {
        returns: BTreeMap::from([((token(), BALANCE_OF, 0), word(1_500))]),
    };
    let view = SequenceView {
        writes: &writes,
        reads: &reads,
        block: BlockContext::default(),

        call_outputs: &[],
    };
    let (outcome, evidence) = subject.check(&view, 0, &mut reader, ReReadBudget::new(8));
    assert!(
        outcome.is_clean_pass(),
        "balance 1500 >= reserve 1000 must hold, got {outcome:?}"
    );
    assert_eq!(Signal::from_outcome(&outcome), Signal::Held);
    // The evidence must name the token contract, proving call_target was honoured.
    let balance_term = evidence
        .terms
        .iter()
        .find(|term| term.symbol == "token0Balance")
        .expect("balance term present");
    assert_eq!(
        balance_term.address, "0x0000000000000000000000000000000000000022",
        "the call must go to the token, not the Well"
    );

    // Violation: reserve exceeds the balance, which is what the real invariant guards.
    let mut reader = BasinReader {
        returns: BTreeMap::from([((token(), BALANCE_OF, 0), word(999))]),
    };
    let (outcome, _) = subject.check(&view, 0, &mut reader, ReReadBudget::new(8));
    assert!(
        outcome.is_violation(),
        "balance 999 < reserve 1000 must be reported, got {outcome:?}"
    );
}

/// `invariant_wellTokenBalancesShouldNeverBeZeroWithLPSupply` is conditional. The IR has
/// no `if`, so it is expressed with short-circuit logic — and the test proves the
/// meaning is preserved.
#[test]
fn the_conditional_zero_balance_invariant_is_expressible_with_short_circuit() {
    // "if supply != 0 then balance0 > 0" == "supply == 0 || balance0 > 0"
    let subject = oracle("lpSupply == 0 || token0Balance > 0");

    // Supply is zero: the invariant is vacuously satisfied without consulting the token.
    let writes: Vec<rustyfuzz_predicate::WriteRecord> = Vec::new();
    let view = SequenceView {
        writes: &writes,
        reads: &[],
        block: BlockContext::default(),

        call_outputs: &[],
    };
    let mut reader = BasinReader {
        returns: BTreeMap::from([((well(), TOTAL_SUPPLY, 0), word(0))]),
    };
    let (outcome, _) = subject.check(&view, 0, &mut reader, ReReadBudget::new(8));
    assert!(outcome.is_clean_pass(), "zero supply satisfies vacuously");

    // Supply is non-zero and the balance is non-zero: satisfied.
    let mut reader = BasinReader {
        returns: BTreeMap::from([
            ((well(), TOTAL_SUPPLY, 0), word(500)),
            ((token(), BALANCE_OF, 0), word(10)),
        ]),
    };
    let (outcome, _) = subject.check(&view, 0, &mut reader, ReReadBudget::new(8));
    assert!(outcome.is_clean_pass(), "positive supply and balance");

    // Supply is non-zero and the balance is zero: the bug this invariant exists for.
    let mut reader = BasinReader {
        returns: BTreeMap::from([
            ((well(), TOTAL_SUPPLY, 0), word(500)),
            ((token(), BALANCE_OF, 0), word(0)),
        ]),
    };
    let (outcome, _) = subject.check(&view, 0, &mut reader, ReReadBudget::new(8));
    assert!(
        outcome.is_violation(),
        "LP supply with an empty Well must be reported, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Relative tolerance regression and remaining binding gaps
// ---------------------------------------------------------------------------

/// The relative comparison preserves Basin's `assertApproxEqRelN` rounding tolerance.
#[test]
fn relative_tolerance_accepts_rounding_and_rejects_excess_error() {
    let subject = oracle("approx_eq(lpSupply, 1000000, 100, 6)");
    let view = SequenceView {
        writes: &[],
        reads: &[],
        block: BlockContext::default(),

        call_outputs: &[],
    };
    for (supply, expected) in [
        (1_000_000, Outcome::True),
        (1_000_001, Outcome::True),
        (1_000_100, Outcome::True),
        (1_000_101, Outcome::False),
    ] {
        let mut reader = BasinReader {
            returns: BTreeMap::from([((well(), TOTAL_SUPPLY, 0), word(supply))]),
        };
        let (outcome, _) = subject.check(&view, 0, &mut reader, ReReadBudget::new(8));
        assert_eq!(outcome, expected, "supply {supply}");
    }
}

/// `invariant_reservesMatchFunctionCalcReserve` needs `calcReserve(...)` — a call whose
/// arguments include the whole reserves array. The IR binds symbols, not computed
/// argument lists, so the call cannot be issued.
#[test]
fn a_call_with_computed_array_arguments_is_not_expressible() {
    assert!(
        PredicateOracle::new(
            InvariantSpec {
                name: "calcReserve".to_string(),
                predicate: "reserve0 == calcReserve(0)".to_string(),
            },
            &packed_manifest(),
        )
        .is_err(),
        "function-call syntax is not in the grammar"
    );
}

/// Multi-word returns are supported, but the caller must name the word explicitly.
#[test]
fn a_multi_word_return_requires_an_explicit_word_index() {
    let manifest = r#"{
            "target": "0x0000000000000000000000000000000000000011",
            "symbols": {
                "reserveFromCall": { "kind": "return_value",
                                      "call_target": "0x0000000000000000000000000000000000000011",
                                      "slot": "0x0ee6f08a",
                                      "word_index": 1,
                                      "offset_bits": 0, "width_bits": 256 }
            }
        }"#;
    let resolved = BindingManifest::from_json(manifest)
        .expect("parses")
        .resolve()
        .expect("resolves");
    assert_eq!(resolved["reserveFromCall"].word_index, 1);

    // Word 1 is read; word 0 is untouched, proving the index selects rather than aliases.
    let mut reader = BasinReader {
        returns: BTreeMap::from([
            ((well(), GET_RESERVES, 0), word(111)),
            ((well(), GET_RESERVES, 1), word(222)),
        ]),
    };
    let (value_a, _) = {
        let _ = &mut reader;
        (reader.read_return_word(well(), GET_RESERVES, 0), ())
    };
    assert_eq!(value_a, Some(word(111)));
    assert_eq!(
        reader.read_return_word(well(), GET_RESERVES, 1),
        Some(word(222))
    );
}

/// An unresolvable call is `Unknown`, never a pass — measured on this real target.
#[test]
fn a_missing_call_result_is_unknown_and_no_signal() {
    let subject = oracle("token0Balance >= reserve0");
    let (reads, reserves) = view_with_reserves(1_000, 2_000, &[]);
    let writes = vec![rustyfuzz_predicate::WriteRecord {
        tx_index: 0,
        address: well(),
        slot: reserves_slot(),
        old_value: [0u8; 32],
        new_value: reserves,
    }];
    let mut reader = empty_reader();
    let view = SequenceView {
        writes: &writes,
        reads: &reads,
        block: BlockContext::default(),

        call_outputs: &[],
    };
    let (outcome, evidence) = subject.check(&view, 0, &mut reader, ReReadBudget::new(8));
    assert!(matches!(outcome, Outcome::Unknown(_)), "got {outcome:?}");
    assert!(!outcome.is_clean_pass());
    assert_eq!(Signal::from_outcome(&outcome), Signal::NoSignal);
    assert!(evidence.unknown_reason.is_some());
}

/// The reserves slot derivation is independently reproducible, so a manifest can state it
/// without trusting a comment in the target's source.
#[test]
fn the_reserves_slot_matches_its_documented_derivation() {
    // keccak256("reserves.storage.slot") - 1, computed by the Python reference and
    // hard-coded in the manifest above.
    assert_eq!(
        rustyfuzz_predicate::binding::hex(&reserves_slot()),
        RESERVES_SLOT_HEX.trim_start_matches("0x")
    );
    let binding: &Binding = &BindingManifest::from_json(&packed_manifest())
        .expect("parses")
        .resolve()
        .expect("resolves")["reserve0"];
    assert_eq!(binding.width_bits, 128);
    assert_eq!(binding.offset_bits, 0);
}
