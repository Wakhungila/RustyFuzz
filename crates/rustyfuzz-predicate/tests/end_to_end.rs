//! End-to-end acceptance test for the predicate layer (§8 item 9).
//!
//! This is the gate the whole phase exists to pass:
//!
//! * a **deliberately false** predicate produces exactly one replayable violation;
//! * a **true** predicate on the same data produces none;
//! * an **unevaluable** predicate produces neither, and is not a signal.
//!
//! The scenario mirrors the motivating bug from the design (§6): a protocol keeps a
//! global accumulator and per-user balances, and a repair path updates the accumulator
//! without updating the users. `sum(userBalances) == totalSupply` must catch it, and
//! must stay quiet on the healthy trace.

use rustyfuzz_predicate::{
    term_value, BlockContext, Evidence, InvariantOracle, InvariantRegistry, InvariantSpec, Outcome,
    PredicateOracle, ReReadBudget, ReadRecord, SequenceView, Signal, Verdict, WriteRecord,
};
use std::collections::BTreeMap;

/// Three actors, addressed by their last byte for readability.
const ALICE: u8 = 0xa1;
const BOB: u8 = 0xb0;
const CAROL: u8 = 0xc0;

fn address(last: u8) -> [u8; 20] {
    let mut bytes = [0u8; 20];
    bytes[19] = last;
    bytes
}

fn word(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// The target contract from the design's worked example.
fn target() -> [u8; 20] {
    address(0xaa)
}

/// Slot 3 holds `totalSupply`; slot 4 roots the `balances` mapping.
const TOTAL_SUPPLY_SLOT: u8 = 3;
const BALANCES_BASE_SLOT: u8 = 4;

fn manifest() -> String {
    format!(
        r#"{{
            "target": "0x00000000000000000000000000000000000000aa",
            "symbols": {{
                "totalSupply": {{ "kind": "slot", "slot": "0x{TOTAL_SUPPLY_SLOT:x}",
                                  "offset_bits": 0, "width_bits": 256 }},
                "userBalances": {{
                    "kind": "mapping",
                    "slot": "0x{BALANCES_BASE_SLOT:x}",
                    "key_type": "address",
                    "keys": [
                        "0x00000000000000000000000000000000000000a1",
                        "0x00000000000000000000000000000000000000b0",
                        "0x00000000000000000000000000000000000000c0"
                    ],
                    "offset_bits": 0, "width_bits": 256
                }}
            }}
        }}"#
    )
}

/// Derives a mapping slot the same way the binder does, so the fixture's writes land
/// where the oracle looks. Computed through the public helper rather than duplicated.
fn balance_slot(actor_last_byte: u8) -> [u8; 32] {
    // An address key is right-aligned in a 32-byte word, so its last byte lands at
    // index 31, not 19. Getting this wrong made every mapping term unobservable while
    // looking correct.
    let mut key = [0u8; 32];
    key[31] = actor_last_byte;
    let mut base = [0u8; 32];
    base[31] = BALANCES_BASE_SLOT;
    rustyfuzz_predicate::mapping_slot(&key, &base)
}

fn total_supply_slot() -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[31] = TOTAL_SUPPLY_SLOT;
    slot
}

fn write(tx_index: usize, slot: [u8; 32], old: u64, new: u64) -> WriteRecord {
    WriteRecord {
        tx_index,
        address: target(),
        slot,
        old_value: word(old),
        new_value: word(new),
    }
}

/// A fixed post-sequence state so re-reads resolve everything the trace did not.
struct FixedState(BTreeMap<([u8; 20], [u8; 32]), [u8; 32]>);

impl rustyfuzz_predicate::StateReader for FixedState {
    fn read_slot(&mut self, address: [u8; 20], slot: [u8; 32]) -> Option<[u8; 32]> {
        self.0.get(&(address, slot)).copied()
    }
}

fn state(entries: &[(u8, u64)]) -> FixedState {
    let mut map = BTreeMap::new();
    for (actor, value) in entries {
        map.insert((target(), balance_slot(*actor)), word(*value));
    }
    FixedState(map)
}

/// Builds a view where every balance is observed at `tx_index`, which is what a real
/// handler does when it checks the invariant.
fn observed_view(
    writes: Vec<WriteRecord>,
    reads: Vec<ReadRecord>,
) -> (Vec<WriteRecord>, Vec<ReadRecord>) {
    (writes, reads)
}

fn read(tx_index: usize, slot: [u8; 32], value: u64) -> ReadRecord {
    ReadRecord {
        tx_index,
        address: target(),
        slot,
        value: word(value),
    }
}

// ---------------------------------------------------------------------------
// The acceptance scenario
// ---------------------------------------------------------------------------

/// Healthy trace: a transfer moves value between two users and the accumulator is
/// unchanged, so the invariant holds.
fn healthy_trace() -> (Vec<WriteRecord>, Vec<ReadRecord>) {
    let writes = vec![
        write(0, balance_slot(ALICE), 100, 40),
        write(0, balance_slot(BOB), 0, 60),
    ];
    let reads = vec![
        read(0, balance_slot(ALICE), 40),
        read(0, balance_slot(BOB), 60),
        read(0, balance_slot(CAROL), 0),
        read(0, total_supply_slot(), 100),
    ];
    observed_view(writes, reads)
}

/// Broken trace: a repair path writes `totalSupply` down to 40 but leaves every user
/// balance untouched, so the books no longer balance.
fn broken_trace() -> (Vec<WriteRecord>, Vec<ReadRecord>) {
    let writes = vec![
        write(0, balance_slot(ALICE), 100, 40),
        write(0, balance_slot(BOB), 0, 60),
        write(1, total_supply_slot(), 100, 40),
    ];
    let reads = vec![
        read(0, balance_slot(ALICE), 40),
        read(0, balance_slot(BOB), 60),
        read(0, balance_slot(CAROL), 0),
        read(1, balance_slot(ALICE), 40),
        read(1, balance_slot(BOB), 60),
        read(1, balance_slot(CAROL), 0),
        read(1, total_supply_slot(), 40),
    ];
    observed_view(writes, reads)
}

fn oracle_for(predicate: &str) -> PredicateOracle {
    PredicateOracle::new(
        InvariantSpec {
            name: "accounting".to_string(),
            predicate: predicate.to_string(),
        },
        &manifest(),
    )
    .expect("oracle must build from the fixture manifest")
}

/// Runs one oracle against a trace at `tx_index` with no re-read available.
fn check(
    oracle: &PredicateOracle,
    writes: &[WriteRecord],
    reads: &[ReadRecord],
    reads_len: usize,
    tx_index: usize,
) -> (Outcome, Evidence) {
    let view = SequenceView {
        writes,
        reads: &reads[..reads_len],
        block: BlockContext::default(),
    };
    let mut reader = rustyfuzz_predicate::NoReRead;
    oracle.check(&view, tx_index, &mut reader, ReReadBudget::new(16))
}

#[test]
fn a_false_predicate_fires_exactly_once_on_the_broken_trace() {
    let oracle = oracle_for("sum(userBalances) == totalSupply");
    let (writes, reads) = broken_trace();

    let (outcome, evidence) = check(&oracle, &writes, &reads, reads.len(), 1);

    assert!(
        outcome.is_violation(),
        "the accounting invariant must be violated, got {outcome:?}"
    );
    assert_eq!(evidence.verdict, Verdict::Violated);
    assert_eq!(Signal::from_outcome(&outcome), Signal::Finding);

    // §6.6: the evidence must be re-derivable by hand. 40 + 60 + 0 = 100, but the
    // accumulator says 40.
    let sum_term = evidence
        .terms
        .iter()
        .find(|term| term.symbol == "userBalances")
        .expect("the sum term must be present");
    assert_eq!(
        term_value(sum_term),
        Some(rustyfuzz_predicate::Int256::from_u64(100)),
        "per-user balances total 100"
    );
    let supply_term = evidence
        .terms
        .iter()
        .find(|term| term.symbol == "totalSupply")
        .expect("the supply term must be present");
    assert_eq!(
        term_value(supply_term),
        Some(rustyfuzz_predicate::Int256::from_u64(40)),
        "the accumulator was written down to 40"
    );
    // No arithmetic degeneracy: neither div0 nor overflow checks were involved. The
    // key-coverage counters are expected to be populated, so this asserts the two
    // arithmetic counters specifically rather than the whole struct.
    assert_eq!(evidence.counters.division_by_zero_observed, 0);
    assert_eq!(evidence.counters.overflow_checked_sites, 0);
    assert_eq!(evidence.counters.overflow_violations, 0);
    assert_eq!(evidence.counters.observed_keys, 3);
}

#[test]
fn the_same_predicate_is_silent_on_the_healthy_trace() {
    let oracle = oracle_for("sum(userBalances) == totalSupply");
    let (writes, reads) = healthy_trace();

    let (outcome, evidence) = check(&oracle, &writes, &reads, reads.len(), 0);

    assert!(
        outcome.is_clean_pass(),
        "a balanced trace must not be reported, got {outcome:?}"
    );
    assert_eq!(evidence.verdict, Verdict::Held);
    assert_ne!(Signal::from_outcome(&outcome), Signal::Finding);
}

#[test]
fn an_unevaluable_predicate_is_no_signal_on_either_trace() {
    // No reads at all and no reader: nothing resolves, so the answer is Unknown --
    // never a finding and never a pass.
    let oracle = oracle_for("sum(userBalances) == totalSupply");
    let (writes, _reads) = broken_trace();

    let view = SequenceView {
        writes: &writes,
        reads: &[],
        block: BlockContext::default(),
    };
    let mut reader = rustyfuzz_predicate::NoReRead;
    let (outcome, evidence) = oracle.check(&view, 1, &mut reader, ReReadBudget::new(4));

    assert!(matches!(outcome, Outcome::Unknown(_)), "got {outcome:?}");
    assert!(
        !outcome.is_violation(),
        "Unknown must never become a finding"
    );
    assert!(!outcome.is_clean_pass(), "Unknown must never become a pass");
    assert_eq!(Signal::from_outcome(&outcome), Signal::NoSignal);
    assert_eq!(evidence.verdict, Verdict::Unknown);
    assert!(evidence.unknown_reason.is_some());
}

#[test]
fn a_re_read_recovers_a_case_the_trace_alone_cannot_decide() {
    // The broken trace, but without the per-user reads at tx 1. The trace alone leaves
    // one term unobserved, yet a re-read over post-sequence state decides it.
    let oracle = oracle_for("sum(userBalances) == totalSupply");
    let (writes, reads) = broken_trace();
    // Only tx-0 reads are retained, so nothing about tx 1 is observed from the
    // trace: the accumulator write is known, but the balances are not. The first six
    // entries are the tx-1 reads, so take the first three instead.
    let partial = &reads[..3];
    let view = SequenceView {
        writes: &writes,
        reads: partial,
        block: BlockContext::default(),
    };
    // Post-sequence state still holds 40 / 60 / 0 and the accumulator was written to 40.
    let mut reader = state(&[(ALICE, 40), (BOB, 60), (CAROL, 0)]);
    let (outcome, evidence) = oracle.check(&view, 1, &mut reader, ReReadBudget::new(8));

    assert!(
        outcome.is_violation(),
        "the re-read must make the case decidable, got {outcome:?}"
    );
    // At least one term must record that it came from a re-read, not the trace.
    assert!(
        evidence
            .terms
            .iter()
            .any(|term| term.provenance == rustyfuzz_predicate::ProvenanceLabel::ReRead),
        "evidence must distinguish re-read provenance: {:?}",
        evidence.terms
    );
}

#[test]
fn a_true_predicate_over_an_unrelated_quantity_stays_quiet() {
    // A trivially true property must never fire, even on the broken trace: an oracle
    // that reports everything is worse than no oracle.
    let oracle = oracle_for("totalSupply >= 0");
    let (writes, reads) = broken_trace();
    let (outcome, _) = check(&oracle, &writes, &reads, reads.len(), 1);
    assert!(outcome.is_clean_pass(), "got {outcome:?}");
}

#[test]
fn a_requires_no_overflow_fixture_fires_only_when_the_sum_wraps() {
    let config = r#"{
            "target": "0x00000000000000000000000000000000000000aa",
            "symbols": {
                "supply": { "kind": "slot", "slot": "0x1",
                             "offset_bits": 0, "width_bits": 256 },
                "amount": { "kind": "slot", "slot": "0x2",
                             "offset_bits": 0, "width_bits": 256 }
            }
        }"#;
    let oracle = PredicateOracle::new(
        InvariantSpec {
            name: "no-overflow".to_string(),
            predicate: "requires_no_overflow(supply + amount)".to_string(),
        },
        config,
    )
    .expect("builds");

    let mut slot1 = [0u8; 32];
    slot1[31] = 1;
    let mut slot2 = [0u8; 32];
    slot2[31] = 2;

    // Fits.
    let safe = vec![
        WriteRecord {
            tx_index: 0,
            address: target(),
            slot: slot1,
            old_value: word(0),
            new_value: word(10),
        },
        WriteRecord {
            tx_index: 0,
            address: target(),
            slot: slot2,
            old_value: word(0),
            new_value: word(20),
        },
    ];
    let view = SequenceView {
        writes: &safe,
        reads: &[],
        block: BlockContext::default(),
    };
    let mut reader = rustyfuzz_predicate::NoReRead;
    let (outcome, _) = oracle.check(&view, 1, &mut reader, ReReadBudget::new(8));
    assert!(
        outcome.is_clean_pass(),
        "10 + 20 must not wrap, got {outcome:?}"
    );

    // Wraps: both operands are max.
    let max = [0xffu8; 32];
    let overflowing = vec![
        WriteRecord {
            tx_index: 0,
            address: target(),
            slot: slot1,
            old_value: word(0),
            new_value: max,
        },
        WriteRecord {
            tx_index: 0,
            address: target(),
            slot: slot2,
            old_value: word(0),
            new_value: max,
        },
    ];
    let view = SequenceView {
        writes: &overflowing,
        reads: &[],
        block: BlockContext::default(),
    };
    let mut reader = rustyfuzz_predicate::NoReRead;
    let (outcome, evidence) = oracle.check(&view, 1, &mut reader, ReReadBudget::new(8));
    assert!(outcome.is_violation(), "max + max wraps, got {outcome:?}");
    assert_eq!(evidence.counters.overflow_violations, 1);
    assert!(
        evidence.verdict_text.contains("requires_no_overflow"),
        "the verdict must name the failed assertion: {}",
        evidence.verdict_text
    );
}

#[test]
fn a_div0_degraded_pass_is_never_reported_as_satisfied() {
    let config = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "a": { "kind": "slot", "slot": "0x1", "offset_bits": 0, "width_bits": 256 },
            "b": { "kind": "slot", "slot": "0x2", "offset_bits": 0, "width_bits": 256 }
        }
    }"#;
    let oracle = PredicateOracle::new(
        InvariantSpec {
            name: "ratio".to_string(),
            predicate: "a / b <= 10".to_string(),
        },
        config,
    )
    .expect("builds");

    let mut slot1 = [0u8; 32];
    slot1[31] = 1;
    let mut slot2 = [0u8; 32];
    slot2[31] = 2;
    let writes = vec![
        WriteRecord {
            tx_index: 0,
            address: target(),
            slot: slot1,
            old_value: word(0),
            new_value: word(100),
        },
        WriteRecord {
            tx_index: 0,
            address: target(),
            slot: slot2,
            old_value: word(0),
            new_value: word(0),
        },
    ];
    let view = SequenceView {
        writes: &writes,
        reads: &[],
        block: BlockContext::default(),
    };
    let mut reader = rustyfuzz_predicate::NoReRead;
    let (outcome, evidence) = oracle.check(&view, 1, &mut reader, ReReadBudget::new(8));

    assert_eq!(evidence.verdict, Verdict::HeldButDiv0);
    assert!(!outcome.is_clean_pass(), "div0 must never be a clean pass");
    assert_eq!(Signal::from_outcome(&outcome), Signal::NoSignal);
    assert_eq!(evidence.counters.division_by_zero_observed, 1);
    assert!(evidence.verdict_text.contains("div0"));
}

#[test]
fn the_registry_reports_one_finding_among_several_invariants() {
    let mut registry = InvariantRegistry::new();
    registry.register(Box::new(oracle_for("sum(userBalances) == totalSupply")));
    registry.register(Box::new(oracle_for("totalSupply >= 0")));
    registry.register(Box::new(oracle_for("totalSupply == totalSupply")));

    let (writes, reads) = broken_trace();
    let view = SequenceView {
        writes: &writes,
        reads: &reads,
        block: BlockContext::default(),
    };
    let mut reader = rustyfuzz_predicate::NoReRead;
    let results = registry.check_all(&view, 1, &mut reader, ReReadBudget::new(16));

    assert_eq!(results.len(), 3);
    let findings: Vec<&Evidence> = results
        .iter()
        .filter(|(outcome, _)| outcome.is_violation())
        .map(|(_, evidence)| evidence)
        .collect();
    assert_eq!(findings.len(), 1, "exactly one invariant is violated");
    assert!(findings[0].predicate.contains("userBalances"));
}

#[test]
fn every_finding_round_trips_through_json_for_replay() {
    // The replay path consumes evidence as JSON, so a finding that cannot round-trip
    // is not replayable evidence.
    let oracle = oracle_for("sum(userBalances) == totalSupply");
    let (writes, reads) = broken_trace();
    let (_, evidence) = check(&oracle, &writes, &reads, reads.len(), 1);

    let json = serde_json::to_string_pretty(&evidence).expect("serialises");
    let back: Evidence = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, evidence);
    assert!(json.contains("\"verdict\": \"violated\""));
}
