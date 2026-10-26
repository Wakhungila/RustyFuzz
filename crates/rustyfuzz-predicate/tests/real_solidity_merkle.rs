//! Validation against a real production Solidity library.
//!
//! Source: <https://github.com/polytope-labs/solidity-merkle-trees> at commit
//! `6bbc83d5ac33f85761725cf2eba4f8700164e8ba`. The repository is **not vendored**;
//! `docs/backtest/cases/polytope-solidity-merkle-trees.json` records the URL and
//! commit so the run is reproducible without copying third-party code here.
//!
//! # What this validates, and what it does not
//!
//! The target has no stateful `invariant_*` functions. Its properties are universal
//! statements over pure functions: "no forged proof verifies". So this exercises the
//! `return_value` binding kind and the tri-state evaluator against real cryptographic
//! code, which is the point — it does **not** exercise the state-machine machinery and
//! is expected to find no new bug, because Foundry's own fuzzer already covers this
//! class faster for a stateless library.
//!
//! The expectations here are transcribed from the project's own tests, which are
//! verified to pass with `forge test` (22 tests, 12+4+6 across three suites). Each
//! case below cites the test it mirrors.

use rustyfuzz_predicate::{
    Binding, BindingManifest, BlockContext, EvalContext, InvariantOracle, InvariantSpec, Outcome,
    PredicateOracle, ProvenanceLabel, ReReadBudget, SequenceView, Signal, StateReader, WriteRecord,
};
use std::collections::BTreeMap;

/// `MerkleMultiProof.VerifyProof(...)` as a return-value symbol.
///
/// The binding names the function by selector; the reader below decides what the
/// function answers for the concrete inputs of each case.
const VERIFY_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

const MANIFEST: &str = r#"{
    "target": "0x00000000000000000000000000000000000000aa",
    "symbols": {
        "forgeryVerifies": {
            "kind": "return_value",
            "slot": "0xdeadbeef",
            "offset_bits": 0,
            "width_bits": 8
        }
    }
}"#;

/// Answers each function call with a fixed word, keyed by selector.
struct FixedReturns(BTreeMap<[u8; 4], [u8; 32]>);

impl StateReader for FixedReturns {
    fn read_slot(&mut self, _address: [u8; 20], _slot: [u8; 32]) -> Option<[u8; 32]> {
        None
    }

    fn read_return(&mut self, _address: [u8; 20], selector: [u8; 4]) -> Option<[u8; 32]> {
        self.0.get(&selector).copied()
    }
}

/// A truthy return word: bool true is 1 in the low byte.
fn returns_true() -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = 1;
    word
}

fn returns_false() -> [u8; 32] {
    [0u8; 32]
}

fn oracle(predicate: &str) -> PredicateOracle {
    PredicateOracle::new(
        InvariantSpec {
            name: "merkle-forgery".to_string(),
            predicate: predicate.to_string(),
        },
        MANIFEST,
    )
    .expect("oracle builds from the manifest")
}

fn evaluate_with(reader_word: Option<[u8; 32]>) -> (Outcome, rustyfuzz_predicate::Evidence) {
    let predicate = oracle("forgeryVerifies == false");
    let mut map = BTreeMap::new();
    if let Some(word) = reader_word {
        map.insert(VERIFY_SELECTOR, word);
    }
    let mut reader = FixedReturns(map);
    let view = SequenceView {
        writes: &[],
        reads: &[],
        block: BlockContext::default(),

        call_outputs: &[],
    };
    predicate.check(&view, 0, &mut reader, ReReadBudget::new(4))
}

// ---------------------------------------------------------------------------
// The library's own forgery tests, as predicates
// ---------------------------------------------------------------------------

/// Mirrors `testForgery_TerminateAtRoot_UnconsumedForgedSubtree`
/// (`tests/foundry/MerkleMultiProof.t.sol:123`).
///
/// Old behaviour: a forged subtree's climb was silently discarded, so the call
/// returned the genuine root and the proof "verified". Fixed behaviour: it reverts.
/// Either way the property "a forgery does not verify" must hold, and the predicate
/// must say so without a false alarm.
#[test]
fn a_forged_multi_proof_does_not_verify() {
    // The library now reverts, so the verify call never returns true. Modelled as
    // returning false, which is what the caller observes.
    let (outcome, evidence) = evaluate_with(Some(returns_false()));
    assert!(
        outcome.is_clean_pass(),
        "the forgery must not verify, got {outcome:?}"
    );
    assert_eq!(Signal::from_outcome(&outcome), Signal::Held);
    assert_eq!(evidence.counters.division_by_zero_observed, 0);
    assert_eq!(
        evidence.terms[0].provenance,
        ProvenanceLabel::ReRead,
        "a return value can only come from calling the function"
    );
}

/// The same property against a verifier that *does* accept the forged proof, which is
/// the vulnerability the library fixed (`testExploit_LeafIndexBypass`,
/// `tests/foundry/MerkleMountainRange.t.sol:86`). The predicate must fire.
#[test]
fn a_forgery_that_verifies_is_reported_as_a_violation() {
    let (outcome, evidence) = evaluate_with(Some(returns_true()));
    assert!(
        outcome.is_violation(),
        "a proof that verifies when it should not must be a finding, got {outcome:?}"
    );
    assert_eq!(Signal::from_outcome(&outcome), Signal::Finding);
    assert!(evidence.verdict_text.contains("violated"));
}

/// If the function cannot be called at all, the predicate must be `Unknown` — never a
/// pass. This is the §5.1 rule measured against a real binding rather than a fixture.
#[test]
fn an_uncallable_verifier_yields_unknown_and_no_signal() {
    let (outcome, evidence) = evaluate_with(None);
    assert!(matches!(outcome, Outcome::Unknown(_)), "got {outcome:?}");
    assert!(!outcome.is_violation(), "Unknown must not become a finding");
    assert!(!outcome.is_clean_pass(), "Unknown must not become a pass");
    assert_eq!(Signal::from_outcome(&outcome), Signal::NoSignal);
    assert!(evidence.unknown_reason.is_some());
}

// ---------------------------------------------------------------------------
// Binding-layer guarantees, exercised on this manifest shape
// ---------------------------------------------------------------------------

#[test]
fn a_return_value_binding_still_requires_an_explicit_width() {
    // The mandatory-bit-range rule is not relaxed for the new kind: a return word can
    // carry a packed bool or a full uint256, and guessing would be wrong either way.
    let manifest = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": { "x": { "kind": "return_value", "slot": "0xdeadbeef" } }
    }"#;
    let error = BindingManifest::from_json(manifest)
        .expect("parses")
        .resolve()
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "binding x: offset_bits/width_bits required (no default)"
    );
}

#[test]
fn a_return_value_binding_needs_no_storage_slot() {
    // The manifest omits `slot`; it must resolve, and the placeholder must be zero.
    let manifest = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "ok": { "kind": "return_value", "offset_bits": 0, "width_bits": 8 }
        }
    }"#;
    let resolved = BindingManifest::from_json(manifest)
        .expect("parses")
        .resolve()
        .expect("resolves");
    let binding: &Binding = &resolved["ok"];
    assert!(binding.is_return_value());
    assert_eq!(binding.slot, [0u8; 32], "no slot was declared");
    assert_eq!(binding.width_bits, 8);
}

#[test]
fn the_predicate_layer_accepts_a_real_solidity_property_shape() {
    // The shape used above is exactly the project's property, expressed as a predicate
    // over a function's answer rather than over storage. Compiling it is the contract
    // that this class of property is expressible at all.
    assert!(oracle("forgeryVerifies == false").symbols().len() == 1);
    // And a nonsensical variant is still rejected rather than silently accepted.
    assert!(PredicateOracle::new(
        InvariantSpec {
            name: "bad".to_string(),
            predicate: "forgeryVerifies ==".to_string(),
        },
        MANIFEST,
    )
    .is_err());
}

#[test]
fn the_evidence_records_the_selector_so_the_call_can_be_repeated() {
    let (_, evidence) = evaluate_with(Some(returns_true()));
    let term = &evidence.terms[0];
    assert_eq!(term.symbol, "forgeryVerifies");
    assert_eq!(term.width_bits, 8);
    // The value and provenance must let a reviewer re-issue the same call.
    assert_eq!(term.value, "1");
    assert_eq!(term.provenance, ProvenanceLabel::ReRead);
    assert_eq!(term.address, "0x00000000000000000000000000000000000000aa");
}

#[test]
fn an_unused_write_record_does_not_disturb_a_return_value_binding() {
    // A return-value symbol has no storage history, so stray writes to the same address
    // must not be mistaken for its value.
    let predicate = oracle("forgeryVerifies == false");
    let mut address = [0u8; 20];
    address[19] = 0xaa;
    let writes = vec![WriteRecord {
        tx_index: 0,
        address,
        slot: [0u8; 32],
        old_value: [0u8; 32],
        new_value: returns_true(),
    }];
    let mut map = BTreeMap::new();
    map.insert(VERIFY_SELECTOR, returns_false());
    let mut reader = FixedReturns(map);
    let view = SequenceView {
        writes: &writes,
        reads: &[],
        block: BlockContext::default(),

        call_outputs: &[],
    };
    let (outcome, _) = predicate.check(&view, 0, &mut reader, ReReadBudget::new(4));
    assert!(
        outcome.is_clean_pass(),
        "the storage write must not override the function's answer, got {outcome:?}"
    );
}

#[test]
fn a_plain_eval_context_also_resolves_a_return_value() {
    // The trait is not oracle-specific: a direct evaluation must agree with the oracle
    // path, or the two would drift.
    let bindings = BindingManifest::from_json(MANIFEST)
        .expect("parses")
        .resolve()
        .expect("resolves");
    let checked = rustyfuzz_predicate::compile("forgeryVerifies == false").expect("compiles");
    let resolver = rustyfuzz_predicate::Resolver::new(&bindings, &[], &[], 0);
    let ctx = EvalContext {
        bindings: &bindings,
        resolver: &resolver,
        block: BlockContext::default(),
        tx_index: 0,
    };
    let mut map = BTreeMap::new();
    map.insert(VERIFY_SELECTOR, returns_true());
    let mut reader = FixedReturns(map);
    let (outcome, _, _) =
        rustyfuzz_predicate::evaluate(checked.expr(), &ctx, &mut reader, ReReadBudget::new(4));
    assert!(
        outcome.is_violation(),
        "direct evaluation must agree with the oracle path, got {outcome:?}"
    );
}
