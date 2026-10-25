//! The oracle seam (§8 item 7) and finding evidence (§6.6).
//!
//! `InvariantOracle` is the trait the design says does not exist yet and must be
//! built. It is deliberately narrow: an oracle is given a compiled predicate, a
//! resolution context and a state reader, and answers with an outcome plus evidence.
//! It does not decide whether a finding is real — promotion and replay do that.
//!
//! # Why evidence is a first-class type
//!
//! §6.6 requires that a finding be re-derivable without the evaluator: the predicate
//! text, every resolved term with its `(address, slot, tx_index, provenance)`, the
//! counters, and the verdict. A finding that says only "invariant violated" is not
//! evidence, so the type that carries it is not an afterthought.

use crate::binding::{Binding, BindingManifest};
use crate::eval::{self, BlockContext, EvalContext, Outcome, Reason};
use crate::resolve::{
    KeyCoverage, Provenance, ReReadBudget, ReadRecord, Resolver, StateReader, WriteRecord,
};
use crate::types::{compile, CheckedPredicate, Int256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One resolved term in a finding, sufficient to recompute the verdict by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermEvidence {
    pub symbol: String,
    pub address: String,
    pub slot: String,
    pub offset_bits: u16,
    pub width_bits: u16,
    /// Decimal rendering of the value the evaluator used.
    pub value: String,
    pub provenance: ProvenanceLabel,
    pub tx_index: usize,
}

/// Serializable form of [`Provenance`], so evidence round-trips through JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceLabel {
    Write,
    ObservedRead,
    PreValue,
    ReRead,
}

impl From<Provenance> for ProvenanceLabel {
    fn from(provenance: Provenance) -> Self {
        match provenance {
            Provenance::Write => ProvenanceLabel::Write,
            Provenance::ObservedRead => ProvenanceLabel::ObservedRead,
            Provenance::PreValue => ProvenanceLabel::PreValue,
            Provenance::ReRead => ProvenanceLabel::ReRead,
        }
    }
}

/// Counters carried with a finding.
///
/// Fields are **always declared** and only *written* when non-default (§9 item 8), so
/// a consumer can tell "counter was zero" from "this version has no such counter".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCounters {
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub division_by_zero_observed: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub overflow_checked_sites: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub overflow_violations: u64,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub observed_keys: usize,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub unobserved_keys: usize,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

impl EvidenceCounters {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// The verdict, spelled out so a reader does not need the enum's definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The property held on authoritative evidence.
    Held,
    /// The property was violated.
    Violated,
    /// Would have held, but a divisor was zero. Not a pass (§3 item 3).
    HeldButDiv0,
    /// No usable evidence.
    Unknown,
}

impl From<&Outcome> for Verdict {
    fn from(outcome: &Outcome) -> Self {
        match outcome {
            Outcome::True => Verdict::Held,
            Outcome::False => Verdict::Violated,
            Outcome::SatisfiedButDiv0 => Verdict::HeldButDiv0,
            Outcome::Unknown(_) => Verdict::Unknown,
        }
    }
}

/// Everything needed to re-derive one predicate's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Original bindings needed to evaluate this predicate on a fresh replay.
    #[serde(default)]
    pub binding_manifest: String,
    /// The predicate exactly as the author wrote it.
    pub predicate: String,
    pub tx_index: usize,
    pub verdict: Verdict,
    /// Human-readable verdict, including the div0 and overflow markers (§6.6).
    pub verdict_text: String,
    /// Every resolved term, or empty when nothing resolved.
    pub terms: Vec<TermEvidence>,
    pub counters: EvidenceCounters,
    /// The typed reason when the verdict is Unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<String>,
    /// Key coverage for mapping sums, always declared per §9 item 8.
    pub key_coverage: KeyCoverage,
}

impl Evidence {
    pub fn is_violation(&self) -> bool {
        self.verdict == Verdict::Violated
    }

    /// Renders the one-line summary a report puts next to a finding.
    pub fn summary_line(&self) -> String {
        format!(
            "{} [tx {}] {}",
            self.predicate, self.tx_index, self.verdict_text
        )
    }
}

/// Metadata an oracle needs to describe itself in a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantSpec {
    pub name: String,
    /// Source text of the predicate, retained verbatim for evidence.
    pub predicate: String,
}

/// Errors an oracle can raise before evaluation even starts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OracleError {
    #[error("invariant `{name}`: {source}")]
    Compile {
        name: String,
        source: crate::CompileError,
    },
    #[error("invariant `{name}`: {message}")]
    Manifest { name: String, message: String },
}

/// Per-transaction storage activity handed to an oracle.
#[derive(Debug, Clone)]
pub struct SequenceView<'a> {
    pub writes: &'a [WriteRecord],
    pub reads: &'a [ReadRecord],
    pub block: BlockContext,
}

/// A registered invariant.
///
/// Implementors are expected to be cheap to call once per transaction, because §2.2
/// of the roadmap checks invariants after **every** step rather than only at the end:
/// a stateful accounting bug is usually visible at an intermediate step.
pub trait InvariantOracle: Send + Sync {
    /// Stable name, used in reports and to key evidence.
    fn name(&self) -> &str;

    /// Checks the invariant at `tx_index`.
    fn check(
        &self,
        view: &SequenceView<'_>,
        tx_index: usize,
        reader: &mut dyn StateReader,
        budget: ReReadBudget,
    ) -> (Outcome, Evidence);
}

/// The built-in oracle: a compiled predicate plus its resolved bindings.
#[derive(Debug)]
pub struct PredicateOracle {
    spec: InvariantSpec,
    checked: CheckedPredicate,
    binding_manifest: String,
    bindings: BTreeMap<String, Binding>,
}

impl PredicateOracle {
    /// Builds an oracle from predicate text and a binding manifest.
    ///
    /// Both failure modes are load-time: a malformed predicate and an unresolvable
    /// binding must not surface mid-campaign (§5 items 1 and 10).
    pub fn new(spec: InvariantSpec, manifest_json: &str) -> Result<Self, OracleError> {
        let checked = compile(&spec.predicate).map_err(|source| OracleError::Compile {
            name: spec.name.clone(),
            source,
        })?;
        let manifest =
            BindingManifest::from_json(manifest_json).map_err(|error| OracleError::Manifest {
                name: spec.name.clone(),
                message: error.to_string(),
            })?;
        let bindings =
            manifest
                .resolve_for(checked.symbols())
                .map_err(|error| OracleError::Manifest {
                    name: spec.name.clone(),
                    message: error.to_string(),
                })?;
        Ok(Self {
            spec,
            checked,
            binding_manifest: manifest_json.to_owned(),
            bindings,
        })
    }

    pub fn spec(&self) -> &InvariantSpec {
        &self.spec
    }

    pub fn symbols(&self) -> &[crate::Symbol] {
        self.checked.symbols()
    }

    /// Builds term evidence for the symbols this predicate touched.
    ///
    /// This runs **after** evaluation and re-resolves each symbol to record the value
    /// the evaluator saw. It gets a fresh budget rather than sharing the evaluator's,
    /// because the evaluator has already consumed its allowance and a starved evidence
    /// pass would silently omit terms from a finding — the evidence would then look
    /// complete while being partial.
    fn collect_terms(
        &self,
        view: &SequenceView<'_>,
        tx_index: usize,
        reader: &mut dyn StateReader,
        budget: ReReadBudget,
    ) -> Vec<TermEvidence> {
        let resolver = Resolver::new(&self.bindings, view.writes, view.reads, tx_index);
        let mut terms = Vec::new();
        // Each symbol gets enough allowance for its own key set, so a mapping with N
        // keys is never starved by an unrelated term. The total is bounded by the
        // caller's budget multiplied by the binding count, which keeps the work finite
        // while letting complete evidence be recorded (§5 item 9b).
        let per_symbol = budget.remaining().max(1);
        for (name, binding) in &self.bindings {
            let symbol = crate::Symbol(name.split('.').map(str::to_string).collect());
            let mut local = ReReadBudget::new(per_symbol + binding.declared_key_count());
            let resolved = if binding.is_mapping() {
                resolver
                    .resolve_sum(&symbol, reader, &mut local)
                    .ok()
                    .map(|(resolved, _)| resolved)
            } else {
                resolver.resolve(&symbol, reader, &mut local).ok()
            };
            if let Some(resolved) = resolved {
                terms.push(TermEvidence {
                    symbol: name.clone(),
                    address: binding.address_hex(),
                    slot: crate::binding::hex(&binding.slot),
                    offset_bits: binding.offset_bits,
                    width_bits: binding.width_bits,
                    value: resolved.value.to_string(),
                    provenance: ProvenanceLabel::from(resolved.provenance),
                    tx_index,
                });
            }
        }
        terms
    }
}

impl InvariantOracle for PredicateOracle {
    fn name(&self) -> &str {
        &self.spec.name
    }

    fn check(
        &self,
        view: &SequenceView<'_>,
        tx_index: usize,
        reader: &mut dyn StateReader,
        budget: ReReadBudget,
    ) -> (Outcome, Evidence) {
        let resolver = Resolver::new(&self.bindings, view.writes, view.reads, tx_index);
        let ctx = EvalContext {
            bindings: &self.bindings,
            resolver: &resolver,
            block: view.block,
            tx_index,
        };
        let (outcome, counters, coverage) =
            eval::evaluate(self.checked.expr(), &ctx, reader, budget);

        let terms = self.collect_terms(view, tx_index, reader, budget);
        let evidence = Evidence {
            binding_manifest: self.binding_manifest.clone(),
            predicate: self.spec.predicate.clone(),
            tx_index,
            verdict: Verdict::from(&outcome),
            verdict_text: eval::verdict_text(&outcome, &counters),
            terms,
            counters: EvidenceCounters {
                division_by_zero_observed: counters.division_by_zero_observed,
                overflow_checked_sites: counters.overflow_checked_sites,
                overflow_violations: counters.overflow_violations,
                observed_keys: coverage.observed_keys,
                unobserved_keys: coverage.unobserved_keys,
            },
            unknown_reason: outcome.reason().map(|reason: &Reason| reason.to_string()),
            key_coverage: coverage,
        };
        (outcome, evidence)
    }
}

/// A collection of invariants checked together.
///
/// Registration is additive: existing campaign oracles are untouched (§8 item 7).
#[derive(Default)]
pub struct InvariantRegistry {
    oracles: Vec<Box<dyn InvariantOracle>>,
}

impl std::fmt::Debug for InvariantRegistry {
    /// Prints the registered names rather than the trait objects.
    ///
    /// A registry is a configuration; when one is wrong, the useful information is which
    /// invariants were registered, not an opaque pointer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvariantRegistry")
            .field(
                "names",
                &self
                    .oracles
                    .iter()
                    .map(|oracle| oracle.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl InvariantRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, oracle: Box<dyn InvariantOracle>) {
        self.oracles.push(oracle);
    }

    pub fn len(&self) -> usize {
        self.oracles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.oracles.is_empty()
    }

    /// Names of the registered invariants, in registration order.
    pub fn names(&self) -> Vec<&str> {
        self.oracles.iter().map(|oracle| oracle.name()).collect()
    }

    /// Checks every registered invariant once.
    pub fn check_all(
        &self,
        view: &SequenceView<'_>,
        tx_index: usize,
        reader: &mut dyn StateReader,
        budget: ReReadBudget,
    ) -> Vec<(Outcome, Evidence)> {
        self.oracles
            .iter()
            .map(|oracle| oracle.check(view, tx_index, reader, budget))
            .collect()
    }
}

/// Convenience for tests and callers that only need the integer a term resolved to.
pub fn term_value(term: &TermEvidence) -> Option<Int256> {
    // Decimal parse via repeated multiply-add, since Int256 has no FromStr yet.
    let mut value = Int256::ZERO;
    let ten = Int256::from_u64(10);
    for ch in term.value.chars() {
        let digit = ch.to_digit(10)?;
        value = value
            .wrapping_mul(ten)
            .wrapping_add(Int256::from_u64(u64::from(digit)));
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::NoReRead;
    use crate::signal::Signal;

    const MANIFEST: &str = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "sumBalances": { "kind": "slot", "slot": "0x3",
                             "offset_bits": 0, "width_bits": 256 },
            "totalSupply": { "kind": "slot", "slot": "0x4",
                             "offset_bits": 0, "width_bits": 256 }
        }
    }"#;

    fn addr() -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = 0xaa;
        a
    }

    fn slot(value: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = value;
        s
    }

    fn word(value: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&value.to_be_bytes());
        w
    }

    fn oracle(predicate: &str) -> PredicateOracle {
        PredicateOracle::new(
            InvariantSpec {
                name: "accounting".to_string(),
                predicate: predicate.to_string(),
            },
            MANIFEST,
        )
        .expect("oracle must build")
    }

    fn writes(a: u64, b: u64) -> Vec<WriteRecord> {
        vec![
            WriteRecord {
                tx_index: 0,
                address: addr(),
                slot: slot(3),
                old_value: word(0),
                new_value: word(a),
            },
            WriteRecord {
                tx_index: 0,
                address: addr(),
                slot: slot(4),
                old_value: word(0),
                new_value: word(b),
            },
        ]
    }

    // ---- load-time failures -------------------------------------------

    #[test]
    fn a_malformed_predicate_fails_at_construction() {
        let error = PredicateOracle::new(
            InvariantSpec {
                name: "bad".to_string(),
                predicate: "a ==".to_string(),
            },
            MANIFEST,
        )
        .unwrap_err();
        assert!(matches!(error, OracleError::Compile { .. }));
    }

    #[test]
    fn an_unbound_symbol_fails_at_construction_not_at_check_time() {
        let error = PredicateOracle::new(
            InvariantSpec {
                name: "bad".to_string(),
                predicate: "absent == 1".to_string(),
            },
            MANIFEST,
        )
        .unwrap_err();
        match error {
            OracleError::Manifest { message, .. } => {
                assert!(
                    message.contains("absent"),
                    "message must name the symbol: {message}"
                )
            }
            other => panic!("expected Manifest error, got {other}"),
        }
    }

    #[test]
    fn an_omitted_bit_range_fails_at_construction() {
        let manifest = r#"{
            "target": "0x00000000000000000000000000000000000000aa",
            "symbols": { "x": { "kind": "slot", "slot": "0x1" } }
        }"#;
        let error = PredicateOracle::new(
            InvariantSpec {
                name: "n".to_string(),
                predicate: "x == 1".to_string(),
            },
            manifest,
        )
        .unwrap_err();
        match error {
            OracleError::Manifest { message, .. } => assert!(message.contains("offset_bits")),
            other => panic!("expected Manifest error, got {other}"),
        }
    }

    // ---- evidence (§6.6) ---------------------------------------------

    #[test]
    fn a_violation_carries_re_derivable_evidence() {
        let oracle = oracle("sumBalances == totalSupply");
        let writes = writes(100, 40);
        let view = SequenceView {
            writes: &writes,
            reads: &[],
            block: BlockContext::default(),
        };
        let mut reader = NoReRead;
        let (outcome, evidence) = oracle.check(&view, 1, &mut reader, ReReadBudget::new(8));

        assert!(outcome.is_violation());
        assert_eq!(evidence.verdict, Verdict::Violated);
        assert_eq!(evidence.predicate, "sumBalances == totalSupply");
        assert_eq!(evidence.tx_index, 1);
        // Both terms must be present with values a human can check.
        let names: Vec<&str> = evidence.terms.iter().map(|t| t.symbol.as_str()).collect();
        assert!(names.contains(&"sumBalances"));
        assert!(names.contains(&"totalSupply"));
        let sum = evidence
            .terms
            .iter()
            .find(|t| t.symbol == "sumBalances")
            .expect("term present");
        assert_eq!(term_value(sum), Some(Int256::from_u64(100)));
        assert_eq!(sum.provenance, ProvenanceLabel::Write);
        assert_eq!(sum.address, "0x00000000000000000000000000000000000000aa");
    }

    #[test]
    fn evidence_round_trips_through_json() {
        let oracle = oracle("sumBalances == totalSupply");
        let writes = writes(100, 40);
        let view = SequenceView {
            writes: &writes,
            reads: &[],
            block: BlockContext::default(),
        };
        let mut reader = NoReRead;
        let (_, evidence) = oracle.check(&view, 1, &mut reader, ReReadBudget::new(8));

        let json = serde_json::to_string(&evidence).expect("serialises");
        let back: Evidence = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, evidence);
    }

    #[test]
    fn default_counters_are_omitted_but_the_field_stays_declared() {
        // §9 item 8: written only when non-default, always present in the schema.
        let evidence = Evidence {
            binding_manifest: String::new(),
            predicate: "x == 1".to_string(),
            tx_index: 0,
            verdict: Verdict::Held,
            verdict_text: "satisfied".to_string(),
            terms: Vec::new(),
            counters: EvidenceCounters::default(),
            unknown_reason: None,
            key_coverage: KeyCoverage::default(),
        };
        let json = serde_json::to_string(&evidence).expect("serialises");
        assert!(
            !json.contains("division_by_zero_observed"),
            "a default counter must not be written: {json}"
        );
        // But deserialising a document *without* the field still works, which is what
        // "always declared in the schema" buys a consumer.
        let back: Evidence = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back.counters.division_by_zero_observed, 0);
    }

    #[test]
    fn a_non_default_counter_is_written() {
        let evidence = Evidence {
            binding_manifest: String::new(),
            predicate: "a / b <= 10".to_string(),
            tx_index: 0,
            verdict: Verdict::HeldButDiv0,
            verdict_text: "satisfied (div0 observed 1 time(s))".to_string(),
            terms: Vec::new(),
            counters: EvidenceCounters {
                division_by_zero_observed: 1,
                ..Default::default()
            },
            unknown_reason: None,
            key_coverage: KeyCoverage::default(),
        };
        let json = serde_json::to_string(&evidence).expect("serialises");
        assert!(json.contains("\"division_by_zero_observed\":1"));
    }

    #[test]
    fn an_unknown_carries_its_reason() {
        let oracle = oracle("sumBalances == totalSupply");
        let view = SequenceView {
            writes: &[],
            reads: &[],
            block: BlockContext::default(),
        };
        let mut reader = NoReRead;
        let (outcome, evidence) = oracle.check(&view, 1, &mut reader, ReReadBudget::new(8));
        assert!(matches!(outcome, Outcome::Unknown(_)));
        assert_eq!(evidence.verdict, Verdict::Unknown);
        assert!(evidence.unknown_reason.is_some(), "reason must be recorded");
        // And it is no signal for the scheduler.
        assert_eq!(Signal::from_outcome(&outcome), Signal::NoSignal);
    }

    #[test]
    fn the_summary_line_names_the_predicate_tx_and_verdict() {
        let evidence = Evidence {
            binding_manifest: String::new(),
            predicate: "sumBalances == totalSupply".to_string(),
            tx_index: 3,
            verdict: Verdict::Violated,
            verdict_text: "violated".to_string(),
            terms: Vec::new(),
            counters: EvidenceCounters::default(),
            unknown_reason: None,
            key_coverage: KeyCoverage::default(),
        };
        let line = evidence.summary_line();
        assert!(line.contains("sumBalances == totalSupply"));
        assert!(line.contains("tx 3"));
        assert!(line.contains("violated"));
    }

    // ---- registry -----------------------------------------------------

    #[test]
    fn the_registry_checks_every_registered_invariant() {
        let mut registry = InvariantRegistry::new();
        registry.register(Box::new(oracle("sumBalances == totalSupply")));
        registry.register(Box::new(
            PredicateOracle::new(
                InvariantSpec {
                    name: "monotonic".to_string(),
                    predicate: "sumBalances >= 0".to_string(),
                },
                MANIFEST,
            )
            .expect("builds"),
        ));
        assert_eq!(registry.len(), 2);

        let writes = writes(100, 40);
        let view = SequenceView {
            writes: &writes,
            reads: &[],
            block: BlockContext::default(),
        };
        let mut reader = NoReRead;
        let results = registry.check_all(&view, 1, &mut reader, ReReadBudget::new(8));
        assert_eq!(results.len(), 2);
        // The first is violated, the second holds.
        let violations = results.iter().filter(|(o, _)| o.is_violation()).count();
        assert_eq!(violations, 1);
        let held = results.iter().filter(|(o, _)| o.is_clean_pass()).count();
        assert_eq!(held, 1);
    }

    #[test]
    fn an_empty_registry_checks_nothing_without_panicking() {
        let registry = InvariantRegistry::new();
        assert!(registry.is_empty());
        let view = SequenceView {
            writes: &[],
            reads: &[],
            block: BlockContext::default(),
        };
        let mut reader = NoReRead;
        assert!(registry
            .check_all(&view, 0, &mut reader, ReReadBudget::new(1))
            .is_empty());
    }
}
