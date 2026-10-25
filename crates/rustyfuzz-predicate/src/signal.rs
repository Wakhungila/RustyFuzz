//! Scheduler signal mapping (§5.1).
//!
//! The owner ruling is one sentence: **`Unknown` must never auto-promote to a finding
//! or to a pass. Treat it as "no signal".** This module is where that sentence becomes
//! a function, because a rule that lives only in a document gets violated by the next
//! caller who only has an `Outcome` and a score in hand.
//!
//! # Why this is its own module and not an `if` at each call site
//!
//! The scheduler has no tri-state concept: scoring is driven by `CampaignScore`, whose
//! pressure fields are plain `u64`. Historically every reading of a predicate ended up
//! as "did it fire or not", so a predicate that could not be evaluated was
//! indistinguishable from one that held. Making the mapping a named type means an
//! unevaluable predicate cannot be silently counted as evidence, and gives one place
//! to audit.

use crate::eval::Outcome;

/// What a campaign loop is allowed to do with one predicate outcome.
///
/// Deliberately not a `bool`: the interesting cases are three, and collapsing them is
/// the bug §5.1 exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// A violation. The only outcome that may produce a finding, subject to replay
    /// and a passing PoC.
    Finding,
    /// The property held on authoritative evidence. Weak negative evidence: the
    /// search may deprioritise this input, but must not treat it as progress.
    Held,
    /// No usable evidence, or a satisfaction that depended on dividing by zero.
    /// Contributes nothing: it is neither a finding nor a pass, and it must not
    /// reward the input.
    NoSignal,
}

impl Signal {
    /// Maps an evaluator outcome to the only legal scheduler action.
    pub fn from_outcome(outcome: &Outcome) -> Self {
        match outcome {
            // A violation is a finding candidate.
            Outcome::False => Signal::Finding,
            // A clean pass is weak negative evidence.
            Outcome::True => Signal::Held,
            // A pass that depended on div0 is NOT a pass (owner ruling, §3 item 3).
            Outcome::SatisfiedButDiv0 => Signal::NoSignal,
            // Absence of evidence is never a verdict.
            Outcome::Unknown(_) => Signal::NoSignal,
        }
    }

    /// Whether this outcome may contribute to a score at all.
    ///
    /// `Held` returns `true` only because "the property held here" is genuinely
    /// informative for pruning; it must never be added to a *positive* pressure
    /// field. `NoSignal` returns `false` for both directions.
    pub fn may_affect_score(self) -> bool {
        !matches!(self, Signal::NoSignal)
    }

    /// Whether this outcome may produce a finding.
    pub fn may_produce_finding(self) -> bool {
        matches!(self, Signal::Finding)
    }

    /// Whether this outcome may be counted as evidence that a property holds.
    pub fn may_count_as_hold(self) -> bool {
        matches!(self, Signal::Held)
    }

    /// The scheduler-facing pressure delta this outcome justifies.
    ///
    /// `NoSignal` is zero **in both directions**: it does not raise priority and it
    /// does not penalise, because penalising would also be treating an absence of
    /// evidence as evidence.
    pub fn pressure_delta(self) -> u64 {
        match self {
            Signal::Finding => 1,
            Signal::Held | Signal::NoSignal => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::Reason;

    #[test]
    fn a_violation_is_the_only_finding_signal() {
        assert_eq!(Signal::from_outcome(&Outcome::False), Signal::Finding);
        assert!(Signal::Finding.may_produce_finding());
        assert!(!Signal::Held.may_produce_finding());
        assert!(!Signal::NoSignal.may_produce_finding());
    }

    #[test]
    fn an_unknown_is_never_a_finding_and_never_a_pass() {
        // The ruling, as an assertion.
        let signal = Signal::from_outcome(&Outcome::Unknown(Reason::ReReadBudgetExhausted));
        assert_eq!(signal, Signal::NoSignal);
        assert!(
            !signal.may_produce_finding(),
            "Unknown must not become a finding"
        );
        assert!(
            !signal.may_count_as_hold(),
            "Unknown must not count as a pass"
        );
        assert!(
            !signal.may_affect_score(),
            "Unknown must not move the score"
        );
        assert_eq!(signal.pressure_delta(), 0);
    }

    #[test]
    fn a_div0_degraded_satisfaction_is_no_signal() {
        // A pass that depended on dividing by zero is not a pass (§3 item 3).
        let signal = Signal::from_outcome(&Outcome::SatisfiedButDiv0);
        assert_eq!(signal, Signal::NoSignal);
        assert!(!signal.may_count_as_hold());
    }

    #[test]
    fn a_clean_pass_is_held_not_a_finding() {
        let signal = Signal::from_outcome(&Outcome::True);
        assert_eq!(signal, Signal::Held);
        assert!(signal.may_count_as_hold());
        assert!(!signal.may_produce_finding());
        // Held must not add positive pressure: "nothing happened" is not progress.
        assert_eq!(signal.pressure_delta(), 0);
    }

    #[test]
    fn only_a_finding_raises_pressure() {
        assert_eq!(Signal::Finding.pressure_delta(), 1);
        for other in [Signal::Held, Signal::NoSignal] {
            assert_eq!(
                other.pressure_delta(),
                0,
                "{other:?} must not raise pressure"
            );
        }
    }

    #[test]
    fn every_unknown_reason_maps_to_no_signal() {
        // Exhaustive over the Reason variants so a new one cannot default to a signal.
        let reasons = [
            Reason::Unresolved("x".to_string()),
            Reason::UnobservedKeys {
                observed: 1,
                total: 3,
            },
            Reason::ReReadBudgetExhausted,
            Reason::NoWriteAtCurrentIndex { tx_index: 2 },
            Reason::SortMismatch {
                expected: "int",
                actual: "bool",
            },
        ];
        for reason in reasons {
            assert_eq!(
                Signal::from_outcome(&Outcome::Unknown(reason.clone())),
                Signal::NoSignal,
                "reason {reason:?} must be no signal"
            );
        }
    }
}
