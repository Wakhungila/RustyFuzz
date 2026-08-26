//! Dependency-neutral finding and evidence references.
//!
//! Stage 2A introduced the evidence reference skeleton. Stage 2D adds the
//! canonical finding lifecycle and versioned finding identity.

use crate::{EvidenceId, OracleId};
use serde::{Deserialize, Serialize};

/// Canonical finding lifecycle (Stage 2D).
///
/// One machine for the whole project:
///
/// ```text
/// Signal -> Candidate -> Replayed -> Minimized -> Proved
///                   \____________ Rejected from any intermediate stage
/// ```
///
/// `Rejected` is terminal. Backward transitions are illegal. Heuristic signal
/// can never jump directly to `Proved`; proof requires passing through the
/// replayed/minimized stages under explicit validation policy.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum FindingLifecycle {
    /// Raw oracle/analysis signal; not yet a candidate.
    #[default]
    Signal,
    /// Selected candidate awaiting deterministic replay.
    Candidate,
    /// Deterministically replayed against recorded/base state.
    Replayed,
    /// Minimized while preserving the finding predicate.
    Minimized,
    /// Passed policy-defined deterministic validation.
    Proved,
    /// Terminal rejection with an explanatory reason.
    Rejected,
}

impl FindingLifecycle {
    /// Returns whether `from -> to` is a legal transition.
    ///
    /// Staying in place (`from == to`) is legal (idempotent re-observation).
    pub fn can_transition(self, to: FindingLifecycle) -> bool {
        use FindingLifecycle::*;
        if self == to {
            return true; // idempotent re-observation
        }
        let forward = matches!(
            (self, to),
            (Signal, Candidate)
                | (Candidate, Replayed)
                | (Replayed, Minimized)
                | (Minimized, Proved)
        );
        let reject = !matches!(self, Proved | Rejected) && to == Rejected;
        forward || reject
    }

    /// Validates a transition, returning `Err` on an illegal move.
    pub fn transition(self, to: FindingLifecycle) -> Result<FindingLifecycle, IllegalTransition> {
        if self.can_transition(to) {
            Ok(to)
        } else {
            Err(IllegalTransition { from: self, to })
        }
    }
}

/// An illegal lifecycle transition attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: FindingLifecycle,
    pub to: FindingLifecycle,
}

/// Versioned canonical finding identity components (Stage 2D).
///
/// Deduplication must key on these stable execution/analysis properties rather
/// than human-readable messages, filesystem paths, or timestamps. The exact
/// digest algorithm stays with the producer; this type carries the normalized
/// component set and its identity schema version so the contract can evolve
/// without silently changing dedup behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingIdentity {
    /// Identity contract version; bump when component semantics change.
    pub identity_version: u32,
    /// Stable oracle/rule identifier that raised the signal.
    pub rule_id: OracleId,
    /// Contract target involved in the finding, when applicable.
    pub target: Option<String>,
    /// Canonical semantic input id that produced the signal (minimized input
    /// may replace this only with an explicit migration note).
    pub input_id: crate::InputId,
    /// Digest of the decisive evidence material.
    pub evidence_fingerprint: String,
}

impl FindingIdentity {
    pub const IDENTITY_VERSION: u32 = 1;

    /// Builds a v1 identity from normalized components.
    pub fn v1(
        rule_id: OracleId,
        target: Option<String>,
        input_id: crate::InputId,
        evidence_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            identity_version: Self::IDENTITY_VERSION,
            rule_id,
            target,
            input_id,
            evidence_fingerprint: evidence_fingerprint.into(),
        }
    }
}

/// Stable category for evidence references.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    /// Evidence derived from transaction call traces.
    CallTrace,
    /// Evidence derived from storage reads, writes, or diffs.
    Storage,
    /// Evidence derived from economic balance or accounting deltas.
    EconomicDelta,
    /// Evidence derived from deterministic replay.
    Replay,
    /// Evidence derived from minimization.
    Minimization,
    /// Evidence produced by a user or external tool and later validated.
    External,
}

/// Reference to evidence stored outside the core domain crate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EvidenceRef {
    /// Stable evidence identifier.
    pub evidence_id: EvidenceId,
    /// Evidence category.
    pub kind: EvidenceKind,
}

impl EvidenceRef {
    /// Creates a new evidence reference.
    pub fn new(evidence_id: EvidenceId, kind: EvidenceKind) -> Self {
        Self { evidence_id, kind }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_lifecycle_allows_forward_and_rejects_backward() {
        use FindingLifecycle::*;
        assert!(Signal.transition(Candidate).is_ok());
        assert!(Candidate.transition(Replayed).is_ok());
        assert!(Replayed.transition(Minimized).is_ok());
        assert!(Minimized.transition(Proved).is_ok());

        // Backward transitions are illegal.
        assert!(!Minimized.can_transition(Replayed));
        assert!(!Replayed.can_transition(Candidate));
        assert!(!Proved.can_transition(Signal));
    }

    #[test]
    fn signal_cannot_become_proved_without_policy_stages() {
        // Global invariant: AI/heuristic/signal never directly proves.
        use FindingLifecycle::*;
        assert!(Signal.transition(Proved).is_err());
        assert!(Candidate.transition(Proved).is_err());
    }

    #[test]
    fn rejection_is_terminal_and_available_from_intermediates() {
        use FindingLifecycle::*;
        for stage in [Signal, Candidate, Replayed, Minimized] {
            assert!(stage.can_transition(Rejected), "{stage:?} -> Rejected");
        }
        // Rejected is terminal.
        assert!(!Rejected.can_transition(Signal));
        assert!(!Rejected.can_transition(Proved));
        assert!(Rejected.can_transition(Rejected)); // idempotent
    }

    #[test]
    fn finding_identity_v1_is_deterministic_component_set() {
        let build = || {
            FindingIdentity::v1(
                OracleId::new("erc20.accounting").unwrap(),
                Some("0xabc".to_string()),
                crate::InputId::new("0xdead").unwrap(),
                "evidence-fp",
            )
        };
        let a = build();
        let b = build();
        assert_eq!(a, b);
        assert_eq!(a.identity_version, FindingIdentity::IDENTITY_VERSION);

        // Changing any component changes identity.
        let mut c = build();
        c.evidence_fingerprint = "other".to_string();
        assert_ne!(a, c);
    }

    #[test]
    fn evidence_ref_round_trips_json() {
        let reference =
            EvidenceRef::new(EvidenceId::new("evidence-a").unwrap(), EvidenceKind::Replay);
        let json = serde_json::to_string(&reference).unwrap();
        assert_eq!(json, "{\"evidence_id\":\"evidence-a\",\"kind\":\"Replay\"}");
        let decoded: EvidenceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, reference);
    }
}
