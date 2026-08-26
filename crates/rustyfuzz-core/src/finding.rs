//! Dependency-neutral finding and evidence references.
//!
//! Stage 2A intentionally does not replace the existing finding lifecycle. The
//! canonical lifecycle and transition policy are Stage 2D work.

use crate::EvidenceId;
use serde::{Deserialize, Serialize};

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
    fn evidence_ref_round_trips_json() {
        let reference =
            EvidenceRef::new(EvidenceId::new("evidence-a").unwrap(), EvidenceKind::Replay);
        let json = serde_json::to_string(&reference).unwrap();
        assert_eq!(json, "{\"evidence_id\":\"evidence-a\",\"kind\":\"Replay\"}");
        let decoded: EvidenceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, reference);
    }
}
