//! Strong domain identifiers.
//!
//! Identifier representation is deliberately not uniform. Some identifiers are
//! content-derived opaque text, while others are assigned names or numeric
//! handles that preserve the current monolith's behavior during migration.

use crate::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

macro_rules! string_id {
    ($name:ident, $kind:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a new identifier after validating its textual form.
            pub fn new(value: impl Into<String>) -> CoreResult<Self> {
                let value = value.into();
                validate_text_id($kind, value).map(Self)
            }

            /// Borrows the stable textual form of this identifier.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the identifier and returns its stable textual form.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = CoreError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = CoreError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = CoreError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

string_id!(
    InputId,
    "input",
    "Opaque content-derived testcase identifier. Stage 2A defines the type; Stage 2B defines the final semantic hash derivation."
);

string_id!(
    CampaignId,
    "campaign",
    "Assigned campaign identifier. This is intended to be human-readable and stable within artifact paths and manifests."
);

string_id!(
    OracleId,
    "oracle",
    "Assigned oracle rule identifier. This names a rule or oracle pack without coupling core to the oracle implementation."
);

string_id!(
    FindingId,
    "finding",
    "Assigned finding identifier used to reference finding records without embedding the finding payload."
);

string_id!(
    EvidenceId,
    "evidence",
    "Assigned evidence identifier used to reference persisted evidence without embedding backend-specific evidence payloads."
);

/// Assigned snapshot identifier preserving the current monolith's numeric
/// snapshot handle during Stage 2A.
///
/// Stage 2C will decide whether snapshot identity remains assigned or becomes
/// content-derived from state and environment hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotId(u64);

impl SnapshotId {
    /// Creates a snapshot identifier from the current numeric representation.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the current numeric representation.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for SnapshotId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<SnapshotId> for u64 {
    fn from(value: SnapshotId) -> Self {
        value.0
    }
}

impl FromStr for SnapshotId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse::<u64>()
            .map(Self::new)
            .map_err(|_| CoreError::InvalidId {
                kind: "snapshot",
                value: value.to_string(),
                reason: "expected unsigned decimal integer",
            })
    }
}

fn validate_text_id(kind: &'static str, value: String) -> CoreResult<String> {
    if value.is_empty() {
        return Err(CoreError::EmptyId { kind });
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_ids_have_stable_display_parse_and_json_forms() {
        let input = InputId::new("input:abc123").unwrap();
        assert_eq!(input.to_string(), "input:abc123");
        assert_eq!("input:abc123".parse::<InputId>().unwrap(), input);
        assert_eq!(serde_json::to_string(&input).unwrap(), "\"input:abc123\"");
        assert_eq!(
            serde_json::from_str::<InputId>("\"input:abc123\"").unwrap(),
            input
        );

        let campaign = CampaignId::new("campaign-local-1").unwrap();
        assert_eq!(campaign.as_str(), "campaign-local-1");

        let oracle = OracleId::new("erc20.accounting").unwrap();
        assert_eq!(oracle.to_string(), "erc20.accounting");

        let finding = FindingId::new("finding-1").unwrap();
        assert_eq!(finding.into_inner(), "finding-1");

        let evidence = EvidenceId::new("evidence-1").unwrap();
        assert_eq!(evidence.as_str(), "evidence-1");
    }

    #[test]
    fn string_ids_reject_empty_text() {
        assert_eq!(
            InputId::new("").unwrap_err(),
            CoreError::EmptyId { kind: "input" }
        );
        assert_eq!(
            CampaignId::new("").unwrap_err(),
            CoreError::EmptyId { kind: "campaign" }
        );
    }

    #[test]
    fn snapshot_id_has_stable_decimal_and_json_forms() {
        let snapshot = SnapshotId::new(42);
        assert_eq!(snapshot.get(), 42);
        assert_eq!(snapshot.to_string(), "42");
        assert_eq!("42".parse::<SnapshotId>().unwrap(), snapshot);
        assert_eq!(serde_json::to_string(&snapshot).unwrap(), "42");
        assert_eq!(serde_json::from_str::<SnapshotId>("42").unwrap(), snapshot);
    }

    #[test]
    fn snapshot_id_rejects_non_decimal_text() {
        assert_eq!(
            "snapshot-a".parse::<SnapshotId>().unwrap_err(),
            CoreError::InvalidId {
                kind: "snapshot",
                value: "snapshot-a".to_string(),
                reason: "expected unsigned decimal integer",
            }
        );
    }

    #[test]
    fn strong_ids_are_distinct_types_at_runtime_boundaries() {
        fn accepts_snapshot_id(id: SnapshotId) -> u64 {
            id.get()
        }

        fn accepts_input_id(id: InputId) -> String {
            id.into_inner()
        }

        assert_eq!(accepts_snapshot_id(SnapshotId::new(7)), 7);
        assert_eq!(
            accepts_input_id(InputId::new("input-7").unwrap()),
            "input-7"
        );
    }
}
