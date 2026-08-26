//! Dependency-neutral snapshot metadata.

use crate::{CampaignId, CoreError, CoreResult, InputId, SnapshotId};
use serde::{Deserialize, Serialize};

/// Deterministic digest of relevant EVM state content.
///
/// This is deliberately distinct from [`SnapshotId`]: a `SnapshotId` is an
/// *assigned* logical reference inside a corpus, while a fingerprint is
/// derived from state content. Two snapshots with equal fingerprints hold
/// equivalent cached-state material even when their ids differ. The exact
/// digest algorithm lives with the backend that can observe the state; this
/// type only carries the canonical textual form (`0x…` hex).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StateFingerprint(String);

impl StateFingerprint {
    /// Creates a fingerprint after validating the textual form.
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(CoreError::EmptyId {
                kind: "state_fingerprint",
            });
        }
        Ok(Self(value))
    }

    /// Borrows the stable textual form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the fingerprint and returns its textual form.
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Metadata needed to identify and reconstruct snapshot ancestry.
///
/// This struct does not contain backend state. REVM databases, fork caches, and
/// snapshot corpus behavior remain outside `rustyfuzz-core`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Snapshot identifier used by corpus and artifact references.
    pub snapshot_id: SnapshotId,
    /// Campaign that produced or owns this snapshot, when known.
    pub campaign_id: Option<CampaignId>,
    /// Parent snapshot in a state-exploration lineage.
    pub parent: Option<SnapshotId>,
    /// Input that produced this snapshot from its parent.
    pub producing_input: Option<InputId>,
}

impl SnapshotMetadata {
    /// Creates metadata for a root snapshot.
    pub fn root(snapshot_id: SnapshotId) -> Self {
        Self {
            snapshot_id,
            campaign_id: None,
            parent: None,
            producing_input: None,
        }
    }

    /// Creates metadata for a derived snapshot.
    pub fn derived(snapshot_id: SnapshotId, parent: SnapshotId, producing_input: InputId) -> Self {
        Self {
            snapshot_id,
            campaign_id: None,
            parent: Some(parent),
            producing_input: Some(producing_input),
        }
    }

    /// Returns the ancestry chain from this snapshot back to its root
    /// (inclusive). Rejects cyclic lineages instead of looping forever.
    ///
    /// `parent_of` maps a snapshot id to its parent; roots simply have no
    /// mapping entry.
    pub fn ancestry(
        &self,
        mut parent_of: impl FnMut(SnapshotId) -> Option<SnapshotId>,
    ) -> CoreResult<Vec<SnapshotId>> {
        let mut chain = vec![self.snapshot_id];
        let mut current = self.snapshot_id;
        while let Some(parent) = parent_of(current) {
            if parent == current {
                // Self-parent is the corpus' root representation.
                break;
            }
            if chain.contains(&parent) {
                return Err(CoreError::InvalidId {
                    kind: "snapshot",
                    value: parent.to_string(),
                    reason: "cyclic snapshot lineage",
                });
            }
            chain.push(parent);
            current = parent;
        }
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_fingerprint_round_trips_and_rejects_empty() {
        let fingerprint = StateFingerprint::new("0xabc123").unwrap();
        assert_eq!(fingerprint.as_str(), "0xabc123");
        assert_eq!(fingerprint.clone().into_inner(), "0xabc123");
        assert!(StateFingerprint::new("").is_err());
        // Distinct type from SnapshotId at the boundary.
        fn takes_fingerprint(_fp: &StateFingerprint) {}
        let id = SnapshotId::new(1);
        let _ = id;
        takes_fingerprint(&fingerprint);
    }

    #[test]
    fn ancestry_walks_to_root_and_rejects_cycles() {
        let metadata = SnapshotMetadata::derived(
            SnapshotId::new(3),
            SnapshotId::new(2),
            InputId::new("input-b").unwrap(),
        );
        let mut parents = std::collections::HashMap::new();
        parents.insert(SnapshotId::new(3), SnapshotId::new(2));
        parents.insert(SnapshotId::new(2), SnapshotId::new(1));
        parents.insert(SnapshotId::new(1), SnapshotId::new(0));
        parents.insert(SnapshotId::new(0), SnapshotId::new(0));

        let chain = metadata.ancestry(|id| parents.get(&id).copied()).unwrap();
        assert_eq!(
            chain,
            vec![
                SnapshotId::new(3),
                SnapshotId::new(2),
                SnapshotId::new(1),
                SnapshotId::new(0)
            ]
        );

        // A genuine two-id cycle (2 -> 1 -> 2) must be rejected; the walk
        // starts from snapshot 2 in that scenario.
        let metadata_cycle = SnapshotMetadata::derived(
            SnapshotId::new(2),
            SnapshotId::new(1),
            InputId::new("input-x").unwrap(),
        );
        let mut cyclic = std::collections::HashMap::new();
        cyclic.insert(SnapshotId::new(2), SnapshotId::new(1));
        cyclic.insert(SnapshotId::new(1), SnapshotId::new(2));
        assert!(metadata_cycle
            .ancestry(|id| cyclic.get(&id).copied())
            .is_err());
    }

    #[test]
    fn snapshot_metadata_round_trips_json() {
        let metadata = SnapshotMetadata {
            snapshot_id: SnapshotId::new(2),
            campaign_id: Some(CampaignId::new("campaign-a").unwrap()),
            parent: Some(SnapshotId::new(1)),
            producing_input: Some(InputId::new("input-a").unwrap()),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert_eq!(
            json,
            "{\"snapshot_id\":2,\"campaign_id\":\"campaign-a\",\"parent\":1,\"producing_input\":\"input-a\"}"
        );
        let decoded: SnapshotMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, metadata);
    }

    #[test]
    fn snapshot_metadata_builders_preserve_ancestry() {
        let root = SnapshotMetadata::root(SnapshotId::new(1));
        assert_eq!(root.snapshot_id, SnapshotId::new(1));
        assert_eq!(root.parent, None);

        let derived = SnapshotMetadata::derived(
            SnapshotId::new(2),
            SnapshotId::new(1),
            InputId::new("input-a").unwrap(),
        );
        assert_eq!(derived.parent, Some(SnapshotId::new(1)));
        assert_eq!(
            derived.producing_input,
            Some(InputId::new("input-a").unwrap())
        );
    }
}
