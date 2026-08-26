//! Dependency-neutral snapshot metadata.

use crate::{CampaignId, InputId, SnapshotId};
use serde::{Deserialize, Serialize};

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
