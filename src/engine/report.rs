use crate::common::types::Snapshot;
use chrono::Utc;

pub struct VulnerabilityReport {
    pub timestamp: String,
    pub snapshot_id: u64,
    pub description: String,
}

impl VulnerabilityReport {
    pub fn new(snapshot: &Snapshot, description: String) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            snapshot_id: snapshot.id,
            description,
        }
    }
}