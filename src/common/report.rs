use crate::common::types::Snapshot;
use crate::engine::scoring::SeverityScore;
use chrono::Utc;
use std::fs;

pub fn generate_report(snapshot: &Snapshot, vuln: Option<&str>, score: &SeverityScore, path: &str) -> anyhow::Result<()> {
    let report = format!(
        r#"{{
  "snapshot_id": {},
  "vuln": {:?},
  "severity_score": {:.2},
  "confidence": {:.2},
  "economic_impact": {:.2},
  "timestamp": "{}"
}}"#,
        snapshot.id,
        vuln,
        score.total,
        score.confidence,
        score.economic_impact,
        Utc::now()
    );
    fs::write(path, report)?;
    Ok(())
}