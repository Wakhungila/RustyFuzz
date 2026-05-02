use crate::common::types::Snapshot;
use chrono::Utc;
use std::fs;

pub fn generate_report(snapshot: &Snapshot, vuln: Option<&str>, path: &str) -> anyhow::Result<()> {
    let report = format!(
        r#"{{
  "snapshot_id": {},
  "vuln": {:?},
  "timestamp": "{}"
}}"#,
        snapshot.id,
        vuln,
        Utc::now()
    );
    fs::write(path, report)?;
    Ok(())
}