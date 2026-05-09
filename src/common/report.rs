use crate::common::types::Snapshot;
use crate::engine::scoring::SeverityScore;
use revm::primitives::keccak256;
use chrono::Utc;
use std::fs;

pub fn generate_report(snapshot: &Snapshot, vuln: Option<&str>, score: &SeverityScore, path: &str) -> anyhow::Result<()> {
    // Production Rigor: Generate a real reproducibility hash by fingerprinting 
    // the transaction sequence and the snapshot ID.
    let repro_hash = if let Some(input) = &snapshot.producing_input {
        let encoded = serde_json::to_vec(input).unwrap_or_default();
        let hash = keccak256(&encoded);
        format!("0x{:x}", hash)
    } else {
        format!("0x{:x}", keccak256(snapshot.id.to_be_bytes()))
    };

    let report = format!(
        r#"{{
  "snapshot_id": {},
  "vuln": {:?},
  "severity_score": {:.2},
  "confidence_level": "{}%",
  "impact_ratio": {:.4},
  "reproducibility_hash": "{}",
  "timestamp": "{}"
}}"#,
        snapshot.id,
        vuln,
        score.total as f64 / 100.0,
        score.confidence,
        score.economic_impact as f64 / 100.0,
        repro_hash,
        Utc::now()
    );
    fs::write(path, report)?;
    Ok(())
}