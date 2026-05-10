use crate::common::types::{Snapshot, ChainState, SingletonTx};
use crate::common::oracle::VulnType;
use crate::engine::scoring::{SeverityScore, ScoringEngine};
use revm::primitives::{Address, U256, keccak256};
use chrono::Utc;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageDiff {
    pub address: Address,
    pub slot: U256,
    pub before: U256,
    pub after: U256,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvidenceChain {
    pub vuln_type: String,
    pub severity_label: String,
    pub score: SeverityScore,
    pub transactions: Vec<SingletonTx>,
    pub storage_diffs: Vec<StorageDiff>,
    pub gas_estimate: u64,
    pub poc_file: String,
    pub dedupe_hash: String, // Fingerprint for automated triage
    pub timestamp: String,
}

/// Generates the full evidence chain in both JSON and Markdown formats.
pub fn generate_finding_report(
    before: &Snapshot,
    after: &Snapshot,
    vuln: &VulnType,
    score: &SeverityScore,
    scoring_engine: &ScoringEngine,
    poc_path: &str,
    output_dir: &Path,
) -> anyhow::Result<()> {
    let timestamp = Utc::now().to_rfc3339();
    let label = scoring_engine.get_label(score);
    
    // Generate a dedupe hash based on the vulnerability type and the 
    // last 5 waypoints (execution context). This ensures unique bugs are 
    // grouped together regardless of the specific input values.
    let context_data: Vec<u8> = after.waypoints.iter().rev().take(5)
        .flat_map(|w| postcard::to_allocvec(w).unwrap_or_default()).collect();
    let dedupe_hash = format!("0x{:x}", keccak256(&[format!("{:?}", vuln).as_bytes(), &context_data].concat()));

    // 1. Extract Minimal Transaction Sequence
    let txs = after.producing_input.as_ref()
        .map(|i| i.txs.clone())
        .unwrap_or_default();

    // 2. Perform Causal Storage Diffing
    let storage_diffs = calculate_storage_diff(before, after);

    let evidence = EvidenceChain {
        vuln_type: format!("{:?}", vuln),
        severity_label: label.to_string(),
        score: score.clone(),
        transactions: txs.clone(),
        storage_diffs: storage_diffs.clone(),
        gas_estimate: after.gas_used,
        poc_file: poc_path.to_string(),
        dedupe_hash,
        timestamp: timestamp.clone(),
    };

    // 3. Write Structured JSON
    let json_filename = format!("finding_{}.json", after.id);
    let json_path = output_dir.join(json_filename);
    fs::write(&json_path, serde_json::to_string_pretty(&evidence)?)?;

    // 4. Write Human-Readable Markdown
    let md_filename = format!("finding_{}.md", after.id);
    let md_path = output_dir.join(md_filename);
    let md_content = generate_markdown_report(&evidence, label);
    fs::write(md_path, md_content)?;

    log::info!("Evidence chain generated: finding_{}", after.id);
    Ok(())
}

fn calculate_storage_diff(before: &Snapshot, after: &Snapshot) -> Vec<StorageDiff> {
    let mut diffs = Vec::new();
    let state_before = before.state.read();
    let state_after = after.state.read();

    if let (ChainState::Evm(db_before), ChainState::Evm(db_after)) = (&*state_before, &*state_after) {
        for (addr, acc_after) in &db_after.cache.accounts {
            let acc_before = db_before.cache.accounts.get(addr);
            for (slot, val_after) in &acc_after.storage {
                let val_before = acc_before
                    .and_then(|a| a.storage.get(slot))
                    .cloned()
                    .unwrap_or(U256::ZERO);

                if val_after != &val_before {
                    diffs.push(StorageDiff {
                        address: *addr,
                        slot: *slot,
                        before: val_before,
                        after: *val_after,
                    });
                }
            }
        }
    }
    diffs
}

fn generate_markdown_report(evidence: &EvidenceChain, label: &str) -> String {
    let mut md = format!(
        "# RustyFuzz Finding: {}\n\n",
        evidence.vuln_type
    );

    md.push_str(&format!("## 🔴 Severity: {}\n", label));
    md.push_str(&format!("- **Score:** {:.2}/100\n", evidence.score.total as f32 / 100.0));
    md.push_str(&format!("- **Confidence:** {}%\n", evidence.score.confidence));
    md.push_str(&format!("- **Exploit Gas Cost:** {}\n", evidence.gas_estimate));
    md.push_str(&format!("- **Timestamp:** {}\n\n", evidence.timestamp));

    md.push_str("## 🛠 Reproducibility\n");
    md.push_str(&format!("- **Foundry PoC:** `{}`\n", evidence.poc_file));
    md.push_str(&format!("To verify, run: `forge test --match-path {}`\n\n", evidence.poc_file));

    md.push_str("## 📦 Minimal Call Sequence\n");
    md.push_str("| Step | Caller | Target | Value | Data |\n");
    md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
    for (i, tx) in evidence.transactions.iter().enumerate() {
        md.push_str(&format!(
            "| {} | `{}` | `{}` | {} | `{}` |\n",
            i + 1,
            tx.caller,
            tx.to,
            tx.value,
            alloy::hex::encode(&tx.input)
        ));
    }

    md.push_str("\n## 🔍 Storage Violations (State Diff)\n");
    if evidence.storage_diffs.is_empty() {
        md.push_str("No storage changes detected.\n");
    } else {
        md.push_str("| Contract | Slot | Value Before | Value After |\n");
        md.push_str("| :--- | :--- | :--- | :--- |\n");
        for diff in &evidence.storage_diffs {
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` |\n",
                diff.address,
                diff.slot,
                diff.before,
                diff.after
            ));
        }
    }

    md.push_str("\n---\n*Generated by RustyFuzz Offensive Research Platform*");
    md
}