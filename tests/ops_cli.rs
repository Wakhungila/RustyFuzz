use rustyfuzz_artifacts::layout::RunLayout;
use rustyfuzz_operations::{
    CampaignPhase, CampaignState, CampaignStatus, IntegrityState, OperationConfig,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rustyfuzz-ops-cli-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn fixture(root: &Path, campaign_id: &str) {
    let config = OperationConfig::new(root);
    let layout = RunLayout::new(&config.artifacts_root(), campaign_id);
    layout.materialize().unwrap();
    let canonical = serde_json::json!({"mode": "safe"});
    let canonical_bytes = serde_json::to_vec(&canonical).unwrap();
    let mut manifest =
        rustyfuzz_artifacts::RunManifest::v1(campaign_id, "test", digest(&canonical_bytes), "safe");
    manifest.canonical_effective_config = Some(canonical);
    manifest.persist(&layout.config_file()).unwrap();
    fs::create_dir_all(layout.root().join("evidence")).unwrap();
    let evidence = b"verified";
    fs::write(layout.root().join("evidence/proof.json"), evidence).unwrap();
    let summary = serde_json::json!({
        "campaign_id": campaign_id,
        "evidence_inventory": [{"path": "evidence/proof.json", "digest": digest(evidence)}]
    });
    let summary_bytes = serde_json::to_vec(&summary).unwrap();
    fs::write(layout.root().join("campaign_summary.json"), &summary_bytes).unwrap();
    layout
        .write_terminal_status(
            campaign_id,
            rustyfuzz_artifacts::RunTerminalState::Completed,
            Some(Path::new("campaign_summary.json")),
            Some(&digest(&summary_bytes)),
        )
        .unwrap();
    fs::write(
        layout.root().join("campaign_status.json"),
        serde_json::to_vec(&CampaignStatus {
            schema_version: 1,
            campaign_id: campaign_id.to_string(),
            state: CampaignState::Completed,
            phase: CampaignPhase::Terminal,
            updated_at_unix: 1,
            terminal: true,
            integrity: IntegrityState::Verified,
            last_error: None,
        })
        .unwrap(),
    )
    .unwrap();
}

fn run_cli(root: &Path, args: &[&str], passphrase: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rusty-fuzz"));
    command.current_dir(root).args(args);
    if let Some(passphrase) = passphrase {
        command.env("RUSTYFUZZ_OPS_BACKUP_PASSPHRASE", passphrase);
    }
    command.output().unwrap()
}

#[test]
fn ops_status_json_works_without_config() {
    let root = TempRoot::new("status");
    let output = run_cli(&root.0, &["ops", "status", "--json"], None);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["readiness"]["ready"], false);
    assert_eq!(value["inventory"]["campaign_count"], 0);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("config.toml"));
}

#[test]
fn ops_alerts_and_events_match_the_derived_operations_layer() {
    let root = TempRoot::new("derived");
    fixture(&root.0, "run-1");
    let alerts = run_cli(&root.0, &["ops", "alerts", "--json"], None);
    assert!(alerts.status.success());
    let alerts: serde_json::Value = serde_json::from_slice(&alerts.stdout).unwrap();
    let events_output = run_cli(
        &root.0,
        &["ops", "events", "--json", "--run-id", "run-1"],
        None,
    );
    assert!(events_output.status.success());
    let events: serde_json::Value = serde_json::from_slice(&events_output.stdout).unwrap();
    assert_eq!(alerts["schema_version"], 1);
    assert_eq!(events["schema_version"], 1);
    assert_eq!(alerts["count"], 1);
    assert_eq!(alerts["alerts"][0]["code"], "integrity_unknown");
    assert_eq!(events["count"], 1);
    assert_eq!(events["events"][0]["campaign_id"], "run-1");
    assert!(!String::from_utf8_lossy(&events_output.stdout).contains("api_key"));
}

#[test]
fn ops_backup_round_trip_and_wrong_passphrase_fail_safely() {
    let root = TempRoot::new("backup");
    let source = root.0.join("source");
    fs::create_dir_all(&source).unwrap();
    fixture(&source, "run-1");
    let backup = source.join("backup.bin");
    let passphrase = "correct horse battery staple";
    let create = run_cli(
        &source,
        &[
            "ops",
            "backup",
            "create",
            "--output",
            backup.to_str().unwrap(),
            "--run-id",
            "run-1",
        ],
        Some(passphrase),
    );
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let verify = run_cli(
        &source,
        &["ops", "backup", "verify", backup.to_str().unwrap()],
        Some(passphrase),
    );
    assert!(verify.status.success());
    let drill_target = root.0.join("drill-target");
    let drill = run_cli(
        &source,
        &[
            "ops",
            "drill",
            "restore",
            backup.to_str().unwrap(),
            "--target",
            drill_target.to_str().unwrap(),
        ],
        Some(passphrase),
    );
    assert!(drill.status.success());
    assert!(!drill_target.exists());
    let wrong = run_cli(
        &source,
        &["ops", "backup", "verify", backup.to_str().unwrap()],
        Some("wrong passphrase value"),
    );
    assert!(!wrong.status.success());
    let wrong_text = format!(
        "{}{}",
        String::from_utf8_lossy(&wrong.stdout),
        String::from_utf8_lossy(&wrong.stderr)
    );
    assert!(!wrong_text.contains("wrong passphrase value"));
    assert!(wrong_text.contains("next safe action"));
}

#[test]
fn ops_restore_rejects_existing_campaign_before_confirmation() {
    let root = TempRoot::new("collision");
    fixture(&root.0, "run-1");
    let backup = root.0.join("backup.bin");
    let passphrase = "correct horse battery staple";
    let create = run_cli(
        &root.0,
        &[
            "ops",
            "backup",
            "create",
            "--output",
            backup.to_str().unwrap(),
        ],
        Some(passphrase),
    );
    assert!(create.status.success());
    let target_root = TempRoot::new("collision-target");
    let target = target_root.0.clone();
    fixture(&target, "run-1");
    let restore = run_cli(
        &root.0,
        &[
            "ops",
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--target",
            target.to_str().unwrap(),
        ],
        Some(passphrase),
    );
    assert!(!restore.status.success());
    let stderr = String::from_utf8_lossy(&restore.stderr);
    assert!(stderr.contains("restore target must be isolated and empty"));
    assert!(stderr.contains("next safe action"));
    let nested = run_cli(
        &root.0,
        &[
            "ops",
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--target",
            root.0.join("nested").to_str().unwrap(),
        ],
        Some(passphrase),
    );
    assert!(!nested.status.success());
    assert!(String::from_utf8_lossy(&nested.stderr)
        .contains("restore target must be isolated outside the source project"));
}
