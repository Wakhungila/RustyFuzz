use rustyfuzz_artifacts::layout::RunLayout;
use rustyfuzz_operations::{
    create_backup, derive_alerts_at, derive_events_from_report, health, inventory,
    preflight_backup, publish_staged_restore, render_prometheus, restore_backup,
    run_recovery_drill, stage_backup, verify_campaign, BackupResult, CampaignState, CampaignStatus,
    IntegrityState, MetricSample, MetricType, OperationConfig, OperationsError,
};
use serde_json::json;
use sha2::Digest;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const PASSPHRASE: &[u8] = b"correct horse battery staple";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

fn fixture(root: &Path, campaign_id: &str) -> OperationConfig {
    let config = OperationConfig::new(root);
    let layout = RunLayout::new(&config.artifacts_root(), campaign_id);
    layout.materialize().unwrap();
    let canonical_config = json!({"mode": "safe"});
    let canonical_bytes = serde_json::to_vec(&canonical_config).unwrap();
    let mut manifest =
        rustyfuzz_artifacts::RunManifest::v1(campaign_id, "test", digest(&canonical_bytes), "safe");
    manifest.canonical_effective_config = Some(canonical_config);
    manifest.persist(&layout.config_file()).unwrap();
    let evidence = b"{\"verified\":true}";
    fs::create_dir_all(layout.root().join("evidence")).unwrap();
    fs::write(layout.root().join("evidence").join("proof.json"), evidence).unwrap();
    let summary = json!({
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
            phase: rustyfuzz_operations::CampaignPhase::Terminal,
            updated_at_unix: 1,
            terminal: true,
            integrity: IntegrityState::Verified,
            last_error: None,
        })
        .unwrap(),
    )
    .unwrap();
    config
}

fn backup(root: &Path, config: &OperationConfig, name: &str) -> BackupResult {
    create_backup(config, &root.join(name), PASSPHRASE, "backup-1", 7).unwrap()
}

#[test]
fn inventory_and_integrity_report_canonical_runs() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let report = inventory(&config).unwrap();
    assert!(report.exists);
    assert_eq!(report.campaigns.len(), 1);
    assert_eq!(report.campaigns[0].campaign_id, "campaign-1");
    let verification = verify_campaign(&config, "campaign-1").unwrap();
    assert!(verification.verified, "{verification:?}");
    assert!(verification.known);
    assert_eq!(
        health(&config).unwrap().level,
        rustyfuzz_operations::HealthLevel::Healthy
    );
}

#[test]
fn inventory_rejects_symlink_and_special_files() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let outside = temp.path().join("outside");
    fs::write(&outside, b"secret").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, config.runs_root().join("campaign-1").join("link"))
            .unwrap();
        assert!(matches!(
            inventory(&config),
            Err(OperationsError::InvalidData(_))
        ));
        fs::remove_file(config.runs_root().join("campaign-1").join("link")).unwrap();
        let fifo = config.runs_root().join("campaign-1").join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(matches!(
            inventory(&config),
            Err(OperationsError::InvalidData(_))
        ));
    }
}

#[test]
fn inventory_does_not_trust_status_integrity_and_validates_canonical_state() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let status_path = config.runs_root().join("campaign-1/campaign_status.json");
    assert_eq!(
        inventory(&config).unwrap().campaigns[0].status.integrity,
        IntegrityState::Unknown
    );
    fs::write(
        &status_path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "mode": "fuzzing",
            "reserved_executions": 10,
            "completed_executions": 2,
            "updated_at_unix": 9
        }))
        .unwrap(),
    )
    .unwrap();
    let legacy = inventory(&config).unwrap().campaigns[0].status.clone();
    assert_eq!(legacy.state, CampaignState::Unknown);
    assert_eq!(legacy.phase, rustyfuzz_operations::CampaignPhase::Unknown);
    assert_eq!(legacy.updated_at_unix, 9);
    for value in [
        serde_json::json!({
            "schema_version": 1,
            "campaign_id": "campaign-1",
            "state": "running",
            "phase": "fuzzing",
            "terminal": true
        }),
        serde_json::json!({
            "schema_version": 1,
            "state": "completed",
            "phase": "terminal",
            "terminal": true
        }),
    ] {
        fs::write(&status_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            inventory(&config),
            Err(OperationsError::InvalidData(_))
        ));
    }
}

#[test]
fn inventory_downgrades_terminal_campaign_status_when_canonical_state_is_incomplete() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let layout = RunLayout::new(&config.artifacts_root(), "campaign-1");
    fs::write(
        layout.terminal_status_path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "terminal": false,
            "state": "incomplete",
            "run_id": "campaign-1"
        }))
        .unwrap(),
    )
    .unwrap();

    let status = inventory(&config).unwrap().campaigns[0].status.clone();
    assert_eq!(status.state, CampaignState::Unknown);
    assert_eq!(status.phase, rustyfuzz_operations::CampaignPhase::Unknown);
    assert!(!status.terminal);
}

#[test]
fn inventory_downgrades_terminal_campaign_state_when_canonical_state_differs() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let layout = RunLayout::new(&config.artifacts_root(), "campaign-1");
    fs::write(
        layout.root().join("campaign_status.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "campaign_id": "campaign-1",
            "state": "failed",
            "phase": "terminal",
            "terminal": true,
            "updated_at_unix": 2
        }))
        .unwrap(),
    )
    .unwrap();

    let status = inventory(&config).unwrap().campaigns[0].status.clone();
    assert_eq!(status.state, CampaignState::Unknown);
    assert_eq!(status.updated_at_unix, 2);
}

#[test]
fn integrity_fails_closed_for_missing_and_tampered_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let layout = RunLayout::new(&config.artifacts_root(), "campaign-1");
    fs::remove_file(layout.root().join("campaign_summary.json")).unwrap();
    let missing = verify_campaign(&config, "campaign-1").unwrap();
    assert!(!missing.verified);
    assert!(!missing.known);
    assert!(missing
        .failures
        .iter()
        .any(|failure| failure.code == "summary_unavailable"));

    let config = fixture(&temp.path().join("second"), "campaign-2");
    let layout = RunLayout::new(&config.artifacts_root(), "campaign-2");
    let summary = layout.root().join("campaign_summary.json");
    let mut bytes = fs::read(&summary).unwrap();
    bytes[0] = b' ';
    fs::write(&summary, bytes).unwrap();
    let tampered = verify_campaign(&config, "campaign-2").unwrap();
    assert!(!tampered.verified);
    assert!(tampered.known);
}

#[test]
fn derived_alerts_cover_integrity_terminal_and_stale_states_without_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let config = OperationConfig::new(temp.path());
    let campaigns = vec![
        rustyfuzz_operations::inventory::CampaignInventory {
            campaign_id: "failed".to_string(),
            root: temp.path().join("failed"),
            files: Vec::new(),
            status: CampaignStatus {
                schema_version: 1,
                campaign_id: "failed".to_string(),
                state: CampaignState::Failed,
                phase: rustyfuzz_operations::CampaignPhase::Terminal,
                updated_at_unix: 1,
                terminal: true,
                integrity: IntegrityState::Failed,
                last_error: Some("token=super-secret".to_string()),
            },
        },
        rustyfuzz_operations::inventory::CampaignInventory {
            campaign_id: "stalled".to_string(),
            root: temp.path().join("stalled"),
            files: Vec::new(),
            status: CampaignStatus {
                schema_version: 1,
                campaign_id: "stalled".to_string(),
                state: CampaignState::Running,
                phase: rustyfuzz_operations::CampaignPhase::Fuzzing,
                updated_at_unix: 1,
                terminal: false,
                integrity: IntegrityState::Unknown,
                last_error: Some("password=super-secret".to_string()),
            },
        },
    ];
    let report = rustyfuzz_operations::inventory::InventoryReport {
        schema_version: 1,
        root: config.runs_root(),
        exists: true,
        campaigns,
        file_count: 0,
        total_bytes: 0,
    };
    let alerts = derive_alerts_at(&report, 1_000);
    let codes: Vec<_> = alerts.iter().map(|alert| alert.code.as_str()).collect();
    assert!(codes.contains(&"integrity_failed"));
    assert!(codes.contains(&"integrity_unknown"));
    assert!(codes.contains(&"terminal_failed"));
    assert!(codes.contains(&"campaign_stale"));
    let serialized = serde_json::to_string(&alerts).unwrap();
    assert!(!serialized.contains("super-secret"));
    assert!(!serialized.contains("password"));
}

#[test]
fn events_are_snapshot_derived_deduplicated_and_sanitized() {
    let report = rustyfuzz_operations::inventory::InventoryReport {
        schema_version: 1,
        root: std::path::PathBuf::from("/tmp/runs"),
        exists: true,
        campaigns: vec![rustyfuzz_operations::inventory::CampaignInventory {
            campaign_id: "campaign-1".to_string(),
            root: std::path::PathBuf::from("/tmp/runs/campaign-1"),
            files: Vec::new(),
            status: CampaignStatus {
                schema_version: 1,
                campaign_id: "campaign-1".to_string(),
                state: CampaignState::Running,
                phase: rustyfuzz_operations::CampaignPhase::Fuzzing,
                updated_at_unix: 7,
                terminal: false,
                integrity: IntegrityState::Verified,
                last_error: Some("api_key=do-not-expose".to_string()),
            },
        }],
        file_count: 0,
        total_bytes: 0,
    };
    let first = derive_events_from_report(&report);
    let second = derive_events_from_report(&report);
    assert_eq!(first, second);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].kind, "campaign_status_snapshot");
    assert!(!serde_json::to_string(&first)
        .unwrap()
        .contains("do-not-expose"));
}

#[test]
fn canonical_summary_reference_is_verified_relative_to_run_root() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "canonical");
    let layout = RunLayout::new(&config.artifacts_root(), "canonical");
    let summary = fs::read(layout.root().join("campaign_summary.json")).unwrap();
    fs::write(layout.reports_dir().join("campaign_summary.json"), &summary).unwrap();
    fs::remove_file(layout.root().join("campaign_summary.json")).unwrap();
    fs::write(
        layout.terminal_status_path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "terminal": true,
            "state": "completed",
            "run_id": "canonical",
            "final_summary_path": "reports/campaign_summary.json",
            "final_summary_digest": digest(&summary),
        }))
        .unwrap(),
    )
    .unwrap();
    let result = verify_campaign(&config, "canonical").unwrap();
    assert!(result.verified, "{result:?}");
    let terminal: serde_json::Value =
        serde_json::from_slice(&fs::read(layout.terminal_status_path()).unwrap()).unwrap();
    assert_eq!(
        terminal["final_summary_path"],
        "reports/campaign_summary.json"
    );
}

#[test]
fn canonical_integrity_requires_a_safe_deduplicated_digested_evidence_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let cases = [
        (
            "missing",
            serde_json::json!({"campaign_id": "case"}),
            "evidence_unknown",
        ),
        (
            "duplicate",
            serde_json::json!({
                "campaign_id": "case",
                "evidence_inventory": [
                    {"path": "evidence/proof.json", "digest": digest(b"{\"verified\":true}")},
                    {"path": "evidence/proof.json", "digest": digest(b"{\"verified\":true}")}
                ]
            }),
            "evidence_path_duplicate",
        ),
        (
            "digest",
            serde_json::json!({
                "campaign_id": "case",
                "evidence_inventory": [{
                    "path": "evidence/proof.json",
                    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                }]
            }),
            "evidence_digest_mismatch",
        ),
    ];
    for (name, mut summary, code) in cases {
        let root = temp.path().join(name);
        let config = fixture(&root, "case");
        let layout = RunLayout::new(&config.artifacts_root(), "case");
        summary["campaign_id"] = serde_json::Value::String("case".to_string());
        let bytes = serde_json::to_vec(&summary).unwrap();
        fs::write(layout.root().join("campaign_summary.json"), &bytes).unwrap();
        fs::write(
            layout.terminal_status_path(),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "terminal": true,
                "state": "failed",
                "run_id": "case",
                "final_summary_path": "campaign_summary.json",
                "final_summary_digest": digest(&bytes),
            }))
            .unwrap(),
        )
        .unwrap();
        let result = verify_campaign(&config, "case").unwrap();
        assert!(!result.verified, "{name}: {result:?}");
        assert!(result.failures.iter().any(|failure| failure.code == code));
    }
}

#[test]
fn canonical_integrity_rejects_missing_digests_unlisted_files_and_empty_inventory() {
    let temp = tempfile::tempdir().unwrap();

    let missing_digest_root = temp.path().join("missing-digest");
    let missing_digest_config = fixture(&missing_digest_root, "case");
    let missing_digest_layout = RunLayout::new(&missing_digest_config.artifacts_root(), "case");
    let summary = serde_json::json!({
        "campaign_id": "case",
        "evidence_inventory": ["evidence/proof.json"]
    });
    let summary_bytes = serde_json::to_vec(&summary).unwrap();
    fs::write(
        missing_digest_layout.root().join("campaign_summary.json"),
        &summary_bytes,
    )
    .unwrap();
    fs::write(
        missing_digest_layout.terminal_status_path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "terminal": true,
            "state": "completed",
            "run_id": "case",
            "final_summary_path": "campaign_summary.json",
            "final_summary_digest": digest(&summary_bytes),
        }))
        .unwrap(),
    )
    .unwrap();
    let missing_digest = verify_campaign(&missing_digest_config, "case").unwrap();
    assert!(!missing_digest.verified);
    assert!(missing_digest
        .failures
        .iter()
        .any(|failure| failure.code == "evidence_digest_missing"));

    let unlisted_root = temp.path().join("unlisted");
    let unlisted_config = fixture(&unlisted_root, "case");
    let unlisted_layout = RunLayout::new(&unlisted_config.artifacts_root(), "case");
    fs::write(unlisted_layout.root().join("unlisted.bin"), b"tampered").unwrap();
    let unlisted = verify_campaign(&unlisted_config, "case").unwrap();
    assert!(!unlisted.verified);
    assert!(unlisted
        .failures
        .iter()
        .any(|failure| failure.code == "evidence_unlisted"));

    let empty_root = temp.path().join("empty");
    let empty_config = fixture(&empty_root, "case");
    let empty_layout = RunLayout::new(&empty_config.artifacts_root(), "case");
    fs::remove_file(empty_layout.root().join("evidence/proof.json")).unwrap();
    let summary = serde_json::json!({
        "campaign_id": "case",
        "evidence_inventory": []
    });
    let summary_bytes = serde_json::to_vec(&summary).unwrap();
    fs::write(
        empty_layout.root().join("campaign_summary.json"),
        &summary_bytes,
    )
    .unwrap();
    fs::write(
        empty_layout.terminal_status_path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "terminal": true,
            "state": "completed",
            "run_id": "case",
            "final_summary_path": "campaign_summary.json",
            "final_summary_digest": digest(&summary_bytes),
        }))
        .unwrap(),
    )
    .unwrap();
    let empty = verify_campaign(&empty_config, "case").unwrap();
    assert!(!empty.verified);
    assert!(empty
        .failures
        .iter()
        .any(|failure| failure.code == "evidence_empty"));
}

#[test]
fn integrity_diagnostics_reference_config_json() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let layout = RunLayout::new(&config.artifacts_root(), "campaign-1");
    fs::remove_file(layout.config_file()).unwrap();
    let result = verify_campaign(&config, "campaign-1").unwrap();
    assert!(result.failures.iter().any(|failure| {
        failure.code == "manifest_unavailable"
            && failure
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("config.json"))
    }));
}

#[test]
fn prometheus_rendering_is_deterministic_and_escaped() {
    let labels = BTreeMap::from([
        ("state".to_string(), "a\\b\"\n".to_string()),
        ("campaign".to_string(), "one".to_string()),
    ]);
    let samples = vec![
        MetricSample {
            name: "rustyfuzz_campaign_total".to_string(),
            help: "campaign\\count\n".to_string(),
            metric_type: MetricType::Counter,
            value: 2.0,
            labels: labels.clone(),
        },
        MetricSample {
            name: "rustyfuzz_campaign_total".to_string(),
            help: "campaign\\count\n".to_string(),
            metric_type: MetricType::Counter,
            value: 3.0,
            labels: BTreeMap::new(),
        },
    ];
    let first = render_prometheus(&samples).unwrap();
    let second = render_prometheus(&samples).unwrap();
    assert_eq!(first, second);
    assert!(first.contains("# HELP rustyfuzz_campaign_total campaign\\\\count\\n"));
    assert!(first.contains("# TYPE rustyfuzz_campaign_total counter"));
    assert!(first.contains("campaign=\"one\",state=\"a\\\\b\\\"\\n\""));
    assert!(first.contains("} 2\n"));
}

#[test]
fn backup_is_authenticated_and_rejects_wrong_passphrase_and_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let result = backup(temp.path(), &config, "backup.bin");
    let preflight = preflight_backup(&config, &result.path, PASSPHRASE).unwrap();
    assert_eq!(preflight.campaign_ids, vec!["campaign-1"]);
    assert!(preflight.file_count > 0);
    assert!(preflight_backup(&config, &result.path, b"wrong passphrase").is_err());
    let mut bytes = fs::read(&result.path).unwrap();
    let index = bytes.len() - 1;
    bytes[index] ^= 1;
    fs::write(&result.path, bytes).unwrap();
    assert!(preflight_backup(&config, &result.path, PASSPHRASE).is_err());
}

#[test]
fn backup_rejects_destinations_inside_canonical_runs_tree() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let layout = RunLayout::new(&config.artifacts_root(), "campaign-1");
    let _campaign_owner = layout.acquire_campaign_lock().unwrap();
    for destination in [
        config.runs_root().join("backup.bin"),
        layout.root().join("backup.bin"),
        config
            .runs_root()
            .join("campaign-1/../campaign-1/nested-backup.bin"),
    ] {
        assert!(create_backup(&config, &destination, PASSPHRASE, "backup-inside", 1).is_err());
        assert!(!destination.exists());
    }
    let sibling = config
        .artifacts_root()
        .join("runs-archive/nested/backup.bin");
    create_backup(&config, &sibling, PASSPHRASE, "backup-sibling", 2).unwrap();
    assert!(sibling.is_file());
    assert!(inventory(&config).is_ok());
}

#[cfg(unix)]
#[test]
fn backup_rejects_symlinked_destination_parent_into_runs_tree() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let alias = temp.path().join("runs-alias");
    std::os::unix::fs::symlink(config.runs_root(), &alias).unwrap();
    let destination = alias.join("campaign-1/backup.bin");
    assert!(create_backup(&config, &destination, PASSPHRASE, "backup-alias", 1).is_err());
    assert!(!destination.exists());
}

#[test]
fn backup_rejects_unsafe_argon2_header_before_decryption() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let result = backup(temp.path(), &config, "backup.bin");
    let original = fs::read(&result.path).unwrap();
    for (offset, value) in [(10, 64_u32 * 1024 + 1), (14, 4), (18, 3)] {
        let mut bytes = original.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        fs::write(&result.path, bytes).unwrap();
        assert!(preflight_backup(&config, &result.path, PASSPHRASE).is_err());
    }
}

#[test]
fn backup_rejects_symlink_collection_and_restore_does_not_reuse_campaigns() {
    let temp = tempfile::tempdir().unwrap();
    let config = fixture(temp.path(), "campaign-1");
    let layout = RunLayout::new(&config.artifacts_root(), "campaign-1");
    let outside = temp.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, layout.root().join("link")).unwrap();
        assert!(
            create_backup(&config, &temp.path().join("bad.bin"), PASSPHRASE, "bad", 1).is_err()
        );
        fs::remove_file(layout.root().join("link")).unwrap();
    }
    let result = backup(temp.path(), &config, "backup.bin");
    let target = temp.path().join("target");
    fs::create_dir_all(&target).unwrap();
    let restored =
        restore_backup(&OperationConfig::new(&target), &result.path, PASSPHRASE).unwrap();
    assert_eq!(restored.published_campaigns, vec!["campaign-1"]);
    let target_config = OperationConfig::new(&target);
    assert!(
        verify_campaign(&target_config, "campaign-1")
            .unwrap()
            .verified
    );
    let failed = restore_backup(&target_config, &result.path, PASSPHRASE).unwrap_err();
    assert!(failed.quarantine_path.is_none());
    assert!(target_config.runs_root().join("campaign-1").is_dir());
}

#[cfg(unix)]
#[test]
fn restore_rejects_symlinked_target() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture(&temp.path().join("source"), "campaign-1");
    let result = backup(temp.path(), &source, "backup.bin");
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let target = temp.path().join("target-link");
    std::os::unix::fs::symlink(&outside, &target).unwrap();
    assert!(restore_backup(&OperationConfig::new(&target), &result.path, PASSPHRASE).is_err());
    assert!(!outside.join(".rustyfuzz/runs").exists());
}

#[test]
fn multi_campaign_restore_stages_all_runs_before_one_publication() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("source");
    let source = fixture(&source_root, "campaign-1");
    fixture(&source_root, "campaign-2");
    let result = create_backup(
        &source,
        &temp.path().join("two.bin"),
        PASSPHRASE,
        "backup-2",
        7,
    )
    .unwrap();
    let target = temp.path().join("atomic-target");
    let target_config = OperationConfig::new(&target);
    let staging_parent = target_config.artifacts_root().join("restore-staging");
    let staged = stage_backup(&source, &result.path, PASSPHRASE, &staging_parent).unwrap();
    assert!(!target_config.runs_root().exists());
    assert!(staged.staging_root.join("runs/campaign-1").is_dir());
    assert!(staged.staging_root.join("runs/campaign-2").is_dir());
    let restored = publish_staged_restore(&target_config, staged).unwrap();
    assert_eq!(
        restored.published_campaigns,
        vec!["campaign-1", "campaign-2"]
    );
    assert!(
        verify_campaign(&target_config, "campaign-1")
            .unwrap()
            .verified
    );
    assert!(
        verify_campaign(&target_config, "campaign-2")
            .unwrap()
            .verified
    );
}

#[test]
fn path_traversal_and_recovery_drill_are_guarded() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("source");
    let config = fixture(&source_root, "campaign-1");
    assert!(rustyfuzz_operations::error::safe_relative_path("../escape").is_err());
    let result = backup(temp.path(), &config, "backup.bin");
    let target = temp.path().join("recovery-target");
    let drill = run_recovery_drill(&config, &result.path, PASSPHRASE, &target).unwrap();
    assert!(drill.passed);
    assert!(drill.verification.verified);
    assert!(drill.target_root.is_dir());
    let occupied = temp.path().join("occupied");
    fs::create_dir_all(&occupied).unwrap();
    fs::write(occupied.join("file"), b"x").unwrap();
    assert!(run_recovery_drill(&config, &result.path, PASSPHRASE, &occupied).is_err());
}
