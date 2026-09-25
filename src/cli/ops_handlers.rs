use super::commands::{OpsBackupCommand, OpsCommand, OpsDrillCommand};
use rustyfuzz_artifacts::validate_run_id;
use rustyfuzz_operations::{
    create_backup, create_backup_for_run, derive_alerts, derive_events, health, inventory,
    preflight_backup, readiness, render_prometheus, restore_backup, run_recovery_drill,
    validate_restore_target, verify_campaign, AlertSeverity, CampaignState, CampaignStatus,
    HealthStatus, MetricSample, MetricType, OperationConfig, ReadinessStatus, VerificationResult,
    OPERATIONS_SCHEMA_VERSION,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub async fn run(command: OpsCommand) -> anyhow::Result<()> {
    match command {
        OpsCommand::Status { run_id, json } => status(run_id, json),
        OpsCommand::Campaigns { state, json } => campaigns(state, json),
        OpsCommand::Metrics => metrics(),
        OpsCommand::Events {
            run_id,
            severity,
            limit,
            json,
        } => events(run_id, severity, limit, json),
        OpsCommand::Alerts { active, json } => alerts(active, json),
        OpsCommand::Verify {
            run_id,
            backup,
            json,
        } => verify(run_id, backup, json),
        OpsCommand::Backup { command } => backup(command),
        OpsCommand::Drill { command } => drill(command),
    }
}

fn fail(json_output: bool, code: &str, message: &str, next_action: &str) -> anyhow::Error {
    if json_output {
        let payload = json!({
            "schema_version": OPERATIONS_SCHEMA_VERSION,
            "error": {
                "code": code,
                "message": message,
                "next_action": next_action,
            }
        });
        let encoded = serde_json::to_string(&payload).unwrap_or_else(|_| {
            r#"{"schema_version":1,"error":{"code":"operation_failed"}}"#.to_string()
        });
        println!("{encoded}");
    } else {
        eprintln!("{message}; next safe action: {next_action}");
    }
    anyhow::anyhow!("{message}; next safe action: {next_action}")
}

fn print_json<T: Serialize>(value: &T, json_output: bool) -> anyhow::Result<()> {
    let encoded = serde_json::to_string(value).map_err(|_| {
        fail(
            json_output,
            "serialization_failed",
            "operations response could not be serialized",
            "retry with a smaller or simpler request",
        )
    })?;
    println!("{encoded}");
    Ok(())
}

fn current_config(json_output: bool) -> anyhow::Result<OperationConfig> {
    std::env::current_dir()
        .map(OperationConfig::new)
        .map_err(|_| {
            fail(
                json_output,
                "project_root_unavailable",
                "the operations project root is unavailable",
                "run the command from a readable project directory",
            )
        })
}

fn read_passphrase(json_output: bool) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if let Some(value) = std::env::var_os("RUSTYFUZZ_OPS_BACKUP_PASSPHRASE") {
        let value = value.into_string().map_err(|_| {
            fail(
                json_output,
                "passphrase_invalid",
                "the backup passphrase environment value is not valid UTF-8",
                "unset RUSTYFUZZ_OPS_BACKUP_PASSPHRASE and use a hidden prompt",
            )
        })?;
        return Ok(Zeroizing::new(value.into_bytes()));
    }
    rpassword::prompt_password("Backup passphrase: ")
        .map(|value| Zeroizing::new(value.into_bytes()))
        .map_err(|_| {
            fail(
                json_output,
                "passphrase_unavailable",
                "the backup passphrase could not be read",
                "set RUSTYFUZZ_OPS_BACKUP_PASSPHRASE or rerun with a hidden prompt",
            )
        })
}

fn validate_run(run_id: Option<&str>, json_output: bool) -> anyhow::Result<()> {
    if let Some(run_id) = run_id {
        if validate_run_id(run_id).is_err() {
            return Err(fail(
                json_output,
                "invalid_run_id",
                "the run id is invalid",
                "use a run id containing only letters, digits, '-' or '_'",
            ));
        }
    }
    Ok(())
}

fn campaign_json(status: &CampaignStatus) -> Value {
    json!({
        "campaign_id": status.campaign_id,
        "state": status.state,
        "phase": status.phase,
        "updated_at_unix": status.updated_at_unix,
        "terminal": status.terminal,
        "integrity": status.integrity,
        "last_error_present": status.last_error.is_some(),
    })
}

fn health_json(value: &HealthStatus) -> Value {
    json!({
        "schema_version": value.schema_version,
        "level": value.level,
        "checks": value.checks.iter().map(|check| json!({
            "name": check.name,
            "level": check.level,
        })).collect::<Vec<_>>(),
    })
}

fn readiness_json(value: &ReadinessStatus) -> Value {
    json!({
        "schema_version": value.schema_version,
        "ready": value.ready,
        "reason": value.reason.as_deref().is_some(),
    })
}

fn verification_json(value: &VerificationResult) -> Value {
    json!({
        "schema_version": value.schema_version,
        "verified": value.verified,
        "known": value.known,
        "checked_files": value.checked_files,
        "failures": value.failures.iter().map(|failure| json!({
            "code": failure.code,
        })).collect::<Vec<_>>(),
    })
}

fn enum_name<T: Serialize + std::fmt::Debug>(value: T) -> String {
    format!("{:?}", value).to_ascii_lowercase()
}

fn status(run_id: Option<String>, json_output: bool) -> anyhow::Result<()> {
    validate_run(run_id.as_deref(), json_output)?;
    let config = current_config(json_output)?;
    let report = inventory(&config).map_err(|_| {
        fail(
            json_output,
            "inventory_unavailable",
            "the operations inventory is unavailable",
            "repair or remove the unsafe .rustyfuzz/runs tree and retry",
        )
    })?;
    let health_value = health(&config).map_err(|_| {
        fail(
            json_output,
            "health_unavailable",
            "operations health could not be determined",
            "repair or remove the unsafe .rustyfuzz/runs tree and retry",
        )
    })?;
    let readiness_value = readiness(&config);
    let campaign = match run_id.as_deref() {
        Some(id) => {
            let Some(entry) = report
                .campaigns
                .iter()
                .find(|entry| entry.campaign_id == id)
            else {
                return Err(fail(
                    json_output,
                    "run_not_found",
                    "the requested run is not present in the operations inventory",
                    "run ops campaigns to list available run ids",
                ));
            };
            Some(campaign_json(&entry.status))
        }
        None => None,
    };
    let value = json!({
        "schema_version": OPERATIONS_SCHEMA_VERSION,
        "health": health_json(&health_value),
        "readiness": readiness_json(&readiness_value),
        "inventory": {
            "exists": report.exists,
            "campaign_count": report.campaigns.len(),
            "file_count": report.file_count,
            "total_bytes": report.total_bytes,
        },
        "run_id": run_id,
        "campaign": campaign,
    });
    if json_output {
        print_json(&value, true)
    } else {
        println!(
            "Operations status: readiness={}, health={}, campaigns={}, files={}, bytes={}",
            if readiness_value.ready {
                "ready"
            } else {
                "not_ready"
            },
            enum_name(health_value.level),
            report.campaigns.len(),
            report.file_count,
            report.total_bytes
        );
        if let Some(id) = run_id {
            println!("Run {id} is available; next safe action: run ops verify --run-id {id}");
        } else {
            println!("Next safe action: run ops campaigns to inspect discovered runs");
        }
        Ok(())
    }
}

fn campaigns(state: Option<String>, json_output: bool) -> anyhow::Result<()> {
    let config = current_config(json_output)?;
    let requested_state = state
        .as_deref()
        .map(|value| parse_state(value, json_output))
        .transpose()?;
    let report = inventory(&config).map_err(|_| {
        fail(
            json_output,
            "inventory_unavailable",
            "the operations inventory is unavailable",
            "repair or remove the unsafe .rustyfuzz/runs tree and retry",
        )
    })?;
    let values: Vec<Value> = report
        .campaigns
        .iter()
        .filter(|entry| requested_state.is_none_or(|requested| entry.status.state == requested))
        .map(|entry| campaign_json(&entry.status))
        .collect();
    let value = json!({
        "schema_version": OPERATIONS_SCHEMA_VERSION,
        "count": values.len(),
        "campaigns": values,
    });
    if json_output {
        print_json(&value, true)
    } else {
        if value["count"] == 0 {
            println!(
                "No campaigns match the requested state; next safe action: run a fuzz campaign"
            );
        } else {
            for campaign in value["campaigns"].as_array().into_iter().flatten() {
                println!(
                    "{} state={} phase={} integrity={}",
                    campaign["campaign_id"].as_str().unwrap_or("unknown"),
                    campaign["state"].as_str().unwrap_or("unknown"),
                    campaign["phase"].as_str().unwrap_or("unknown"),
                    campaign["integrity"].as_str().unwrap_or("unknown")
                );
            }
            println!("Next safe action: run ops status --run-id ID for a selected campaign");
        }
        Ok(())
    }
}

fn parse_state(value: &str, json_output: bool) -> anyhow::Result<CampaignState> {
    match value.trim().to_ascii_lowercase().as_str() {
        "unknown" => Ok(CampaignState::Unknown),
        "queued" => Ok(CampaignState::Queued),
        "running" => Ok(CampaignState::Running),
        "completed" => Ok(CampaignState::Completed),
        "partial" => Ok(CampaignState::Partial),
        "cancelled" => Ok(CampaignState::Cancelled),
        "failed" => Ok(CampaignState::Failed),
        _ => Err(fail(
            json_output,
            "invalid_state",
            "the campaign state filter is invalid",
            "use unknown, queued, running, completed, partial, cancelled, or failed",
        )),
    }
}

fn events(
    run_id: Option<String>,
    severity: Option<String>,
    limit: Option<usize>,
    json_output: bool,
) -> anyhow::Result<()> {
    validate_run(run_id.as_deref(), json_output)?;
    let requested_severity = severity
        .as_deref()
        .map(parse_severity)
        .transpose()
        .map_err(|_| {
            fail(
                json_output,
                "invalid_severity",
                "the event severity filter is invalid",
                "use info, warning, or critical",
            )
        })?;
    if limit == Some(0) {
        return Err(fail(
            json_output,
            "invalid_limit",
            "the event limit must be greater than zero",
            "pass a positive --limit or omit it",
        ));
    }
    let config = current_config(json_output)?;
    let values: Vec<_> = derive_events(&config)
        .map_err(|_| {
            fail(
                json_output,
                "inventory_unavailable",
                "the operations inventory is unavailable",
                "repair or remove the unsafe .rustyfuzz/runs tree and retry",
            )
        })?
        .into_iter()
        .filter(|event| run_id.as_deref().is_none_or(|id| event.campaign_id == id))
        .filter(|event| requested_severity.is_none_or(|value| event.severity == value))
        .take(limit.unwrap_or(usize::MAX))
        .collect();
    let value = json!({
        "schema_version": OPERATIONS_SCHEMA_VERSION,
        "count": values.len(),
        "events": values,
    });
    if json_output {
        print_json(&value, true)
    } else {
        if values.is_empty() {
            println!("No operational events match the requested filters");
        } else {
            for event in values {
                println!(
                    "{} {} {} {}",
                    event.event_id, event.campaign_id, event.kind, event.message
                );
            }
        }
        Ok(())
    }
}

fn parse_severity(value: &str) -> Result<AlertSeverity, ()> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" => Ok(AlertSeverity::Info),
        "warning" => Ok(AlertSeverity::Warning),
        "critical" => Ok(AlertSeverity::Critical),
        _ => Err(()),
    }
}

fn alerts(active: bool, json_output: bool) -> anyhow::Result<()> {
    let config = current_config(json_output)?;
    let values: Vec<_> = derive_alerts(&config)
        .map_err(|_| {
            fail(
                json_output,
                "inventory_unavailable",
                "the operations inventory is unavailable",
                "repair or remove the unsafe .rustyfuzz/runs tree and retry",
            )
        })?
        .into_iter()
        .filter(|alert| !active || alert.active)
        .collect();
    let value = json!({
        "schema_version": OPERATIONS_SCHEMA_VERSION,
        "count": values.len(),
        "alerts": values,
    });
    if json_output {
        print_json(&value, true)
    } else {
        if values.is_empty() {
            println!("No operational alerts match the requested filters");
        } else {
            for alert in values {
                println!(
                    "{} {} {} {}",
                    alert.alert_id,
                    alert.campaign_id.unwrap_or_default(),
                    alert.code,
                    alert.message
                );
            }
        }
        Ok(())
    }
}

fn verify(
    run_id: Option<String>,
    backup: Option<PathBuf>,
    json_output: bool,
) -> anyhow::Result<()> {
    if run_id.is_some() && backup.is_some() {
        return Err(fail(
            json_output,
            "conflicting_verification_target",
            "--run-id and --backup cannot be used together",
            "choose one verification target",
        ));
    }
    validate_run(run_id.as_deref(), json_output)?;
    let config = current_config(json_output)?;
    if let Some(backup_path) = backup {
        let passphrase = read_passphrase(json_output)?;
        let result =
            preflight_backup(&config, &backup_path, passphrase.as_slice()).map_err(|_| {
                fail(
                    json_output,
                    "backup_verification_failed",
                    "the backup could not be authenticated or preflighted",
                    "set the correct hidden passphrase and retry",
                )
            })?;
        let value = json!({
            "schema_version": OPERATIONS_SCHEMA_VERSION,
            "kind": "backup",
            "verified": true,
            "known": true,
            "checked_files": result.file_count,
            "backup_id": result.backup_id,
            "campaign_ids": result.campaign_ids,
            "manifest_digest": result.manifest_digest,
        });
        if json_output {
            print_json(&value, true)
        } else {
            println!(
                "Backup verified: {} campaigns, {} files",
                result.campaign_ids.len(),
                result.file_count
            );
            println!("Next safe action: restore only to an isolated empty target");
            Ok(())
        }
    } else {
        let report = inventory(&config).map_err(|_| {
            fail(
                json_output,
                "inventory_unavailable",
                "the operations inventory is unavailable",
                "repair or remove the unsafe .rustyfuzz/runs tree and retry",
            )
        })?;
        let run_ids: Vec<String> = match run_id {
            Some(id) => vec![id],
            None => report
                .campaigns
                .iter()
                .map(|entry| entry.campaign_id.clone())
                .collect(),
        };
        if run_ids.is_empty() {
            return Err(fail(
                json_output,
                "verification_incomplete",
                "no runs are available to verify",
                "run a campaign or provide --run-id",
            ));
        }
        let mut verifications = Vec::with_capacity(run_ids.len());
        for id in &run_ids {
            let result = verify_campaign(&config, id).map_err(|_| {
                fail(
                    json_output,
                    "verification_unavailable",
                    "campaign verification could not be completed",
                    "repair the campaign artifacts and retry",
                )
            })?;
            verifications.push(json!({
                "run_id": id,
                "verification": verification_json(&result),
            }));
            if !result.verified || !result.known {
                return Err(fail(
                    json_output,
                    "verification_incomplete",
                    "one or more runs are incomplete or unverified",
                    "complete the run or repair its artifacts before trusting verification",
                ));
            }
        }
        let value = json!({
            "schema_version": OPERATIONS_SCHEMA_VERSION,
            "kind": "campaigns",
            "verified": true,
            "known": true,
            "verifications": verifications,
        });
        if json_output {
            print_json(&value, true)
        } else {
            println!("Verified {} runs", run_ids.len());
            println!("Next safe action: create an encrypted backup of the verified runs");
            Ok(())
        }
    }
}

fn backup(command: OpsBackupCommand) -> anyhow::Result<()> {
    match command {
        OpsBackupCommand::Create {
            output,
            run_id,
            strict,
        } => create_backup_file(output, run_id, strict),
        OpsBackupCommand::List => list_backups(),
        OpsBackupCommand::Verify { path } => verify_backup(path),
        OpsBackupCommand::Restore { path, target } => restore(path, target),
    }
}

fn create_backup_file(output: PathBuf, run_id: Option<String>, strict: bool) -> anyhow::Result<()> {
    validate_run(run_id.as_deref(), false)?;
    let config = current_config(false)?;
    let report = inventory(&config).map_err(|_| {
        fail(
            false,
            "inventory_unavailable",
            "the operations inventory is unavailable",
            "repair or remove the unsafe .rustyfuzz/runs tree and retry",
        )
    })?;
    if let Some(id) = run_id.as_deref() {
        if !report.campaigns.iter().any(|entry| entry.campaign_id == id) {
            return Err(fail(
                false,
                "run_not_found",
                "the requested run is not present in the operations inventory",
                "run ops campaigns to list available run ids",
            ));
        }
    }
    if strict {
        let selected = report
            .campaigns
            .iter()
            .filter(|entry| run_id.as_deref().is_none_or(|id| entry.campaign_id == id));
        for entry in selected {
            let result = verify_campaign(&config, &entry.campaign_id).map_err(|_| {
                fail(
                    false,
                    "strict_verification_failed",
                    "strict backup verification could not be completed",
                    "complete or repair every run before creating a strict backup",
                )
            })?;
            if !result.verified || !result.known {
                return Err(fail(
                    false,
                    "strict_verification_incomplete",
                    "strict backup requires every run to be complete and verified",
                    "complete or repair every run before creating a strict backup",
                ));
            }
        }
    }
    let passphrase = read_passphrase(false)?;
    let backup_id = format!("backup-{}", uuid::Uuid::new_v4());
    let created_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            fail(
                false,
                "clock_unavailable",
                "the system clock is unavailable",
                "restore the system clock and retry",
            )
        })?
        .as_secs();
    let result = match run_id.as_deref() {
        Some(run_id) => create_backup_for_run(
            &config,
            &output,
            passphrase.as_slice(),
            &backup_id,
            created_at_unix,
            run_id,
        ),
        None => create_backup(
            &config,
            &output,
            passphrase.as_slice(),
            &backup_id,
            created_at_unix,
        ),
    }
    .map_err(|_| {
        fail(
            false,
            "backup_creation_failed",
            "the encrypted backup could not be created",
            "choose a new output path and verify the runs are complete",
        )
    })?;
    println!(
        "Backup created: {} files, {} bytes, manifest {}",
        result.file_count, result.total_bytes, result.manifest_digest
    );
    println!("Next safe action: verify the backup with ops backup verify PATH");
    Ok(())
}

fn list_backups() -> anyhow::Result<()> {
    let config = current_config(false)?;
    let directory = config.artifacts_root().join("backups");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("No backups found; next safe action: create one with ops backup create");
            return Ok(());
        }
        Err(_) => {
            return Err(fail(
                false,
                "backup_list_unavailable",
                "the operations backup directory is unavailable",
                "repair the .rustyfuzz/backups directory and retry",
            ));
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| {
            fail(
                false,
                "backup_list_unavailable",
                "the operations backup directory is unavailable",
                "repair the .rustyfuzz/backups directory and retry",
            )
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| {
            fail(
                false,
                "backup_list_unavailable",
                "a backup entry could not be inspected",
                "remove the unsafe backup entry and retry",
            )
        })?;
        if metadata.is_file() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    if names.is_empty() {
        println!("No backups found; next safe action: create one with ops backup create");
    } else {
        for name in names {
            println!("{name}");
        }
        println!("Next safe action: verify a listed path with ops backup verify PATH");
    }
    Ok(())
}

fn verify_backup(path: PathBuf) -> anyhow::Result<()> {
    let config = current_config(false)?;
    let passphrase = read_passphrase(false)?;
    let result = preflight_backup(&config, &path, passphrase.as_slice()).map_err(|_| {
        fail(
            false,
            "backup_verification_failed",
            "the backup could not be authenticated or preflighted",
            "set the correct hidden passphrase and retry",
        )
    })?;
    println!(
        "Backup verified: {} campaigns, {} files",
        result.campaign_ids.len(),
        result.file_count
    );
    println!("Next safe action: restore only to an isolated empty target");
    Ok(())
}

fn restore(path: PathBuf, target: PathBuf) -> anyhow::Result<()> {
    let config = current_config(false)?;
    if let Err(error) = validate_restore_target(&config, &target) {
        return Err(fail(
            false,
            "restore_target_invalid",
            &error.to_string(),
            "choose an isolated empty target outside the source project",
        ));
    }
    let passphrase = read_passphrase(false)?;
    preflight_backup(&config, &path, passphrase.as_slice()).map_err(|_| {
        fail(
            false,
            "backup_verification_failed",
            "the backup could not be authenticated or preflighted",
            "set the correct hidden passphrase and retry",
        )
    })?;
    let target_config = OperationConfig::new(&target);
    confirm_restore()?;
    let result = restore_backup(&target_config, &path, passphrase.as_slice()).map_err(|_| {
        fail(
            false,
            "restore_failed",
            "the backup could not be restored safely",
            "choose an isolated empty target and retry",
        )
    })?;
    println!(
        "Restore completed: {} campaigns",
        result.published_campaigns.len()
    );
    println!("Next safe action: run ops verify --run-id ID in the restored target");
    Ok(())
}

fn confirm_restore() -> anyhow::Result<()> {
    print!("Type RESTORE to confirm restore: ");
    io::stdout().flush().map_err(|_| {
        fail(
            false,
            "confirmation_unavailable",
            "restore confirmation could not be displayed",
            "rerun in an interactive terminal",
        )
    })?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation).map_err(|_| {
        fail(
            false,
            "confirmation_unavailable",
            "restore confirmation could not be read",
            "rerun in an interactive terminal and type RESTORE",
        )
    })?;
    if confirmation.trim() != "RESTORE" {
        return Err(fail(
            false,
            "restore_not_confirmed",
            "restore was not explicitly confirmed",
            "rerun and type RESTORE after reviewing the target",
        ));
    }
    Ok(())
}

fn drill(command: OpsDrillCommand) -> anyhow::Result<()> {
    match command {
        OpsDrillCommand::Restore {
            path,
            target,
            keep_payload,
        } => recovery_drill(path, target, keep_payload),
    }
}

fn recovery_drill(path: PathBuf, target: PathBuf, keep_payload: bool) -> anyhow::Result<()> {
    let config = current_config(false)?;
    let passphrase = read_passphrase(false)?;
    let result =
        run_recovery_drill(&config, &path, passphrase.as_slice(), &target).map_err(|_| {
            fail(
                false,
                "recovery_drill_failed",
                "the recovery drill could not be completed safely",
                "choose an isolated empty target and retry",
            )
        })?;
    if !result.passed {
        return Err(fail(
            false,
            "recovery_drill_incomplete",
            "the recovery drill did not verify every restored run",
            "inspect the target artifacts and repair the backup source",
        ));
    }
    if !keep_payload {
        fs::remove_dir_all(&target).map_err(|_| {
            fail(
                false,
                "recovery_cleanup_failed",
                "the recovery drill passed but its target could not be removed",
                "inspect the isolated target and remove it manually",
            )
        })?;
    }
    println!(
        "Recovery drill passed: {} campaigns",
        result.restore.published_campaigns.len()
    );
    println!(
        "Next safe action: inspect the isolated target{}",
        if keep_payload {
            " retained by --keep-payload"
        } else {
            " removed after verification"
        }
    );
    Ok(())
}

fn metrics() -> anyhow::Result<()> {
    let config = current_config(false)?;
    let report = inventory(&config).map_err(|_| {
        fail(
            false,
            "inventory_unavailable",
            "the operations inventory is unavailable",
            "repair or remove the unsafe .rustyfuzz/runs tree and retry",
        )
    })?;
    let samples = vec![
        MetricSample {
            name: "rustyfuzz_service_up".to_string(),
            help: "Whether the local operations inventory could be read".to_string(),
            metric_type: MetricType::Gauge,
            value: 1.0,
            labels: BTreeMap::new(),
        },
        MetricSample {
            name: "rustyfuzz_campaigns".to_string(),
            help: "Number of discovered campaign runs".to_string(),
            metric_type: MetricType::Gauge,
            value: report.campaigns.len() as f64,
            labels: BTreeMap::new(),
        },
        MetricSample {
            name: "rustyfuzz_inventory_files".to_string(),
            help: "Number of files in the bounded operations inventory".to_string(),
            metric_type: MetricType::Gauge,
            value: report.file_count as f64,
            labels: BTreeMap::new(),
        },
        MetricSample {
            name: "rustyfuzz_inventory_bytes".to_string(),
            help: "Bytes in the bounded operations inventory".to_string(),
            metric_type: MetricType::Gauge,
            value: report.total_bytes as f64,
            labels: BTreeMap::new(),
        },
    ];
    let rendered = render_prometheus(&samples).map_err(|_| {
        fail(
            false,
            "metrics_unavailable",
            "the operations metrics could not be rendered",
            "retry after the local inventory is readable",
        )
    })?;
    print!("{rendered}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestArgs {
        #[command(subcommand)]
        command: OpsCommand,
    }

    #[test]
    fn parses_explicit_ops_surface() {
        let args = TestArgs::try_parse_from([
            "test",
            "backup",
            "create",
            "--output",
            "backup.bin",
            "--run-id",
            "run-1",
            "--strict",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            OpsCommand::Backup {
                command: OpsBackupCommand::Create { strict: true, .. }
            }
        ));
        assert!(TestArgs::try_parse_from(["test", "metrics"]).is_ok());
        assert!(TestArgs::try_parse_from([
            "test",
            "backup",
            "restore",
            "backup.bin",
            "--target",
            "target"
        ])
        .is_ok());
    }
}
