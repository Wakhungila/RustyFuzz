use crate::error::{ensure_directory, read_bounded_regular, OperationsError};
use crate::models::{CampaignState, CampaignStatus, IntegrityState, OperationConfig};
use rustyfuzz_artifacts::layout::RunLayout;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryFile {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignInventory {
    pub campaign_id: String,
    pub root: PathBuf,
    pub files: Vec<InventoryFile>,
    pub status: CampaignStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryReport {
    pub schema_version: u32,
    pub root: PathBuf,
    pub exists: bool,
    pub campaigns: Vec<CampaignInventory>,
    pub file_count: usize,
    pub total_bytes: u64,
}

pub fn inventory(config: &OperationConfig) -> Result<InventoryReport, OperationsError> {
    config.validate().map_err(OperationsError::InvalidData)?;
    let runs_root = config.runs_root();
    let metadata = match fs::symlink_metadata(&runs_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InventoryReport {
                schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
                root: runs_root,
                exists: false,
                campaigns: Vec::new(),
                file_count: 0,
                total_bytes: 0,
            });
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(OperationsError::InvalidData(
            "runs root is not a safe directory".to_string(),
        ));
    }
    let mut campaigns = Vec::new();
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    let entries = fs::read_dir(&runs_root)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(OperationsError::InvalidData(
                "runs root contains a non-directory or symlink".to_string(),
            ));
        }
        let campaign_id = entry
            .file_name()
            .to_str()
            .ok_or_else(|| OperationsError::InvalidData("campaign id is not UTF-8".to_string()))?
            .to_string();
        rustyfuzz_artifacts::validate_run_id(&campaign_id)
            .map_err(|error| OperationsError::InvalidData(error.to_string()))?;
        if campaigns.len() >= config.max_inventory_runs {
            return Err(OperationsError::InvalidData(
                "inventory run limit exceeded".to_string(),
            ));
        }
        let files = collect_files(&path, config)?;
        total_files = total_files.checked_add(files.len()).ok_or_else(|| {
            OperationsError::InvalidData("inventory file count overflow".to_string())
        })?;
        if total_files > config.max_inventory_files {
            return Err(OperationsError::InvalidData(
                "inventory file limit exceeded".to_string(),
            ));
        }
        for file in &files {
            total_bytes = total_bytes.checked_add(file.size).ok_or_else(|| {
                OperationsError::InvalidData("inventory byte count overflow".to_string())
            })?;
            if total_bytes > config.max_total_bytes {
                return Err(OperationsError::InvalidData(
                    "inventory byte limit exceeded".to_string(),
                ));
            }
        }
        let layout = RunLayout::new(&config.artifacts_root(), &campaign_id);
        let terminal = layout
            .read_terminal_status()
            .map_err(|error| OperationsError::InvalidData(error.to_string()))?;
        let mut status = load_status(&layout, &campaign_id, config.max_file_bytes)?;
        let consistent = match terminal.as_ref().map(|status| status.state) {
            Some(rustyfuzz_artifacts::RunTerminalState::Incomplete) | None => !status.terminal,
            Some(rustyfuzz_artifacts::RunTerminalState::Completed) => {
                status.state == CampaignState::Completed
            }
            Some(rustyfuzz_artifacts::RunTerminalState::Partial) => {
                status.state == CampaignState::Partial
            }
            Some(rustyfuzz_artifacts::RunTerminalState::Cancelled) => {
                status.state == CampaignState::Cancelled
            }
            Some(rustyfuzz_artifacts::RunTerminalState::Failed) => {
                status.state == CampaignState::Failed
            }
        };
        if !consistent {
            let updated_at_unix = status.updated_at_unix;
            status = unknown_status(&campaign_id);
            status.updated_at_unix = updated_at_unix;
            status.last_error =
                Some("campaign status and canonical terminal record are contradictory".to_string());
        }
        campaigns.push(CampaignInventory {
            campaign_id,
            root: path,
            files,
            status,
        });
    }
    campaigns.sort_by(|left, right| left.campaign_id.cmp(&right.campaign_id));
    Ok(InventoryReport {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        root: runs_root,
        exists: true,
        campaigns,
        file_count: total_files,
        total_bytes,
    })
}

fn load_status(
    layout: &RunLayout,
    campaign_id: &str,
    max_file_bytes: u64,
) -> Result<CampaignStatus, OperationsError> {
    let path = layout.root().join("campaign_status.json");
    let bytes = match read_bounded_regular(&path, max_file_bytes) {
        Ok(bytes) => bytes,
        Err(OperationsError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CampaignStatus::unknown(campaign_id));
        }
        Err(error) => return Err(error),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(OperationsError::InvalidData(
            "campaign status schema is unsupported".to_string(),
        ));
    }
    let state_value = value.get("state").and_then(serde_json::Value::as_str);
    let legacy_progress = state_value.is_none()
        && value.get("phase").is_none()
        && value.get("terminal").is_none()
        && value
            .get("mode")
            .and_then(serde_json::Value::as_str)
            .is_some()
        && [
            "reserved_executions",
            "completed_executions",
            "mutated_inputs",
            "seed_replays",
            "artifacts",
            "coverage_edges",
        ]
        .iter()
        .any(|field| value.get(*field).is_some());
    if legacy_progress {
        let mut status = CampaignStatus::unknown(campaign_id);
        status.updated_at_unix = value
            .get("updated_at_unix")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        return Ok(status);
    }
    match value.get("campaign_id").and_then(serde_json::Value::as_str) {
        Some(recorded_id) if recorded_id == campaign_id => {}
        Some(_) => {
            return Err(OperationsError::InvalidData(
                "campaign status identity does not match its run".to_string(),
            ))
        }
        None => {
            return Err(OperationsError::InvalidData(
                "canonical campaign status has no campaign identity".to_string(),
            ))
        }
    }
    let state = match state_value {
        Some("completed") | Some("finalized") => CampaignState::Completed,
        Some("partial") => CampaignState::Partial,
        Some("cancelled") => CampaignState::Cancelled,
        Some("failed") => CampaignState::Failed,
        Some("running") => CampaignState::Running,
        Some("queued") => CampaignState::Queued,
        Some("unknown") => CampaignState::Unknown,
        Some(_) => {
            return Err(OperationsError::InvalidData(
                "campaign status state is invalid".to_string(),
            ))
        }
        None => {
            return Err(OperationsError::InvalidData(
                "canonical campaign status has no state".to_string(),
            ))
        }
    };
    let phase = match value.get("phase").and_then(serde_json::Value::as_str) {
        Some("discovered") => crate::models::CampaignPhase::Discovered,
        Some("preparing") => crate::models::CampaignPhase::Preparing,
        Some("fuzzing") => crate::models::CampaignPhase::Fuzzing,
        Some("verifying") => crate::models::CampaignPhase::Verifying,
        Some("finalizing") => crate::models::CampaignPhase::Finalizing,
        Some("terminal") => crate::models::CampaignPhase::Terminal,
        Some(_) => {
            return Err(OperationsError::InvalidData(
                "campaign status phase is invalid".to_string(),
            ))
        }
        None => crate::models::CampaignPhase::Unknown,
    };
    let state_terminal = matches!(
        state,
        CampaignState::Completed
            | CampaignState::Partial
            | CampaignState::Cancelled
            | CampaignState::Failed
    );
    let terminal = match value.get("terminal") {
        Some(value) => value.as_bool().ok_or_else(|| {
            OperationsError::InvalidData("campaign status terminal flag is invalid".to_string())
        })?,
        None => state_terminal,
    };
    if terminal != state_terminal || terminal != (phase == crate::models::CampaignPhase::Terminal) {
        return Err(OperationsError::InvalidData(
            "campaign status state and terminal fields are contradictory".to_string(),
        ));
    }
    Ok(CampaignStatus {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        campaign_id: campaign_id.to_string(),
        state,
        phase,
        updated_at_unix: value
            .get("updated_at_unix")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        terminal,
        integrity: IntegrityState::Unknown,
        last_error: value
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    })
}

pub(crate) fn collect_files(
    root: &Path,
    config: &OperationConfig,
) -> Result<Vec<InventoryFile>, OperationsError> {
    let mut files = Vec::new();
    collect_files_inner(root, root, 0, config, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_files_inner(
    root: &Path,
    directory: &Path,
    depth: usize,
    config: &OperationConfig,
    files: &mut Vec<InventoryFile>,
) -> Result<(), OperationsError> {
    if depth > config.max_path_depth {
        return Err(OperationsError::InvalidData(
            "artifact path depth limit exceeded".to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(OperationsError::InvalidData(
            "artifact directory is not safe".to_string(),
        ));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(OperationsError::InvalidData(
                "artifact tree contains a symlink".to_string(),
            ));
        }
        if metadata.is_dir() {
            collect_files_inner(root, &path, depth + 1, config, files)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(OperationsError::InvalidData(
                "artifact tree contains a special file".to_string(),
            ));
        }
        if files.len() >= config.max_inventory_files {
            return Err(OperationsError::InvalidData(
                "artifact file limit exceeded".to_string(),
            ));
        }
        if metadata.len() > config.max_file_bytes {
            return Err(OperationsError::InvalidData(
                "artifact file exceeds the configured size limit".to_string(),
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| {
                OperationsError::InvalidData("artifact path escaped run root".to_string())
            })?
            .to_string_lossy()
            .replace('\\', "/");
        files.push(InventoryFile {
            path: relative,
            size: metadata.len(),
        });
    }
    Ok(())
}

pub fn health(config: &OperationConfig) -> Result<crate::models::HealthStatus, OperationsError> {
    let inventory = inventory(config)?;
    let checks = vec![crate::models::HealthCheck {
        name: "artifact_inventory".to_string(),
        level: if inventory.exists {
            crate::models::HealthLevel::Healthy
        } else {
            crate::models::HealthLevel::Degraded
        },
        detail: None,
    }];
    Ok(crate::models::HealthStatus {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        level: if inventory.exists {
            crate::models::HealthLevel::Healthy
        } else {
            crate::models::HealthLevel::Degraded
        },
        checks,
    })
}

pub fn readiness(config: &OperationConfig) -> crate::models::ReadinessStatus {
    let ready = config.validate().is_ok() && config.runs_root().is_dir();
    crate::models::ReadinessStatus {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        ready,
        reason: if ready {
            None
        } else {
            Some("operations root is not ready".to_string())
        },
    }
}

pub fn ensure_runs_root(config: &OperationConfig) -> Result<PathBuf, OperationsError> {
    ensure_directory(&config.runs_root())?;
    Ok(config.runs_root())
}

pub fn status_for<'a>(
    report: &'a InventoryReport,
    campaign_id: &str,
) -> Option<&'a CampaignInventory> {
    report
        .campaigns
        .iter()
        .find(|entry| entry.campaign_id == campaign_id)
}

pub fn unknown_status(campaign_id: &str) -> CampaignStatus {
    CampaignStatus {
        integrity: IntegrityState::Unknown,
        ..CampaignStatus::unknown(campaign_id)
    }
}
