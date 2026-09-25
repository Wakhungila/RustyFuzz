use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const OPERATIONS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationConfig {
    pub schema_version: u32,
    pub project_root: PathBuf,
    pub max_inventory_runs: usize,
    pub max_inventory_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_path_depth: usize,
    pub max_backup_files: usize,
    pub max_backup_bytes: u64,
}

impl OperationConfig {
    pub fn new(project_root: impl AsRef<Path>) -> Self {
        Self {
            schema_version: OPERATIONS_SCHEMA_VERSION,
            project_root: project_root.as_ref().to_path_buf(),
            max_inventory_runs: 4096,
            max_inventory_files: 100_000,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_path_depth: 32,
            max_backup_files: 4096,
            max_backup_bytes: 32 * 1024 * 1024,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != OPERATIONS_SCHEMA_VERSION {
            return Err("unsupported operations config schema version".to_string());
        }
        if self.max_inventory_runs == 0
            || self.max_inventory_files == 0
            || self.max_file_bytes == 0
            || self.max_total_bytes == 0
            || self.max_path_depth == 0
            || self.max_backup_files == 0
            || self.max_backup_bytes == 0
        {
            return Err("operations limits must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn artifacts_root(&self) -> PathBuf {
        self.project_root.join(".rustyfuzz")
    }

    pub fn runs_root(&self) -> PathBuf {
        self.artifacts_root().join("runs")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignState {
    Unknown,
    Queued,
    Running,
    Completed,
    Partial,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignPhase {
    Unknown,
    Discovered,
    Preparing,
    Fuzzing,
    Verifying,
    Finalizing,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignStatus {
    pub schema_version: u32,
    pub campaign_id: String,
    pub state: CampaignState,
    pub phase: CampaignPhase,
    pub updated_at_unix: u64,
    pub terminal: bool,
    pub integrity: IntegrityState,
    pub last_error: Option<String>,
}

impl CampaignStatus {
    pub fn unknown(campaign_id: impl Into<String>) -> Self {
        Self {
            schema_version: OPERATIONS_SCHEMA_VERSION,
            campaign_id: campaign_id.into(),
            state: CampaignState::Unknown,
            phase: CampaignPhase::Unknown,
            updated_at_unix: 0,
            terminal: false,
            integrity: IntegrityState::Unknown,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityState {
    Unknown,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub level: HealthLevel,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    pub schema_version: u32,
    pub level: HealthLevel,
    pub checks: Vec<HealthCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessStatus {
    pub schema_version: u32,
    pub ready: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub schema_version: u32,
    pub alert_id: String,
    pub severity: AlertSeverity,
    pub code: String,
    pub kind: String,
    pub campaign_id: Option<String>,
    pub message: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub observed_at_unix: u64,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub severity: AlertSeverity,
    pub campaign_id: String,
    pub kind: String,
    pub message: String,
    pub state: String,
    pub phase: String,
    pub terminal: bool,
    pub integrity: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub observed_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricType {
    Counter,
    Gauge,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    pub name: String,
    pub help: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Accepted,
    Running,
    Succeeded,
    Failed,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Inventory,
    Integrity,
    Backup,
    Preflight,
    Restore,
    RecoveryDrill,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub schema_version: u32,
    pub operation_id: String,
    pub kind: OperationKind,
    pub campaign_id: Option<String>,
    pub requested_at_unix: u64,
    pub state: OperationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub backup_id: String,
    pub created_at_unix: u64,
    pub campaign_ids: Vec<String>,
    pub files: Vec<BackupManifestEntry>,
    pub total_bytes: u64,
}

impl BackupManifest {
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifestEntry {
    pub path: String,
    pub size: u64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupResult {
    pub schema_version: u32,
    pub backup_id: String,
    pub path: PathBuf,
    pub file_count: usize,
    pub total_bytes: u64,
    pub manifest_digest: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFailure {
    pub code: String,
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub schema_version: u32,
    pub verified: bool,
    pub known: bool,
    pub checked_files: usize,
    pub failures: Vec<VerificationFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePreflight {
    pub schema_version: u32,
    pub backup_id: String,
    pub campaign_ids: Vec<String>,
    pub manifest_digest: String,
    pub file_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreResult {
    pub schema_version: u32,
    pub backup_id: String,
    pub published_campaigns: Vec<String>,
    pub staged_path: PathBuf,
    pub quarantine_path: Option<PathBuf>,
    pub rolled_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDrillResult {
    pub schema_version: u32,
    pub backup_id: String,
    pub target_root: PathBuf,
    pub passed: bool,
    pub restore: RestoreResult,
    pub verification: VerificationResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backup_limit_is_workstation_safe() {
        assert_eq!(OperationConfig::new(".").max_backup_bytes, 32 * 1024 * 1024);
    }
}
