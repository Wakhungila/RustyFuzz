use crate::backup::decode_backup;
use crate::error::{
    ensure_directory, reject_symlink_components, safe_relative_path, sha256_digest, OperationsError,
};
use crate::integrity::verify_run_root;
use crate::models::{OperationConfig, RestorePreflight, RestoreResult, VerificationResult};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct StagedRestore {
    pub preflight: RestorePreflight,
    pub staging_root: PathBuf,
    pub verification: VerificationResult,
}

#[derive(Debug)]
pub struct RestoreFailure {
    pub error: OperationsError,
    pub quarantine_path: Option<PathBuf>,
}

impl Display for RestoreFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.error)
    }
}

impl std::error::Error for RestoreFailure {}

impl From<OperationsError> for RestoreFailure {
    fn from(error: OperationsError) -> Self {
        Self {
            error,
            quarantine_path: None,
        }
    }
}

pub fn preflight_backup(
    config: &OperationConfig,
    backup_path: &Path,
    passphrase: &[u8],
) -> Result<RestorePreflight, OperationsError> {
    config.validate().map_err(OperationsError::InvalidData)?;
    let envelope = decode_backup(config, backup_path, passphrase)?;
    Ok(RestorePreflight {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        backup_id: envelope.manifest.backup_id.clone(),
        campaign_ids: envelope.manifest.campaign_ids.clone(),
        manifest_digest: envelope.manifest.digest(),
        file_count: envelope.files.len(),
        total_bytes: envelope.manifest.total_bytes,
    })
}

pub fn stage_backup(
    config: &OperationConfig,
    backup_path: &Path,
    passphrase: &[u8],
    staging_parent: &Path,
) -> Result<StagedRestore, RestoreFailure> {
    let preflight = preflight_backup(config, backup_path, passphrase)?;
    let envelope = decode_backup(config, backup_path, passphrase).map_err(RestoreFailure::from)?;
    if let Err(error) = ensure_directory(staging_parent) {
        return Err(RestoreFailure::from(error));
    }
    let staging_root = unique_child(staging_parent, "restore")?;
    if let Err(error) = fs::create_dir(&staging_root) {
        return Err(RestoreFailure::from(OperationsError::from(error)));
    }
    let staged_runs = staging_root.join("runs");
    if let Err(error) = ensure_directory(&staged_runs) {
        return Err(quarantine(staging_root, error));
    }
    for file in &envelope.files {
        let relative = match safe_relative_path(&file.path) {
            Ok(path) => path,
            Err(error) => return Err(quarantine(staging_root, error)),
        };
        let bytes = match BASE64.decode(&file.data) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(quarantine(
                    staging_root,
                    OperationsError::InvalidData("backup file encoding is invalid".to_string()),
                ))
            }
        };
        let entry = envelope
            .manifest
            .files
            .iter()
            .find(|entry| entry.path == file.path)
            .ok_or_else(|| {
                OperationsError::InvalidData("backup manifest entry is missing".to_string())
            });
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return Err(quarantine(staging_root, error)),
        };
        if bytes.len() as u64 != entry.size || sha256_digest(&bytes) != entry.digest {
            return Err(quarantine(
                staging_root,
                OperationsError::InvalidData("staged backup digest mismatch".to_string()),
            ));
        }
        let destination = staged_runs.join(relative);
        if let Some(parent) = destination.parent() {
            if let Err(error) = ensure_directory(parent) {
                return Err(quarantine(staging_root, error));
            }
        }
        if let Err(error) = rustyfuzz_artifacts::fsutil::write_atomic(&destination, bytes) {
            let error = match error {
                rustyfuzz_artifacts::FsUtilError::Io(error) => OperationsError::Io(error),
                rustyfuzz_artifacts::FsUtilError::Serialize(error) => OperationsError::Json(error),
                rustyfuzz_artifacts::FsUtilError::InvalidData(detail) => {
                    OperationsError::InvalidData(detail)
                }
            };
            return Err(quarantine(staging_root, error));
        }
    }
    let mut verification = VerificationResult {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        verified: true,
        known: true,
        checked_files: 0,
        failures: Vec::new(),
    };
    for campaign_id in &preflight.campaign_ids {
        let result = verify_run_root(&staged_runs, campaign_id, config.max_file_bytes)?;
        verification.checked_files += result.checked_files;
        if !result.verified {
            verification.verified = false;
            verification.known &= result.known;
            verification.failures.extend(result.failures);
        }
    }
    if !verification.verified {
        return Err(quarantine(
            staging_root,
            OperationsError::Verification("staged artifacts are not fully verified".to_string()),
        ));
    }
    Ok(StagedRestore {
        preflight,
        staging_root,
        verification,
    })
}

pub fn publish_staged_restore(
    config: &OperationConfig,
    staged: StagedRestore,
) -> Result<RestoreResult, RestoreFailure> {
    if !staged.verification.verified || !staged.verification.known {
        return Err(quarantine(
            staged.staging_root,
            OperationsError::Verification("staged artifacts are not fully known".to_string()),
        ));
    }
    let artifacts_root = config.artifacts_root();
    let runs_root = config.runs_root();
    if let Err(error) = ensure_directory(&artifacts_root) {
        return Err(quarantine(staged.staging_root, error));
    }
    match fs::symlink_metadata(&runs_root) {
        Ok(_) => {
            return Err(quarantine(
                staged.staging_root,
                OperationsError::Conflict("restore runs target already exists".to_string()),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(quarantine(staged.staging_root, error.into())),
    }
    let lock_path = artifacts_root.join("operations.lock");
    let _lock = match crate::error::lock_file(&lock_path) {
        Ok(lock) => lock,
        Err(error) => return Err(RestoreFailure::from(error)),
    };
    if let Err(error) = reject_symlink_components(&runs_root) {
        return Err(quarantine(staged.staging_root, error));
    }
    let staged_runs = staged.staging_root.join("runs");
    if let Err(error) = fs::rename(&staged_runs, &runs_root) {
        return Err(quarantine(staged.staging_root, error.into()));
    }
    let published = staged.preflight.campaign_ids.clone();
    let _ = fs::remove_dir_all(&staged.staging_root);
    Ok(RestoreResult {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        backup_id: staged.preflight.backup_id,
        published_campaigns: published,
        staged_path: staged.staging_root,
        quarantine_path: None,
        rolled_back: false,
    })
}

pub fn restore_backup(
    config: &OperationConfig,
    backup_path: &Path,
    passphrase: &[u8],
) -> Result<RestoreResult, RestoreFailure> {
    validate_isolated_target(&config.project_root)?;
    let staging_parent = config.artifacts_root().join("restore-staging");
    let staged = stage_backup(config, backup_path, passphrase, &staging_parent)?;
    publish_staged_restore(config, staged)
}

pub fn validate_restore_target(
    source_config: &OperationConfig,
    target_root: &Path,
) -> Result<(), OperationsError> {
    source_config
        .validate()
        .map_err(OperationsError::InvalidData)?;
    let source_root = fs::canonicalize(&source_config.project_root)?;
    let resolved = resolved_target_path(target_root)?;
    if resolved == source_root || resolved.starts_with(&source_root) {
        return Err(OperationsError::Conflict(
            "restore target must be isolated outside the source project".to_string(),
        ));
    }
    validate_isolated_target(target_root)
}

fn validate_isolated_target(target_root: &Path) -> Result<(), OperationsError> {
    resolved_target_path(target_root)?;
    Ok(())
}

fn resolved_target_path(target_root: &Path) -> Result<PathBuf, OperationsError> {
    let target_root = absolute_target_path(target_root)?;
    reject_symlink_components(&target_root)?;
    let mut existing = target_root.clone();
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(&existing) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(OperationsError::InvalidData(
                        "restore target is not a safe directory".to_string(),
                    ));
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or_else(|| {
                    OperationsError::InvalidData("restore target has no usable path".to_string())
                })?;
                suffix.push(name.to_os_string());
                existing = existing
                    .parent()
                    .ok_or_else(|| {
                        OperationsError::InvalidData(
                            "restore target has no usable parent".to_string(),
                        )
                    })?
                    .to_path_buf();
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut resolved = fs::canonicalize(&existing)?;
    for component in suffix.into_iter().rev() {
        resolved.push(component);
    }
    if fs::symlink_metadata(&target_root).is_ok() && fs::read_dir(&target_root)?.next().is_some() {
        return Err(OperationsError::Conflict(
            "restore target must be isolated and empty".to_string(),
        ));
    }
    Ok(resolved)
}

fn absolute_target_path(path: &Path) -> Result<PathBuf, OperationsError> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => result.push(prefix.as_os_str()),
            Component::RootDir => result.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(OperationsError::InvalidData(
                    "restore target contains parent traversal".to_string(),
                ))
            }
            Component::Normal(name) => result.push(name),
        }
    }
    Ok(result)
}

fn quarantine(staging_root: PathBuf, error: OperationsError) -> RestoreFailure {
    let parent = staging_root
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let quarantine_root = parent
        .parent()
        .map(|path| path.join("quarantine"))
        .unwrap_or_default();
    let destination = if quarantine_root.as_os_str().is_empty() {
        Ok(PathBuf::from(format!(
            "{}.quarantine",
            staging_root.display()
        )))
    } else {
        unique_child(&quarantine_root, "restore")
    };
    let destination = match destination {
        Ok(path) => path,
        Err(_) => PathBuf::from(format!("{}.quarantine", staging_root.display())),
    };
    let quarantine_path = fs::rename(&staging_root, &destination)
        .ok()
        .map(|_| destination);
    RestoreFailure {
        error,
        quarantine_path,
    }
}

fn unique_child(parent: &Path, prefix: &str) -> Result<PathBuf, OperationsError> {
    ensure_directory(parent)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| OperationsError::Io(std::io::Error::other(error)))?
        .as_nanos();
    Ok(parent.join(format!(".{prefix}-{}-{stamp}", std::process::id())))
}
