use crate::error::OperationsError;
use crate::models::{OperationConfig, RecoveryDrillResult, VerificationResult};
use crate::restore::{restore_backup, validate_restore_target};
use std::path::Path;

pub fn run_recovery_drill(
    source_config: &OperationConfig,
    backup_path: &Path,
    passphrase: &[u8],
    target_root: &Path,
) -> Result<RecoveryDrillResult, OperationsError> {
    validate_restore_target(source_config, target_root)?;
    let target_config = OperationConfig::new(target_root);
    let restore = restore_backup(&target_config, backup_path, passphrase)
        .map_err(|failure| OperationsError::Verification(failure.to_string()))?;
    let mut verification = VerificationResult {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        verified: true,
        known: true,
        checked_files: 0,
        failures: Vec::new(),
    };
    for campaign_id in &restore.published_campaigns {
        let result = crate::integrity::verify_campaign(&target_config, campaign_id)?;
        verification.checked_files += result.checked_files;
        verification.verified &= result.verified;
        verification.known &= result.known;
        verification.failures.extend(result.failures);
    }
    Ok(RecoveryDrillResult {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        backup_id: restore.backup_id.clone(),
        target_root: target_root.to_path_buf(),
        passed: verification.verified && verification.known,
        restore,
        verification,
    })
}
