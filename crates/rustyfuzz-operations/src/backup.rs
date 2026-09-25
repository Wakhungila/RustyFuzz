use crate::error::{
    canonicalize_with_missing_tail, ensure_directory, read_bounded_regular, safe_relative_path,
    sha256_digest, verify_digest, OperationsError,
};
use crate::inventory::collect_files;
use crate::models::{BackupManifest, BackupManifestEntry, BackupResult, OperationConfig};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"RFOPBAK1";
const FORMAT_VERSION: u16 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 70;
const MIN_MEMORY_KIB: u32 = 8 * 1024;
const MAX_MEMORY_KIB: u32 = 64 * 1024;
const MAX_TIME_COST: u32 = 3;
const MAX_PARALLELISM: u32 = 2;
const MAX_PLAINTEXT_OVERHEAD: u64 = 1024 * 1024;
const MAX_BACKUP_PLAINTEXT_BYTES: u64 = 48 * 1024 * 1024;
const MAX_ENCRYPTED_BACKUP_BYTES: u64 = MAX_BACKUP_PLAINTEXT_BYTES + 16;

fn estimated_plaintext_bytes(
    total_raw_bytes: u64,
    file_count: usize,
) -> Result<u64, OperationsError> {
    let encoded_groups = total_raw_bytes
        .checked_add(2)
        .ok_or_else(|| OperationsError::InvalidData("backup size overflow".to_string()))?
        / 3;
    let encoded_bytes = encoded_groups
        .checked_mul(4)
        .ok_or_else(|| OperationsError::InvalidData("backup size overflow".to_string()))?;
    let file_overhead = (file_count as u64)
        .checked_mul(1024)
        .ok_or_else(|| OperationsError::InvalidData("backup size overflow".to_string()))?;
    encoded_bytes
        .checked_add(file_overhead)
        .and_then(|value| value.checked_add(MAX_PLAINTEXT_OVERHEAD))
        .ok_or_else(|| OperationsError::InvalidData("backup size overflow".to_string()))
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BackupEnvelope {
    pub(crate) schema_version: u32,
    pub(crate) manifest: BackupManifest,
    pub(crate) files: Vec<BackupFile>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BackupFile {
    pub(crate) path: String,
    pub(crate) data: String,
}

pub fn create_backup(
    config: &OperationConfig,
    backup_path: &Path,
    passphrase: &[u8],
    backup_id: &str,
    created_at_unix: u64,
) -> Result<BackupResult, OperationsError> {
    create_backup_inner(
        config,
        backup_path,
        passphrase,
        backup_id,
        created_at_unix,
        None,
    )
}

pub fn create_backup_for_run(
    config: &OperationConfig,
    backup_path: &Path,
    passphrase: &[u8],
    backup_id: &str,
    created_at_unix: u64,
    run_id: &str,
) -> Result<BackupResult, OperationsError> {
    rustyfuzz_artifacts::validate_run_id(run_id)
        .map_err(|error| OperationsError::InvalidData(error.to_string()))?;
    create_backup_inner(
        config,
        backup_path,
        passphrase,
        backup_id,
        created_at_unix,
        Some(run_id),
    )
}

fn validate_backup_destination(
    config: &OperationConfig,
    backup_path: &Path,
) -> Result<(), OperationsError> {
    let destination = canonicalize_with_missing_tail(backup_path)?;
    let runs_root = fs::canonicalize(config.runs_root())?;
    if destination == runs_root || destination.starts_with(&runs_root) {
        return Err(OperationsError::InvalidData(
            "backup destination must be outside the canonical runs tree".to_string(),
        ));
    }
    Ok(())
}

fn create_backup_inner(
    config: &OperationConfig,
    backup_path: &Path,
    passphrase: &[u8],
    backup_id: &str,
    created_at_unix: u64,
    selected_run: Option<&str>,
) -> Result<BackupResult, OperationsError> {
    config.validate().map_err(OperationsError::InvalidData)?;
    let _operation_lock =
        crate::error::try_lock_file(&config.artifacts_root().join("operations.lock"))?;
    rustyfuzz_artifacts::validate_run_id(backup_id)
        .map_err(|error| OperationsError::InvalidData(error.to_string()))?;
    if passphrase.len() < 12 {
        return Err(OperationsError::Crypto(
            "passphrase is too short".to_string(),
        ));
    }
    if fs::symlink_metadata(backup_path).is_ok() {
        return Err(OperationsError::Conflict(
            "backup path already exists".to_string(),
        ));
    }
    let runs_root = config.runs_root();
    if !runs_root.is_dir() {
        return Err(OperationsError::InvalidData(
            "runs root does not exist".to_string(),
        ));
    }
    validate_backup_destination(config, backup_path)?;
    let inventory = collect_files(&runs_root, config)?;
    let inventory: Vec<_> = inventory
        .into_iter()
        .filter(|file| {
            selected_run.is_none_or(|run_id| {
                file.path
                    .split('/')
                    .next()
                    .is_some_and(|campaign_id| campaign_id == run_id)
            })
        })
        .collect();
    if inventory.is_empty() {
        return Err(OperationsError::InvalidData(
            "selected backup inventory is empty".to_string(),
        ));
    }
    if inventory.len() > config.max_backup_files {
        return Err(OperationsError::InvalidData(
            "backup file limit exceeded".to_string(),
        ));
    }
    let inventory_bytes = inventory.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or_else(|| OperationsError::InvalidData("backup size overflow".to_string()))
    })?;
    if estimated_plaintext_bytes(inventory_bytes, inventory.len())? > MAX_BACKUP_PLAINTEXT_BYTES {
        return Err(OperationsError::InvalidData(
            "backup would exceed the workstation memory safety limit".to_string(),
        ));
    }
    let mut files = Vec::with_capacity(inventory.len());
    let mut manifest_files = Vec::with_capacity(inventory.len());
    let mut total_bytes = 0u64;
    let mut campaign_ids = Vec::new();
    for file in inventory {
        let relative = safe_relative_path(&file.path)?;
        let path = runs_root.join(&relative);
        let bytes = read_bounded_regular(&path, config.max_file_bytes)?;
        if bytes.len() as u64 != file.size {
            return Err(OperationsError::InvalidData(
                "artifact changed during backup".to_string(),
            ));
        }
        let digest = sha256_digest(&bytes);
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
            OperationsError::InvalidData("backup byte count overflow".to_string())
        })?;
        if total_bytes > config.max_backup_bytes {
            return Err(OperationsError::InvalidData(
                "backup byte limit exceeded".to_string(),
            ));
        }
        let path_text = file.path.clone();
        manifest_files.push(BackupManifestEntry {
            path: path_text,
            size: bytes.len() as u64,
            digest,
        });
        files.push(BackupFile {
            path: file.path,
            data: BASE64.encode(bytes),
        });
        if let Some(campaign_id) = relative
            .components()
            .next()
            .and_then(|component| component.as_os_str().to_str())
        {
            rustyfuzz_artifacts::validate_run_id(campaign_id)
                .map_err(|error| OperationsError::InvalidData(error.to_string()))?;
            if !campaign_ids.iter().any(|value| value == campaign_id) {
                campaign_ids.push(campaign_id.to_string());
            }
        }
    }
    campaign_ids.sort();
    let manifest = BackupManifest {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        backup_id: backup_id.to_string(),
        created_at_unix,
        campaign_ids,
        files: manifest_files,
        total_bytes,
    };
    let manifest_digest = manifest.digest();
    let file_count = files.len();
    let envelope = BackupEnvelope {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        manifest,
        files,
    };
    let plaintext = serde_json::to_vec(&envelope)?;
    if plaintext.len() as u64 > MAX_BACKUP_PLAINTEXT_BYTES {
        return Err(OperationsError::InvalidData(
            "encrypted backup is too large".to_string(),
        ));
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt)
        .map_err(|_| OperationsError::Crypto("random source unavailable".to_string()))?;
    getrandom::fill(&mut nonce_bytes)
        .map_err(|_| OperationsError::Crypto("random source unavailable".to_string()))?;
    let params = Params::new(19 * 1024, 2, 1, Some(KEY_LEN))
        .map_err(|error| OperationsError::Crypto(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, &salt, key_bytes.as_mut())
        .map_err(|error| OperationsError::Crypto(error.to_string()))?;
    let mut header = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&(19u32 * 1024).to_be_bytes());
    header.extend_from_slice(&2u32.to_be_bytes());
    header.extend_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);
    let ciphertext_len = (plaintext.len() + 16) as u64;
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    let sealed = XChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let ciphertext = sealed
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| OperationsError::Crypto("backup encryption failed".to_string()))?;
    if ciphertext.len() as u64 > MAX_ENCRYPTED_BACKUP_BYTES {
        return Err(OperationsError::InvalidData(
            "encrypted backup is too large".to_string(),
        ));
    }
    if ciphertext.len() as u64 != ciphertext_len {
        return Err(OperationsError::Crypto(
            "backup encryption length mismatch".to_string(),
        ));
    }
    let mut output = header;
    output.extend_from_slice(&ciphertext);
    if let Some(parent) = backup_path.parent() {
        ensure_directory(parent)?;
    }
    validate_backup_destination(config, backup_path)?;
    rustyfuzz_artifacts::fsutil::write_atomic_noclobber(backup_path, output).map_err(|error| {
        match error {
            rustyfuzz_artifacts::FsUtilError::Io(error) => OperationsError::Io(error),
            rustyfuzz_artifacts::FsUtilError::Serialize(error) => OperationsError::Json(error),
            rustyfuzz_artifacts::FsUtilError::InvalidData(detail) => {
                OperationsError::InvalidData(detail)
            }
        }
    })?;
    Ok(BackupResult {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        backup_id: backup_id.to_string(),
        path: backup_path.to_path_buf(),
        file_count,
        total_bytes,
        manifest_digest,
        created_at_unix,
    })
}

pub(crate) fn decode_backup(
    config: &OperationConfig,
    backup_path: &Path,
    passphrase: &[u8],
) -> Result<BackupEnvelope, OperationsError> {
    if passphrase.len() < 12 {
        return Err(OperationsError::Crypto(
            "passphrase is too short".to_string(),
        ));
    }
    let bytes = read_bounded_regular(
        backup_path,
        MAX_ENCRYPTED_BACKUP_BYTES.saturating_add(HEADER_LEN as u64),
    )?;
    if bytes.len() < HEADER_LEN + 16 {
        return Err(OperationsError::Crypto("backup is truncated".to_string()));
    }
    if &bytes[..8] != MAGIC || u16::from_be_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION {
        return Err(OperationsError::Crypto(
            "unsupported backup format".to_string(),
        ));
    }
    let memory = u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| OperationsError::Crypto("invalid header".to_string()))?,
    );
    let time = u32::from_be_bytes(
        bytes[14..18]
            .try_into()
            .map_err(|_| OperationsError::Crypto("invalid header".to_string()))?,
    );
    let parallelism = u32::from_be_bytes(
        bytes[18..22]
            .try_into()
            .map_err(|_| OperationsError::Crypto("invalid header".to_string()))?,
    );
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory)
        || time == 0
        || time > MAX_TIME_COST
        || parallelism == 0
        || parallelism > MAX_PARALLELISM
    {
        return Err(OperationsError::Crypto(
            "unsupported key derivation parameters".to_string(),
        ));
    }
    let salt = &bytes[22..38];
    let nonce = &bytes[38..62];
    let ciphertext_len = u64::from_be_bytes(
        bytes[62..70]
            .try_into()
            .map_err(|_| OperationsError::Crypto("invalid header".to_string()))?,
    );
    if ciphertext_len == 0 || ciphertext_len > MAX_ENCRYPTED_BACKUP_BYTES {
        return Err(OperationsError::Crypto(
            "invalid encrypted payload size".to_string(),
        ));
    }
    if bytes.len() as u64 != HEADER_LEN as u64 + ciphertext_len {
        return Err(OperationsError::Crypto(
            "backup length does not match header".to_string(),
        ));
    }
    let params = Params::new(memory, time, parallelism, Some(KEY_LEN))
        .map_err(|error| OperationsError::Crypto(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, key_bytes.as_mut())
        .map_err(|error| OperationsError::Crypto(error.to_string()))?;
    let sealed = XChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let plaintext = sealed
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &bytes[HEADER_LEN..],
                aad: &bytes[..HEADER_LEN],
            },
        )
        .map_err(|_| OperationsError::Crypto("backup authentication failed".to_string()))?;
    let envelope: BackupEnvelope = serde_json::from_slice(&plaintext)
        .map_err(|_| OperationsError::Crypto("backup plaintext is malformed".to_string()))?;
    validate_envelope(config, &envelope)?;
    Ok(envelope)
}

fn validate_envelope(
    config: &OperationConfig,
    envelope: &BackupEnvelope,
) -> Result<(), OperationsError> {
    if envelope.schema_version != crate::models::OPERATIONS_SCHEMA_VERSION
        || envelope.manifest.schema_version != crate::models::OPERATIONS_SCHEMA_VERSION
    {
        return Err(OperationsError::Crypto(
            "unsupported backup schema".to_string(),
        ));
    }
    if envelope.files.len() > config.max_backup_files
        || envelope.manifest.files.len() > config.max_backup_files
    {
        return Err(OperationsError::Crypto(
            "backup file limit exceeded".to_string(),
        ));
    }
    if envelope.files.len() != envelope.manifest.files.len() {
        return Err(OperationsError::Crypto(
            "backup manifest file count mismatch".to_string(),
        ));
    }
    let mut total = 0u64;
    let mut previous = None;
    let mut seen_campaigns = Vec::new();
    for (file, entry) in envelope.files.iter().zip(&envelope.manifest.files) {
        let relative = safe_relative_path(&file.path)?;
        if file.path != entry.path || entry.size > config.max_file_bytes {
            return Err(OperationsError::Crypto(
                "backup manifest entry is invalid".to_string(),
            ));
        }
        if previous
            .as_ref()
            .is_some_and(|value: &String| value >= &file.path)
        {
            return Err(OperationsError::Crypto(
                "backup paths are not strictly ordered".to_string(),
            ));
        }
        previous = Some(file.path.clone());
        let bytes = BASE64
            .decode(&file.data)
            .map_err(|_| OperationsError::Crypto("backup file encoding is invalid".to_string()))?;
        if bytes.len() as u64 != entry.size || !verify_digest(&bytes, &entry.digest) {
            return Err(OperationsError::Crypto(
                "backup file digest mismatch".to_string(),
            ));
        }
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| OperationsError::Crypto("backup size overflow".to_string()))?;
        if total > config.max_backup_bytes {
            return Err(OperationsError::Crypto(
                "backup byte limit exceeded".to_string(),
            ));
        }
        let campaign_id = relative
            .components()
            .next()
            .and_then(|component| component.as_os_str().to_str())
            .ok_or_else(|| OperationsError::Crypto("backup path has no campaign".to_string()))?;
        rustyfuzz_artifacts::validate_run_id(campaign_id)
            .map_err(|_| OperationsError::Crypto("backup campaign id is invalid".to_string()))?;
        if !seen_campaigns
            .iter()
            .any(|value: &String| value == campaign_id)
        {
            seen_campaigns.push(campaign_id.to_string());
        }
    }
    if seen_campaigns != envelope.manifest.campaign_ids {
        return Err(OperationsError::Crypto(
            "backup campaign inventory mismatch".to_string(),
        ));
    }
    if total != envelope.manifest.total_bytes {
        return Err(OperationsError::Crypto(
            "backup total size mismatch".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_plaintext_estimate_fails_before_unbounded_base64_allocation() {
        let estimate = estimated_plaintext_bytes(40 * 1024 * 1024, 4_096).unwrap();
        assert!(estimate > MAX_BACKUP_PLAINTEXT_BYTES);
        assert!(
            estimated_plaintext_bytes(32 * 1024 * 1024, 4_096).unwrap()
                <= MAX_BACKUP_PLAINTEXT_BYTES
        );
    }
}
