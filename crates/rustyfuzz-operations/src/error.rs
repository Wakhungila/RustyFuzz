use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub enum OperationsError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidData(String),
    Conflict(String),
    Crypto(String),
    Verification(String),
}

impl Display for OperationsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "operations I/O error: {error}"),
            Self::Json(error) => write!(formatter, "operations JSON error: {error}"),
            Self::InvalidData(detail) => write!(formatter, "invalid operations data: {detail}"),
            Self::Conflict(detail) => write!(formatter, "operations conflict: {detail}"),
            Self::Crypto(detail) => write!(formatter, "backup cryptography error: {detail}"),
            Self::Verification(detail) => {
                write!(formatter, "operations verification error: {detail}")
            }
        }
    }
}

impl std::error::Error for OperationsError {}

impl From<io::Error> for OperationsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for OperationsError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub fn safe_relative_path(value: &str) -> Result<PathBuf, OperationsError> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || value.contains('\\')
        || value.contains('\0')
    {
        return Err(OperationsError::InvalidData(
            "relative path must not be empty or absolute".to_string(),
        ));
    }
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                if name.to_str().is_none() {
                    return Err(OperationsError::InvalidData(
                        "relative path must be valid UTF-8".to_string(),
                    ));
                }
                result.push(name);
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(OperationsError::InvalidData(
                    "relative path contains traversal or root components".to_string(),
                ));
            }
        }
    }
    if result.as_os_str().is_empty() {
        return Err(OperationsError::InvalidData(
            "relative path is empty".to_string(),
        ));
    }
    Ok(result)
}

pub fn ensure_directory(path: &Path) -> Result<(), OperationsError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(OperationsError::InvalidData(
                "path is not a safe directory".to_string(),
            ));
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        ensure_directory(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                Err(OperationsError::InvalidData(
                    "path became an unsafe directory".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        Err(error) => Err(error.into()),
    }
}

pub fn reject_symlink_components(path: &Path) -> Result<(), OperationsError> {
    let mut current = Some(path.to_path_buf());
    while let Some(candidate) = current {
        if let Ok(metadata) = fs::symlink_metadata(&candidate) {
            if metadata.file_type().is_symlink() {
                return Err(OperationsError::InvalidData(
                    "path contains a symlink".to_string(),
                ));
            }
        }
        current = candidate.parent().map(Path::to_path_buf);
    }
    Ok(())
}

pub fn canonicalize_with_missing_tail(path: &Path) -> Result<PathBuf, OperationsError> {
    reject_symlink_components(path)?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(name) => normalized.push(name),
        }
    }
    reject_symlink_components(&normalized)?;
    let mut existing = normalized.clone();
    let mut missing = Vec::new();
    let mut canonical = loop {
        match fs::symlink_metadata(&existing) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(OperationsError::InvalidData(
                        "path contains a symlink".to_string(),
                    ));
                }
                if !missing.is_empty() && !metadata.is_dir() {
                    return Err(OperationsError::InvalidData(
                        "path parent is not a directory".to_string(),
                    ));
                }
                break fs::canonicalize(existing)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or_else(|| {
                    OperationsError::InvalidData("path has no existing ancestor".to_string())
                })?;
                missing.push(name.to_os_string());
                if !existing.pop() {
                    return Err(OperationsError::InvalidData(
                        "path has no existing ancestor".to_string(),
                    ));
                }
            }
            Err(error) => return Err(error.into()),
        }
    };
    for name in missing.into_iter().rev() {
        canonical.push(name);
    }
    Ok(canonical)
}

pub fn read_bounded_regular(path: &Path, max_bytes: u64) -> Result<Vec<u8>, OperationsError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OperationsError::InvalidData(
            "artifact is not a regular file".to_string(),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(OperationsError::InvalidData(
            "artifact exceeds the configured size limit".to_string(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() || opened_metadata.len() > max_bytes {
        return Err(OperationsError::InvalidData(
            "artifact changed while being read".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(OperationsError::InvalidData(
            "artifact exceeds the configured size limit".to_string(),
        ));
    }
    Ok(bytes)
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

pub fn verify_digest(bytes: &[u8], expected: &str) -> bool {
    expected == sha256_digest(bytes)
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), OperationsError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    rustyfuzz_artifacts::fsutil::write_atomic(path, bytes).map_err(|error| match error {
        rustyfuzz_artifacts::FsUtilError::Io(error) => OperationsError::Io(error),
        rustyfuzz_artifacts::FsUtilError::Serialize(error) => OperationsError::Json(error),
        rustyfuzz_artifacts::FsUtilError::InvalidData(detail) => {
            OperationsError::InvalidData(detail)
        }
    })
}

pub fn json_path<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, OperationsError> {
    let bytes = read_bounded_regular(path, max_bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn try_lock_file(path: &Path) -> Result<File, OperationsError> {
    if let Some(parent) = path.parent() {
        ensure_directory(parent)?;
    }
    reject_symlink_components(path)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| {
        OperationsError::Conflict("another operations operation is active".to_string())
    })?;
    Ok(file)
}

pub fn lock_file(path: &Path) -> Result<File, OperationsError> {
    if let Some(parent) = path.parent() {
        ensure_directory(parent)?;
    }
    reject_symlink_components(path)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    fs2::FileExt::lock_exclusive(&file)?;
    Ok(file)
}
