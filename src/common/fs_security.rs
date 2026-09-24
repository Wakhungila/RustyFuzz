use std::fs;
use std::path::{Component, Path, PathBuf};

pub const MAX_JOB_EXECUTIONS: u64 = 100_000;
pub const MAX_JOB_DURATION_SECS: u64 = 3_600;

pub fn validate_job_bounds(
    max_execs: Option<u64>,
    duration_secs: Option<u64>,
) -> Result<(), String> {
    if max_execs.is_some_and(|value| value > MAX_JOB_EXECUTIONS) {
        return Err(format!("job execution budget exceeds {MAX_JOB_EXECUTIONS}"));
    }
    if duration_secs.is_some_and(|value| value > MAX_JOB_DURATION_SECS) {
        return Err(format!(
            "job duration exceeds {MAX_JOB_DURATION_SECS} seconds"
        ));
    }
    Ok(())
}

pub const MAX_FILESYSTEM_IDENTIFIER_LENGTH: usize = 200;

pub fn validate_filesystem_identifier(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("filesystem identifier must not be empty".to_string());
    }
    if value.len() > MAX_FILESYSTEM_IDENTIFIER_LENGTH {
        return Err("filesystem identifier is too long".to_string());
    }
    if value == "." || value == ".." {
        return Err("filesystem identifier must not be a dot path".to_string());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err("filesystem identifier must be a single relative path segment".to_string());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("filesystem identifier contains unsupported characters".to_string());
    }
    Ok(())
}

pub fn contained_path(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "filesystem path is outside its configured root".to_string())?;
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect filesystem root: {error}"))?;
    if root_metadata.file_type().is_symlink() {
        return Err("filesystem root must not be a symlink".to_string());
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize filesystem root: {error}"))?;

    let mut existing = path.to_path_buf();
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(&existing) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err("filesystem path contains a symlink".to_string());
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = existing
                    .file_name()
                    .ok_or_else(|| "path has no existing ancestor".to_string())?;
                suffix.push(name.to_os_string());
                existing = existing
                    .parent()
                    .ok_or_else(|| "path has no existing ancestor".to_string())?
                    .to_path_buf();
            }
            Err(error) => return Err(format!("cannot inspect filesystem path: {error}")),
        }
    }

    let mut candidate = fs::canonicalize(&existing)
        .map_err(|error| format!("cannot canonicalize filesystem path: {error}"))?;
    for name in suffix.iter().rev() {
        candidate.push(name);
    }
    if !candidate.starts_with(&canonical_root) {
        return Err("filesystem path escapes its canonical root".to_string());
    }
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("filesystem path must stay beneath its configured root".to_string());
    }
    Ok(candidate)
}

pub fn identifier_path(root: &Path, identifier: &str) -> Result<PathBuf, String> {
    validate_filesystem_identifier(identifier)?;
    let path = root.join(identifier);
    contained_path(root, &path)
}

pub fn ensure_path_contained(root: &Path, path: &Path) -> Result<(), String> {
    contained_path(root, path).map(|_| ())
}

pub fn write_atomic_under(root: &Path, path: &Path, bytes: impl AsRef<[u8]>) -> Result<(), String> {
    let safe_path = contained_path(root, path)?;
    rustyfuzz_artifacts::fsutil::write_atomic(safe_path, bytes).map_err(|error| error.to_string())
}

pub fn write_json_atomic_under<T: serde::Serialize>(
    root: &Path,
    path: &Path,
    value: &T,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    write_atomic_under(root, path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_job_bounds_reject_oversized_limits() {
        assert!(validate_job_bounds(Some(MAX_JOB_EXECUTIONS), Some(MAX_JOB_DURATION_SECS)).is_ok());
        assert!(validate_job_bounds(Some(MAX_JOB_EXECUTIONS + 1), None).is_err());
        assert!(validate_job_bounds(None, Some(MAX_JOB_DURATION_SECS + 1)).is_err());
    }

    #[test]
    fn identifiers_reject_traversal_absolute_and_separator_paths() {
        for value in [
            "", ".", "..", "../x", "/tmp/x", "a/b", "a\\b", "a:b", "a\0b",
        ] {
            assert!(validate_filesystem_identifier(value).is_err(), "{value:?}");
        }
        assert!(validate_filesystem_identifier("job-abc_1.json").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn contained_path_rejects_symlink_escape() {
        let temp = std::env::temp_dir().join(format!(
            "rustyfuzz-fs-security-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let root = temp.join("root");
        let outside = temp.join("outside");
        fs::create_dir_all(&root).expect("root");
        fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink");
        let path = root.join("link").join("file.json");
        assert!(contained_path(&root, &path).is_err());
        let _ = fs::remove_dir_all(temp);
    }
}
