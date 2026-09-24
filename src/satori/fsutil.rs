use crate::common::fs_security::{contained_path, identifier_path, validate_filesystem_identifier};
use crate::satori::error::SatoriResult;
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

static MEMORY_APPEND_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn new_run_id(prefix: &str) -> String {
    let safe_prefix: String = prefix
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .take(100)
        .collect();
    let safe_prefix = if safe_prefix.is_empty() {
        "run"
    } else {
        safe_prefix.as_str()
    };
    format!(
        "{safe_prefix}-{}-{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        Uuid::new_v4()
    )
}

pub fn new_run_id_checked(prefix: &str) -> SatoriResult<String> {
    let run_id = format!(
        "{}-{}-{}",
        prefix,
        Utc::now().format("%Y%m%d-%H%M%S"),
        Uuid::new_v4()
    );
    validate_filesystem_identifier(&run_id).map_err(anyhow::Error::msg)?;
    Ok(run_id)
}

pub fn validate_identifier(identifier: &str) -> SatoriResult<()> {
    validate_filesystem_identifier(identifier).map_err(anyhow::Error::msg)
}

pub fn safe_identifier_path(root: &Path, identifier: &str) -> SatoriResult<PathBuf> {
    identifier_path(root, identifier).map_err(anyhow::Error::msg)
}

pub fn ensure_dir(path: impl AsRef<Path>) -> SatoriResult<()> {
    let path = path.as_ref();
    reject_symlink_components(path)?;
    fs::create_dir_all(path)?;
    reject_symlink_components(path)?;
    Ok(())
}

pub fn canonical_run_root() -> SatoriResult<PathBuf> {
    let root = PathBuf::from("satori/runs");
    if root.exists() {
        anyhow::ensure!(
            !fs::symlink_metadata(&root)?.file_type().is_symlink(),
            "Satori run root must not be a symlink"
        );
    }
    ensure_dir(&root)?;
    let canonical = fs::canonicalize(&root)?;
    anyhow::ensure!(
        fs::symlink_metadata(&canonical)?.is_dir(),
        "Satori run root is not a directory"
    );
    Ok(canonical)
}

pub fn canonical_run_dir(run_id: &str) -> SatoriResult<PathBuf> {
    validate_identifier(run_id)?;
    let root = canonical_run_root()?;
    let run_dir = identifier_path(&root, run_id).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        run_dir.starts_with(&root) && run_dir.is_dir(),
        "Satori run directory is not contained beneath the canonical run root"
    );
    Ok(run_dir)
}

pub fn canonical_run_dir_path(run_dir: &Path) -> SatoriResult<PathBuf> {
    let root = canonical_run_root()?;
    let run_dir = contained_path(&root, run_dir).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&run_dir)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "Satori run directory is not a regular directory"
    );
    Ok(run_dir)
}

pub fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> SatoriResult<()> {
    rustyfuzz_artifacts::fsutil::write_json_atomic(path.as_ref(), value)?;
    Ok(())
}

pub fn write_json_under<T: Serialize>(root: &Path, path: &Path, value: &T) -> SatoriResult<()> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    rustyfuzz_artifacts::fsutil::write_json_atomic(&safe_path, value)?;
    Ok(())
}

pub fn write_json_in_run<T: Serialize>(
    run_dir: &Path,
    relative_path: &Path,
    value: &T,
) -> SatoriResult<()> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    write_json_under(&canonical_run_root()?, &run_dir.join(relative_path), value)
}

pub fn write_text_under(root: &Path, path: &Path, value: &str) -> SatoriResult<()> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    rustyfuzz_artifacts::fsutil::write_atomic(&safe_path, value.as_bytes())?;
    Ok(())
}

pub fn write_text_in_run(run_dir: &Path, relative_path: &Path, value: &str) -> SatoriResult<()> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    write_text_under(&canonical_run_root()?, &run_dir.join(relative_path), value)
}

pub fn write_atomic_under(root: &Path, path: &Path, bytes: &[u8]) -> SatoriResult<()> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    rustyfuzz_artifacts::fsutil::write_atomic(&safe_path, bytes)?;
    Ok(())
}

pub fn read_json_under<T: DeserializeOwned>(root: &Path, path: &Path) -> SatoriResult<T> {
    Ok(serde_json::from_slice(&read_bytes_under(root, path)?)?)
}

pub fn read_json_in_run<T: DeserializeOwned>(
    run_dir: &Path,
    relative_path: &Path,
) -> SatoriResult<T> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    read_json_under(&canonical_run_root()?, &run_dir.join(relative_path))
}

pub fn read_bytes_under(root: &Path, path: &Path) -> SatoriResult<Vec<u8>> {
    let canonical_root = fs::canonicalize(root)?;
    let safe_path = contained_path(&canonical_root, path).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&safe_path)?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Satori run artifact is not a regular file: {}",
        safe_path.display()
    );
    Ok(fs::read(safe_path)?)
}

pub fn append_bytes_under(path: &Path, bytes: &[u8]) -> SatoriResult<()> {
    let _guard = MEMORY_APPEND_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("Satori memory append lock is poisoned"))?;
    reject_symlink_components(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(parent)?;
    let canonical_parent = fs::canonicalize(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("Satori memory path has no valid file name"))?;
    let safe_path = canonical_parent.join(file_name);
    let mut existing = Vec::new();
    if safe_path.exists() {
        existing = read_bytes_under(&canonical_parent, &safe_path)?;
    }
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        existing.push(b'\n');
    }
    existing.extend_from_slice(bytes);
    if !bytes.ends_with(b"\n") {
        existing.push(b'\n');
    }
    rustyfuzz_artifacts::fsutil::write_atomic(&safe_path, existing)?;
    Ok(())
}

pub fn read_dir_under(root: &Path, path: &Path) -> SatoriResult<std::fs::ReadDir> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&safe_path)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "Satori directory is not a regular directory: {}",
        safe_path.display()
    );
    Ok(fs::read_dir(safe_path)?)
}

pub fn reject_symlink_components(path: &Path) -> SatoriResult<()> {
    let mut current = Some(path.to_path_buf());
    while let Some(candidate) = current {
        if let Ok(metadata) = fs::symlink_metadata(&candidate) {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "Satori artifact path contains a symlink"
            );
        }
        current = candidate.parent().map(Path::to_path_buf);
    }
    Ok(())
}

pub fn write_text(path: impl AsRef<Path>, value: &str) -> SatoriResult<()> {
    rustyfuzz_artifacts::fsutil::write_atomic(path.as_ref(), value.as_bytes())?;
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn collect_files(root: &Path) -> SatoriResult<Vec<PathBuf>> {
    let root = fs::canonicalize(root)?;
    let mut files = Vec::new();
    collect_files_inner(&root, &root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_inner(root: &Path, path: &Path, files: &mut Vec<PathBuf>) -> SatoriResult<()> {
    if should_ignore(path) {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "Satori project contains symlink entry: {}",
            entry_path.display()
        );
        if should_ignore(&entry_path) {
            continue;
        }
        if metadata.is_dir() {
            collect_files_inner(root, &entry_path, files)?;
        } else {
            anyhow::ensure!(
                metadata.is_file(),
                "Satori project entry is not a regular file: {}",
                entry_path.display()
            );
            let canonical = fs::canonicalize(&entry_path)?;
            anyhow::ensure!(
                canonical.starts_with(root),
                "Satori project file escapes canonical root: {}",
                entry_path.display()
            );
            files.push(canonical);
        }
    }
    Ok(())
}

pub fn should_ignore(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            matches!(
                name,
                ".git"
                    | "node_modules"
                    | "out"
                    | "cache"
                    | "broadcast"
                    | "target"
                    | "artifacts"
                    | "typechain"
                    | ".forge-snapshots"
            )
        })
        .unwrap_or(false)
}

pub const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

pub fn read_evidence_file(root: &Path, path: &Path) -> SatoriResult<Vec<u8>> {
    let canonical_root = fs::canonicalize(root)?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let safe_path = contained_path(&canonical_root, &candidate).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&safe_path)?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Satori evidence path is not a regular file: {}",
        safe_path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_EVIDENCE_BYTES as u64,
        "Satori evidence file exceeds the {MAX_EVIDENCE_BYTES} byte limit"
    );
    Ok(fs::read(safe_path)?)
}

pub fn read_lossy_limited(path: &Path, max_bytes: usize) -> SatoriResult<String> {
    let file = fs::File::open(path)?;
    let mut reader = file.take(max_bytes as u64);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    reader.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

pub fn verify_source_file_binding(
    root: &Path,
    path: &Path,
    relative_path: &Path,
    expected_hash: &str,
) -> SatoriResult<()> {
    let canonical_root = fs::canonicalize(root)?;
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "Satori source identity is not a regular file: {}",
        path.display()
    );
    let canonical_path = contained_path(&canonical_root, path).map_err(anyhow::Error::msg)?;
    let actual_relative = canonical_path
        .strip_prefix(&canonical_root)
        .map_err(|_| anyhow::anyhow!("Satori source identity has no relative path"))?;
    anyhow::ensure!(
        actual_relative == relative_path,
        "Satori source identity path does not match its run identity"
    );
    let bytes = read_bytes_under(&canonical_root, &canonical_path)?;
    anyhow::ensure!(
        sha256_hex(&bytes) == expected_hash,
        "Satori source identity changed after ingestion: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_reader_rejects_escape_symlink_and_oversized_files() -> SatoriResult<()> {
        let root =
            std::env::temp_dir().join(format!("rustyfuzz-satori-evidence-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let findings = root.join("findings");
        fs::create_dir_all(&findings)?;
        let evidence = findings.join("evidence.json");
        fs::write(&evidence, b"ok")?;
        assert_eq!(read_evidence_file(&findings, &evidence)?, b"ok");

        let outside = root.join("outside");
        fs::write(&outside, b"secret")?;
        assert!(read_evidence_file(&findings, &outside).is_err());

        #[cfg(unix)]
        {
            let link = findings.join("link");
            std::os::unix::fs::symlink(&outside, &link)?;
            assert!(read_evidence_file(&findings, &link).is_err());
        }

        fs::write(&evidence, vec![b'x'; MAX_EVIDENCE_BYTES + 1])?;
        assert!(read_evidence_file(&findings, &evidence).is_err());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn lossy_reader_honors_requested_byte_limit() -> SatoriResult<()> {
        let path = std::env::temp_dir().join(format!(
            "rustyfuzz-satori-limited-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, b"0123456789")?;
        assert_eq!(read_lossy_limited(&path, 4)?, "0123");
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn contained_json_reader_rejects_symlink_artifacts() -> SatoriResult<()> {
        let root =
            std::env::temp_dir().join(format!("rustyfuzz-satori-contained-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(root.join("run.json"), br#"{"run_id":"ok"}"#)?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("run.json"), root.join("linked.json"))?;
            assert!(
                read_json_under::<serde_json::Value>(&root, &root.join("linked.json")).is_err()
            );
        }
        let value: serde_json::Value = read_json_under(&root, &root.join("run.json"))?;
        assert_eq!(value["run_id"], "ok");
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn memory_append_preserves_lines_and_rejects_destination_symlink() -> SatoriResult<()> {
        let root =
            std::env::temp_dir().join(format!("rustyfuzz-satori-append-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let path = root.join("events.jsonl");
        append_bytes_under(&path, b"{\"id\":1}")?;
        append_bytes_under(&path, b"{\"id\":2}\n")?;
        assert_eq!(fs::read(&path)?, b"{\"id\":1}\n{\"id\":2}\n");
        #[cfg(unix)]
        {
            let victim = root.join("victim");
            fs::write(&victim, b"untouched")?;
            fs::remove_file(&path)?;
            std::os::unix::fs::symlink(&victim, &path)?;
            assert!(append_bytes_under(&path, b"{\"id\":3}").is_err());
            assert_eq!(fs::read(victim)?, b"untouched");
        }
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn generated_run_ids_and_job_identifiers_are_safe_segments() {
        let first = new_run_id("satori");
        let second = new_run_id("satori");
        assert_ne!(first, second);
        assert!(validate_identifier(&first).is_ok());
        assert!(validate_identifier(&second).is_ok());
        assert!(new_run_id_checked("../satori").is_err());
        assert!(validate_identifier("job-abc_1").is_ok());
        for value in ["../job", "/tmp/job", "job/name", "job\\name"] {
            assert!(validate_identifier(value).is_err(), "{value}");
        }
    }
}
