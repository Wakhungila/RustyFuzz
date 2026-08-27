//! Crash-safe filesystem primitives: temp-file + rename atomic writes.
//!
//! Interrupted writes must never leave a reader-observable partial artifact
//! (global invariant / crash-safety policy). `write_atomic` serializes to a
//! sibling temp file in the same directory (same filesystem), fsyncs, then
//! renames over the destination. Rename is atomic on POSIX; readers either
//! see the previous complete file or the new complete file.

use std::fs;
use std::io::Write;
use std::path::Path;

/// Errors surfaced by safe persistence helpers.
#[derive(Debug)]
pub enum FsUtilError {
    Io(std::io::Error),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for FsUtilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsUtilError::Io(err) => write!(f, "filesystem error: {err}"),
            FsUtilError::Serialize(err) => write!(f, "serialization error: {err}"),
        }
    }
}

impl std::error::Error for FsUtilError {}

impl From<std::io::Error> for FsUtilError {
    fn from(err: std::io::Error) -> Self {
        FsUtilError::Io(err)
    }
}

impl From<serde_json::Error> for FsUtilError {
    fn from(err: serde_json::Error) -> Self {
        FsUtilError::Serialize(err)
    }
}

/// Writes `bytes` to `path` atomically via temp file + rename + best-effort
/// parent fsync.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), FsUtilError> {
    let parent = path
        .parent()
        .ok_or_else(|| FsUtilError::Io(std::io::Error::other("artifact path has no parent")))?;
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| FsUtilError::Io(std::io::Error::other("non-utf8 artifact file name")))?;

    // Unique temp suffix; uniqueness only matters for concurrent writers to
    // the same destination, which RustyFuzz serializes per run.
    let tmp = parent.join(format!(".{file_name}.tmp"));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    match fs::rename(&tmp, path) {
        Ok(()) => {}
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            return Err(err.into());
        }
    }
    sync_parent_best_effort(parent);
    Ok(())
}

/// Serializes `value` as pretty JSON and writes it atomically.
pub fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), FsUtilError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_atomic(path, &bytes)
}

fn sync_parent_best_effort(parent: &Path) {
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_leaves_no_temp_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("rustyfuzz-fsutil-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nested").join("file.json");
        write_atomic(&path, b"{\"v\":1}").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"{\"v\":1}");
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!leftovers.iter().any(|name| name.ends_with(".tmp")));

        // Overwrite is also atomic.
        write_atomic(&path, b"{\"v\":2}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"v\":2}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_write_round_trips_typed_value() {
        let dir =
            std::env::temp_dir().join(format!("rustyfuzz-fsutil-json-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Payload {
            schema_version: u32,
            name: String,
        }
        let payload = Payload {
            schema_version: 1,
            name: "run".into(),
        };
        let path = dir.join("payload.json");
        write_json_atomic(&path, &payload).unwrap();
        let decoded: Payload = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(decoded, payload);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
