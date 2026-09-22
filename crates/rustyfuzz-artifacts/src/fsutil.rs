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
pub fn write_atomic(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> Result<(), FsUtilError> {
    let path = path.as_ref();
    let bytes = bytes.as_ref();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| FsUtilError::Io(std::io::Error::other("non-utf8 artifact file name")))?;

    // Exclusive creation prevents collisions and following pre-existing symlinks.
    // Each writer owns its temporary file; Drop cleans it up on every error path.
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!(".{file_name}."))
        .suffix(".tmp")
        .tempfile_in(parent)?;
    for chunk in bytes.chunks(64 * 1024) {
        tmp.write_all(chunk)?;
    }
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|err| FsUtilError::Io(err.error))?;
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
    fn concurrent_writers_publish_only_complete_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.json");
        let payloads: Vec<Vec<u8>> = (0..8).map(|i| vec![b'a' + i; 65536]).collect();
        write_atomic(&path, &payloads[0]).unwrap();
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Acquire) {
                    let bytes = fs::read(&path).unwrap();
                    assert!(payloads.contains(&bytes), "reader observed torn artifact");
                }
            });
            let writers: Vec<_> = payloads
                .iter()
                .map(|payload| {
                    let path = &path;
                    scope.spawn(move || {
                        for _ in 0..20 {
                            write_atomic(path, payload).unwrap();
                        }
                    })
                })
                .collect();
            let results: Vec<_> = writers.into_iter().map(|writer| writer.join()).collect();
            done.store(true, std::sync::atomic::Ordering::Release);
            reader.join().unwrap();
            for result in results {
                result.unwrap();
            }
        });
        assert!(payloads.contains(&fs::read(&path).unwrap()));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_publish_cleans_up_its_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("directory");
        fs::create_dir(&destination).unwrap();
        assert!(write_atomic(&destination, b"payload").is_err());
        assert!(destination.is_dir());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_temp_symlink_cannot_redirect_writes() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(".artifact.json.tmp")).unwrap();
        write_atomic(dir.path().join("artifact.json"), b"new artifact").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(
            fs::read(dir.path().join("artifact.json")).unwrap(),
            b"new artifact"
        );
    }

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
    fn reader_never_observes_partial_file_during_overwrite() {
        // Simulate an interrupted write: the temp file existing alone must not
        // affect the previous complete artifact at the destination.
        let dir =
            std::env::temp_dir().join(format!("rustyfuzz-fsutil-crash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("manifest.json");
        write_atomic(&path, b"{\"complete\":true}").unwrap();

        // A crashed writer left a temp file behind.
        let tmp = dir.join(".manifest.json.tmp");
        std::fs::write(&tmp, b"{\"partial\":").unwrap();

        // Readers see the previous complete file.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"complete\":true}"
        );

        // A new writer must not touch a temporary file owned by another writer.
        write_atomic(&path, b"{\"complete\":true,\"v\":2}").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"complete\":true,\"v\":2}"
        );
        assert_eq!(std::fs::read(&tmp).unwrap(), b"{\"partial\":");
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
