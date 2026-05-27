use crate::satori::error::SatoriResult;
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub fn new_run_id(prefix: &str) -> String {
    format!("{}-{}", prefix, Utc::now().format("%Y%m%d-%H%M%S"))
}

pub fn ensure_dir(path: impl AsRef<Path>) -> SatoriResult<()> {
    fs::create_dir_all(path.as_ref())?;
    Ok(())
}

pub fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> SatoriResult<()> {
    if let Some(parent) = path.as_ref().parent() {
        ensure_dir(parent)?;
    }
    fs::write(path.as_ref(), serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> SatoriResult<T> {
    Ok(serde_json::from_slice(&fs::read(path.as_ref())?)?)
}

pub fn write_text(path: impl AsRef<Path>, value: &str) -> SatoriResult<()> {
    if let Some(parent) = path.as_ref().parent() {
        ensure_dir(parent)?;
    }
    fs::write(path.as_ref(), value)?;
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn collect_files(root: &Path) -> SatoriResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_inner(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_inner(path: &Path, files: &mut Vec<PathBuf>) -> SatoriResult<()> {
    if should_ignore(path) {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if should_ignore(&path) {
            continue;
        }
        if path.is_dir() {
            collect_files_inner(&path, files)?;
        } else {
            files.push(path);
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

pub fn read_lossy_limited(path: &Path, max_bytes: usize) -> SatoriResult<String> {
    let bytes = fs::read(path)?;
    let len = bytes.len().min(max_bytes);
    Ok(String::from_utf8_lossy(&bytes[..len]).to_string())
}
