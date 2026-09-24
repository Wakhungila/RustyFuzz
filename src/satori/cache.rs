use crate::common::fs_security::contained_path;
use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{ensure_dir, read_json_under, reject_symlink_components, sha256_hex};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ResponseCache {
    root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    pub prompt_hash: String,
    pub model: String,
    pub response_text: String,
}

impl ResponseCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn key(model: &str, prompt: &str) -> String {
        sha256_hex(format!("{model}\n{prompt}").as_bytes())
    }

    pub fn get(&self, key: &str) -> SatoriResult<Option<CachedResponse>> {
        let (root, path) = self.checked_path(key)?;
        if !path.exists() {
            return Ok(None);
        }
        read_json_under(&root, &path).map(Some).map_err(|error| {
            anyhow::anyhow!("Satori cache entry is corrupt for key {key}: {error}")
        })
    }

    pub fn put(&self, value: &CachedResponse) -> SatoriResult<()> {
        let (root, path) = self.checked_path(&value.prompt_hash)?;
        ensure_dir(&root)?;
        crate::satori::fsutil::write_json_under(&root, &path, value)?;
        Ok(())
    }

    pub fn path(&self, key: &str) -> SatoriResult<PathBuf> {
        self.checked_path(key).map(|(_, path)| path)
    }

    fn checked_path(&self, key: &str) -> SatoriResult<(PathBuf, PathBuf)> {
        anyhow::ensure!(
            key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Satori cache key must be a 64-character hexadecimal digest"
        );
        anyhow::ensure!(
            key.bytes().all(|byte| !byte.is_ascii_uppercase()),
            "Satori cache key must be lowercase hexadecimal"
        );
        reject_symlink_components(&self.root)?;
        let root = if self.root.exists() {
            anyhow::ensure!(
                !std::fs::symlink_metadata(&self.root)?
                    .file_type()
                    .is_symlink(),
                "Satori cache root must not be a symlink"
            );
            let root = std::fs::canonicalize(&self.root)?;
            anyhow::ensure!(
                root.is_dir() && !std::fs::symlink_metadata(&root)?.file_type().is_symlink(),
                "Satori cache root must be a regular directory"
            );
            root
        } else {
            self.root.clone()
        };
        let path = root.join(format!("{key}.json"));
        let path = if root.exists() {
            contained_path(&root, &path).map_err(anyhow::Error::msg)?
        } else {
            path
        };
        Ok((root, path))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_rejects_invalid_keys_and_symlinked_roots() -> SatoriResult<()> {
        let root = std::env::temp_dir().join(format!(
            "satori-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let target = root.with_extension("target");
        std::fs::create_dir_all(&target)?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &root)?;
            assert!(ResponseCache::new(&root).get("not-a-key").is_err());
            assert!(ResponseCache::new(&root)
                .put(&CachedResponse {
                    prompt_hash: "0".repeat(64),
                    model: "model".to_string(),
                    response_text: "{}".to_string(),
                })
                .is_err());
            let _ = std::fs::remove_file(&root);
        }
        let _ = std::fs::remove_dir_all(target);
        #[cfg(unix)]
        {
            let parent = root.with_extension("parent");
            let parent_target = parent.with_extension("parent-target");
            std::fs::create_dir_all(&parent_target)?;
            std::os::unix::fs::symlink(&parent_target, &parent)?;
            let cache = ResponseCache::new(parent.join("cache"));
            assert!(cache.get(&"a".repeat(64)).is_err());
            let _ = std::fs::remove_file(parent);
            let _ = std::fs::remove_dir_all(parent_target);
        }
        Ok(())
    }

    #[test]
    fn cache_reads_only_contained_digest_paths() -> SatoriResult<()> {
        let root = std::env::temp_dir().join(format!(
            "satori-cache-contained-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&root)?;
        let cache = ResponseCache::new(&root);
        let key = "a".repeat(64);
        assert!(cache.get("../outside").is_err());
        cache.put(&CachedResponse {
            prompt_hash: key.clone(),
            model: "model".to_string(),
            response_text: "{}".to_string(),
        })?;
        assert!(cache.get(&key)?.is_some());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
