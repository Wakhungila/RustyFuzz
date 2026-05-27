use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{ensure_dir, sha256_hex};
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
        let path = self.path(key);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&std::fs::read(path)?)?))
    }

    pub fn put(&self, value: &CachedResponse) -> SatoriResult<()> {
        ensure_dir(&self.root)?;
        std::fs::write(
            self.path(&value.prompt_hash),
            serde_json::to_vec_pretty(value)?,
        )?;
        Ok(())
    }

    pub fn path(&self, key: &str) -> PathBuf {
        self.root.join(format!("{key}.json"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
