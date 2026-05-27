use crate::satori::error::SatoriResult;
use crate::satori::memory::jsonl;
use crate::satori::types::MemoryEvent;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct MemoryStore {
    path: PathBuf,
}

impl MemoryStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn append(&self, event: &MemoryEvent) -> SatoriResult<()> {
        jsonl::append(&self.path, event)
    }

    pub fn retrieve(&self, keywords: &[&str]) -> SatoriResult<Vec<MemoryEvent>> {
        let events = jsonl::read_all(&self.path)?;
        let needles = keywords
            .iter()
            .filter(|keyword| !keyword.trim().is_empty())
            .map(|keyword| keyword.to_ascii_lowercase())
            .collect::<Vec<_>>();
        Ok(events
            .into_iter()
            .filter(|event| {
                let haystack = format!(
                    "{} {} {} {} {}",
                    event.summary,
                    event.bug_class.clone().unwrap_or_default(),
                    event.contract.clone().unwrap_or_default(),
                    event.function.clone().unwrap_or_default(),
                    event.tags.join(" ")
                )
                .to_ascii_lowercase();
                needles.iter().any(|needle| haystack.contains(needle))
            })
            .take(12)
            .collect())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn memory_jsonl_append_and_retrieve_works() {
        let path = std::env::temp_dir().join(format!(
            "satori-memory-test-{}.jsonl",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let store = MemoryStore::new(&path);
        store
            .append(&MemoryEvent {
                timestamp: Utc::now(),
                event_type: "detector_signal".to_string(),
                protocol_type: None,
                bug_class: Some("share_inflation".to_string()),
                contract: Some("Vault".to_string()),
                function: Some("deposit".to_string()),
                tags: vec!["erc4626".to_string()],
                summary: "ERC4626 share inflation false-positive caveat".to_string(),
                artifact: None,
            })
            .unwrap();
        assert_eq!(store.retrieve(&["share"]).unwrap().len(), 1);
        let _ = std::fs::remove_file(path);
    }
}
