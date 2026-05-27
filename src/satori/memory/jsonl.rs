use crate::satori::error::SatoriResult;
use crate::satori::fsutil::ensure_dir;
use crate::satori::types::MemoryEvent;
use std::io::Write;
use std::path::Path;

pub fn append(path: &Path, event: &MemoryEvent) -> SatoriResult<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", serde_json::to_string(event)?)?;
    Ok(())
}

pub fn read_all(path: &Path) -> SatoriResult<Vec<MemoryEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    let mut events = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        events.push(serde_json::from_str(line)?);
    }
    Ok(events)
}
