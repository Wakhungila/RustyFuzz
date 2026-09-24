use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{append_bytes_under, ensure_dir, read_bytes_under};
use crate::satori::types::MemoryEvent;
use std::path::Path;

pub fn append(path: &Path, event: &MemoryEvent) -> SatoriResult<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    append_bytes_under(path, &line)
}

pub fn read_all(path: &Path) -> SatoriResult<Vec<MemoryEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
    let bytes = read_bytes_under(parent, &absolute)?;
    let text = String::from_utf8(bytes)?;
    let mut events = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        events.push(serde_json::from_str(line)?);
    }
    Ok(events)
}
