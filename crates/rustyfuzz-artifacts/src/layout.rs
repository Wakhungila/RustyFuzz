//! Canonical run layout for campaign artifacts.
//!
//! One authoritative mapping from artifact kind to filesystem path, so no
//! caller reconstructs paths ad hoc. The layout does not own policy (what to
//! persist is the fuzzer's decision); it owns *where*.

use crate::fsutil::write_json_atomic;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Lifecycle state persisted in the canonical run directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunTerminalState {
    Incomplete,
    Completed,
    Partial,
    Cancelled,
    Failed,
}

impl RunTerminalState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Incomplete)
    }
}

const MAX_TERMINAL_STATUS_BYTES: u64 = 64 * 1024;

pub struct CampaignLock {
    run_id: String,
    _file: File,
}

impl CampaignLock {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
}

struct TerminalStatusLock {
    _file: File,
}

impl TerminalStatusLock {
    fn acquire(root: &Path) -> Result<Self, crate::FsUtilError> {
        let path = root.join(".terminal_status.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(crate::FsUtilError::InvalidData(
                "terminal status lock is not a regular file".to_string(),
            ));
        }
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(Self { _file: file })
    }
}

pub fn validate_run_id(run_id: &str) -> Result<(), crate::FsUtilError> {
    let path = Path::new(run_id);
    let valid = !run_id.is_empty()
        && run_id.len() <= 200
        && path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(crate::FsUtilError::InvalidData(
            "run id must be one safe filesystem path segment".to_string(),
        ))
    }
}

fn ensure_directory_chain(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(std::io::Error::other(
                    "artifact path contains a parent traversal",
                ))
            }
            Component::Normal(name) => {
                current.push(name);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(std::io::Error::other(
                                "artifact path contains a non-directory or symlink",
                            ));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        fs::create_dir(&current)?;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(())
}

/// Atomic terminal record for a run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTerminalStatus {
    pub schema_version: u32,
    pub terminal: bool,
    pub state: RunTerminalState,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_summary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_summary_digest: Option<String>,
}

impl RunTerminalStatus {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported terminal status schema version {}",
                self.schema_version
            ));
        }
        if self.terminal != self.state.is_terminal() {
            return Err("terminal boolean does not match terminal state".to_string());
        }
        if self.run_id.trim().is_empty() {
            return Err("terminal status run_id is empty".to_string());
        }
        Ok(())
    }

    pub fn validate_for_run_id(&self, expected_run_id: &str) -> Result<(), String> {
        self.validate()?;
        if self.run_id != expected_run_id {
            return Err("terminal status run_id does not match canonical run".to_string());
        }
        Ok(())
    }
}

/// Root-relative structure of one fuzzing run.
///
/// ```text
/// .rustyfuzz/
/// ├── runs/<run-id>/           <- RunLayout rooted here
/// │   ├── manifest.json
/// │   ├── config.json
/// │   ├── terminal_status.json
/// │   ├── inputs/
/// │   ├── snapshots/
/// │   ├── candidates/
/// │   ├── rejected/
/// │   ├── proved/
/// │   ├── minimized/
/// │   ├── fork-cache/
/// │   ├── reports/
/// │   └── telemetry/
/// ├── cache/  datasets/  tmp/
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLayout {
    root: PathBuf,
    owner_lock_dir: PathBuf,
}

impl RunLayout {
    /// Creates a run layout rooted at `.rustyfuzz/runs/<run_id>`.
    pub fn new(base: &Path, run_id: &str) -> Self {
        Self {
            root: base.join("runs").join(run_id),
            owner_lock_dir: base.join("locks"),
        }
    }

    /// Creates a run layout from an explicit root path.
    pub fn at_root(root: &Path) -> Self {
        let owner_lock_dir = root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".campaign-locks");
        Self {
            root: root.to_path_buf(),
            owner_lock_dir,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn acquire_campaign_lock(&self) -> Result<CampaignLock, crate::FsUtilError> {
        self.validate_canonical_run_id()?;
        let run_id = self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                crate::FsUtilError::InvalidData("run id is not valid UTF-8".to_string())
            })?;
        validate_run_id(run_id)?;
        ensure_directory_chain(&self.owner_lock_dir)?;
        let path = self.owner_lock_dir.join(format!(".{run_id}.campaign.lock"));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(crate::FsUtilError::InvalidData(
                "campaign lock is not a regular file".to_string(),
            ));
        }
        fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                crate::FsUtilError::InvalidData("campaign is already owned".to_string())
            } else {
                crate::FsUtilError::Io(error)
            }
        })?;
        Ok(CampaignLock {
            run_id: run_id.to_string(),
            _file: file,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn inputs_dir(&self) -> PathBuf {
        self.root.join("inputs")
    }

    pub fn snapshots_dir(&self) -> PathBuf {
        self.root.join("snapshots")
    }

    pub fn candidates_dir(&self) -> PathBuf {
        self.root.join("candidates")
    }

    pub fn rejected_dir(&self) -> PathBuf {
        self.root.join("rejected")
    }

    pub fn proved_dir(&self) -> PathBuf {
        self.root.join("proved")
    }

    pub fn minimized_dir(&self) -> PathBuf {
        self.root.join("minimized")
    }

    pub fn fork_cache_dir(&self) -> PathBuf {
        self.root.join("fork-cache")
    }

    pub fn reports_dir(&self) -> PathBuf {
        self.root.join("reports")
    }

    pub fn telemetry_dir(&self) -> PathBuf {
        self.root.join("telemetry")
    }

    pub fn terminal_status_path(&self) -> PathBuf {
        self.root.join("terminal_status.json")
    }

    pub fn terminal_state(&self) -> Option<RunTerminalState> {
        self.read_terminal_status()
            .ok()
            .flatten()
            .map(|status| status.state)
    }

    pub fn read_terminal_status(&self) -> Result<Option<RunTerminalStatus>, crate::FsUtilError> {
        let path = self.terminal_status_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(crate::FsUtilError::InvalidData(
                "terminal status is not a regular file".to_string(),
            ));
        }
        if metadata.len() > MAX_TERMINAL_STATUS_BYTES {
            return Err(crate::FsUtilError::InvalidData(
                "terminal status exceeds the size limit".to_string(),
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&path)?;
        let opened_metadata = file.metadata()?;
        if !opened_metadata.is_file() || opened_metadata.len() > MAX_TERMINAL_STATUS_BYTES {
            return Err(crate::FsUtilError::InvalidData(
                "terminal status changed while being read".to_string(),
            ));
        }
        let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
        file.by_ref()
            .take(MAX_TERMINAL_STATUS_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_TERMINAL_STATUS_BYTES {
            return Err(crate::FsUtilError::InvalidData(
                "terminal status exceeds the size limit".to_string(),
            ));
        }
        let status: RunTerminalStatus = serde_json::from_slice(&bytes)
            .map_err(|error| crate::FsUtilError::InvalidData(error.to_string()))?;
        status.validate().map_err(crate::FsUtilError::InvalidData)?;
        if self
            .root
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|parent| parent == "runs")
        {
            if let Some(expected_run_id) = self.root.file_name().and_then(|name| name.to_str()) {
                status
                    .validate_for_run_id(expected_run_id)
                    .map_err(crate::FsUtilError::InvalidData)?;
            }
        }
        Ok(Some(status))
    }

    /// Marks a newly created run as explicitly incomplete.
    pub fn mark_incomplete(&self, run_id: &str) -> Result<(), crate::FsUtilError> {
        self.write_terminal_status(run_id, RunTerminalState::Incomplete, None, None)
    }

    /// Atomically records a terminal state, never replacing an already-terminal
    /// outcome. This makes error cleanup idempotent after normal finalization.
    pub fn write_terminal_status(
        &self,
        run_id: &str,
        state: RunTerminalState,
        final_summary_path: Option<&Path>,
        final_summary_digest: Option<&str>,
    ) -> Result<(), crate::FsUtilError> {
        self.validate_canonical_run_id()
            .map_err(|error| crate::FsUtilError::InvalidData(error.to_string()))?;
        validate_run_id(run_id)?;
        let _lock = TerminalStatusLock::acquire(&self.root)?;
        if let Some(existing) = self.read_terminal_status()? {
            existing
                .validate_for_run_id(run_id)
                .map_err(crate::FsUtilError::InvalidData)?;
            if existing.state.is_terminal() {
                return Ok(());
            }
        }
        let status = RunTerminalStatus {
            schema_version: 1,
            terminal: state.is_terminal(),
            state,
            run_id: run_id.to_string(),
            final_summary_path: final_summary_path
                .map(crate::manifest::sanitize_path_for_persistence),
            final_summary_digest: final_summary_digest.map(str::to_string),
        };
        status
            .validate_for_run_id(run_id)
            .map_err(crate::FsUtilError::InvalidData)?;
        write_json_atomic(&self.terminal_status_path(), &status)
    }

    /// Creates every directory in the layout; idempotent.
    pub fn materialize(&self) -> std::io::Result<()> {
        self.validate_canonical_run_id()?;
        ensure_directory_chain(&self.root)?;
        self.materialize_inner()
    }

    /// Creates a fresh canonical run directory, rejecting an existing run ID.
    /// The exclusive root creation prevents a new manifest from coexisting with
    /// stale artifacts or terminal state from a prior attempt. If subdirectory
    /// creation fails after the exclusive root is created, the partially created
    /// root is removed so the campaign ID stays reusable instead of being burned.
    pub fn materialize_new(&self) -> std::io::Result<()> {
        self.validate_canonical_run_id()?;
        if let Some(parent) = self.root.parent() {
            ensure_directory_chain(parent)?;
        }
        std::fs::create_dir(&self.root)?;
        if let Err(error) = self.materialize_inner() {
            let _ = std::fs::remove_dir_all(&self.root);
            return Err(error);
        }
        Ok(())
    }

    fn validate_canonical_run_id(&self) -> std::io::Result<()> {
        if self.root.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("runs")) {
            let run_id = self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| std::io::Error::other("run id is not valid UTF-8"))?;
            validate_run_id(run_id).map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        Ok(())
    }

    fn materialize_inner(&self) -> std::io::Result<()> {
        for dir in [
            self.inputs_dir(),
            self.snapshots_dir(),
            self.candidates_dir(),
            self.rejected_dir(),
            self.proved_dir(),
            self.minimized_dir(),
            self.fork_cache_dir(),
            self.reports_dir(),
            self.telemetry_dir(),
        ] {
            ensure_directory_chain(&dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_layout_terminal_status_is_explicitly_incomplete_and_transitions_once() {
        let base =
            std::env::temp_dir().join(format!("rustyfuzz-terminal-layout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let layout = RunLayout::new(&base, "run-terminal");
        layout.materialize().unwrap();

        assert_eq!(layout.terminal_state(), None);
        layout.mark_incomplete("run-terminal").unwrap();
        assert_eq!(layout.terminal_state(), Some(RunTerminalState::Incomplete));

        let summary = layout.root().join("campaign_summary.json");
        layout
            .write_terminal_status(
                "run-terminal",
                RunTerminalState::Completed,
                Some(&summary),
                Some("sha256:test"),
            )
            .unwrap();
        assert_eq!(layout.terminal_state(), Some(RunTerminalState::Completed));

        layout
            .write_terminal_status("run-terminal", RunTerminalState::Failed, None, None)
            .unwrap();
        assert_eq!(layout.terminal_state(), Some(RunTerminalState::Completed));
        let raw = std::fs::read_to_string(layout.terminal_status_path()).unwrap();
        assert!(raw.contains("campaign_summary.json"));
        assert!(raw.contains("sha256:test"));
        assert!(!raw.contains("secret"));

        for (index, state) in [
            RunTerminalState::Partial,
            RunTerminalState::Cancelled,
            RunTerminalState::Failed,
        ]
        .into_iter()
        .enumerate()
        {
            let run_id = format!("run-state-{index}");
            let run_layout = RunLayout::new(&base, &run_id);
            run_layout.materialize().unwrap();
            run_layout.mark_incomplete(&run_id).unwrap();
            run_layout
                .write_terminal_status(&run_id, state, None, None)
                .unwrap();
            assert_eq!(run_layout.terminal_state(), Some(state));
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn existing_canonical_run_id_cannot_be_reused() {
        let base =
            std::env::temp_dir().join(format!("rustyfuzz-reused-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let layout = RunLayout::new(&base, "run-reused");
        layout.materialize().unwrap();

        assert!(layout.materialize_new().is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn terminal_status_rejects_schema_run_id_and_terminal_boolean_mismatches() {
        let base = std::env::temp_dir().join(format!(
            "rustyfuzz-terminal-validation-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let layout = RunLayout::new(&base, "run-valid");
        layout.materialize().unwrap();
        layout.mark_incomplete("run-valid").unwrap();

        for malformed in [
            serde_json::json!({
                "schema_version": 2,
                "terminal": false,
                "state": "incomplete",
                "run_id": "run-valid"
            }),
            serde_json::json!({
                "schema_version": 1,
                "terminal": false,
                "state": "incomplete",
                "run_id": "different-run"
            }),
            serde_json::json!({
                "schema_version": 1,
                "terminal": true,
                "state": "incomplete",
                "run_id": "run-valid"
            }),
        ] {
            std::fs::write(
                layout.terminal_status_path(),
                serde_json::to_vec(&malformed).unwrap(),
            )
            .unwrap();
            assert!(layout
                .write_terminal_status("run-valid", RunTerminalState::Failed, None, None)
                .is_err());
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn terminal_status_redacts_credential_like_summary_paths() {
        let base = std::env::temp_dir().join(format!(
            "rustyfuzz-terminal-redaction-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let layout = RunLayout::new(&base, "run-redaction");
        layout.materialize().unwrap();
        layout.mark_incomplete("run-redaction").unwrap();
        layout
            .write_terminal_status(
                "run-redaction",
                RunTerminalState::Completed,
                Some(Path::new("/tmp/api_key=secret/campaign_summary.json")),
                None,
            )
            .unwrap();

        let raw = std::fs::read_to_string(layout.terminal_status_path()).unwrap();
        assert!(!raw.contains("secret"));
        assert!(raw.contains("[redacted]"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn layout_rejects_symlinked_run_parent_and_traversal_run_id() {
        let base =
            std::env::temp_dir().join(format!("rustyfuzz-layout-symlink-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("rustyfuzz-layout-outside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("runs")).unwrap();
        assert!(RunLayout::new(&base, "safe-run").materialize().is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        assert!(RunLayout::new(&base, "../escape").materialize().is_err());
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn terminal_status_rejects_oversized_files() {
        let base =
            std::env::temp_dir().join(format!("rustyfuzz-layout-oversized-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let layout = RunLayout::new(&base, "run-oversized");
        layout.materialize().unwrap();
        std::fs::write(
            layout.terminal_status_path(),
            vec![b'x'; MAX_TERMINAL_STATUS_BYTES as usize + 1],
        )
        .unwrap();
        assert!(layout.read_terminal_status().is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn concurrent_terminal_transitions_preserve_one_terminal_state() {
        let base = std::env::temp_dir().join(format!(
            "rustyfuzz-layout-concurrent-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let layout = RunLayout::new(&base, "run-concurrent");
        layout.materialize().unwrap();
        layout.mark_incomplete("run-concurrent").unwrap();
        let first = layout.clone();
        let second = layout.clone();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                first.write_terminal_status(
                    "run-concurrent",
                    RunTerminalState::Completed,
                    None,
                    None,
                )
            });
            scope.spawn(move || {
                second.write_terminal_status("run-concurrent", RunTerminalState::Failed, None, None)
            });
        });
        assert!(layout
            .terminal_state()
            .is_some_and(RunTerminalState::is_terminal));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn campaign_lock_is_exclusive_and_outside_evidence_tree() {
        let base =
            std::env::temp_dir().join(format!("rustyfuzz-layout-owner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let layout = RunLayout::new(&base, "run-owner");
        let first = layout.acquire_campaign_lock().unwrap();
        assert!(layout.acquire_campaign_lock().is_err());
        assert!(!layout.root().join("campaign.lock").exists());
        layout.materialize().unwrap();
        assert!(!base.join("runs").read_dir().unwrap().any(|entry| entry
            .unwrap()
            .file_type()
            .unwrap()
            .is_file()));
        assert!(base.join("locks/.run-owner.campaign.lock").is_file());
        drop(first);
        let second = layout.acquire_campaign_lock().unwrap();
        drop(second);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn run_layout_paths_are_consistent_and_materialize() {
        let base = std::env::temp_dir().join(format!("rustyfuzz-layout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let layout = RunLayout::new(&base, "run-0001");

        assert_eq!(layout.root(), base.join("runs").join("run-0001"));
        assert_eq!(layout.config_file(), layout.root().join("config.json"));

        layout.materialize().unwrap();
        assert!(layout.inputs_dir().is_dir());
        assert!(layout.snapshots_dir().is_dir());
        assert!(layout.candidates_dir().is_dir());
        assert!(layout.rejected_dir().is_dir());
        assert!(layout.proved_dir().is_dir());
        assert!(layout.minimized_dir().is_dir());
        assert!(layout.fork_cache_dir().is_dir());
        assert!(layout.reports_dir().is_dir());
        assert!(layout.telemetry_dir().is_dir());

        // Idempotent.
        layout.materialize().unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }
}
