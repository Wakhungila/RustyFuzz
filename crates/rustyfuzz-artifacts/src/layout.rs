//! Canonical run layout for campaign artifacts.
//!
//! One authoritative mapping from artifact kind to filesystem path, so no
//! caller reconstructs paths ad hoc. The layout does not own policy (what to
//! persist is the fuzzer's decision); it owns *where*.

use std::path::{Path, PathBuf};

/// Root-relative structure of one fuzzing run.
///
/// ```text
/// .rustyfuzz/
/// ├── runs/<run-id>/           <- RunLayout rooted here
/// │   ├── manifest.json
/// │   ├── config.json
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
}

impl RunLayout {
    /// Creates a run layout rooted at `.rustyfuzz/runs/<run_id>`.
    pub fn new(base: &Path, run_id: &str) -> Self {
        Self {
            root: base.join("runs").join(run_id),
        }
    }

    /// Creates a run layout from an explicit root path.
    pub fn at_root(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
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

    /// Creates every directory in the layout; idempotent.
    pub fn materialize(&self) -> std::io::Result<()> {
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
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
