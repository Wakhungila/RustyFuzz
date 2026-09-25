//! Artifact persistence for RustyFuzz: run layouts, versioned schemas, atomic
//! writes.
//!
//! Global invariant #7: anything persisted carries an explicit schema version.
//! This crate owns *where* and *how safely* bytes hit disk. It deliberately
//! knows nothing about fuzzing policy; production callers hand it typed data.

pub mod fsutil;

pub use fsutil::FsUtilError;
pub mod layout;
pub mod manifest;

pub use layout::{validate_run_id, CampaignLock, RunLayout, RunTerminalState, RunTerminalStatus};
pub use manifest::{
    sanitize_path_for_persistence, sanitize_rpc_endpoint, Environment, ManifestError, RunManifest,
    RuntimeEnvironmentFingerprint, SourceIdentity, RUN_MANIFEST_SCHEMA_VERSION,
};
