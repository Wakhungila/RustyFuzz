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

pub use layout::RunLayout;
pub use manifest::{
    sanitize_rpc_endpoint, ManifestError, RunManifest, RUN_MANIFEST_SCHEMA_VERSION,
};
