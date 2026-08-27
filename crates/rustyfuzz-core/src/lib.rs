//! Stable domain types for RustyFuzz.
//!
//! `rustyfuzz-core` owns boring, durable concepts: strongly typed identifiers,
//! dependency-neutral execution summaries, snapshot metadata, finding/evidence
//! references, testcase metadata skeletons, and typed errors for those APIs.
//!
//! This crate must never depend on execution backends, fuzzing frameworks,
//! network clients, AI providers, or CLI frameworks. In particular it must not
//! depend on REVM, Alloy, LibAFL, RPC/HTTP clients, Satori, or `clap`.
//!
//! Public serialized types in this crate are treated as artifact-facing schema
//! pieces. JSON field names, enum variant names, and textual ID forms should
//! change only with an explicit migration plan.

pub mod error;
pub mod execution;
pub mod finding;
pub mod ids;
pub mod metadata;
pub mod proposal;
pub mod snapshot;

pub use error::{CoreError, CoreResult};
pub use execution::ExecutionStatus;
pub use finding::{
    EvidenceKind, EvidenceRef, FindingIdentity, FindingLifecycle, IllegalTransition, OracleSignal,
    SignalStrength,
};
pub use ids::{CampaignId, EvidenceId, FindingId, InputId, OracleId, SnapshotId};
pub use metadata::TestcaseMetadata;
pub use proposal::{AiProposal, ProposalKind, ProposalValidation};
pub use snapshot::{SnapshotMetadata, StateFingerprint};
