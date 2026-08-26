//! Typed errors for core domain APIs.

use thiserror::Error;

/// Result alias used by `rustyfuzz-core` APIs.
pub type CoreResult<T> = Result<T, CoreError>;

/// Errors produced by stable core domain types.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CoreError {
    /// An identifier was empty.
    #[error("{kind} identifier must not be empty")]
    EmptyId {
        /// Human-readable identifier kind.
        kind: &'static str,
    },

    /// An identifier failed format validation.
    #[error("invalid {kind} identifier `{value}`: {reason}")]
    InvalidId {
        /// Human-readable identifier kind.
        kind: &'static str,
        /// Rejected identifier text.
        value: String,
        /// Stable validation reason.
        reason: &'static str,
    },
}
