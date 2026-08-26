//! Dependency-neutral execution result primitives.

use serde::{Deserialize, Serialize};

/// Coarse transaction execution status independent of REVM result internals.
///
/// The JSON representation intentionally matches the pre-workspace
/// `common::types::ExecutionStatus` enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ExecutionStatus {
    /// Execution completed successfully.
    Success,
    /// Execution reverted.
    Revert,
    /// Execution halted for a backend-provided reason.
    Halt(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_status_json_matches_existing_shape() {
        assert_eq!(
            serde_json::to_string(&ExecutionStatus::Success).unwrap(),
            "\"Success\""
        );
        assert_eq!(
            serde_json::to_string(&ExecutionStatus::Revert).unwrap(),
            "\"Revert\""
        );
        assert_eq!(
            serde_json::to_string(&ExecutionStatus::Halt("OutOfGas".to_string())).unwrap(),
            "{\"Halt\":\"OutOfGas\"}"
        );
    }

    #[test]
    fn execution_status_round_trips() {
        for status in [
            ExecutionStatus::Success,
            ExecutionStatus::Revert,
            ExecutionStatus::Halt("StackUnderflow".to_string()),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let decoded: ExecutionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, status);
        }
    }
}
