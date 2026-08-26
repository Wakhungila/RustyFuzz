//! Dependency-neutral testcase metadata skeletons.
//!
//! These types are destinations for later migration. Stage 2A does not alter
//! the current `EvmInput` fields, input hashing, corpus serialization, or
//! scheduler scoring behavior.

use crate::{InputId, SnapshotId};
use serde::{Deserialize, Serialize};

/// Execution and scheduling metadata associated with a testcase.
///
/// This is intentionally minimal. Concrete coverage maps, waypoints,
/// comparison hints, and scheduler internals remain in the monolith until Stage
/// 2B and later engine extraction stages define their compatibility paths.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestcaseMetadata {
    /// Stable semantic input identifier once one is assigned.
    pub input_id: Option<InputId>,
    /// Starting snapshot used by this testcase.
    pub base_snapshot_id: Option<SnapshotId>,
    /// Parent testcase, if produced by mutation.
    pub parent_input_id: Option<InputId>,
    /// Names of mutation strategies that contributed to this testcase.
    pub mutation_strategies: Vec<String>,
}

impl TestcaseMetadata {
    /// Creates empty testcase metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a mutation strategy name.
    pub fn push_mutation_strategy(&mut self, strategy: impl Into<String>) {
        self.mutation_strategies.push(strategy.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testcase_metadata_round_trips_json() {
        let mut metadata = TestcaseMetadata {
            input_id: Some(InputId::new("input-b").unwrap()),
            base_snapshot_id: Some(SnapshotId::new(9)),
            parent_input_id: Some(InputId::new("input-a").unwrap()),
            mutation_strategies: Vec::new(),
        };
        metadata.push_mutation_strategy("abi_sequence_insert");

        let json = serde_json::to_string(&metadata).unwrap();
        assert_eq!(
            json,
            "{\"input_id\":\"input-b\",\"base_snapshot_id\":9,\"parent_input_id\":\"input-a\",\"mutation_strategies\":[\"abi_sequence_insert\"]}"
        );
        let decoded: TestcaseMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, metadata);
    }
}
