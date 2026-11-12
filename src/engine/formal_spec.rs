use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemporalConstraint {
    pub id: String,
    pub kind: TemporalConstraintKind,
    pub functions: Vec<String>,
    pub max_gap_blocks: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemporalConstraintKind {
    MustPrecede,     // first function must be called before second
    CannotFollow,    // second function cannot be called after first
    RequireInterval, // functions must be called within N blocks
    OneTimeOnly,     // function can only be called once per sequence
}
