//! Campaign scoring primitives shared by the fuzzer and scheduler.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampaignScore {
    pub total: u64,
    pub economic_pressure: u64,
    pub invariant_pressure: u64,
    pub counterexample_pressure: u64,
    pub oracle_pressure: u64,
    pub state_pressure: u64,
    pub exploration_pressure: u64,
    pub explanation: Vec<String>,
}

impl CampaignScore {
    pub fn is_interesting(&self) -> bool {
        self.total > 0
    }
}
