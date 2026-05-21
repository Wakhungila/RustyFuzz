use crate::common::oracle::{VulnType, VulnerabilityOracle};
use crate::common::types::{Snapshot, Waypoint};
use revm::primitives::Address;
use std::collections::HashSet;

/// GovernanceParameterOracle: Detects unauthorized changes to critical governance parameters.
pub struct GovernanceParameterOracle {
    pub authorized_callers: HashSet<Address>,
}

impl VulnerabilityOracle for GovernanceParameterOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::GovernanceAction { caller, .. } = waypoint {
                if !self.authorized_callers.contains(caller) {
                    return Some(VulnType::GovernanceParameterManipulation);
                }
            }
        }
        None
    }
}

/// GovernanceFlashLoanOracle: Detects Beanstalk-style governance attacks.
pub struct GovernanceFlashLoanOracle {
    pub fuzzer_address: Address,
}

impl VulnerabilityOracle for GovernanceFlashLoanOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let has_flashloan = after
            .waypoints
            .iter()
            .any(|w| matches!(w, Waypoint::FlashloanExecution { .. }));

        for waypoint in &after.waypoints {
            if let Waypoint::GovernanceAction {
                selector, caller, ..
            } = waypoint
            {
                if *selector == [0xfe, 0x0d, 0x94, 0xc1] && *caller == self.fuzzer_address {
                    if has_flashloan {
                        return Some(VulnType::GovernanceTakeover);
                    }
                    if after.depth < 5 {
                        return Some(VulnType::GovernanceTakeover);
                    }
                }
            }
        }
        None
    }
}
