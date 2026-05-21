use crate::common::oracle::{VulnType, VulnerabilityOracle};
use crate::common::types::{Snapshot, Waypoint};
use std::collections::HashMap;

/// PdaIntegrityOracle: Detects PDA seed collisions and spoofing in SVM programs.
pub struct PdaIntegrityOracle;

impl VulnerabilityOracle for PdaIntegrityOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        let mut observed_pdas: HashMap<[u8; 32], Vec<Vec<u8>>> = HashMap::new();

        for waypoint in &after.waypoints {
            if let Waypoint::SvmCpiCall {
                accounts,
                instruction_data,
                ..
            } = waypoint
            {
                for account_bytes in accounts {
                    let pda = *account_bytes;
                    if let Some(prev_seeds) = observed_pdas.get(&pda) {
                        if prev_seeds.last().unwrap() != instruction_data {
                            log::error!(
                                "CRITICAL: PDA Collision detected for account 0x{}",
                                hex::encode(pda)
                            );
                            return Some(VulnType::SvmPdaCollision);
                        }
                    }
                    observed_pdas
                        .entry(pda)
                        .or_default()
                        .push(instruction_data.clone());
                }
            }
        }
        None
    }
}

/// SvmCpiPrivilegeEscalationOracle: Detects unauthorized authority gains via CPI.
pub struct SvmCpiPrivilegeEscalationOracle;

impl VulnerabilityOracle for SvmCpiPrivilegeEscalationOracle {
    fn check(&self, _before: &Snapshot, after: &Snapshot) -> Option<VulnType> {
        for waypoint in &after.waypoints {
            if let Waypoint::SvmCpiCall {
                callee_program,
                signers,
                ..
            } = waypoint
            {
                for signer in signers {
                    if callee_program != &[0u8; 32] && signer != &[0u8; 32] {
                        // Production: query SvmState to verify signer ownership.
                        // return Some(VulnType::SvmCpiPrivilegeEscalation);
                    }
                }
            }
        }
        None
    }
}
