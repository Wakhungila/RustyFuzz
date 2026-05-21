use crate::common::oracle::VulnType;
use crate::evm::trace::ExecutionTrace;
use revm::primitives::U256;
use serde::{Deserialize, Serialize};

// TODO: Missing module - stub or implement
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfitReport {
    pub profit: U256,
    pub loss: U256,
}

impl Default for ProfitReport {
    fn default() -> Self {
        Self {
            profit: U256::ZERO,
            loss: U256::ZERO,
        }
    }
}

impl ProfitReport {
    pub fn is_significant(&self, _threshold: u64) -> bool {
        self.profit > U256::ZERO
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityScore {
    pub total: u32,            // 0-10000 (scaled by 100)
    pub reachability: u32,     // 0-100
    pub privilege: u32,        // 0-100
    pub economic_impact: u32,  // 0-100
    pub exploitability: u32,   // 0-100
    pub state_corruption: u32, // 0-100
    pub confidence: u32,       // 0-100
}

pub struct ScoringEngine {
    pub protocol_tvl: U256,
}

impl ScoringEngine {
    pub fn new(tvl: U256) -> Self {
        Self { protocol_tvl: tvl }
    }

    /// Computes a P0-centric severity score based on the weighted exploitability model.
    pub fn calculate(
        &self,
        trace: &ExecutionTrace,
        vuln: &VulnType,
        profit: &ProfitReport,
        seq_len: usize,
    ) -> SeverityScore {
        // A. Reachability (0-100): Based on call depth and sequence complexity
        let reachability = if seq_len <= 1 {
            100
        } else if seq_len <= 3 {
            80
        } else {
            50
        };

        // B. Privilege Escalation (0-100): Weighted heavily for Pashov's triage workflow.
        // Access control bypasses are the highest-priority findings.
        let privilege = match vuln {
            VulnType::PrivilegeEscalation => 100,
            VulnType::GovernanceParameterManipulation => 90,
            _ => {
                if trace.calls.iter().any(|c| c.is_delegate) {
                    70
                } else {
                    0
                }
            }
        };

        // C. Economic Impact (0-100): funds_drained / TVL
        let total_profit_eth = profit.profit; // Simplified for demo
        let economic_impact = if self.protocol_tvl > U256::ZERO {
            let ratio = (total_profit_eth * U256::from(100)) / self.protocol_tvl;
            ratio.to::<u64>() as u32
        } else {
            0
        };

        // D. Exploitability (0-100): Shorter sequences are much easier to report.
        let exploitability = if seq_len <= 2 {
            100
        } else {
            100 / (seq_len as u32)
        };

        // E. State Corruption (0-100): Intensity of storage modifications
        let state_corruption = ((trace.state_changes.len() as u32 * 100) / 50).min(100);

        // F. Criticality Multipliers: Boost findings that map to known P0 archetypes.
        let boost: u32 = match vuln {
            VulnType::InvariantViolation(_) | VulnType::UniswapV3LiquidityAsymmetry => 4000, // 40.0 * 100
            VulnType::MevSandwichExploit | VulnType::VaultDonationAttack => 3000,
            _ => 0,
        };

        // Adjusted weights: Prioritize Privilege (30%) and Impact (30%) over sequence complexity.
        let mut total = (reachability * 20)
            + (privilege * 30)
            + (economic_impact * 30)
            + (exploitability * 10)
            + (state_corruption * 10)
            + boost;

        total = total.min(10000);

        // Confidence Score (0-100)
        let confidence = if trace.success { 90 } else { 40 };

        SeverityScore {
            total,
            reachability,
            privilege,
            economic_impact,
            exploitability,
            state_corruption,
            confidence,
        }
    }

    pub fn get_label(&self, score: &SeverityScore) -> &'static str {
        if score.total >= 8000 && score.confidence > 80 {
            "P0 / CRITICAL"
        } else if score.total >= 6000 {
            "HIGH"
        } else if score.total >= 3000 {
            "MEDIUM"
        } else {
            "LOW"
        }
    }
}
