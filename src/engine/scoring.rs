use crate::common::oracle::VulnType;
use crate::evm::trace::ExecutionTrace;
use crate::evm::economic::ProfitReport;
use revm::primitives::U256;

#[derive(Debug, Clone)]
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
        let reachability = if seq_len <= 1 { 100 } else if seq_len <= 3 { 80 } else { 50 };

        // B. Privilege Escalation (0-100): Did we hit AccessControl or DelegateCall patterns?
        let privilege = match vuln {
            VulnType::PrivilegeEscalation => 100,
            _ => if trace.calls.iter().any(|c| c.is_delegate) { 60 } else { 0 },
        };

        // C. Economic Impact (0-100): funds_drained / TVL
        let total_profit_eth = profit.eth_profit; // Simplified for demo
        let economic_impact = if self.protocol_tvl > U256::ZERO {
            let ratio = (total_profit_eth * U256::from(100)) / self.protocol_tvl;
            ratio.to::<u64>() as u32
        } else {
            0
        };

        // D. Exploitability (0-100): Inverse of sequence length
        let exploitability = 100 / (seq_len as u32).max(1);

        // E. State Corruption (0-100): Intensity of storage modifications
        let state_corruption = ((trace.state_changes.len() as u32 * 100) / 50).min(100);

        // F. Invariant Boost: If it's an invariant violation, boost score by 40 points
        let invariant_boost: u32 = match vuln {
            VulnType::InvariantViolation(_) | VulnType::UniswapV3LiquidityAsymmetry => 4000, // 40.0 * 100
            _ => 0,
        };

        let mut total = (reachability * 25)
            + (privilege * 25)
            + (economic_impact * 25)
            + (exploitability * 15)
            + (state_corruption * 10)
            + invariant_boost;

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
        if score.total >= 80.0 && score.confidence > 0.8 {
            "P0 / CRITICAL"
        } else if score.total >= 60.0 {
            "HIGH"
        } else if score.total >= 30.0 {
            "MEDIUM"
        } else {
            "LOW"
        }
    }
}