use crate::common::oracle::VulnType;
use crate::evm::trace::ExecutionTrace;
use crate::evm::economic::ProfitReport;
use revm::primitives::U256;

#[derive(Debug, Clone)]
pub struct SeverityScore {
    pub total: f32,
    pub reachability: f32,
    pub privilege: f32,
    pub economic_impact: f32,
    pub exploitability: f32,
    pub state_corruption: f32,
    pub confidence: f32,
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
        // A. Reachability (0-1): Based on call depth and sequence complexity
        let reachability = if seq_len <= 1 { 1.0 } else if seq_len <= 3 { 0.8 } else { 0.5 };

        // B. Privilege Escalation (0-1): Did we hit AccessControl or DelegateCall patterns?
        let privilege = match vuln {
            VulnType::PrivilegeEscalation => 1.0,
            _ => if trace.calls.iter().any(|c| c.is_delegate) { 0.6 } else { 0.0 },
        };

        // C. Economic Impact (0-1): funds_drained / TVL
        let total_profit_eth = profit.eth_profit; // Simplified for demo
        let economic_impact = if self.protocol_tvl > U256::ZERO {
            let ratio = (total_profit_eth * U256::from(100)) / self.protocol_tvl;
            (ratio.to::<u64>() as f32 / 100.0).min(1.0)
        } else {
            0.0
        };

        // D. Exploitability (0-1): Simplicity of reproduction
        let exploitability = 1.0 / (seq_len as f32).max(1.0);

        // E. State Corruption (0-1): Intensity of storage modifications
        let state_corruption = (trace.state_changes.len() as f32 / 50.0).min(1.0);

        // F. Invariant Boost: If it's an invariant violation, it's highly likely a logic collapse
        let invariant_boost = match vuln {
            VulnType::InvariantViolation(_) | VulnType::UniswapV3LiquidityAsymmetry => 40.0,
            _ => 0.0,
        };

        let mut total = (reachability * 25.0)
            + (privilege * 25.0)
            + (economic_impact * 25.0)
            + (exploitability * 15.0)
            + (state_corruption * 10.0)
            + invariant_boost;

        total = total.min(100.0);

        // Confidence Score: High if reproducible and based on strong signals
        let confidence = if trace.success { 0.9 } else { 0.4 };

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