use crate::common::oracle::{ProtocolFinding, ProtocolSeverity, VulnType};
use crate::common::types::SequenceExecutionResult;
use crate::evm::feedback::StateNoveltyReport;
use crate::evm::fuzz::EvmInput;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampaignScore {
    pub total: u64,
    pub economic_pressure: u64,
    pub invariant_pressure: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignScoringConfig {
    pub large_storage_delta: U256,
    pub max_score: u64,
}

impl Default for CampaignScoringConfig {
    fn default() -> Self {
        Self {
            large_storage_delta: U256::from(10u128.pow(18)),
            max_score: 10_000,
        }
    }
}

#[derive(Default)]
pub struct CampaignScorer {
    pub config: CampaignScoringConfig,
}

impl CampaignScorer {
    pub fn new(config: CampaignScoringConfig) -> Self {
        Self { config }
    }

    pub fn score(
        &self,
        input: &EvmInput,
        execution: &SequenceExecutionResult,
        state_novelty: &StateNoveltyReport,
        findings: &[ProtocolFinding],
    ) -> CampaignScore {
        let mut explanation = Vec::new();
        let economic_pressure = self.economic_pressure(execution, findings, &mut explanation);
        let invariant_pressure = self.invariant_pressure(findings, input, &mut explanation);
        let oracle_pressure = self.oracle_pressure(findings, &mut explanation);
        let state_pressure = state_novelty.novelty_score();
        if state_pressure > 0 {
            explanation.push(format!("state_novelty={state_pressure}"));
        }
        let exploration_pressure = self.exploration_pressure(input, execution, &mut explanation);

        let total = economic_pressure
            .saturating_add(invariant_pressure)
            .saturating_add(oracle_pressure)
            .saturating_add(state_pressure)
            .saturating_add(exploration_pressure)
            .min(self.config.max_score);

        CampaignScore {
            total,
            economic_pressure,
            invariant_pressure,
            oracle_pressure,
            state_pressure,
            exploration_pressure,
            explanation,
        }
    }

    fn economic_pressure(
        &self,
        execution: &SequenceExecutionResult,
        findings: &[ProtocolFinding],
        explanation: &mut Vec<String>,
    ) -> u64 {
        let large_deltas = execution
            .storage_diffs
            .iter()
            .filter(|diff| {
                let delta = if diff.new_value > diff.old_value {
                    diff.new_value - diff.old_value
                } else {
                    diff.old_value - diff.new_value
                };
                delta >= self.config.large_storage_delta
            })
            .count() as u64;
        let economic_findings = findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.vuln,
                    VulnType::FlashLoanProfit
                        | VulnType::FlashLoanAttack
                        | VulnType::PriceManipulation
                        | VulnType::PriceOracleManipulation
                        | VulnType::VaultDonationAttack
                        | VulnType::VaultInflation
                        | VulnType::MevSandwichExploit
                        | VulnType::UniswapV3LiquidityAsymmetry
                        | VulnType::AccountingDesync
                        | VulnType::RebalanceValueLoss
                )
            })
            .count() as u64;
        let score = large_deltas * 40 + economic_findings * 600;
        if score > 0 {
            explanation.push(format!(
                "economic_pressure: large_deltas={large_deltas}, economic_findings={economic_findings}"
            ));
        }
        score
    }

    fn invariant_pressure(
        &self,
        findings: &[ProtocolFinding],
        input: &EvmInput,
        explanation: &mut Vec<String>,
    ) -> u64 {
        let invariant_findings = findings
            .iter()
            .filter(|finding| matches!(finding.vuln, VulnType::InvariantViolation(_)))
            .count() as u64;
        let governance_or_critical = findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.vuln,
                    VulnType::GovernanceTakeover
                        | VulnType::GovernanceParameterManipulation
                        | VulnType::PrivilegeEscalation
                        | VulnType::SystemicStateCorruption
                ) || finding.severity == ProtocolSeverity::Critical
            })
            .count() as u64;
        let oracle_guided_mutations = input
            .mutation_provenance
            .iter()
            .filter(|mutation| {
                matches!(
                    mutation.strategy.as_str(),
                    "oracle_pressure" | "mev_sandwich" | "flashloan_wrap"
                )
            })
            .count() as u64;
        let score =
            invariant_findings * 700 + governance_or_critical * 900 + oracle_guided_mutations * 50;
        if score > 0 {
            explanation.push(format!(
                "invariant_pressure: invariant_findings={invariant_findings}, critical={governance_or_critical}, guided_mutations={oracle_guided_mutations}"
            ));
        }
        score
    }

    fn oracle_pressure(&self, findings: &[ProtocolFinding], explanation: &mut Vec<String>) -> u64 {
        let score: u64 = findings
            .iter()
            .map(|finding| match finding.severity {
                ProtocolSeverity::Info => 5,
                ProtocolSeverity::Low => 25,
                ProtocolSeverity::Medium => 100,
                ProtocolSeverity::High => 350,
                ProtocolSeverity::Critical => 900,
            })
            .sum();
        if score > 0 {
            explanation.push(format!("oracle_pressure: findings={}", findings.len()));
        }
        score
    }

    fn exploration_pressure(
        &self,
        input: &EvmInput,
        execution: &SequenceExecutionResult,
        explanation: &mut Vec<String>,
    ) -> u64 {
        let successful_txs = execution
            .tx_results
            .iter()
            .filter(|result| {
                matches!(
                    result.status,
                    crate::common::types::ExecutionStatus::Success
                )
            })
            .count() as u64;
        let call_depth = execution
            .call_trace
            .iter()
            .map(|call| call.depth)
            .max()
            .unwrap_or_default() as u64;
        let sequence_depth = input.txs.len() as u64;
        let score = successful_txs * 5 + call_depth * 10 + sequence_depth.saturating_sub(1) * 15;
        if score > 0 {
            explanation.push(format!(
                "exploration_pressure: successful_txs={successful_txs}, call_depth={call_depth}, sequence_depth={sequence_depth}"
            ));
        }
        score
    }
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
