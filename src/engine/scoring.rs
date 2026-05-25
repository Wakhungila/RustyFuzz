use crate::common::oracle::{ProtocolFinding, ProtocolSeverity, VulnType};
use crate::common::types::{
    CallKind, CallPhase, SequenceExecutionResult, SymbolicExpression, TaintSource, Waypoint,
};
use crate::engine::dependency::dependency_sequence_score;
use crate::engine::exploit_path::exploit_path_score;
use crate::engine::protocol_model::FormalProtocolModel;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignScoringConfig {
    pub large_storage_delta: U256,
    pub max_score: u64,
    pub large_delta_weight: u64,
    pub economic_finding_weight: u64,
    pub invariant_finding_weight: u64,
    pub critical_finding_weight: u64,
    pub oracle_guided_mutation_weight: u64,
    pub successful_tx_weight: u64,
    pub call_depth_weight: u64,
    pub sequence_depth_weight: u64,
    pub near_miss_weight: u64,
    pub expression_backed_weight: u64,
    pub mapping_backed_weight: u64,
}

impl Default for CampaignScoringConfig {
    fn default() -> Self {
        Self {
            large_storage_delta: U256::from(10u128.pow(18)),
            max_score: 10_000,
            large_delta_weight: 40,
            economic_finding_weight: 600,
            invariant_finding_weight: 700,
            critical_finding_weight: 900,
            oracle_guided_mutation_weight: 50,
            successful_tx_weight: 5,
            call_depth_weight: 10,
            sequence_depth_weight: 15,
            near_miss_weight: 40,
            expression_backed_weight: 15,
            mapping_backed_weight: 25,
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
        let protocol_model = FormalProtocolModel::synthesize(input, execution, findings, None);
        let counterexample_pressure = protocol_model.counterexample_pressure();
        if counterexample_pressure > 0 {
            explanation.push(format!(
                "formal_protocol_model: confidence={}, pressure={}, invariants={}, protocols={:?}",
                protocol_model.confidence,
                counterexample_pressure,
                protocol_model.invariant_hypotheses.len(),
                protocol_model.inferred_protocol_types
            ));
        }
        let oracle_pressure = self.oracle_pressure(findings, &mut explanation);
        let state_pressure = state_novelty.novelty_score();
        if state_pressure > 0 {
            explanation.push(format!("state_novelty={state_pressure}"));
        }
        let mut exploration_pressure =
            self.exploration_pressure(input, execution, &mut explanation);
        let dataflow_pressure = self.dataflow_pressure(input, execution, &mut explanation);
        exploration_pressure = exploration_pressure.saturating_add(dataflow_pressure);
        let dependency_pressure = dependency_sequence_score(input);
        if dependency_pressure > 0 {
            explanation.push(format!(
                "dependency-aware sequence pressure {dependency_pressure}"
            ));
            exploration_pressure = exploration_pressure.saturating_add(dependency_pressure);
        }
        let exploit_pressure = exploit_path_score(input);
        if exploit_pressure > 0 {
            explanation.push(format!(
                "exploit-directed sequence pressure {exploit_pressure}"
            ));
            exploration_pressure = exploration_pressure.saturating_add(exploit_pressure);
        }
        let branch_pressure = self.branch_frontier_pressure(execution, &mut explanation);

        let total = economic_pressure
            .saturating_add(invariant_pressure)
            .saturating_add(counterexample_pressure)
            .saturating_add(oracle_pressure)
            .saturating_add(state_pressure)
            .saturating_add(exploration_pressure)
            .saturating_add(branch_pressure)
            .min(self.config.max_score);

        CampaignScore {
            total,
            economic_pressure,
            invariant_pressure,
            counterexample_pressure,
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
        let score = large_deltas
            .saturating_mul(self.config.large_delta_weight)
            .saturating_add(economic_findings.saturating_mul(self.config.economic_finding_weight));
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
        let score = invariant_findings
            .saturating_mul(self.config.invariant_finding_weight)
            .saturating_add(
                governance_or_critical.saturating_mul(self.config.critical_finding_weight),
            )
            .saturating_add(
                oracle_guided_mutations.saturating_mul(self.config.oracle_guided_mutation_weight),
            );
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
        let score = successful_txs
            .saturating_mul(self.config.successful_tx_weight)
            .saturating_add(call_depth.saturating_mul(self.config.call_depth_weight))
            .saturating_add(
                sequence_depth
                    .saturating_sub(1)
                    .saturating_mul(self.config.sequence_depth_weight),
            );
        if score > 0 {
            explanation.push(format!(
                "exploration_pressure: successful_txs={successful_txs}, call_depth={call_depth}, sequence_depth={sequence_depth}"
            ));
        }
        score
    }

    fn branch_frontier_pressure(
        &self,
        execution: &SequenceExecutionResult,
        explanation: &mut Vec<String>,
    ) -> u64 {
        let mut near_misses = 0u64;
        let mut expression_backed = 0u64;
        let mut mapping_backed = 0u64;

        for waypoint in execution
            .tx_results
            .iter()
            .flat_map(|result| result.waypoints.iter())
        {
            match waypoint {
                Waypoint::Comparison {
                    branch_distance: Some(distance),
                    lhs_expression,
                    rhs_expression,
                    ..
                } => {
                    if *distance <= U256::from(256) {
                        near_misses += 1;
                    }
                    if lhs_expression.is_some() || rhs_expression.is_some() {
                        expression_backed += 1;
                    }
                }
                Waypoint::MappingDerivation {
                    key_expression,
                    base_slot_expression,
                    ..
                } => {
                    if key_expression.is_some() || base_slot_expression.is_some() {
                        mapping_backed += 1;
                    }
                }
                _ => {}
            }
        }

        let score = near_misses
            .saturating_mul(self.config.near_miss_weight)
            .saturating_add(expression_backed.saturating_mul(self.config.expression_backed_weight))
            .saturating_add(mapping_backed.saturating_mul(self.config.mapping_backed_weight));
        if score > 0 {
            explanation.push(format!(
                "branch_frontier: near_misses={near_misses}, expression_backed={expression_backed}, mapping_backed={mapping_backed}"
            ));
        }
        score
    }

    fn dataflow_pressure(
        &self,
        input: &EvmInput,
        execution: &SequenceExecutionResult,
        explanation: &mut Vec<String>,
    ) -> u64 {
        let report = DataflowScoreReport::from_execution(input, execution);
        let score = report.score();
        if score > 0 {
            explanation.push(format!(
                "dataflow_pressure: score={}, calldata_to_storage={}, caller_role_checks={}, approval_transfer_flows={}, oracle_to_lending={}, amount_to_accounting={}, evidence={}",
                score,
                report.calldata_to_storage,
                report.caller_role_checks,
                report.approval_to_transfer_from,
                report.oracle_read_to_borrow_or_liquidate,
                report.amount_to_share_debt_or_reserve,
                report.evidence.join(" | ")
            ));
        }
        score
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataflowScoreReport {
    pub calldata_to_storage: u64,
    pub caller_role_checks: u64,
    pub approval_to_transfer_from: u64,
    pub oracle_read_to_borrow_or_liquidate: u64,
    pub amount_to_share_debt_or_reserve: u64,
    pub evidence: Vec<String>,
}

impl DataflowScoreReport {
    pub fn from_execution(input: &EvmInput, execution: &SequenceExecutionResult) -> Self {
        let mut report = Self::default();
        let selectors = input
            .txs
            .iter()
            .map(|tx| selector_for_calldata(&tx.input))
            .collect::<Vec<_>>();

        for result in &execution.tx_results {
            for waypoint in &result.waypoints {
                match waypoint {
                    Waypoint::StorageWrite {
                        tx_idx,
                        taint_source_of_value: Some(TaintSource::Calldata(offset)),
                        value_expression,
                        ..
                    } => {
                        report.calldata_to_storage += 1;
                        if is_accounting_selector(selectors.get(*tx_idx).copied().flatten())
                            || expression_uses_calldata(value_expression)
                        {
                            report.amount_to_share_debt_or_reserve += 1;
                            report.evidence.push(format!(
                                "calldata offset {offset} reached accounting storage in tx {tx_idx}"
                            ));
                        } else {
                            report.evidence.push(format!(
                                "calldata offset {offset} reached storage in tx {tx_idx}"
                            ));
                        }
                    }
                    Waypoint::StorageWrite {
                        tx_idx,
                        taint_source_of_value: Some(TaintSource::Storage(origin_tx, offset)),
                        ..
                    } => {
                        report.calldata_to_storage += 1;
                        report.amount_to_share_debt_or_reserve += u64::from(
                            is_accounting_selector(selectors.get(*tx_idx).copied().flatten()),
                        );
                        report.evidence.push(format!(
                            "storage value from tx {origin_tx} offset {offset} flowed into tx {tx_idx}"
                        ));
                    }
                    Waypoint::Comparison {
                        taint_source: Some(source),
                        lhs_expression,
                        rhs_expression,
                        ..
                    } => {
                        if matches!(
                            source,
                            TaintSource::Storage(_, _)
                                | TaintSource::Calldata(_)
                                | TaintSource::Caller
                        ) && expression_looks_role_sensitive(lhs_expression, rhs_expression)
                        {
                            report.caller_role_checks += 1;
                            report.evidence.push(format!(
                                "tainted comparison may gate role/access logic via {:?}",
                                source
                            ));
                        }
                    }
                    Waypoint::BranchPath { constraint, .. } => {
                        if let Waypoint::Comparison {
                            taint_source: Some(source),
                            lhs_expression,
                            rhs_expression,
                            ..
                        } = constraint.as_ref()
                        {
                            if matches!(
                                source,
                                TaintSource::Storage(_, _)
                                    | TaintSource::Calldata(_)
                                    | TaintSource::Caller
                            ) && expression_looks_role_sensitive(lhs_expression, rhs_expression)
                            {
                                report.caller_role_checks += 1;
                                report.evidence.push(format!(
                                    "tainted branch may gate role/access logic via {:?}",
                                    source
                                ));
                            }
                        }
                    }
                    Waypoint::StorageRead {
                        read_tx_idx,
                        taint_source: Some(TaintSource::Storage(origin_tx, offset)),
                        ..
                    } if origin_tx < read_tx_idx => {
                        report.calldata_to_storage += 1;
                        if is_accounting_selector(selectors.get(*read_tx_idx).copied().flatten()) {
                            report.amount_to_share_debt_or_reserve += 1;
                        }
                        report.evidence.push(format!(
                            "tx {read_tx_idx} read storage tainted by tx {origin_tx} calldata offset {offset}"
                        ));
                    }
                    _ => {}
                }
            }
        }

        if has_ordered_selector_pair(
            &selectors,
            function_selector("approve(address,uint256)"),
            function_selector("transferFrom(address,address,uint256)"),
        ) {
            report.approval_to_transfer_from += 1;
            report
                .evidence
                .push("approval selector precedes transferFrom selector".to_string());
        }

        if has_oracle_read_before_lending_action(execution, &selectors) {
            report.oracle_read_to_borrow_or_liquidate += 1;
            report
                .evidence
                .push("oracle/price read precedes borrow or liquidation action".to_string());
        }

        report.evidence.sort();
        report.evidence.dedup();
        report
    }

    pub fn score(&self) -> u64 {
        self.calldata_to_storage
            .saturating_mul(35)
            .saturating_add(self.caller_role_checks.saturating_mul(70))
            .saturating_add(self.approval_to_transfer_from.saturating_mul(90))
            .saturating_add(self.oracle_read_to_borrow_or_liquidate.saturating_mul(110))
            .saturating_add(self.amount_to_share_debt_or_reserve.saturating_mul(85))
            .min(500)
    }
}

fn selector_for_calldata(calldata: &[u8]) -> Option<[u8; 4]> {
    calldata.get(0..4).map(|selector| {
        let mut out = [0u8; 4];
        out.copy_from_slice(selector);
        out
    })
}

fn function_selector(signature: &str) -> [u8; 4] {
    let hash = revm::primitives::keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

fn is_accounting_selector(selector: Option<[u8; 4]>) -> bool {
    let Some(selector) = selector else {
        return false;
    };
    [
        "deposit(uint256,address)",
        "mint(uint256,address)",
        "withdraw(uint256,address,address)",
        "redeem(uint256,address,address)",
        "borrow(uint256)",
        "borrow(address,uint256,uint256,uint16,address)",
        "repay(uint256)",
        "repay(address,uint256,uint256,address)",
        "liquidate(address,address,uint256,uint256)",
        "liquidationCall(address,address,address,uint256,bool)",
        "donateToReserves(uint256,uint256)",
        "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        "swap(uint256,uint256,address,bytes)",
    ]
    .iter()
    .map(|signature| function_selector(signature))
    .any(|known| known == selector)
}

fn expression_uses_calldata(expression: &Option<SymbolicExpression>) -> bool {
    match expression {
        Some(SymbolicExpression::Source(TaintSource::Calldata(_)))
        | Some(SymbolicExpression::Source(TaintSource::CallValue)) => true,
        Some(SymbolicExpression::Add(left, right))
        | Some(SymbolicExpression::Sub(left, right))
        | Some(SymbolicExpression::Mul(left, right))
        | Some(SymbolicExpression::Div(left, right))
        | Some(SymbolicExpression::Mod(left, right))
        | Some(SymbolicExpression::And(left, right))
        | Some(SymbolicExpression::Or(left, right))
        | Some(SymbolicExpression::Xor(left, right)) => {
            expression_uses_calldata(&Some((**left).clone()))
                || expression_uses_calldata(&Some((**right).clone()))
        }
        _ => false,
    }
}

fn expression_looks_role_sensitive(
    lhs: &Option<SymbolicExpression>,
    rhs: &Option<SymbolicExpression>,
) -> bool {
    expression_uses_storage(lhs)
        || expression_uses_storage(rhs)
        || expression_uses_calldata(lhs)
        || expression_uses_calldata(rhs)
}

fn expression_uses_storage(expression: &Option<SymbolicExpression>) -> bool {
    match expression {
        Some(SymbolicExpression::Source(TaintSource::Storage(_, _)))
        | Some(SymbolicExpression::Source(TaintSource::Caller)) => true,
        Some(SymbolicExpression::Add(left, right))
        | Some(SymbolicExpression::Sub(left, right))
        | Some(SymbolicExpression::Mul(left, right))
        | Some(SymbolicExpression::Div(left, right))
        | Some(SymbolicExpression::Mod(left, right))
        | Some(SymbolicExpression::And(left, right))
        | Some(SymbolicExpression::Or(left, right))
        | Some(SymbolicExpression::Xor(left, right)) => {
            expression_uses_storage(&Some((**left).clone()))
                || expression_uses_storage(&Some((**right).clone()))
        }
        _ => false,
    }
}

fn has_ordered_selector_pair(selectors: &[Option<[u8; 4]>], left: [u8; 4], right: [u8; 4]) -> bool {
    let mut seen_left = false;
    for selector in selectors.iter().flatten() {
        if *selector == left {
            seen_left = true;
        }
        if seen_left && *selector == right {
            return true;
        }
    }
    false
}

fn has_oracle_read_before_lending_action(
    execution: &SequenceExecutionResult,
    selectors: &[Option<[u8; 4]>],
) -> bool {
    let oracle_selectors = [
        function_selector("latestAnswer()"),
        function_selector("latestRoundData()"),
        function_selector("getPrice()"),
        function_selector("price()"),
    ];
    let lending_selectors = [
        function_selector("borrow(uint256)"),
        function_selector("borrow(address,uint256,uint256,uint16,address)"),
        function_selector("liquidate(address,address,uint256,uint256)"),
        function_selector("liquidationCall(address,address,address,uint256,bool)"),
    ];
    let mut oracle_tx = None;
    for call in execution.call_trace.iter().filter(|call| {
        call.phase == CallPhase::End
            && call.success
            && matches!(
                call.kind,
                CallKind::StaticCall | CallKind::Call | CallKind::Transaction
            )
    }) {
        let Some(selector) = selector_for_calldata(&call.input) else {
            continue;
        };
        if oracle_selectors.contains(&selector) {
            oracle_tx = Some(call.tx_index);
        }
    }
    let Some(oracle_tx) = oracle_tx else {
        return false;
    };
    selectors.iter().enumerate().any(|(idx, selector)| {
        idx >= oracle_tx && selector.is_some_and(|selector| lending_selectors.contains(&selector))
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{CallObservation, ExecutionStatus, SingletonTx, TxExecutionResult};
    use revm::primitives::{Address, B256};

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn tx(selector: [u8; 4]) -> SingletonTx {
        SingletonTx {
            input: selector.to_vec(),
            caller: addr(0xaa),
            to: addr(0xcc),
            value: U256::ZERO,
            is_victim: false,
        }
    }

    fn execution_with_txs(
        tx_results: Vec<TxExecutionResult>,
        call_trace: Vec<CallObservation>,
    ) -> SequenceExecutionResult {
        let storage_diffs = tx_results
            .iter()
            .flat_map(|result| result.storage_diffs.clone())
            .collect::<Vec<_>>();
        SequenceExecutionResult {
            tx_results,
            total_gas_used: 1,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs,
            call_trace,
            oracle_observations: Vec::new(),
        }
    }

    fn result(tx_index: usize, waypoints: Vec<Waypoint>) -> TxExecutionResult {
        TxExecutionResult {
            tx_index,
            status: ExecutionStatus::Success,
            gas_used: 1,
            output: Vec::new(),
            coverage_hash: 1,
            coverage_edges: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            waypoints,
        }
    }

    #[test]
    fn dataflow_scores_calldata_to_accounting_storage() {
        let input = EvmInput {
            txs: vec![tx(function_selector("deposit(uint256,address)"))],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let execution = execution_with_txs(
            vec![result(
                0,
                vec![Waypoint::StorageWrite {
                    address: addr(0xcc),
                    slot: B256::ZERO.to_vec(),
                    value: U256::from(10),
                    pc: 1,
                    tx_idx: 0,
                    taint_source_of_value: Some(TaintSource::Calldata(4)),
                    value_expression: Some(SymbolicExpression::Source(TaintSource::Calldata(4))),
                }],
            )],
            Vec::new(),
        );

        let report = DataflowScoreReport::from_execution(&input, &execution);
        assert_eq!(report.calldata_to_storage, 1);
        assert_eq!(report.amount_to_share_debt_or_reserve, 1);
        assert!(report.score() >= 100);
    }

    #[test]
    fn dataflow_scores_approval_to_transfer_from() {
        let input = EvmInput {
            txs: vec![
                tx(function_selector("approve(address,uint256)")),
                tx(function_selector("transferFrom(address,address,uint256)")),
            ],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let execution = execution_with_txs(
            vec![result(0, Vec::new()), result(1, Vec::new())],
            Vec::new(),
        );

        let report = DataflowScoreReport::from_execution(&input, &execution);
        assert_eq!(report.approval_to_transfer_from, 1);
        assert!(report.score() >= 90);
    }

    #[test]
    fn dataflow_scores_oracle_read_to_lending_action() {
        let input = EvmInput {
            txs: vec![tx(function_selector(
                "liquidationCall(address,address,address,uint256,bool)",
            ))],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let execution = execution_with_txs(
            vec![result(0, Vec::new())],
            vec![CallObservation {
                tx_index: 0,
                depth: 1,
                caller: addr(0xcc),
                target: addr(0x0f),
                value: U256::ZERO,
                input: function_selector("latestAnswer()").to_vec(),
                output: U256::from(1).to_be_bytes::<32>().to_vec(),
                gas_limit: 1,
                gas_used: 1,
                success: true,
                kind: CallKind::StaticCall,
                phase: CallPhase::End,
                created_address: None,
                result: None,
            }],
        );

        let report = DataflowScoreReport::from_execution(&input, &execution);
        assert_eq!(report.oracle_read_to_borrow_or_liquidate, 1);
        assert!(report.score() >= 110);
    }

    #[test]
    fn dataflow_scores_tainted_role_branch() {
        let input = EvmInput {
            txs: vec![tx(function_selector("upgradeTo(address)"))],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let execution = execution_with_txs(
            vec![result(
                0,
                vec![Waypoint::Comparison {
                    op: 0x14,
                    lhs: U256::from(1),
                    rhs: U256::from(2),
                    pc: 1,
                    calldata_offset: None,
                    condition: false,
                    hit: false,
                    taint_source: Some(TaintSource::Storage(0, 4)),
                    tainted_operand: crate::common::types::ComparisonOperand::Lhs,
                    lhs_expression: Some(SymbolicExpression::Source(TaintSource::Storage(0, 4))),
                    rhs_expression: Some(SymbolicExpression::Constant(U256::ZERO)),
                    branch_distance: Some(U256::from(1)),
                }],
            )],
            Vec::new(),
        );

        let report = DataflowScoreReport::from_execution(&input, &execution);
        assert_eq!(report.caller_role_checks, 1);
        assert!(report.score() >= 70);
    }
}
