//! Differential fuzzing engine for comparing multiple implementations
//!
//! This module enables detection of subtle bugs by comparing execution results across:
//! - Different contract versions (git diff analysis)
//! - Different DEX implementations (Uniswap vs SushiSwap)
//! - Forked vs simulated state
//! - Optimistic vs pessimistic execution paths

use crate::common::types::SingletonTx;
use crate::evm::trace::ExecutionTrace;
use revm::primitives::{Address, Bytes, Log, U256};
use std::collections::HashMap;

/// Result from a single implementation execution
#[derive(Debug, Clone)]
pub struct ImplementationResult {
    pub name: String,
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Option<Bytes>,
    pub state_diff: StateDiff,
    pub logs: Vec<Log>,
    pub trace: ExecutionTrace,
    pub revert_reason: Option<String>,
}

/// State difference between before and after execution
#[derive(Debug, Clone, Default)]
pub struct StateDiff {
    pub balance_changes: HashMap<Address, BalanceChange>,
    pub storage_changes: HashMap<Address, HashMap<U256, StorageChange>>,
    pub code_changes: HashMap<Address, Bytes>,
    pub nonce_changes: HashMap<Address, u64>,
}

#[derive(Debug, Clone)]
pub struct BalanceChange {
    pub before: U256,
    pub after: U256,
    pub delta: i128, // Signed to handle both increases and decreases
}

#[derive(Debug, Clone)]
pub struct StorageChange {
    pub slot: U256,
    pub before: U256,
    pub after: U256,
}

impl StateDiff {
    /// Calculate the net ETH flow for an address
    pub fn eth_flow(&self, address: &Address) -> i128 {
        self.balance_changes
            .get(address)
            .map(|c| c.delta)
            .unwrap_or(0)
    }

    /// Get all addresses with balance changes
    pub fn changed_addresses(&self) -> Vec<Address> {
        self.balance_changes.keys().cloned().collect()
    }

    /// Check if a specific storage slot changed
    pub fn storage_changed(&self, contract: &Address, slot: &U256) -> bool {
        self.storage_changes
            .get(contract)
            .map(|changes| changes.contains_key(slot))
            .unwrap_or(false)
    }
}

/// Differential fuzzer that compares multiple implementations
pub struct DifferentialFuzzer {
    implementations: Vec<String>,
    baseline_idx: usize,
}

impl DifferentialFuzzer {
    pub fn new(implementations: Vec<String>) -> Self {
        Self {
            implementations,
            baseline_idx: 0, // First implementation is baseline
        }
    }

    /// Compare results across all implementations
    pub fn compare(&self, results: &[ImplementationResult]) -> DifferentialReport {
        if results.is_empty() {
            return DifferentialReport::new("No results".to_string());
        }

        let mut report =
            DifferentialReport::new(format!("Comparing {} implementations", results.len()));

        let baseline = &results[self.baseline_idx];

        for (i, result) in results.iter().enumerate() {
            if i == self.baseline_idx {
                continue;
            }

            // Compare success/failure
            if baseline.success != result.success {
                report.findings.push(DifferentialFinding {
                    severity: FindingSeverity::Critical,
                    category: "Execution Divergence".to_string(),
                    description: format!(
                        "Baseline ({}) succeeded but {} failed (or vice versa)",
                        baseline.name, result.name
                    ),
                    evidence: format!(
                        "Baseline: {}, {}: {}",
                        if baseline.success { "success" } else { "failed" },
                        result.name,
                        if result.success { "success" } else { "failed" }
                    ),
                    recommendation: "Investigate why implementations behave differently. This could indicate a bug in one implementation.".to_string(),
                });
            }

            // Compare gas usage
            let gas_diff = result.gas_used as i64 - baseline.gas_used as i64;
            if gas_diff.abs() > 1000 {
                // Threshold: 1000 gas
                let severity = if gas_diff.abs() > 100_000 {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                };

                report.findings.push(DifferentialFinding {
                    severity,
                    category: "Gas Usage Divergence".to_string(),
                    description: format!(
                        "Gas usage differs by {} gas ({} vs {})",
                        gas_diff, baseline.gas_used, result.gas_used
                    ),
                    evidence: format!(
                        "{}% difference",
                        (gas_diff.abs() as f64 / baseline.gas_used as f64 * 100.0).abs()
                    ),
                    recommendation: "Large gas differences may indicate different code paths or optimization opportunities.".to_string(),
                });
            }

            // Compare return data
            if baseline.return_data != result.return_data {
                report.findings.push(DifferentialFinding {
                    severity: FindingSeverity::High,
                    category: "Return Data Mismatch".to_string(),
                    description: "Return data differs between implementations".to_string(),
                    evidence: format!(
                        "Baseline: {:?}, {}: {:?}",
                        baseline.return_data.as_ref().map(|b| b.len()),
                        result.name,
                        result.return_data.as_ref().map(|b| b.len())
                    ),
                    recommendation:
                        "Different return values indicate semantic differences in implementation."
                            .to_string(),
                });
            }

            // Compare state diffs
            self.compare_state_diffs(
                &baseline.state_diff,
                &result.state_diff,
                &result.name,
                &mut report,
            );

            // Compare logs
            if baseline.logs.len() != result.logs.len() {
                report.findings.push(DifferentialFinding {
                    severity: FindingSeverity::Medium,
                    category: "Event Log Count Mismatch".to_string(),
                    description: format!(
                        "Different number of events emitted ({} vs {})",
                        baseline.logs.len(),
                        result.logs.len()
                    ),
                    evidence: "Event count divergence".to_string(),
                    recommendation: "Missing or extra events may indicate incomplete state updates.".to_string(),
                });
            }
        }

        report
    }

    fn compare_state_diffs(
        &self,
        baseline: &StateDiff,
        other: &StateDiff,
        other_name: &str,
        report: &mut DifferentialReport,
    ) {
        // Compare balance changes
        let all_addresses: std::collections::HashSet<_> = baseline
            .balance_changes
            .keys()
            .chain(other.balance_changes.keys())
            .cloned()
            .collect();

        for addr in all_addresses {
            let baseline_change = baseline.balance_changes.get(&addr);
            let other_change = other.balance_changes.get(&addr);

            match (baseline_change, other_change) {
                (Some(b), Some(o)) => {
                    if b.delta != o.delta {
                        report.findings.push(DifferentialFinding {
                            severity: FindingSeverity::High,
                            category: "Balance Change Divergence".to_string(),
                            description: format!(
                                "Balance change for {:?} differs: {} vs {}",
                                addr, b.delta, o.delta
                            ),
                            evidence: "Net ETH flow mismatch".to_string(),
                            recommendation: "Investigate why balance changes differ. Could indicate missing transfers or double-spends.".to_string(),
                        });
                    }
                }
                (Some(_), None) | (None, Some(_)) => {
                    report.findings.push(DifferentialFinding {
                        severity: FindingSeverity::Medium,
                        category: "Balance Change Presence Mismatch".to_string(),
                        description: format!(
                            "Balance change for {:?} present in one implementation but not the other",
                            addr
                        ),
                        evidence: format!("Baseline: {}, {}: {}", 
                            if baseline_change.is_some() { "yes" } else { "no" },
                            other_name,
                            if other_change.is_some() { "yes" } else { "no" }
                        ),
                        recommendation: "Missing balance changes may indicate untracked value flows.".to_string(),
                    });
                }
                (None, None) => {}
            }
        }

        // Compare storage changes
        let all_contracts: std::collections::HashSet<_> = baseline
            .storage_changes
            .keys()
            .chain(other.storage_changes.keys())
            .cloned()
            .collect();

        for contract in all_contracts {
            let baseline_slots = baseline.storage_changes.get(&contract);
            let other_slots = other.storage_changes.get(&contract);

            match (baseline_slots, other_slots) {
                (Some(b), Some(o)) => {
                    // Find slots that changed differently
                    let all_slots: std::collections::HashSet<_> =
                        b.keys().chain(o.keys()).cloned().collect();

                    for slot in all_slots {
                        let b_change = b.get(&slot);
                        let o_change = o.get(&slot);

                        match (b_change, o_change) {
                            (Some(bc), Some(oc)) => {
                                if bc.after != oc.after {
                                    report.findings.push(DifferentialFinding {
                                        severity: FindingSeverity::Critical,
                                        category: "Storage Divergence".to_string(),
                                        description: format!(
                                            "Storage slot {:?} in {:?} has different final values",
                                            slot, contract
                                        ),
                                        evidence: format!(
                                            "Baseline: {:?}, {}: {:?}",
                                            bc.after, other_name, oc.after
                                        ),
                                        recommendation: "Critical: State divergence indicates semantic bug. One implementation is incorrect.".to_string(),
                                    });
                                }
                            }
                            (Some(_), None) | (None, Some(_)) => {
                                report.findings.push(DifferentialFinding {
                                    severity: FindingSeverity::High,
                                    category: "Storage Change Presence Mismatch".to_string(),
                                    description: format!(
                                        "Storage slot {:?} changed in one implementation but not the other",
                                        slot
                                    ),
                                    evidence: format!("Contract: {:?}", contract),
                                    recommendation: "Missing storage updates may indicate incomplete state synchronization.".to_string(),
                                });
                            }
                            (None, None) => {}
                        }
                    }
                }
                (Some(_), None) | (None, Some(_)) => {
                    report.findings.push(DifferentialFinding {
                        severity: FindingSeverity::High,
                        category: "Storage Changes Presence Mismatch".to_string(),
                        description: format!(
                            "Contract {:?} has storage changes in one implementation but not the other",
                            contract
                        ),
                        evidence: "Storage change set mismatch".to_string(),
                        recommendation: "Entire contract state divergence is critical.".to_string(),
                    });
                }
                (None, None) => {}
            }
        }
    }

    /// Run differential fuzzing on a specific transaction across implementations
    pub async fn run_differential(
        &self,
        tx: &SingletonTx,
        executors: &[&dyn DifferentialExecutor],
    ) -> anyhow::Result<DifferentialReport> {
        if executors.len() != self.implementations.len() {
            anyhow::bail!("Number of executors must match number of implementations");
        }

        let mut results = Vec::new();

        for (i, executor) in executors.iter().enumerate() {
            let result = executor.execute(tx).await?;
            results.push(ImplementationResult {
                name: self.implementations[i].clone(),
                ..result
            });
        }

        Ok(self.compare(&results))
    }
}

/// Trait for executing transactions (allows different backends)
#[async_trait::async_trait]
pub trait DifferentialExecutor {
    async fn execute(&self, tx: &SingletonTx) -> anyhow::Result<ImplementationResult>;
}

#[derive(Debug, Clone)]
pub struct DifferentialReport {
    pub summary: String,
    pub findings: Vec<DifferentialFinding>,
    pub total_comparisons: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl DifferentialReport {
    pub fn new(summary: String) -> Self {
        Self {
            summary,
            findings: Vec::new(),
            total_comparisons: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
        }
    }

    pub fn has_critical_findings(&self) -> bool {
        self.critical_count > 0
    }

    pub fn has_high_findings(&self) -> bool {
        self.high_count > 0
    }

    pub fn severity_summary(&self) -> String {
        format!(
            "Critical: {}, High: {}, Medium: {}, Low: {}",
            self.critical_count, self.high_count, self.medium_count, self.low_count
        )
    }
}

#[derive(Debug, Clone)]
pub struct DifferentialFinding {
    pub severity: FindingSeverity,
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Git diff analyzer for identifying risky code changes
pub struct DiffAnalyzer {
    #[allow(dead_code)]
    old_commit: String,
    #[allow(dead_code)]
    new_commit: String,
}

impl DiffAnalyzer {
    pub fn new(old_commit: &str, new_commit: &str) -> Self {
        Self {
            old_commit: old_commit.to_string(),
            new_commit: new_commit.to_string(),
        }
    }

    /// Analyze git diff to identify security-relevant changes
    pub fn analyze_diff(&self, diff_content: &str) -> Vec<SecurityConcern> {
        let mut concerns = Vec::new();

        for line in diff_content.lines() {
            // Look for removed access controls
            if line.starts_with("-") && (line.contains("onlyOwner") || line.contains("onlyRole")) {
                concerns.push(SecurityConcern {
                    concern_type: ConcernType::AccessControlRemoved,
                    description: "Access control modifier removed".to_string(),
                    line: line.to_string(),
                    severity: FindingSeverity::Critical,
                });
            }

            // Look for changed arithmetic operations
            if line.starts_with("-") && line.contains(".sub(")
                || line.starts_with("+") && !line.contains(".sub(") && line.contains("-")
            {
                concerns.push(SecurityConcern {
                    concern_type: ConcernType::ArithmeticChange,
                    description: "Arithmetic operation changed (potential overflow risk)"
                        .to_string(),
                    line: line.to_string(),
                    severity: FindingSeverity::High,
                });
            }

            // Look for modified external calls
            if line.contains("call(")
                || line.contains("delegatecall(")
                || line.contains("staticcall(")
            {
                let severity = if line.starts_with("+") {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                };

                concerns.push(SecurityConcern {
                    concern_type: ConcernType::ExternalCallModified,
                    description: "External call pattern modified".to_string(),
                    line: line.to_string(),
                    severity,
                });
            }

            // Look for visibility changes
            if (line.starts_with("-") && line.contains("private"))
                || (line.starts_with("+") && line.contains("public"))
            {
                concerns.push(SecurityConcern {
                    concern_type: ConcernType::VisibilityChange,
                    description: "Function/variable visibility changed".to_string(),
                    line: line.to_string(),
                    severity: FindingSeverity::Medium,
                });
            }

            // Look for oracle price source changes
            if line.contains("price") || line.contains("oracle") || line.contains("twap") {
                concerns.push(SecurityConcern {
                    concern_type: ConcernType::OracleModification,
                    description: "Price oracle logic modified".to_string(),
                    line: line.to_string(),
                    severity: FindingSeverity::High,
                });
            }
        }

        concerns
    }

    /// Generate targeted fuzzing strategies based on diff analysis
    pub fn generate_fuzz_targets(&self, concerns: &[SecurityConcern]) -> Vec<FuzzTarget> {
        let mut targets = Vec::new();

        for concern in concerns {
            match concern.concern_type {
                ConcernType::AccessControlRemoved => {
                    targets.push(FuzzTarget {
                        strategy: FuzzStrategy::AccessControlBypass,
                        priority: 100,
                        description:
                            "Test calling previously protected functions without authorization"
                                .to_string(),
                    });
                }
                ConcernType::ArithmeticChange => {
                    targets.push(FuzzTarget {
                        strategy: FuzzStrategy::BoundaryValues,
                        priority: 90,
                        description: "Test boundary values (0, 1, MAX) for potential overflows"
                            .to_string(),
                    });
                }
                ConcernType::ExternalCallModified => {
                    targets.push(FuzzTarget {
                        strategy: FuzzStrategy::ReentrancyTest,
                        priority: 95,
                        description: "Test reentrancy through modified external calls".to_string(),
                    });
                }
                ConcernType::VisibilityChange => {
                    targets.push(FuzzTarget {
                        strategy: FuzzStrategy::DirectCall,
                        priority: 70,
                        description: "Test directly calling newly public functions".to_string(),
                    });
                }
                ConcernType::OracleModification => {
                    targets.push(FuzzTarget {
                        strategy: FuzzStrategy::PriceManipulation,
                        priority: 95,
                        description: "Test price manipulation attacks on modified oracle"
                            .to_string(),
                    });
                }
            }
        }

        targets
    }
}

#[derive(Debug, Clone)]
pub struct SecurityConcern {
    pub concern_type: ConcernType,
    pub description: String,
    pub line: String,
    pub severity: FindingSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcernType {
    AccessControlRemoved,
    ArithmeticChange,
    ExternalCallModified,
    VisibilityChange,
    OracleModification,
}

#[derive(Debug, Clone)]
pub struct FuzzTarget {
    pub strategy: FuzzStrategy,
    pub priority: u32,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzStrategy {
    AccessControlBypass,
    BoundaryValues,
    ReentrancyTest,
    DirectCall,
    PriceManipulation,
}
