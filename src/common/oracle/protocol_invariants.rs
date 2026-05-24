use crate::common::oracle::{ProtocolFinding, ProtocolOraclePackKind, ProtocolSeverity, VulnType};
use crate::common::types::{
    CallKind, CallObservation, CallPhase, SequenceExecutionResult, StorageDiff,
};
use revm::primitives::{keccak256, Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolInvariantFinding {
    pub family: ProtocolInvariantFamily,
    pub severity_hint: ProtocolSeverity,
    pub confidence: u64,
    pub affected_contracts: Vec<Address>,
    pub evidence: String,
    pub recommended_reproduction_sequence: Vec<String>,
    pub false_positive_caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolInvariantFamily {
    GenericAccounting,
    Erc20Accounting,
    Erc4626Accounting,
    AmmReserve,
    LendingHealth,
    OracleFreshness,
    AccessControl,
    GovernanceTimelock,
    BridgeReplay,
}

#[derive(Debug, Clone)]
pub struct ProtocolInvariantEvaluator {
    pub large_delta_threshold: U256,
    pub min_persistable_confidence: u64,
}

impl Default for ProtocolInvariantEvaluator {
    fn default() -> Self {
        Self {
            large_delta_threshold: U256::from(10u128.pow(18)),
            min_persistable_confidence: 70,
        }
    }
}

impl ProtocolInvariantEvaluator {
    pub fn evaluate(&self, execution: &SequenceExecutionResult) -> Vec<ProtocolInvariantFinding> {
        let mut findings = Vec::new();
        self.evaluate_generic_accounting(execution, &mut findings);
        self.evaluate_erc20(execution, &mut findings);
        self.evaluate_erc4626(execution, &mut findings);
        self.evaluate_oracle_freshness(execution, &mut findings);
        self.evaluate_access_control(execution, &mut findings);

        findings.retain(|finding| finding.confidence >= self.min_persistable_confidence);
        findings.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.family.cmp(&b.family))
        });
        findings.dedup_by(|a, b| {
            a.family == b.family
                && a.affected_contracts == b.affected_contracts
                && a.evidence == b.evidence
        });
        findings
    }

    pub fn evaluate_as_protocol_findings(
        &self,
        execution: &SequenceExecutionResult,
    ) -> Vec<ProtocolFinding> {
        self.evaluate(execution)
            .into_iter()
            .map(protocol_invariant_to_finding)
            .collect()
    }

    fn evaluate_generic_accounting(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolInvariantFinding>,
    ) {
        for target in
            targets_with_large_diffs(execution, self.large_delta_threshold * U256::from(8))
        {
            let writes = execution
                .storage_diffs
                .iter()
                .filter(|diff| diff.address == target)
                .count();
            if writes < 6 {
                continue;
            }
            findings.push(ProtocolInvariantFinding {
                family: ProtocolInvariantFamily::GenericAccounting,
                severity_hint: ProtocolSeverity::Medium,
                confidence: 74,
                affected_contracts: vec![target],
                evidence: format!(
                    "large aggregate accounting movement across {writes} storage slots"
                ),
                recommended_reproduction_sequence: selectors_for_target(execution, target),
                false_positive_caveats: vec![
                    "large rebases, migrations, or administrative accounting updates can be legitimate"
                        .to_string(),
                ],
            });
        }
    }

    fn evaluate_erc20(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolInvariantFinding>,
    ) {
        for call in calls_with_selectors(
            execution,
            &[
                function_selector("transfer(address,uint256)"),
                function_selector("transferFrom(address,address,uint256)"),
                function_selector("approve(address,uint256)"),
            ],
        ) {
            let writes = writes_for_target(execution, call.target, call.tx_index);
            if writes.len() >= 5 {
                findings.push(ProtocolInvariantFinding {
                    family: ProtocolInvariantFamily::Erc20Accounting,
                    severity_hint: ProtocolSeverity::Medium,
                    confidence: 76,
                    affected_contracts: vec![call.target],
                    evidence: format!(
                        "ERC20 selector {} changed {} storage slots in one transaction",
                        selector_hex(call),
                        writes.len()
                    ),
                    recommended_reproduction_sequence: vec![selector_hex(call)],
                    false_positive_caveats: vec![
                        "fee-on-transfer, rebasing, and hook-based tokens may touch extra accounting slots"
                            .to_string(),
                    ],
                });
            }
            if selector(call) == Some(function_selector("approve(address,uint256)"))
                && writes.iter().any(|diff| diff.new_value == U256::MAX)
            {
                findings.push(ProtocolInvariantFinding {
                    family: ProtocolInvariantFamily::Erc20Accounting,
                    severity_hint: ProtocolSeverity::Low,
                    confidence: 72,
                    affected_contracts: vec![call.target],
                    evidence: "approve path wrote U256::MAX allowance-like value".to_string(),
                    recommended_reproduction_sequence: vec![selector_hex(call)],
                    false_positive_caveats: vec![
                        "infinite approvals are common but become risky when paired with later transferFrom"
                            .to_string(),
                    ],
                });
            }
        }
    }

    fn evaluate_erc4626(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolInvariantFinding>,
    ) {
        for call in calls_with_selectors(
            execution,
            &[
                function_selector("deposit(uint256,address)"),
                function_selector("mint(uint256,address)"),
                function_selector("withdraw(uint256,address,address)"),
                function_selector("redeem(uint256,address,address)"),
            ],
        ) {
            let writes = writes_for_target(execution, call.target, call.tx_index);
            let large_writes = writes
                .iter()
                .filter(|diff| abs_delta(diff) >= self.large_delta_threshold)
                .count();
            let share_reads = execution
                .storage_reads
                .iter()
                .filter(|read| read.tx_index == call.tx_index && read.address == call.target)
                .count();
            if large_writes > 0 && share_reads == 0 {
                findings.push(ProtocolInvariantFinding {
                    family: ProtocolInvariantFamily::Erc4626Accounting,
                    severity_hint: ProtocolSeverity::High,
                    confidence: 84,
                    affected_contracts: vec![call.target],
                    evidence: format!(
                        "ERC4626-like selector {} caused {large_writes} large writes without share/accounting reads",
                        selector_hex(call)
                    ),
                    recommended_reproduction_sequence: vec![selector_hex(call)],
                    false_positive_caveats: vec![
                        "instrumentation may miss reads performed through precompiles or off-target delegatecalls"
                            .to_string(),
                    ],
                });
            }
        }
    }

    fn evaluate_access_control(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolInvariantFinding>,
    ) {
        for call in calls_with_selectors(
            execution,
            &[
                function_selector("upgradeTo(address)"),
                function_selector("upgradeToAndCall(address,bytes)"),
                function_selector("transferOwnership(address)"),
                function_selector("grantRole(bytes32,address)"),
                function_selector("execute(uint256)"),
            ],
        ) {
            if !call.success || call.caller == call.target {
                continue;
            }
            let writes = writes_for_target(execution, call.target, call.tx_index);
            if writes.is_empty() {
                continue;
            }
            findings.push(ProtocolInvariantFinding {
                family: ProtocolInvariantFamily::AccessControl,
                severity_hint: ProtocolSeverity::High,
                confidence: 82,
                affected_contracts: vec![call.target],
                evidence: format!(
                    "privileged selector {} succeeded for caller {} and wrote {} target slots",
                    selector_hex(call),
                    call.caller,
                    writes.len()
                ),
                recommended_reproduction_sequence: vec![selector_hex(call)],
                false_positive_caveats: vec![
                    "caller may legitimately hold a role in the forked state; replay with known non-owner actors"
                        .to_string(),
                ],
            });
        }
    }

    fn evaluate_oracle_freshness(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolInvariantFinding>,
    ) {
        const LATEST_ANSWER: [u8; 4] = [0xfe, 0xaf, 0x96, 0x8c];
        const GET_PRICE: [u8; 4] = [0x98, 0x74, 0x5a, 0x8c];
        const PRICE: [u8; 4] = [0xa1, 0x57, 0xf5, 0x68];
        const SET_PRICE: [u8; 4] = [0xfe, 0xaf, 0x96, 0x8d];

        let oracle_calls =
            calls_with_selectors(execution, &[LATEST_ANSWER, GET_PRICE, PRICE, SET_PRICE]);
        if oracle_calls.len() < 2 {
            return;
        }

        for window in oracle_calls.windows(2) {
            let a = window[0];
            let b = window[1];
            let out_a = output_word(a);
            let out_b = output_word(b);
            if let (Some(a_value), Some(b_value)) = (out_a, out_b) {
                let delta = if a_value > b_value {
                    a_value - b_value
                } else {
                    b_value - a_value
                };
                if delta.is_zero() {
                    continue;
                }
                findings.push(ProtocolInvariantFinding {
                    family: ProtocolInvariantFamily::OracleFreshness,
                    severity_hint: ProtocolSeverity::High,
                    confidence: 81,
                    affected_contracts: vec![a.target],
                    evidence: format!(
                        "oracle output changed from {} to {} between consecutive reads",
                        a_value, b_value
                    ),
                    recommended_reproduction_sequence: vec![
                        selector_hex(a),
                        selector_hex(b),
                    ],
                    false_positive_caveats: vec![
                        "updating oracle feeds or switching price sources can legitimately change outputs"
                            .to_string(),
                    ],
                });
                break;
            }
        }
    }
}

fn protocol_invariant_to_finding(finding: ProtocolInvariantFinding) -> ProtocolFinding {
    let pack = match finding.family {
        ProtocolInvariantFamily::Erc20Accounting => ProtocolOraclePackKind::Erc20,
        ProtocolInvariantFamily::Erc4626Accounting => ProtocolOraclePackKind::Erc4626,
        ProtocolInvariantFamily::AmmReserve => ProtocolOraclePackKind::Amm,
        ProtocolInvariantFamily::LendingHealth => ProtocolOraclePackKind::Lending,
        ProtocolInvariantFamily::GovernanceTimelock => ProtocolOraclePackKind::Governance,
        _ => ProtocolOraclePackKind::Governance,
    };
    let vuln = match finding.family {
        ProtocolInvariantFamily::AccessControl => VulnType::PrivilegeEscalation,
        ProtocolInvariantFamily::Erc4626Accounting => VulnType::VaultInflation,
        ProtocolInvariantFamily::Erc20Accounting | ProtocolInvariantFamily::GenericAccounting => {
            VulnType::AccountingDesync
        }
        ProtocolInvariantFamily::AmmReserve | ProtocolInvariantFamily::OracleFreshness => {
            VulnType::PriceManipulation
        }
        ProtocolInvariantFamily::GovernanceTimelock => VulnType::GovernanceTakeover,
        ProtocolInvariantFamily::BridgeReplay => {
            VulnType::InvariantViolation("bridge replay/finalize invariant".to_string())
        }
        ProtocolInvariantFamily::LendingHealth => {
            VulnType::InvariantViolation("lending health invariant".to_string())
        }
    };
    ProtocolFinding {
        pack,
        vuln,
        severity: finding.severity_hint,
        tx_index: None,
        target: finding.affected_contracts.first().copied(),
        evidence: format!(
            "{} | confidence={} | reproduce={} | caveats={}",
            finding.evidence,
            finding.confidence,
            finding.recommended_reproduction_sequence.join(" -> "),
            finding.false_positive_caveats.join("; ")
        ),
    }
}

fn calls_with_selectors<'a>(
    execution: &'a SequenceExecutionResult,
    selectors: &[[u8; 4]],
) -> Vec<&'a CallObservation> {
    execution
        .call_trace
        .iter()
        .filter(|call| {
            call.phase == CallPhase::End
                && matches!(
                    call.kind,
                    CallKind::Transaction
                        | CallKind::Call
                        | CallKind::CallCode
                        | CallKind::DelegateCall
                        | CallKind::StaticCall
                )
                && selector(call).is_some_and(|sel| selectors.contains(&sel))
        })
        .collect()
}

fn targets_with_large_diffs(
    execution: &SequenceExecutionResult,
    threshold: U256,
) -> BTreeSet<Address> {
    let mut aggregate_by_target: HashMap<Address, U256> = HashMap::new();
    for diff in &execution.storage_diffs {
        let entry = aggregate_by_target.entry(diff.address).or_default();
        *entry = entry.saturating_add(abs_delta(diff));
    }

    let mut targets = BTreeSet::new();
    for (target, aggregate) in aggregate_by_target {
        if aggregate >= threshold {
            targets.insert(target);
        }
    }
    targets
}

fn selectors_for_target(execution: &SequenceExecutionResult, target: Address) -> Vec<String> {
    execution
        .call_trace
        .iter()
        .filter(|call| call.target == target && call.phase == CallPhase::End)
        .filter_map(|call| selector(call).map(hex::encode))
        .collect()
}

fn writes_for_target(
    execution: &SequenceExecutionResult,
    target: Address,
    tx_index: usize,
) -> Vec<&StorageDiff> {
    execution
        .storage_diffs
        .iter()
        .filter(|diff| diff.address == target && diff.tx_index == tx_index)
        .collect()
}

fn abs_delta(diff: &StorageDiff) -> U256 {
    if diff.new_value > diff.old_value {
        diff.new_value - diff.old_value
    } else {
        diff.old_value - diff.new_value
    }
}

fn selector(call: &CallObservation) -> Option<[u8; 4]> {
    call.input.get(0..4)?.try_into().ok()
}

fn selector_hex(call: &CallObservation) -> String {
    selector(call)
        .map(hex::encode)
        .unwrap_or_else(|| "none".to_string())
}

fn output_word(call: &CallObservation) -> Option<U256> {
    (call.output.len() >= 32).then(|| U256::from_be_slice(&call.output[..32]))
}

fn function_selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{ExecutionStatus, TxExecutionResult};
    use revm::primitives::B256;

    #[test]
    fn detects_erc20_accounting_invariant_case() {
        let target = Address::repeat_byte(0xaa);
        let execution = execution_with_call_and_writes(
            target,
            function_selector("transfer(address,uint256)"),
            0,
            5,
            U256::from(10u128.pow(18)),
        );

        let findings = ProtocolInvariantEvaluator::default().evaluate(&execution);

        assert!(findings
            .iter()
            .any(|finding| finding.family == ProtocolInvariantFamily::Erc20Accounting));
    }

    #[test]
    fn detects_erc4626_share_inflation_style_case() {
        let target = Address::repeat_byte(0xbb);
        let execution = execution_with_call_and_writes(
            target,
            function_selector("deposit(uint256,address)"),
            0,
            1,
            U256::from(10u128.pow(18)),
        );

        let findings = ProtocolInvariantEvaluator::default().evaluate(&execution);

        assert!(findings
            .iter()
            .any(|finding| finding.family == ProtocolInvariantFamily::Erc4626Accounting));
    }

    #[test]
    fn detects_access_control_invariant_case() {
        let target = Address::repeat_byte(0xcc);
        let execution = execution_with_call_and_writes(
            target,
            function_selector("upgradeTo(address)"),
            0,
            1,
            U256::from(1),
        );

        let findings = ProtocolInvariantEvaluator::default().evaluate(&execution);

        assert!(findings
            .iter()
            .any(|finding| finding.family == ProtocolInvariantFamily::AccessControl));
    }

    #[test]
    fn detects_oracle_freshness_invariant_case() {
        let target = Address::repeat_byte(0xee);
        let mut first =
            execution_with_call_and_writes(target, [0xfe, 0xaf, 0x96, 0x8c], 0, 1, U256::from(100));
        first.call_trace.push(CallObservation {
            tx_index: 1,
            depth: 0,
            caller: Address::repeat_byte(0x14),
            target,
            value: U256::ZERO,
            input: vec![0xfe, 0xaf, 0x96, 0x8c],
            output: U256::from(200).to_be_bytes::<32>().to_vec(),
            gas_limit: 0,
            gas_used: 0,
            success: true,
            kind: CallKind::Transaction,
            phase: CallPhase::End,
            created_address: None,
            result: Some("Success".to_string()),
        });
        first.call_trace[0].output = U256::from(100).to_be_bytes::<32>().to_vec();
        first.tx_results.push(TxExecutionResult {
            tx_index: 1,
            status: ExecutionStatus::Success,
            gas_used: 0,
            output: U256::from(200).to_be_bytes::<32>().to_vec(),
            coverage_hash: 0,
            coverage_edges: 0,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: vec![StorageDiff {
                tx_index: 1,
                address: target,
                slot: B256::from([0x01; 32]),
                old_value: U256::from(100),
                new_value: U256::from(200),
                pc: 0,
            }],
            call_trace: Vec::new(),
            waypoints: Vec::new(),
        });
        first.storage_diffs.push(StorageDiff {
            tx_index: 1,
            address: target,
            slot: B256::from([0x01; 32]),
            old_value: U256::from(100),
            new_value: U256::from(200),
            pc: 0,
        });
        first.total_gas_used = 0;

        let findings = ProtocolInvariantEvaluator::default().evaluate(&first);
        assert!(findings
            .iter()
            .any(|finding| finding.family == ProtocolInvariantFamily::OracleFreshness));
    }

    #[test]
    fn detects_generic_accounting_invariant_case() {
        let target = Address::repeat_byte(0xdd);
        let execution = execution_with_call_and_writes(
            target,
            function_selector("settle(uint256)"),
            0,
            8,
            U256::from(10u128.pow(18)),
        );

        let findings = ProtocolInvariantEvaluator::default().evaluate(&execution);

        assert!(findings
            .iter()
            .any(|finding| finding.family == ProtocolInvariantFamily::GenericAccounting));
    }

    fn execution_with_call_and_writes(
        target: Address,
        selector: [u8; 4],
        tx_index: usize,
        writes: usize,
        delta: U256,
    ) -> SequenceExecutionResult {
        let mut input = selector.to_vec();
        input.resize(36, 0);
        SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index,
                status: ExecutionStatus::Success,
                gas_used: 0,
                output: Vec::new(),
                coverage_hash: 0,
                coverage_edges: 0,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: Vec::new(),
                call_trace: Vec::new(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 0,
            final_coverage_hash: 0,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: (0..writes)
                .map(|idx| StorageDiff {
                    tx_index,
                    address: target,
                    slot: B256::from([idx as u8; 32]),
                    old_value: U256::ZERO,
                    new_value: delta,
                    pc: idx,
                })
                .collect(),
            call_trace: vec![CallObservation {
                tx_index,
                depth: 0,
                caller: Address::repeat_byte(0x13),
                target,
                value: U256::ZERO,
                input,
                output: Vec::new(),
                gas_limit: 0,
                gas_used: 0,
                success: true,
                kind: CallKind::Transaction,
                phase: CallPhase::End,
                created_address: None,
                result: Some("Success".to_string()),
            }],
            oracle_observations: Vec::new(),
        }
    }
}
