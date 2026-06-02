use crate::common::oracle::{ProtocolInvariantEvaluator, VulnType};
use crate::common::types::{
    CallKind, CallObservation, CallPhase, ExecutionStatus, OracleObservation,
    SequenceExecutionResult, StorageDiff,
};
use revm::primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const ERC20_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const ERC20_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const ERC20_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const ERC20_TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];

const ERC4626_DEPOSIT: [u8; 4] = [0xb6, 0xb5, 0x5f, 0x25];
const ERC4626_MINT: [u8; 4] = [0x94, 0xbf, 0x80, 0x4d];
const ERC4626_WITHDRAW: [u8; 4] = [0x2e, 0x1a, 0x7d, 0x4d];
const ERC4626_REDEEM: [u8; 4] = [0xba, 0x08, 0x77, 0x52];
const ERC4626_TOTAL_ASSETS: [u8; 4] = [0x01, 0xad, 0x8a, 0x86];
const ERC4626_CONVERT_TO_SHARES: [u8; 4] = [0xc6, 0xe6, 0xf5, 0x92];

const UNISWAP_V2_SWAP: [u8; 4] = [0x02, 0x2c, 0x0d, 0x9f];
const UNISWAP_V3_SWAP: [u8; 4] = [0xa4, 0x15, 0xbb, 0x22];
const GET_RESERVES: [u8; 4] = [0x09, 0x02, 0xf1, 0xac];

const AAVE_SUPPLY: [u8; 4] = [0x61, 0x7c, 0x03, 0xcb];
const AAVE_BORROW: [u8; 4] = [0xa4, 0x15, 0xbc, 0xad];
const AAVE_REPAY: [u8; 4] = [0x57, 0x3a, 0xd8, 0xc5];
const AAVE_LIQUIDATION_CALL: [u8; 4] = [0x00, 0xa7, 0x18, 0xa9];
const COMPOUND_BORROW: [u8; 4] = [0xc5, 0xeb, 0xea, 0xec];
const COMPOUND_REDEEM: [u8; 4] = [0xdb, 0x00, 0x6a, 0x75];

const GOVERNOR_PROPOSE: [u8; 4] = [0xda, 0x95, 0x69, 0x1a];
const GOVERNOR_CAST_VOTE: [u8; 4] = [0x56, 0x78, 0x13, 0x88];
const GOVERNOR_EXECUTE: [u8; 4] = [0xfe, 0x0d, 0x94, 0xc1];
const TIMELOCK_QUEUE: [u8; 4] = [0xdd, 0xf0, 0xb0, 0x09];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolFinding {
    pub pack: ProtocolOraclePackKind,
    pub vuln: VulnType,
    pub severity: ProtocolSeverity,
    pub tx_index: Option<usize>,
    pub target: Option<Address>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolOraclePackKind {
    Erc20,
    Erc4626,
    Amm,
    Lending,
    Governance,
    ProxyUpgradeability,
    Bridge,
    RuntimePanic,
}

#[derive(Debug, Clone)]
pub struct ProtocolOraclePack {
    pub enabled: BTreeSet<ProtocolOraclePackKind>,
    pub price_move_threshold_bps: u64,
    pub large_diff_threshold: U256,
}

impl Default for ProtocolOraclePack {
    fn default() -> Self {
        Self {
            enabled: [
                ProtocolOraclePackKind::Erc20,
                ProtocolOraclePackKind::Erc4626,
                ProtocolOraclePackKind::Amm,
                ProtocolOraclePackKind::Lending,
                ProtocolOraclePackKind::Governance,
                ProtocolOraclePackKind::ProxyUpgradeability,
                ProtocolOraclePackKind::Bridge,
                ProtocolOraclePackKind::RuntimePanic,
            ]
            .into_iter()
            .collect(),
            price_move_threshold_bps: 500,
            large_diff_threshold: U256::from(10u128.pow(18)),
        }
    }
}

impl ProtocolOraclePack {
    pub fn evaluate(&self, execution: &SequenceExecutionResult) -> Vec<ProtocolFinding> {
        let mut findings = Vec::new();
        if self.enabled.contains(&ProtocolOraclePackKind::Erc20) {
            self.evaluate_erc20(execution, &mut findings);
        }
        if self.enabled.contains(&ProtocolOraclePackKind::Erc4626) {
            self.evaluate_erc4626(execution, &mut findings);
        }
        if self.enabled.contains(&ProtocolOraclePackKind::Amm) {
            self.evaluate_amm(execution, &mut findings);
        }
        if self.enabled.contains(&ProtocolOraclePackKind::Lending) {
            self.evaluate_lending(execution, &mut findings);
        }
        if self.enabled.contains(&ProtocolOraclePackKind::Governance) {
            self.evaluate_governance(execution, &mut findings);
        }
        if self.enabled.contains(&ProtocolOraclePackKind::RuntimePanic) {
            self.evaluate_runtime_panics(execution, &mut findings);
        }
        if self
            .enabled
            .contains(&ProtocolOraclePackKind::ProxyUpgradeability)
        {
            self.evaluate_proxy_upgradeability(execution, &mut findings);
        }
        findings.extend(
            ProtocolInvariantEvaluator {
                large_delta_threshold: self.large_diff_threshold,
                ..ProtocolInvariantEvaluator::default()
            }
            .evaluate_as_protocol_findings(execution),
        );
        findings.sort_by(|a, b| {
            (&b.severity, &a.pack, a.tx_index, a.target).cmp(&(
                &a.severity,
                &b.pack,
                b.tx_index,
                b.target,
            ))
        });
        findings.dedup_by(|a, b| {
            a.pack == b.pack
                && a.vuln == b.vuln
                && a.tx_index == b.tx_index
                && a.target == b.target
                && a.evidence == b.evidence
        });
        findings
    }

    fn evaluate_runtime_panics(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolFinding>,
    ) {
        for tx in &execution.tx_results {
            if tx.status != ExecutionStatus::Revert || tx.output.len() < 36 {
                continue;
            }
            if tx.output[0..4] != [0x4e, 0x48, 0x7b, 0x71] {
                continue;
            }
            let code = U256::from_be_slice(&tx.output[4..36]).to::<u64>();
            findings.push(ProtocolFinding {
                pack: ProtocolOraclePackKind::RuntimePanic,
                vuln: VulnType::UnintendedPanic(code),
                severity: if code == 0x01 {
                    ProtocolSeverity::High
                } else {
                    ProtocolSeverity::Medium
                },
                tx_index: Some(tx.tx_index),
                target: tx.call_trace.first().map(|call| call.target),
                evidence: format!(
                    "transaction reverted with Solidity Panic(0x{code:x}); code 0x01 is an assert/invariant failure"
                ),
            });
        }
    }

    pub fn evaluate_as_observations(
        &self,
        execution: &SequenceExecutionResult,
    ) -> Vec<OracleObservation> {
        self.evaluate(execution)
            .into_iter()
            .map(|finding| OracleObservation {
                oracle: format!("{:?}", finding.pack),
                finding: finding.vuln.to_string(),
                tx_index: finding.tx_index,
                evidence: finding.evidence,
            })
            .collect()
    }

    fn evaluate_erc20(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolFinding>,
    ) {
        let erc20_calls = calls_with_selectors(
            execution,
            &[ERC20_TRANSFER, ERC20_TRANSFER_FROM, ERC20_APPROVE],
        );
        if erc20_calls.is_empty() {
            return;
        }

        for call in erc20_calls {
            let writes = writes_for_target(execution, call.target, call.tx_index);
            let has_supply_query = execution.call_trace.iter().any(|other| {
                other.target == call.target
                    && selector(other).is_some_and(|sel| sel == ERC20_TOTAL_SUPPLY)
            });
            if writes.len() >= 4 && !has_supply_query {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Erc20,
                    vuln: VulnType::AccountingDesync,
                    severity: ProtocolSeverity::Medium,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence: format!(
                        "ERC20 call {} wrote {} slots without totalSupply reconciliation",
                        selector_hex(call),
                        writes.len()
                    ),
                });
            }

            if selector(call) == Some(ERC20_APPROVE)
                && writes.iter().any(|diff| diff.new_value == U256::MAX)
            {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Erc20,
                    vuln: VulnType::Other("unbounded allowance mutation".to_string()),
                    severity: ProtocolSeverity::Low,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence: "approve path wrote U256::MAX allowance-like value".to_string(),
                });
            }
        }
    }

    fn evaluate_erc4626(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolFinding>,
    ) {
        let vault_calls = calls_with_selectors(
            execution,
            &[
                ERC4626_DEPOSIT,
                ERC4626_MINT,
                ERC4626_WITHDRAW,
                ERC4626_REDEEM,
                ERC4626_TOTAL_ASSETS,
                ERC4626_CONVERT_TO_SHARES,
            ],
        );
        if vault_calls.is_empty() {
            return;
        }

        for call in vault_calls {
            let writes = writes_for_target(execution, call.target, call.tx_index);
            let large_asset_delta = writes
                .iter()
                .filter(|diff| abs_delta(diff) >= self.large_diff_threshold)
                .count();
            let share_related_reads = execution
                .storage_reads
                .iter()
                .filter(|read| {
                    read.address == call.target
                        && read.tx_index == call.tx_index
                        && read.value.is_some_and(|value| !value.is_zero())
                })
                .count();
            if selector(call) == Some(ERC4626_DEPOSIT)
                && large_asset_delta > 0
                && share_related_reads == 0
            {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Erc4626,
                    vuln: VulnType::VaultInflation,
                    severity: ProtocolSeverity::High,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence: format!(
                        "deposit-like call caused {} large vault storage deltas without nonzero share/accounting reads",
                        large_asset_delta
                    ),
                });
            }

            if selector(call) == Some(ERC4626_CONVERT_TO_SHARES)
                && call.phase == CallPhase::End
                && output_u256(call).is_some_and(|value| value.is_zero())
                && !call
                    .input
                    .get(4..36)
                    .is_some_and(|arg| U256::from_be_slice(arg).is_zero())
            {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Erc4626,
                    vuln: VulnType::RoundingLeakage,
                    severity: ProtocolSeverity::Medium,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence: "convertToShares returned zero for nonzero asset input".to_string(),
                });
            }
        }
    }

    fn evaluate_amm(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolFinding>,
    ) {
        for call in calls_with_selectors(execution, &[UNISWAP_V2_SWAP, UNISWAP_V3_SWAP]) {
            let writes = writes_for_target(execution, call.target, call.tx_index);
            if writes.len() >= 2 {
                let mut deltas: Vec<_> = writes.iter().map(|diff| abs_delta(diff)).collect();
                deltas.sort();
                let max = *deltas.last().unwrap_or(&U256::ZERO);
                let min = *deltas.first().unwrap_or(&U256::ZERO);
                if !min.is_zero() && max / min > U256::from(100) {
                    findings.push(ProtocolFinding {
                        pack: ProtocolOraclePackKind::Amm,
                        vuln: VulnType::UniswapV3LiquidityAsymmetry,
                        severity: ProtocolSeverity::High,
                        tx_index: Some(call.tx_index),
                        target: Some(call.target),
                        evidence: format!(
                            "swap created asymmetric reserve/storage deltas max={max} min={min}"
                        ),
                    });
                }
            }
        }

        let reserve_reads = calls_with_selectors(execution, &[GET_RESERVES]);
        let mut by_target: HashMap<Address, Vec<U256>> = HashMap::new();
        for call in reserve_reads {
            if let Some(value) = output_u256(call) {
                by_target.entry(call.target).or_default().push(value);
            }
        }
        for (target, values) in by_target {
            for window in values.windows(2) {
                let prev = window[0];
                let curr = window[1];
                let diff = if curr > prev {
                    curr - prev
                } else {
                    prev - curr
                };
                if !prev.is_zero()
                    && diff * U256::from(10_000) / prev > U256::from(self.price_move_threshold_bps)
                {
                    findings.push(ProtocolFinding {
                        pack: ProtocolOraclePackKind::Amm,
                        vuln: VulnType::PriceManipulation,
                        severity: ProtocolSeverity::High,
                        tx_index: None,
                        target: Some(target),
                        evidence: format!(
                            "reserve view moved by more than {} bps",
                            self.price_move_threshold_bps
                        ),
                    });
                }
            }
        }
    }

    fn evaluate_lending(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolFinding>,
    ) {
        let calls = calls_with_selectors(
            execution,
            &[
                AAVE_SUPPLY,
                AAVE_BORROW,
                AAVE_REPAY,
                AAVE_LIQUIDATION_CALL,
                COMPOUND_BORROW,
                COMPOUND_REDEEM,
            ],
        );
        for call in calls {
            let writes = writes_for_target(execution, call.target, call.tx_index);
            let large_decrease_without_repay =
                writes.iter().any(|diff| {
                    diff.old_value > diff.new_value
                        && diff.old_value - diff.new_value >= self.large_diff_threshold
                }) && !matches!(selector(call), Some(AAVE_REPAY | AAVE_LIQUIDATION_CALL));

            if large_decrease_without_repay {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Lending,
                    vuln: VulnType::AccountingDesync,
                    severity: ProtocolSeverity::High,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence:
                        "large lending-market storage decrease outside repay/liquidation path"
                            .to_string(),
                });
            }

            if matches!(selector(call), Some(AAVE_BORROW | COMPOUND_BORROW))
                && writes.is_empty()
                && call.success
                && call.phase == CallPhase::End
            {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Lending,
                    vuln: VulnType::InvariantViolation(
                        "borrow succeeded without observed accounting writes".to_string(),
                    ),
                    severity: ProtocolSeverity::Medium,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence: "borrow-like call succeeded but no storage writes were observed"
                        .to_string(),
                });
            }
        }
    }

    fn evaluate_governance(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolFinding>,
    ) {
        let mut saw_vote = false;
        let mut saw_flashloan_like_call = false;
        for call in &execution.call_trace {
            let sel = selector(call);
            saw_vote |= sel == Some(GOVERNOR_CAST_VOTE);
            saw_flashloan_like_call |= call.input.starts_with(&[0x5c, 0x19, 0xe9, 0x51]);

            if matches!(sel, Some(GOVERNOR_EXECUTE | TIMELOCK_QUEUE)) {
                let prior_votes = execution
                    .call_trace
                    .iter()
                    .filter(|prior| {
                        prior.tx_index <= call.tx_index
                            && selector(prior) == Some(GOVERNOR_CAST_VOTE)
                    })
                    .count();
                if prior_votes == 0 {
                    findings.push(ProtocolFinding {
                        pack: ProtocolOraclePackKind::Governance,
                        vuln: VulnType::GovernanceTakeover,
                        severity: ProtocolSeverity::Critical,
                        tx_index: Some(call.tx_index),
                        target: Some(call.target),
                        evidence: "execute/queue observed without prior vote in sequence"
                            .to_string(),
                    });
                }
                if saw_flashloan_like_call {
                    findings.push(ProtocolFinding {
                        pack: ProtocolOraclePackKind::Governance,
                        vuln: VulnType::GovernanceTakeover,
                        severity: ProtocolSeverity::Critical,
                        tx_index: Some(call.tx_index),
                        target: Some(call.target),
                        evidence: "governance execution followed flashloan-like call path"
                            .to_string(),
                    });
                }
            }
        }

        if saw_vote {
            let governance_writes = execution
                .storage_diffs
                .iter()
                .filter(|diff| abs_delta(diff) >= self.large_diff_threshold)
                .count();
            if governance_writes >= 4 {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Governance,
                    vuln: VulnType::GovernanceParameterManipulation,
                    severity: ProtocolSeverity::High,
                    tx_index: None,
                    target: None,
                    evidence: format!(
                        "vote path caused {} large governance-state storage deltas",
                        governance_writes
                    ),
                });
            }
        }

        let proposed = calls_with_selectors(execution, &[GOVERNOR_PROPOSE]).len();
        let executed = calls_with_selectors(execution, &[GOVERNOR_EXECUTE]).len();
        if executed > proposed && executed > 0 {
            findings.push(ProtocolFinding {
                pack: ProtocolOraclePackKind::Governance,
                vuln: VulnType::GovernanceTakeover,
                severity: ProtocolSeverity::Critical,
                tx_index: None,
                target: None,
                evidence: format!("observed {executed} executes but only {proposed} proposes"),
            });
        }
    }

    fn evaluate_proxy_upgradeability(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolFinding>,
    ) {
        let initializer_selectors = [
            sig("initialize()"),
            sig("initialize(address)"),
            sig("initialize(address,address)"),
            sig("initialize(bytes)"),
            sig("reinitialize(uint8)"),
        ];
        let upgrade_selectors = [
            sig("upgradeTo(address)"),
            sig("upgradeToAndCall(address,bytes)"),
        ];
        let implementation_slot = eip1967_slot("eip1967.proxy.implementation");
        let admin_slot = eip1967_slot("eip1967.proxy.admin");

        for call in calls_with_selectors(execution, &initializer_selectors) {
            if !call.success {
                continue;
            }
            let writes = writes_for_target(execution, call.target, call.tx_index);
            if writes.is_empty() {
                continue;
            }
            let eip1967_writes = writes
                .iter()
                .filter(|diff| diff.slot == implementation_slot || diff.slot == admin_slot)
                .count();
            findings.push(ProtocolFinding {
                pack: ProtocolOraclePackKind::ProxyUpgradeability,
                vuln: VulnType::ProxyUpgradeabilityViolation,
                severity: if eip1967_writes > 0 {
                    ProtocolSeverity::Critical
                } else {
                    ProtocolSeverity::High
                },
                tx_index: Some(call.tx_index),
                target: Some(call.target),
                evidence: format!(
                    "successful external initializer {} wrote {} storage slots after fork/deployment state; eip1967_writes={}",
                    selector_hex(call),
                    writes.len(),
                    eip1967_writes
                ),
            });
        }

        for diff in execution.storage_diffs.iter().filter(|diff| {
            diff.old_value != diff.new_value
                && (diff.slot == implementation_slot || diff.slot == admin_slot)
        }) {
            let role = if diff.slot == implementation_slot {
                "implementation"
            } else {
                "admin"
            };
            let selector_context = execution
                .call_trace
                .iter()
                .find(|call| {
                    call.tx_index == diff.tx_index
                        && call.target == diff.address
                        && call.phase == CallPhase::End
                })
                .and_then(selector);
            let upgrade_like = selector_context.is_some_and(|sel| {
                upgrade_selectors.contains(&sel) || initializer_selectors.contains(&sel)
            });
            findings.push(ProtocolFinding {
                pack: ProtocolOraclePackKind::ProxyUpgradeability,
                vuln: VulnType::ProxyUpgradeabilityViolation,
                severity: if role == "admin" || upgrade_like {
                    ProtocolSeverity::Critical
                } else {
                    ProtocolSeverity::High
                },
                tx_index: Some(diff.tx_index),
                target: Some(diff.address),
                evidence: format!(
                    "EIP-1967 {role} slot mutated old={} new={} selector={} upgrade_like={upgrade_like}",
                    diff.old_value,
                    diff.new_value,
                    selector_context
                        .map(hex::encode)
                        .unwrap_or_else(|| "none".to_string())
                ),
            });
        }

        for call in calls_with_selectors(execution, &upgrade_selectors) {
            if call.success {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::ProxyUpgradeability,
                    vuln: VulnType::ProxyUpgradeabilityViolation,
                    severity: ProtocolSeverity::High,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence: format!(
                        "successful upgrade entrypoint {} reached through fuzzed input",
                        selector_hex(call)
                    ),
                });
            }
        }
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

fn selector(call: &CallObservation) -> Option<[u8; 4]> {
    call.input.get(0..4)?.try_into().ok()
}

fn selector_hex(call: &CallObservation) -> String {
    selector(call)
        .map(hex::encode)
        .unwrap_or_else(|| "none".to_string())
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

fn output_u256(call: &CallObservation) -> Option<U256> {
    (call.output.len() >= 32).then(|| U256::from_be_slice(&call.output[..32]))
}

fn eip1967_slot(label: &str) -> B256 {
    let value = U256::from_be_bytes(keccak256(label.as_bytes()).0).saturating_sub(U256::from(1));
    B256::from(value.to_be_bytes::<32>())
}

fn sig(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

pub fn summarize_findings_by_pack(
    findings: &[ProtocolFinding],
) -> BTreeMap<ProtocolOraclePackKind, usize> {
    let mut out = BTreeMap::new();
    for finding in findings {
        *out.entry(finding.pack.clone()).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{CallKind, ExecutionStatus, TxExecutionResult};

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn call(selector: [u8; 4]) -> CallObservation {
        CallObservation {
            tx_index: 0,
            depth: 0,
            caller: addr(0x01),
            target: addr(0xaa),
            value: U256::ZERO,
            input: selector.to_vec(),
            output: Vec::new(),
            gas_limit: 100_000,
            gas_used: 21_000,
            success: true,
            kind: CallKind::Transaction,
            phase: CallPhase::End,
            created_address: None,
            result: None,
        }
    }

    fn execution(
        call_trace: Vec<CallObservation>,
        storage_diffs: Vec<StorageDiff>,
    ) -> SequenceExecutionResult {
        SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 21_000,
                output: Vec::new(),
                coverage_hash: 0,
                coverage_edges: 0,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: storage_diffs.clone(),
                call_trace: call_trace.clone(),
                waypoints: Vec::new(),
            }],
            total_gas_used: 21_000,
            final_coverage_hash: 0,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs,
            call_trace,
            oracle_observations: Vec::new(),
        }
    }

    #[test]
    fn flags_successful_initializer_with_storage_writes() {
        let diff = StorageDiff {
            tx_index: 0,
            address: addr(0xaa),
            slot: B256::from(U256::from(7).to_be_bytes::<32>()),
            old_value: U256::ZERO,
            new_value: U256::from(1),
            pc: 0,
        };
        let findings = ProtocolOraclePack::default()
            .evaluate(&execution(vec![call(sig("initialize()"))], vec![diff]));

        assert!(findings.iter().any(|finding| {
            finding.pack == ProtocolOraclePackKind::ProxyUpgradeability
                && finding.vuln == VulnType::ProxyUpgradeabilityViolation
        }));
    }

    #[test]
    fn flags_eip1967_implementation_slot_mutation() {
        let diff = StorageDiff {
            tx_index: 0,
            address: addr(0xaa),
            slot: eip1967_slot("eip1967.proxy.implementation"),
            old_value: U256::ZERO,
            new_value: U256::from(0xbb),
            pc: 0,
        };
        let findings = ProtocolOraclePack::default().evaluate(&execution(
            vec![call(sig("upgradeTo(address)"))],
            vec![diff],
        ));

        assert!(findings.iter().any(|finding| {
            finding.pack == ProtocolOraclePackKind::ProxyUpgradeability
                && finding.severity == ProtocolSeverity::Critical
                && finding.evidence.contains("implementation slot mutated")
        }));
    }
}
