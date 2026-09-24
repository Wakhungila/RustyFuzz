use crate::common::oracle::{EvidenceGrade, ProtocolInvariantEvaluator, RejectionReason, VulnType};
use crate::common::types::{
    CallKind, CallObservation, CallPhase, ExecutionStatus, OracleObservation,
    SequenceExecutionResult, StorageDiff,
};
use revm::primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const ERC20_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const ERC20_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const ERC20_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const ERC20_MINT: [u8; 4] = [0x40, 0xc1, 0x0f, 0x19];
const ERC20_TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];

const ERC4626_DEPOSIT: [u8; 4] = [0x6e, 0x55, 0x3f, 0x65];
const ERC4626_MINT: [u8; 4] = [0x94, 0xbf, 0x80, 0x4d];
const ERC4626_WITHDRAW: [u8; 4] = [0xb4, 0x60, 0xaf, 0x94];
const ERC4626_REDEEM: [u8; 4] = [0xba, 0x08, 0x76, 0x52];
const ERC4626_TOTAL_ASSETS: [u8; 4] = [0x01, 0xe1, 0xd1, 0x14];
const ERC4626_CONVERT_TO_SHARES: [u8; 4] = [0xc6, 0xe6, 0xf5, 0x92];

const UNISWAP_V2_SWAP: [u8; 4] = [0x02, 0x2c, 0x0d, 0x9f];
const UNISWAP_V3_SWAP: [u8; 4] = [0x12, 0x8a, 0xcb, 0x08];
const GET_RESERVES: [u8; 4] = [0x09, 0x02, 0xf1, 0xac];

const AAVE_SUPPLY: [u8; 4] = [0x61, 0x7b, 0xa0, 0x37];
const AAVE_BORROW: [u8; 4] = [0xa4, 0x15, 0xbc, 0xad];
const AAVE_REPAY: [u8; 4] = [0x57, 0x3a, 0xde, 0x81];
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

impl ProtocolFinding {
    /// Adapts a legacy pack finding into the canonical [`rustyfuzz_core::
    /// OracleSignal`] shape (Stage 4B).
    ///
    /// Detection logic is untouched: this is a pure mapping for downstream
    /// consumers that speak the canonical signal model. Severity hints are
    /// carried verbatim; strength defaults to heuristic because pack findings
    /// are snapshot-diff heuristics until deterministic replay backs them.
    ///
    /// TODO(stage-4): retire once oracle packs emit `OracleSignal` directly.
    pub fn to_signal(&self) -> rustyfuzz_core::OracleSignal {
        let rule_id = rustyfuzz_core::OracleId::new(format!(
            "pack.{}",
            format!("{:?}", self.pack).to_ascii_lowercase()
        ))
        .unwrap_or_else(|_| rustyfuzz_core::OracleId::new("pack.unknown").expect("static id"));
        rustyfuzz_core::OracleSignal::heuristic(
            rule_id,
            format!("{:?}", self.vuln),
            self.evidence.clone(),
        )
        .with_severity(format!("{:?}", self.severity))
        .with_tx_index(self.tx_index)
        .with_target(self.target.map(|address| address.to_string()))
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OracleBugClass {
    UnauthorizedAssetDrain,
    BalanceInvariantViolation,
    ShareAccountingInflation,
    DonationManipulation,
    ReentrancyStateInconsistency,
    AccessControlBypass,
    OraclePriceManipulation,
    LiquidationAccounting,
    FeeBypassManipulation,
    ApprovalAllowanceAbuse,
    MintPolicyViolation,
    UpgradeProxyMisconfiguration,
    RoundingAmplification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RequiredProofArtifact {
    RealismProof,
    FoundryPoc,
    StorageDeltaAssertion,
    BalanceDeltaAssertion,
    CallTraceAssertion,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OracleSpec {
    pub name: &'static str,
    pub bug_class: OracleBugClass,
    pub pack: ProtocolOraclePackKind,
    pub required_preconditions: &'static [&'static str],
    pub required_state_observations: &'static [&'static str],
    pub positive_trigger_conditions: &'static [&'static str],
    pub negative_rejection_rules: &'static [&'static str],
    pub minimum_evidence_grade: EvidenceGrade,
    pub required_proof_artifact: RequiredProofArtifact,
}

pub const ORACLE_SPECS: &[OracleSpec] = &[
    OracleSpec {
        name: "unauthorized-asset-drain",
        bug_class: OracleBugClass::UnauthorizedAssetDrain,
        pack: ProtocolOraclePackKind::Erc20,
        required_preconditions: &["attacker is not privileged", "real balance exists on fork"],
        required_state_observations: &["attacker balance delta", "victim/target balance delta"],
        positive_trigger_conditions: &["attacker gains assets while target/victim loses assets"],
        negative_rejection_rules: &[
            "caller is owner/admin/approved operator",
            "delta is explained by a successful user withdrawal",
            "profit requires synthetic balance",
        ],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::BalanceDeltaAssertion,
    },
    OracleSpec {
        name: "balance-invariant-violation",
        bug_class: OracleBugClass::BalanceInvariantViolation,
        pack: ProtocolOraclePackKind::Erc20,
        required_preconditions: &["token/accounting slots are observed before and after"],
        required_state_observations: &["supply or reserve slot", "account balance slots"],
        positive_trigger_conditions: &["aggregate balance relation changes unexpectedly"],
        negative_rejection_rules: &[
            "mint/burn path explains supply movement",
            "insufficient balance observations",
        ],
        minimum_evidence_grade: EvidenceGrade::DeterministicReplay,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
    OracleSpec {
        name: "share-accounting-inflation",
        bug_class: OracleBugClass::ShareAccountingInflation,
        pack: ProtocolOraclePackKind::Erc4626,
        required_preconditions: &["vault share/accounting reads are available"],
        required_state_observations: &[
            "totalAssets/totalSupply style reads",
            "share or asset deltas",
        ],
        positive_trigger_conditions: &[
            "share price/accounting moves in attacker-favorable direction",
        ],
        negative_rejection_rules: &["zero-asset input", "profit disappears after minimization"],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
    OracleSpec {
        name: "donation-manipulation",
        bug_class: OracleBugClass::DonationManipulation,
        pack: ProtocolOraclePackKind::Erc4626,
        required_preconditions: &["donation or unsolicited asset movement is observed"],
        required_state_observations: &["asset reserve delta", "share mint/redeem delta"],
        positive_trigger_conditions: &["donation changes share/accounting outcome"],
        negative_rejection_rules: &["delta is normal deposit/mint accounting"],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::BalanceDeltaAssertion,
    },
    OracleSpec {
        name: "reentrancy-state-inconsistency",
        bug_class: OracleBugClass::ReentrancyStateInconsistency,
        pack: ProtocolOraclePackKind::RuntimePanic,
        required_preconditions: &["nested external call or callback is observed"],
        required_state_observations: &["pre-callback state", "post-callback state"],
        positive_trigger_conditions: &[
            "state is externally observable before invariant restoration",
        ],
        negative_rejection_rules: &[
            "no nested call",
            "only a revert without state inconsistency",
        ],
        minimum_evidence_grade: EvidenceGrade::DeterministicReplay,
        required_proof_artifact: RequiredProofArtifact::CallTraceAssertion,
    },
    OracleSpec {
        name: "access-control-bypass",
        bug_class: OracleBugClass::AccessControlBypass,
        pack: ProtocolOraclePackKind::Governance,
        required_preconditions: &["caller is not authorized in fork state"],
        required_state_observations: &["privileged selector call", "privileged storage delta"],
        positive_trigger_conditions: &["unauthorized caller mutates protected state"],
        negative_rejection_rules: &["caller has owner/admin role", "role is invented by setup"],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
    OracleSpec {
        name: "oracle-price-manipulation",
        bug_class: OracleBugClass::OraclePriceManipulation,
        pack: ProtocolOraclePackKind::Amm,
        required_preconditions: &["price/reserve read is observed before dependent action"],
        required_state_observations: &["price/reserve output", "dependent borrow/swap/liquidation"],
        positive_trigger_conditions: &["dependent action uses manipulated price/reserve"],
        negative_rejection_rules: &["price movement is within configured threshold"],
        minimum_evidence_grade: EvidenceGrade::DeterministicReplay,
        required_proof_artifact: RequiredProofArtifact::CallTraceAssertion,
    },
    OracleSpec {
        name: "liquidation-accounting",
        bug_class: OracleBugClass::LiquidationAccounting,
        pack: ProtocolOraclePackKind::Lending,
        required_preconditions: &["debt/collateral accounting slots are observed"],
        required_state_observations: &["borrower debt delta", "collateral delta"],
        positive_trigger_conditions: &["liquidation or borrow accounting relation is violated"],
        negative_rejection_rules: &["normal repay/liquidation explains the delta"],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
    OracleSpec {
        name: "fee-bypass-manipulation",
        bug_class: OracleBugClass::FeeBypassManipulation,
        pack: ProtocolOraclePackKind::Amm,
        required_preconditions: &["fee/reward accounting slots are observed"],
        required_state_observations: &["fee accumulator delta", "trade or withdrawal delta"],
        positive_trigger_conditions: &["value movement avoids expected fee accounting"],
        negative_rejection_rules: &["fee-exempt role is real in fork state"],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
    OracleSpec {
        name: "approval-allowance-abuse",
        bug_class: OracleBugClass::ApprovalAllowanceAbuse,
        pack: ProtocolOraclePackKind::Erc20,
        required_preconditions: &["allowance slot or approval call is observed"],
        required_state_observations: &["allowance delta", "transferFrom path"],
        positive_trigger_conditions: &["allowance is consumed or expanded without owner intent"],
        negative_rejection_rules: &[
            "owner explicitly approved allowance",
            "allowance is synthetic",
        ],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
    OracleSpec {
        name: "erc20-mint-policy-violation",
        bug_class: OracleBugClass::MintPolicyViolation,
        pack: ProtocolOraclePackKind::Erc20,
        required_preconditions: &["explicit mint authorization policy is observed"],
        required_state_observations: &["mint call", "supply or balance delta"],
        positive_trigger_conditions: &["mint succeeds despite explicit policy denial"],
        negative_rejection_rules: &["owner or delegated minter authorization is observed"],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
    OracleSpec {
        name: "upgrade-proxy-misconfiguration",
        bug_class: OracleBugClass::UpgradeProxyMisconfiguration,
        pack: ProtocolOraclePackKind::ProxyUpgradeability,
        required_preconditions: &["EIP-1967/admin/initializer state is observed"],
        required_state_observations: &["implementation/admin slot", "upgrade or initializer call"],
        positive_trigger_conditions: &["unprivileged path mutates upgrade-critical state"],
        negative_rejection_rules: &["caller is real admin", "initializer already consumed"],
        minimum_evidence_grade: EvidenceGrade::RealisticForkProof,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
    OracleSpec {
        name: "rounding-amplification",
        bug_class: OracleBugClass::RoundingAmplification,
        pack: ProtocolOraclePackKind::Erc4626,
        required_preconditions: &["nonzero input amount is observed"],
        required_state_observations: &["conversion output", "asset/share deltas"],
        positive_trigger_conditions: &["rounding outcome creates exploitable value difference"],
        negative_rejection_rules: &["input is zero", "loss/profit disappears after minimization"],
        minimum_evidence_grade: EvidenceGrade::DeterministicReplay,
        required_proof_artifact: RequiredProofArtifact::StorageDeltaAssertion,
    },
];

pub fn oracle_spec_by_name(name: &str) -> Option<&'static OracleSpec> {
    ORACLE_SPECS.iter().find(|spec| spec.name == name)
}

pub fn oracle_spec_for_finding(finding: &ProtocolFinding) -> Option<&'static OracleSpec> {
    ORACLE_SPECS.iter().find(|spec| {
        spec.pack == finding.pack
            && match (&spec.bug_class, &finding.vuln) {
                (OracleBugClass::UnauthorizedAssetDrain, VulnType::FlashLoanProfit)
                | (OracleBugClass::UnauthorizedAssetDrain, VulnType::FlashLoanAttack)
                | (OracleBugClass::BalanceInvariantViolation, VulnType::AccountingDesync)
                | (OracleBugClass::ShareAccountingInflation, VulnType::VaultInflation)
                | (OracleBugClass::DonationManipulation, VulnType::VaultDonationAttack)
                | (OracleBugClass::ReentrancyStateInconsistency, VulnType::Reentrancy)
                | (OracleBugClass::ReentrancyStateInconsistency, VulnType::ReadOnlyReentrancy)
                | (OracleBugClass::AccessControlBypass, VulnType::PrivilegeEscalation)
                | (OracleBugClass::AccessControlBypass, VulnType::GovernanceTakeover)
                | (OracleBugClass::OraclePriceManipulation, VulnType::PriceManipulation)
                | (OracleBugClass::OraclePriceManipulation, VulnType::PriceOracleManipulation)
                | (OracleBugClass::LiquidationAccounting, VulnType::AccountingDesync)
                | (OracleBugClass::FeeBypassManipulation, VulnType::MevSandwichExploit)
                | (
                    OracleBugClass::UpgradeProxyMisconfiguration,
                    VulnType::ProxyUpgradeabilityViolation,
                )
                | (OracleBugClass::RoundingAmplification, VulnType::RoundingLeakage) => true,
                (OracleBugClass::ApprovalAllowanceAbuse, VulnType::Other(label))
                    if label == "unbounded allowance mutation" =>
                {
                    true
                }
                (OracleBugClass::MintPolicyViolation, VulnType::Other(label))
                    if label == "mint authorization policy violation" =>
                {
                    true
                }

                (OracleBugClass::LiquidationAccounting, VulnType::InvariantViolation(label)) => {
                    label.to_ascii_lowercase().contains("lending")
                }
                _ => false,
            }
    })
}

pub fn oracle_rejection_reasons_for_finding(finding: &ProtocolFinding) -> Vec<RejectionReason> {
    let mut reasons = Vec::new();
    if finding.evidence.trim().is_empty() {
        reasons.push(RejectionReason::OracleWeakness);
    }
    if finding.target.is_none()
        && !matches!(
            finding.pack,
            ProtocolOraclePackKind::Governance | ProtocolOraclePackKind::RuntimePanic
        )
    {
        reasons.push(RejectionReason::OracleWeakness);
    }
    if finding.evidence.to_ascii_lowercase().contains("synthetic") {
        reasons.push(RejectionReason::SyntheticFundingRequired);
    }
    if finding
        .evidence
        .to_ascii_lowercase()
        .contains("invented allowance")
    {
        reasons.push(RejectionReason::MissingAllowance);
    }
    if finding.evidence.to_ascii_lowercase().contains("privileged")
        && finding.pack != ProtocolOraclePackKind::ProxyUpgradeability
    {
        reasons.push(RejectionReason::PrivilegedRoleRequired);
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

enum MintAuthorization {
    Authorized,
    Denied { tx_index: usize, rule: &'static str },
    Unknown,
}

fn mint_authorization_observation(
    execution: &SequenceExecutionResult,
    mint: &CallObservation,
) -> MintAuthorization {
    let can_mint = sig("canMint(address)");
    let is_minter = sig("isMinter(address)");
    let owner = sig("owner()");
    let Some(prior) = execution
        .call_trace
        .iter()
        .filter(|prior| {
            prior.target == mint.target
                && prior.tx_index < mint.tx_index
                && prior.success
                && prior.phase == CallPhase::End
                && prior.kind != CallKind::DelegateCall
                && matches!(selector(prior), Some(selector) if selector == can_mint || selector == is_minter || selector == owner)
        })
        .max_by_key(|prior| prior.tx_index)
    else {
        return MintAuthorization::Unknown;
    };
    let Some(selector) = selector(prior) else {
        return MintAuthorization::Unknown;
    };
    let invalidated = execution.storage_diffs.iter().any(|diff| {
        diff.address == mint.target
            && diff.tx_index > prior.tx_index
            && diff.tx_index < mint.tx_index
            && diff.old_value != diff.new_value
    }) || execution.storage_writes.iter().any(|write| {
        write.address == mint.target
            && write.tx_index > prior.tx_index
            && write.tx_index < mint.tx_index
    });
    if invalidated {
        return MintAuthorization::Unknown;
    }
    if selector == owner {
        return match output_address(prior) {
            Some(owner) if owner == mint.caller => MintAuthorization::Authorized,
            _ => MintAuthorization::Unknown,
        };
    }
    if prior.input.len() != 36
        || prior.input[4..16] != [0; 12]
        || prior.input[16..36] != mint.caller.as_slice()[..]
    {
        return MintAuthorization::Unknown;
    }
    match output_u256(prior) {
        Some(value) if value.is_zero() => MintAuthorization::Denied {
            tx_index: prior.tx_index,
            rule: if selector == can_mint {
                "canMint"
            } else {
                "isMinter"
            },
        },
        Some(_) => MintAuthorization::Authorized,
        None => MintAuthorization::Unknown,
    }
}

fn output_address(call: &CallObservation) -> Option<Address> {
    if call.output.len() < 32 || call.output[..12] != [0; 12] {
        return None;
    }
    Some(Address::from_slice(&call.output[12..32]))
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
        self.evaluate_erc20_mint_inflation(execution, findings);

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

    fn evaluate_erc20_mint_inflation(
        &self,
        execution: &SequenceExecutionResult,
        findings: &mut Vec<ProtocolFinding>,
    ) {
        for call in calls_with_selectors(execution, &[ERC20_MINT]) {
            if !call.success || call.phase != CallPhase::End || call.input.len() != 68 {
                continue;
            }
            let policy = mint_authorization_observation(execution, call);
            let MintAuthorization::Denied { tx_index, rule } = policy else {
                continue;
            };
            let writes = writes_for_target(execution, call.target, call.tx_index);
            if U256::from_be_slice(&call.input[36..68]).is_zero()
                || !writes.iter().any(|diff| diff.new_value > diff.old_value)
            {
                continue;
            }
            findings.push(ProtocolFinding {
                pack: ProtocolOraclePackKind::Erc20,
                vuln: VulnType::Other("mint authorization policy violation".to_string()),
                severity: ProtocolSeverity::High,
                tx_index: Some(call.tx_index),
                target: Some(call.target),
                evidence: format!(
                    "mint succeeded and increased storage despite {rule}({})=false at tx {}; explicit contract policy violation requires balance/supply replay confirmation",
                    call.caller, tx_index
                ),
            });
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

            if selector(call) == Some(ERC4626_DEPOSIT)
                && call.success
                && call.input.len() == 68
                && call.output.len() == 32
                && output_u256(call) == Some(U256::ZERO)
                && !U256::from_be_slice(&call.input[4..36]).is_zero()
                && execution.call_trace.iter().any(|transfer| {
                    transfer.tx_index == call.tx_index
                        && transfer.caller == call.target
                        && transfer.success
                        && transfer.phase == CallPhase::End
                        && selector(transfer) == Some(ERC20_TRANSFER_FROM)
                        && transfer.input.len() == 100
                        && transfer.input[48..68] == call.target.as_slice()[..]
                        && transfer.input[68..100] == call.input[4..36]
                        && (transfer.output.is_empty()
                            || output_u256(transfer) == Some(U256::from(1)))
                })
            {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Erc4626,
                    vuln: VulnType::VaultInflation,
                    severity: ProtocolSeverity::High,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence: "nonzero ERC4626 deposit transferred assets into vault but returned zero shares; verify victim loss in replay".to_string(),
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
            let committed_transfer = has_committed_token_transfer(execution, call);
            let reserve_movement =
                has_large_reserve_movement(execution, call, self.price_move_threshold_bps);
            let reserve_product_break = has_reserve_product_break(execution, call);
            if call.success
                && committed_transfer
                && !writes.is_empty()
                && reserve_movement
                && reserve_product_break
            {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Amm,
                    vuln: VulnType::UniswapV3LiquidityAsymmetry,
                    severity: ProtocolSeverity::High,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence: "successful swap committed a token transfer, reserve writes, and a reserve movement above the configured threshold; verify pool balance deltas in replay".to_string(),
                });
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
            let committed_transfer = has_committed_token_transfer(execution, call);
            let token_transfer_target = committed_token_transfer_target(execution, call);
            let has_debt_or_accounting_writes = execution.storage_diffs.iter().any(|diff| {
                diff.tx_index == call.tx_index
                    && diff.address != call.target
                    && Some(diff.address) != token_transfer_target
                    && !abs_delta(diff).is_zero()
            });
            if matches!(selector(call), Some(AAVE_BORROW | COMPOUND_BORROW))
                && call.success
                && committed_transfer
                && writes.is_empty()
                && !has_debt_or_accounting_writes
            {
                findings.push(ProtocolFinding {
                    pack: ProtocolOraclePackKind::Lending,
                    vuln: VulnType::InvariantViolation(
                        "borrow transferred assets without observed debt accounting writes".to_string(),
                    ),
                    severity: ProtocolSeverity::High,
                    tx_index: Some(call.tx_index),
                    target: Some(call.target),
                    evidence:
                        "successful borrow committed an asset transfer without observed debt accounting writes; verify borrower and protocol balance deltas in replay"
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
            // Rejected governance attempts are evidence that guards held, not
            // successful votes/queues/executions. Begin frames are not outcomes.
            if !call.success || call.phase != CallPhase::End {
                continue;
            }
            let sel = selector(call);
            saw_vote |= sel == Some(GOVERNOR_CAST_VOTE);
            saw_flashloan_like_call |= call.input.starts_with(&[0x5c, 0x19, 0xe9, 0x51]);

            if matches!(sel, Some(GOVERNOR_EXECUTE | TIMELOCK_QUEUE)) {
                let prior_votes = execution
                    .call_trace
                    .iter()
                    .filter(|prior| {
                        prior.tx_index <= call.tx_index
                            && prior.target == call.target
                            && prior.success
                            && prior.phase == CallPhase::End
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

        let proposed = calls_with_selectors(execution, &[GOVERNOR_PROPOSE])
            .into_iter()
            .filter(|call| call.success)
            .count();
        let executed = calls_with_selectors(execution, &[GOVERNOR_EXECUTE])
            .into_iter()
            .filter(|call| call.success)
            .count();
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

fn has_large_reserve_movement(
    execution: &SequenceExecutionResult,
    action: &CallObservation,
    threshold_bps: u64,
) -> bool {
    let reads: Vec<(usize, (U256, U256))> = calls_with_selectors(execution, &[GET_RESERVES])
        .into_iter()
        .filter(|call| call.target == action.target)
        .filter_map(|call| reserve_pair(call).map(|reserves| (call.tx_index, reserves)))
        .collect();
    reads.windows(2).any(|window| {
        let (before_index, before) = window[0];
        let (after_index, after) = window[1];
        if before_index > action.tx_index || after_index < action.tx_index {
            return false;
        }
        [before.0, before.1]
            .into_iter()
            .zip([after.0, after.1])
            .any(|(previous, current)| {
                if previous.is_zero() {
                    return false;
                }
                let delta = if current > previous {
                    current - previous
                } else {
                    previous - current
                };
                delta
                    .checked_mul(U256::from(10_000))
                    .map(|scaled| scaled / previous > U256::from(threshold_bps))
                    .unwrap_or(false)
            })
    })
}

fn has_reserve_product_break(
    execution: &SequenceExecutionResult,
    action: &CallObservation,
) -> bool {
    let reads: Vec<(usize, (U256, U256))> = calls_with_selectors(execution, &[GET_RESERVES])
        .into_iter()
        .filter(|call| call.target == action.target)
        .filter_map(|call| reserve_pair(call).map(|reserves| (call.tx_index, reserves)))
        .collect();
    reads.windows(2).any(|window| {
        let (before_index, before) = window[0];
        let (after_index, after) = window[1];
        if before_index > action.tx_index || after_index < action.tx_index {
            return false;
        }
        let Some(previous) = before.0.checked_mul(before.1) else {
            return false;
        };
        let Some(current) = after.0.checked_mul(after.1) else {
            return false;
        };
        if previous.is_zero() {
            return false;
        }
        let delta = if current > previous {
            current - previous
        } else {
            previous - current
        };
        delta
            .checked_mul(U256::from(10_000))
            .map(|scaled| scaled / previous > U256::from(100))
            .unwrap_or(false)
    })
}

fn reserve_pair(call: &CallObservation) -> Option<(U256, U256)> {
    (call.output.len() >= 64).then(|| {
        (
            U256::from_be_slice(&call.output[..32]),
            U256::from_be_slice(&call.output[32..64]),
        )
    })
}

fn transfer_amount_nonzero(call: &CallObservation) -> bool {
    let amount_start = call.input.len().saturating_sub(32);
    call.input.len() >= 68 && U256::from_be_slice(&call.input[amount_start..]) != U256::ZERO
}

fn committed_token_transfer_target(
    execution: &SequenceExecutionResult,
    action: &CallObservation,
) -> Option<Address> {
    execution
        .call_trace
        .iter()
        .find(|transfer| {
            transfer.tx_index == action.tx_index
                && transfer.success
                && transfer.phase == CallPhase::End
                && transfer.caller == action.target
                && matches!(
                    selector(transfer),
                    Some(ERC20_TRANSFER | ERC20_TRANSFER_FROM)
                )
                && ((transfer.input.len() == 68 && selector(transfer) == Some(ERC20_TRANSFER))
                    || (transfer.input.len() == 100
                        && selector(transfer) == Some(ERC20_TRANSFER_FROM)))
                && transfer_amount_nonzero(transfer)
        })
        .map(|transfer| transfer.target)
}

fn has_committed_token_transfer(
    execution: &SequenceExecutionResult,
    action: &CallObservation,
) -> bool {
    committed_token_transfer_target(execution, action).is_some()
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
mod stage_4b_tests {
    use super::*;

    /// Trust-boundary invariant (invariant #5): pack findings adapt to the
    /// canonical signal model as heuristic evidence — never as proofs.
    #[test]
    fn protocol_findings_adapt_to_heuristic_signals_with_stable_rule_ids() {
        let finding = ProtocolFinding {
            pack: ProtocolOraclePackKind::Erc4626,
            vuln: VulnType::VaultInflation,
            severity: ProtocolSeverity::High,
            tx_index: Some(2),
            target: Some(revm::primitives::Address::repeat_byte(0x44)),
            evidence: "share price anomaly".to_string(),
        };
        let signal = finding.to_signal();
        assert_eq!(signal.strength, rustyfuzz_core::SignalStrength::Heuristic);
        assert_eq!(signal.rule_id.as_str(), "pack.erc4626");
        assert_eq!(signal.severity_hint, "High");
        assert_eq!(signal.tx_index, Some(2));
        assert!(signal
            .target
            .as_deref()
            .is_some_and(|t| t.starts_with("0x")));
        // Deterministic rule id across repeated adaptation.
        assert_eq!(finding.to_signal().rule_id, signal.rule_id);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn selectors_match_canonical_abi_signatures() {
        for (signature, expected) in [
            (
                "swap(address,bool,int256,uint160,bytes)",
                super::UNISWAP_V3_SWAP,
            ),
            ("redeem(uint256)", super::COMPOUND_REDEEM),
            ("deposit(uint256,address)", super::ERC4626_DEPOSIT),
            ("mint(uint256,address)", super::ERC4626_MINT),
            ("withdraw(uint256,address,address)", super::ERC4626_WITHDRAW),
            ("redeem(uint256,address,address)", super::ERC4626_REDEEM),
            ("convertToShares(uint256)", super::ERC4626_CONVERT_TO_SHARES),
            ("totalAssets()", super::ERC4626_TOTAL_ASSETS),
            ("supply(address,uint256,address,uint16)", super::AAVE_SUPPLY),
            ("repay(address,uint256,uint256,address)", super::AAVE_REPAY),
            (
                "borrow(address,uint256,uint256,uint16,address)",
                super::AAVE_BORROW,
            ),
        ] {
            assert_eq!(
                &revm::primitives::keccak256(signature.as_bytes())[..4],
                &expected,
                "{signature}"
            );
        }
    }
    use super::*;
    use crate::common::types::{CallKind, ExecutionStatus, TxExecutionResult};

    #[test]
    fn oracle_fixture_helpers_build_deterministic_observations() {
        let observation = call([0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(observation.caller, addr(0x01));
        assert_eq!(observation.target, addr(0xaa));
        assert_eq!(observation.input, vec![0xde, 0xad, 0xbe, 0xef]);
    }

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

    #[test]
    fn oracle_execution_fixture_is_deterministic() {
        let result = execution(vec![call([0xde, 0xad, 0xbe, 0xef])], Vec::new());
        assert_eq!(result.total_gas_used, 21_000);
        assert_eq!(result.call_trace.len(), 1);
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

    fn spec_positive_finding(spec: &OracleSpec) -> ProtocolFinding {
        let vuln = match spec.bug_class {
            OracleBugClass::UnauthorizedAssetDrain => VulnType::FlashLoanProfit,
            OracleBugClass::BalanceInvariantViolation => VulnType::AccountingDesync,
            OracleBugClass::ShareAccountingInflation => VulnType::VaultInflation,
            OracleBugClass::DonationManipulation => VulnType::VaultDonationAttack,
            OracleBugClass::ReentrancyStateInconsistency => VulnType::Reentrancy,
            OracleBugClass::AccessControlBypass => VulnType::PrivilegeEscalation,
            OracleBugClass::OraclePriceManipulation => VulnType::PriceManipulation,
            OracleBugClass::LiquidationAccounting => {
                VulnType::InvariantViolation("lending health invariant".to_string())
            }
            OracleBugClass::FeeBypassManipulation => VulnType::MevSandwichExploit,
            OracleBugClass::MintPolicyViolation => {
                VulnType::Other("mint authorization policy violation".to_string())
            }
            OracleBugClass::ApprovalAllowanceAbuse => {
                VulnType::Other("unbounded allowance mutation".to_string())
            }
            OracleBugClass::UpgradeProxyMisconfiguration => VulnType::ProxyUpgradeabilityViolation,
            OracleBugClass::RoundingAmplification => VulnType::RoundingLeakage,
        };
        ProtocolFinding {
            pack: spec.pack.clone(),
            vuln,
            severity: ProtocolSeverity::High,
            tx_index: Some(0),
            target: Some(addr(0xaa)),
            evidence: format!("{} concrete fork evidence", spec.name),
        }
    }

    #[test]
    fn oracle_specs_cover_required_bug_classes() {
        assert_eq!(ORACLE_SPECS.len(), 13);
        for spec in ORACLE_SPECS {
            assert!(!spec.required_preconditions.is_empty(), "{}", spec.name);
            assert!(
                !spec.required_state_observations.is_empty(),
                "{}",
                spec.name
            );
            assert!(
                !spec.positive_trigger_conditions.is_empty(),
                "{}",
                spec.name
            );
            assert!(!spec.negative_rejection_rules.is_empty(), "{}", spec.name);
            assert!(oracle_spec_by_name(spec.name).is_some(), "{}", spec.name);
        }
    }

    #[test]
    fn each_oracle_spec_accepts_positive_and_rejects_incomplete_evidence() {
        for spec in ORACLE_SPECS {
            let positive = spec_positive_finding(spec);
            assert_eq!(
                oracle_spec_for_finding(&positive).map(|found| found.name),
                Some(spec.name),
                "{}",
                spec.name
            );
            assert!(
                oracle_rejection_reasons_for_finding(&positive).is_empty(),
                "{}",
                spec.name
            );

            let mut missing_observation = positive.clone();
            missing_observation.target = None;
            if !matches!(
                missing_observation.pack,
                ProtocolOraclePackKind::Governance | ProtocolOraclePackKind::RuntimePanic
            ) {
                assert!(
                    oracle_rejection_reasons_for_finding(&missing_observation)
                        .contains(&RejectionReason::OracleWeakness),
                    "{}",
                    spec.name
                );
            }

            let mut heuristic = positive;
            heuristic.evidence = "synthetic invented allowance privileged heuristic".to_string();
            let rejections = oracle_rejection_reasons_for_finding(&heuristic);
            assert!(
                rejections.contains(&RejectionReason::SyntheticFundingRequired),
                "{}",
                spec.name
            );
            assert!(
                rejections.contains(&RejectionReason::MissingAllowance),
                "{}",
                spec.name
            );
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

    fn observation(
        tx_index: usize,
        caller: Address,
        target: Address,
        kind: CallKind,
        success: bool,
        input: Vec<u8>,
        output: Vec<u8>,
    ) -> CallObservation {
        CallObservation {
            tx_index,
            depth: 0,
            caller,
            target,
            value: U256::ZERO,
            input,
            output,
            gas_limit: 100_000,
            gas_used: 21_000,
            success,
            kind,
            phase: CallPhase::End,
            created_address: None,
            result: None,
        }
    }

    fn address_argument(selector: [u8; 4], caller: Address) -> Vec<u8> {
        let mut input = selector.to_vec();
        input.extend_from_slice(&[0; 12]);
        input.extend_from_slice(caller.as_slice());
        input
    }

    fn address_word(address: Address) -> Vec<u8> {
        let mut output = vec![0; 12];
        output.extend_from_slice(address.as_slice());
        output
    }

    fn mint_observation(tx_index: usize, caller: Address, target: Address) -> CallObservation {
        let mut input = ERC20_MINT.to_vec();
        input.extend_from_slice(&[0; 12]);
        input.extend_from_slice(target.as_slice());
        input.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        observation(
            tx_index,
            caller,
            target,
            CallKind::Transaction,
            true,
            input,
            Vec::new(),
        )
    }

    fn increasing_diff(tx_index: usize, target: Address) -> StorageDiff {
        StorageDiff {
            tx_index,
            address: target,
            slot: B256::from(U256::from(7).to_be_bytes::<32>()),
            old_value: U256::from(1),
            new_value: U256::from(2),
            pc: 0,
        }
    }

    fn mint_violations(findings: &[ProtocolFinding]) -> bool {
        findings.iter().any(|finding| {
            finding.pack == ProtocolOraclePackKind::Erc20
                && finding.vuln
                    == VulnType::Other("mint authorization policy violation".to_string())
        })
    }

    #[test]
    fn owner_observation_authorizes_owner_mint_without_denied_probe() {
        let target = addr(0xaa);
        let owner = addr(0x01);
        let owner_selector = sig("owner()");
        let findings = ProtocolOraclePack::default().evaluate(&execution(
            vec![
                observation(
                    0,
                    owner,
                    target,
                    CallKind::StaticCall,
                    true,
                    owner_selector.to_vec(),
                    address_word(owner),
                ),
                mint_observation(1, owner, target),
            ],
            vec![increasing_diff(1, target)],
        ));
        assert!(!mint_violations(&findings));
    }

    #[test]
    fn delegated_minter_observation_authorizes_mint() {
        let target = addr(0xaa);
        let minter = addr(0x02);
        let selector = sig("isMinter(address)");
        let findings = ProtocolOraclePack::default().evaluate(&execution(
            vec![
                observation(
                    0,
                    minter,
                    target,
                    CallKind::StaticCall,
                    true,
                    address_argument(selector, minter),
                    U256::from(1).to_be_bytes::<32>().to_vec(),
                ),
                mint_observation(1, minter, target),
            ],
            vec![increasing_diff(1, target)],
        ));
        assert!(!mint_violations(&findings));
    }

    #[test]
    fn unknown_authorization_remains_unknown() {
        let target = addr(0xaa);
        let caller = addr(0x02);
        let findings = ProtocolOraclePack::default().evaluate(&execution(
            vec![mint_observation(0, caller, target)],
            vec![increasing_diff(0, target)],
        ));
        assert!(!mint_violations(&findings));
    }

    #[test]
    fn stale_denied_policy_does_not_survive_role_change() {
        let target = addr(0xaa);
        let caller = addr(0x02);
        let selector = sig("canMint(address)");
        let findings = ProtocolOraclePack::default().evaluate(&execution(
            vec![
                observation(
                    0,
                    caller,
                    target,
                    CallKind::StaticCall,
                    true,
                    address_argument(selector, caller),
                    vec![0; 32],
                ),
                mint_observation(2, caller, target),
            ],
            vec![increasing_diff(1, target), increasing_diff(2, target)],
        ));
        assert!(!mint_violations(&findings));
    }

    #[test]
    fn revoked_mint_invalidates_prior_authorized_observation() {
        let target = addr(0xaa);
        let caller = addr(0x02);
        let selector = sig("canMint(address)");
        let findings = ProtocolOraclePack::default().evaluate(&execution(
            vec![
                observation(
                    0,
                    caller,
                    target,
                    CallKind::StaticCall,
                    true,
                    address_argument(selector, caller),
                    U256::from(1).to_be_bytes::<32>().to_vec(),
                ),
                mint_observation(2, caller, target),
            ],
            vec![increasing_diff(1, target), increasing_diff(2, target)],
        ));
        assert!(!mint_violations(&findings));
    }

    #[test]
    fn rejected_or_delegated_authorization_observation_is_not_evidence() {
        let target = addr(0xaa);
        let caller = addr(0x02);
        let selector = sig("canMint(address)");
        let rejected = observation(
            0,
            caller,
            target,
            CallKind::StaticCall,
            false,
            address_argument(selector, caller),
            vec![0; 32],
        );
        let delegated = observation(
            0,
            caller,
            target,
            CallKind::DelegateCall,
            true,
            address_argument(selector, caller),
            vec![0; 32],
        );
        for policy in [rejected, delegated] {
            let findings = ProtocolOraclePack::default().evaluate(&execution(
                vec![policy, mint_observation(1, caller, target)],
                vec![increasing_diff(1, target)],
            ));
            assert!(!mint_violations(&findings));
        }
    }

    #[test]
    fn authorization_observations_do_not_cross_tokens_or_callers() {
        let target_a = addr(0xaa);
        let target_b = addr(0xbb);
        let caller = addr(0x02);
        let other_caller = addr(0x03);
        let selector = sig("canMint(address)");
        let findings = ProtocolOraclePack::default().evaluate(&execution(
            vec![
                observation(
                    0,
                    caller,
                    target_a,
                    CallKind::StaticCall,
                    true,
                    address_argument(selector, caller),
                    vec![0; 32],
                ),
                mint_observation(1, caller, target_b),
                mint_observation(2, other_caller, target_a),
            ],
            vec![increasing_diff(1, target_b), increasing_diff(2, target_a)],
        ));
        assert!(!mint_violations(&findings));
    }

    #[test]
    fn amm_evidence_requires_pool_correlated_transfer_and_reserve_reads() {
        let pool = addr(0xaa);
        let other_pool = addr(0xab);
        let token = addr(0x90);
        let reserve_output = |reserve0: U256, reserve1: U256| {
            let mut output = reserve0.to_be_bytes::<32>().to_vec();
            output.extend_from_slice(&reserve1.to_be_bytes::<32>());
            output
        };
        let mut transfer_input = ERC20_TRANSFER.to_vec();
        transfer_input.resize(68, 0);
        let findings = ProtocolOraclePack::default().evaluate(&execution(
            vec![
                observation(
                    0,
                    addr(0x01),
                    pool,
                    CallKind::StaticCall,
                    true,
                    GET_RESERVES.to_vec(),
                    reserve_output(U256::from(1_000_000), U256::from(1_000_000)),
                ),
                call(UNISWAP_V2_SWAP),
                observation(
                    1,
                    addr(0x02),
                    token,
                    CallKind::Call,
                    true,
                    transfer_input,
                    Vec::new(),
                ),
                observation(
                    2,
                    addr(0x01),
                    pool,
                    CallKind::StaticCall,
                    true,
                    GET_RESERVES.to_vec(),
                    reserve_output(U256::from(1_200_000), U256::from(1_000_000)),
                ),
                observation(
                    2,
                    addr(0x01),
                    other_pool,
                    CallKind::StaticCall,
                    true,
                    GET_RESERVES.to_vec(),
                    reserve_output(U256::from(1_000_000), U256::from(1_000_000)),
                ),
            ],
            vec![increasing_diff(1, pool)],
        ));
        assert!(!findings
            .iter()
            .any(|finding| finding.pack == ProtocolOraclePackKind::Amm));
    }

    #[test]
    fn reserve_reads_without_swap_and_borrow_without_transfer_are_not_findings() {
        let reserve_findings = ProtocolOraclePack::default()
            .evaluate(&execution(vec![call(GET_RESERVES)], Vec::new()));
        assert!(!reserve_findings
            .iter()
            .any(|finding| finding.pack == ProtocolOraclePackKind::Amm));

        let borrow_findings =
            ProtocolOraclePack::default().evaluate(&execution(vec![call(AAVE_BORROW)], Vec::new()));
        assert!(!borrow_findings
            .iter()
            .any(|finding| finding.pack == ProtocolOraclePackKind::Lending));
    }
}
