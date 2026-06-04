use crate::common::oracle::{ProtocolFinding, ProtocolOraclePackKind, ProtocolSeverity, VulnType};
use crate::engine::abi_ingest::{AbiIngestReport, SelectorClassification};
use crate::engine::bytecode_analysis::BytecodeAnalysisReport;
use crate::engine::economic_delta::{EconomicDeltaReport, EconomicStateKind};
use crate::engine::fork_setup::ForkSetupReport;
use crate::engine::formal_spec::FormalSpecification;
use crate::engine::permission_model::PermissionModelAnalyzer;
use crate::engine::state_transition_checker::StateTransitionChecker;
use crate::engine::target_profile::ProtocolType;
use crate::engine::temporal_constraints::TemporalConstraintChecker;
use crate::satori::types::RustyFuzzJobSpec;
use anyhow::Context;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInvariantManifest {
    #[serde(default)]
    pub target: Option<Address>,
    #[serde(default)]
    pub invariants: Vec<TargetInvariantRule>,
    #[serde(skip)]
    #[serde(default)]
    pub formal_spec: Option<FormalSpecification>,
    #[serde(skip)]
    #[serde(default)]
    pub state_transition_checker: Option<StateTransitionChecker>,
    #[serde(skip)]
    #[serde(default)]
    pub permission_analyzer: Option<PermissionModelAnalyzer>,
    #[serde(skip)]
    #[serde(default)]
    pub temporal_checker: Option<TemporalConstraintChecker>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetInvariantRule {
    pub id: String,
    pub kind: TargetInvariantKind,
    #[serde(default)]
    pub max_bps: Option<u64>,
    #[serde(default)]
    pub min_profit: Option<u128>,
    #[serde(default)]
    pub severity: Option<ProtocolSeverity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetInvariantKind {
    MaxSharePriceIncreaseBps,
    MaxReservePriceMoveBps,
    NoBadDebtIncrease,
    RequireAttackerProfitBelow,
    RequireNoAccountingAnomaly,
    Erc4626SharePriceBound,
    AmmConstantProductNonDecreasing,
    LendingHealthFactorNotDecreasedBelowOne,
    CreditedAmountEqualsReceivedAmount,
    InterestIndexMonotonicAndBounded,
}

impl TargetInvariantManifest {
    pub fn generate(
        target: Option<Address>,
        abi_report: Option<&AbiIngestReport>,
        setup_report: Option<&ForkSetupReport>,
        satori_job: Option<&RustyFuzzJobSpec>,
    ) -> Self {
        let mut manifest = TargetInvariantManifest {
            target,
            invariants: Vec::new(),
            formal_spec: None,
            state_transition_checker: None,
            permission_analyzer: None,
            temporal_checker: None,
        };
        manifest.push_rule(
            "generic-accounting-anomaly",
            TargetInvariantKind::RequireNoAccountingAnomaly,
            Some(ProtocolSeverity::Medium),
        );

        if let Some(report) = abi_report {
            for function in &report.functions {
                match function.classification {
                    SelectorClassification::Erc4626Like => manifest.push_rule(
                        "erc4626-share-price-bound",
                        TargetInvariantKind::Erc4626SharePriceBound,
                        Some(ProtocolSeverity::High),
                    ),
                    SelectorClassification::Erc20Like => manifest.push_rule(
                        "fee-token-credit-conservation",
                        TargetInvariantKind::CreditedAmountEqualsReceivedAmount,
                        Some(ProtocolSeverity::High),
                    ),
                    SelectorClassification::OraclePrice | SelectorClassification::PoolEconomic => {
                        manifest.push_rule(
                            "market-price-move-bound",
                            TargetInvariantKind::MaxReservePriceMoveBps,
                            Some(ProtocolSeverity::High),
                        );
                        manifest.push_rule(
                            "amm-k-product-nondecreasing",
                            TargetInvariantKind::AmmConstantProductNonDecreasing,
                            Some(ProtocolSeverity::High),
                        );
                    }
                    SelectorClassification::WithdrawClaim
                    | SelectorClassification::FactoryOrPoolCreation
                    | SelectorClassification::RegistryMutation => manifest.push_rule(
                        "attacker-profit-bound",
                        TargetInvariantKind::RequireAttackerProfitBelow,
                        Some(ProtocolSeverity::High),
                    ),
                    SelectorClassification::Governance
                    | SelectorClassification::OwnershipAdmin
                    | SelectorClassification::UpgradeProxyInit => manifest.push_rule(
                        "privileged-accounting-integrity",
                        TargetInvariantKind::RequireNoAccountingAnomaly,
                        Some(ProtocolSeverity::Critical),
                    ),
                    _ => {}
                }
            }
            if report
                .target_profile
                .protocol_types
                .contains(&ProtocolType::LendingBorrowing)
            {
                manifest.push_rule(
                    "lending-health-factor-bound",
                    TargetInvariantKind::LendingHealthFactorNotDecreasedBelowOne,
                    Some(ProtocolSeverity::Critical),
                );
                manifest.push_rule(
                    "interest-index-monotonic-bound",
                    TargetInvariantKind::InterestIndexMonotonicAndBounded,
                    Some(ProtocolSeverity::High),
                );
            }
            if report
                .target_profile
                .protocol_types
                .contains(&ProtocolType::AccountingHeavy)
            {
                manifest.push_rule(
                    "accounting-credit-conservation",
                    TargetInvariantKind::CreditedAmountEqualsReceivedAmount,
                    Some(ProtocolSeverity::High),
                );
            }
        }

        if let Some(report) = setup_report {
            if !report.oracle_feeds.is_empty() || !report.pools.is_empty() {
                manifest.push_rule(
                    "fork-setup-price-integrity",
                    TargetInvariantKind::MaxReservePriceMoveBps,
                    Some(ProtocolSeverity::High),
                );
            }
            if !report.collateral_assets.is_empty() {
                manifest.push_rule(
                    "fork-setup-solvency",
                    TargetInvariantKind::NoBadDebtIncrease,
                    Some(ProtocolSeverity::Critical),
                );
            }
            if !report.tokens.is_empty() || !report.whales.is_empty() {
                manifest.push_rule(
                    "fork-setup-profit-bound",
                    TargetInvariantKind::RequireAttackerProfitBelow,
                    Some(ProtocolSeverity::High),
                );
            }
        }

        if let Some(job) = satori_job {
            for invariant in &job.invariants {
                let lowered = format!(
                    "{} {} {}",
                    invariant.id, invariant.description, invariant.expected_signal
                )
                .to_ascii_lowercase();
                if lowered.contains("price") || lowered.contains("oracle") {
                    manifest.push_rule(
                        &format!("satori-{}-price", invariant.id),
                        TargetInvariantKind::MaxReservePriceMoveBps,
                        Some(ProtocolSeverity::High),
                    );
                } else if lowered.contains("profit")
                    || lowered.contains("withdraw")
                    || lowered.contains("balance")
                {
                    manifest.push_rule(
                        &format!("satori-{}-profit", invariant.id),
                        TargetInvariantKind::RequireAttackerProfitBelow,
                        Some(ProtocolSeverity::High),
                    );
                } else {
                    manifest.push_rule(
                        &format!("satori-{}-accounting", invariant.id),
                        TargetInvariantKind::RequireNoAccountingAnomaly,
                        Some(ProtocolSeverity::Medium),
                    );
                }
            }
        }

        manifest.invariants.sort_by(|a, b| a.id.cmp(&b.id));
        manifest.invariants.dedup_by(|a, b| a.id == b.id);
        manifest
    }

    pub fn apply_bytecode_report(&mut self, report: &BytecodeAnalysisReport) {
        for summary in &report.function_summaries {
            let selector = hex::encode(summary.selector);
            if summary.behavior.writes_storage {
                self.push_rule(
                    &format!("bytecode-{selector}-accounting"),
                    TargetInvariantKind::RequireNoAccountingAnomaly,
                    Some(ProtocolSeverity::Medium),
                );
            }
            if summary.behavior.uses_call_value {
                self.push_rule(
                    &format!("bytecode-{selector}-profit-bound"),
                    TargetInvariantKind::RequireAttackerProfitBelow,
                    Some(ProtocolSeverity::High),
                );
            }
            if summary.behavior.makes_external_call || summary.behavior.makes_delegate_call {
                self.push_rule(
                    &format!("bytecode-{selector}-cross-contract-accounting"),
                    TargetInvariantKind::RequireNoAccountingAnomaly,
                    Some(ProtocolSeverity::High),
                );
            }
            if summary.behavior.uses_caller
                || summary.behavior.uses_origin
                || summary.behavior.makes_delegate_call
            {
                self.push_rule(
                    &format!("bytecode-{selector}-access-control"),
                    TargetInvariantKind::RequireNoAccountingAnomaly,
                    Some(ProtocolSeverity::Critical),
                );
            }
            match summary.protocol_type_hint {
                Some(ProtocolType::Erc4626Vault) => self.push_rule(
                    &format!("bytecode-{selector}-share-price"),
                    TargetInvariantKind::Erc4626SharePriceBound,
                    Some(ProtocolSeverity::High),
                ),
                Some(ProtocolType::AmmDexPool) | Some(ProtocolType::OraclePriceFeed) => self
                    .push_rule(
                        &format!("bytecode-{selector}-price"),
                        TargetInvariantKind::MaxReservePriceMoveBps,
                        Some(ProtocolSeverity::High),
                    ),
                Some(ProtocolType::LendingBorrowing) => {
                    self.push_rule(
                        &format!("bytecode-{selector}-solvency"),
                        TargetInvariantKind::LendingHealthFactorNotDecreasedBelowOne,
                        Some(ProtocolSeverity::Critical),
                    );
                    self.push_rule(
                        &format!("bytecode-{selector}-interest-index"),
                        TargetInvariantKind::InterestIndexMonotonicAndBounded,
                        Some(ProtocolSeverity::High),
                    );
                }
                Some(ProtocolType::Erc20Token) | Some(ProtocolType::AccountingHeavy) => self
                    .push_rule(
                        &format!("bytecode-{selector}-credit-conservation"),
                        TargetInvariantKind::CreditedAmountEqualsReceivedAmount,
                        Some(ProtocolSeverity::High),
                    ),
                _ => {}
            }
        }
        self.invariants.sort_by(|a, b| a.id.cmp(&b.id));
        self.invariants.dedup_by(|a, b| a.id == b.id);
    }

    fn push_rule(
        &mut self,
        id: &str,
        kind: TargetInvariantKind,
        severity: Option<ProtocolSeverity>,
    ) {
        if self.invariants.iter().any(|rule| rule.id == id) {
            return;
        }
        self.invariants.push(TargetInvariantRule {
            id: id.to_string(),
            kind,
            max_bps: Some(500),
            min_profit: Some(1),
            severity,
        });
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read target invariant manifest {}", path.display()))?;
        toml::from_str(&raw)
            .with_context(|| format!("parse target invariant manifest {}", path.display()))
    }

    pub fn load_with_formal_spec(
        path: impl AsRef<Path>,
        spec_path: Option<impl AsRef<Path>>,
    ) -> anyhow::Result<Self> {
        let mut manifest = Self::load(path)?;

        if let Some(spec_path) = spec_path {
            let formal_spec = FormalSpecification::load(&spec_path)?;
            manifest.initialize_checkers(&formal_spec);
        }

        Ok(manifest)
    }

    pub fn initialize_checkers(&mut self, spec: &FormalSpecification) {
        self.formal_spec = Some(spec.clone());
        self.state_transition_checker = Some(StateTransitionChecker::new(Some(spec)));
        self.permission_analyzer = Some(PermissionModelAnalyzer::new(Some(spec)));
        self.temporal_checker = Some(TemporalConstraintChecker::new(Some(spec)));
    }

    pub fn check_temporal_constraints(&self) -> Vec<String> {
        self.temporal_checker
            .as_ref()
            .map(|tc| {
                tc.violations()
                    .iter()
                    .map(|v| format!("{}: {}", v.constraint_id, v.reason))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn check_permission_model(&self) -> Vec<String> {
        self.permission_analyzer
            .as_ref()
            .map(|pa| {
                pa.get_anomalies()
                    .iter()
                    .map(|a| format!("{:?}: {}", a.kind, a.evidence))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn check_state_transitions(&self) -> Vec<String> {
        self.state_transition_checker
            .as_ref()
            .map(|stc| {
                stc.violations()
                    .iter()
                    .map(|v| {
                        format!(
                            "{}: {} -> {} ({})",
                            v.tx_index, v.from_state, v.to_state, v.reason
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn evaluate(&self, report: &EconomicDeltaReport) -> Vec<ProtocolFinding> {
        self.invariants
            .iter()
            .filter_map(|rule| self.evaluate_rule(rule, report))
            .collect()
    }

    fn evaluate_rule(
        &self,
        rule: &TargetInvariantRule,
        report: &EconomicDeltaReport,
    ) -> Option<ProtocolFinding> {
        let violated = match rule.kind {
            TargetInvariantKind::MaxSharePriceIncreaseBps => {
                report.share_price_pressure && report.accounting_anomaly
            }
            TargetInvariantKind::MaxReservePriceMoveBps => report.price_impact_pressure,
            TargetInvariantKind::NoBadDebtIncrease => report.debt_or_collateral_pressure,
            TargetInvariantKind::RequireAttackerProfitBelow => {
                report.estimated_profit > U256::from(rule.min_profit.unwrap_or_default())
            }
            TargetInvariantKind::RequireNoAccountingAnomaly => report.accounting_anomaly,
            TargetInvariantKind::Erc4626SharePriceBound => {
                max_positive_bps_for_kind(report, EconomicStateKind::ShareBalance)
                    .is_some_and(|bps| bps > rule.max_bps.unwrap_or(500))
                    || (report.share_price_pressure && report.accounting_anomaly)
            }
            TargetInvariantKind::AmmConstantProductNonDecreasing => report
                .reserve_deltas
                .iter()
                .any(|delta| delta.product_change_bps < -(rule.max_bps.unwrap_or(30) as i128)),
            TargetInvariantKind::LendingHealthFactorNotDecreasedBelowOne => {
                report.debt_or_collateral_pressure
                    && (report.suspicious_value_extraction || report.accounting_anomaly)
            }
            TargetInvariantKind::CreditedAmountEqualsReceivedAmount => {
                report.semantic_deltas.iter().any(|delta| {
                    matches!(delta.kind, EconomicStateKind::TokenBalance)
                        && delta.delta < 0
                        && report.semantic_deltas.iter().any(|credit| {
                            credit.tx_index == delta.tx_index
                                && matches!(
                                    credit.kind,
                                    EconomicStateKind::ShareBalance
                                        | EconomicStateKind::UnknownAccounting
                                )
                                && credit.delta > delta.delta.unsigned_abs() as i128
                        })
                }) || report.accounting_anomaly
            }
            TargetInvariantKind::InterestIndexMonotonicAndBounded => {
                report.semantic_deltas.iter().any(|delta| {
                    matches!(
                        delta.kind,
                        EconomicStateKind::Debt
                            | EconomicStateKind::Collateral
                            | EconomicStateKind::ShareBalance
                            | EconomicStateKind::UnknownAccounting
                    ) && (delta.delta < 0
                        || bps_change(delta.before, delta.after)
                            .is_some_and(|bps| bps > rule.max_bps.unwrap_or(500)))
                })
            }
        };
        violated.then(|| ProtocolFinding {
            pack: pack_for_rule(&rule.kind),
            vuln: vuln_for_rule(rule),
            severity: rule.severity.clone().unwrap_or(ProtocolSeverity::High),
            tx_index: None,
            target: self.target,
            evidence: invariant_evidence(rule, report),
        })
    }
}

fn pack_for_rule(kind: &TargetInvariantKind) -> ProtocolOraclePackKind {
    match kind {
        TargetInvariantKind::MaxSharePriceIncreaseBps
        | TargetInvariantKind::Erc4626SharePriceBound => ProtocolOraclePackKind::Erc4626,
        TargetInvariantKind::MaxReservePriceMoveBps
        | TargetInvariantKind::AmmConstantProductNonDecreasing => ProtocolOraclePackKind::Amm,
        TargetInvariantKind::NoBadDebtIncrease
        | TargetInvariantKind::LendingHealthFactorNotDecreasedBelowOne
        | TargetInvariantKind::InterestIndexMonotonicAndBounded => ProtocolOraclePackKind::Lending,
        TargetInvariantKind::CreditedAmountEqualsReceivedAmount => ProtocolOraclePackKind::Erc20,
        TargetInvariantKind::RequireAttackerProfitBelow
        | TargetInvariantKind::RequireNoAccountingAnomaly => ProtocolOraclePackKind::Erc20,
    }
}

fn vuln_for_rule(rule: &TargetInvariantRule) -> VulnType {
    match rule.kind {
        TargetInvariantKind::MaxSharePriceIncreaseBps
        | TargetInvariantKind::Erc4626SharePriceBound => VulnType::VaultInflation,
        TargetInvariantKind::MaxReservePriceMoveBps
        | TargetInvariantKind::AmmConstantProductNonDecreasing => VulnType::PriceManipulation,
        TargetInvariantKind::NoBadDebtIncrease
        | TargetInvariantKind::LendingHealthFactorNotDecreasedBelowOne => {
            VulnType::InvariantViolation("target-specific bad debt invariant".to_string())
        }
        TargetInvariantKind::CreditedAmountEqualsReceivedAmount => VulnType::AccountingDesync,
        TargetInvariantKind::InterestIndexMonotonicAndBounded => VulnType::PrecisionLossExploit,
        TargetInvariantKind::RequireAttackerProfitBelow => VulnType::FlashLoanProfit,
        TargetInvariantKind::RequireNoAccountingAnomaly => VulnType::AccountingDesync,
    }
}

fn invariant_evidence(rule: &TargetInvariantRule, report: &EconomicDeltaReport) -> String {
    let max_share_bps = max_positive_bps_for_kind(report, EconomicStateKind::ShareBalance);
    let worst_product_drop_bps = report
        .reserve_deltas
        .iter()
        .map(|delta| delta.product_change_bps)
        .min();
    let max_price_bps = report
        .price_impact
        .as_ref()
        .map(|impact| impact.max_price_change_bps);
    format!(
        "math invariant `{}` violated via {:?}; limit_bps={:?}; share_bps={:?}; k_change_bps={:?}; price_bps={:?}; confidence={}; profit={}; caveats={}",
        rule.id,
        rule.kind,
        rule.max_bps,
        max_share_bps,
        worst_product_drop_bps,
        max_price_bps,
        report.confidence,
        report.estimated_profit,
        report.caveats.join("; ")
    )
}

fn max_positive_bps_for_kind(report: &EconomicDeltaReport, kind: EconomicStateKind) -> Option<u64> {
    report
        .semantic_deltas
        .iter()
        .filter(|delta| delta.kind == kind)
        .filter_map(|delta| bps_change(delta.before, delta.after))
        .max()
}

fn bps_change(before: U256, after: U256) -> Option<u64> {
    if before.is_zero() {
        return (!after.is_zero()).then_some(u64::MAX);
    }
    if after <= before {
        return Some(0);
    }
    let delta = after - before;
    Some(((delta.saturating_mul(U256::from(10_000u64))) / before).to::<u64>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::U256;

    #[test]
    fn manifest_rule_converts_economic_delta_to_protocol_finding() {
        let manifest = TargetInvariantManifest {
            target: Some(Address::new([0x42; 20])),
            invariants: vec![TargetInvariantRule {
                id: "share-price-bound".to_string(),
                kind: TargetInvariantKind::MaxSharePriceIncreaseBps,
                max_bps: Some(50),
                min_profit: None,
                severity: Some(ProtocolSeverity::Critical),
            }],
            formal_spec: None,
            state_transition_checker: None,
            permission_analyzer: None,
            temporal_checker: None,
        };
        let report = EconomicDeltaReport {
            share_price_pressure: true,
            accounting_anomaly: true,
            confidence: 95,
            estimated_profit: U256::from(1),
            ..EconomicDeltaReport::default()
        };
        let findings = manifest.evaluate(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, ProtocolSeverity::Critical);
        assert_eq!(findings[0].target, manifest.target);
    }

    #[test]
    fn generated_manifest_uses_abi_and_satori_context() {
        let target = Address::new([0x42; 20]);
        let abi: alloy_json_abi::JsonAbi = serde_json::from_str(
            r#"[
              {"type":"function","name":"deposit","stateMutability":"nonpayable","inputs":[{"name":"assets","type":"uint256"},{"name":"receiver","type":"address"}],"outputs":[]},
              {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[]}
            ]"#,
        )
        .unwrap();
        let (_registry, abi_report) =
            crate::engine::abi_ingest::ingest_abi(&abi, Some(target), None);
        let job = crate::satori::types::RustyFuzzJobSpec {
            job_id: "j1".to_string(),
            hypothesis_id: "h1".to_string(),
            job_type: "sequence_fuzz".to_string(),
            target_contract: Some(target.to_string()),
            bug_class: "oracle".to_string(),
            actors: Vec::new(),
            preconditions: Vec::new(),
            sequence_template: Vec::new(),
            mutation_focus: Vec::new(),
            invariants: vec![crate::satori::types::CandidateInvariant {
                id: "oracle-bound".to_string(),
                description: "price cannot move too far".to_string(),
                check: "price bound".to_string(),
                expected_signal: "price movement".to_string(),
            }],
            objective: "price manipulation".to_string(),
            success_condition: "local replay".to_string(),
            max_depth: 2,
            fork_rpc_url: None,
            fork_block: None,
            abi_hints: Vec::new(),
        };

        let manifest =
            TargetInvariantManifest::generate(Some(target), Some(&abi_report), None, Some(&job));

        assert!(manifest
            .invariants
            .iter()
            .any(|rule| rule.kind == TargetInvariantKind::Erc4626SharePriceBound));
        assert!(manifest
            .invariants
            .iter()
            .any(|rule| rule.id.contains("satori-oracle-bound")));
    }

    #[test]
    fn bytecode_report_adds_selector_specific_invariants() {
        let selector = crate::engine::target_profile::function_selector("deposit(uint256,address)");
        let mut bytecode = vec![0x60, 0x00, 0x35, 0x63];
        bytecode.extend(selector);
        bytecode.extend([0x14, 0x60, 0x20, 0x57, 0x00]);
        while bytecode.len() < 0x20 {
            bytecode.push(0x00);
        }
        bytecode.extend([
            0x5b, // jumpdest
            0x34, // callvalue
            0x60, 0x02, // slot
            0x55, // sstore
            0x00, // stop
        ]);
        let report = crate::engine::bytecode_analysis::analyze_bytecode(&bytecode);
        let mut manifest = TargetInvariantManifest::generate(None, None, None, None);

        manifest.apply_bytecode_report(&report);

        assert!(manifest
            .invariants
            .iter()
            .any(|rule| rule.id.contains("profit-bound")));
        assert!(manifest
            .invariants
            .iter()
            .any(|rule| rule.kind == TargetInvariantKind::Erc4626SharePriceBound));
    }

    #[test]
    fn explicit_math_rules_use_concrete_delta_evidence() {
        let target = Address::new([0x42; 20]);
        let manifest = TargetInvariantManifest {
            target: Some(target),
            invariants: vec![
                TargetInvariantRule {
                    id: "erc4626-donation-inflation".to_string(),
                    kind: TargetInvariantKind::Erc4626SharePriceBound,
                    max_bps: Some(100),
                    min_profit: None,
                    severity: Some(ProtocolSeverity::High),
                },
                TargetInvariantRule {
                    id: "amm-k-product".to_string(),
                    kind: TargetInvariantKind::AmmConstantProductNonDecreasing,
                    max_bps: Some(30),
                    min_profit: None,
                    severity: Some(ProtocolSeverity::High),
                },
            ],
            formal_spec: None,
            state_transition_checker: None,
            permission_analyzer: None,
            temporal_checker: None,
        };
        let report = EconomicDeltaReport {
            semantic_deltas: vec![crate::engine::economic_delta::SemanticValueDelta {
                tx_index: 0,
                address: target,
                slot: revm::primitives::B256::ZERO,
                before: U256::from(10_000u64),
                after: U256::from(10_200u64),
                delta: 200,
                kind: EconomicStateKind::ShareBalance,
                confidence: 95,
                reason: "concrete vault share-price view delta".to_string(),
            }],
            reserve_deltas: vec![crate::engine::economic_delta::ReserveDelta {
                pool: target,
                tx_index: 0,
                slot_a: revm::primitives::B256::ZERO,
                slot_b: revm::primitives::B256::ZERO,
                reserve_a_before: U256::from(100u64),
                reserve_a_after: U256::from(80u64),
                reserve_b_before: U256::from(100u64),
                reserve_b_after: U256::from(100u64),
                product_before: U256::from(10_000u64),
                product_after: U256::from(8_000u64),
                product_change_bps: -2_000,
                price_change_bps: Some(2_500),
                confidence: 95,
            }],
            share_price_pressure: true,
            price_impact_pressure: true,
            accounting_anomaly: true,
            confidence: 95,
            ..EconomicDeltaReport::default()
        };

        let findings = manifest.evaluate(&report);
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|finding| finding.evidence.contains("share_bps=Some(200)")));
        assert!(findings
            .iter()
            .any(|finding| finding.evidence.contains("k_change_bps=Some(-2000)")));
    }
}
