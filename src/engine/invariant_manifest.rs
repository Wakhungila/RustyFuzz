use crate::common::oracle::{ProtocolFinding, ProtocolOraclePackKind, ProtocolSeverity, VulnType};
use crate::engine::abi_ingest::{AbiIngestReport, SelectorClassification};
use crate::engine::bytecode_analysis::BytecodeAnalysisReport;
use crate::engine::economic_delta::EconomicDeltaReport;
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
                        TargetInvariantKind::MaxSharePriceIncreaseBps,
                        Some(ProtocolSeverity::High),
                    ),
                    SelectorClassification::OraclePrice | SelectorClassification::PoolEconomic => {
                        manifest.push_rule(
                            "market-price-move-bound",
                            TargetInvariantKind::MaxReservePriceMoveBps,
                            Some(ProtocolSeverity::High),
                        )
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
                    TargetInvariantKind::MaxSharePriceIncreaseBps,
                    Some(ProtocolSeverity::High),
                ),
                Some(ProtocolType::AmmDexPool) | Some(ProtocolType::OraclePriceFeed) => self
                    .push_rule(
                        &format!("bytecode-{selector}-price"),
                        TargetInvariantKind::MaxReservePriceMoveBps,
                        Some(ProtocolSeverity::High),
                    ),
                Some(ProtocolType::LendingBorrowing) => self.push_rule(
                    &format!("bytecode-{selector}-solvency"),
                    TargetInvariantKind::NoBadDebtIncrease,
                    Some(ProtocolSeverity::Critical),
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
        };
        violated.then(|| ProtocolFinding {
            pack: pack_for_rule(&rule.kind),
            vuln: vuln_for_rule(rule),
            severity: rule.severity.clone().unwrap_or(ProtocolSeverity::High),
            tx_index: None,
            target: self.target,
            evidence: format!(
                "target invariant `{}` violated via {:?}; confidence={}; profit={}; caveats={}",
                rule.id,
                rule.kind,
                report.confidence,
                report.estimated_profit,
                report.caveats.join("; ")
            ),
        })
    }
}

fn pack_for_rule(kind: &TargetInvariantKind) -> ProtocolOraclePackKind {
    match kind {
        TargetInvariantKind::MaxSharePriceIncreaseBps => ProtocolOraclePackKind::Erc4626,
        TargetInvariantKind::MaxReservePriceMoveBps => ProtocolOraclePackKind::Amm,
        TargetInvariantKind::NoBadDebtIncrease => ProtocolOraclePackKind::Lending,
        TargetInvariantKind::RequireAttackerProfitBelow
        | TargetInvariantKind::RequireNoAccountingAnomaly => ProtocolOraclePackKind::Erc20,
    }
}

fn vuln_for_rule(rule: &TargetInvariantRule) -> VulnType {
    match rule.kind {
        TargetInvariantKind::MaxSharePriceIncreaseBps => VulnType::VaultInflation,
        TargetInvariantKind::MaxReservePriceMoveBps => VulnType::PriceManipulation,
        TargetInvariantKind::NoBadDebtIncrease => {
            VulnType::InvariantViolation("target-specific bad debt invariant".to_string())
        }
        TargetInvariantKind::RequireAttackerProfitBelow => VulnType::FlashLoanProfit,
        TargetInvariantKind::RequireNoAccountingAnomaly => VulnType::AccountingDesync,
    }
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
            .any(|rule| rule.kind == TargetInvariantKind::MaxSharePriceIncreaseBps));
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
            .any(|rule| rule.kind == TargetInvariantKind::MaxSharePriceIncreaseBps));
    }
}
