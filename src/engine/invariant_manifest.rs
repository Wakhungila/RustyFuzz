use crate::common::oracle::{ProtocolFinding, ProtocolOraclePackKind, ProtocolSeverity, VulnType};
use crate::engine::economic_delta::EconomicDeltaReport;
use anyhow::Context;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetInvariantManifest {
    #[serde(default)]
    pub target: Option<Address>,
    #[serde(default)]
    pub invariants: Vec<TargetInvariantRule>,
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
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read target invariant manifest {}", path.display()))?;
        toml::from_str(&raw)
            .with_context(|| format!("parse target invariant manifest {}", path.display()))
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
}
