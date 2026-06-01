use crate::common::oracle::{ProtocolFinding, VulnType};
use crate::engine::exploit_path::MinimizedSequenceStatus;
use crate::engine::proof::{ProofCarryingFinding, ProofConfidenceTier, ReplayVerificationStatus};
use crate::engine::scoring::CampaignScore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingConfirmationConfig {
    pub min_confirmed_score: u64,
    pub min_economic_confidence: u64,
    pub require_replay: bool,
    pub require_minimized: bool,
    pub require_actor_labels: bool,
    pub require_protocol_assertion: bool,
}

impl Default for FindingConfirmationConfig {
    fn default() -> Self {
        Self {
            min_confirmed_score: 700,
            min_economic_confidence: 70,
            require_replay: true,
            require_minimized: true,
            require_actor_labels: true,
            require_protocol_assertion: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingConfirmation {
    pub tier: ProofConfidenceTier,
    pub confirmed: bool,
    pub high_value_artifact: bool,
    pub replay_success: bool,
    pub minimized_path: bool,
    pub invariant_or_economic_proof: bool,
    pub actor_labels: bool,
    pub protocol_specific_assertion: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FindingConfirmationGate {
    pub config: FindingConfirmationConfig,
}

impl FindingConfirmationGate {
    pub fn new(config: FindingConfirmationConfig) -> Self {
        Self { config }
    }

    pub fn evaluate(
        &self,
        proof: Option<&ProofCarryingFinding>,
        findings: &[ProtocolFinding],
        score: &CampaignScore,
    ) -> FindingConfirmation {
        let replay_success = proof
            .is_some_and(|proof| matches!(proof.replay_result, ReplayVerificationStatus::Verified));
        let minimized_path = proof
            .is_some_and(|proof| proof.minimization_result == MinimizedSequenceStatus::Minimized);
        let actor_labels = proof.is_some_and(|proof| !proof.actor_roles.is_empty());
        let economic_proof = proof.is_some_and(|proof| {
            proof.economic_delta.confidence >= self.config.min_economic_confidence
                && (proof.economic_delta.estimated_profit > revm::primitives::U256::ZERO
                    || proof.economic_delta.suspicious_value_extraction
                    || proof.economic_delta.accounting_anomaly
                    || proof.economic_delta.flashloan_pressure
                    || proof.economic_delta.price_impact_pressure
                    || proof.economic_delta.debt_or_collateral_pressure
                    || proof.economic_delta.share_price_pressure)
        });
        let invariant_proof = proof.is_some_and(|proof| proof.invariant_id.is_some())
            || findings
                .iter()
                .any(protocol_finding_is_invariant_or_economic);
        let invariant_or_economic_proof = invariant_proof || economic_proof;
        let protocol_specific_assertion = proof.is_some_and(|proof| {
            proof.foundry_poc_path.is_some()
                && !findings.is_empty()
                && proof.violated_condition != "unknown-violated-condition"
        });

        let mut reasons = Vec::new();
        push_missing(
            &mut reasons,
            !self.config.require_replay || replay_success,
            "missing replay success",
        );
        push_missing(
            &mut reasons,
            !self.config.require_minimized || minimized_path,
            "missing minimized path",
        );
        push_missing(
            &mut reasons,
            invariant_or_economic_proof,
            "missing invariant or economic proof",
        );
        push_missing(
            &mut reasons,
            !self.config.require_actor_labels || actor_labels,
            "missing actor labels",
        );
        push_missing(
            &mut reasons,
            !self.config.require_protocol_assertion || protocol_specific_assertion,
            "missing protocol-specific PoC assertion",
        );
        push_missing(
            &mut reasons,
            score.total >= self.config.min_confirmed_score,
            "score below confirmed threshold",
        );

        let confirmed = reasons.is_empty();
        let tier = if confirmed {
            ProofConfidenceTier::Confirmed
        } else {
            derive_non_confirmed_tier(
                proof,
                replay_success,
                minimized_path,
                invariant_or_economic_proof,
                protocol_specific_assertion,
            )
        };

        FindingConfirmation {
            tier,
            confirmed,
            high_value_artifact: confirmed,
            replay_success,
            minimized_path,
            invariant_or_economic_proof,
            actor_labels,
            protocol_specific_assertion,
            reasons,
        }
    }
}

fn derive_non_confirmed_tier(
    proof: Option<&ProofCarryingFinding>,
    replay_success: bool,
    minimized_path: bool,
    invariant_or_economic_proof: bool,
    protocol_specific_assertion: bool,
) -> ProofConfidenceTier {
    if replay_success
        && minimized_path
        && invariant_or_economic_proof
        && protocol_specific_assertion
    {
        return ProofConfidenceTier::PocGenerated;
    }
    if replay_success && minimized_path && invariant_or_economic_proof {
        return ProofConfidenceTier::ProofCarrying;
    }
    if replay_success && minimized_path {
        return ProofConfidenceTier::ReplayedMinimized;
    }
    if replay_success {
        return ProofConfidenceTier::Replayed;
    }
    proof
        .map(|proof| proof.confidence_tier.clone())
        .unwrap_or(ProofConfidenceTier::Heuristic)
        .min(ProofConfidenceTier::Heuristic)
}

fn protocol_finding_is_invariant_or_economic(finding: &ProtocolFinding) -> bool {
    matches!(
        finding.vuln,
        VulnType::InvariantViolation(_)
            | VulnType::FlashLoanProfit
            | VulnType::FlashLoanAttack
            | VulnType::PriceManipulation
            | VulnType::PriceOracleManipulation
            | VulnType::VaultDonationAttack
            | VulnType::VaultInflation
            | VulnType::MevSandwichExploit
            | VulnType::UniswapV3LiquidityAsymmetry
            | VulnType::AccountingDesync
            | VulnType::RebalanceValueLoss
            | VulnType::SystemicStateCorruption
            | VulnType::PrivilegeEscalation
            | VulnType::ProxyUpgradeabilityViolation
    )
}

fn push_missing(reasons: &mut Vec<String>, ok: bool, reason: &str) {
    if !ok {
        reasons.push(reason.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::oracle::{ProtocolOraclePackKind, ProtocolSeverity};
    use crate::common::types::{SingletonTx, StorageDiff};
    use crate::engine::actors::ActorType;
    use crate::engine::economic_delta::EconomicDeltaReport;
    use crate::engine::exploit_path::CounterexampleProofStatus;
    use revm::primitives::{Address, B256, U256};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn score(total: u64) -> CampaignScore {
        CampaignScore {
            total,
            economic_pressure: 0,
            invariant_pressure: 0,
            counterexample_pressure: 0,
            oracle_pressure: 0,
            state_pressure: 0,
            exploration_pressure: 0,
            explanation: Vec::new(),
        }
    }

    fn finding() -> ProtocolFinding {
        ProtocolFinding {
            pack: ProtocolOraclePackKind::Lending,
            vuln: VulnType::InvariantViolation("bad debt".to_string()),
            severity: ProtocolSeverity::High,
            target: Some(Address::repeat_byte(0xaa)),
            tx_index: Some(0),
            evidence: "bad debt invariant failed".to_string(),
        }
    }

    fn proof() -> ProofCarryingFinding {
        ProofCarryingFinding {
            target: Some(Address::repeat_byte(0xaa)),
            vulnerability_class: Some("bad debt".to_string()),
            invariant_id: Some("lending-health".to_string()),
            actor_roles: BTreeMap::from([(0, ActorType::Attacker)]),
            tx_sequence: vec![SingletonTx {
                input: vec![1, 2, 3, 4],
                caller: Address::repeat_byte(0x13),
                to: Address::repeat_byte(0xaa),
                value: U256::ZERO,
                is_victim: false,
            }],
            pre_state_evidence: Vec::new(),
            post_state_evidence: Vec::new(),
            storage_diffs: vec![StorageDiff {
                tx_index: 0,
                address: Address::repeat_byte(0xaa),
                slot: B256::ZERO,
                old_value: U256::ZERO,
                new_value: U256::from(1),
                pc: 1,
            }],
            economic_delta: EconomicDeltaReport {
                estimated_profit: U256::from(1),
                accounting_anomaly: true,
                confidence: 85,
                ..EconomicDeltaReport::default()
            },
            violated_condition: "bad debt invariant".to_string(),
            replay_result: ReplayVerificationStatus::Verified,
            minimization_result: MinimizedSequenceStatus::Minimized,
            confidence: 90,
            caveats: Vec::new(),
            foundry_poc_path: Some(PathBuf::from("poc.t.sol")),
            proof_status: CounterexampleProofStatus::ConcretelyReplayed,
            confidence_tier: ProofConfidenceTier::PocGenerated,
        }
    }

    #[test]
    fn gate_confirms_only_replayed_minimized_proven_poc_findings() {
        let gate = FindingConfirmationGate::default();
        let confirmation = gate.evaluate(Some(&proof()), &[finding()], &score(1_000));
        assert_eq!(confirmation.tier, ProofConfidenceTier::Confirmed);
        assert!(confirmation.confirmed);
        assert!(confirmation.high_value_artifact);
    }

    #[test]
    fn gate_rejects_heuristic_finding_without_replay_or_poc() {
        let gate = FindingConfirmationGate::default();
        let confirmation = gate.evaluate(None, &[finding()], &score(2_000));
        assert_eq!(confirmation.tier, ProofConfidenceTier::Heuristic);
        assert!(!confirmation.confirmed);
        assert!(confirmation
            .reasons
            .iter()
            .any(|reason| reason.contains("missing replay success")));
    }
}
