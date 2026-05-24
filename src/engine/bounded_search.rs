use crate::common::types::SingletonTx;
use crate::engine::actors::{ActorModel, ActorModelConfig, ActorSet, ActorType};
use crate::engine::exploit_path::{
    CounterexampleProofStatus, ExploitExtensionHint, MinimizedSequenceStatus, ReplayabilityStatus,
};
use crate::engine::seed_intelligence::SeedCandidate;
use crate::engine::target_profile::{ProtocolType, TargetProfile};
use crate::evm::fuzz::{AbiRegistry, EvmInput};
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundedSearchBounds {
    pub max_tx_depth: usize,
    pub max_actor_roles: usize,
    pub max_template_sequences: usize,
}

impl Default for BoundedSearchBounds {
    fn default() -> Self {
        Self {
            max_tx_depth: 4,
            max_actor_roles: 4,
            max_template_sequences: 128,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BoundedSearchRequest<'a> {
    pub target: Address,
    pub target_profile: &'a TargetProfile,
    pub abi_registry: &'a AbiRegistry,
    pub actor_set: Option<&'a ActorSet>,
    pub seed_candidates: &'a [SeedCandidate],
    pub base_input: Option<&'a EvmInput>,
    pub bounds: BoundedSearchBounds,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundedSearchOutcome {
    pub template_name: String,
    pub candidate: crate::engine::protocol_model::CounterexampleCandidate,
    pub exhaustive: bool,
    pub modeled_space_size: usize,
    pub proof_status: CounterexampleProofStatus,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundedSearchResult {
    pub candidates: Vec<BoundedSearchOutcome>,
    pub exhaustive: bool,
    pub enumerated_candidates: usize,
    pub modeled_space_size: usize,
    pub explanation: Vec<String>,
}

#[derive(Debug, Default)]
pub struct BoundedSearchEngine;

impl BoundedSearchEngine {
    pub fn search(&self, request: BoundedSearchRequest<'_>) -> BoundedSearchResult {
        let actor_set = request
            .actor_set
            .cloned()
            .unwrap_or_else(|| ActorModel::new(ActorModelConfig::default()).generate([]));
        let actor_space = actor_set
            .actors
            .iter()
            .take(request.bounds.max_actor_roles.max(1))
            .collect::<Vec<_>>();
        let mut template_inputs = crate::engine::dependency::generate_flow_template_inputs(
            request.target,
            actor_set.address_for(ActorType::Attacker),
            request.abi_registry,
        );

        if template_inputs.is_empty() {
            template_inputs.extend(
                request
                    .seed_candidates
                    .iter()
                    .cloned()
                    .map(|seed| seed.into_evm_input(0))
                    .collect::<Vec<_>>(),
            );
        }
        if template_inputs.is_empty() {
            template_inputs.push(
                request
                    .base_input
                    .cloned()
                    .unwrap_or_else(|| fallback_input(request.target)),
            );
        }

        let mut candidates = Vec::new();
        let template_count = template_inputs.len();
        let modeled_space_size = template_count.saturating_mul(actor_space.len().max(1));
        let exhaustive = template_count <= request.bounds.max_template_sequences;

        for mut input in template_inputs
            .into_iter()
            .take(request.bounds.max_template_sequences)
        {
            let actor_roles = actor_set.apply_roles_to_sequence(&mut input.txs);
            let selected_profile = classify_candidate_profile(request.target_profile, &input);
            let proof_status = if selected_profile.exhaustive {
                CounterexampleProofStatus::AbstractlyProven
            } else {
                CounterexampleProofStatus::HeuristicOnly
            };
            let candidate = crate::engine::protocol_model::CounterexampleCandidate {
                input,
                target: Some(request.target),
                actor_roles,
                profit_delta: None,
                violated_invariant: selected_profile.violated_invariant,
                confidence: selected_profile.confidence,
                replayability_status: selected_profile.replayability_status,
                minimized_sequence_status: selected_profile.minimized_sequence_status,
                proof_status: proof_status.clone(),
                extension_hints: selected_profile.extension_hints,
                replay_checks: selected_profile.replay_checks,
                evidence: selected_profile.evidence,
            };
            candidates.push(BoundedSearchOutcome {
                template_name: selected_profile.template_name,
                candidate,
                exhaustive: selected_profile.exhaustive,
                modeled_space_size,
                proof_status,
                explanation: selected_profile.explanation,
            });
        }

        if candidates.is_empty() {
            let mut input = request
                .base_input
                .cloned()
                .unwrap_or_else(|| fallback_input(request.target));
            let actor_roles = actor_set.apply_roles_to_sequence(&mut input.txs);
            let selected_profile = classify_candidate_profile(request.target_profile, &input);
            let candidate = crate::engine::protocol_model::CounterexampleCandidate {
                input,
                target: Some(request.target),
                actor_roles,
                profit_delta: None,
                violated_invariant: selected_profile.violated_invariant,
                confidence: selected_profile.confidence,
                replayability_status: selected_profile.replayability_status,
                minimized_sequence_status: selected_profile.minimized_sequence_status,
                proof_status: CounterexampleProofStatus::HeuristicOnly,
                extension_hints: selected_profile.extension_hints,
                replay_checks: selected_profile.replay_checks,
                evidence: selected_profile.evidence,
            };
            candidates.push(BoundedSearchOutcome {
                template_name: "fallback-generic".to_string(),
                candidate,
                exhaustive: false,
                modeled_space_size: 1,
                proof_status: CounterexampleProofStatus::HeuristicOnly,
                explanation: vec![
                    "bounded search fell back to a generic single-tx model".to_string()
                ],
            });
        }

        BoundedSearchResult {
            enumerated_candidates: candidates.len(),
            modeled_space_size,
            exhaustive,
            explanation: vec![
                format!(
                    "bounded search enumerated {} candidate templates",
                    candidates.len()
                ),
                format!(
                    "actor bound={}, template bound={}, tx depth bound={}",
                    request.bounds.max_actor_roles,
                    request.bounds.max_template_sequences,
                    request.bounds.max_tx_depth
                ),
            ],
            candidates,
        }
    }
}

#[derive(Debug, Clone)]
struct CandidateProfile {
    template_name: String,
    violated_invariant: Option<String>,
    confidence: u64,
    replayability_status: ReplayabilityStatus,
    minimized_sequence_status: MinimizedSequenceStatus,
    extension_hints: Vec<ExploitExtensionHint>,
    replay_checks: Vec<String>,
    evidence: Vec<String>,
    explanation: Vec<String>,
    exhaustive: bool,
}

fn classify_candidate_profile(profile: &TargetProfile, input: &EvmInput) -> CandidateProfile {
    let mut explanation = profile.explanation.clone();
    let template_name = profile
        .recommended_seed_templates
        .first()
        .cloned()
        .unwrap_or_else(|| "generic-bounded-sequence".to_string());
    let protocol = profile
        .protocol_types
        .first()
        .cloned()
        .unwrap_or(ProtocolType::Unknown);
    let violated_invariant = profile.recommended_invariant_families.first().cloned();
    let confidence = profile
        .confidence
        .saturating_add((input.txs.len() as u64) * 3)
        .min(100);
    let replayability_status = if input.txs.is_empty() {
        ReplayabilityStatus::Unknown
    } else {
        ReplayabilityStatus::Replayable
    };
    let minimized_sequence_status = if input.txs.len() <= 2 {
        MinimizedSequenceStatus::Minimized
    } else {
        MinimizedSequenceStatus::NeedsMinimization
    };
    let extension_hints = match protocol {
        ProtocolType::Erc4626Vault => vec![
            ExploitExtensionHint::PreserveInvariantViolation,
            ExploitExtensionHint::MutateAmountsAndValue,
        ],
        ProtocolType::AmmDexPool => vec![
            ExploitExtensionHint::PreserveInvariantViolation,
            ExploitExtensionHint::MutateAmountsAndValue,
            ExploitExtensionHint::PreserveEconomicDelta,
        ],
        ProtocolType::LendingBorrowing => vec![
            ExploitExtensionHint::PreserveInvariantViolation,
            ExploitExtensionHint::ExtendStorageDependentSelector,
        ],
        ProtocolType::GovernanceTimelock | ProtocolType::AccessControlHeavy => vec![
            ExploitExtensionHint::RetryNonOwnerCaller,
            ExploitExtensionHint::PreserveReplaySuccess,
        ],
        _ => vec![ExploitExtensionHint::PreserveInvariantViolation],
    };
    let replay_checks = vec![
        "replay within bounded actor space".to_string(),
        "verify selector-valid calldata".to_string(),
        "preserve transaction ordering".to_string(),
    ];
    let evidence = vec![
        format!("profile confidence={}", profile.confidence),
        format!("protocols={:?}", profile.protocol_types),
        format!("selectors={}", profile.relevant_selectors.len()),
    ];
    explanation.push(format!(
        "bounded candidate template `{template_name}` derived from {:?}",
        protocol
    ));
    CandidateProfile {
        template_name,
        violated_invariant,
        confidence,
        replayability_status,
        minimized_sequence_status,
        extension_hints,
        replay_checks,
        evidence,
        explanation,
        exhaustive: true,
    }
}

fn fallback_input(target: Address) -> EvmInput {
    EvmInput {
        txs: vec![SingletonTx {
            input: vec![0u8; 4],
            caller: Address::repeat_byte(0x13),
            to: target,
            value: U256::ZERO,
            is_victim: false,
        }],
        base_snapshot_id: 0,
        waypoints: Vec::new(),
        mutation_provenance: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::target_profile::function_selector;

    fn target() -> Address {
        Address::repeat_byte(0x44)
    }

    #[test]
    fn enumerates_bounded_templates_with_proof_status() {
        let mut abi = AbiRegistry::default();
        abi.functions.insert(
            function_selector("deposit(uint256,address)"),
            Default::default(),
        );
        abi.functions.insert(
            function_selector("withdraw(uint256,address,address)"),
            Default::default(),
        );
        let profile = TargetProfile {
            protocol_types: vec![ProtocolType::Erc4626Vault],
            confidence: 80,
            relevant_selectors: abi.functions.keys().copied().collect(),
            risky_selectors: vec![],
            read_only_functions: vec![],
            state_changing_functions: vec![],
            role_sensitive_functions: vec![],
            value_sensitive_functions: vec![],
            token_accounting_functions: vec![],
            recommended_seed_templates: vec!["deposit->withdraw".to_string()],
            recommended_invariant_families: vec!["erc4626-accounting".to_string()],
            explanation: vec!["vault profile".to_string()],
        };
        let result = BoundedSearchEngine.search(BoundedSearchRequest {
            target: target(),
            target_profile: &profile,
            abi_registry: &abi,
            actor_set: None,
            seed_candidates: &[],
            base_input: None,
            bounds: BoundedSearchBounds::default(),
        });
        assert!(result.exhaustive);
        assert!(!result.candidates.is_empty());
        assert!(matches!(
            result.candidates[0].proof_status,
            CounterexampleProofStatus::AbstractlyProven | CounterexampleProofStatus::HeuristicOnly
        ));
    }

    #[test]
    fn falls_back_to_generic_input_when_no_templates_exist() {
        let abi = AbiRegistry::default();
        let profile = TargetProfile::default();
        let result = BoundedSearchEngine.search(BoundedSearchRequest {
            target: target(),
            target_profile: &profile,
            abi_registry: &abi,
            actor_set: None,
            seed_candidates: &[],
            base_input: None,
            bounds: BoundedSearchBounds::default(),
        });
        assert!(!result.candidates.is_empty());
        assert!(result.enumerated_candidates >= 1);
        assert!(!result.explanation.is_empty());
    }
}
