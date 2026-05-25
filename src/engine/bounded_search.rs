use crate::common::types::SingletonTx;
use crate::engine::actors::{ActorModel, ActorModelConfig, ActorSet, ActorType};
use crate::engine::exploit_path::{
    CounterexampleProofStatus, ExploitExtensionHint, MinimizedSequenceStatus, ReplayabilityStatus,
};
use crate::engine::seed_intelligence::SeedCandidate;
use crate::engine::target_profile::{ProtocolType, TargetProfile};
use crate::evm::fuzz::{AbiRegistry, EvmInput, MutationProvenance};
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
    #[serde(default)]
    pub objectives: Vec<SearchObjectiveHit>,
    #[serde(default)]
    pub objective_score: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SearchObjective {
    MaximizeAttackerProfit,
    ReduceCollateralHealth,
    IncreaseSharesPerAsset,
    BypassRoleCheck,
    CreateReserveProductAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchObjectiveHit {
    pub objective: SearchObjective,
    pub score: u64,
    pub confidence: u64,
    pub explanation: String,
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
            let objective_hits = evaluate_search_objectives(request.target_profile, &input);
            let objective_score = objective_hits.iter().map(|hit| hit.score).sum::<u64>();
            annotate_objectives(&mut input, &objective_hits);
            let proof_status = if selected_profile.exhaustive {
                CounterexampleProofStatus::AbstractlyProven
            } else {
                CounterexampleProofStatus::HeuristicOnly
            };
            let candidate = crate::engine::protocol_model::CounterexampleCandidate {
                input,
                target: Some(request.target),
                actor_roles,
                profit_delta: profit_hint_from_objectives(&objective_hits),
                violated_invariant: selected_profile.violated_invariant,
                confidence: selected_profile
                    .confidence
                    .saturating_add(objective_score / 12)
                    .min(100),
                replayability_status: selected_profile.replayability_status,
                minimized_sequence_status: selected_profile.minimized_sequence_status,
                proof_status: proof_status.clone(),
                extension_hints: selected_profile.extension_hints,
                replay_checks: selected_profile.replay_checks,
                evidence: selected_profile
                    .evidence
                    .into_iter()
                    .chain(objective_hits.iter().map(|hit| {
                        format!(
                            "objective {:?}: score={}, confidence={}, {}",
                            hit.objective, hit.score, hit.confidence, hit.explanation
                        )
                    }))
                    .collect(),
            };
            let mut explanation = selected_profile.explanation;
            explanation.extend(objective_hits.iter().map(|hit| {
                format!(
                    "goal-directed objective {:?}: score={}, confidence={}",
                    hit.objective, hit.score, hit.confidence
                )
            }));
            candidates.push(BoundedSearchOutcome {
                template_name: selected_profile.template_name,
                candidate,
                objectives: objective_hits,
                objective_score,
                exhaustive: selected_profile.exhaustive,
                modeled_space_size,
                proof_status,
                explanation,
            });
        }

        candidates.sort_by(|left, right| {
            right
                .objective_score
                .cmp(&left.objective_score)
                .then_with(|| right.candidate.confidence.cmp(&left.candidate.confidence))
                .then_with(|| {
                    left.candidate
                        .input
                        .txs
                        .len()
                        .cmp(&right.candidate.input.txs.len())
                })
        });

        if candidates.is_empty() {
            let mut input = request
                .base_input
                .cloned()
                .unwrap_or_else(|| fallback_input(request.target));
            let actor_roles = actor_set.apply_roles_to_sequence(&mut input.txs);
            let selected_profile = classify_candidate_profile(request.target_profile, &input);
            let objective_hits = evaluate_search_objectives(request.target_profile, &input);
            let objective_score = objective_hits.iter().map(|hit| hit.score).sum::<u64>();
            annotate_objectives(&mut input, &objective_hits);
            let candidate = crate::engine::protocol_model::CounterexampleCandidate {
                input,
                target: Some(request.target),
                actor_roles,
                profit_delta: profit_hint_from_objectives(&objective_hits),
                violated_invariant: selected_profile.violated_invariant,
                confidence: selected_profile
                    .confidence
                    .saturating_add(objective_score / 12)
                    .min(100),
                replayability_status: selected_profile.replayability_status,
                minimized_sequence_status: selected_profile.minimized_sequence_status,
                proof_status: CounterexampleProofStatus::HeuristicOnly,
                extension_hints: selected_profile.extension_hints,
                replay_checks: selected_profile.replay_checks,
                evidence: selected_profile
                    .evidence
                    .into_iter()
                    .chain(objective_hits.iter().map(|hit| {
                        format!(
                            "objective {:?}: score={}, confidence={}, {}",
                            hit.objective, hit.score, hit.confidence, hit.explanation
                        )
                    }))
                    .collect(),
            };
            candidates.push(BoundedSearchOutcome {
                template_name: "fallback-generic".to_string(),
                candidate,
                objectives: objective_hits,
                objective_score,
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
                    "bounded search enumerated {} candidate templates with goal-directed objective scoring",
                    candidates.len()
                ),
                format!(
                    "top objective score={}",
                    candidates
                        .first()
                        .map(|candidate| candidate.objective_score)
                        .unwrap_or_default()
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

pub fn evaluate_search_objectives(
    profile: &TargetProfile,
    input: &EvmInput,
) -> Vec<SearchObjectiveHit> {
    let selectors = input
        .txs
        .iter()
        .filter_map(|tx| selector_for(&tx.input))
        .collect::<Vec<_>>();
    let mut hits = Vec::new();
    if objective_supported(
        profile,
        &[ProtocolType::AmmDexPool, ProtocolType::RouterAggregator],
    ) || profile_has_signatures(
        profile,
        &[
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
            "swap(uint256,uint256,address,bytes)",
            "borrow(uint256)",
        ],
    ) || template_mentions(profile, &["swap", "flash", "borrow"])
    {
        if has_any_selector(
            &selectors,
            &[
                "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
                "swap(uint256,uint256,address,bytes)",
            ],
        ) || template_mentions(profile, &["swap"])
        {
            hits.push(SearchObjectiveHit {
                objective: SearchObjective::MaximizeAttackerProfit,
                score: 90,
                confidence: 65,
                explanation: "swap-like path can be optimized for positive attacker balance delta"
                    .to_string(),
            });
        }
    }
    if objective_supported(profile, &[ProtocolType::LendingBorrowing])
        || profile_has_signatures(
            profile,
            &[
                "borrow(uint256)",
                "borrow(address,uint256,uint256,uint16,address)",
                "liquidate(address,address,uint256,uint256)",
                "liquidationCall(address,address,address,uint256,bool)",
                "repay(uint256)",
                "repay(address,uint256,uint256,address)",
                "donateToReserves(uint256,uint256)",
            ],
        )
        || template_mentions(profile, &["borrow", "liquidate", "repay"])
    {
        if has_any_selector(
            &selectors,
            &[
                "borrow(uint256)",
                "borrow(address,uint256,uint256,uint16,address)",
                "liquidate(address,address,uint256,uint256)",
                "liquidationCall(address,address,address,uint256,bool)",
                "repay(uint256)",
                "repay(address,uint256,uint256,address)",
                "donateToReserves(uint256,uint256)",
            ],
        ) || template_mentions(profile, &["borrow", "liquidate"])
        {
            hits.push(SearchObjectiveHit {
                objective: SearchObjective::ReduceCollateralHealth,
                score: 105,
                confidence: 75,
                explanation:
                    "lending path should search amounts that worsen collateral/debt health"
                        .to_string(),
            });
        }
    }
    if objective_supported(profile, &[ProtocolType::Erc4626Vault])
        || profile_has_signatures(
            profile,
            &[
                "deposit(uint256,address)",
                "mint(uint256,address)",
                "withdraw(uint256,address,address)",
                "redeem(uint256,address,address)",
            ],
        )
        || template_mentions(profile, &["deposit", "mint", "redeem", "withdraw"])
    {
        if has_any_selector(
            &selectors,
            &[
                "deposit(uint256,address)",
                "mint(uint256,address)",
                "withdraw(uint256,address,address)",
                "redeem(uint256,address,address)",
            ],
        ) || template_mentions(profile, &["deposit", "redeem", "withdraw"])
        {
            hits.push(SearchObjectiveHit {
                objective: SearchObjective::IncreaseSharesPerAsset,
                score: 95,
                confidence: 70,
                explanation:
                    "vault path should search donation/deposit/redeem amounts that skew shares per asset"
                        .to_string(),
            });
        }
    }
    if objective_supported(
        profile,
        &[
            ProtocolType::GovernanceTimelock,
            ProtocolType::AccessControlHeavy,
            ProtocolType::ProxyUpgradeable,
        ],
    ) || profile_has_signatures(
        profile,
        &[
            "initialize()",
            "upgradeTo(address)",
            "execute(uint256)",
            "queue(uint256)",
        ],
    ) || template_mentions(profile, &["initialize", "upgrade", "execute", "queue"])
    {
        if template_mentions(profile, &["initialize", "upgrade", "execute", "queue"])
            || has_any_selector(
                &selectors,
                &[
                    "initialize()",
                    "upgradeTo(address)",
                    "execute(uint256)",
                    "queue(uint256)",
                ],
            )
        {
            hits.push(SearchObjectiveHit {
                objective: SearchObjective::BypassRoleCheck,
                score: 110,
                confidence: 76,
                explanation:
                    "role-sensitive selector path should enumerate non-owner and role-like callers"
                        .to_string(),
            });
        }
    }
    if objective_supported(profile, &[ProtocolType::AmmDexPool])
        || profile_has_signatures(
            profile,
            &[
                "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
                "swap(uint256,uint256,address,bytes)",
            ],
        )
        || template_mentions(profile, &["swap", "sync", "skim"])
    {
        if has_any_selector(
            &selectors,
            &[
                "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
                "swap(uint256,uint256,address,bytes)",
            ],
        ) || template_mentions(profile, &["swap"])
        {
            hits.push(SearchObjectiveHit {
                objective: SearchObjective::CreateReserveProductAnomaly,
                score: 100,
                confidence: 72,
                explanation:
                    "AMM path should maximize reserve/product movement and round-trip imbalance"
                        .to_string(),
            });
        }
    }
    hits.sort_by(|left, right| right.score.cmp(&left.score));
    hits
}

fn annotate_objectives(input: &mut EvmInput, objectives: &[SearchObjectiveHit]) {
    input
        .mutation_provenance
        .extend(objectives.iter().map(|hit| {
            MutationProvenance {
                strategy: format!("goal_{:?}", hit.objective)
                    .replace("::", "_")
                    .to_ascii_lowercase(),
                tx_index: None,
                selector: None,
                detail: hit.explanation.clone(),
            }
        }));
}

fn profit_hint_from_objectives(objectives: &[SearchObjectiveHit]) -> Option<U256> {
    let score = objectives
        .iter()
        .filter(|hit| {
            matches!(
                hit.objective,
                SearchObjective::MaximizeAttackerProfit
                    | SearchObjective::CreateReserveProductAnomaly
                    | SearchObjective::IncreaseSharesPerAsset
            )
        })
        .map(|hit| hit.score)
        .sum::<u64>();
    (score > 0).then(|| U256::from(score))
}

fn objective_supported(profile: &TargetProfile, protocols: &[ProtocolType]) -> bool {
    protocols
        .iter()
        .any(|protocol| profile.protocol_types.contains(protocol))
}

fn profile_has_signatures(profile: &TargetProfile, signatures: &[&str]) -> bool {
    let selectors = signatures
        .iter()
        .map(|signature| crate::engine::target_profile::function_selector(signature))
        .collect::<Vec<_>>();
    let profile_selectors = profile
        .relevant_selectors
        .iter()
        .chain(profile.risky_selectors.iter())
        .chain(profile.state_changing_functions.iter())
        .chain(profile.role_sensitive_functions.iter())
        .chain(profile.value_sensitive_functions.iter())
        .chain(profile.token_accounting_functions.iter());
    profile_selectors
        .into_iter()
        .any(|selector| selectors.contains(selector))
}

fn template_mentions(profile: &TargetProfile, fragments: &[&str]) -> bool {
    profile.recommended_seed_templates.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        fragments.iter().any(|fragment| lower.contains(fragment))
    })
}

fn has_any_selector(selectors: &[[u8; 4]], signatures: &[&str]) -> bool {
    signatures
        .iter()
        .map(|signature| crate::engine::target_profile::function_selector(signature))
        .any(|selector| selectors.contains(&selector))
}

fn selector_for(calldata: &[u8]) -> Option<[u8; 4]> {
    calldata.get(0..4).map(|selector| {
        let mut out = [0u8; 4];
        out.copy_from_slice(selector);
        out
    })
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

    #[test]
    fn objective_layer_prioritizes_vault_share_price_search() {
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
            confidence: 75,
            relevant_selectors: abi.functions.keys().copied().collect(),
            risky_selectors: Vec::new(),
            read_only_functions: Vec::new(),
            state_changing_functions: abi.functions.keys().copied().collect(),
            role_sensitive_functions: Vec::new(),
            value_sensitive_functions: Vec::new(),
            token_accounting_functions: abi.functions.keys().copied().collect(),
            recommended_seed_templates: vec!["vault deposit redeem".to_string()],
            recommended_invariant_families: vec!["erc4626-accounting".to_string()],
            explanation: Vec::new(),
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

        let top = result.candidates.first().expect("candidate");
        assert!(top
            .objectives
            .iter()
            .any(|hit| { matches!(hit.objective, SearchObjective::IncreaseSharesPerAsset) }));
        assert!(top.objective_score > 0);
        assert!(top
            .candidate
            .input
            .mutation_provenance
            .iter()
            .any(|entry| entry.strategy.starts_with("goal_")));
    }

    #[test]
    fn objective_layer_prioritizes_lending_health_search() {
        let mut abi = AbiRegistry::default();
        abi.functions
            .insert(function_selector("borrow(uint256)"), Default::default());
        abi.functions.insert(
            function_selector("liquidate(address,address,uint256,uint256)"),
            Default::default(),
        );
        let profile = TargetProfile {
            protocol_types: vec![ProtocolType::LendingBorrowing],
            confidence: 80,
            relevant_selectors: abi.functions.keys().copied().collect(),
            risky_selectors: abi.functions.keys().copied().collect(),
            read_only_functions: Vec::new(),
            state_changing_functions: abi.functions.keys().copied().collect(),
            role_sensitive_functions: Vec::new(),
            value_sensitive_functions: Vec::new(),
            token_accounting_functions: Vec::new(),
            recommended_seed_templates: vec!["lending borrow liquidate".to_string()],
            recommended_invariant_families: vec!["lending-health".to_string()],
            explanation: Vec::new(),
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

        let top = result.candidates.first().expect("candidate");
        assert!(top
            .objectives
            .iter()
            .any(|hit| { matches!(hit.objective, SearchObjective::ReduceCollateralHealth) }));
        assert!(top.candidate.confidence >= profile.confidence);
    }

    #[test]
    fn objective_layer_identifies_role_bypass_search() {
        let mut abi = AbiRegistry::default();
        abi.functions
            .insert(function_selector("initialize()"), Default::default());
        abi.functions
            .insert(function_selector("upgradeTo(address)"), Default::default());
        let profile = TargetProfile {
            protocol_types: vec![
                ProtocolType::ProxyUpgradeable,
                ProtocolType::AccessControlHeavy,
            ],
            confidence: 78,
            relevant_selectors: abi.functions.keys().copied().collect(),
            risky_selectors: abi.functions.keys().copied().collect(),
            read_only_functions: Vec::new(),
            state_changing_functions: abi.functions.keys().copied().collect(),
            role_sensitive_functions: abi.functions.keys().copied().collect(),
            value_sensitive_functions: Vec::new(),
            token_accounting_functions: Vec::new(),
            recommended_seed_templates: vec!["initialize upgrade".to_string()],
            recommended_invariant_families: vec!["access-control".to_string()],
            explanation: Vec::new(),
        };

        let input = EvmInput {
            txs: vec![SingletonTx {
                input: function_selector("initialize()").to_vec(),
                caller: Address::repeat_byte(0x13),
                to: target(),
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let hits = evaluate_search_objectives(&profile, &input);
        assert!(hits
            .iter()
            .any(|hit| matches!(hit.objective, SearchObjective::BypassRoleCheck)));
    }
}
