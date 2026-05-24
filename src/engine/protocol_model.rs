use crate::common::oracle::{ProtocolFinding, ProtocolSeverity};
use crate::common::types::{CallKind, CallPhase, SequenceExecutionResult};
use crate::engine::actors::{ActorSet, ActorType};
use crate::engine::concolic::{ConcolicHint, ConcolicSolver};
use crate::engine::dependency::{
    dependency_sequence_score, generate_flow_template_inputs, TransactionDependencyGraph,
};
use crate::engine::economic_delta::{EconomicDeltaEngine, EconomicDeltaReport};
use crate::engine::exploit_path::{
    CounterexampleProofStatus, ExploitExtensionHint, ExploitPathCandidate, MinimizedSequenceStatus,
    ReplayabilityStatus,
};
use crate::engine::target_profile::{ProtocolType, TargetProfile, TargetProfiler};
use crate::evm::fuzz::{AbiRegistry, EvmInput};
use libafl_bolts::HasLen;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorInvariantHypothesis {
    pub family: String,
    pub severity_hint: ProtocolSeverity,
    pub confidence: u64,
    pub affected_contracts: Vec<Address>,
    pub evidence: String,
    pub recommended_reproduction_sequence: Vec<String>,
    pub false_positive_caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormalProtocolModel {
    pub target_profile: TargetProfile,
    pub inferred_protocol_types: Vec<ProtocolType>,
    pub dependency_graph: TransactionDependencyGraph,
    pub economic_delta: EconomicDeltaReport,
    pub invariant_hypotheses: Vec<BehaviorInvariantHypothesis>,
    pub concolic_hints: Vec<ConcolicHint>,
    pub confidence: u64,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CounterexampleCandidate {
    pub input: EvmInput,
    pub target: Option<Address>,
    pub actor_roles: BTreeMap<usize, ActorType>,
    pub profit_delta: Option<U256>,
    pub violated_invariant: Option<String>,
    pub confidence: u64,
    pub replayability_status: ReplayabilityStatus,
    pub minimized_sequence_status: MinimizedSequenceStatus,
    pub proof_status: CounterexampleProofStatus,
    pub extension_hints: Vec<ExploitExtensionHint>,
    pub replay_checks: Vec<String>,
    pub evidence: Vec<String>,
}

impl CounterexampleCandidate {
    pub fn into_exploit_path_candidate(self) -> ExploitPathCandidate {
        let attacker = self
            .actor_roles
            .iter()
            .find(|(_, role)| **role == ActorType::Attacker)
            .and_then(|(idx, _)| self.input.txs.get(*idx).map(|tx| tx.caller))
            .or_else(|| self.input.txs.first().map(|tx| tx.caller));
        let victims = self
            .actor_roles
            .iter()
            .filter(|(_, role)| **role == ActorType::Victim)
            .filter_map(|(idx, _)| self.input.txs.get(*idx).map(|tx| tx.caller))
            .collect::<Vec<_>>();
        ExploitPathCandidate {
            sequence: self.input.txs,
            target: self.target,
            attacker,
            victims,
            actor_roles: self.actor_roles,
            profit_delta: self.profit_delta,
            violated_invariant: self.violated_invariant,
            confidence: self.confidence,
            required_preconditions: self.replay_checks.clone(),
            replayability_status: self.replayability_status,
            minimized_sequence_status: self.minimized_sequence_status,
            proof_status: self.proof_status,
            proof: None,
            extension_hints: self.extension_hints,
            persistence_reason: Some("counterexample-search".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CounterexampleSearchResult {
    pub model: FormalProtocolModel,
    pub candidate: Option<CounterexampleCandidate>,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CounterexampleSearchEngine {
    pub max_candidates: usize,
}

impl FormalProtocolModel {
    pub fn synthesize(
        input: &EvmInput,
        execution: &SequenceExecutionResult,
        findings: &[ProtocolFinding],
        target_profile: Option<&TargetProfile>,
    ) -> Self {
        let observed_selectors = execution
            .call_trace
            .iter()
            .filter(|call| call.phase == CallPhase::End)
            .filter(|call| {
                matches!(
                    call.kind,
                    CallKind::Transaction
                        | CallKind::Call
                        | CallKind::StaticCall
                        | CallKind::DelegateCall
                )
            })
            .filter_map(selector)
            .collect::<BTreeSet<_>>();

        let synthesized_profile = target_profile.cloned().unwrap_or_else(|| {
            if observed_selectors.is_empty() {
                TargetProfile::default()
            } else {
                TargetProfiler::profile_from_selectors(observed_selectors.iter().copied())
            }
        });

        let dependency_graph = TransactionDependencyGraph::from_execution(input, execution);
        let economic_delta = EconomicDeltaEngine::from_execution(input, execution);
        let inferred_protocol_types = inferred_protocol_types(
            &synthesized_profile,
            execution,
            &dependency_graph,
            &economic_delta,
        );
        let mut explanation = synthesized_profile.explanation.clone();
        explanation.extend(
            dependency_graph
                .edges
                .iter()
                .take(8)
                .map(|edge| format!("dependency edge {:?}: {}", edge.kind, edge.explanation)),
        );
        explanation.extend(economic_delta.storage_delta_summary.iter().map(|summary| {
            format!(
                "storage delta {} slots={} abs_delta={}",
                summary.address, summary.slot_count, summary.absolute_delta_score
            )
        }));

        let invariant_hypotheses = synthesize_invariants(
            &synthesized_profile,
            &dependency_graph,
            &economic_delta,
            execution,
            findings,
        );
        let concolic_hints = concolic_hints_from_execution(execution);
        let confidence = model_confidence(
            &inferred_protocol_types,
            &invariant_hypotheses,
            &dependency_graph,
            &economic_delta,
        );

        Self {
            target_profile: synthesized_profile,
            inferred_protocol_types,
            dependency_graph,
            economic_delta,
            invariant_hypotheses,
            concolic_hints,
            confidence,
            explanation,
        }
    }

    pub fn counterexample_pressure(&self) -> u64 {
        let invariant_pressure = self
            .invariant_hypotheses
            .iter()
            .map(|hypothesis| hypothesis.confidence)
            .sum::<u64>()
            / 2;
        let protocol_pressure = self
            .inferred_protocol_types
            .iter()
            .filter(|protocol| **protocol != ProtocolType::Unknown)
            .count() as u64
            * 20;
        let dependency_pressure = dependency_sequence_score_from_graph(&self.dependency_graph);
        let economic_pressure = EconomicDeltaEngine::score(&self.economic_delta);

        (invariant_pressure
            .saturating_add(protocol_pressure)
            .saturating_add(dependency_pressure)
            .saturating_add(economic_pressure / 4)
            .saturating_add(self.confidence / 2))
        .min(320)
    }

    pub fn best_invariant(&self) -> Option<&BehaviorInvariantHypothesis> {
        self.invariant_hypotheses.iter().max_by_key(|hypothesis| {
            hypothesis
                .confidence
                .saturating_add(match hypothesis.severity_hint {
                    ProtocolSeverity::Info => 0,
                    ProtocolSeverity::Low => 10,
                    ProtocolSeverity::Medium => 20,
                    ProtocolSeverity::High => 30,
                    ProtocolSeverity::Critical => 40,
                })
        })
    }
}

impl CounterexampleSearchEngine {
    pub fn search(
        &self,
        input: &EvmInput,
        execution: &SequenceExecutionResult,
        findings: &[ProtocolFinding],
        target_profile: Option<&TargetProfile>,
        actor_set: Option<&ActorSet>,
    ) -> CounterexampleSearchResult {
        let model = FormalProtocolModel::synthesize(input, execution, findings, target_profile);
        let mut explanation = model.explanation.clone();
        let best_invariant = model.best_invariant();
        let mut candidate = None;

        if let Some(mut template) =
            build_candidate_template(&model, input, execution, actor_set, best_invariant)
        {
            let concolic_adjustments = apply_concolic_hints(
                &mut template.input,
                &model.concolic_hints,
                self.max_candidates.max(1),
            );
            if !concolic_adjustments.is_empty() {
                template.evidence.extend(
                    concolic_adjustments
                        .into_iter()
                        .map(|entry| format!("concolic: {entry}")),
                );
            }
            if template.confidence == 0 {
                template.confidence = model.confidence.min(100);
            }
            explanation.push(format!(
                "counterexample candidate confidence={} invariant={:?}",
                template.confidence, template.violated_invariant
            ));
            candidate = Some(template);
        }

        CounterexampleSearchResult {
            model,
            candidate,
            explanation,
        }
    }
}

fn inferred_protocol_types(
    profile: &TargetProfile,
    execution: &SequenceExecutionResult,
    graph: &TransactionDependencyGraph,
    economic_delta: &EconomicDeltaReport,
) -> Vec<ProtocolType> {
    let mut protocols = profile.protocol_types.clone();
    if protocols == vec![ProtocolType::Unknown] {
        for edge in &graph.edges {
            match edge.kind {
                crate::engine::dependency::DependencyEdgeKind::ApprovalAllowance => {
                    protocols.push(ProtocolType::Erc20Token);
                    protocols.push(ProtocolType::RouterAggregator);
                }
                crate::engine::dependency::DependencyEdgeKind::BalanceShareSupply => {
                    protocols.push(ProtocolType::Erc4626Vault);
                }
                crate::engine::dependency::DependencyEdgeKind::OraclePriceState => {
                    protocols.push(ProtocolType::OraclePriceFeed);
                }
                crate::engine::dependency::DependencyEdgeKind::CallerRole => {
                    protocols.push(ProtocolType::AccessControlHeavy);
                }
                crate::engine::dependency::DependencyEdgeKind::Economic => {
                    protocols.push(ProtocolType::AccountingHeavy);
                }
                _ => {}
            }
        }
        if economic_delta.accounting_anomaly {
            protocols.push(ProtocolType::AccountingHeavy);
        }
        if repeated_oracle_reads_with_drift(execution) {
            protocols.push(ProtocolType::OraclePriceFeed);
        }
    }

    protocols.sort();
    protocols.dedup();
    if protocols.is_empty() {
        vec![ProtocolType::Unknown]
    } else {
        protocols
    }
}

fn synthesize_invariants(
    profile: &TargetProfile,
    graph: &TransactionDependencyGraph,
    economic_delta: &EconomicDeltaReport,
    execution: &SequenceExecutionResult,
    findings: &[ProtocolFinding],
) -> Vec<BehaviorInvariantHypothesis> {
    let mut hypotheses = Vec::new();

    let base_target = execution
        .call_trace
        .iter()
        .find(|call| call.phase == CallPhase::End)
        .map(|call| call.target);

    if graph.edges.iter().any(|edge| {
        matches!(
            edge.kind,
            crate::engine::dependency::DependencyEdgeKind::ApprovalAllowance
        )
    }) {
        hypotheses.push(BehaviorInvariantHypothesis {
            family: "erc20-accounting".to_string(),
            severity_hint: ProtocolSeverity::Medium,
            confidence: 80,
            affected_contracts: base_target.into_iter().collect(),
            evidence: "behavioral approve -> transferFrom dependency exposed an allowance path"
                .to_string(),
            recommended_reproduction_sequence: vec![
                "approve(address,uint256)".to_string(),
                "transferFrom(address,address,uint256)".to_string(),
            ],
            false_positive_caveats: vec![
                "allowance flows may be legitimate when paired with a router or permit flow"
                    .to_string(),
            ],
        });
    }

    if graph.edges.iter().any(|edge| {
        matches!(
            edge.kind,
            crate::engine::dependency::DependencyEdgeKind::BalanceShareSupply
        )
    }) || profile.protocol_types.contains(&ProtocolType::Erc4626Vault)
    {
        hypotheses.push(BehaviorInvariantHypothesis {
            family: "erc4626-accounting".to_string(),
            severity_hint: ProtocolSeverity::High,
            confidence: 86,
            affected_contracts: base_target.into_iter().collect(),
            evidence: "behavioral deposit/mint -> withdraw/redeem dependency indicates share-supply accounting".to_string(),
            recommended_reproduction_sequence: vec![
                "deposit(uint256,address)".to_string(),
                "withdraw(uint256,address,address)".to_string(),
            ],
            false_positive_caveats: vec![
                "legitimate vault routing and rebasing can move share accounting".to_string(),
            ],
        });
    }

    if graph.edges.iter().any(|edge| {
        matches!(
            edge.kind,
            crate::engine::dependency::DependencyEdgeKind::OraclePriceState
        )
    }) || repeated_oracle_reads_with_drift(execution)
        || profile
            .protocol_types
            .contains(&ProtocolType::OraclePriceFeed)
    {
        hypotheses.push(BehaviorInvariantHypothesis {
            family: "oracle-freshness".to_string(),
            severity_hint: ProtocolSeverity::High,
            confidence: 83,
            affected_contracts: base_target.into_iter().collect(),
            evidence: "behavioral oracle reads changed across repeated calls or price-state dependency observed".to_string(),
            recommended_reproduction_sequence: vec![
                "latestAnswer()".to_string(),
                "latestAnswer()".to_string(),
            ],
            false_positive_caveats: vec![
                "oracle updates between reads or feed rotation can legitimately change output".to_string(),
            ],
        });
    }

    if graph.edges.iter().any(|edge| {
        matches!(
            edge.kind,
            crate::engine::dependency::DependencyEdgeKind::CallerRole
        )
    }) || profile.protocol_types.iter().any(|protocol| {
        matches!(
            protocol,
            ProtocolType::AccessControlHeavy | ProtocolType::ProxyUpgradeable
        )
    }) {
        hypotheses.push(BehaviorInvariantHypothesis {
            family: "access-control".to_string(),
            severity_hint: ProtocolSeverity::High,
            confidence: 82,
            affected_contracts: base_target.into_iter().collect(),
            evidence: "privileged selector or caller-role dependency observed in behavior"
                .to_string(),
            recommended_reproduction_sequence: vec![
                "upgradeTo(address)".to_string(),
                "initialize()".to_string(),
            ],
            false_positive_caveats: vec![
                "fork state may grant caller a role; replay with non-owner actor to confirm"
                    .to_string(),
            ],
        });
    }

    if economic_delta.accounting_anomaly {
        hypotheses.push(BehaviorInvariantHypothesis {
            family: "generic-accounting".to_string(),
            severity_hint: ProtocolSeverity::Medium,
            confidence: 74,
            affected_contracts: economic_delta
                .storage_delta_summary
                .iter()
                .map(|summary| summary.address)
                .collect(),
            evidence: "economic/storage accounting movement exceeded the normal threshold"
                .to_string(),
            recommended_reproduction_sequence: vec![
                "preserve storage-delta path and replay on same fork state".to_string(),
            ],
            false_positive_caveats: vec![
                "administrative migrations, rebases, and protocol upgrades can create large deltas"
                    .to_string(),
            ],
        });
    }

    if findings.is_empty() && hypotheses.is_empty() {
        hypotheses.push(BehaviorInvariantHypothesis {
            family: "generic-accounting".to_string(),
            severity_hint: ProtocolSeverity::Low,
            confidence: 40,
            affected_contracts: base_target.into_iter().collect(),
            evidence: "no strong behavior-specific hypothesis; fallback generic accounting model"
                .to_string(),
            recommended_reproduction_sequence: vec!["multi-tx stateful replay".to_string()],
            false_positive_caveats: vec![
                "weak signal until a stronger dependency, profit, or invariant pattern emerges"
                    .to_string(),
            ],
        });
    }

    hypotheses.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    hypotheses.dedup_by(|a, b| a.family == b.family && a.evidence == b.evidence);
    hypotheses
}

fn build_candidate_template(
    model: &FormalProtocolModel,
    input: &EvmInput,
    execution: &SequenceExecutionResult,
    actor_set: Option<&ActorSet>,
    best_invariant: Option<&BehaviorInvariantHypothesis>,
) -> Option<CounterexampleCandidate> {
    let target = input.txs.first().map(|tx| tx.to)?;
    let attacker = actor_set
        .and_then(|set| set.by_role(ActorType::Attacker))
        .map(|actor| actor.address)
        .or_else(|| input.txs.first().map(|tx| tx.caller))?;
    let mut abi_registry = AbiRegistry::default();
    for selector in &model.target_profile.relevant_selectors {
        abi_registry.functions.entry(*selector).or_default();
    }
    for selector in &model.target_profile.risky_selectors {
        abi_registry.functions.entry(*selector).or_default();
    }

    for protocol in &model.inferred_protocol_types {
        for selector in template_selectors(protocol) {
            abi_registry.functions.entry(selector).or_default();
        }
    }

    let mut template_inputs = generate_flow_template_inputs(target, attacker, &abi_registry);
    if template_inputs.is_empty() {
        template_inputs.push(input.clone());
    }

    let mut selected = template_inputs
        .into_iter()
        .max_by_key(|candidate| candidate.txs.len())?;
    let actor_roles = if let Some(set) = actor_set {
        set.apply_roles_to_sequence(&mut selected.txs)
    } else {
        default_role_map(selected.txs.len())
    };

    let replayability_status = if execution.tx_results.iter().all(|result| {
        matches!(
            result.status,
            crate::common::types::ExecutionStatus::Success
        )
    }) {
        ReplayabilityStatus::Replayable
    } else {
        ReplayabilityStatus::NeedsForkState
    };
    let minimized_sequence_status = if selected.txs.len() <= input.txs.len() {
        MinimizedSequenceStatus::Minimized
    } else {
        MinimizedSequenceStatus::NeedsMinimization
    };
    let proof_status = if best_invariant.is_some()
        && (model.confidence >= 70
            || matches!(replayability_status, ReplayabilityStatus::Replayable))
    {
        if matches!(replayability_status, ReplayabilityStatus::Replayable) {
            CounterexampleProofStatus::ConcretelyReplayed
        } else {
            CounterexampleProofStatus::AbstractlyProven
        }
    } else {
        CounterexampleProofStatus::HeuristicOnly
    };
    let profit_delta = if model.economic_delta.estimated_profit.is_zero() {
        None
    } else {
        Some(model.economic_delta.estimated_profit)
    };
    let extension_hints = best_invariant
        .map(|hypothesis| extension_hints_for_family(&hypothesis.family))
        .unwrap_or_default();
    let mut evidence = vec![
        format!("formal-model confidence={}", model.confidence),
        format!("dependency-score={}", dependency_sequence_score(&selected)),
    ];
    if let Some(hypothesis) = best_invariant {
        evidence.push(format!(
            "best invariant family={} confidence={}",
            hypothesis.family, hypothesis.confidence
        ));
    }

    Some(CounterexampleCandidate {
        input: selected,
        target: Some(target),
        actor_roles,
        profit_delta,
        violated_invariant: best_invariant.map(|hypothesis| hypothesis.family.clone()),
        confidence: model.confidence.max(
            best_invariant
                .map(|hypothesis| hypothesis.confidence)
                .unwrap_or_default(),
        ),
        replayability_status,
        minimized_sequence_status,
        proof_status,
        extension_hints,
        replay_checks: vec![
            "replay on same fork state".to_string(),
            "compare storage diffs and call trace".to_string(),
            "synthesize Foundry PoC only after replay succeeds".to_string(),
        ],
        evidence,
    })
}

fn apply_concolic_hints(input: &mut EvmInput, hints: &[ConcolicHint], limit: usize) -> Vec<String> {
    let mut applied = Vec::new();
    for hint in hints.iter().take(limit) {
        let Some(tx) = input.txs.get_mut(hint.tx_index) else {
            continue;
        };
        if apply_word_at_offset(&mut tx.input, hint.calldata_offset, &hint.word) {
            applied.push(format!(
                "tx={} offset={} pc={} strategy={:?}",
                hint.tx_index, hint.calldata_offset, hint.pc, hint.strategy
            ));
        }
    }
    applied
}

fn apply_word_at_offset(bytes: &mut Vec<u8>, offset: usize, word: &[u8; 32]) -> bool {
    let offset = offset.max(4);
    let end = offset.saturating_add(32);
    if bytes.len() < end {
        bytes.resize(end, 0);
    }
    if bytes.len() < end {
        return false;
    }
    bytes[offset..end].copy_from_slice(word);
    true
}

fn extension_hints_for_family(family: &str) -> Vec<ExploitExtensionHint> {
    match family {
        "erc4626-accounting" => vec![
            ExploitExtensionHint::PreserveInvariantViolation,
            ExploitExtensionHint::MutateAmountsAndValue,
            ExploitExtensionHint::PreserveEconomicDelta,
        ],
        "erc20-accounting" => vec![
            ExploitExtensionHint::PreserveInvariantViolation,
            ExploitExtensionHint::ExtendStorageDependentSelector,
        ],
        "oracle-freshness" => vec![
            ExploitExtensionHint::PreserveInvariantViolation,
            ExploitExtensionHint::PreserveReplaySuccess,
        ],
        "access-control" => vec![
            ExploitExtensionHint::RetryNonOwnerCaller,
            ExploitExtensionHint::PreserveReplaySuccess,
        ],
        _ => vec![
            ExploitExtensionHint::PreserveInvariantViolation,
            ExploitExtensionHint::MinimizeTransactionCount,
        ],
    }
}

fn default_role_map(len: usize) -> BTreeMap<usize, ActorType> {
    let mut roles = BTreeMap::new();
    for idx in 0..len {
        roles.insert(
            idx,
            match idx {
                0 => ActorType::Attacker,
                1 => ActorType::Victim,
                2 => ActorType::Attacker,
                _ => ActorType::RandomUser,
            },
        );
    }
    roles
}

fn template_selectors(protocol: &ProtocolType) -> Vec<[u8; 4]> {
    match protocol {
        ProtocolType::Erc20Token => vec![
            selector_from_sig("approve(address,uint256)"),
            selector_from_sig("transfer(address,uint256)"),
            selector_from_sig("transferFrom(address,address,uint256)"),
        ],
        ProtocolType::Erc4626Vault => vec![
            selector_from_sig("deposit(uint256,address)"),
            selector_from_sig("withdraw(uint256,address,address)"),
            selector_from_sig("redeem(uint256,address,address)"),
        ],
        ProtocolType::AmmDexPool => vec![
            selector_from_sig("swap(address,bool,int256,uint160,bytes)"),
            selector_from_sig("addLiquidity(uint256,uint256)"),
            selector_from_sig("removeLiquidity(uint256)"),
        ],
        ProtocolType::LendingBorrowing => vec![
            selector_from_sig("borrow(address,uint256,uint256,uint16,address)"),
            selector_from_sig("repay(address,uint256,uint256,address)"),
            selector_from_sig("liquidationCall(address,address,address,uint256,bool)"),
        ],
        ProtocolType::OraclePriceFeed => vec![
            selector_from_sig("latestAnswer()"),
            selector_from_sig("latestRoundData()"),
        ],
        ProtocolType::GovernanceTimelock => vec![
            selector_from_sig("propose(address[],uint256[],bytes[],string)"),
            selector_from_sig("castVote(uint256,uint8)"),
            selector_from_sig("queue(uint256)"),
            selector_from_sig("execute(uint256)"),
        ],
        ProtocolType::BridgeMessagePassing => vec![
            selector_from_sig("send(bytes)"),
            selector_from_sig("prove(bytes)"),
            selector_from_sig("finalize(bytes)"),
            selector_from_sig("claim()"),
        ],
        ProtocolType::StakingRewards => vec![
            selector_from_sig("stake(uint256)"),
            selector_from_sig("claim()"),
            selector_from_sig("unstake(uint256)"),
        ],
        ProtocolType::AccessControlHeavy | ProtocolType::ProxyUpgradeable => vec![
            selector_from_sig("upgradeTo(address)"),
            selector_from_sig("initialize()"),
            selector_from_sig("grantRole(bytes32,address)"),
            selector_from_sig("transferOwnership(address)"),
        ],
        ProtocolType::RouterAggregator | ProtocolType::AccountingHeavy | ProtocolType::Unknown => {
            Vec::new()
        }
    }
}

fn selector_from_sig(signature: &str) -> [u8; 4] {
    let hash = revm::primitives::keccak256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

fn selector(call: &crate::common::types::CallObservation) -> Option<[u8; 4]> {
    call.input.get(0..4)?.try_into().ok()
}

fn repeated_oracle_reads_with_drift(execution: &SequenceExecutionResult) -> bool {
    let oracle_selectors = [
        selector_from_sig("latestAnswer()"),
        selector_from_sig("latestRoundData()"),
        selector_from_sig("price()"),
        selector_from_sig("getPrice()"),
    ];
    let mut previous: Option<U256> = None;
    for call in execution.call_trace.iter().filter(|call| {
        call.phase == CallPhase::End
            && matches!(
                call.kind,
                CallKind::Transaction | CallKind::Call | CallKind::StaticCall
            )
            && selector(call).is_some_and(|sel| oracle_selectors.contains(&sel))
    }) {
        if let Some(word) = output_word(call) {
            if let Some(prev) = previous {
                if prev != word {
                    return true;
                }
            }
            previous = Some(word);
        }
    }
    false
}

fn output_word(call: &crate::common::types::CallObservation) -> Option<U256> {
    (call.output.len() >= 32).then(|| U256::from_be_slice(&call.output[..32]))
}

fn dependency_sequence_score_from_graph(graph: &TransactionDependencyGraph) -> u64 {
    graph
        .edges
        .iter()
        .map(|edge| match edge.kind {
            crate::engine::dependency::DependencyEdgeKind::ApprovalAllowance
            | crate::engine::dependency::DependencyEdgeKind::Temporal
            | crate::engine::dependency::DependencyEdgeKind::Economic => edge.confidence / 2,
            crate::engine::dependency::DependencyEdgeKind::ReadsAfterWrites
            | crate::engine::dependency::DependencyEdgeKind::SameSlot => edge.confidence / 3,
            _ => edge.confidence / 4,
        })
        .sum::<u64>()
        .min(150)
}

fn concolic_hints_from_execution(execution: &SequenceExecutionResult) -> Vec<ConcolicHint> {
    let solver = ConcolicSolver::new();
    solver.solve_hints(execution.tx_results.iter().flat_map(|tx| {
        tx.waypoints
            .iter()
            .map(move |waypoint| (tx.tx_index, waypoint))
    }))
}

fn model_confidence(
    protocols: &[ProtocolType],
    hypotheses: &[BehaviorInvariantHypothesis],
    graph: &TransactionDependencyGraph,
    economic_delta: &EconomicDeltaReport,
) -> u64 {
    let protocol_score = protocols
        .iter()
        .filter(|protocol| **protocol != ProtocolType::Unknown)
        .count() as u64
        * 10;
    let hypothesis_score = hypotheses
        .iter()
        .map(|hypothesis| hypothesis.confidence)
        .sum::<u64>()
        / 3;
    let graph_score = dependency_sequence_score_from_graph(graph);
    let economic_score = EconomicDeltaEngine::score(economic_delta) / 8;
    (protocol_score
        .saturating_add(hypothesis_score)
        .saturating_add(graph_score)
        .saturating_add(economic_score))
    .clamp(25, 95)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::oracle::{ProtocolFinding, VulnType};
    use crate::common::types::SingletonTx;
    use crate::common::types::{CallObservation, ExecutionStatus, StorageDiff, TxExecutionResult};
    use crate::engine::target_profile::function_selector;

    fn target() -> Address {
        Address::repeat_byte(0x44)
    }

    fn execution_with_selectors(selectors: &[&str]) -> SequenceExecutionResult {
        let tx_results = selectors
            .iter()
            .enumerate()
            .map(|(idx, selector)| TxExecutionResult {
                tx_index: idx,
                status: ExecutionStatus::Success,
                gas_used: 1,
                output: if selector.contains("latestAnswer") {
                    U256::from(100 + idx as u64).to_be_bytes::<32>().to_vec()
                } else {
                    Vec::new()
                },
                coverage_hash: idx as u64,
                coverage_edges: 1,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: Vec::new(),
                call_trace: vec![CallObservation {
                    tx_index: idx,
                    depth: 0,
                    caller: Address::repeat_byte(0x10 + idx as u8),
                    target: target(),
                    value: U256::ZERO,
                    input: function_selector(selector).to_vec(),
                    output: if selector.contains("latestAnswer") {
                        U256::from(100 + idx as u64).to_be_bytes::<32>().to_vec()
                    } else {
                        Vec::new()
                    },
                    gas_limit: 0,
                    gas_used: 0,
                    success: true,
                    kind: CallKind::Transaction,
                    phase: CallPhase::End,
                    created_address: None,
                    result: Some("Success".to_string()),
                }],
                waypoints: Vec::new(),
            })
            .collect::<Vec<_>>();

        SequenceExecutionResult {
            tx_results,
            total_gas_used: 2,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: Vec::new(),
            oracle_observations: Vec::new(),
        }
    }

    #[test]
    fn synthesizes_behavioral_protocol_model_without_abi() {
        let input = EvmInput {
            txs: vec![
                SingletonTx {
                    input: function_selector("approve(address,uint256)").to_vec(),
                    caller: Address::repeat_byte(0xaa),
                    to: target(),
                    value: U256::ZERO,
                    is_victim: false,
                },
                SingletonTx {
                    input: function_selector("transferFrom(address,address,uint256)").to_vec(),
                    caller: Address::repeat_byte(0xaa),
                    to: target(),
                    value: U256::ZERO,
                    is_victim: true,
                },
            ],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let execution = SequenceExecutionResult {
            tx_results: vec![TxExecutionResult {
                tx_index: 0,
                status: ExecutionStatus::Success,
                gas_used: 1,
                output: Vec::new(),
                coverage_hash: 0,
                coverage_edges: 1,
                storage_reads: Vec::new(),
                storage_writes: Vec::new(),
                storage_diffs: vec![StorageDiff {
                    tx_index: 0,
                    address: target(),
                    slot: revm::primitives::B256::from([1u8; 32]),
                    old_value: U256::ZERO,
                    new_value: U256::from(1_000u64),
                    pc: 0,
                }],
                call_trace: vec![CallObservation {
                    tx_index: 0,
                    depth: 0,
                    caller: Address::repeat_byte(0xaa),
                    target: target(),
                    value: U256::ZERO,
                    input: function_selector("approve(address,uint256)").to_vec(),
                    output: Vec::new(),
                    gas_limit: 0,
                    gas_used: 0,
                    success: true,
                    kind: CallKind::Transaction,
                    phase: CallPhase::End,
                    created_address: None,
                    result: Some("Success".to_string()),
                }],
                waypoints: Vec::new(),
            }],
            total_gas_used: 1,
            final_coverage_hash: 1,
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            storage_diffs: vec![StorageDiff {
                tx_index: 0,
                address: target(),
                slot: revm::primitives::B256::from([1u8; 32]),
                old_value: U256::ZERO,
                new_value: U256::from(1_000u64),
                pc: 0,
            }],
            call_trace: vec![CallObservation {
                tx_index: 0,
                depth: 0,
                caller: Address::repeat_byte(0xaa),
                target: target(),
                value: U256::ZERO,
                input: function_selector("approve(address,uint256)").to_vec(),
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
        };

        let model = FormalProtocolModel::synthesize(&input, &execution, &[], None);

        assert!(model
            .inferred_protocol_types
            .contains(&ProtocolType::Erc20Token));
        assert!(!model.invariant_hypotheses.is_empty());
        assert!(model.counterexample_pressure() > 0);
    }

    #[test]
    fn counterexample_search_builds_template_candidate() {
        let input = EvmInput {
            txs: vec![SingletonTx {
                input: function_selector("deposit(uint256,address)").to_vec(),
                caller: Address::repeat_byte(0xaa),
                to: target(),
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        let execution = execution_with_selectors(&["deposit(uint256,address)", "latestAnswer()"]);
        let findings = vec![ProtocolFinding {
            pack: crate::common::oracle::ProtocolOraclePackKind::Erc4626,
            vuln: VulnType::VaultInflation,
            severity: ProtocolSeverity::High,
            tx_index: Some(0),
            target: Some(target()),
            evidence: "share inflation".to_string(),
        }];
        let result =
            CounterexampleSearchEngine::default().search(&input, &execution, &findings, None, None);
        assert!(result.model.counterexample_pressure() > 0);
        assert!(result.candidate.is_some());
        let candidate = result.candidate.unwrap();
        assert!(!candidate.replay_checks.is_empty());
        assert!(!candidate.evidence.is_empty());
    }
}
