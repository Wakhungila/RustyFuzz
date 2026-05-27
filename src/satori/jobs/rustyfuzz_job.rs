use crate::satori::types::{RustyFuzzJobSpec, VulnerabilityHypothesis};

pub fn job_from_hypothesis(hypothesis: &VulnerabilityHypothesis) -> RustyFuzzJobSpec {
    RustyFuzzJobSpec {
        job_id: format!("job-{}", hypothesis.id),
        hypothesis_id: hypothesis.id.clone(),
        job_type: "sequence_fuzz".to_string(),
        target_contract: hypothesis.affected_contracts.first().cloned(),
        bug_class: hypothesis.bug_class.clone(),
        actors: hypothesis
            .attack_sequence
            .iter()
            .map(|step| step.actor.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
        preconditions: hypothesis.required_conditions.clone(),
        sequence_template: hypothesis.attack_sequence.clone(),
        mutation_focus: vec![hypothesis.rustyfuzz_objective.clone()],
        invariants: hypothesis.suggested_invariants.clone(),
        objective: hypothesis.rustyfuzz_objective.clone(),
        success_condition: hypothesis
            .validation_plan
            .first()
            .map(|step| step.success_condition.clone())
            .unwrap_or_else(|| "local replay produces invariant or economic signal".to_string()),
        max_depth: hypothesis.attack_sequence.len().max(1),
        fork_rpc_url: None,
        fork_block: None,
        abi_hints: hypothesis.affected_functions.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::{AttackStep, CandidateInvariant, ValidationStep};

    #[test]
    fn job_schema_serializes() {
        let hypothesis = VulnerabilityHypothesis {
            id: "h1".to_string(),
            title: "x".to_string(),
            bug_class: "access_control".to_string(),
            root_cause: "x".to_string(),
            affected_contracts: vec!["Vault".to_string()],
            affected_functions: vec!["withdraw()".to_string()],
            evidence_from_context: vec!["public withdraw".to_string()],
            required_conditions: Vec::new(),
            attack_sequence: vec![AttackStep {
                actor: "attacker".to_string(),
                action: "withdraw".to_string(),
                target: Some("Vault".to_string()),
                calldata_hint: None,
                value_hint: None,
            }],
            false_positive_checks: Vec::new(),
            validation_plan: vec![ValidationStep {
                tool: "foundry".to_string(),
                action: "compile scaffold".to_string(),
                success_condition: "manual binding required".to_string(),
            }],
            suggested_invariants: vec![CandidateInvariant {
                id: "i1".to_string(),
                description: "no unauthorized withdraw".to_string(),
                check: "attacker balance does not increase".to_string(),
                expected_signal: "revert or no balance delta".to_string(),
            }],
            rustyfuzz_objective: "maximize attacker profit".to_string(),
            confidence_before_validation: 0.4,
        };
        let job = job_from_hypothesis(&hypothesis);
        let json = serde_json::to_string(&job).unwrap();
        assert!(json.contains("sequence_fuzz"));
        let decoded: RustyFuzzJobSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.hypothesis_id, "h1");
    }
}
