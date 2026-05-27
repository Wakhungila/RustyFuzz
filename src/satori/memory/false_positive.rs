use crate::satori::types::VulnerabilityHypothesis;

pub fn has_minimum_evidence(hypothesis: &VulnerabilityHypothesis) -> bool {
    !hypothesis.evidence_from_context.is_empty()
        && !hypothesis.attack_sequence.is_empty()
        && !hypothesis.validation_plan.is_empty()
}
