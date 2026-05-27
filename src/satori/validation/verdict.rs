use crate::satori::types::{ProofStatus, ValidationStatus, ValidationVerdict};

pub fn needs_context(
    hypothesis_id: &str,
    job_id: Option<String>,
    reason: String,
) -> ValidationVerdict {
    ValidationVerdict {
        hypothesis_id: hypothesis_id.to_string(),
        job_id,
        status: ValidationStatus::NeedsMoreContext,
        proof_status: ProofStatus::JobGeneratedOnly,
        reason,
        artifacts: Vec::new(),
        economic_impact: None,
        confidence_after_validation: 0.0,
    }
}
