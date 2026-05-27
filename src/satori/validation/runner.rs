use crate::satori::error::SatoriResult;
use crate::satori::fsutil::write_json;
use crate::satori::jobs::foundry_poc::generate_foundry_poc;
use crate::satori::types::{
    FoundryPocSpec, ProjectModel, ProofStatus, RustyFuzzJobSpec, ValidationStatus,
    ValidationVerdict, VulnerabilityHypothesis,
};
use crate::satori::validation::foundry_runner::maybe_run_forge_test;
use crate::satori::validation::rustyfuzz_runner::has_direct_rustyfuzz_context;
use std::path::Path;

pub fn validate_jobs(
    project: &ProjectModel,
    run_dir: &Path,
    hypotheses: &[VulnerabilityHypothesis],
    jobs: &[RustyFuzzJobSpec],
) -> SatoriResult<(Vec<ValidationVerdict>, Vec<FoundryPocSpec>)> {
    let mut verdicts = Vec::new();
    let mut pocs = Vec::new();
    for hypothesis in hypotheses {
        let job = jobs.iter().find(|job| job.hypothesis_id == hypothesis.id);
        let poc = generate_foundry_poc(run_dir, hypothesis, job)?;
        let mut verdict = if let Some(job) = job {
            if has_direct_rustyfuzz_context(job) {
                ValidationVerdict {
                    hypothesis_id: hypothesis.id.clone(),
                    job_id: Some(job.job_id.clone()),
                    status: ValidationStatus::JobGenerated,
                    proof_status: ProofStatus::JobGeneratedOnly,
                    reason: "Direct RustyFuzz context exists, but bounded campaign adapter is not invoked by Satori v1.".to_string(),
                    artifacts: vec![poc.path.clone()],
                    economic_impact: None,
                    confidence_after_validation: hypothesis.confidence_before_validation.min(0.49),
                }
            } else {
                ValidationVerdict {
                    hypothesis_id: hypothesis.id.clone(),
                    job_id: Some(job.job_id.clone()),
                    status: ValidationStatus::NeedsMoreContext,
                    proof_status: ProofStatus::JobGeneratedOnly,
                    reason: "Missing concrete target address, ABI, fork RPC, or fork block for local replay.".to_string(),
                    artifacts: vec![poc.path.clone()],
                    economic_impact: None,
                    confidence_after_validation: 0.0,
                }
            }
        } else {
            ValidationVerdict {
                hypothesis_id: hypothesis.id.clone(),
                job_id: None,
                status: ValidationStatus::NeedsMoreContext,
                proof_status: ProofStatus::HeuristicOnly,
                reason: "No RustyFuzz job was generated for this hypothesis.".to_string(),
                artifacts: vec![poc.path.clone()],
                economic_impact: None,
                confidence_after_validation: 0.0,
            }
        };
        if matches!(
            project.project_type,
            crate::satori::types::ProjectType::Foundry | crate::satori::types::ProjectType::Mixed
        ) {
            let tool_run = maybe_run_forge_test(&project.root, &poc.path)?;
            if tool_run.available && tool_run.success {
                verdict.status = ValidationStatus::FoundryCompiled;
                verdict.proof_status = ProofStatus::FoundryCompiled;
                verdict.reason.push_str(
                    " Foundry scaffold compiled locally; this is still not exploit proof without target-specific assertions.",
                );
            } else if tool_run.available {
                verdict.status = ValidationStatus::FoundryFailedToCompile;
                verdict.proof_status = ProofStatus::JobGeneratedOnly;
                verdict.reason.push_str(&format!(
                    " Foundry compile/test attempt failed: {}",
                    tool_run.stderr_snippet
                ));
            } else {
                verdict.status = ValidationStatus::FoundryPocGenerated;
                verdict.proof_status = ProofStatus::JobGeneratedOnly;
                verdict.reason.push_str(
                    " Foundry PoC scaffold was generated, but forge is unavailable; scaffold is not proof.",
                );
            }
        } else {
            verdict.status = ValidationStatus::FoundryPocGenerated;
            verdict
                .reason
                .push_str(" Foundry PoC scaffold was generated for manual binding.");
        }
        pocs.push(poc);
        verdicts.push(verdict);
    }
    write_json(run_dir.join("validation_verdicts.json"), &verdicts)?;
    write_json(run_dir.join("foundry_pocs.json"), &pocs)?;
    Ok((verdicts, pocs))
}
