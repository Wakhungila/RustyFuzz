use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{verify_source_file_binding, write_json_in_run};
use crate::satori::jobs::foundry_poc::generate_foundry_poc;
use crate::satori::types::{
    FoundryPocSpec, ProjectModel, ProofStatus, RustyFuzzJobSpec, ValidationStatus,
    ValidationVerdict, VulnerabilityHypothesis,
};
use crate::satori::validation::foundry_runner::{foundry_assertion_failure, maybe_run_forge_test};
use crate::satori::validation::rustyfuzz_runner::{
    execute_bounded_job, has_direct_rustyfuzz_context,
};
use std::path::Path;

pub fn validate_jobs(
    project: &ProjectModel,
    run_dir: &Path,
    hypotheses: &[VulnerabilityHypothesis],
    jobs: &[RustyFuzzJobSpec],
    external_foundry_opt_in: bool,
) -> SatoriResult<(Vec<ValidationVerdict>, Vec<FoundryPocSpec>)> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("validation runtime failed: {error}"))?
        .block_on(validate_jobs_async(
            project,
            run_dir,
            hypotheses,
            jobs,
            external_foundry_opt_in,
        ))
}

pub async fn validate_jobs_async(
    project: &ProjectModel,
    run_dir: &Path,
    hypotheses: &[VulnerabilityHypothesis],
    jobs: &[RustyFuzzJobSpec],
    external_foundry_opt_in: bool,
) -> SatoriResult<(Vec<ValidationVerdict>, Vec<FoundryPocSpec>)> {
    crate::satori::fsutil::reject_symlink_components(&project.root)?;
    let project_root = project.root.canonicalize()?;
    for source in project.source_files.iter().chain(project.docs.iter()) {
        verify_source_file_binding(
            &project_root,
            &source.path,
            &source.relative_path,
            &source.content_hash,
        )?;
    }
    let mut verdicts = Vec::new();
    let mut pocs = Vec::new();
    for hypothesis in hypotheses {
        let job = jobs.iter().find(|job| job.hypothesis_id == hypothesis.id);
        let hypothesis_for_poc = hypothesis.clone();
        let job_for_poc = job.cloned();
        let poc_dir = run_dir.to_path_buf();
        let project_root = project.root.clone();
        let mut poc = tokio::task::spawn_blocking(move || {
            generate_foundry_poc(
                &project_root,
                &poc_dir,
                &hypothesis_for_poc,
                job_for_poc.as_ref(),
            )
        })
        .await
        .map_err(|error| anyhow::anyhow!("foundry scaffold worker failed: {error}"))??;
        let direct_context = job.is_some_and(has_direct_rustyfuzz_context);
        let mut verdict = if let Some(job) = job {
            if direct_context {
                execute_bounded_job(job, run_dir, external_foundry_opt_in).await?
            } else {
                ValidationVerdict {
                    hypothesis_id: hypothesis.id.clone(),
                    job_id: Some(job.job_id.clone()),
                     status: ValidationStatus::NeedsMoreContext,
                     proof_status: ProofStatus::HeuristicOnly,
                     reason: "RustyFuzz job is missing target, fork RPC, or fork block; bounded execution was not started.".to_string(),

                    artifacts: vec![poc.path.clone()],
                    economic_impact: None,
                    confidence_after_validation: hypothesis.confidence_before_validation.min(0.49),
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
        ) && external_foundry_opt_in
        {
            let project_root = project.root.clone();
            let run_dir = run_dir.to_path_buf();
            let poc_path = poc.path.clone();
            let rpc_url = job.and_then(|job| job.fork_rpc_url.clone());
            let tool_run = tokio::task::spawn_blocking(move || {
                maybe_run_forge_test(&project_root, &run_dir, &poc_path, rpc_url.as_deref())
            })
            .await
            .map_err(|error| anyhow::anyhow!("forge worker failed: {error}"))??;
            poc.compile_attempted = tool_run.available;
            poc.compile_success = tool_run.available && tool_run.success;
            if tool_run.available && tool_run.success {
                if direct_context {
                    verdict.reason.push_str(
                        " Generated Foundry scaffold compiled separately; compilation is not exploit proof.",
                    );
                } else {
                    verdict.status = ValidationStatus::FoundryCompiled;
                    verdict.proof_status = ProofStatus::FoundryCompiled;
                    verdict.reason.push_str(
                        " Foundry scaffold compiled locally; this is still not exploit proof without target-specific assertions.",
                    );
                }
            } else if tool_run.available {
                if foundry_assertion_failure(&tool_run) {
                    verdict.status = ValidationStatus::FoundryTestSignal;
                    verdict.proof_status = ProofStatus::HeuristicOnly;
                    verdict.reason.push_str(
                        " Foundry scaffold test assertion failed; this is not a compile result.",
                    );
                } else if direct_context {
                    verdict
                        .reason
                        .push_str(" Generated Foundry scaffold test or compilation failed; bounded execution status is unchanged.");
                } else {
                    verdict.status = ValidationStatus::FoundryFailedToCompile;
                    verdict.proof_status = ProofStatus::JobGeneratedOnly;
                    verdict.reason.push_str(&format!(
                        " Foundry compile/test attempt failed: {}",
                        tool_run.stderr_snippet
                    ));
                }
            } else if direct_context {
                verdict
                    .reason
                    .push_str(" Generated Foundry scaffold could not be compiled because forge is unavailable.");
            } else {
                verdict.status = ValidationStatus::FoundryPocGenerated;
                verdict.proof_status = ProofStatus::JobGeneratedOnly;
                verdict.reason.push_str(
                    " Foundry PoC scaffold was generated, but forge is unavailable; scaffold is not proof.",
                );
            }
        } else if matches!(
            project.project_type,
            crate::satori::types::ProjectType::Foundry | crate::satori::types::ProjectType::Mixed
        ) {
            verdict.reason.push_str(
                " Foundry validation skipped: external Foundry analysis requires explicit operator opt-in.",
            );
        } else if !direct_context {
            verdict.status = ValidationStatus::FoundryPocGenerated;
            verdict
                .reason
                .push_str(" Foundry PoC scaffold was generated for manual binding.");
        }
        pocs.push(poc);
        verdicts.push(verdict);
    }
    let verdicts_for_write = verdicts.clone();
    let pocs_for_write = pocs.clone();
    let report_dir = run_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        write_json_in_run(
            &report_dir,
            Path::new("validation_verdicts.json"),
            &verdicts_for_write,
        )?;
        write_json_in_run(&report_dir, Path::new("foundry_pocs.json"), &pocs_for_write)
    })
    .await
    .map_err(|error| anyhow::anyhow!("validation report worker failed: {error}"))??;
    Ok((verdicts, pocs))
}
