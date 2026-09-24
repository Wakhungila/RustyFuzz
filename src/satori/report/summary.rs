use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{ensure_dir, validate_identifier, write_text, write_text_in_run};
use crate::satori::report::json::write_report_json;
use crate::satori::report::markdown::render_markdown;
use crate::satori::types::SatoriReport;
use std::path::Path;

pub fn write_reports(run_dir: &Path, report: &SatoriReport) -> SatoriResult<()> {
    validate_identifier(&report.run_id)?;
    require_replay_for_report(report)?;
    write_report_json(run_dir, report)?;
    let md = render_markdown(report);
    write_text_in_run(run_dir, Path::new("report.md"), &md)?;
    let reports_dir = Path::new("satori/reports");
    ensure_dir(reports_dir)?;
    write_text(reports_dir.join(format!("{}.md", report.run_id)), &md)?;
    Ok(())
}

fn require_replay_for_report(report: &SatoriReport) -> SatoriResult<()> {
    for verdict in &report.validation_verdicts {
        let validated = matches!(
            verdict.status,
            crate::satori::types::ValidationStatus::ValidatedLocal
                | crate::satori::types::ValidationStatus::ValidatedMinimized
                | crate::satori::types::ValidationStatus::ValidatedEconomicImpact
        );
        if validated {
            anyhow::ensure!(
                matches!(
                    verdict.proof_status,
                    crate::satori::types::ProofStatus::ConcretelyReplayed
                        | crate::satori::types::ProofStatus::Minimized
                ),
                "Satori report rejected: validated verdict `{}` lacks replay proof",
                verdict.hypothesis_id
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::{BudgetReport, ProofStatus, ValidationStatus, ValidationVerdict};

    fn report_with_verdict(proof_status: ProofStatus) -> SatoriReport {
        SatoriReport {
            run_id: "run-test".to_string(),
            project_summary: String::new(),
            tool_status: Vec::new(),
            protocol_model: Default::default(),
            critical_functions: Vec::new(),
            hypotheses: Vec::new(),
            rejected_hypotheses: Vec::new(),
            jobs: Vec::new(),
            foundry_pocs: Vec::new(),
            validation_verdicts: vec![ValidationVerdict {
                hypothesis_id: "h1".to_string(),
                job_id: None,
                status: ValidationStatus::ValidatedLocal,
                proof_status,
                reason: String::new(),
                artifacts: Vec::new(),
                economic_impact: None,
                confidence_after_validation: 0.9,
            }],
            budget: BudgetReport::default(),
            next_steps: Vec::new(),
        }
    }

    #[test]
    fn validated_reports_require_replay_proof() {
        assert!(
            require_replay_for_report(&report_with_verdict(ProofStatus::HeuristicOnly)).is_err()
        );
        assert!(
            require_replay_for_report(&report_with_verdict(ProofStatus::ConcretelyReplayed))
                .is_ok()
        );
    }
}
