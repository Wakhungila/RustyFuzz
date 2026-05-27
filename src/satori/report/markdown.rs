use crate::satori::types::{SatoriReport, ValidationStatus};

pub fn render_markdown(report: &SatoriReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Satori Report `{}`\n\n", report.run_id));
    out.push_str("## Repository Summary\n\n");
    out.push_str(&report.project_summary);
    out.push_str("\n\n## Tool Status\n\n");
    for tool in &report.tool_status {
        out.push_str(&format!(
            "- `{}`: available={}, success={} {}\n",
            tool.command, tool.available, tool.success, tool.stderr_snippet
        ));
    }
    out.push_str("\n## Protocol Model\n\n");
    out.push_str(&format!(
        "- Types: {:?}\n- Confidence: {:.2}\n- Explanation: {}\n",
        report.protocol_model.protocol_types,
        report.protocol_model.confidence,
        report.protocol_model.explanation
    ));
    out.push_str("\n## Critical Functions Analyzed\n\n");
    for function in &report.critical_functions {
        out.push_str(&format!(
            "- `{}` score={:.2} file={}\n",
            function.id,
            function.criticality_score,
            function.file.display()
        ));
    }
    out.push_str("\n## Hypotheses Generated\n\n");
    for hypothesis in &report.hypotheses {
        out.push_str(&format!(
            "- `{}` [{}] confidence_before_validation={:.2}: {}\n",
            hypothesis.id,
            hypothesis.bug_class,
            hypothesis.confidence_before_validation,
            hypothesis.title
        ));
    }
    out.push_str("\n## Rejected Hypotheses\n\n");
    for rejected in &report.rejected_hypotheses {
        out.push_str(&format!("- {rejected}\n"));
    }
    out.push_str("\n## RustyFuzz Jobs Generated\n\n");
    for job in &report.jobs {
        out.push_str(&format!("- `{}` objective={}\n", job.job_id, job.objective));
    }
    out.push_str("\n## Foundry PoCs Generated\n\n");
    for poc in &report.foundry_pocs {
        out.push_str(&format!(
            "- `{}` generated={}\n",
            poc.path.display(),
            poc.generated
        ));
    }
    out.push_str("\n## Validation Verdicts\n\n");
    for verdict in &report.validation_verdicts {
        out.push_str(&format!(
            "- `{}` status={:?} proof={:?}: {}\n",
            verdict.hypothesis_id, verdict.status, verdict.proof_status, verdict.reason
        ));
    }
    out.push_str("\n## Validated Findings Only\n\n");
    let validated = report
        .validation_verdicts
        .iter()
        .filter(|verdict| {
            matches!(
                verdict.status,
                ValidationStatus::ValidatedLocal
                    | ValidationStatus::ValidatedMinimized
                    | ValidationStatus::ValidatedEconomicImpact
            )
        })
        .count();
    if validated == 0 {
        out.push_str("No validated findings. Hypotheses remain unconfirmed until local replay/test evidence exists.\n");
    }
    out.push_str("\n## Plausible But Unvalidated Items\n\n");
    for verdict in &report.validation_verdicts {
        if !matches!(
            verdict.status,
            ValidationStatus::ValidatedLocal
                | ValidationStatus::ValidatedMinimized
                | ValidationStatus::ValidatedEconomicImpact
        ) {
            out.push_str(&format!(
                "- `{}`: {:?}\n",
                verdict.hypothesis_id, verdict.status
            ));
        }
    }
    out.push_str("\n## Budget / Call Summary\n\n");
    out.push_str(&format!(
        "- model_calls={}\n- cached_model_hits={}\n- approximate_input_tokens={}\n- approximate_output_tokens={}\n",
        report.budget.model_calls,
        report.budget.cached_model_hits,
        report.budget.approximate_input_tokens,
        report.budget.approximate_output_tokens
    ));
    out.push_str("\n## Next Recommended Manual Steps\n\n");
    for step in &report.next_steps {
        out.push_str(&format!("- {step}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::{BudgetReport, ProtocolModel, SatoriReport};

    #[test]
    fn report_generation_writes_expected_sections() {
        let report = SatoriReport {
            run_id: "r".to_string(),
            project_summary: "summary".to_string(),
            tool_status: Vec::new(),
            protocol_model: ProtocolModel::default(),
            critical_functions: Vec::new(),
            hypotheses: Vec::new(),
            rejected_hypotheses: Vec::new(),
            jobs: Vec::new(),
            foundry_pocs: Vec::new(),
            validation_verdicts: Vec::new(),
            budget: BudgetReport::default(),
            next_steps: vec!["bind targets".to_string()],
        };
        let md = render_markdown(&report);
        assert!(md.contains("Validated Findings Only"));
        assert!(md.contains("Budget / Call Summary"));
    }
}
