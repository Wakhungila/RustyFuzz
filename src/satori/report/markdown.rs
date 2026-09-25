use crate::satori::types::{SatoriReport, ValidationStatus};

pub fn render_markdown(report: &SatoriReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Satori Report {}\n\n", md_code(&report.run_id)));
    out.push_str("## Repository Summary\n\n");
    out.push_str(&md_block(&report.project_summary));
    out.push_str("\n\n## Tool Status\n\n");
    for tool in &report.tool_status {
        out.push_str(&format!(
            "- command={} available={}, success={} stderr={}\n",
            md_code(&tool.command),
            tool.available,
            tool.success,
            md_code(&tool.stderr_snippet)
        ));
    }
    out.push_str("\n## Protocol Model\n\n");
    out.push_str(&format!(
        "- Types: {:?}\n- Confidence: {:.2}\n",
        report.protocol_model.protocol_types, report.protocol_model.confidence
    ));
    out.push_str(&md_block(&report.protocol_model.explanation));
    out.push_str("\n## Critical Functions Analyzed\n\n");
    for function in &report.critical_functions {
        out.push_str(&format!(
            "- id={} score={:.2} file={}\n",
            md_code(&function.id),
            function.criticality_score,
            md_code(&function.file.display().to_string())
        ));
    }
    out.push_str("\n## Hypotheses Generated\n\n");
    for hypothesis in &report.hypotheses {
        out.push_str(&format!(
            "- id={} bug_class={} confidence_before_validation={:.2}\n",
            md_code(&hypothesis.id),
            md_code(&hypothesis.bug_class),
            hypothesis.confidence_before_validation
        ));
        out.push_str(&format!("{}\n", md_block(&hypothesis.title)));
    }
    out.push_str("\n## Rejected Hypotheses\n\n");
    for rejected in &report.rejected_hypotheses {
        out.push_str(&format!("{}\n", md_block(rejected)));
    }
    out.push_str("\n## RustyFuzz Jobs Generated\n\n");
    for job in &report.jobs {
        out.push_str(&format!(
            "- id={} objective={}\n",
            md_code(&job.job_id),
            md_code(&job.objective)
        ));
    }
    out.push_str("\n## Foundry PoCs Generated\n\n");
    for poc in &report.foundry_pocs {
        out.push_str(&format!(
            "- path={} generated={}\n",
            md_code(&poc.path.display().to_string()),
            poc.generated
        ));
    }
    out.push_str("\n## Validation Verdicts\n\n");
    for verdict in &report.validation_verdicts {
        out.push_str(&format!(
            "- id={} status={:?} proof={:?} reason={}\n",
            md_code(&verdict.hypothesis_id),
            verdict.status,
            verdict.proof_status,
            md_code(&verdict.reason)
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
                "- id={} status={:?}\n",
                md_code(&verdict.hypothesis_id),
                verdict.status
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
        out.push_str(&format!("{}\n", md_block(step)));
    }
    out
}

fn md_code(value: &str) -> String {
    let delimiter = markdown_delimiter(value);
    let value = value.replace('\r', "&#13;").replace('\n', "&#10;");
    format!("{delimiter} {value} {delimiter}")
}

fn md_block(value: &str) -> String {
    let delimiter = markdown_delimiter(value);
    format!("{delimiter}\n{value}\n{delimiter}")
}

fn markdown_delimiter(value: &str) -> String {
    let mut longest = 0usize;
    let mut current = 0usize;
    for character in value.chars() {
        if character == '`' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    "`".repeat(longest.max(2) + 1)
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

    #[test]
    fn untrusted_markdown_values_are_fenced_or_encoded() {
        let value = "value\n## injected\n```";
        let inline = md_code(value);
        assert!(!inline.contains('\n'));
        assert!(inline.contains("&#10;"));
        let block = md_block(value);
        assert!(block.starts_with("````\n"));
        assert!(block.ends_with("\n````"));
    }
}
