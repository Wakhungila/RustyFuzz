use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{
    canonical_run_dir_path, ensure_dir, reject_symlink_components, sha256_hex, write_text_in_run,
};
use crate::satori::types::{FoundryPocSpec, RustyFuzzJobSpec, VulnerabilityHypothesis};
use serde::Serialize;
use std::path::Path;
use uuid::Uuid;

const MAX_HYPOTHESIS_DATA_BYTES: usize = 16_384;

#[derive(Serialize)]
struct PocSummary {
    hypothesis_ref: String,
    bug_class: String,
    confidence_before_validation: f64,
    evidence_count: usize,
    attack_step_count: usize,
    validation_step_count: usize,
}

pub fn generate_foundry_poc(
    project_root: &Path,
    run_dir: &Path,
    hypothesis: &VulnerabilityHypothesis,
    job: Option<&RustyFuzzJobSpec>,
) -> SatoriResult<FoundryPocSpec> {
    reject_symlink_components(project_root)?;
    let _project_root = project_root.canonicalize()?;
    let run_dir = canonical_run_dir_path(run_dir)?;
    let hypothesis_ref = format!("hypothesis-{}", &sha256_hex(hypothesis.id.as_bytes())[..16]);
    let file_name = format!(
        "{}-{}-{}",
        sanitize(&hypothesis_ref),
        &sha256_hex(hypothesis_ref.as_bytes())[..16],
        Uuid::new_v4().simple()
    );
    let path = run_dir
        .join("foundry_poc")
        .join(format!("{file_name}.t.sol"));
    ensure_dir(path.parent().expect("PoC path has a parent"))?;
    let content = render_poc(hypothesis, job)?;
    write_text_in_run(
        &run_dir,
        Path::new("foundry_poc")
            .join(format!("{file_name}.t.sol"))
            .as_path(),
        &content,
    )?;
    let canonical_path = path.canonicalize()?;
    let report_path = canonical_path
        .strip_prefix(&run_dir)
        .map_err(|_| anyhow::anyhow!("generated Foundry PoC escaped the Satori run directory"))?
        .to_path_buf();
    Ok(FoundryPocSpec {
        hypothesis_id: hypothesis_ref,
        path: report_path,
        generated: true,
        compile_attempted: false,
        compile_success: false,
        notes: vec![
            "Scaffold generated from a fixed template; only bounded non-secret metadata is embedded."
                .to_string(),
            "Target and actor addresses are intentionally fixed placeholders for manual binding."
                .to_string(),
            format!("Bug class: {}", safe_bug_class(&hypothesis.bug_class)),
        ],
    })
}

fn render_poc(
    hypothesis: &VulnerabilityHypothesis,
    _job: Option<&RustyFuzzJobSpec>,
) -> SatoriResult<String> {
    let summary = PocSummary {
        hypothesis_ref: format!("hypothesis-{}", &sha256_hex(hypothesis.id.as_bytes())[..16]),
        bug_class: safe_bug_class(&hypothesis.bug_class),
        confidence_before_validation: hypothesis.confidence_before_validation,
        evidence_count: hypothesis.evidence_from_context.len(),
        attack_step_count: hypothesis.attack_sequence.len(),
        validation_step_count: hypothesis.validation_plan.len(),
    };
    let hypothesis_data = serde_json::to_string(&summary)?;
    if hypothesis_data.len() > MAX_HYPOTHESIS_DATA_BYTES {
        anyhow::bail!("hypothesis summary exceeds the fixed PoC data limit");
    }
    let escaped_data = escape_sol_string(&hypothesis_data)?;
    Ok(format!(
        r#"// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract SatoriPoC is Test {{
    address internal targetAddress;
    address internal actorAddress;
    bytes internal stepCalldata;
    string internal hypothesisData;

    function setUp() public {{
        targetAddress = address(0);
        actorAddress = address(0);
        stepCalldata = hex"";
        hypothesisData = "{escaped_data}";
    }}

    function test_satori_hypothesis() public pure {{}}
}}
"#
    ))
}

fn safe_bug_class(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let normalized = lower
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();
    if [
        "privatekey",
        "secret",
        "token",
        "password",
        "apikey",
        "bearer",
        "mnemonic",
        "seedphrase",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
    {
        return "redacted".to_string();
    }
    let sanitized = lower
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .take(64)
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn escape_sol_string(value: &str) -> SatoriResult<String> {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_ascii_graphic() || character == ' ' => {
                escaped.push(character);
            }
            _ => anyhow::bail!("hypothesis data contains unsupported control or non-ASCII text"),
        }
    }
    Ok(escaped)
}

fn sanitize(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    if sanitized.is_empty() {
        "hypothesis".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::{AttackStep, CandidateInvariant, ValidationStep};

    fn malicious_hypothesis() -> VulnerabilityHypothesis {
        VulnerabilityHypothesis {
            id: "malicious".to_string(),
            title: "\"; } contract Injected { function".to_string(),
            bug_class: "access_control\"; import".to_string(),
            root_cause: "line\ncomment".to_string(),
            affected_contracts: vec!["0x0000000000000000000000000000000000000001".to_string()],
            affected_functions: vec!["withdraw()".to_string()],
            evidence_from_context: vec!["public withdraw".to_string()],
            required_conditions: Vec::new(),
            attack_sequence: vec![AttackStep {
                actor: "attacker".to_string(),
                action: "withdraw".to_string(),
                target: Some("Vault".to_string()),
                calldata_hint: Some("0xdeadbeef".to_string()),
                value_hint: Some("1".to_string()),
            }],
            false_positive_checks: Vec::new(),
            validation_plan: vec![ValidationStep {
                tool: "foundry".to_string(),
                action: "compile".to_string(),
                success_condition: "x".to_string(),
            }],
            suggested_invariants: vec![CandidateInvariant {
                id: "i1".to_string(),
                description: "no unauthorized withdraw".to_string(),
                check: "attacker balance does not increase".to_string(),
                expected_signal: "revert".to_string(),
            }],
            rustyfuzz_objective: "maximize profit".to_string(),
            confidence_before_validation: 0.4,
        }
    }

    #[test]
    fn malicious_model_text_remains_data_only() -> SatoriResult<()> {
        let content = render_poc(&malicious_hypothesis(), None)?;
        assert!(content.contains("contract SatoriPoC is Test"));
        assert!(content.contains("hypothesisData = \""));
        assert!(!content
            .lines()
            .any(|line| line.trim_start().starts_with("contract Injected")));
        assert!(!content.contains("import \";"));
        assert!(!content.contains("assertTrue(false"));
        Ok(())
    }

    #[test]
    fn fixed_template_has_no_model_derived_type_or_identifier() -> SatoriResult<()> {
        let content = render_poc(&malicious_hypothesis(), None)?;
        assert!(content.contains("address internal targetAddress;"));
        assert!(content.contains("address internal actorAddress;"));
        assert!(!content.contains("malicious Vault"));
        assert!(!content.contains("address attacker"));
        Ok(())
    }

    #[test]
    fn generated_poc_contains_only_bounded_summary_fields() -> SatoriResult<()> {
        let mut hypothesis = malicious_hypothesis();
        hypothesis.bug_class = "api_key=secret-value".to_string();
        hypothesis.rustyfuzz_objective = "private key exfiltration".to_string();
        let content = render_poc(&hypothesis, None)?;
        assert!(content.contains("hypothesis-"));
        assert!(content.contains("bug_class"));
        assert!(content.contains("redacted"));
        assert!(!content.contains("api_key=secret-value"));
        assert!(!content.contains("private key exfiltration"));
        assert!(!content.contains("line\\ncomment"));
        assert!(!content.contains("withdraw()"));
        let encoded = content
            .lines()
            .find_map(|line| line.strip_prefix("        hypothesisData = \""))
            .and_then(|line| line.strip_suffix("\";"))
            .expect("PoC summary assignment");
        let encoded: String = serde_json::from_str(&format!("\"{encoded}\""))?;
        let summary: serde_json::Value = serde_json::from_str(&encoded)?;
        let keys = summary
            .as_object()
            .expect("PoC summary object")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            [
                "attack_step_count",
                "bug_class",
                "confidence_before_validation",
                "evidence_count",
                "hypothesis_ref",
                "validation_step_count",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>()
        );
        Ok(())
    }

    #[test]
    fn generated_poc_names_are_non_empty_and_collision_resistant() -> SatoriResult<()> {
        let root = std::env::temp_dir().join(format!(
            "satori-poc-name-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let run_dir = crate::satori::fsutil::canonical_run_root()
            .unwrap()
            .join("satori-poc-name-test");
        let _ = std::fs::remove_dir_all(&run_dir);
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&run_dir)?;
        let first = generate_foundry_poc(&root, &run_dir, &malicious_hypothesis(), None)?;
        let second = generate_foundry_poc(&root, &run_dir, &malicious_hypothesis(), None)?;
        assert_ne!(first.path, second.path);
        assert!(first.path.extension().is_some());
        assert!(first.path.starts_with("foundry_poc"));
        assert!(run_dir.join(&first.path).is_file());
        assert!(first
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| !name.is_empty()));
        let _ = std::fs::remove_dir_all(&run_dir);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
