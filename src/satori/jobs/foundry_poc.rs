use crate::satori::error::SatoriResult;
use crate::satori::fsutil::write_text;
use crate::satori::types::{FoundryPocSpec, RustyFuzzJobSpec, VulnerabilityHypothesis};
use std::path::Path;

pub fn generate_foundry_poc(
    run_dir: &Path,
    hypothesis: &VulnerabilityHypothesis,
    job: Option<&RustyFuzzJobSpec>,
) -> SatoriResult<FoundryPocSpec> {
    let file_name = sanitize(&hypothesis.id);
    let path = run_dir
        .join("foundry_poc")
        .join(format!("{file_name}.t.sol"));
    let content = render_poc(hypothesis, job);
    write_text(&path, &content)?;
    Ok(FoundryPocSpec {
        hypothesis_id: hypothesis.id.clone(),
        path,
        generated: true,
        compile_attempted: false,
        compile_success: false,
        notes: vec!["Scaffold generated. Manual target bindings may be required.".to_string()],
    })
}

fn render_poc(hypothesis: &VulnerabilityHypothesis, job: Option<&RustyFuzzJobSpec>) -> String {
    let steps = hypothesis
        .attack_sequence
        .iter()
        .enumerate()
        .map(|(idx, step)| {
            format!(
                "        // {}. actor={} action={} target={:?} calldata_hint={:?}",
                idx + 1,
                step.actor,
                step.action,
                step.target,
                step.calldata_hint
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let invariants = hypothesis
        .suggested_invariants
        .iter()
        .map(|inv| format!("        // invariant {}: {}", inv.id, inv.description))
        .collect::<Vec<_>>()
        .join("\n");
    let job_note = job
        .map(|job| format!("// RustyFuzz job: {}\n", job.job_id))
        .unwrap_or_default();
    format!(
        r#"// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

{job_note}// Satori hypothesis: {id}
// Bug class: {bug_class}
// Title: {title}
// This scaffold is not a confirmed finding. Bind real target contracts and assert local replay evidence.
contract Satori_{contract_name}_PoC is Test {{
    function setUp() public {{
        // TODO: bind fork/local fixtures and actor labels.
    }}

    function test_satori_hypothesis_requires_manual_bindings() public {{
{steps}
{invariants}
        // Required assertion style:
        // - compare before/after balances, shares, debt, reserves, or role-sensitive state.
        // - fail only when deterministic local evidence proves the hypothesis.
        assertTrue(true, "Satori scaffold generated; bind target-specific assertions");
    }}
}}
"#,
        id = hypothesis.id,
        bug_class = hypothesis.bug_class,
        title = hypothesis.title,
        contract_name = sanitize(&hypothesis.id).replace('-', "_"),
        steps = steps,
        invariants = invariants,
        job_note = job_note,
    )
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
