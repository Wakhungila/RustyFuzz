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
        notes: vec![
            "Scaffold generated with automatic bindings from hypothesis.".to_string(),
            format!(
                "Target contract: {:?}",
                hypothesis
                    .affected_contracts
                    .first()
                    .unwrap_or(&"UNKNOWN".to_string())
            ),
            format!("Bug class: {}", hypothesis.bug_class),
        ],
    })
}

fn render_poc(hypothesis: &VulnerabilityHypothesis, job: Option<&RustyFuzzJobSpec>) -> String {
    let steps = hypothesis
        .attack_sequence
        .iter()
        .enumerate()
        .map(|(idx, step)| {
            let target = step
                .target
                .as_ref()
                .map(|t| format!("{:?}", t))
                .unwrap_or_else(|| "address(0)".to_string());
            let calldata = step
                .calldata_hint
                .as_ref()
                .map(|c| format!("{:?}", c))
                .unwrap_or_else(|| "hex\"\"".to_string());
            format!(
                "        // {}. actor={} action={} target={} calldata={}",
                idx + 1,
                step.actor,
                step.action,
                target,
                calldata
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

    let target_contract = hypothesis
        .affected_contracts
        .first()
        .map(|s| s.as_str())
        .unwrap_or("TargetContract");
    let contract_name = sanitize(&hypothesis.id).replace('-', "_");

    // Generate automatic bindings based on hypothesis data
    let bindings = generate_automatic_bindings(hypothesis);

    format!(
        r#"// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

{job_note}// Satori hypothesis: {id}
// Bug class: {bug_class}
// Title: {title}
// Target contract: {target}
// This scaffold includes automatic bindings from hypothesis data.
contract Satori_{contract_name}_PoC is Test {{
    {target} target;
    
    function setUp() public {{
        // Automatic bindings from hypothesis
{bindings}
    }}

    function test_satori_hypothesis() public {{
{steps}
{invariants}
        // Required assertion style:
        // - compare before/after balances, shares, debt, reserves, or role-sensitive state.
        // - fail only when deterministic local evidence proves the hypothesis.
        assertTrue(true, "Satori scaffold generated; add target-specific assertions");
    }}
}}
"#,
        id = hypothesis.id,
        bug_class = hypothesis.bug_class,
        title = hypothesis.title,
        target = target_contract,
        contract_name = contract_name,
        bindings = bindings,
        steps = steps,
        invariants = invariants,
        job_note = job_note,
    )
}

fn generate_automatic_bindings(hypothesis: &VulnerabilityHypothesis) -> String {
    let mut bindings = String::new();

    // Add target contract deployment
    if let Some(target) = hypothesis.affected_contracts.first() {
        bindings.push_str(&format!("        target = {}(targetAddress);\n", target));
    } else {
        bindings.push_str("        target = new TargetContract();\n");
    }

    // Add actor address bindings if available
    let mut actors = std::collections::HashSet::new();
    for step in &hypothesis.attack_sequence {
        actors.insert(&step.actor);
    }

    for actor in actors {
        bindings.push_str(&format!(
            "        address {} = address({:?});\n",
            sanitize(actor),
            actor
        ));
    }

    // Add fork setup if hypothesis suggests it
    if hypothesis
        .attack_sequence
        .iter()
        .any(|s| s.action.contains("fork") || s.action.contains("mainnet"))
    {
        bindings.push_str("        vm.createSelectFork(\"mainnet_rpc_url\");\n");
    }

    bindings
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
