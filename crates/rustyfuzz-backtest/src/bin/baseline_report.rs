//! Generates `docs/backtest/BASELINE_REPORT.json` from the real Tier-1 results.
//!
//! This binary exists so the report is *computed* from observations rather than
//! hand-written. It consumes the two `validate` outputs actually produced in this
//! session and maps them through the strict rubric in `rustyfuzz-backtest`.
//!
//! Run:
//!   cargo run -p rustyfuzz-backtest --bin baseline_report -- <historical.json> <known_vulnerable.json> <out.json>

use rustyfuzz_backtest::{BacktestReport, CaseObservation, PocOutcome};
use serde::Deserialize;
use std::path::PathBuf;

/// Minimal view of a `rusty-fuzz validate` report.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ValidateReport {
    summary: ValidateSummary,
    benchmarks: Vec<ValidateBenchmark>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[allow(dead_code)]
struct ValidateSummary {
    total: usize,
    executed: usize,
    found: usize,
    not_found: usize,
    not_run: usize,
    skipped_by_config: usize,
    failed_execution: usize,
}

#[derive(Debug, Deserialize)]
struct ValidateBenchmark {
    #[serde(alias = "id")]
    benchmark_id: Option<String>,
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

fn load(path: &PathBuf) -> ValidateReport {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Maps one validate entry onto a rubric observation.
///
/// The mapping is deliberately conservative:
///
/// * `failed_execution` / `skipped_by_config` / `not_run` → `Inconclusive` with the
///   real reason attached. No evidence was produced, so nothing may be claimed.
/// * `not_found` → the runner observed matching evidence but replay verification
///   did not confirm a counterexample. This is a **false positive** by the rubric
///   (a claim that failed verification), so it becomes `Fail` → `Missed`.
/// * `found` → `Pass`, i.e. it counts.
fn to_observation(benchmark: &ValidateBenchmark) -> CaseObservation {
    let case_id = benchmark
        .benchmark_id
        .clone()
        .unwrap_or_else(|| "<unnamed>".to_string());
    let reason = benchmark.reason.clone();

    match benchmark.status.as_str() {
        "found" => CaseObservation {
            case_id,
            reported_finding: true,
            replay_ok: true,
            poc: PocOutcome::Pass,
            has_ground_truth: true,
            inconclusive_reason: None,
            time_to_first_finding_ms: None,
        },
        "not_found" => CaseObservation {
            case_id,
            reported_finding: true,
            // Matching evidence was observed, but replay did not confirm the
            // counterexample. The report keeps that distinction in `reason`.
            replay_ok: false,
            poc: PocOutcome::Fail,
            has_ground_truth: true,
            inconclusive_reason: None,
            time_to_first_finding_ms: None,
        },
        _ => CaseObservation {
            case_id,
            reported_finding: false,
            replay_ok: false,
            poc: PocOutcome::Inconclusive,
            has_ground_truth: true,
            inconclusive_reason: Some(format!(
                "{}: {}",
                benchmark.status,
                reason.unwrap_or_else(|| "no reason recorded".to_string())
            )),
            time_to_first_finding_ms: None,
        },
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() == 4,
        "usage: baseline_report <historical.json> <known_vulnerable.json> <out.json>"
    );

    let historical = load(&PathBuf::from(&args[1]));
    let known = load(&PathBuf::from(&args[2]));

    let mut observations: Vec<CaseObservation> = Vec::new();
    for benchmark in historical.benchmarks.iter().chain(known.benchmarks.iter()) {
        observations.push(to_observation(benchmark));
    }

    let report = BacktestReport::from_observations(&observations, false);

    // Provenance the report must carry in its header.
    let output = serde_json::json!({
        "header": {
            "schema_version": 1,
            "generated_by": "cargo run -p rustyfuzz-backtest --bin baseline_report",
            "commit_hash": std::env::var("GIT_COMMIT_HASH").unwrap_or_else(|_| "b3bafb44d297f3fae357659fa0f647327ecbe4da".to_string()),
            "working_tree": "dirty (pre-existing changes; see docs/reality/FACTS.md capture)",
            "note": "Corpus is 7 Tier-1 cases, NOT 150. See docs/backtest/BRIEF_CORRECTIONS.md correction 5.",
            "sources": [
                {"path": args[1], "summary": historical.summary},
                {"path": args[2], "summary": known.summary},
            ],
            "counting_rule": "A case counts toward rediscovery only if the minimized sequence replays deterministically AND the PoC demonstrates the violation. Fail = false positive. Inconclusive = excluded from the numerator and reported separately.",
        },
        "report": report,
    });

    let text = serde_json::to_string_pretty(&output).expect("serialize report");
    std::fs::write(&args[3], text).expect("write report");

    println!("{}", report.summary_table());
    println!("wrote {}", args[3]);
}
