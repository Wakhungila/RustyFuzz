pub mod ast;
pub mod criticality;
pub mod detectors;
pub mod foundry;
pub mod slither;
pub mod storage;

use crate::satori::analysis::ast::extract_contracts_and_functions;
use crate::satori::analysis::detectors::detect_in_project;
use crate::satori::analysis::foundry::run_foundry_tools;
use crate::satori::analysis::slither::run_slither_tool;
use crate::satori::error::SatoriResult;
use crate::satori::fsutil::write_json_in_run;
use crate::satori::types::{ProjectModel, StaticAnalysisBundle};
use std::path::Path;

pub fn analyze_project(
    project: &ProjectModel,
    run_dir: &Path,
    allow_foundry: bool,
    allow_slither: bool,
) -> SatoriResult<StaticAnalysisBundle> {
    let mut bundle = StaticAnalysisBundle::default();
    bundle
        .tool_runs
        .extend(run_foundry_tools(project, run_dir, allow_foundry)?);
    bundle
        .tool_runs
        .push(run_slither_tool(project, run_dir, allow_slither)?);
    let (contracts, functions) = extract_contracts_and_functions(project);
    bundle.contracts = contracts;
    bundle.functions = functions;
    bundle.detector_signals = detect_in_project(project);
    write_json_in_run(run_dir, Path::new("static_analysis.json"), &bundle)?;

    let mut critical = bundle.functions.clone();
    critical.sort_by(|a, b| b.criticality_score.total_cmp(&a.criticality_score));
    write_json_in_run(run_dir, Path::new("critical_functions.json"), &critical)?;
    Ok(bundle)
}
