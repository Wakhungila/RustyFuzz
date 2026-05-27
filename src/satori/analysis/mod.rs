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
use crate::satori::fsutil::write_json;
use crate::satori::types::{ProjectModel, StaticAnalysisBundle};
use std::path::Path;

pub fn analyze_project(
    project: &ProjectModel,
    run_dir: &Path,
) -> SatoriResult<StaticAnalysisBundle> {
    let mut bundle = StaticAnalysisBundle::default();
    bundle
        .tool_runs
        .extend(run_foundry_tools(project, run_dir)?);
    bundle.tool_runs.push(run_slither_tool(project, run_dir)?);
    let (contracts, functions) = extract_contracts_and_functions(project);
    bundle.contracts = contracts;
    bundle.functions = functions;
    bundle.detector_signals = detect_in_project(project);
    write_json(run_dir.join("static_analysis.json"), &bundle)?;

    let mut critical = bundle.functions.clone();
    critical.sort_by(|a, b| b.criticality_score.total_cmp(&a.criticality_score));
    write_json(run_dir.join("critical_functions.json"), &critical)?;
    Ok(bundle)
}
