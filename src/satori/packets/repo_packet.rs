use crate::satori::error::SatoriResult;
use crate::satori::fsutil::write_json_in_run;
use crate::satori::graph::query::top_critical_functions;
use crate::satori::ingest::docs::summarize_docs;
use crate::satori::packets::function_packet::{bug_class_library, redact_function_summary};
use crate::satori::types::{ProjectModel, RepoPacket, SatoriGraph, StaticAnalysisBundle};
use std::collections::BTreeMap;
use std::path::Path;

pub fn build_repo_packet(
    project: &ProjectModel,
    analysis: &StaticAnalysisBundle,
    graph: &SatoriGraph,
    run_dir: &Path,
) -> SatoriResult<RepoPacket> {
    let packet = RepoPacket {
        project_type: project.project_type.clone(),
        docs_summary: summarize_docs(&project.docs),
        contracts: analysis.contracts.clone(),
        critical_functions: top_critical_functions(analysis, 16)
            .into_iter()
            .map(redact_function_summary)
            .collect(),
        tool_runs: analysis.tool_runs.clone(),
        graph_stats: BTreeMap::from([
            ("nodes".to_string(), graph.nodes.len()),
            ("edges".to_string(), graph.edges.len()),
        ]),
        detected_protocol_hints: project.detected_protocols.clone(),
        top_bug_class_hints: bug_class_library(),
    };
    write_json_in_run(run_dir, Path::new("packets/repo_packet.json"), &packet)?;
    Ok(packet)
}
