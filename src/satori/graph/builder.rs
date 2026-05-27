use crate::satori::error::SatoriResult;
use crate::satori::fsutil::write_json;
use crate::satori::types::{GraphEdge, GraphNode, ProjectModel, SatoriGraph, StaticAnalysisBundle};
use std::collections::BTreeMap;
use std::path::Path;

pub fn build_graph(
    project: &ProjectModel,
    analysis: &StaticAnalysisBundle,
    run_dir: &Path,
) -> SatoriResult<SatoriGraph> {
    let mut graph = SatoriGraph::default();
    for file in &project.source_files {
        graph.nodes.push(GraphNode {
            id: format!("file:{}", file.relative_path.display()),
            kind: "SourceFile".to_string(),
            label: file.relative_path.display().to_string(),
            metadata: BTreeMap::from([("language".to_string(), file.language.clone())]),
        });
    }
    for contract in &analysis.contracts {
        graph.nodes.push(GraphNode {
            id: format!("contract:{}", contract.name),
            kind: "Contract".to_string(),
            label: contract.name.clone(),
            metadata: BTreeMap::new(),
        });
        graph.edges.push(GraphEdge {
            from: format!("file:{}", contract.file.display()),
            to: format!("contract:{}", contract.name),
            kind: "DEFINES".to_string(),
            evidence: "source extraction".to_string(),
        });
    }
    for function in &analysis.functions {
        graph.nodes.push(GraphNode {
            id: format!("function:{}", function.id),
            kind: "Function".to_string(),
            label: function.signature.clone(),
            metadata: BTreeMap::from([(
                "criticality".to_string(),
                format!("{:.3}", function.criticality_score),
            )]),
        });
        graph.edges.push(GraphEdge {
            from: format!("contract:{}", function.contract),
            to: format!("function:{}", function.id),
            kind: "DEFINES".to_string(),
            evidence: "source extraction".to_string(),
        });
        for signal in &function.detector_signals {
            let kind = match signal.tag.as_str() {
                "token-transfer" => "TRANSFERS_TOKEN",
                "oracle-read" => "USES_ORACLE",
                "access-control" => "CHECKS_ROLE",
                "low-level-call" => "CAN_REENTER",
                _ => "DEPENDS_ON",
            };
            graph.edges.push(GraphEdge {
                from: format!("function:{}", function.id),
                to: format!("signal:{}:{}", signal.detector, function.id),
                kind: kind.to_string(),
                evidence: signal.evidence.clone(),
            });
        }
    }
    write_json(run_dir.join("graph.json"), &graph)?;
    Ok(graph)
}
