use crate::satori::types::{FunctionSummary, GraphEdge, SatoriGraph, StaticAnalysisBundle};

pub fn top_critical_functions(
    analysis: &StaticAnalysisBundle,
    limit: usize,
) -> Vec<FunctionSummary> {
    let mut functions = analysis.functions.clone();
    functions.sort_by(|a, b| b.criticality_score.total_cmp(&a.criticality_score));
    functions.truncate(limit);
    functions
}

pub fn neighbors(graph: &SatoriGraph, node_id: &str, depth: usize) -> Vec<GraphEdge> {
    if depth == 0 {
        return Vec::new();
    }
    graph
        .edges
        .iter()
        .filter(|edge| edge.from == node_id || edge.to == node_id)
        .cloned()
        .collect()
}

pub fn contract_functions(analysis: &StaticAnalysisBundle, contract: &str) -> Vec<FunctionSummary> {
    analysis
        .functions
        .iter()
        .filter(|function| function.contract == contract)
        .cloned()
        .collect()
}

pub fn functions_touching_state_var(
    analysis: &StaticAnalysisBundle,
    var: &str,
) -> Vec<FunctionSummary> {
    analysis
        .functions
        .iter()
        .filter(|function| {
            function
                .reads
                .iter()
                .chain(function.writes.iter())
                .any(|access| access.name.contains(var))
        })
        .cloned()
        .collect()
}

pub fn functions_with_external_calls(analysis: &StaticAnalysisBundle) -> Vec<FunctionSummary> {
    analysis
        .functions
        .iter()
        .filter(|function| !function.external_calls.is_empty())
        .cloned()
        .collect()
}

pub fn functions_using_oracles(analysis: &StaticAnalysisBundle) -> Vec<FunctionSummary> {
    analysis
        .functions
        .iter()
        .filter(|function| {
            function
                .detector_signals
                .iter()
                .any(|signal| signal.tag == "oracle-read")
        })
        .cloned()
        .collect()
}

pub fn functions_moving_tokens(analysis: &StaticAnalysisBundle) -> Vec<FunctionSummary> {
    analysis
        .functions
        .iter()
        .filter(|function| {
            function
                .detector_signals
                .iter()
                .any(|signal| signal.tag == "token-transfer")
        })
        .cloned()
        .collect()
}

pub fn related_functions(
    analysis: &StaticAnalysisBundle,
    function: &FunctionSummary,
) -> Vec<FunctionSummary> {
    analysis
        .functions
        .iter()
        .filter(|candidate| {
            candidate.contract == function.contract
                && candidate.id != function.id
                && candidate
                    .reads
                    .iter()
                    .chain(candidate.writes.iter())
                    .any(|access| {
                        function
                            .reads
                            .iter()
                            .chain(function.writes.iter())
                            .any(|other| other.name == access.name)
                    })
        })
        .take(8)
        .cloned()
        .collect()
}
