use crate::satori::analysis::criticality::score_function;
use crate::satori::analysis::detectors::detect_in_source;
use crate::satori::types::{
    ContractSummary, ExternalCallSummary, FunctionSummary, ProjectModel, ProtocolType, SourceFile,
    StateAccess,
};
use std::path::PathBuf;

pub fn extract_contracts_and_functions(
    project: &ProjectModel,
) -> (Vec<ContractSummary>, Vec<FunctionSummary>) {
    let mut contracts = Vec::new();
    let mut functions = Vec::new();
    for file in &project.source_files {
        let Some(text) = file.text.as_deref() else {
            continue;
        };
        let file_contracts = extract_contract_names(text);
        for contract in &file_contracts {
            contracts.push(ContractSummary {
                name: contract.clone(),
                file: file.relative_path.clone(),
                protocol_hints: protocol_hints(text),
                functions: Vec::new(),
            });
        }
        for function in extract_functions(file, text, &file_contracts) {
            functions.push(function);
        }
    }
    for contract in &mut contracts {
        contract.functions = functions
            .iter()
            .filter(|function| function.contract == contract.name)
            .map(|function| function.id.clone())
            .collect();
    }
    (contracts, functions)
}

fn extract_contract_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        for keyword in ["contract ", "abstract contract ", "interface ", "library "] {
            if let Some(rest) = trimmed.strip_prefix(keyword) {
                let name = rest
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or_default();
                if !name.is_empty() {
                    names.push(name.to_string());
                }
            }
        }
    }
    if names.is_empty() {
        names.push("UnknownContract".to_string());
    }
    names
}

fn extract_functions(file: &SourceFile, text: &str, contracts: &[String]) -> Vec<FunctionSummary> {
    let mut result = Vec::new();
    let lines = text.lines().collect::<Vec<_>>();
    let contract = contracts
        .first()
        .cloned()
        .unwrap_or_else(|| "UnknownContract".to_string());
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("function ") && !trimmed.starts_with("constructor(") {
            continue;
        }
        let snippet = lines[idx..lines.len().min(idx + 18)].join("\n");
        let signature = signature_from_line(trimmed);
        let name = function_name_from_signature(&signature);
        let detectors = detect_in_snippet(&snippet, file);
        let mut summary = FunctionSummary {
            id: format!("{}::{}", contract, signature),
            contract: contract.clone(),
            name,
            signature,
            selector: None,
            file: file.relative_path.clone(),
            visibility: visibility(trimmed).to_string(),
            mutability: mutability(trimmed).to_string(),
            modifiers: modifiers(trimmed),
            source_snippet: snippet.clone(),
            reads: state_accesses(&snippet, "read"),
            writes: state_accesses(&snippet, "write"),
            internal_calls: Vec::new(),
            external_calls: external_calls(&snippet),
            detector_signals: detectors,
            criticality_score: 0.0,
        };
        summary.criticality_score = score_function(&summary);
        result.push(summary);
    }
    result
}

fn detect_in_snippet(
    snippet: &str,
    file: &SourceFile,
) -> Vec<crate::satori::types::DetectorSignal> {
    let mut copy = file.clone();
    copy.text = Some(snippet.to_string());
    detect_in_source(&copy)
}

fn signature_from_line(line: &str) -> String {
    let header = line.split('{').next().unwrap_or(line).trim();
    if header.starts_with("constructor(") {
        return "constructor()".to_string();
    }
    header
        .strip_prefix("function ")
        .unwrap_or(header)
        .split_whitespace()
        .next()
        .unwrap_or("unknown()")
        .to_string()
}

fn function_name_from_signature(signature: &str) -> String {
    signature
        .split('(')
        .next()
        .unwrap_or(signature)
        .trim()
        .to_string()
}

fn visibility(line: &str) -> &'static str {
    if line.contains(" external") {
        "external"
    } else if line.contains(" public") {
        "public"
    } else if line.contains(" internal") {
        "internal"
    } else if line.contains(" private") {
        "private"
    } else {
        "unknown"
    }
}

fn mutability(line: &str) -> &'static str {
    if line.contains(" view") {
        "view"
    } else if line.contains(" pure") {
        "pure"
    } else if line.contains(" payable") {
        "payable"
    } else {
        "nonpayable"
    }
}

fn modifiers(line: &str) -> Vec<String> {
    [
        "onlyOwner",
        "onlyRole",
        "initializer",
        "reinitializer",
        "nonReentrant",
        "whenNotPaused",
    ]
    .iter()
    .filter(|modifier| line.contains(**modifier))
    .map(|modifier| modifier.to_string())
    .collect()
}

fn state_accesses(snippet: &str, access_type: &str) -> Vec<StateAccess> {
    let lower = snippet.to_ascii_lowercase();
    let names = [
        "balance",
        "shares",
        "totalsupply",
        "totalassets",
        "reserve",
        "debt",
        "collateral",
        "allowance",
        "owner",
        "admin",
    ];
    names
        .iter()
        .filter(|name| lower.contains(**name))
        .map(|name| StateAccess {
            name: name.to_string(),
            access_type: access_type.to_string(),
            evidence: format!("snippet contains `{name}`"),
        })
        .collect()
}

fn external_calls(snippet: &str) -> Vec<ExternalCallSummary> {
    let lower = snippet.to_ascii_lowercase();
    [
        ".call",
        "delegatecall",
        "staticcall",
        "transferfrom",
        "safetransfer",
        "latestrounddata",
    ]
    .iter()
    .filter(|needle| lower.contains(**needle))
    .map(|needle| ExternalCallSummary {
        target: "unknown".to_string(),
        call_type: needle.trim_start_matches('.').to_string(),
        evidence: format!("snippet contains `{needle}`"),
    })
    .collect()
}

fn protocol_hints(text: &str) -> Vec<ProtocolType> {
    let lower = text.to_ascii_lowercase();
    let mut hints = Vec::new();
    if lower.contains("totalassets") || lower.contains("converttoassets") {
        hints.push(ProtocolType::ERC4626Vault);
    }
    if lower.contains("getreserves") || lower.contains("swap") || lower.contains("skim") {
        hints.push(ProtocolType::AMM);
    }
    if lower.contains("borrow") || lower.contains("liquidate") || lower.contains("collateral") {
        hints.push(ProtocolType::LendingMarket);
    }
    if lower.contains("latestanswer") || lower.contains("latestrounddata") {
        hints.push(ProtocolType::Oracle);
    }
    if lower.contains("upgradeto") || lower.contains("initializer") {
        hints.push(ProtocolType::Upgradeability);
    }
    if hints.is_empty() {
        hints.push(ProtocolType::Unknown);
    }
    hints
}

#[allow(dead_code)]
fn _path(path: PathBuf) -> PathBuf {
    path
}
