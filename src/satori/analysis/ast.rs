use crate::satori::analysis::criticality::score_function;
use crate::satori::analysis::detectors::detect_in_source;
use crate::satori::fsutil::redact_source_text;
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
        let raw_snippet = lines[idx..lines.len().min(idx + 18)].join("\n");
        let snippet = redact_source_text(&raw_snippet);
        // A parameter list may span several lines; keep joining until the
        // parentheses balance so the signature is never cut short.
        let mut header = trimmed.to_string();
        let mut end = idx;
        while paren_depth(&header) > 0 && end + 1 < lines.len() {
            end += 1;
            header.push(' ');
            header.push_str(lines[end].trim());
        }
        let signature = signature_from_header(&header);
        let name = function_name_from_signature(&signature);
        let selector = selector_for_signature(&signature);
        let detectors = detect_in_snippet(&raw_snippet, file);
        let mut summary = FunctionSummary {
            id: format!("{}::{}", contract, signature),
            contract: contract.clone(),
            name,
            signature,
            selector,
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

/// Net parenthesis depth of a header fragment.
fn paren_depth(text: &str) -> i32 {
    let mut depth = 0i32;
    for character in text.chars() {
        match character {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// Index of the parenthesis matching the one at `open`.
fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extracts the canonical Solidity signature of a function declaration.
///
/// The signature is the part a 4-byte selector is derived from, so it must
/// carry the complete parameter *types*: `approve(address,uint256)`, never
/// `approve(address`. Parameter names, storage locations and `indexed` are
/// dropped, and the `uint`/`int` aliases are widened to their canonical form.
fn signature_from_header(header: &str) -> String {
    let header = header.split('{').next().unwrap_or(header).trim();
    if header.starts_with("constructor(") {
        return "constructor()".to_string();
    }
    let rest = header.strip_prefix("function ").unwrap_or(header);
    let Some(open) = rest.find('(') else {
        return rest
            .split_whitespace()
            .next()
            .unwrap_or("unknown()")
            .to_string();
    };
    let Some(close) = matching_paren(rest, open) else {
        return "unknown()".to_string();
    };
    let name = rest[..open].trim();
    if name.is_empty() {
        return "unknown()".to_string();
    }
    let parameters = canonical_parameters(&rest[open + 1..close]);
    format!("{name}({parameters})")
}

/// Canonicalises a parameter list into comma-separated ABI types.
fn canonical_parameters(parameters: &str) -> String {
    split_top_level(parameters, ',')
        .iter()
        .map(|parameter| canonical_parameter_type(parameter))
        .filter(|parameter| !parameter.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// Canonical ABI type of a single parameter declaration.
fn canonical_parameter_type(parameter: &str) -> String {
    let cleaned = strip_parameter_noise(parameter);
    if cleaned.is_empty() {
        return String::new();
    }
    // `mapping(address => uint256) balances`: the type ends with the mapping
    // expression; the trailing identifier is the parameter name.
    if let Some(open) = cleaned.find('(') {
        if cleaned[..open].trim_end().ends_with("mapping") {
            if let Some(close) = matching_paren(&cleaned, open) {
                let mapping = cleaned[..=close].replace(' ', "");
                return widen_builtin_alias(&mapping);
            }
        }
    }
    // Tuple parameter: `(address owner, uint256 amount) vault`.
    if cleaned.starts_with('(') {
        if let Some(close) = matching_paren(&cleaned, 0) {
            let tuple = &cleaned[1..close];
            let inner = canonical_parameters(tuple);
            if inner.is_empty() {
                return String::new();
            }
            return format!("({inner})");
        }
    }
    let tokens = cleaned.split_whitespace().collect::<Vec<_>>();
    // The last token is the parameter name unless the declaration only
    // carries a type.
    let type_tokens = if tokens.len() > 1 {
        &tokens[..tokens.len() - 1]
    } else {
        &tokens[..]
    };
    let type_text = type_tokens.join("").replace(' ', "");
    widen_builtin_alias(&type_text)
}

/// Removes storage-location and data-location keywords from a declaration.
fn strip_parameter_noise(parameter: &str) -> String {
    let mut out = String::new();
    for token in parameter.split_whitespace() {
        if matches!(
            token,
            "memory" | "calldata" | "storage" | "indexed" | "payable"
        ) {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
    }
    out
}

/// Widens the `uint`/`int` aliases to their canonical ABI spelling.
fn widen_builtin_alias(type_text: &str) -> String {
    let mut out = String::with_capacity(type_text.len());
    let mut rest = type_text;
    while let Some(index) = rest.find("uint") {
        let (before, after) = rest.split_at(index);
        out.push_str(before);
        let tail = &after[4..];
        let digits = tail
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .count();
        if digits == 0 {
            out.push_str("uint256");
        } else {
            out.push_str("uint");
            out.push_str(&tail[..digits]);
        }
        rest = &tail[digits..];
    }
    out.push_str(rest);

    let mut widened = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(index) = rest.find("int") {
        let (before, after) = rest.split_at(index);
        widened.push_str(before);
        let tail = &after[3..];
        let digits = tail
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .count();
        if digits == 0 {
            widened.push_str("int256");
        } else {
            widened.push_str("int");
            widened.push_str(&tail[..digits]);
        }
        rest = &tail[digits..];
    }
    widened.push_str(rest);
    widened
}

/// Splits on `separator`, ignoring separators nested in parentheses.
fn split_top_level(text: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for character in text.chars() {
        match character {
            '(' => {
                depth += 1;
                current.push(character);
            }
            ')' => {
                depth -= 1;
                current.push(character);
            }
            _ if character == separator && depth == 0 => {
                parts.push(current.trim().to_string());
                current = String::new();
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

/// 4-byte selector of a canonical signature, as `0x` + 8 hex characters.
fn selector_for_signature(signature: &str) -> Option<String> {
    if signature.is_empty() || signature == "unknown()" {
        return None;
    }
    let hash = rustyfuzz_evm::keccak256(signature.as_bytes());
    Some(format!("0x{}", hex::encode(&hash[..4])))
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn function_snippets_redact_source_secrets_before_analysis_output() {
        let file = SourceFile {
            path: PathBuf::from("Vault.sol"),
            relative_path: PathBuf::from("Vault.sol"),
            language: "solidity".to_string(),
            content_hash: "x".to_string(),
            bytes: 1,
            text: Some(
                "contract Vault {\n    function deposit() external {\n        string private_key = \"source-secret\";\n    }\n}"
                    .to_string(),
            ),
        };
        let (contracts, functions) = extract_contracts_and_functions(&ProjectModel {
            root: PathBuf::from("."),
            project_type: crate::satori::types::ProjectType::Solidity,
            source_files: vec![file],
            test_files: Vec::new(),
            docs: Vec::new(),
            foundry_toml: None,
            hardhat_config: None,
            package_json: None,
            remappings: None,
            detected_protocols: Vec::new(),
        });
        assert_eq!(contracts.len(), 1);
        assert_eq!(functions.len(), 1);
        assert!(!functions[0].source_snippet.contains("source-secret"));
        assert!(functions[0].source_snippet.contains("<redacted>"));
    }

    fn summarize(source: &str) -> Vec<FunctionSummary> {
        let file = SourceFile {
            path: PathBuf::from("Vault.sol"),
            relative_path: PathBuf::from("Vault.sol"),
            language: "solidity".to_string(),
            content_hash: "x".to_string(),
            bytes: 1,
            text: Some(source.to_string()),
        };
        let (_, functions) = extract_contracts_and_functions(&ProjectModel {
            root: PathBuf::from("."),
            project_type: crate::satori::types::ProjectType::Solidity,
            source_files: vec![file],
            test_files: Vec::new(),
            docs: Vec::new(),
            foundry_toml: None,
            hardhat_config: None,
            package_json: None,
            remappings: None,
            detected_protocols: Vec::new(),
        });
        functions
    }

    #[test]
    fn signature_keeps_the_full_parameter_list() {
        let functions = summarize(
            "contract Vault {\n\
             \x20   function approve(address spender, uint256 amount) external returns (bool) {\n\
             \x20       return true;\n\
             \x20   }\n\
             }\n",
        );
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].signature, "approve(address,uint256)");
        assert_eq!(functions[0].name, "approve");
    }

    #[test]
    fn signature_spanning_multiple_lines_is_not_truncated() {
        let functions = summarize(
            "contract Vault {\n\
             \x20   function addCollateral(\n\
             \x20       address token,\n\
             \x20       uint256 amount\n\
             \x20   ) external {\n\
             \x20   }\n\
             }\n",
        );
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].signature, "addCollateral(address,uint256)");
    }

    #[test]
    fn signature_drops_parameter_names_and_storage_locations() {
        let functions = summarize(
            "contract Vault {\n\
             \x20   function store(bytes calldata data, bool flag) external {}\n\
             \x20   function widen(uint amount, int delta) external {}\n\
             \x20   function table(mapping(address => uint256) balances) external {}\n\
             }\n",
        );
        let signatures = functions
            .iter()
            .map(|function| function.signature.as_str())
            .collect::<Vec<_>>();
        assert!(signatures.contains(&"store(bytes,bool)"), "{signatures:?}");
        assert!(
            signatures.contains(&"widen(uint256,int256)"),
            "{signatures:?}"
        );
        assert!(
            signatures.contains(&"table(mapping(address=>uint256))"),
            "{signatures:?}"
        );
    }

    #[test]
    fn selector_matches_the_known_approve_selector() {
        let functions = summarize(
            "contract Vault {\n\
             \x20   function approve(address spender, uint256 amount) external {}\n\
             }\n",
        );
        // keccak256("approve(address,uint256)")[..4] == 0x095ea7b3
        assert_eq!(functions[0].selector.as_deref(), Some("0x095ea7b3"));
    }

    #[test]
    fn selector_is_absent_for_unparseable_declarations() {
        let functions = summarize("contract Vault {\n    function broken(\n}\n");
        assert!(functions[0].selector.is_none());
    }
}
