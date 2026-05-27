use crate::satori::types::{DetectorSignal, ProjectModel, SourceFile};

pub fn detect_in_project(project: &ProjectModel) -> Vec<DetectorSignal> {
    project
        .source_files
        .iter()
        .flat_map(|file| detect_in_source(file).into_iter())
        .collect()
}

pub fn detect_in_source(file: &SourceFile) -> Vec<DetectorSignal> {
    let Some(text) = file.text.as_deref() else {
        return Vec::new();
    };
    let mut signals = Vec::new();
    let lower = text.to_ascii_lowercase();
    if lower.contains("totalassets") && lower.contains("balanceof(address(this))") {
        signals.push(signal(
            "erc4626_raw_total_assets",
            "erc4626-raw-total-assets",
            0.8,
            "totalAssets appears to depend directly on asset.balanceOf(address(this))",
        ));
    }
    if lower.contains("virtual") || lower.contains("decimalsoffset") || lower.contains("_offset") {
        signals.push(signal(
            "erc4626_virtual_offset",
            "erc4626-virtual-offset",
            0.65,
            "virtual asset/share or decimal offset style protection is present",
        ));
    }
    if [
        "safetransferfrom",
        "safetransfer",
        "transferfrom",
        ".transfer(",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        signals.push(signal(
            "token_transfer",
            "token-transfer",
            0.75,
            "token transfer or transferFrom-like call detected",
        ));
    }
    if ["latestrounddata", "latestanswer", "getprice", "priceoracle"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        signals.push(signal(
            "oracle_read",
            "oracle-read",
            0.75,
            "oracle-like price read detected",
        ));
    }
    if [
        "initialize",
        "reinitialize",
        "initializer",
        "reinitializer",
        "upgradeto",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        signals.push(signal(
            "upgradeability_initializer",
            "upgradeability-init",
            0.7,
            "initializer, reinitializer, or upgrade function detected",
        ));
    }
    if [".call{", ".call(", "delegatecall", "staticcall"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        signals.push(signal(
            "low_level_call",
            "low-level-call",
            0.7,
            "low-level call surface detected",
        ));
    }
    if ["onlyowner", "onlyrole", "hasrole", "msg.sender"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        signals.push(signal(
            "privileged_function",
            "access-control",
            0.65,
            "owner, role, or msg.sender access-control-like check detected",
        ));
    }
    signals
}

pub fn signal(detector: &str, tag: &str, confidence: f64, evidence: &str) -> DetectorSignal {
    DetectorSignal {
        detector: detector.to_string(),
        tag: tag.to_string(),
        confidence,
        evidence: evidence.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn source(text: &str) -> SourceFile {
        SourceFile {
            path: PathBuf::from("T.sol"),
            relative_path: PathBuf::from("T.sol"),
            language: "solidity".to_string(),
            content_hash: "x".to_string(),
            bytes: text.len(),
            text: Some(text.to_string()),
        }
    }

    #[test]
    fn detects_token_transfer() {
        let signals = detect_in_source(&source("token.safeTransferFrom(a,b,c);"));
        assert!(signals.iter().any(|s| s.detector == "token_transfer"));
    }

    #[test]
    fn detects_oracle_read() {
        let signals = detect_in_source(&source("feed.latestRoundData();"));
        assert!(signals.iter().any(|s| s.detector == "oracle_read"));
    }

    #[test]
    fn detects_initializer() {
        let signals = detect_in_source(&source("function initialize() external initializer {}"));
        assert!(signals
            .iter()
            .any(|s| s.detector == "upgradeability_initializer"));
    }
}
