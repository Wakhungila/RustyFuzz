use crate::engine::target_profile::{
    function_selector, ProtocolType, TargetProfile, TargetProfiler,
};
use crate::evm::fuzz::AbiRegistry;
use alloy_dyn_abi::DynSolType;
use alloy_json_abi::JsonAbi;
use revm::primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiIngestReport {
    pub target: Option<Address>,
    pub source_path: Option<PathBuf>,
    pub function_count: usize,
    pub event_count: usize,
    pub error_count: usize,
    pub classified_selectors: usize,
    pub functions: Vec<AbiFunctionSummary>,
    pub protocol_types: Vec<ProtocolType>,
    pub target_profile: TargetProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiFunctionSummary {
    pub name: String,
    pub signature: String,
    pub selector: [u8; 4],
    pub mutability: String,
    pub inputs: Vec<String>,
    pub classification: SelectorClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SelectorClassification {
    FactoryOrPoolCreation,
    RegistryMutation,
    OwnershipAdmin,
    Governance,
    OraclePrice,
    Erc20Like,
    Erc721Like,
    Erc4626Like,
    UpgradeProxyInit,
    PauseFreeze,
    WithdrawClaim,
    PoolEconomic,
    ViewProbe,
    Unknown,
}

pub fn load_abi_file(path: impl AsRef<Path>) -> anyhow::Result<JsonAbi> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn ingest_abi_file(
    path: impl AsRef<Path>,
    target: Option<Address>,
) -> anyhow::Result<(JsonAbi, AbiRegistry, AbiIngestReport)> {
    let path = path.as_ref();
    let abi = load_abi_file(path)?;
    let (registry, report) = ingest_abi(&abi, target, Some(path.to_path_buf()));
    Ok((abi, registry, report))
}

pub fn ingest_abi(
    abi: &JsonAbi,
    target: Option<Address>,
    source_path: Option<PathBuf>,
) -> (AbiRegistry, AbiIngestReport) {
    let mut registry = AbiRegistry::default();
    let mut functions = Vec::new();
    for func in abi.functions() {
        let selector = func.selector().0;
        let inputs = func
            .inputs
            .iter()
            .map(|input| input.ty.clone())
            .collect::<Vec<_>>();
        let dyn_inputs = func
            .inputs
            .iter()
            .filter_map(|input| DynSolType::parse(&input.ty).ok())
            .collect::<Vec<_>>();
        registry.functions.insert(selector, dyn_inputs);
        let signature = format!("{}({})", func.name, inputs.join(","));
        functions.push(AbiFunctionSummary {
            name: func.name.clone(),
            signature,
            selector,
            mutability: format!("{:?}", func.state_mutability),
            inputs,
            classification: classify_selector_name(&func.name),
        });
    }

    functions.sort_by(|a, b| a.selector.cmp(&b.selector));
    let classified_selectors = functions
        .iter()
        .filter(|function| function.classification != SelectorClassification::Unknown)
        .count();
    let names = functions
        .iter()
        .map(|function| function.name.as_str())
        .collect::<Vec<_>>();
    let target_profile = TargetProfiler::profile_from_selector_names(
        functions.iter().map(|function| function.selector),
        names,
    );
    let protocol_types = target_profile.protocol_types.clone();
    let report = AbiIngestReport {
        target,
        source_path,
        function_count: functions.len(),
        event_count: abi.events().count(),
        error_count: abi.errors().count(),
        classified_selectors,
        functions,
        protocol_types,
        target_profile,
    };
    (registry, report)
}

pub fn merge_abi_registry(dst: &mut AbiRegistry, src: &AbiRegistry) {
    for (selector, inputs) in &src.functions {
        dst.functions.insert(*selector, inputs.clone());
    }
}

pub fn write_abi_cache(
    cache_dir: impl AsRef<Path>,
    bundle_id: &str,
    abi: &JsonAbi,
    report: &AbiIngestReport,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let cache_dir = cache_dir.as_ref().join(bundle_id);
    std::fs::create_dir_all(&cache_dir)?;
    let abi_path = cache_dir.join("abi.json");
    let report_path = cache_dir.join("report.json");
    std::fs::write(&abi_path, serde_json::to_vec_pretty(abi)?)?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(report)?)?;
    Ok((abi_path, report_path))
}

pub fn abi_generated_selectors(report: &AbiIngestReport) -> Vec<[u8; 4]> {
    report
        .functions
        .iter()
        .map(|function| function.selector)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn classify_selector_name(name: &str) -> SelectorClassification {
    let lowered = name.to_ascii_lowercase();
    if contains_any(
        &lowered,
        &["create", "deploy", "newpool", "poolfor", "clone"],
    ) {
        SelectorClassification::FactoryOrPoolCreation
    } else if contains_any(
        &lowered,
        &["register", "setpool", "settoken", "setasset", "map"],
    ) {
        SelectorClassification::RegistryMutation
    } else if contains_any(
        &lowered,
        &[
            "owner",
            "admin",
            "role",
            "grant",
            "revoke",
            "transferownership",
        ],
    ) {
        SelectorClassification::OwnershipAdmin
    } else if contains_any(
        &lowered,
        &["propose", "queue", "execute", "vote", "quorum", "timelock"],
    ) {
        SelectorClassification::Governance
    } else if contains_any(&lowered, &["price", "oracle", "answer", "rounddata"]) {
        SelectorClassification::OraclePrice
    } else if matches!(
        function_selector(&format!("{name}()")),
        selector if selector == function_selector("totalSupply()")
    ) || contains_any(&lowered, &["balanceof", "transfer", "approve", "allowance"])
    {
        SelectorClassification::Erc20Like
    } else if contains_any(&lowered, &["tokenuri", "ownerof", "safetransferfrom"]) {
        SelectorClassification::Erc721Like
    } else if contains_any(
        &lowered,
        &[
            "totalassets",
            "converttoshares",
            "previewdeposit",
            "deposit",
            "redeem",
        ],
    ) {
        SelectorClassification::Erc4626Like
    } else if contains_any(
        &lowered,
        &["upgrade", "implementation", "initialize", "reinitialize"],
    ) {
        SelectorClassification::UpgradeProxyInit
    } else if contains_any(&lowered, &["pause", "unpause", "freeze"]) {
        SelectorClassification::PauseFreeze
    } else if contains_any(&lowered, &["withdraw", "claim", "collect", "harvest"]) {
        SelectorClassification::WithdrawClaim
    } else if contains_any(
        &lowered,
        &["swap", "mint", "burn", "reserve", "sync", "skim"],
    ) {
        SelectorClassification::PoolEconomic
    } else if contains_any(
        &lowered,
        &["get", "is", "has", "decimals", "symbol", "name"],
    ) {
        SelectorClassification::ViewProbe
    } else {
        SelectorClassification::Unknown
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_ingest_extracts_selectors_and_profile() {
        let abi: JsonAbi = serde_json::from_str(
            r#"[
              {"type":"function","name":"deposit","stateMutability":"nonpayable","inputs":[{"name":"assets","type":"uint256"},{"name":"receiver","type":"address"}],"outputs":[]},
              {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint256"}]},
              {"type":"event","name":"Deposit","anonymous":false,"inputs":[]}
            ]"#,
        )
        .unwrap();
        let (_registry, report) = ingest_abi(&abi, None, None);
        assert_eq!(report.function_count, 2);
        assert_eq!(report.event_count, 1);
        assert!(report.classified_selectors >= 2);
        assert!(report
            .target_profile
            .protocol_types
            .contains(&ProtocolType::Erc4626Vault));
    }
}
