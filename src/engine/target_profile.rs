use crate::engine::foundry_ingest::FoundryHarnessManifest;
use crate::engine::seed_intelligence::{SeedCandidate, SeedTag};
use crate::evm::fuzz::AbiRegistry;
use revm::primitives::keccak256;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolType {
    Erc20Token,
    Erc4626Vault,
    AmmDexPool,
    LendingBorrowing,
    OraclePriceFeed,
    StakingRewards,
    GovernanceTimelock,
    BridgeMessagePassing,
    RouterAggregator,
    ProxyUpgradeable,
    AccessControlHeavy,
    AccountingHeavy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetProfile {
    pub protocol_types: Vec<ProtocolType>,
    pub confidence: u64,
    pub relevant_selectors: Vec<[u8; 4]>,
    pub risky_selectors: Vec<[u8; 4]>,
    pub read_only_functions: Vec<[u8; 4]>,
    pub state_changing_functions: Vec<[u8; 4]>,
    pub role_sensitive_functions: Vec<[u8; 4]>,
    pub value_sensitive_functions: Vec<[u8; 4]>,
    pub token_accounting_functions: Vec<[u8; 4]>,
    pub recommended_seed_templates: Vec<String>,
    pub recommended_invariant_families: Vec<String>,
    pub explanation: Vec<String>,
}

impl Default for TargetProfile {
    fn default() -> Self {
        Self {
            protocol_types: vec![ProtocolType::Unknown],
            confidence: 20,
            relevant_selectors: Vec::new(),
            risky_selectors: Vec::new(),
            read_only_functions: Vec::new(),
            state_changing_functions: Vec::new(),
            role_sensitive_functions: Vec::new(),
            value_sensitive_functions: Vec::new(),
            token_accounting_functions: Vec::new(),
            recommended_seed_templates: vec!["generic-stateful-sequence".to_string()],
            recommended_invariant_families: vec!["generic-accounting".to_string()],
            explanation: vec![
                "no strong protocol signature; using conservative generic profile".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TargetProfiler;

impl TargetProfiler {
    pub fn profile(
        &self,
        abi_registry: &AbiRegistry,
        foundry_harness: Option<&FoundryHarnessManifest>,
        seed_candidates: &[SeedCandidate],
    ) -> TargetProfile {
        let mut selectors: BTreeSet<[u8; 4]> = abi_registry.functions.keys().copied().collect();
        let mut names = Vec::new();
        if let Some(harness) = foundry_harness {
            for target in &harness.target_selectors {
                for selector in &target.selectors {
                    if let Some(selector_hex) = selector.selector_hex {
                        selectors.insert(selector_hex);
                    }
                    names.push(selector.expression.clone());
                }
            }
            for invariant in &harness.invariant_functions {
                names.push(invariant.name.clone());
            }
        }
        for seed in seed_candidates {
            if let Some(selector) = seed.selector {
                selectors.insert(selector);
            }
        }

        let mut scores: BTreeMap<ProtocolType, u64> = BTreeMap::new();
        let mut explanation = Vec::new();
        for selector in &selectors {
            for spec in selector_specs()
                .iter()
                .filter(|spec| spec.selector == *selector)
            {
                *scores.entry(spec.protocol.clone()).or_default() += spec.weight;
                explanation.push(format!(
                    "selector 0x{} matched {:?}: {}",
                    hex::encode(selector),
                    spec.protocol,
                    spec.reason
                ));
            }
        }
        for name in names {
            let lowered = name.to_ascii_lowercase();
            for spec in name_specs()
                .iter()
                .filter(|spec| lowered.contains(spec.needle))
            {
                *scores.entry(spec.protocol.clone()).or_default() += spec.weight;
                explanation.push(format!(
                    "source/foundry hint `{}` matched {:?}: {}",
                    name, spec.protocol, spec.reason
                ));
            }
        }
        for seed in seed_candidates {
            for tag in &seed.tags {
                if let Some(protocol) = protocol_from_seed_tag(tag) {
                    *scores.entry(protocol.clone()).or_default() += 15;
                    explanation.push(format!("seed `{}` contributed {:?}", seed.reason, protocol));
                }
            }
        }

        if scores.is_empty() {
            return TargetProfile::default();
        }

        let max_score = scores.values().copied().max().unwrap_or_default();
        let mut protocol_types = scores
            .iter()
            .filter(|(_, score)| **score >= 35 || **score * 2 >= max_score)
            .map(|(protocol, _)| protocol.clone())
            .collect::<Vec<_>>();
        protocol_types.sort();
        protocol_types.dedup();

        let mut read_only = Vec::new();
        let mut state_changing = Vec::new();
        let mut role_sensitive = Vec::new();
        let mut value_sensitive = Vec::new();
        let mut token_accounting = Vec::new();
        let mut risky = Vec::new();
        for selector in &selectors {
            let class = selector_class(*selector);
            if class.read_only {
                read_only.push(*selector);
            } else {
                state_changing.push(*selector);
            }
            if class.role_sensitive {
                role_sensitive.push(*selector);
                risky.push(*selector);
            }
            if class.value_sensitive {
                value_sensitive.push(*selector);
                risky.push(*selector);
            }
            if class.token_accounting {
                token_accounting.push(*selector);
            }
            if class.risky {
                risky.push(*selector);
            }
        }
        risky.sort();
        risky.dedup();

        let confidence = (max_score + selectors.len() as u64 * 2).clamp(25, 95);
        TargetProfile {
            protocol_types: protocol_types.clone(),
            confidence,
            relevant_selectors: selectors.into_iter().collect(),
            risky_selectors: risky,
            read_only_functions: read_only,
            state_changing_functions: state_changing,
            role_sensitive_functions: role_sensitive,
            value_sensitive_functions: value_sensitive,
            token_accounting_functions: token_accounting,
            recommended_seed_templates: recommended_templates(&protocol_types),
            recommended_invariant_families: recommended_invariants(&protocol_types),
            explanation,
        }
    }

    pub fn profile_from_selectors(selectors: impl IntoIterator<Item = [u8; 4]>) -> TargetProfile {
        let mut abi = AbiRegistry::default();
        for selector in selectors {
            abi.functions.entry(selector).or_default();
        }
        TargetProfiler.profile(&abi, None, &[])
    }
}

#[derive(Debug, Clone)]
struct SelectorSpec {
    selector: [u8; 4],
    protocol: ProtocolType,
    weight: u64,
    reason: &'static str,
}

#[derive(Debug, Clone)]
struct NameSpec {
    needle: &'static str,
    protocol: ProtocolType,
    weight: u64,
    reason: &'static str,
}

#[derive(Debug, Clone, Copy, Default)]
struct SelectorClass {
    read_only: bool,
    role_sensitive: bool,
    value_sensitive: bool,
    token_accounting: bool,
    risky: bool,
}

fn selector_specs() -> Vec<SelectorSpec> {
    let entries = [
        (
            "balanceOf(address)",
            ProtocolType::Erc20Token,
            35,
            "ERC20 balance read",
        ),
        (
            "totalSupply()",
            ProtocolType::Erc20Token,
            30,
            "ERC20 supply read",
        ),
        (
            "transfer(address,uint256)",
            ProtocolType::Erc20Token,
            40,
            "ERC20 transfer",
        ),
        (
            "approve(address,uint256)",
            ProtocolType::Erc20Token,
            40,
            "ERC20 approval",
        ),
        (
            "transferFrom(address,address,uint256)",
            ProtocolType::Erc20Token,
            45,
            "allowance-dependent transfer",
        ),
        (
            "deposit(uint256,address)",
            ProtocolType::Erc4626Vault,
            55,
            "ERC4626 deposit",
        ),
        (
            "mint(uint256,address)",
            ProtocolType::Erc4626Vault,
            50,
            "ERC4626 mint",
        ),
        (
            "withdraw(uint256,address,address)",
            ProtocolType::Erc4626Vault,
            55,
            "ERC4626 withdraw",
        ),
        (
            "redeem(uint256,address,address)",
            ProtocolType::Erc4626Vault,
            55,
            "ERC4626 redeem",
        ),
        (
            "totalAssets()",
            ProtocolType::Erc4626Vault,
            45,
            "ERC4626 accounting read",
        ),
        (
            "convertToShares(uint256)",
            ProtocolType::Erc4626Vault,
            40,
            "ERC4626 preview/accounting",
        ),
        (
            "previewDeposit(uint256)",
            ProtocolType::Erc4626Vault,
            40,
            "ERC4626 preview",
        ),
        (
            "swap(address,bool,int256,uint160,bytes)",
            ProtocolType::AmmDexPool,
            55,
            "AMM swap",
        ),
        (
            "swap(uint256,uint256,address,bytes)",
            ProtocolType::AmmDexPool,
            50,
            "AMM swap",
        ),
        (
            "addLiquidity(uint256,uint256)",
            ProtocolType::AmmDexPool,
            45,
            "liquidity add",
        ),
        (
            "removeLiquidity(uint256)",
            ProtocolType::AmmDexPool,
            45,
            "liquidity remove",
        ),
        (
            "getReserves()",
            ProtocolType::AmmDexPool,
            40,
            "AMM reserve read",
        ),
        (
            "borrow(address,uint256,uint256,uint16,address)",
            ProtocolType::LendingBorrowing,
            55,
            "lending borrow",
        ),
        (
            "repay(address,uint256,uint256,address)",
            ProtocolType::LendingBorrowing,
            45,
            "lending repay",
        ),
        (
            "liquidationCall(address,address,address,uint256,bool)",
            ProtocolType::LendingBorrowing,
            60,
            "liquidation",
        ),
        (
            "latestAnswer()",
            ProtocolType::OraclePriceFeed,
            45,
            "oracle read",
        ),
        (
            "latestRoundData()",
            ProtocolType::OraclePriceFeed,
            45,
            "oracle read",
        ),
        (
            "setPrice(uint256)",
            ProtocolType::OraclePriceFeed,
            45,
            "oracle update",
        ),
        (
            "stake(uint256)",
            ProtocolType::StakingRewards,
            45,
            "staking",
        ),
        (
            "unstake(uint256)",
            ProtocolType::StakingRewards,
            45,
            "unstaking",
        ),
        (
            "claim()",
            ProtocolType::StakingRewards,
            35,
            "claim/reward path",
        ),
        (
            "propose(address[],uint256[],bytes[],string)",
            ProtocolType::GovernanceTimelock,
            50,
            "governance proposal",
        ),
        (
            "castVote(uint256,uint8)",
            ProtocolType::GovernanceTimelock,
            45,
            "governance vote",
        ),
        (
            "queue(uint256)",
            ProtocolType::GovernanceTimelock,
            45,
            "timelock queue",
        ),
        (
            "execute(uint256)",
            ProtocolType::GovernanceTimelock,
            50,
            "governance execution",
        ),
        (
            "finalize(bytes)",
            ProtocolType::BridgeMessagePassing,
            50,
            "bridge finalization",
        ),
        (
            "relay(bytes)",
            ProtocolType::BridgeMessagePassing,
            45,
            "bridge relay",
        ),
        (
            "upgradeTo(address)",
            ProtocolType::ProxyUpgradeable,
            55,
            "upgradeable proxy",
        ),
        (
            "initialize()",
            ProtocolType::ProxyUpgradeable,
            45,
            "initializer",
        ),
        (
            "owner()",
            ProtocolType::AccessControlHeavy,
            35,
            "owner read",
        ),
        (
            "grantRole(bytes32,address)",
            ProtocolType::AccessControlHeavy,
            55,
            "role mutation",
        ),
    ];
    entries
        .into_iter()
        .map(|(signature, protocol, weight, reason)| SelectorSpec {
            selector: function_selector(signature),
            protocol,
            weight,
            reason,
        })
        .collect()
}

fn name_specs() -> Vec<NameSpec> {
    vec![
        NameSpec {
            needle: "vault",
            protocol: ProtocolType::Erc4626Vault,
            weight: 25,
            reason: "vault naming",
        },
        NameSpec {
            needle: "swap",
            protocol: ProtocolType::AmmDexPool,
            weight: 25,
            reason: "swap naming",
        },
        NameSpec {
            needle: "liquidat",
            protocol: ProtocolType::LendingBorrowing,
            weight: 30,
            reason: "liquidation naming",
        },
        NameSpec {
            needle: "oracle",
            protocol: ProtocolType::OraclePriceFeed,
            weight: 25,
            reason: "oracle naming",
        },
        NameSpec {
            needle: "govern",
            protocol: ProtocolType::GovernanceTimelock,
            weight: 25,
            reason: "governance naming",
        },
        NameSpec {
            needle: "bridge",
            protocol: ProtocolType::BridgeMessagePassing,
            weight: 25,
            reason: "bridge naming",
        },
        NameSpec {
            needle: "router",
            protocol: ProtocolType::RouterAggregator,
            weight: 25,
            reason: "router naming",
        },
        NameSpec {
            needle: "admin",
            protocol: ProtocolType::AccessControlHeavy,
            weight: 20,
            reason: "admin naming",
        },
        NameSpec {
            needle: "account",
            protocol: ProtocolType::AccountingHeavy,
            weight: 20,
            reason: "accounting naming",
        },
    ]
}

fn selector_class(selector: [u8; 4]) -> SelectorClass {
    let read_only = [
        "balanceOf(address)",
        "totalSupply()",
        "totalAssets()",
        "convertToShares(uint256)",
        "previewDeposit(uint256)",
        "getReserves()",
        "latestAnswer()",
        "latestRoundData()",
        "owner()",
    ];
    let role_sensitive = [
        "execute(uint256)",
        "grantRole(bytes32,address)",
        "upgradeTo(address)",
        "initialize()",
        "setPrice(uint256)",
    ];
    let value_sensitive = [
        "deposit(uint256,address)",
        "mint(uint256,address)",
        "withdraw(uint256,address,address)",
        "redeem(uint256,address,address)",
        "swap(address,bool,int256,uint160,bytes)",
        "swap(uint256,uint256,address,bytes)",
        "borrow(address,uint256,uint256,uint16,address)",
        "liquidationCall(address,address,address,uint256,bool)",
    ];
    let token_accounting = [
        "balanceOf(address)",
        "totalSupply()",
        "transfer(address,uint256)",
        "approve(address,uint256)",
        "transferFrom(address,address,uint256)",
        "deposit(uint256,address)",
        "withdraw(uint256,address,address)",
        "redeem(uint256,address,address)",
    ];
    SelectorClass {
        read_only: read_only
            .iter()
            .any(|sig| function_selector(sig) == selector),
        role_sensitive: role_sensitive
            .iter()
            .any(|sig| function_selector(sig) == selector),
        value_sensitive: value_sensitive
            .iter()
            .any(|sig| function_selector(sig) == selector),
        token_accounting: token_accounting
            .iter()
            .any(|sig| function_selector(sig) == selector),
        risky: role_sensitive
            .iter()
            .chain(value_sensitive.iter())
            .any(|sig| function_selector(sig) == selector),
    }
}

fn protocol_from_seed_tag(tag: &SeedTag) -> Option<ProtocolType> {
    Some(match tag {
        SeedTag::Erc20 => ProtocolType::Erc20Token,
        SeedTag::Erc4626 => ProtocolType::Erc4626Vault,
        SeedTag::Amm => ProtocolType::AmmDexPool,
        SeedTag::Lending => ProtocolType::LendingBorrowing,
        SeedTag::Oracle => ProtocolType::OraclePriceFeed,
        SeedTag::Governance => ProtocolType::GovernanceTimelock,
        SeedTag::Bridge => ProtocolType::BridgeMessagePassing,
        SeedTag::Staking => ProtocolType::StakingRewards,
        SeedTag::AccessControl => ProtocolType::AccessControlHeavy,
        SeedTag::Unknown => return None,
    })
}

fn recommended_templates(protocols: &[ProtocolType]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for protocol in protocols {
        match protocol {
            ProtocolType::Erc4626Vault => {
                out.insert("erc4626-inflation".to_string());
            }
            ProtocolType::AmmDexPool => {
                out.insert("amm-price-manipulation".to_string());
            }
            ProtocolType::LendingBorrowing => {
                out.insert("lending-liquidation".to_string());
            }
            ProtocolType::GovernanceTimelock => {
                out.insert("governance-queue-execute".to_string());
            }
            ProtocolType::BridgeMessagePassing => {
                out.insert("bridge-finalize-replay".to_string());
            }
            ProtocolType::StakingRewards => {
                out.insert("stake-claim-unstake".to_string());
            }
            ProtocolType::AccessControlHeavy | ProtocolType::ProxyUpgradeable => {
                out.insert("access-control-sensitive-call".to_string());
            }
            _ => {
                out.insert("generic-stateful-sequence".to_string());
            }
        }
    }
    out.into_iter().collect()
}

fn recommended_invariants(protocols: &[ProtocolType]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for protocol in protocols {
        match protocol {
            ProtocolType::Erc4626Vault => {
                out.insert("erc4626-vault".to_string());
            }
            ProtocolType::AmmDexPool => {
                out.insert("amm-reserves".to_string());
            }
            ProtocolType::LendingBorrowing => {
                out.insert("lending-solvency".to_string());
            }
            ProtocolType::GovernanceTimelock => {
                out.insert("governance-timelock".to_string());
            }
            ProtocolType::OraclePriceFeed => {
                out.insert("oracle-freshness".to_string());
            }
            ProtocolType::BridgeMessagePassing => {
                out.insert("bridge-message".to_string());
            }
            ProtocolType::AccessControlHeavy | ProtocolType::ProxyUpgradeable => {
                out.insert("access-control".to_string());
            }
            _ => {
                out.insert("generic-accounting".to_string());
            }
        }
    }
    out.into_iter().collect()
}

pub fn function_selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(signatures: &[&str]) -> TargetProfile {
        TargetProfiler::profile_from_selectors(signatures.iter().map(|sig| function_selector(sig)))
    }

    #[test]
    fn erc4626_selectors_classify_as_vault() {
        let profile = profile(&[
            "deposit(uint256,address)",
            "redeem(uint256,address,address)",
            "totalAssets()",
        ]);
        assert!(profile.protocol_types.contains(&ProtocolType::Erc4626Vault));
        assert!(profile
            .recommended_seed_templates
            .contains(&"erc4626-inflation".to_string()));
    }

    #[test]
    fn amm_selectors_classify_as_pool() {
        let profile = profile(&[
            "swap(uint256,uint256,address,bytes)",
            "addLiquidity(uint256,uint256)",
            "removeLiquidity(uint256)",
        ]);
        assert!(profile.protocol_types.contains(&ProtocolType::AmmDexPool));
    }

    #[test]
    fn lending_selectors_classify_as_lending() {
        let profile = profile(&[
            "borrow(address,uint256,uint256,uint16,address)",
            "repay(address,uint256,uint256,address)",
            "liquidationCall(address,address,address,uint256,bool)",
        ]);
        assert!(profile
            .protocol_types
            .contains(&ProtocolType::LendingBorrowing));
    }

    #[test]
    fn governance_selectors_classify_as_governance() {
        let profile = profile(&[
            "propose(address[],uint256[],bytes[],string)",
            "queue(uint256)",
            "execute(uint256)",
        ]);
        assert!(profile
            .protocol_types
            .contains(&ProtocolType::GovernanceTimelock));
        assert!(!profile.role_sensitive_functions.is_empty());
    }

    #[test]
    fn unknown_protocol_has_conservative_profile() {
        let profile = TargetProfiler::profile_from_selectors([[0xde, 0xad, 0xbe, 0xef]]);
        assert_eq!(profile.protocol_types, vec![ProtocolType::Unknown]);
        assert!(profile.confidence <= 25);
    }
}
