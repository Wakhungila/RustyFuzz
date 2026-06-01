use crate::common::types::{CallKind, CallPhase, SequenceExecutionResult, StorageAccess};
use crate::engine::abi_ingest::{AbiIngestReport, SelectorClassification};
use crate::engine::target_profile::{ProtocolType, TargetProfile, TargetProfiler};
use crate::evm::fuzz::AbiRegistry;
use crate::evm::seed_ingester::{extract_address_hints, selector, DiscoveredAccount, MainnetSeed};
use revm::primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkSetupReport {
    pub target: Address,
    pub target_profile: TargetProfile,
    pub tokens: Vec<SetupAddressFinding>,
    pub whales: Vec<SetupAddressFinding>,
    pub holders: Vec<SetupAddressFinding>,
    pub pools: Vec<SetupAddressFinding>,
    pub oracle_feeds: Vec<SetupAddressFinding>,
    pub collateral_assets: Vec<SetupAddressFinding>,
    pub admin_slots: Vec<SetupSlotFinding>,
    pub timelock_or_governance: Vec<SetupAddressFinding>,
    pub proxy_slots: Vec<SetupSlotFinding>,
    pub recent_valid_flows: Vec<RecentValidFlow>,
    #[serde(default)]
    pub probe_plan: ProbePlan,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProbePlan {
    pub read_only: bool,
    pub probes: Vec<ProbeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeSpec {
    pub target: Address,
    pub selector: [u8; 4],
    pub name: String,
    pub reason: String,
    pub gas_cap: u64,
    pub confidence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupAddressFinding {
    pub address: Address,
    pub role: SetupRole,
    pub confidence: u64,
    pub source: SetupSource,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupSlotFinding {
    pub address: Address,
    pub slot: B256,
    pub kind: SetupSlotKind,
    pub confidence: u64,
    pub source: SetupSource,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentValidFlow {
    pub seed_ids: Vec<String>,
    pub callers: Vec<Address>,
    pub targets: Vec<Address>,
    pub selectors: Vec<Option<[u8; 4]>>,
    pub total_value: U256,
    pub confidence: u64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SetupRole {
    Token,
    Whale,
    Holder,
    Pool,
    OracleFeed,
    CollateralAsset,
    GovernanceOrTimelock,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SetupSlotKind {
    Eip1967Implementation,
    Eip1967Admin,
    Eip1967Beacon,
    TimelockOrDelayLike,
    RoleOrAdminLike,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SetupSource {
    HistoricalSeed,
    DiscoveredAccount,
    ExecutionTrace,
    StorageAccess,
    SelectorHeuristic,
    KnownSlot,
}

#[derive(Debug, Clone, Default)]
pub struct ForkSetupDiscoverer;

impl ForkSetupDiscoverer {
    pub fn discover_from_seed_bundle(
        target: Address,
        seeds: &[MainnetSeed],
        discovered_accounts: &[DiscoveredAccount],
    ) -> ForkSetupReport {
        Self::discover(target, seeds, discovered_accounts, &[])
    }

    pub fn discover_with_abi_report(
        target: Address,
        seeds: &[MainnetSeed],
        discovered_accounts: &[DiscoveredAccount],
        abi_report: &AbiIngestReport,
    ) -> ForkSetupReport {
        let mut report = Self::discover(target, seeds, discovered_accounts, &[]);
        report.target_profile = abi_report.target_profile.clone();
        let mut has_oracle = false;
        let mut has_pool = false;
        let mut has_governance = false;
        let mut has_token = false;
        for function in &abi_report.functions {
            match function.classification {
                SelectorClassification::OraclePrice => has_oracle = true,
                SelectorClassification::FactoryOrPoolCreation
                | SelectorClassification::PoolEconomic => has_pool = true,
                SelectorClassification::Governance => has_governance = true,
                SelectorClassification::Erc20Like
                | SelectorClassification::Erc721Like
                | SelectorClassification::Erc4626Like => has_token = true,
                _ => {}
            }
        }
        if has_oracle {
            report.oracle_feeds =
                merge_report_vec(report.oracle_feeds, target, SetupRole::OracleFeed);
        }
        if has_pool {
            report.pools = merge_report_vec(report.pools, target, SetupRole::Pool);
        }
        if has_governance {
            report.timelock_or_governance = merge_report_vec(
                report.timelock_or_governance,
                target,
                SetupRole::GovernanceOrTimelock,
            );
        }
        if has_token {
            report.tokens = merge_report_vec(report.tokens, target, SetupRole::Token);
        }
        report.probe_plan = probe_plan_from_abi(target, abi_report);
        report
    }

    pub fn discover(
        target: Address,
        seeds: &[MainnetSeed],
        discovered_accounts: &[DiscoveredAccount],
        executions: &[SequenceExecutionResult],
    ) -> ForkSetupReport {
        let abi_registry = abi_registry_from_observations(seeds, executions);
        let target_profile = TargetProfiler.profile(&abi_registry, None, &[]);
        let mut by_address: BTreeMap<(SetupRole, Address), SetupAddressFinding> = BTreeMap::new();
        let mut slots = Vec::new();
        let mut evidence = Vec::new();

        for account in discovered_accounts {
            if account.balance > U256::ZERO && !account.is_contract {
                upsert_address(
                    &mut by_address,
                    account.address,
                    SetupRole::Holder,
                    50,
                    SetupSource::DiscoveredAccount,
                    format!("discovered funded EOA balance={}", account.balance),
                );
                upsert_address(
                    &mut by_address,
                    account.address,
                    SetupRole::Whale,
                    whale_confidence(account.balance),
                    SetupSource::DiscoveredAccount,
                    format!(
                        "candidate whale from fork-cache balance={}",
                        account.balance
                    ),
                );
            }

            if account.is_contract && selectors_look_like_token(&account.observed_selectors) {
                upsert_address(
                    &mut by_address,
                    account.address,
                    SetupRole::Token,
                    75,
                    SetupSource::DiscoveredAccount,
                    "contract exposes token-like selectors in historical seeds".to_string(),
                );
            }
            if account.is_contract && selectors_look_like_pool(&account.observed_selectors) {
                upsert_address(
                    &mut by_address,
                    account.address,
                    SetupRole::Pool,
                    75,
                    SetupSource::DiscoveredAccount,
                    "contract exposes AMM/pool-like selectors in historical seeds".to_string(),
                );
            }
            if account.is_contract && selectors_look_like_oracle(&account.observed_selectors) {
                upsert_address(
                    &mut by_address,
                    account.address,
                    SetupRole::OracleFeed,
                    80,
                    SetupSource::DiscoveredAccount,
                    "contract exposes oracle-like selectors in historical seeds".to_string(),
                );
            }
            if account.is_contract && selectors_look_like_governance(&account.observed_selectors) {
                upsert_address(
                    &mut by_address,
                    account.address,
                    SetupRole::GovernanceOrTimelock,
                    75,
                    SetupSource::DiscoveredAccount,
                    "contract exposes governance/timelock-like selectors".to_string(),
                );
            }
        }

        for seed in seeds {
            for tx in &seed.input.txs {
                let tx_selector = selector(&tx.input);
                classify_seed_target(&mut by_address, tx.to, tx_selector);
                if tx.value > U256::ZERO {
                    upsert_address(
                        &mut by_address,
                        tx.caller,
                        SetupRole::Whale,
                        65,
                        SetupSource::HistoricalSeed,
                        format!("caller funded value-bearing seed {}", seed.id),
                    );
                }
                upsert_address(
                    &mut by_address,
                    tx.caller,
                    SetupRole::Holder,
                    55,
                    SetupSource::HistoricalSeed,
                    format!("caller observed in successful/recent flow {}", seed.id),
                );
                for hint in extract_address_hints(&tx.input) {
                    classify_address_hint(&mut by_address, hint, tx_selector, &seed.id);
                }
            }
        }

        for execution in executions {
            for call in execution
                .call_trace
                .iter()
                .filter(|call| call.phase == CallPhase::End)
            {
                let call_selector = selector(&call.input);
                classify_seed_target(&mut by_address, call.target, call_selector);
                if call.success && matches!(call.kind, CallKind::Call | CallKind::StaticCall) {
                    evidence.push(format!(
                        "successful internal call target={} selector={:?}",
                        call.target, call_selector
                    ));
                }
            }

            for access in execution
                .storage_reads
                .iter()
                .chain(execution.storage_writes.iter())
            {
                if let Some(kind) = known_setup_slot_kind(access) {
                    slots.push(SetupSlotFinding {
                        address: access.address,
                        slot: access.slot,
                        kind,
                        confidence: 90,
                        source: SetupSource::KnownSlot,
                        evidence: vec![format!(
                            "observed known setup slot at pc={} tx={}",
                            access.pc, access.tx_index
                        )],
                    });
                }
            }
        }

        if target_profile
            .protocol_types
            .contains(&ProtocolType::LendingBorrowing)
            || seeds.iter().any(|seed| {
                seed.input
                    .txs
                    .iter()
                    .filter_map(|tx| selector(&tx.input))
                    .any(|selector| selectors_look_like_lending(&[selector]))
            })
        {
            let token_addresses = by_address
                .values()
                .filter(|finding| finding.role == SetupRole::Token)
                .map(|finding| finding.address)
                .collect::<Vec<_>>();
            for token in token_addresses {
                upsert_address(
                    &mut by_address,
                    token,
                    SetupRole::CollateralAsset,
                    70,
                    SetupSource::SelectorHeuristic,
                    "token candidate promoted as collateral asset for lending target".to_string(),
                );
            }
        }

        for kind in [
            SetupSlotKind::Eip1967Implementation,
            SetupSlotKind::Eip1967Admin,
            SetupSlotKind::Eip1967Beacon,
        ] {
            slots.push(SetupSlotFinding {
                address: target,
                slot: known_slot_for_kind(&kind),
                kind,
                confidence: if target_profile
                    .protocol_types
                    .contains(&ProtocolType::ProxyUpgradeable)
                {
                    78
                } else {
                    45
                },
                source: SetupSource::KnownSlot,
                evidence: vec!["standard EIP-1967 slot to probe during fork setup".to_string()],
            });
        }

        let mut findings = by_address.into_values().collect::<Vec<_>>();
        findings.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.role.cmp(&b.role))
                .then_with(|| a.address.cmp(&b.address))
        });

        let take_role = |role: SetupRole, findings: &[SetupAddressFinding]| {
            findings
                .iter()
                .filter(|finding| finding.role == role)
                .cloned()
                .collect::<Vec<_>>()
        };

        let recent_valid_flows = recent_flows_from_seeds(seeds);
        if !recent_valid_flows.is_empty() {
            evidence.push(format!(
                "constructed {} recent valid flow windows from historical seeds",
                recent_valid_flows.len()
            ));
        }

        slots.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.address.cmp(&b.address))
                .then_with(|| a.slot.cmp(&b.slot))
        });
        slots.dedup_by(|a, b| a.address == b.address && a.slot == b.slot && a.kind == b.kind);

        ForkSetupReport {
            target,
            target_profile,
            tokens: take_role(SetupRole::Token, &findings),
            whales: take_role(SetupRole::Whale, &findings),
            holders: take_role(SetupRole::Holder, &findings),
            pools: take_role(SetupRole::Pool, &findings),
            oracle_feeds: take_role(SetupRole::OracleFeed, &findings),
            collateral_assets: take_role(SetupRole::CollateralAsset, &findings),
            admin_slots: slots
                .iter()
                .filter(|slot| {
                    matches!(
                        slot.kind,
                        SetupSlotKind::Eip1967Admin | SetupSlotKind::RoleOrAdminLike
                    )
                })
                .cloned()
                .collect(),
            timelock_or_governance: take_role(SetupRole::GovernanceOrTimelock, &findings),
            proxy_slots: slots
                .iter()
                .filter(|slot| {
                    matches!(
                        slot.kind,
                        SetupSlotKind::Eip1967Implementation
                            | SetupSlotKind::Eip1967Admin
                            | SetupSlotKind::Eip1967Beacon
                    )
                })
                .cloned()
                .collect(),
            recent_valid_flows,
            probe_plan: ProbePlan {
                read_only: true,
                probes: conservative_default_probes(target),
            },
            evidence,
        }
    }
}

fn report_vec_map(
    findings: &[SetupAddressFinding],
) -> BTreeMap<(SetupRole, Address), SetupAddressFinding> {
    findings
        .iter()
        .cloned()
        .map(|finding| ((finding.role.clone(), finding.address), finding))
        .collect()
}

fn merge_report_vec(
    findings: Vec<SetupAddressFinding>,
    target: Address,
    role: SetupRole,
) -> Vec<SetupAddressFinding> {
    let mut map = report_vec_map(&findings);
    let evidence = match role {
        SetupRole::OracleFeed => "ABI selector heuristic identified oracle-like target",
        SetupRole::Pool => "ABI selector heuristic identified pool/factory-like target",
        SetupRole::GovernanceOrTimelock => {
            "ABI selector heuristic identified governance/timelock-like target"
        }
        SetupRole::Token => "ABI selector heuristic identified token-like target",
        _ => "ABI selector heuristic identified target role",
    };
    upsert_address(
        &mut map,
        target,
        role,
        65,
        SetupSource::SelectorHeuristic,
        evidence.to_string(),
    );
    map.into_values().collect()
}

fn conservative_default_probes(target: Address) -> Vec<ProbeSpec> {
    [
        ("owner()", "owner/admin discovery"),
        ("admin()", "admin discovery"),
        ("implementation()", "proxy implementation discovery"),
        ("getImplementation()", "proxy implementation discovery"),
        ("paused()", "pause state discovery"),
        ("totalSupply()", "token/accounting discovery"),
        ("decimals()", "token/oracle metadata"),
        ("name()", "token metadata"),
        ("symbol()", "token metadata"),
    ]
    .into_iter()
    .map(|(signature, reason)| ProbeSpec {
        target,
        selector: sig(signature),
        name: signature.trim_end_matches("()").to_string(),
        reason: reason.to_string(),
        gas_cap: 150_000,
        confidence: 50,
    })
    .collect()
}

fn probe_plan_from_abi(target: Address, abi_report: &AbiIngestReport) -> ProbePlan {
    let mut probes = conservative_default_probes(target);
    for function in &abi_report.functions {
        if matches!(
            function.classification,
            SelectorClassification::ViewProbe
                | SelectorClassification::OraclePrice
                | SelectorClassification::Erc20Like
                | SelectorClassification::Erc4626Like
        ) && function.inputs.is_empty()
        {
            probes.push(ProbeSpec {
                target,
                selector: function.selector,
                name: function.name.clone(),
                reason: format!("read-only ABI probe for {}", function.signature),
                gas_cap: 150_000,
                confidence: 75,
            });
        }
    }
    probes.sort_by(|a, b| {
        a.selector
            .cmp(&b.selector)
            .then_with(|| a.name.cmp(&b.name))
    });
    probes.dedup_by(|a, b| a.selector == b.selector && a.target == b.target);
    ProbePlan {
        read_only: true,
        probes,
    }
}

fn abi_registry_from_observations(
    seeds: &[MainnetSeed],
    executions: &[SequenceExecutionResult],
) -> AbiRegistry {
    let mut abi = AbiRegistry::default();
    for seed in seeds {
        for tx in &seed.input.txs {
            if let Some(selector) = selector(&tx.input) {
                abi.functions.entry(selector).or_default();
            }
        }
    }
    for execution in executions {
        for call in &execution.call_trace {
            if let Some(selector) = selector(&call.input) {
                abi.functions.entry(selector).or_default();
            }
        }
    }
    abi
}

fn upsert_address(
    findings: &mut BTreeMap<(SetupRole, Address), SetupAddressFinding>,
    address: Address,
    role: SetupRole,
    confidence: u64,
    source: SetupSource,
    evidence: String,
) {
    let entry = findings
        .entry((role.clone(), address))
        .or_insert_with(|| SetupAddressFinding {
            address,
            role,
            confidence,
            source: source.clone(),
            evidence: Vec::new(),
        });
    entry.confidence = entry.confidence.max(confidence.min(100));
    if !entry.evidence.contains(&evidence) {
        entry.evidence.push(evidence);
    }
}

fn classify_seed_target(
    findings: &mut BTreeMap<(SetupRole, Address), SetupAddressFinding>,
    address: Address,
    selector: Option<[u8; 4]>,
) {
    let Some(selector) = selector else {
        return;
    };
    if selectors_look_like_token(&[selector]) {
        upsert_address(
            findings,
            address,
            SetupRole::Token,
            70,
            SetupSource::HistoricalSeed,
            format!(
                "target received token-like selector 0x{}",
                hex::encode(selector)
            ),
        );
    }
    if selectors_look_like_pool(&[selector]) {
        upsert_address(
            findings,
            address,
            SetupRole::Pool,
            72,
            SetupSource::HistoricalSeed,
            format!(
                "target received pool-like selector 0x{}",
                hex::encode(selector)
            ),
        );
    }
    if selectors_look_like_oracle(&[selector]) {
        upsert_address(
            findings,
            address,
            SetupRole::OracleFeed,
            78,
            SetupSource::HistoricalSeed,
            format!(
                "target received oracle-like selector 0x{}",
                hex::encode(selector)
            ),
        );
    }
    if selectors_look_like_governance(&[selector]) {
        upsert_address(
            findings,
            address,
            SetupRole::GovernanceOrTimelock,
            72,
            SetupSource::HistoricalSeed,
            format!(
                "target received governance/timelock-like selector 0x{}",
                hex::encode(selector)
            ),
        );
    }
}

fn classify_address_hint(
    findings: &mut BTreeMap<(SetupRole, Address), SetupAddressFinding>,
    address: Address,
    selector: Option<[u8; 4]>,
    seed_id: &str,
) {
    let Some(selector) = selector else {
        return;
    };
    let role = if selectors_look_like_pool(&[selector]) {
        Some(SetupRole::Token)
    } else if selectors_look_like_token(&[selector]) {
        Some(SetupRole::Holder)
    } else if selectors_look_like_oracle(&[selector]) {
        Some(SetupRole::OracleFeed)
    } else if selectors_look_like_lending(&[selector]) {
        Some(SetupRole::CollateralAsset)
    } else {
        None
    };
    if let Some(role) = role {
        upsert_address(
            findings,
            address,
            role,
            55,
            SetupSource::HistoricalSeed,
            format!(
                "address argument in seed {seed_id} near selector 0x{}",
                hex::encode(selector)
            ),
        );
    }
}

fn recent_flows_from_seeds(seeds: &[MainnetSeed]) -> Vec<RecentValidFlow> {
    let mut ordered = seeds.to_vec();
    ordered.sort_by(|a, b| {
        a.metadata
            .source_block
            .cmp(&b.metadata.source_block)
            .then_with(|| {
                a.metadata
                    .transaction_ordinal
                    .cmp(&b.metadata.transaction_ordinal)
            })
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut flows = Vec::new();
    for window in ordered.windows(2) {
        flows.push(flow_from_seeds(window));
    }
    for seed in ordered.iter().take(16) {
        flows.push(flow_from_seeds(std::slice::from_ref(seed)));
    }
    flows.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    flows.dedup_by(|a, b| a.seed_ids == b.seed_ids);
    flows.truncate(32);
    flows
}

fn flow_from_seeds(seeds: &[MainnetSeed]) -> RecentValidFlow {
    let mut seed_ids = Vec::new();
    let mut callers = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut selectors = Vec::new();
    let mut total_value = U256::ZERO;
    for seed in seeds {
        seed_ids.push(seed.id.clone());
        for tx in &seed.input.txs {
            callers.insert(tx.caller);
            targets.insert(tx.to);
            selectors.push(selector(&tx.input));
            total_value = total_value.saturating_add(tx.value);
        }
    }
    let confidence = 45
        + selectors
            .iter()
            .filter(|selector| selector.is_some())
            .count() as u64
            * 10;
    RecentValidFlow {
        seed_ids,
        callers: callers.into_iter().collect(),
        targets: targets.into_iter().collect(),
        selectors,
        total_value,
        confidence: confidence.min(90),
        evidence: vec!["ordered historical transaction flow candidate".to_string()],
    }
}

fn selectors_look_like_token(selectors: &[[u8; 4]]) -> bool {
    contains_any(
        selectors,
        &[
            sig("balanceOf(address)"),
            sig("totalSupply()"),
            sig("transfer(address,uint256)"),
            sig("approve(address,uint256)"),
            sig("transferFrom(address,address,uint256)"),
            sig("allowance(address,address)"),
        ],
    )
}

fn selectors_look_like_pool(selectors: &[[u8; 4]]) -> bool {
    contains_any(
        selectors,
        &[
            sig("getReserves()"),
            sig("swap(uint256,uint256,address,bytes)"),
            sig("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
            sig("mint(address)"),
            sig("burn(address)"),
            sig("sync()"),
            sig("skim(address)"),
        ],
    )
}

fn selectors_look_like_oracle(selectors: &[[u8; 4]]) -> bool {
    contains_any(
        selectors,
        &[
            sig("latestAnswer()"),
            sig("latestRoundData()"),
            sig("getPrice()"),
            sig("price()"),
            sig("decimals()"),
        ],
    )
}

fn selectors_look_like_lending(selectors: &[[u8; 4]]) -> bool {
    contains_any(
        selectors,
        &[
            sig("borrow(uint256)"),
            sig("borrow(address,uint256,uint256,uint16,address)"),
            sig("repay(uint256)"),
            sig("liquidate(address,address,uint256,uint256)"),
            sig("liquidationCall(address,address,address,uint256,bool)"),
            sig("supply(address,uint256,address,uint16)"),
            sig("deposit(uint256,address)"),
        ],
    )
}

fn selectors_look_like_governance(selectors: &[[u8; 4]]) -> bool {
    contains_any(
        selectors,
        &[
            sig("propose(address[],uint256[],bytes[],string)"),
            sig("queue(uint256)"),
            sig("execute(uint256)"),
            sig("execute(address,uint256,bytes)"),
            sig("castVote(uint256,uint8)"),
            sig("initialize(address)"),
            sig("upgradeTo(address)"),
        ],
    )
}

fn contains_any(selectors: &[[u8; 4]], known: &[[u8; 4]]) -> bool {
    selectors.iter().any(|selector| known.contains(selector))
}

fn whale_confidence(balance: U256) -> u64 {
    if balance >= U256::from(10u128.pow(20)) {
        90
    } else if balance >= U256::from(10u128.pow(18)) {
        75
    } else {
        45
    }
}

fn known_setup_slot_kind(access: &StorageAccess) -> Option<SetupSlotKind> {
    let slot = access.slot;
    if slot == known_slot_for_kind(&SetupSlotKind::Eip1967Implementation) {
        Some(SetupSlotKind::Eip1967Implementation)
    } else if slot == known_slot_for_kind(&SetupSlotKind::Eip1967Admin) {
        Some(SetupSlotKind::Eip1967Admin)
    } else if slot == known_slot_for_kind(&SetupSlotKind::Eip1967Beacon) {
        Some(SetupSlotKind::Eip1967Beacon)
    } else {
        None
    }
}

fn known_slot_for_kind(kind: &SetupSlotKind) -> B256 {
    match kind {
        SetupSlotKind::Eip1967Implementation => eip1967_slot("eip1967.proxy.implementation"),
        SetupSlotKind::Eip1967Admin => eip1967_slot("eip1967.proxy.admin"),
        SetupSlotKind::Eip1967Beacon => eip1967_slot("eip1967.proxy.beacon"),
        SetupSlotKind::TimelockOrDelayLike | SetupSlotKind::RoleOrAdminLike => B256::ZERO,
    }
}

fn eip1967_slot(label: &str) -> B256 {
    let value = U256::from_be_bytes(keccak256(label.as_bytes()).0).saturating_sub(U256::from(1));
    B256::from(value.to_be_bytes::<32>())
}

fn sig(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{CallObservation, StorageAccess};
    use crate::evm::seed_ingester::{MainnetSeed, SeedMetadata};
    use revm::primitives::Address;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn seed(id: &str, caller: Address, to: Address, selector: [u8; 4]) -> MainnetSeed {
        let input = crate::evm::fuzz::EvmInput {
            txs: vec![crate::common::types::SingletonTx {
                input: selector.to_vec(),
                caller,
                to,
                value: U256::ZERO,
                is_victim: false,
            }],
            base_snapshot_id: 0,
            waypoints: Vec::new(),
            mutation_provenance: Vec::new(),
        };
        MainnetSeed {
            id: id.to_string(),
            input,
            metadata: SeedMetadata {
                source_block: 1,
                block_offset: 0,
                transaction_ordinal: 0,
                caller,
                target: to,
                value: U256::ZERO,
                selector: Some(selector),
                calldata_len: 4,
                discovered_address_hints: Vec::new(),
                matched_target: Some(to),
                match_kind: Some("test".to_string()),
                confidence: None,
                provenance: None,
            },
        }
    }

    #[test]
    fn setup_discovers_tokens_holders_whales_and_flows() {
        let target = addr(0xaa);
        let token = addr(0x10);
        let user = addr(0x33);
        let seeds = vec![seed(
            "seed-a",
            user,
            token,
            sig("transfer(address,uint256)"),
        )];
        let accounts = vec![
            DiscoveredAccount {
                address: token,
                is_contract: true,
                balance: U256::ZERO,
                nonce: 1,
                code_hash: B256::ZERO,
                code_len: 100,
                observed_selectors: vec![sig("balanceOf(address)")],
                referenced_by_seed_ids: vec!["seed-a".to_string()],
            },
            DiscoveredAccount {
                address: user,
                is_contract: false,
                balance: U256::from(10u128.pow(20)),
                nonce: 1,
                code_hash: B256::ZERO,
                code_len: 0,
                observed_selectors: Vec::new(),
                referenced_by_seed_ids: vec!["seed-a".to_string()],
            },
        ];

        let report = ForkSetupDiscoverer::discover_from_seed_bundle(target, &seeds, &accounts);
        assert!(report.tokens.iter().any(|finding| finding.address == token));
        assert!(report.holders.iter().any(|finding| finding.address == user));
        assert!(report.whales.iter().any(|finding| finding.address == user));
        assert!(!report.recent_valid_flows.is_empty());
    }

    #[test]
    fn setup_discovers_oracles_pools_and_collateral_assets() {
        let target = addr(0xbb);
        let pool = addr(0x44);
        let oracle = addr(0x55);
        let collateral = addr(0x66);
        let seeds = vec![
            seed(
                "pool",
                addr(1),
                pool,
                sig("swap(uint256,uint256,address,bytes)"),
            ),
            seed("oracle", addr(1), oracle, sig("latestRoundData()")),
            seed("borrow", addr(1), target, sig("borrow(uint256)")),
            seed(
                "token",
                addr(1),
                collateral,
                sig("approve(address,uint256)"),
            ),
        ];

        let report = ForkSetupDiscoverer::discover_from_seed_bundle(target, &seeds, &[]);
        assert!(report.pools.iter().any(|finding| finding.address == pool));
        assert!(report
            .oracle_feeds
            .iter()
            .any(|finding| finding.address == oracle));
        assert!(report
            .collateral_assets
            .iter()
            .any(|finding| finding.address == collateral));
    }

    #[test]
    fn setup_discovers_known_proxy_slots_from_execution() {
        let target = addr(0xcc);
        let slot = known_slot_for_kind(&SetupSlotKind::Eip1967Admin);
        let execution = SequenceExecutionResult {
            tx_results: Vec::new(),
            total_gas_used: 1,
            final_coverage_hash: 1,
            storage_reads: vec![StorageAccess {
                tx_index: 0,
                address: target,
                slot,
                value: Some(U256::from(1)),
                pc: 1,
            }],
            storage_writes: Vec::new(),
            storage_diffs: Vec::new(),
            call_trace: vec![CallObservation {
                tx_index: 0,
                depth: 1,
                caller: addr(1),
                target,
                value: U256::ZERO,
                input: sig("upgradeTo(address)").to_vec(),
                output: Vec::new(),
                gas_limit: 1,
                gas_used: 1,
                success: true,
                kind: CallKind::Call,
                phase: CallPhase::End,
                created_address: None,
                result: None,
            }],
            oracle_observations: Vec::new(),
        };

        let report = ForkSetupDiscoverer::discover(target, &[], &[], &[execution]);
        assert!(report
            .admin_slots
            .iter()
            .any(|finding| finding.slot == slot));
        assert!(report
            .proxy_slots
            .iter()
            .any(|finding| finding.slot == slot));
    }

    #[test]
    fn abi_report_adds_read_only_probe_plan_and_profile() {
        let target = addr(0xaa);
        let abi: alloy_json_abi::JsonAbi = serde_json::from_str(
            r#"[
              {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[]},
              {"type":"function","name":"setPrice","stateMutability":"nonpayable","inputs":[{"name":"price","type":"uint256"}],"outputs":[]}
            ]"#,
        )
        .unwrap();
        let (_registry, abi_report) =
            crate::engine::abi_ingest::ingest_abi(&abi, Some(target), None);

        let report = ForkSetupDiscoverer::discover_with_abi_report(target, &[], &[], &abi_report);

        assert!(report.probe_plan.read_only);
        assert!(report
            .probe_plan
            .probes
            .iter()
            .any(|probe| probe.name == "latestRoundData"));
        assert!(report
            .oracle_feeds
            .iter()
            .any(|finding| finding.address == target));
        assert!(report
            .target_profile
            .protocol_types
            .contains(&ProtocolType::OraclePriceFeed));
    }
}
