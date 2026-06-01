use crate::common::types::SingletonTx;
use crate::engine::bytecode_analysis::FunctionSliceSummary;
use crate::engine::foundry_ingest::FoundryHarnessManifest;
use crate::engine::target_profile::ProtocolType;
use crate::evm::fuzz::{AbiRegistry, EvmInput, MutationProvenance};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use revm::primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeedSourceType {
    Synthetic,
    Abi,
    Trace,
    Foundry,
    Manual,
    Historical,
    Bytecode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeedTag {
    Erc20,
    Erc4626,
    Amm,
    Lending,
    Oracle,
    Governance,
    Bridge,
    AccessControl,
    Staking,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedCandidate {
    pub target: Address,
    pub caller: Address,
    pub calldata: Vec<u8>,
    pub selector: Option<[u8; 4]>,
    pub value: U256,
    pub source_type: SeedSourceType,
    pub confidence_score: u64,
    pub reason: String,
    pub touched_addresses: Vec<Address>,
    pub touched_slots: Vec<B256>,
    pub prerequisites: Vec<String>,
    pub tags: BTreeSet<SeedTag>,
}

impl SeedCandidate {
    pub fn into_evm_input(self, base_snapshot_id: u64) -> EvmInput {
        let detail = format!(
            "seed source={:?}, confidence={}, reason={}",
            self.source_type, self.confidence_score, self.reason
        );
        EvmInput {
            txs: vec![SingletonTx {
                input: self.calldata,
                caller: self.caller,
                to: self.target,
                value: self.value,
                is_victim: false,
            }],
            base_snapshot_id,
            waypoints: Vec::new(),
            mutation_provenance: vec![MutationProvenance {
                strategy: "seed_intelligence".to_string(),
                tx_index: Some(0),
                selector: self.selector,
                detail,
            }],
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeedIntelligenceConfig {
    pub max_candidates: usize,
    pub include_low_confidence_fallbacks: bool,
    pub conservative_startup_only: bool,
}

impl Default for SeedIntelligenceConfig {
    fn default() -> Self {
        Self {
            max_candidates: 64,
            include_low_confidence_fallbacks: true,
            conservative_startup_only: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeedIntelligence {
    config: SeedIntelligenceConfig,
}

impl Default for SeedIntelligence {
    fn default() -> Self {
        Self::new(SeedIntelligenceConfig::default())
    }
}

impl SeedIntelligence {
    pub fn new(config: SeedIntelligenceConfig) -> Self {
        Self { config }
    }

    pub fn generate_candidates(
        &self,
        target: Address,
        caller: Address,
        abi_registry: &AbiRegistry,
        foundry_harness: Option<&FoundryHarnessManifest>,
    ) -> Vec<SeedCandidate> {
        let mut candidates = Vec::new();

        for (selector, types) in &abi_registry.functions {
            if self.config.conservative_startup_only && !is_conservative_startup_selector(*selector)
            {
                continue;
            }
            let priority = selector_priority_detail(*selector);
            let calldata = encode_default_call(*selector, types, caller, target);
            candidates.push(SeedCandidate {
                target,
                caller,
                calldata,
                selector: Some(*selector),
                value: default_value_for_selector(*selector, types),
                source_type: SeedSourceType::Abi,
                confidence_score: priority.base_confidence + 10,
                reason: format!(
                    "ABI selector {}: {}",
                    hex::encode(selector),
                    priority.reason
                ),
                touched_addresses: vec![target],
                touched_slots: Vec::new(),
                prerequisites: priority.prerequisites,
                tags: priority.tags,
            });
        }

        if let Some(harness) = foundry_harness {
            for target_selectors in &harness.target_selectors {
                for selector in &target_selectors.selectors {
                    let Some(selector_hex) = selector.selector_hex else {
                        continue;
                    };
                    let priority = selector_priority_detail(selector_hex);
                    let calldata = abi_registry
                        .functions
                        .get(&selector_hex)
                        .map(|types| encode_default_call(selector_hex, types, caller, target))
                        .unwrap_or_else(|| selector_hex.to_vec());

                    candidates.push(SeedCandidate {
                        target,
                        caller,
                        calldata,
                        selector: Some(selector_hex),
                        value: U256::ZERO,
                        source_type: SeedSourceType::Foundry,
                        confidence_score: priority.base_confidence + 20,
                        reason: format!(
                            "Foundry target selector {} from {}:{} ({})",
                            hex::encode(selector_hex),
                            target_selectors.file.display(),
                            target_selectors.line,
                            selector.expression
                        ),
                        touched_addresses: vec![target],
                        touched_slots: Vec::new(),
                        prerequisites: priority.prerequisites,
                        tags: priority.tags,
                    });
                }
            }
        }

        if candidates.is_empty() && self.config.include_low_confidence_fallbacks {
            candidates.push(SeedCandidate {
                target,
                caller,
                calldata: Vec::new(),
                selector: None,
                value: U256::ZERO,
                source_type: SeedSourceType::Synthetic,
                confidence_score: 10,
                reason: "fallback empty calldata; no ABI or Foundry selectors were available"
                    .to_string(),
                touched_addresses: vec![target],
                touched_slots: Vec::new(),
                prerequisites: Vec::new(),
                tags: BTreeSet::from([SeedTag::Unknown]),
            });
        }

        candidates.sort_by(|a, b| {
            b.confidence_score
                .cmp(&a.confidence_score)
                .then_with(|| a.source_type.cmp(&b.source_type))
                .then_with(|| a.selector.cmp(&b.selector))
        });
        candidates.dedup_by(|a, b| {
            a.target == b.target
                && a.caller == b.caller
                && a.calldata == b.calldata
                && a.source_type == b.source_type
        });
        candidates.truncate(self.config.max_candidates);
        candidates
    }

    pub fn generate_bytecode_candidates(
        &self,
        target: Address,
        caller: Address,
        function_summaries: &[FunctionSliceSummary],
    ) -> Vec<SeedCandidate> {
        let mut candidates = function_summaries
            .iter()
            .map(|summary| {
                let mut tags = summary
                    .protocol_type_hint
                    .as_ref()
                    .map(seed_tags_for_protocol)
                    .unwrap_or_else(|| BTreeSet::from([SeedTag::Unknown]));
                if summary.behavior.uses_caller
                    || summary.behavior.uses_origin
                    || summary.behavior.makes_delegate_call
                {
                    tags.insert(SeedTag::AccessControl);
                }
                let value = if summary.behavior.uses_call_value {
                    U256::from(10u128.pow(15))
                } else {
                    U256::ZERO
                };
                let mut prerequisites = summary.seed_hints.clone();
                prerequisites.extend(summary.invariant_hints.iter().map(|hint| {
                    format!("monitor-invariant-family:{hint}")
                }));
                prerequisites.sort();
                prerequisites.dedup();
                SeedCandidate {
                    target,
                    caller,
                    calldata: summary.selector.to_vec(),
                    selector: Some(summary.selector),
                    value,
                    source_type: SeedSourceType::Bytecode,
                    confidence_score: bytecode_slice_confidence(summary),
                    reason: format!(
                        "bytecode function slice selector 0x{} entry_pc={} signature_hint={} writes_storage={} external_call={} delegate_call={} value_sensitive={} caller_sensitive={}",
                        hex::encode(summary.selector),
                        summary.entry_pc,
                        summary.signature_hint.as_deref().unwrap_or("unknown"),
                        summary.behavior.writes_storage,
                        summary.behavior.makes_external_call,
                        summary.behavior.makes_delegate_call,
                        summary.behavior.uses_call_value,
                        summary.behavior.uses_caller || summary.behavior.uses_origin
                    ),
                    touched_addresses: vec![target],
                    touched_slots: Vec::new(),
                    prerequisites,
                    tags,
                }
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| {
            b.confidence_score
                .cmp(&a.confidence_score)
                .then_with(|| a.selector.cmp(&b.selector))
        });
        candidates.dedup_by(|a, b| a.target == b.target && a.calldata == b.calldata);
        candidates.truncate(self.config.max_candidates);
        candidates
    }

    pub fn parse_trace_seed_bundle_json(&self, json: &str) -> anyhow::Result<Vec<SeedCandidate>> {
        let bundle: TraceSeedBundle = serde_json::from_str(json)?;
        let mut out = Vec::new();

        for tx in bundle.transactions {
            let target = parse_address(tx.target.as_deref().or(tx.to.as_deref()))?;
            let caller = parse_address(tx.caller.as_deref())?;
            let calldata = parse_bytes(tx.calldata.as_deref().or(tx.input.as_deref()))?;
            let selector = calldata.get(0..4).and_then(|bytes| bytes.try_into().ok());
            let priority = selector
                .map(selector_priority_detail)
                .unwrap_or_else(fallback_priority);

            out.push(SeedCandidate {
                target,
                caller,
                calldata,
                selector,
                value: parse_u256(tx.value.as_deref()).unwrap_or_default(),
                source_type: tx.source_type.unwrap_or(SeedSourceType::Trace),
                confidence_score: priority.base_confidence + 15,
                reason: tx
                    .reason
                    .unwrap_or_else(|| "external trace/historical transaction seed".to_string()),
                touched_addresses: tx.touched_addresses.unwrap_or_default(),
                touched_slots: tx.touched_slots.unwrap_or_default(),
                prerequisites: tx.prerequisites.unwrap_or_default(),
                tags: if tx.tags.is_empty() {
                    priority.tags
                } else {
                    tx.tags.into_iter().collect()
                },
            });
        }

        out.sort_by(|a, b| b.confidence_score.cmp(&a.confidence_score));
        out.truncate(self.config.max_candidates);
        Ok(out)
    }
}

fn bytecode_slice_confidence(summary: &FunctionSliceSummary) -> u64 {
    let mut score = if summary.signature_hint.is_some() {
        58
    } else {
        42
    };
    if summary.behavior.writes_storage {
        score += 14;
    }
    if summary.behavior.uses_call_value {
        score += 10;
    }
    if summary.behavior.uses_caller || summary.behavior.uses_origin {
        score += 10;
    }
    if summary.behavior.makes_external_call {
        score += 8;
    }
    if summary.behavior.makes_delegate_call {
        score += 12;
    }
    if summary.protocol_type_hint.is_some() {
        score += 8;
    }
    score.min(92)
}

fn seed_tags_for_protocol(protocol: &ProtocolType) -> BTreeSet<SeedTag> {
    match protocol {
        ProtocolType::Erc20Token => BTreeSet::from([SeedTag::Erc20]),
        ProtocolType::Erc4626Vault => BTreeSet::from([SeedTag::Erc4626]),
        ProtocolType::AmmDexPool => BTreeSet::from([SeedTag::Amm]),
        ProtocolType::LendingBorrowing => BTreeSet::from([SeedTag::Lending]),
        ProtocolType::OraclePriceFeed => BTreeSet::from([SeedTag::Oracle]),
        ProtocolType::GovernanceTimelock => BTreeSet::from([SeedTag::Governance]),
        ProtocolType::BridgeMessagePassing => BTreeSet::from([SeedTag::Bridge]),
        ProtocolType::AccessControlHeavy | ProtocolType::ProxyUpgradeable => {
            BTreeSet::from([SeedTag::AccessControl])
        }
        _ => BTreeSet::from([SeedTag::Unknown]),
    }
}

fn is_conservative_startup_selector(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        [0x09, 0x5e, 0xa7, 0xb3] // approve(address,uint256)
            | [0xa9, 0x05, 0x9c, 0xbb] // transfer(address,uint256)
            | [0x23, 0xb8, 0x72, 0xdd] // transferFrom(address,address,uint256)
            | [0x18, 0x16, 0x0d, 0xdd] // totalSupply()
            | [0x70, 0xa0, 0x82, 0x31] // balanceOf(address)
    )
}

#[derive(Debug, Clone)]
struct SelectorPriority {
    base_confidence: u64,
    reason: &'static str,
    prerequisites: Vec<String>,
    tags: BTreeSet<SeedTag>,
}

pub fn selector_priority(selector: [u8; 4]) -> u64 {
    selector_priority_profile(selector).base_confidence
}

fn selector_priority_detail(selector: [u8; 4]) -> SelectorPriority {
    selector_priority_profile(selector)
}

fn selector_priority_profile(selector: [u8; 4]) -> SelectorPriority {
    for spec in risk_selector_specs() {
        if spec.selector == selector {
            return SelectorPriority {
                base_confidence: spec.confidence,
                reason: spec.reason,
                prerequisites: spec
                    .prerequisites
                    .iter()
                    .map(|item| (*item).to_string())
                    .collect(),
                tags: spec.tags.iter().cloned().collect(),
            };
        }
    }

    fallback_priority()
}

fn fallback_priority() -> SelectorPriority {
    SelectorPriority {
        base_confidence: 25,
        reason: "unknown selector; selector validity is useful but semantic risk is unknown",
        prerequisites: Vec::new(),
        tags: BTreeSet::from([SeedTag::Unknown]),
    }
}

#[derive(Debug, Clone)]
struct RiskSelectorSpec {
    selector: [u8; 4],
    confidence: u64,
    reason: &'static str,
    prerequisites: &'static [&'static str],
    tags: &'static [SeedTag],
}

fn risk_selector_specs() -> Vec<RiskSelectorSpec> {
    [
        (
            "deposit(uint256,address)",
            88,
            "vault deposit/mint path can create share-accounting dependencies",
            &["asset approval or payable funding"][..],
            &[SeedTag::Erc4626][..],
        ),
        (
            "mint(uint256,address)",
            86,
            "vault mint path exercises share issuance and rounding",
            &["asset approval"][..],
            &[SeedTag::Erc4626][..],
        ),
        (
            "withdraw(uint256,address,address)",
            90,
            "vault withdraw path consumes shares/assets and depends on prior deposits",
            &["prior deposit or share balance"][..],
            &[SeedTag::Erc4626][..],
        ),
        (
            "redeem(uint256,address,address)",
            90,
            "vault redeem path is high value for share inflation and rounding checks",
            &["prior mint/deposit"][..],
            &[SeedTag::Erc4626][..],
        ),
        (
            "borrow(address,uint256,uint256,uint16,address)",
            92,
            "borrow path creates debt/collateral dependencies",
            &["collateral deposit"][..],
            &[SeedTag::Lending][..],
        ),
        (
            "repay(address,uint256,uint256,address)",
            72,
            "repay path validates debt accounting and allowance usage",
            &["borrowed debt", "token approval"][..],
            &[SeedTag::Lending, SeedTag::Erc20][..],
        ),
        (
            "liquidationCall(address,address,address,uint256,bool)",
            95,
            "liquidation is an exploit-relevant terminal action",
            &["unhealthy debt position"][..],
            &[SeedTag::Lending][..],
        ),
        (
            "swap(address,bool,int256,uint160,bytes)",
            86,
            "AMM swap path stresses reserves, oracle reads, and price movement",
            &["token approval or pool funding"][..],
            &[SeedTag::Amm][..],
        ),
        (
            "addLiquidity(uint256,uint256)",
            70,
            "liquidity add path changes reserve/share accounting",
            &["token approvals"][..],
            &[SeedTag::Amm][..],
        ),
        (
            "removeLiquidity(uint256)",
            78,
            "liquidity removal is useful after reserve/share setup",
            &["LP balance"][..],
            &[SeedTag::Amm][..],
        ),
        (
            "approve(address,uint256)",
            72,
            "approval unlocks allowance-dependent multi-transaction flows",
            &[],
            &[SeedTag::Erc20][..],
        ),
        (
            "transferFrom(address,address,uint256)",
            80,
            "transferFrom depends on allowance and exposes token accounting bugs",
            &["prior approval"][..],
            &[SeedTag::Erc20][..],
        ),
        (
            "transfer(address,uint256)",
            62,
            "transfer exercises balance accounting and token hooks",
            &["token balance"][..],
            &[SeedTag::Erc20][..],
        ),
        (
            "claim()",
            68,
            "claim path can expose accounting, reward, or bridge finalization issues",
            &["accrued rewards or finalized message"][..],
            &[SeedTag::Staking, SeedTag::Bridge][..],
        ),
        (
            "harvest()",
            70,
            "harvest path exercises reward accounting and external calls",
            &["accrued rewards"][..],
            &[SeedTag::Staking][..],
        ),
        (
            "stake(uint256)",
            72,
            "stake path creates balance/share dependencies",
            &["token approval"][..],
            &[SeedTag::Staking, SeedTag::Erc20][..],
        ),
        (
            "unstake(uint256)",
            78,
            "unstake path depends on prior stake and reward accounting",
            &["prior stake"][..],
            &[SeedTag::Staking][..],
        ),
        (
            "propose(address[],uint256[],bytes[],string)",
            76,
            "governance proposal starts temporal execution chains",
            &["proposal threshold"][..],
            &[SeedTag::Governance][..],
        ),
        (
            "castVote(uint256,uint8)",
            72,
            "vote path creates governance state dependencies",
            &["active proposal"][..],
            &[SeedTag::Governance][..],
        ),
        (
            "queue(uint256)",
            82,
            "queue path should depend on proposal/vote state and timelock rules",
            &["successful proposal"][..],
            &[SeedTag::Governance][..],
        ),
        (
            "execute(uint256)",
            88,
            "execute path is a high-risk privileged terminal action",
            &["queued proposal or authorized role"][..],
            &[SeedTag::Governance, SeedTag::AccessControl][..],
        ),
        (
            "settle(uint256)",
            74,
            "settlement paths often finalize accounting after delayed state",
            &["open position/order"][..],
            &[SeedTag::Bridge, SeedTag::Amm][..],
        ),
        (
            "finalize(bytes)",
            84,
            "bridge finalization should depend on proof/replay state",
            &["valid message proof"][..],
            &[SeedTag::Bridge][..],
        ),
    ]
    .into_iter()
    .map(
        |(signature, confidence, reason, prerequisites, tags)| RiskSelectorSpec {
            selector: function_selector(signature),
            confidence,
            reason,
            prerequisites,
            tags,
        },
    )
    .collect()
}

fn function_selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

fn encode_default_call(
    selector: [u8; 4],
    types: &[DynSolType],
    caller: Address,
    target: Address,
) -> Vec<u8> {
    let values: Vec<_> = types
        .iter()
        .enumerate()
        .map(|(idx, ty)| default_sol_value(ty, idx, caller, target))
        .collect();
    let mut calldata = selector.to_vec();
    calldata.extend_from_slice(&DynSolValue::Tuple(values).abi_encode());
    calldata
}

fn default_sol_value(ty: &DynSolType, idx: usize, caller: Address, target: Address) -> DynSolValue {
    match ty {
        DynSolType::Uint(size) => DynSolValue::Uint(default_uint(idx), *size),
        DynSolType::Int(size) => DynSolValue::Int(alloy_primitives::I256::ZERO, *size),
        DynSolType::Address => {
            let address = if idx == 0 { caller } else { target };
            DynSolValue::Address(address)
        }
        DynSolType::Bool => DynSolValue::Bool(true),
        DynSolType::Bytes => DynSolValue::Bytes(vec![0u8; 32]),
        DynSolType::String => DynSolValue::String("RustyFuzz".to_string()),
        DynSolType::Tuple(inner) => DynSolValue::Tuple(
            inner
                .iter()
                .enumerate()
                .map(|(inner_idx, inner_ty)| default_sol_value(inner_ty, inner_idx, caller, target))
                .collect(),
        ),
        DynSolType::Array(inner) => {
            DynSolValue::Array(vec![default_sol_value(inner, idx, caller, target)])
        }
        DynSolType::FixedArray(inner, len) => DynSolValue::FixedArray(
            (0..*len)
                .map(|array_idx| default_sol_value(inner, array_idx, caller, target))
                .collect(),
        ),
        _ => DynSolValue::Uint(default_uint(idx), 256),
    }
}

fn default_uint(idx: usize) -> U256 {
    match idx {
        0 => U256::from(10u128.pow(18)),
        1 => U256::from(10u128.pow(6)),
        _ => U256::from(1),
    }
}

fn default_value_for_selector(selector: [u8; 4], types: &[DynSolType]) -> U256 {
    let _ = (selector, types);
    U256::ZERO
}

#[derive(Debug, Clone, Deserialize)]
struct TraceSeedBundle {
    #[serde(default)]
    transactions: Vec<TraceSeedTransaction>,
}

#[derive(Debug, Clone, Deserialize)]
struct TraceSeedTransaction {
    target: Option<String>,
    to: Option<String>,
    caller: Option<String>,
    calldata: Option<String>,
    input: Option<String>,
    value: Option<String>,
    #[serde(default)]
    source_type: Option<SeedSourceType>,
    reason: Option<String>,
    #[serde(default)]
    touched_addresses: Option<Vec<Address>>,
    #[serde(default)]
    touched_slots: Option<Vec<B256>>,
    #[serde(default)]
    prerequisites: Option<Vec<String>>,
    #[serde(default)]
    tags: Vec<SeedTag>,
}

fn parse_address(value: Option<&str>) -> anyhow::Result<Address> {
    let value = value.ok_or_else(|| anyhow::anyhow!("trace seed missing address"))?;
    Address::from_str(value).map_err(|err| anyhow::anyhow!("invalid address `{value}`: {err}"))
}

fn parse_bytes(value: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let value = value.unwrap_or_default().trim();
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        return Ok(Vec::new());
    }
    Ok(hex::decode(value)?)
}

fn parse_u256(value: Option<&str>) -> anyhow::Result<U256> {
    let Some(value) = value else {
        return Ok(U256::ZERO);
    };
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        let bytes = hex::decode(hex)?;
        return Ok(U256::from_be_slice(&bytes));
    }
    U256::from_str(value).map_err(|err| anyhow::anyhow!("invalid U256 `{value}`: {err}"))
}

#[derive(Debug, Clone, Deserialize)]
struct HistoricalSeedJson {
    chain_id: Option<u64>,
    block_number: Option<u64>,
    target: Option<String>,
    #[serde(default)]
    transactions: Vec<HistoricalSeedTx>,
}

#[derive(Debug, Clone, Deserialize)]
struct HistoricalSeedTx {
    hash: Option<String>,
    #[serde(rename = "from")]
    from_addr: Option<String>,
    to: Option<String>,
    value: Option<String>,
    input: Option<String>,
    selector: Option<String>,
    success: Option<bool>,
    #[serde(rename = "isError")]
    is_error: Option<String>,
    #[serde(rename = "blockNumber")]
    block_number: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

impl SeedIntelligence {
    pub fn parse_historical_seed_json(&self, json: &str) -> anyhow::Result<Vec<SeedCandidate>> {
        self.parse_historical_seed_json_with_target(json, None)
    }

    pub fn parse_historical_seed_json_with_target(
        &self,
        json: &str,
        explicit_target: Option<Address>,
    ) -> anyhow::Result<Vec<SeedCandidate>> {
        let bundle = parse_historical_seed_container(json)?;
        let target_hint = bundle
            .target
            .as_deref()
            .and_then(|value| Address::from_str(value).ok());
        let target_hint = explicit_target.or(target_hint);
        let mut out = Vec::new();
        for tx in bundle.transactions {
            if tx.success == Some(false) || tx.is_error.as_deref() == Some("1") {
                continue;
            }
            let Some(to) = tx
                .to
                .as_deref()
                .and_then(|value| Address::from_str(value).ok())
            else {
                continue;
            };
            let caller = tx
                .from_addr
                .as_deref()
                .and_then(|value| Address::from_str(value).ok())
                .unwrap_or_else(|| Address::repeat_byte(0x13));
            let calldata = parse_bytes(tx.input.as_deref())?;
            if !calldata.is_empty() && calldata.len() < 4 {
                continue;
            }
            let selector = calldata
                .get(0..4)
                .and_then(|bytes| bytes.try_into().ok())
                .or_else(|| {
                    tx.selector
                        .as_deref()
                        .and_then(|raw| parse_selector_hex(raw).ok())
                });
            let priority = selector
                .map(selector_priority_detail)
                .unwrap_or_else(fallback_priority);
            let mut tags = tx
                .tags
                .iter()
                .filter_map(|tag| seed_tag_from_text(tag))
                .collect::<BTreeSet<_>>();
            if tags.is_empty() {
                tags = priority.tags;
            }
            let target_relevant = target_hint.is_some_and(|target| target == to);
            out.push(SeedCandidate {
                target: to,
                caller,
                calldata,
                selector,
                value: parse_u256(tx.value.as_deref()).unwrap_or_default(),
                source_type: SeedSourceType::Historical,
                confidence_score: (priority.base_confidence
                    + if target_relevant { 25 } else { 10 })
                .min(100),
                reason: format!(
                    "historical tx seed{}{}{}",
                    tx.hash
                        .as_deref()
                        .map(|hash| format!(" {hash}"))
                        .unwrap_or_default(),
                    bundle
                        .chain_id
                        .map(|chain| format!(" on chain {chain}"))
                        .unwrap_or_default(),
                    bundle
                        .block_number
                        .map(|block| format!(" at block {block}"))
                        .or_else(|| {
                            tx.block_number
                                .as_deref()
                                .map(|block| format!(" at block {block}"))
                        })
                        .unwrap_or_default()
                ),
                touched_addresses: vec![to],
                touched_slots: Vec::new(),
                prerequisites: Vec::new(),
                tags,
            });
        }
        out.sort_by(|a, b| b.confidence_score.cmp(&a.confidence_score));
        out.truncate(self.config.max_candidates);
        Ok(out)
    }

    pub fn historical_candidates_to_inputs(
        &self,
        candidates: Vec<SeedCandidate>,
        base_snapshot_id: u64,
        max_sequence_len: usize,
    ) -> Vec<EvmInput> {
        let mut inputs = candidates
            .iter()
            .cloned()
            .map(|candidate| candidate.into_evm_input(base_snapshot_id))
            .collect::<Vec<_>>();
        let max_window = max_sequence_len.clamp(2, 4).min(candidates.len());
        for window_len in 2..=max_window {
            for window in candidates.windows(window_len) {
                let mut txs = Vec::new();
                let mut provenance = Vec::new();
                for (idx, candidate) in window.iter().enumerate() {
                    txs.push(SingletonTx {
                        input: candidate.calldata.clone(),
                        caller: candidate.caller,
                        to: candidate.target,
                        value: candidate.value,
                        is_victim: false,
                    });
                    provenance.push(MutationProvenance {
                        strategy: "historical_seed_sequence".to_string(),
                        tx_index: Some(idx),
                        selector: candidate.selector,
                        detail: candidate.reason.clone(),
                    });
                }
                inputs.push(EvmInput {
                    txs,
                    base_snapshot_id,
                    waypoints: Vec::new(),
                    mutation_provenance: provenance,
                });
            }
        }
        inputs
    }
}

fn parse_historical_seed_container(json: &str) -> anyhow::Result<HistoricalSeedJson> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    if value.is_array() {
        return Ok(HistoricalSeedJson {
            chain_id: None,
            block_number: None,
            target: None,
            transactions: serde_json::from_value(value)?,
        });
    }
    if let Some(result) = value.get("result").filter(|result| result.is_array()) {
        return Ok(HistoricalSeedJson {
            chain_id: None,
            block_number: None,
            target: None,
            transactions: serde_json::from_value(result.clone())?,
        });
    }
    Ok(serde_json::from_value(value)?)
}

fn parse_selector_hex(raw: &str) -> anyhow::Result<[u8; 4]> {
    let raw = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    let bytes = hex::decode(raw)?;
    let selector = bytes
        .get(0..4)
        .ok_or_else(|| anyhow::anyhow!("selector too short"))?;
    Ok(selector.try_into().expect("slice length checked"))
}

fn seed_tag_from_text(tag: &str) -> Option<SeedTag> {
    let tag = tag.to_ascii_lowercase();
    Some(
        if tag.contains("erc20") || tag.contains("token") || tag.contains("approve") {
            SeedTag::Erc20
        } else if tag.contains("4626")
            || tag.contains("vault")
            || tag.contains("deposit")
            || tag.contains("redeem")
        {
            SeedTag::Erc4626
        } else if tag.contains("amm") || tag.contains("swap") || tag.contains("pool") {
            SeedTag::Amm
        } else if tag.contains("lend") || tag.contains("borrow") || tag.contains("liquidat") {
            SeedTag::Lending
        } else if tag.contains("oracle") || tag.contains("price") {
            SeedTag::Oracle
        } else if tag.contains("govern") || tag.contains("vote") || tag.contains("queue") {
            SeedTag::Governance
        } else if tag.contains("bridge") || tag.contains("message") {
            SeedTag::Bridge
        } else if tag.contains("stake") || tag.contains("reward") {
            SeedTag::Staking
        } else if tag.contains("access") || tag.contains("admin") || tag.contains("owner") {
            SeedTag::AccessControl
        } else {
            return None;
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_dyn_abi::DynSolType;

    #[test]
    fn selector_prioritization_prefers_exploit_relevant_flows() {
        let withdraw = function_selector("withdraw(uint256,address,address)");
        let unknown = [0xde, 0xad, 0xbe, 0xef];

        assert!(selector_priority(withdraw) > selector_priority(unknown));
    }

    #[test]
    fn abi_generation_produces_explainable_protocol_seed() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let mut abi = AbiRegistry::default();
        let approve = function_selector("approve(address,uint256)");
        abi.functions
            .insert(approve, vec![DynSolType::Address, DynSolType::Uint(256)]);

        let seeds = SeedIntelligence::default().generate_candidates(target, caller, &abi, None);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].selector, Some(approve));
        assert!(seeds[0].confidence_score >= 70);
        assert!(seeds[0].tags.contains(&SeedTag::Erc20));
        assert!(seeds[0].reason.contains("ABI selector"));
        assert!(seeds[0].calldata.len() > 4);
    }

    #[test]
    fn historical_seed_json_converts_valid_tx_to_seed_and_input() {
        let json = r#"{
          "chain_id": 1,
          "block_number": 123,
          "target": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "transactions": [{
            "hash": "0xabc",
            "from": "0x1313131313131313131313131313131313131313",
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "value": "0",
            "input": "0x095ea7b3000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000001",
            "selector": "0x095ea7b3",
            "success": true,
            "tags": ["approve", "vault"]
          }]
        }"#;
        let intelligence = SeedIntelligence::default();
        let seeds = intelligence
            .parse_historical_seed_json(json)
            .expect("historical seeds");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].source_type, SeedSourceType::Historical);
        assert_eq!(
            seeds[0].selector,
            Some(function_selector("approve(address,uint256)"))
        );
        assert!(seeds[0].confidence_score >= 90);
        assert!(seeds[0].tags.contains(&SeedTag::Erc20));
        let inputs = intelligence.historical_candidates_to_inputs(seeds, 0, 2);
        assert!(!inputs.is_empty());
        assert_eq!(inputs[0].txs[0].caller, Address::repeat_byte(0x13));
    }

    #[test]
    fn historical_seed_json_builds_adjacent_two_transaction_sequences() {
        let json = r#"{
          "chain_id": 1,
          "block_number": 123,
          "target": "0x1111111111111111111111111111111111111111",
          "transactions": [
            {
              "hash": "0x1",
              "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "to": "0x1111111111111111111111111111111111111111",
              "value": "0",
              "input": "0xfeaf968c",
              "success": true,
              "tags": ["oracle"]
            },
            {
              "hash": "0x2",
              "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "to": "0x1111111111111111111111111111111111111111",
              "value": "0",
              "input": "0xfeaf968c",
              "success": true,
              "tags": ["oracle"]
            }
          ]
        }"#;
        let intelligence = SeedIntelligence::default();
        let seeds = intelligence
            .parse_historical_seed_json(json)
            .expect("historical seeds");
        let inputs = intelligence.historical_candidates_to_inputs(seeds, 0, 4);
        assert!(inputs.iter().any(|input| input.txs.len() == 2));
    }

    #[test]
    fn historical_seed_json_rejects_too_short_calldata() {
        let json = r#"{
          "transactions": [{
            "from": "0x1313131313131313131313131313131313131313",
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "input": "0x1234",
            "success": true
          }]
        }"#;
        let seeds = SeedIntelligence::default()
            .parse_historical_seed_json(json)
            .unwrap();
        assert!(seeds.is_empty());
    }

    #[test]
    fn historical_seed_json_accepts_bscscan_result_list() {
        let json = r#"{
          "status": "1",
          "message": "OK",
          "result": [{
            "hash": "0xabc",
            "from": "0x1313131313131313131313131313131313131313",
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "value": "0",
            "input": "0x095ea7b3000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber": "100600727",
            "isError": "0"
          }]
        }"#;

        let target = Address::repeat_byte(0xaa);
        let seeds = SeedIntelligence::default()
            .parse_historical_seed_json_with_target(json, Some(target))
            .expect("bscscan seed list");

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].target, target);
        assert!(seeds[0].reason.contains("100600727"));
        assert_eq!(
            seeds[0].selector,
            Some(function_selector("approve(address,uint256)"))
        );
    }

    #[test]
    fn historical_seed_json_accepts_generic_tx_array_and_skips_errors() {
        let json = r#"[
          {
            "hash": "0xok",
            "from": "0x1313131313131313131313131313131313131313",
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "value": "0",
            "input": "0xa9059cbb000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber": "7",
            "isError": "0"
          },
          {
            "hash": "0xbad",
            "from": "0x1313131313131313131313131313131313131313",
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "value": "0",
            "input": "0xa9059cbb000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber": "8",
            "isError": "1"
          }
        ]"#;

        let seeds = SeedIntelligence::default()
            .parse_historical_seed_json_with_target(json, Some(Address::repeat_byte(0xaa)))
            .expect("generic seed list");

        assert_eq!(seeds.len(), 1);
        assert_eq!(
            seeds[0].selector,
            Some(function_selector("transfer(address,uint256)"))
        );
        assert!(seeds[0].reason.contains("0xok"));
    }

    #[test]
    fn trace_seed_parser_accepts_historical_transaction_json() {
        let json = r#"{
          "transactions": [{
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "caller": "0x1313131313131313131313131313131313131313",
            "input": "0x095ea7b3000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000001",
            "value": "0",
            "reason": "historical approve"
          }]
        }"#;

        let seeds = SeedIntelligence::default()
            .parse_trace_seed_bundle_json(json)
            .expect("trace seed bundle");

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].source_type, SeedSourceType::Trace);
        assert_eq!(
            seeds[0].selector,
            Some(function_selector("approve(address,uint256)"))
        );
        assert!(seeds[0].tags.contains(&SeedTag::Erc20));
    }

    #[test]
    fn fallback_seed_is_low_confidence_and_explained() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let seeds = SeedIntelligence::default().generate_candidates(
            target,
            caller,
            &AbiRegistry::default(),
            None,
        );

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].source_type, SeedSourceType::Synthetic);
        assert!(seeds[0].confidence_score < 20);
        assert!(seeds[0].reason.contains("fallback"));
    }

    #[test]
    fn conservative_startup_filters_complex_protocol_selectors() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let mut abi = AbiRegistry::default();
        let liquidation =
            function_selector("liquidationCall(address,address,address,uint256,bool)");
        let approve = function_selector("approve(address,uint256)");
        abi.functions.insert(
            liquidation,
            vec![
                DynSolType::Address,
                DynSolType::Address,
                DynSolType::Address,
                DynSolType::Uint(256),
                DynSolType::Bool,
            ],
        );
        abi.functions
            .insert(approve, vec![DynSolType::Address, DynSolType::Uint(256)]);

        let seeds = SeedIntelligence::new(SeedIntelligenceConfig {
            max_candidates: 8,
            include_low_confidence_fallbacks: true,
            conservative_startup_only: true,
        })
        .generate_candidates(target, caller, &abi, None);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].selector, Some(approve));
    }

    #[test]
    fn bytecode_function_summaries_generate_actionable_seeds() {
        let target = Address::repeat_byte(0xaa);
        let caller = Address::repeat_byte(0x13);
        let selector = function_selector("deposit(uint256,address)");
        let summaries = vec![FunctionSliceSummary {
            selector,
            entry_pc: 0x40,
            signature_hint: Some("deposit(uint256,address)".to_string()),
            protocol_type_hint: Some(ProtocolType::Erc4626Vault),
            symbolic_summary: crate::engine::bytecode_analysis::SymbolicBytecodeSummary::default(),
            behavior: crate::engine::bytecode_analysis::FunctionBehavior {
                writes_storage: true,
                uses_call_value: true,
                ..Default::default()
            },
            seed_hints: vec!["vary-msg-value".to_string()],
            invariant_hints: vec!["erc4626-share-price-bound".to_string()],
        }];

        let seeds =
            SeedIntelligence::default().generate_bytecode_candidates(target, caller, &summaries);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].source_type, SeedSourceType::Bytecode);
        assert_eq!(seeds[0].selector, Some(selector));
        assert_eq!(seeds[0].calldata, selector.to_vec());
        assert!(seeds[0].value > U256::ZERO);
        assert!(seeds[0].tags.contains(&SeedTag::Erc4626));
        assert!(seeds[0].confidence_score >= 80);
    }
}
